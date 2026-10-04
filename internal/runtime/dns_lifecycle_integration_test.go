// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/dnsbroker"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/net/dns/dnsmessage"
)

// These root-only fixtures run the actual cooperating CLI under each tier's
// production supervisor. They do not change libc's resolver or invoke external
// DNS. The numeric upstream and every run/anchor/log are owned by the fixture.
func TestDNSBrokerCLIOnRealKernel(t *testing.T) { dnsCLIKernelCases(t, false) }

func TestDNSBrokerOrphanCleanupOnRealKernel(t *testing.T) { dnsCLIKernelCases(t, true) }

type dnsCLIResult struct {
	PID, Code int
	Response  struct {
		RCode   string            `json:"rcode"`
		Answers []json.RawMessage `json:"answers"`
	} `json:"response"`
}
type dnsCLIState struct {
	PID, UID, GID, Descendant int
	Directory                 string `json:"directory"`
	ServerPID                 int    `json:"server_pid"`
	Results                   []dnsCLIResult
}

const dnsCLIActor = `import json, os, subprocess, sys, time
state = {'pid':os.getpid(), 'uid':os.getuid(), 'gid':os.getgid(),
         'directory':os.environ['TEGO_DNS_BROKER_DIR'],
         'server_pid':int(os.environ['TEGO_DNS_BROKER_PID']), 'results':[]}
for name, typ, expected in [('allowed.example','A',0), ('allowed.example','A',0),
                             ('forbidden.example','A',1), ('allowed.example','AAAA',1)]:
    child = subprocess.Popen([sys.argv[1], 'dns', name, '--type', typ, '--json'],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, errors = child.communicate(timeout=10)
    if child.returncode != expected:
        raise RuntimeError('DNS CLI code %s expected %s: %s' % (child.returncode, expected, errors.decode()))
    state['results'].append({'pid':child.pid, 'code':child.returncode, 'response':json.loads(output)})
if sys.argv[2] == 'orphan':
    first = os.fork()
    if first == 0:
        os.setsid()
        second = os.fork()
        if second == 0:
            with open('out/descendant.tmp','w') as f: f.write(str(os.getpid()))
            os.rename('out/descendant.tmp','out/descendant')
            while True: time.sleep(1)
        os._exit(0)
    os.waitpid(first, 0)
    while not os.path.exists('out/descendant'): time.sleep(.01)
    with open('out/descendant') as f: state['descendant'] = int(f.read())
with open('out/results.tmp','w') as f: json.dump(state, f)
os.rename('out/results.tmp','out/results.json')
if sys.argv[2] == 'orphan':
    while True: time.sleep(1)
`

// dnsCLIReportWait bounds the launch up to the actor's report, which is almost all tego run's start: the four
// queries take tens of milliseconds. A tier-2 or tier-3 subtest whose start finds no doctor run-cache answer for
// its plane probes every program (probe.programs) and may load the build's objects cold; the cache holds one
// plane mode's answer, so every switch of TEGO_TEST_PLANE here (fmod_ret, then lsm) misses it, and the first
// BPF run after a guest boots misses both. Measured in the 6.17 KVM guest (4 vCPUs, a loaded host;
// TEGO_TEST_PHASE_TIMING, 2026-10-05), that first run took 15.8-29.6 s over ten boots, probe.programs up to
// 23.3 s and the cold load up to 7.0 s; other BPF runs took 0.8-24.4 s; and the 30 s this used to be expired
// in three runs (R6). Product starts keep their machine's one plane mode, which the cache answers after the first run.
// It is no budget, only the point past which a start that never reports fails: the launcher's own exit fails the
// subtest at once, and the launcher's start phases (TEGO_TEST_PHASE_TIMING) are in the log printed then. On
// 2026-10-16, with the KVM host at load ~80, the cgroup subtest's first start passed the 120 s this was, and the
// bpflsm subtest's start, one plane mode's probe, took 94.6 s against 0.7-1.1 s on a quiet host, while the same
// guest's tagged cgroup suite ran past its 45 minutes: the guest was starved, the start was not stuck.
const dnsCLIReportWait = 5 * time.Minute

func dnsCLIKernelCases(t *testing.T, orphan bool) {
	if os.Geteuid() != 0 {
		t.Skip("needs root/SUDO credentials: actual governed DNS CLI and detached reaper fixture")
	}
	uid, gid, ok := agentUID(t)
	if !ok {
		t.Skip("needs root/SUDO credentials: actual governed DNS CLI and detached reaper fixture")
	}
	requireLandlock(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("needs python3: actual governed DNS CLI actor")
	}
	binDir := t.TempDir()
	agentReaches(t, filepath.Join(binDir, "tego"))
	bin := filepath.Join(binDir, "tego")
	build := exec.Command("go", "build", "-tags", "tegobpf,tegotesthooks", "-trimpath", "-o", bin, "github.com/attention-span-ai/tego/cmd/tego")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build governed DNS CLI: %v %s", err, output)
	}
	for _, tc := range []struct{ tier, plane string }{{"landlock", ""}, {"cgroup", "fmod_ret"}, {"bpflsm", "lsm"}} {
		t.Run(tc.tier, func(t *testing.T) {
			if tc.tier == "bpflsm" {
				lsms, err := os.ReadFile("/sys/kernel/security/lsm")
				if err != nil || !strings.Contains(","+strings.TrimSpace(string(lsms))+",", ",bpf,") {
					t.Skip("BPF LSM is not active on this boot (no bpf in lsm=); the default guest boot runs this case")
				}
			}
			dnsCLIKernelRun(t, bin, python, uid, gid, tc.tier, tc.plane, orphan)
		})
	}
}

func dnsCLIKernelRun(t *testing.T, bin, python string, uid, gid int, tier, plane string, orphan bool) {
	u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			raw := make([]byte, dnsbroker.MaxPacket)
			n, from, err := u.ReadFromUDP(raw)
			if err != nil {
				return
			}
			calls.Add(1)
			var q dnsmessage.Message
			if q.Unpack(raw[:n]) != nil {
				continue
			}
			q.Response, q.RecursionAvailable = true, true
			q.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: q.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 17}}}}
			out, _ := q.Pack()
			_, _ = u.WriteToUDP(out, from)
		}
	})
	t.Cleanup(func() { u.Close(); wg.Wait() })
	project, stateDir := t.TempDir(), t.TempDir()
	out := filepath.Join(project, "out")
	if err := os.Mkdir(out, 0755); err != nil {
		t.Fatal(err)
	}
	agentReaches(t, out)
	agentOwns(t, project, out)
	mode := "ordinary"
	if orphan {
		mode = "orphan"
	}
	contract := fmt.Sprintf(`version: 0
name: dns-cli
command: [%q, "./agent.py", %q, %q]
fs:
  write: ["./out/"]
exec:
  allow: [%q, %q]
net:
  allow: []
  dns:
    mode: broker
    allow: [allowed.example]
    types: [A]
    cache: 4
env:
  pass: [PATH, HOME]
  set:
    TEGO_DNS_BROKER_DIR: /forged-broker
    TEGO_DNS_BROKER_PID: "1"
limits:
  pids: 128
record: summary
`, python, bin, mode, python, bin)
	for name, body := range map[string]string{"agent.py": dnsCLIActor, "agent.yaml": contract} {
		path := filepath.Join(project, name)
		if err := os.WriteFile(path, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		agentOwns(t, path)
	}
	root, anchor := filepath.Join(stateDir, "ledger"), filepath.Join(stateDir, "chain.log")
	cfg := filepath.Join(stateDir, "config.yaml")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\nresolver: [%q]\nstop_grace: 1s\n", root, u.LocalAddr().String())), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsCLIReportWait+60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "run", "--tier", tier, filepath.Join(project, "agent.yaml"))
	cmd.Dir = project
	cmd.Env = append(os.Environ(), "TEGO_CONFIG="+cfg, "TEGO_TEST_CHAIN_ANCHOR="+anchor,
		"TEGO_TEST_OWN_LOG_HOME="+filepath.Join(stateDir, "log-home"), "TEGO_TEST_PLANE="+plane,
		"HOME="+out, "PYTHONDONTWRITEBYTECODE=1", "TEGO_TEST_PHASE_TIMING=1")
	logPath := filepath.Join(stateDir, "launcher.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	defer func() { _ = cmd.Process.Kill() }()
	var state dnsCLIState
	var finished bool
	var finishErr error
	started := time.Now()
	deadline := started.Add(dnsCLIReportWait)
reportWait:
	for {
		raw, err := os.ReadFile(filepath.Join(out, "results.json"))
		if err == nil && json.Unmarshal(raw, &state) == nil {
			break
		}
		select {
		case err := <-done:
			finished, finishErr = true, err
			// The ordinary actor may publish and exit between our first read
			// and its Wait. Re-read its atomic report before declaring failure.
			raw, readErr := os.ReadFile(filepath.Join(out, "results.json"))
			if readErr == nil && json.Unmarshal(raw, &state) == nil {
				break reportWait
			}
			log, _ := os.ReadFile(logPath)
			t.Fatalf("governed DNS actor ended before proof: %v\n%s", err, log)
		default:
		}
		if time.Now().After(deadline) {
			log, _ := os.ReadFile(logPath)
			t.Fatalf("governed DNS actor did not report within %s:\n%s", dnsCLIReportWait, log)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Logf("the actor reported %v after the launcher started", time.Since(started).Round(time.Millisecond))
	if state.UID != uid || state.GID != gid || state.ServerPID != cmd.Process.Pid || !validDNSDirectoryName(filepath.Base(state.Directory)) || filepath.Dir(state.Directory) != "/tmp" || len(filepath.Join(state.Directory, dnsbroker.SocketName)) >= 108 || len(state.Results) != 4 {
		t.Fatalf("runtime authority/identity not observed: %+v", state)
	}
	for i, result := range state.Results {
		want, rcode := 0, "RCodeSuccess"
		if i >= 2 {
			want, rcode = 1, "RCodeRefused"
		}
		if result.PID <= 0 || result.Code != want || result.Response.RCode != rcode || i < 2 && len(result.Response.Answers) != 1 {
			t.Fatalf("actual governed CLI result%d %+v", i, result)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("cache/refusal dispatched%dqueries, want1", calls.Load())
	}
	dirs := runDirs(t, root)
	if len(dirs) != 1 {
		t.Fatalf("run directories%v", dirs)
	}
	dir := dirs[0]
	if orphan {
		if state.Descendant <= 0 {
			t.Fatal("detached descendant not observed")
		}
		for _, pid := range []int{state.PID, state.Descendant} {
			status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
			if err != nil || !strings.Contains(string(status), fmt.Sprintf("Uid:\t%d\t%d\t%d\t%d", uid, uid, uid, uid)) {
				t.Fatalf("live dropped identity pid%d: %v\n%s", pid, err, status)
			}
		}
		descStat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", state.Descendant))
		if err != nil {
			t.Fatal(err)
		}
		descClose := strings.LastIndexByte(string(descStat), ')')
		if descClose < 0 {
			t.Fatal("live descendant stat has no command boundary")
		}
		descFields := strings.Fields(string(descStat[descClose+1:]))
		if len(descFields) < 20 {
			t.Fatal("live descendant stat lacks birth identity")
		}
		descBirth := descFields[19]
		var scope string
		cg, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", state.Descendant))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(cg), "\n") {
			if path, ok := strings.CutPrefix(line, "0::"); ok {
				scope = filepath.Join("/sys/fs/cgroup", path)
			}
		}
		if filepath.Base(scope) != identity.RunScope(identity.RunID(filepath.Base(dir))) {
			t.Fatalf("descendant scope%s does not name run%s", scope, dir)
		}
		scopeDir, err := os.Open(scope)
		if err != nil {
			t.Fatal(err)
		}
		defer scopeDir.Close()
		// Recovery after a failed fixture targets this held scope, never a
		// replacement that later appeared under the same path.
		defer func() {
			_ = os.WriteFile(fmt.Sprintf("/proc/self/fd/%d/cgroup.kill", scopeDir.Fd()), []byte("1"), 0200)
		}()
		endpoint := filepath.Join(state.Directory, dnsbroker.SocketName)
		st, err := os.Lstat(state.Directory)
		if err != nil || st.Mode().Perm() != 0711 || st.Sys().(*syscall.Stat_t).Uid != 0 {
			t.Fatalf("DNS directory is not owned/search-only:%v %v", st, err)
		}
		if st, err := os.Lstat(endpoint); err != nil || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Uid != uint32(uid) {
			t.Fatalf("DNS endpoint identity/permissions:%v %v", st, err)
		}
		outside := exec.CommandContext(ctx, bin, "dns", "allowed.example", "--run-dir", state.Directory, "--server-pid", strconv.Itoa(state.ServerPID), "--json")
		// The run's own isolation: the test build keeps no anchor or own log of the invoking user's (tools/isocheck GO-5).
		outside.Env = append(os.Environ(), "TEGO_CONFIG="+cfg, "TEGO_TEST_CHAIN_ANCHOR="+anchor,
			"TEGO_TEST_OWN_LOG_HOME="+filepath.Join(stateDir, "log-home"), "HOME="+out)
		outside.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
		output, err := outside.CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != identity.ExitError || calls.Load() != 1 {
			t.Fatalf("same-UID outside sender admitted:%v count%d output%s", err, calls.Load(), output)
		}
		if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if !errors.As(err, &exit) || !exit.Sys().(syscall.WaitStatus).Signaled() {
				t.Fatalf("launcher did not die by signal:%v", err)
			}
		case <-ctx.Done():
			t.Fatal("killed launcher did not join")
		}
		deadline = time.Now().Add(15 * time.Second)
		for {
			_, serr := os.Stat(scope)
			_, derr := os.Stat(state.Directory)
			if errors.Is(serr, os.ErrNotExist) && errors.Is(derr, os.ErrNotExist) && lastKind(t, dir) == record.KindRunEnd {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("autonomous reaper did not remove exact scope+DNS endpoint: scope%v directory%v last%s", serr, derr, lastKind(t, dir))
			}
			time.Sleep(20 * time.Millisecond)
		}
		if raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", state.Descendant)); err == nil {
			close := strings.LastIndexByte(string(raw), ')')
			if close < 0 {
				t.Fatal("descendant stat has no command boundary")
			}
			fields := strings.Fields(string(raw[close+1:]))
			// A guest init may retain a zombie; it executes nothing and owns no
			// run cgroup. Any live state after removal is a failed cleanup proof.
			if len(fields) < 20 || fields[19] == descBirth && fields[0] != "Z" {
				t.Fatalf("descendant remains executable after reaping:%s", raw)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	} else {
		if !finished {
			select {
			case finishErr = <-done:
			case <-ctx.Done():
				t.Fatal("normal DNS run did not end")
			}
		}
		if finishErr != nil {
			log, _ := os.ReadFile(logPath)
			t.Fatalf("normal DNS run:%v\n%s", finishErr, log)
		}
		if _, err := os.Stat(state.Directory); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("normal shutdown retained owned DNS endpoint:%v", err)
		}
		if _, err := os.Stat(identity.UserCgroupPath(identity.SystemCgroupRoot, "dns-cli", identity.RunID(filepath.Base(dir)))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("normal shutdown retained the run cgroup:%v", err)
		}
	}
	var start record.RunStartPayload
	var end record.RunEndPayload
	var decisions, responses, denials, cached, endings int
	for _, ev := range events(t, dir) {
		switch ev.Kind {
		case record.KindRunStart:
			if err := ev.DecodePayload(&start); err != nil {
				t.Fatal(err)
			}
		case record.KindRunEnd:
			endings++
			if err := ev.DecodePayload(&end); err != nil {
				t.Fatal(err)
			}
		case record.KindNet:
			var payload dnsPayload
			if ev.DecodePayload(&payload) != nil || payload.Mechanism != "dns-broker" {
				continue
			}
			matched := false
			for _, result := range state.Results {
				matched = matched || ev.PID == result.PID
			}
			if !matched || payload.Proto != "unix" || payload.Dst != "unix:"+filepath.Join(state.Directory, dnsbroker.SocketName) || ev.Source != record.SourceSupervisor {
				t.Fatalf("DNS line lacks actual governed writer/endpoint proof:%+v %+v", ev, payload)
			}
			switch payload.DNSPhase {
			case dnsbroker.PhaseDecision:
				decisions++
				if ev.Verdict == record.VerdictRefused {
					denials++
				}
			case dnsbroker.PhaseCompletion:
				responses++
				if payload.DNSCached {
					cached++
				}
			}
		}
	}
	if start.Tier != tier || !start.NetGuarantees["dns_broker"] || decisions != 4 || responses != 2 || denials != 2 || cached != 1 || endings != 1 {
		t.Fatalf("actual capability/ledger proof: start%+v decision%d response%d denied%d cached%d endings%d", start, decisions, responses, denials, cached, endings)
	}
	if tier != "landlock" && start.DecisionPlane != plane {
		t.Fatalf("root tier ran on%s, want%s", start.DecisionPlane, plane)
	}
	if orphan && (end.Reason != record.RunEndOrphaned || end.ExitCode != identity.ExitLauncher) || !orphan && (end.Reason != record.RunEndExit || end.ExitCode != 0) {
		t.Fatalf("run_end%+v", end)
	}
	verify := exec.CommandContext(ctx, bin, "events", filepath.Base(dir), "--verify", "--json")
	verify.Env = cmd.Env
	output, err := verify.CombinedOutput()
	if err != nil {
		t.Fatalf("actual anchored CLI verify:%v %s", err, output)
	}
	if report, err := ledger.VerifyRunDir(ctx, dir, ledger.NewFileChainAnchor(anchor)); err != nil || !report.Anchored || !report.Ended {
		t.Fatalf("supplementary anchored raw chain:%+v %v", report, err)
	}
}
