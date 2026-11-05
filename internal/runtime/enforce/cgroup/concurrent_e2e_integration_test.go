// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/testutil"
)

// concurrentAgent is each run's agent in TestTier2ConcurrentRunsOfOneBuild: it opens its run's own watched file
// E2E_OPENS times, execs true, and makes one TLS exchange with the fake Anthropic endpoint on E2E_PORT through
// the host's libssl, whose capture probes the build's runs share.
const concurrentAgent = `import os, socket, ssl, subprocess, time
# The parent samples the active file-open program once every agent is waiting here.
with open("out/ready", "w"):
    pass
while not os.path.exists("out/start"):
    time.sleep(0.01)
path = "out/data"
for _ in range(int(os.environ["E2E_OPENS"])):
    os.close(os.open(path, os.O_RDONLY))
subprocess.run(["true"], check=True)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
body = b'{"model":"claude-opus-4-1","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}'
with socket.create_connection(("127.0.0.1", int(os.environ["E2E_PORT"]))) as raw:
    with ctx.wrap_socket(raw, server_hostname="api.anthropic.com") as s:
        s.sendall(b"POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nContent-Type: application/json\r\n"
                  b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        data = b""
        while not (b"\r\n\r\n" in data and data.endswith(b"}")):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
print("RESULT exchange", len(data), flush=True)
`

// concurrentContract pins capture: uprobe and carries a token budget, so a run whose capture could not start is
// refused (limits-check-doctor-cli R32) rather than run unmetered, and a run that does start is metered.
const concurrentContract = `version: 0
name: t2-concurrent
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
  watch: ["./out/data"]
exec:
  allow: ["python3", "true"]
net:
  allow: ["127.0.0.1:%d"]
env:
  pass: ["PATH", "HOME", "E2E_PORT", "E2E_OPENS"]
limits:
  tokens: 1000000
capture: uprobe
record: full
`

// anthropicReply is a whole Messages API answer with its usage, which the uprobe path meters.
const anthropicReply = `{"id":"msg_01","type":"message","role":"assistant","model":"claude-opus-4-1",` +
	`"content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","stop_sequence":null,` +
	`"usage":{"input_tokens":12,"output_tokens":3}}`

// concurrentE2EOpens is how many times each run's agent opens its watched file.
const concurrentE2EOpens = 2000

// TestTier2ConcurrentRunsOfOneBuild is capture-derive.md E26 and ADR 0026 run the way an operator runs it: 2, 8 and 32 `tego run --tier
// cgroup` of one build at once, as root, each with a token budget and capture: uprobe, each agent opening its own
// watched file, execing true and making one TLS exchange with a fake Anthropic endpoint. Every run starts (none is
// refused [capture-unavailable], none records kernel-record-unavailable or mechanism-unavailable, since each has
// its own record and capture ring), each ledger has its own opens and exec and none of another run's, and each
// run's exchange is captured once and metered: its ssl_response carries the reply's usage. Before, the second
// concurrent run of a build had no kernel record and no capture, and with a budget ran unmetered.
func TestTier2ConcurrentRunsOfOneBuild(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("tier 2 needs root: run as `sudo go test -tags integration,tegobpf` or `make vm-root-test`")
	}
	uid, gid, ok := sudoIDs()
	if !ok {
		t.Skip("a root `tego run` drops the agent to the sudo caller and refuses without SUDO_UID and SUDO_GID")
	}
	if _, err := bpfHash(); err != nil {
		t.Skipf("this test binary carries no BPF objects; the end-to-end run belongs to the tegobpf suite: %v", err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("the agent is a python3 script: %v", err)
	}
	base, err := os.MkdirTemp("", "tego-t2-conc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o711); err != nil {
		t.Fatal(err)
	}
	// The testhooks build prints each start phase's time under TEGO_TEST_PHASE_TIMING (internal/platform/startphase),
	// so a round logs what its Prepares took apart from the agents' own work.
	bin := buildTegoWithTags(t, base, "tegobpf,tegotesthooks")
	requireTier(t, bin, "cgroup")
	_, resolverSetting, _ := machineResolver(t)
	ln, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{anthropicCert(t)}})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveAnthropic(ln)
	port := ln.Addr().(*net.TCPAddr).Port
	for _, n := range []int{2, 8, 32} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			concurrentE2E(t, bin, python, base, resolverSetting, port, uid, gid, n)
		})
	}
}

// logPhases logs, for a round of n runs, each start phase's slowest and median time across the runs, from the
// "tego-phase <name> <us>" lines a testhooks build writes to each run's stderr. enforce.prepare is the backend's
// Prepare (the plane's compile, fill and slot header included); its slowest is when the round's last Prepare ended,
// since the runs start together.
func logPhases(t *testing.T, n int, stderrs []string) {
	t.Helper()
	phases := map[string][]time.Duration{}
	var names []string
	for _, s := range stderrs {
		for _, line := range strings.Split(s, "\n") {
			f := strings.Fields(line)
			if len(f) != 3 || f[0] != "tego-phase" {
				continue
			}
			us, err := strconv.ParseInt(f[2], 10, 64)
			if err != nil {
				continue
			}
			if _, seen := phases[f[1]]; !seen {
				names = append(names, f[1])
			}
			phases[f[1]] = append(phases[f[1]], time.Duration(us)*time.Microsecond)
		}
	}
	for _, name := range names {
		d := phases[name]
		slices.Sort(d)
		t.Logf("%d runs: phase %s: %d timed, slowest %v, median %v", n, name, len(d),
			d[len(d)-1].Round(time.Millisecond), d[len(d)/2].Round(time.Millisecond))
	}
}

// concurrentE2E is one round of TestTier2ConcurrentRunsOfOneBuild with n runs.
func concurrentE2E(t *testing.T, bin, python, base, resolverSetting string, port, uid, gid, n int) {
	type run struct {
		project, ledger, cfg string
		stdout, stderr       strings.Builder
		err                  error
		done                 chan struct{}
	}
	runs := make([]*run, n)
	for i := range n {
		dir := filepath.Join(base, fmt.Sprintf("r%d-%d", n, i))
		r := &run{project: filepath.Join(dir, "project"), ledger: filepath.Join(dir, "ledger"), cfg: filepath.Join(dir, "config.yaml"), done: make(chan struct{})}
		if err := os.MkdirAll(filepath.Join(r.project, "out"), 0o755); err != nil {
			t.Fatal(err)
		}
		for name, content := range map[string]string{
			"agent.py":   concurrentAgent,
			"agent.yaml": fmt.Sprintf(concurrentContract, port),
			"out/data":   "x",
		} {
			if err := os.WriteFile(filepath.Join(r.project, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := filepath.Walk(r.project, func(p string, _ os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			return os.Lchown(p, uid, gid)
		}); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o711); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(r.ledger, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(r.cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\nresolver: %s\n", r.ledger,
			resolverSetting)), 0o644); err != nil {
			t.Fatal(err)
		}
		runs[i] = r
	}
	// Ten minutes: the round of 32 takes 33–108 s on a quiet host and 2–5 min with 16–48% steal (measured
	// 2026-09-29), so a hang still fails well inside the suite while a starved but live round finishes.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	// Every run's watched-file opens wait on every run's fanotify group, since all n mark the one mount the
	// projects share: n×n×concurrentE2EOpens permission events a round, which the guest's vCPUs answer. The round's
	// time and the share of it the host took from the guest (steal) are logged, so a round that ran past the bound
	// on a host with no CPU to spare is told from one that hung.
	total0, steal0 := cpuTimes()
	started := time.Now()
	defer func() {
		total1, steal1 := cpuTimes()
		share := 0.0
		if total1 > total0 {
			share = 100 * float64(steal1-steal0) / float64(total1-total0)
		}
		t.Logf("%d runs took %v; the host took %.1f%% of the guest's CPU time (steal)", n,
			time.Since(started).Round(time.Millisecond), share)
	}()
	isoEnv := testutil.TegoEnv(t, base) // built here: the goroutines below must not call t.Fatal
	var wg sync.WaitGroup
	for _, r := range runs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer close(r.done)
			cmd := tegoRunCommand(ctx, bin, "run", "--tier", "cgroup", filepath.Join(r.project, "agent.yaml"),
				"--", python, "./agent.py")
			cmd.Dir = r.project
			cmd.Env = append(isoEnv[:len(isoEnv):len(isoEnv)], "TEGO_CONFIG="+r.cfg, "E2E_PORT="+strconv.Itoa(port),
				"E2E_OPENS="+strconv.Itoa(concurrentE2EOpens), "GOTRACEBACK=all", "TEGO_TEST_PHASE_TIMING=1")
			cmd.Stdout, cmd.Stderr = &r.stdout, &r.stderr
			r.err = cmd.Run()
		}()
	}
	// Every agent is now running but has not opened its watched file. Sampling after this barrier
	// includes the full round even on a cold build with no links before the first Prepare.
	var counter *fileOpenCounter
	var before, fileOpenSkips uint64
	counterErr := func() error {
		ticker := time.NewTicker(25 * time.Millisecond)
		defer ticker.Stop()
		for {
			ready := true
			for i, r := range runs {
				select {
				case <-r.done:
					return fmt.Errorf("run %d ended before the watched-open barrier", i)
				default:
				}
				if _, err := os.Stat(filepath.Join(r.project, "out", "ready")); err != nil {
					if !os.IsNotExist(err) {
						return err
					}
					ready = false
				}
			}
			if ready {
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-ticker.C:
			}
		}
		hash, err := bpfHash()
		if err != nil {
			return err
		}
		counter, err = openFileOpenCounter(filepath.Join(DefaultBPFFS, pinRoot, hash, pinLinks, bpf.ProgFileOpen))
		if err != nil {
			return err
		}
		before, err = counter.read()
		if err != nil {
			return err
		}
		for _, r := range runs {
			if err := os.WriteFile(filepath.Join(r.project, "out", "start"), nil, 0o644); err != nil {
				return err
			}
		}
		return nil
	}()
	if counterErr != nil {
		cancel()
	}
	wg.Wait()
	if counter != nil {
		if counterErr == nil {
			var after uint64
			after, counterErr = counter.read()
			if counterErr == nil {
				if after < before {
					counterErr = fmt.Errorf("file-open skip counter went backwards")
				} else {
					fileOpenSkips = after - before
				}
			}
		}
		counter.close()
	}
	if counterErr != nil {
		t.Errorf("round-wide file-open coverage uncertain: %v", counterErr)
	}
	stderrs := make([]string, len(runs))
	for i, r := range runs {
		stderrs[i] = r.stderr.String()
	}
	logPhases(t, n, stderrs)
	// Ended or stopped at the bound, no run of the round may leave its row behind: the tests after this one need
	// the build's last launcher out to find its run set empty.
	if liveRunRows(t) {
		t.Errorf("after %d runs of the build ended, its run set still holds a row of a live cgroup", n)
	}

	openCounts := make([]watchedOpenCount, 0, n)
	for i, r := range runs {
		if r.err != nil {
			t.Errorf("run %d: tego run: %v\nstdout:\n%s\nstderr:\n%s", i, r.err, r.stdout.String(), r.stderr.String())
			continue
		}
		events := runEvents(t, r.ledger)
		own := filepath.Join(r.project, "out", "data")
		opens, trues, sharedMisses := 0, 0, 0
		for _, e := range events {
			path, _ := e["path"].(string)
			if strings.HasPrefix(path, base+"/r") && !strings.HasPrefix(path, filepath.Dir(r.project)+"/") {
				t.Errorf("run %d recorded another run's %s %s", i, e["kind"], path)
			}
			switch {
			// The watched file's opens are the kernel record's lines, the ones this run's own ring carried. The exec
			// of true has one line (supervisor R7a): the supervisor's on the fanotify listener, and the kernel's,
			// named by the plane's rule, where a decision plane mode decides the run's execs (R7a as TIER3-PLAN T9
			// amended it). Failed PATH search candidates have observed kernel syscall outcomes without a plane
			// verdict; only an allowed exec needs the plane's policy attribution. Counting every allowed line
			// still catches duplicate supervisor/kernel records.
			case e["kind"] == "fs" && path == own && e["source"] == "kernel":
				c, _ := e["count"].(float64)
				opens += max(int(c), 1)
			case e["kind"] == "exec" && filepath.Base(path) == "true" && e["verdict"] == "allow" && e["source"] == "kernel" && e["mechanism"] != "plane":
				t.Errorf("run %d: a kernel exec line no decision plane named: %v", i, e)
			case e["kind"] == "exec" && filepath.Base(path) == "true" && e["verdict"] == "allow":
				trues++
			case e["kind"] == "gap":
				switch e["why"] {
				case "bpf-trampoline-miss/shared-build":
					count, _ := e["count"].(float64)
					sharedMisses += int(count)
				case "kernel-record-unavailable", "mechanism-unavailable", "budget-unmetered", "ringbuf-full",
					"ring-buffer-drop", "ringbuf-undrained", "bpf-trampoline-counter-unavailable":
					t.Errorf("run %d: gap %v", i, e)
				}
			}
		}
		// A preemptible kernel may skip the shared fexit program before it can identify this run. Require its
		// explicit shared-build count as well as the single round-wide file-open bound below. Without a
		// skip, every open is still required, and duplicates or unaccounted loss always fail.
		openCounts = append(openCounts, watchedOpenCount{opens, sharedMisses})
		if opens > concurrentE2EOpens || opens+sharedMisses < concurrentE2EOpens || trues != 1 {
			t.Errorf("run %d recorded %d opens and %d execs of true, with %d shared-build trampoline misses; want %d opens (or a covering miss bound) and 1 exec", i, opens, trues, sharedMisses, concurrentE2EOpens)
		}
		if opens != concurrentE2EOpens {
			t.Logf("run %d: %d watched opens missing; shared-build trampoline miss upper bound %d", i, concurrentE2EOpens-opens, sharedMisses)
		}
		start := findEvent(events, func(e map[string]any) bool { return e["kind"] == "run_start" })
		if start == nil || start["capture"] != "uprobe" {
			t.Errorf("run %d run_start %v, want capture uprobe", i, start)
		}
		var requests, metered int
		for _, e := range events {
			switch e["kind"] {
			case "ssl_request":
				requests++
			case "ssl_response":
				if u, ok := e["usage"].(map[string]any); ok && u["input"] == float64(12) && u["output"] == float64(3) {
					metered++
				}
			}
		}
		if requests != 1 || metered != 1 {
			t.Errorf("run %d captured %d requests and %d metered responses, want its one exchange once with its usage",
				i, requests, metered)
		}
		end := findEvent(events, func(e map[string]any) bool { return e["kind"] == "run_end" })
		if end == nil || end["reason"] != "exit" {
			t.Errorf("run %d run_end %v, want reason exit", i, end)
		}
	}
	if counterErr == nil {
		if err := watchedOpenCoverage(openCounts, fileOpenSkips); err != nil {
			t.Error(err)
		}
		t.Logf("round-wide shared file-open skipped executions: %d", fileOpenSkips)
	}

}

// serveAnthropic answers every HTTP/1.1 request on every TLS connection with anthropicReply, until ln closes.
func serveAnthropic(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
			r := bufio.NewReader(conn)
			length := 0
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if line == "\r\n" {
					break
				}
				if v, ok := strings.CutPrefix(strings.ToLower(line), "content-length:"); ok {
					length, _ = strconv.Atoi(strings.TrimSpace(v))
				}
			}
			if _, err := io.CopyN(io.Discard, r, int64(length)); err != nil {
				return
			}
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nRequest-Id: req_conc\r\n"+
				"Content-Length: "+strconv.Itoa(len(anthropicReply))+"\r\n\r\n"+anthropicReply)
		}()
	}
}

// anthropicCert is a throwaway certificate for api.anthropic.com.
func anthropicCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "api.anthropic.com"},
		DNSNames: []string{"api.anthropic.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
