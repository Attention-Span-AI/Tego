// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/net/dns/dnsmessage"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestTier2RunEndToEnd is tier 2's acceptance, run the way an operator runs it: an unmodified tego binary
// built with the BPF objects (`make build`), started as root under sudo, runs an ordinary contract with
// `tego run --tier cgroup` to the end. It names no tego binary in exec.allow and gives the agent python3
// alone. The agent then checks, from inside the run, what tier 2 is for:
//
//   - a write inside the contract succeeds and one outside it is refused, with a refusal line in the ledger;
//   - a deny_read path under a writable parent, which tier 1 leaves unenforced (enforce-landlock R4), is
//     refused by the fanotify listener with a source=fanotify line naming the entry;
//   - a DNS query to the resolver the machine uses reaches it: the supervisor admits it under net.resolver
//     and relays it on the agent's socket, and the kernel's connect4 must admit it too (§5 R5);
//   - a connect to a host the contract does not declare is refused;
//   - and the run's ledger carries the tier's own record (source=kernel lines) beside run_start's tier and
//     bpf_hash.
//
// Before the fixes this test pins, the run never started: the fanotify exec check refused the child stage's
// own exec of /proc/self/exe inside the run's cgroup (exit 125 at clone3), then /bin/sh and every dynamically
// linked binary by their resolved paths (exit 126), and with those admitted every DNS query met EPERM in the
// kernel because the run's resolvers never reached it.
//
// It runs as root with SUDO_UID set, which is what test/vm/root-suites.sh gives it in the KVM guest
// (`make vm-root-test`), and only in the tegobpf suite, since it builds the tagged binary itself.
func TestTier2RunEndToEnd(t *testing.T) {
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

	base, err := os.MkdirTemp("", "tego-t2-e2e-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	bin := buildTaggedTego(t, base)
	// A kernel without tier 2's hooks is not this test's subject: doctor's derivation is the one `tego run`
	// selects from, so its refusal is the run's, and the reason is what the skip reports. On the kernel the
	// guest boots by default, test/vm/root-suites.sh fails `doctor --require cgroup` on its own.
	requireTier(t, bin, "cgroup")

	// The project belongs to the sudo caller, as a real `sudo tego run` of the user's own project does, and
	// sits under a root-only directory the agent may pass through but not list. The ledger root and the
	// machine config sit beside it, root's: the agent can never rewrite its own record.
	if err := os.Chmod(base, 0o711); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(base, "project")
	secret := filepath.Join(project, "out", "secret")
	if err := os.MkdirAll(secret, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secret, "key"), []byte("s3cret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "agent.py"), []byte(e2eAgent), 0o644); err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(project, "agent.yaml")
	if err := os.WriteFile(contract, []byte(e2eContract), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := filepath.Walk(project, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	}); err != nil {
		t.Fatal(err)
	}
	ledgerRoot := filepath.Join(base, "ledger")
	if err := os.Mkdir(ledgerRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	resolver, resolverSetting, fake := machineResolver(t)
	cfg := filepath.Join(base, "config.yaml")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\nresolver: %s\n", ledgerRoot,
		resolverSetting)), 0o644); err != nil {
		t.Fatal(err)
	}

	// An undeclared destination with a listener behind it, so a refusal is the run's and not an empty port.
	undeclared, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer undeclared.Close()
	var accepted atomic.Int64
	go func() {
		for {
			c, err := undeclared.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	undeclaredPort := undeclared.Addr().(*net.TCPAddr).Port

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "run", "--tier", "cgroup", contract, "--", python, "./agent.py")
	cmd.Dir = project
	// GOTRACEBACK=all: a launcher aborted at the bound prints every goroutine (the agent never sees it, since
	// the contract passes it no such variable).
	cmd.Env = testutil.TegoEnv(t, base, "TEGO_CONFIG="+cfg, "E2E_RESOLVER="+resolver.String(),
		"E2E_PORT="+strconv.Itoa(undeclaredPort), "GOTRACEBACK=all")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	// A run that outlives the bound is described before it is killed: each of its threads' state and kernel
	// stack, then the launcher's goroutines, which SIGABRT writes to the stderr logged below; SIGKILL follows
	// if it has not exited. That is how the deadlock startFanotify now prevents was found: the stage in
	// fanotify_get_response, and the listener's goroutine runnable in a runtime that could not schedule it.
	cmd.Cancel = func() error {
		t.Logf("`tego run` still running after the bound; its processes:\n%s", stalledRun())
		return cmd.Process.Signal(syscall.SIGABRT)
	}
	cmd.WaitDelay = 15 * time.Second
	runErr := cmd.Run()
	t.Logf("tego run: %v\nstdout:\n%s\nstderr:\n%s", runErr, stdout.String(), stderr.String())
	if runErr != nil {
		t.Fatalf("`tego run --tier cgroup` of an ordinary contract did not run to completion: %v", runErr)
	}
	results := agentResults(t, stdout.String())

	// What the agent saw.
	if got := results["write-inside"]; got != "ok" {
		t.Errorf("a write inside ./out/: %q, want ok", got)
	}
	if got := results["write-outside"]; !strings.HasPrefix(got, "refused") {
		t.Errorf("a write outside the contract: %q, want refused", got)
	}
	if _, err := os.Stat(filepath.Join(project, "forbidden.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("forbidden.txt exists after a refused write (%v)", err)
	}
	// The deny_read under a writable parent, which tier 1 leaves unenforced, is the listener's (EPERM, a
	// source=fanotify line) where the run decides through fanotify, the decision plane's (EACCES, a source=kernel
	// line with the plane's reason) where doctor selected a plane mode (TIER3-PLAN T6).
	plane := planeSelected(t, bin, "")
	wantRead, wantSource := "refused errno=1", "fanotify"
	if plane != PlaneFanotify {
		wantRead, wantSource = "refused errno=13", "kernel"
	}
	if got := results["deny-read"]; got != wantRead {
		t.Errorf("a read of the deny_read path under a writable parent, deciding through %s: %q, want %q "+
			"(tier 1 cannot enforce that entry)", plane, got, wantRead)
	}
	if got := results["dns"]; !strings.HasPrefix(got, "sent") {
		t.Errorf("a DNS query to the machine's resolver %s: %q, want it sent: the kernel must admit what the "+
			"supervisor admits under net.resolver", resolver, got)
	} else if fake {
		if !strings.Contains(got, "answer=192.0.2.77") {
			t.Errorf("a DNS query to this test's resolver at %s: %q, want its answer 192.0.2.77", resolver, got)
		}
	} else {
		t.Logf("the machine's own resolver at %s answered: %s", resolver, got)
	}
	if got := results["connect-undeclared"]; !strings.HasPrefix(got, "refused") {
		t.Errorf("a connect to undeclared 127.0.0.1:%d: %q, want refused", undeclaredPort, got)
	}
	if n := accepted.Load(); n != 0 {
		t.Errorf("the undeclared listener accepted %d connection(s)", n)
	}

	// What the ledger says.
	events := runEvents(t, ledgerRoot)
	start := findEvent(events, func(e map[string]any) bool { return e["kind"] == "run_start" })
	if start == nil {
		t.Fatal("no run_start line")
	}
	if start["tier"] != "cgroup" || start["bpf_hash"] == "" || start["bpf_hash"] == nil {
		t.Errorf("run_start tier %v bpf_hash %v, want tier cgroup and the pins' hash", start["tier"], start["bpf_hash"])
	}
	// The tier's own record: the ring buffer this build pinned is drained into the run's ledger.
	if findEvent(events, func(e map[string]any) bool { return e["source"] == "kernel" }) == nil {
		t.Error("no source=kernel line: the tier-2 recorder wrote nothing to the run's ledger")
	}
	forbidden := filepath.Join(project, "forbidden.txt")
	if findEvent(events, func(e map[string]any) bool {
		return e["kind"] == "fs" && e["verdict"] == "refused" && e["reason"] == "write-outside-contract" &&
			e["path"] == forbidden
	}) == nil {
		t.Errorf("no refused fs line with reason write-outside-contract for %s", forbidden)
	}
	key := filepath.Join(secret, "key")
	if findEvent(events, func(e map[string]any) bool {
		return e["kind"] == "fs" && e["source"] == wantSource && e["verdict"] == "refused" &&
			e["reason"] == "read-denied" && e["rule"] == "fs.deny_read[./out/secret/]" && e["path"] == key
	}) == nil {
		t.Errorf("no source=%s read-denied line naming fs.deny_read[./out/secret/] for %s", wantSource, key)
	}
	dst := netip.AddrPortFrom(resolver, 53).String()
	if findEvent(events, func(e map[string]any) bool {
		return e["kind"] == "net" && e["rule"] == "net.resolver" && e["verdict"] == "allow" && e["dst"] == dst
	}) == nil {
		t.Errorf("no net.resolver allow line for %s", dst)
	}
	undeclaredDst := "127.0.0.1:" + strconv.Itoa(undeclaredPort)
	if findEvent(events, func(e map[string]any) bool {
		return e["kind"] == "net" && e["verdict"] == "refused" && e["reason"] == "net-not-allowed" && e["dst"] == undeclaredDst
	}) == nil {
		t.Errorf("no refused net line for %s", undeclaredDst)
	}
	if findEvent(events, func(e map[string]any) bool {
		return e["kind"] == "exec" && e["verdict"] == "refused" && strings.Contains(fmt.Sprint(e["path"]), "tego")
	}) != nil {
		t.Error("the ledger records a refused exec of the launcher binary")
	}
	end := findEvent(events, func(e map[string]any) bool { return e["kind"] == "run_end" })
	if code, _ := end["exit_code"].(float64); end == nil || end["reason"] != "exit" || code != 0 {
		t.Errorf("run_end %v, want reason exit with exit code 0 (the field is omitted when 0)", end)
	}
}

// e2eContract is an ordinary contract: one write directory with a deny_read entry beneath it, one binary, no
// network beyond what the runtime admits on its own (the machine's resolver), and nothing that names tego.
const e2eContract = `version: 0
name: t2-e2e
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
  deny_read: ["./out/secret/"]
exec:
  allow: ["python3"]
net:
  allow: []
env:
  pass: ["PATH", "HOME", "E2E_RESOLVER", "E2E_PORT"]
record: full
`

// e2eAgent reports each check as one "RESULT <name> <outcome>" line on stdout. Its DNS query is the one a
// stub resolver makes: a connected UDP socket to the server on port 53, one A question.
const e2eAgent = `import os, socket, struct

def result(name, outcome):
    print("RESULT", name, outcome, flush=True)

def refused(e):
    return "refused errno=%d" % e.errno

try:
    with open("out/ok.txt", "w") as f:
        f.write("ok")
    result("write-inside", "ok")
except OSError as e:
    result("write-inside", refused(e))

try:
    with open("forbidden.txt", "w") as f:
        f.write("x")
    result("write-outside", "allowed")
except OSError as e:
    result("write-outside", refused(e))

try:
    with open("out/secret/key") as f:
        f.read()
    result("deny-read", "allowed")
except OSError as e:
    result("deny-read", refused(e))

name = b"".join(bytes([len(p)]) + p.encode() for p in "tego-e2e.test".split(".")) + b"\0"
query = struct.pack(">HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + name + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET6 if ":" in os.environ["E2E_RESOLVER"] else socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.settimeout(5)
    s.connect((os.environ["E2E_RESOLVER"], 53))
    s.send(query)
    try:
        d = s.recv(512)
        rid, rcode, an = struct.unpack(">H", d[:2])[0], d[3] & 15, struct.unpack(">H", d[6:8])[0]
        answer = ".".join(str(b) for b in d[-4:]) if an else "none"
        result("dns", "sent id=%x rcode=%d answer=%s" % (rid, rcode, answer))
    except socket.timeout:
        result("dns", "sent no-answer")
except OSError as e:
    result("dns", refused(e))

try:
    socket.create_connection(("127.0.0.1", int(os.environ["E2E_PORT"])), timeout=5).close()
    result("connect-undeclared", "allowed")
except OSError as e:
    result("connect-undeclared", refused(e))
`

// sudoIDs is the caller a root `tego run` drops the agent to.
func sudoIDs() (uid, gid int, ok bool) {
	u, err1 := strconv.Atoi(os.Getenv("SUDO_UID"))
	g, err2 := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err1 != nil || err2 != nil || u <= 0 {
		return 0, 0, false
	}
	return u, g, true
}

// buildTaggedTego builds cmd/tego as `make build` does (CGO off, -tags tegobpf) plus tegotesthooks, whose
// chain anchor and own log the caller points into its own directory with testutil.TegoEnv: a product build
// anchors in the invoking user's ~/.tego/chain.log, so a root test run by `sudo go test` would append to the
// developer's own anchor. In the KVM guest test/vm/go-shim.sh serves the same build, made on the host from the
// same tree.
func buildTaggedTego(t *testing.T, dir string) string {
	t.Helper()
	return buildTegoWithTags(t, dir, "tegobpf,tegotesthooks")
}

// buildTegoWithTags is buildTaggedTego with the build tags named (comma-separated), tegobpf among them.
func buildTegoWithTags(t *testing.T, dir, tags string) string {
	t.Helper()
	out := filepath.Join(dir, "tego")
	cmd := exec.Command("go", "build", "-tags", tags, "-trimpath", "-o", out, "github.com/attention-span-ai/tego/cmd/tego")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("cannot build the tegobpf tego binary: %v: %s", err, b)
	}
	if err := os.Chmod(out, 0o755); err != nil {
		t.Fatal(err)
	}
	return out
}

// isolatedTego is exec.Command for a tego that buildTaggedTego or buildPlaneTego built, for a command the test
// starts before it has a machine config of its own (doctor, asked whether this machine offers tier cgroup and which
// plane it selects). It gets the isolation the test's runs get, in a directory of its own: a machine config naming a
// ledger root there, and testutil.TegoEnv's chain anchor and own-log home beside it. A test build refuses a machine
// config whose ledger root lies inside the invoking user's own ~/.tego, the built-in ~/.tego/runs included
// (identity-config.md R27), and under sudo that user is the sudo caller: given no machine config, doctor exited 125
// and every test that asked it first skipped as though the machine offered no tier cgroup.
func isolatedTego(t *testing.T, bin string, args ...string) *exec.Cmd {
	t.Helper()
	dir, err := os.MkdirTemp("", "tego-iso-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	ledger := filepath.Join(dir, "ledger")
	if err := os.Mkdir(ledger, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte(fmt.Sprintf("version: 0\nledger_root: %s\n", ledger)), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Env = testutil.TegoEnv(t, dir, "TEGO_CONFIG="+cfg)
	return cmd
}

// requireTier asks bin's doctor, isolated, whether this machine offers tier, and skips the test only on doctor's
// answer that it does not (testutil.RequireTier): any other failure of that command fails the test, so a harness
// fault such as the one isolatedTego fixed cannot pass for a machine without the tier again.
func requireTier(t *testing.T, bin, tier string) {
	t.Helper()
	testutil.RequireTier(t, isolatedTego(t, bin, "doctor", "--require", tier), tier)
}

// machineResolver is the resolver the machine uses and the machine config's `resolver:` value naming it:
// /etc/resolv.conf's first nameserver under `resolver: auto`, or, on a machine with no resolv.conf (the KVM
// guest), 127.0.0.1, which is where glibc's stub resolver sends a query when the file names none
// (resolv.conf(5)), named explicitly. When nothing already listens there, the test answers on it itself and
// fake is true; otherwise the machine's own server answers, whatever it says.
func machineResolver(t *testing.T) (addr netip.Addr, setting string, fake bool) {
	t.Helper()
	setting = "auto"
	if rs := dns.SystemResolvers(); len(rs) > 0 {
		addr = rs[0].Addr()
	} else {
		addr, setting = netip.MustParseAddr("127.0.0.1"), `["127.0.0.1"]`
	}
	pc, err := net.ListenPacket("udp", netip.AddrPortFrom(addr, 53).String())
	if err != nil {
		t.Logf("the resolver %s:53 is the machine's own (%v); any answer it gives will do", addr, err)
		return addr, setting, false
	}
	t.Cleanup(func() { _ = pc.Close() })
	go serveDNS(pc)
	return addr, setting, true
}

// serveDNS answers every A question with 192.0.2.77 and every other question with no data, until pc closes.
func serveDNS(pc net.PacketConn) {
	buf := make([]byte, 512)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		var p dnsmessage.Parser
		h, err := p.Start(buf[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil {
			continue
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: h.ID, Response: true, RecursionAvailable: true})
		_ = b.StartQuestions()
		_ = b.Question(q)
		_ = b.StartAnswers()
		if q.Type == dnsmessage.TypeA {
			_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60},
				dnsmessage.AResource{A: [4]byte{192, 0, 2, 77}})
		}
		msg, err := b.Finish()
		if err != nil {
			continue
		}
		_, _ = pc.WriteTo(msg, from)
	}
}

// agentResults reads the agent's RESULT lines.
func agentResults(t *testing.T, stdout string) map[string]string {
	t.Helper()
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(stdout))
	for sc.Scan() {
		f := strings.SplitN(sc.Text(), " ", 3)
		if len(f) == 3 && f[0] == "RESULT" {
			out[f[1]] = f[2]
		}
	}
	return out
}

// runEvents reads the one run's ledger under root.
func runEvents(t *testing.T, root string) []map[string]any {
	t.Helper()
	var events []map[string]any
	eachRunEvent(t, root, func(e map[string]any) { events = append(events, e) })
	return events
}

// eachRunEvent hands each line of the one run's ledger under root to fn, in order, holding one line at a time: a
// run that writes hundreds of thousands of lines is checked without the whole ledger in memory.
func eachRunEvent(t *testing.T, root string, fn func(map[string]any)) {
	t.Helper()
	runs, err := filepath.Glob(filepath.Join(root, "*", "events.jsonl"))
	if err != nil || len(runs) != 1 {
		t.Fatalf("ledgers under %s: %v (%v), want exactly one run", root, runs, err)
	}
	f, err := os.Open(runs[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<16)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
		if len(bytes.TrimSpace(line)) > 0 || !errors.Is(err, io.EOF) {
			var e map[string]any
			if err := json.Unmarshal(line, &e); err != nil {
				t.Fatalf("ledger line %q: %v", line, err)
			}
			fn(e)
		}
		if err != nil {
			return
		}
	}
}

// stalledRun describes a run that did not end in time: each process of tego's own and of its cgroups, with
// every thread's scheduler state, wait channel, current syscall and kernel stack. It reads /proc alone: an
// open on a mount the run's permission group marks can wait on the very listener that stalled. Anything it
// cannot read is left out, since it is written for a failure already being reported.
func stalledRun() string {
	var b strings.Builder
	read := func(format string, a ...any) string {
		data, _ := os.ReadFile(fmt.Sprintf(format, a...))
		return strings.TrimSpace(string(data))
	}
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil {
			continue
		}
		comm, cg := read("/proc/%d/comm", pid), read("/proc/%d/cgroup", pid)
		if comm != "tego" && !strings.Contains(cg, "tego") {
			continue
		}
		fmt.Fprintf(&b, "pid %d %s [%s] %s\n", pid, comm,
			strings.ReplaceAll(read("/proc/%d/cmdline", pid), "\x00", " "), cg)
		tasks, _ := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
		for _, task := range tasks {
			tid := task.Name()
			state := ""
			if f := strings.Fields(read("/proc/%d/task/%s/stat", pid, tid)); len(f) > 2 {
				state = f[2]
			}
			fmt.Fprintf(&b, "  task %s %s wchan=%s syscall=%s\n", tid, state,
				read("/proc/%d/task/%s/wchan", pid, tid), read("/proc/%d/task/%s/syscall", pid, tid))
			for i, frame := range strings.Split(read("/proc/%d/task/%s/stack", pid, tid), "\n") {
				if i == 8 || frame == "" {
					break
				}
				fmt.Fprintf(&b, "    %s\n", frame)
			}
		}
	}
	return b.String()
}

// tegoRunCommand is exec.CommandContext for a test's `tego run`, cancelled the way an operator stops a run: a
// SIGTERM, which the launcher answers by stopping its agent within stop_grace and tearing the run down
// (runtime-launch R9), and a SIGKILL only once WaitDelay is past that. exec.CommandContext's own cancel is a
// SIGKILL of the launcher alone, and a launcher that dies leaves its run's scope and run-set rows for the next
// run's sweep (ADR 0020). In this test binary no sweep comes, so the build stayed pinned for every later test,
// and one that checks the last launcher out removes it (TestSecondLauncherAdoptsTheBuildsPinnedObjects) failed
// after a round of TestTier2ConcurrentRunsOfOneBuild ran past its bound on a host with no CPU to spare.
func tegoRunCommand(ctx context.Context, bin string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = config.DefaultStopGrace + 20*time.Second
	return cmd
}

// liveRunRows reports whether the pinned run set of this test binary's build holds a row for a cgroup that
// exists: a run of the build that is still alive, or one whose launcher died without removing it. A build that
// is not pinned holds none.
func liveRunRows(t *testing.T) bool {
	t.Helper()
	hash, err := bpfHash()
	if err != nil {
		t.Fatal(err)
	}
	pins, err := newPinLayout(DefaultBPFFS, hash)
	if err != nil {
		t.Fatal(err)
	}
	m, err := ebpf.LoadPinnedMap(filepath.Join(pins.Maps, ebpfbindings.MapRunSet), nil)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	live, err := runSetLive(m, identity.SystemCgroupRoot)
	if err != nil {
		t.Fatal(err)
	}
	return live
}

// cpuTimes is the machine's total and steal jiffies, from /proc/stat's cpu line. Steal is the time the host ran
// something else while a vCPU of this guest had work: what tells a starved guest from a hung run.
func cpuTimes() (total, steal uint64) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0
	}
	line, _, _ := strings.Cut(string(data), "\n")
	f := strings.Fields(line)
	if len(f) < 9 || f[0] != "cpu" {
		return 0, 0
	}
	// user nice system idle iowait irq softirq steal; guest and guest_nice are inside user and nice already.
	for i, v := range f[1:9] {
		n, _ := strconv.ParseUint(v, 10, 64)
		total += n
		if i == 7 {
			steal = n
		}
	}
	return total, steal
}

// findEvent returns the first event match accepts, or nil.
func findEvent(events []map[string]any, match func(map[string]any) bool) map[string]any {
	for _, e := range events {
		if match(e) {
			return e
		}
	}
	return nil
}
