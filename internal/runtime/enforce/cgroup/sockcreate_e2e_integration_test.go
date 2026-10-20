// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// sockCreateIOUringContract declares io_uring: true under a net: section; the agent's arguments are added per run.
const sockCreateIOUringContract = `version: 0
name: sockcreate-iouring
command: ["python3", "./agent.py"]
fs:
  write: ["./out/"]
exec:
  allow: ["python3", "./bin/uringsock"]
net:
  allow: []
io_uring: true
env:
  pass: ["PATH", "HOME"]
record: full
`

// sockCreateIOUringAgent makes each socket of its argument list through io_uring in each submission mode, and one SCTP
// socket through socket(2), the seccomp filter's path, as the control. It also sets TCP_ULP "smc" on a TCP socket
// through io_uring's SOCKET_URING_OP_SETSOCKOPT in each mode, and through setsockopt(2) (ADR 0018 (7)), saying the
// family the socket ended with.
const sockCreateIOUringAgent = `import socket, subprocess, sys
for mode in ("inline", "async", "sqpoll"):
    for spec in sys.argv[1:]:
        name, f, t, p = spec.split(":")
        r = subprocess.run(["./bin/uringsock", name + "-" + mode, f, t, p, mode], capture_output=True, text=True)
        print(r.stdout.strip() or "RESULT %s-%s failed exit=%d %s" % (name, mode, r.returncode, r.stderr.strip()), flush=True)
    r = subprocess.run(["./bin/uringsock", "ulp-" + mode, "ulp", "smc", mode], capture_output=True, text=True)
    print(r.stdout.strip() or "RESULT ulp-%s failed exit=%d %s" % (mode, r.returncode, r.stderr.strip()), flush=True)
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM, 132).close()
    print("RESULT syscall-sctp ok", flush=True)
except OSError as e:
    print("RESULT syscall-sctp refused errno=%d" % e.errno, flush=True)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
try:
    s.setsockopt(socket.IPPROTO_TCP, 31, b"smc\0")
    print("RESULT syscall-ulp ok domain=%d" % s.getsockopt(socket.SOL_SOCKET, 39), flush=True)
except OSError as e:
    print("RESULT syscall-ulp refused errno=%d domain=%d" % (e.errno, s.getsockopt(socket.SOL_SOCKET, 39)), flush=True)
s.close()
`

// uringModes are the io_uring submission modes the agent makes each socket in (internal/testutil/uring).
var uringModes = []string{"inline", "async", "sqpoll"}

// uringCell is one socket the agent makes through io_uring.
type uringCell struct {
	name string
	c    sockTriple
}

var uringCells = []uringCell{
	{"sctp", sockTriple{unix.AF_INET, unix.SOCK_STREAM, ipprotoSCTP}},
	{"udplite", sockTriple{unix.AF_INET, unix.SOCK_DGRAM, ipprotoUDPLite}},
	{"mptcp", sockTriple{unix.AF_INET, unix.SOCK_STREAM, ipprotoMPTCP}},
	{"smc", sockTriple{unix.AF_INET, unix.SOCK_STREAM, ipprotoSMC}},
	{"sctp6", sockTriple{unix.AF_INET6, unix.SOCK_SEQPACKET, ipprotoSCTP}},
	{"tcp", sockTriple{unix.AF_INET, unix.SOCK_STREAM, 0}},
	{"vsock", sockTriple{afVsock, unix.SOCK_STREAM, 0}},
}

// isolatedEnv is a test build's environment for project p: its config's ledger root, its own chain anchor and own-log
// home, so the binary never reaches the invoking user's ~/.tego (a test build refuses it).
func isolatedEnv(p *planeProject, extra ...string) []string {
	return append(append(os.Environ(), "TEGO_CONFIG="+p.cfg, "TEGO_TEST_CHAIN_ANCHOR="+filepath.Join(p.base, "chain.log"),
		"TEGO_TEST_OWN_LOG_HOME="+filepath.Join(p.base, "home")), extra...)
}

// isolatedPlaneSelected is the plane doctor selects for tier cgroup under TEGO_TEST_PLANE=pin, asked with p's
// isolation: lsm, fmod_ret or fanotify.
func isolatedPlaneSelected(t *testing.T, bin string, p *planeProject, pin string) string {
	t.Helper()
	cmd := exec.Command(bin, "doctor", "--json")
	cmd.Env = isolatedEnv(p, "TEGO_TEST_PLANE="+pin)
	out, _ := cmd.Output() // a finding exits non-zero with the report on stdout
	var rep struct {
		Plane *struct {
			Selected string `json:"selected"`
		} `json:"plane"`
	}
	if err := json.Unmarshal(out, &rep); err != nil || rep.Plane == nil {
		t.Fatalf("tego doctor --json under TEGO_TEST_PLANE=%s: %v\n%s", pin, err, out)
	}
	return rep.Plane.Selected
}

// TestIOUringSocketsMeetTheKernelBackstops is ADR 0018 PR 2's io_uring cells through the whole of `tego run --tier
// cgroup`. An inet socket outside ADR 0018's allowlist made through IORING_OP_SOCKET, which the seccomp filter never
// sees, is refused in the kernel inline, from an io-wq worker (IOSQE_ASYNC) and from the SQPOLL thread alike, with
// exactly one refused line each and no supervisor line:
//
//   - On the fanotify fallback a product build keeps io_uring ENOSYS (the control run, and the warning naming why). A
//     test build's seam (TEGO_TEST_FALLBACK_IOURING, A-0018-5) admits it to show cgroup/sock_create refusing SCTP,
//     UDP-Lite, MPTCP 262 and SMC 256 with EPERM, wherever this kernel makes them, each line with mechanism cgroup. A
//     TCP socket is made, and AF_VSOCK is not refused by Tego there: the residual that keeps io_uring refused on the
//     fallback in a product build.
//   - In a plane mode io_uring is admitted in a product build and the plane's socket_create, which runs in
//     __sock_create before inet_create, refuses every one of them, AF_VSOCK too, with EACCES and its own line; the
//     cgroup/sock_create attached beside it never sees them, so there is no second line.
//
// socket(2) of SCTP, the control, is the supervisor's EPROTONOSUPPORT and line in every mode.
//
// ADR 0018 (7): TCP_ULP "smc", which with the smc module loaded turned an admitted TCP socket into
// AF_SMC in place, is refused on both of its paths in every mode, and the socket stays AF_INET: through setsockopt(2)
// by the supervisor (ENOENT, its line), and through io_uring's SOCKET_URING_OP_SETSOCKOPT, inline, async and through
// SQPOLL, by cgroup/setsockopt (EPERM, one mechanism-cgroup line each), which no plane hook precedes.
//
// Each run's run_start says what it bounds (A-0018-10): net_guarantees.socket_families and the capability row
// net.socket_families are true in a plane mode and on the fallback with io_uring refused, and false on the fallback
// under the seam, where the filter never sees an IORING_OP_SOCKET and nothing decides one of another family. Where LSM
// mode passes, the plane cells run once more at tier bpflsm (`tego run --tier bpflsm`), which attaches the same
// cgroup programs beside its plane.
func TestIOUringSocketsMeetTheKernelBackstops(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("tier cgroup needs root: run as `sudo go test -tags integration,tegobpf` or `make vm-root-test`")
	}
	uid, gid, ok := sudoIDs()
	if !ok {
		t.Skip("a root `tego run` drops the agent to the sudo caller and refuses without SUDO_UID and SUDO_GID")
	}
	if _, err := bpfHash(); err != nil {
		t.Skipf("this test binary carries no BPF objects; the run belongs to the tegobpf suite: %v", err)
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skipf("the agent is a python3 script: %v", err)
	}
	dir := t.TempDir()
	bin := buildPlaneTego(t, dir)
	uringsock := filepath.Join(dir, "uringsock")
	build := exec.Command("go", "build", "-o", uringsock, "github.com/attention-span-ai/tego/test/workloads/uringsock")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build the io_uring workload: %v: %s", err, b)
	}
	sock, err := os.ReadFile(uringsock)
	if err != nil {
		t.Fatal(err)
	}
	var args []string
	for _, c := range uringCells {
		args = append(args, fmt.Sprintf("%s:%d:%d:%d", c.name, c.c.family, c.c.typ, c.c.protocol))
	}
	contract := strings.Replace(sockCreateIOUringContract, `command: ["python3", "./agent.py"]`,
		`command: ["python3", "./agent.py", "`+strings.Join(args, `", "`)+`"]`, 1)
	project := func(t *testing.T) *planeProject {
		return newPlaneProject(t, uid, gid, map[string]string{"agent.py": sockCreateIOUringAgent, "agent.yaml": contract,
			"bin/uringsock": string(sock)}, []string{"out"}, nil)
	}
	probe := project(t)
	doctor := exec.Command(bin, "doctor", "--require", "cgroup")
	doctor.Env = isolatedEnv(probe)
	testutil.RequireTier(t, doctor, "cgroup")
	uringOff := ""
	if b, err := os.ReadFile("/proc/sys/kernel/io_uring_disabled"); err == nil && strings.TrimSpace(string(b)) != "0" {
		uringOff = strings.TrimSpace(string(b))
	}
	modes := []string{PlaneFanotify}
	for _, m := range []string{"lsm", "fmod_ret"} {
		if got := isolatedPlaneSelected(t, bin, probe, m); got == m {
			modes = append(modes, m)
		} else {
			t.Logf("plane mode %s is not available here (doctor selects %s under that pin)", m, got)
		}
	}
	if slices.Contains(modes, "lsm") {
		modes = append(modes, "bpflsm") // tier 3, decided by the plane in LSM mode
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			if uringOff != "" {
				t.Skipf("kernel.io_uring_disabled is %s here: io_uring_setup is EPERM to the agent whatever the run admits", uringOff)
			}
			switch mode {
			case PlaneFanotify:
				fallbackIOUringCells(t, bin, project(t), project(t))
			case "bpflsm":
				planeIOUringCells(t, bin, "bpflsm", "lsm", project(t))
			default:
				planeIOUringCells(t, bin, "cgroup", mode, project(t))
			}
		})
	}
}

// uringRun runs the contract in p at tier cgroup under the plane pin with extra environment and returns the agent's
// results, the run's ledger and its output.
func uringRun(t *testing.T, bin string, p *planeProject, pin string, extra ...string) (map[string]string, []map[string]any, string) {
	t.Helper()
	return uringRunAt(t, bin, p, "cgroup", pin, extra...)
}

// uringRunAt is uringRun at tier.
func uringRunAt(t *testing.T, bin string, p *planeProject, tier, pin string, extra ...string) (map[string]string, []map[string]any, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var out bytes.Buffer
	cmd := p.runAt(ctx, bin, tier, "agent.yaml", pin, &out)
	cmd.Env = append(cmd.Env, extra...)
	err := cmd.Run()
	t.Logf("tego run (--tier %s, %s %v): %v\n%s", tier, pin, extra, err, out.String())
	if err != nil {
		t.Fatalf("the run did not complete: %v\nledger:\n%s", err, ledgerDump(p.ledger))
	}
	return agentResults(t, out.String()), runEvents(t, p.ledger), out.String()
}

// socketLines counts the run's refused socket lines for target whose mechanism prints as mechanism ("<nil>" for a
// line with none, the supervisor's).
func socketLines(events []map[string]any, target, mechanism string) int {
	n := 0
	for _, e := range events {
		if e["kind"] == "refused" && e["op"] == "socket" && e["target"] == target && fmt.Sprint(e["mechanism"]) == mechanism {
			n++
		}
	}
	return n
}

// ulpTarget is the refused line's target for TCP_ULP "smc", from the supervisor or from cgroup/setsockopt.
var ulpTarget = record.SocketOption(unix.SOL_TCP, unix.TCP_ULP, []byte("smc"), true)

// sockoptLines counts the run's refused setsockopt lines for TCP_ULP "smc" whose mechanism prints as mechanism.
func sockoptLines(events []map[string]any, mechanism string) int {
	n := 0
	for _, e := range events {
		if e["kind"] == "refused" && e["op"] == "setsockopt" && e["target"] == ulpTarget && fmt.Sprint(e["mechanism"]) == mechanism {
			n++
		}
	}
	return n
}

// wantSyscallControl checks the socket(2) SCTP control, the supervisor's EPROTONOSUPPORT and its one line, and the
// setsockopt(2) TCP_ULP "smc" cell, the supervisor's ENOENT and its one line, the socket still AF_INET.
func wantSyscallControl(t *testing.T, res map[string]string, events []map[string]any) {
	t.Helper()
	if res["syscall-sctp"] != "refused errno="+strconv.Itoa(int(unix.EPROTONOSUPPORT)) {
		t.Errorf("socket(2) of SCTP: %q, want the supervisor's EPROTONOSUPPORT", res["syscall-sctp"])
	}
	if n := socketLines(events, record.SocketTriple(unix.AF_INET, unix.SOCK_STREAM, ipprotoSCTP), "<nil>"); n != 1 {
		t.Errorf("socket(2) of SCTP: %d supervisor lines, want 1", n)
	}
	if want := fmt.Sprintf("refused errno=%d domain=%d", unix.ENOENT, unix.AF_INET); res["syscall-ulp"] != want {
		t.Errorf("setsockopt(2) of TCP_ULP smc: %q, want the supervisor's %q", res["syscall-ulp"], want)
	}
	if n := sockoptLines(events, "<nil>"); n != 1 {
		t.Errorf("setsockopt(2) of TCP_ULP smc: %d supervisor lines, want 1", n)
	}
}

// wantURingULP checks the io_uring TCP_ULP "smc" cells, which cgroup/setsockopt refuses in every mode where io_uring is
// admitted (EPERM, one mechanism-cgroup line each, the socket still AF_INET). A kernel without the socket command
// (before 6.7) completes them with EOPNOTSUPP, and then nothing is set and nothing recorded.
func wantURingULP(t *testing.T, res map[string]string, events []map[string]any) {
	t.Helper()
	if res["ulp-inline"] == "refused errno="+strconv.Itoa(int(unix.EOPNOTSUPP)) {
		t.Logf("this kernel has no SOCKET_URING_OP_SETSOCKOPT: the io_uring TCP_ULP cells have no path to refuse")
		if n := sockoptLines(events, record.MechanismCgroup); n != 0 {
			t.Errorf("%d cgroup/setsockopt lines on a kernel without the io_uring setsockopt command", n)
		}
		return
	}
	for _, m := range uringModes {
		if got := res["ulp-"+m]; got != "refused errno="+strconv.Itoa(int(unix.EPERM)) {
			t.Errorf("TCP_ULP smc through io_uring (%s): %q, want EPERM from cgroup/setsockopt", m, got)
		}
	}
	if n := sockoptLines(events, record.MechanismCgroup); n != len(uringModes) {
		t.Errorf("TCP_ULP smc through io_uring: %d cgroup/setsockopt lines, want %d (one per mode)", n, len(uringModes))
	}
}

// wantSocketFamilies checks what the run's run_start says it bounds (ADR 0018 PR 2, A-0018-10): its tier, and
// net_guarantees.socket_families and the capability row net.socket_families, both want.
func wantSocketFamilies(t *testing.T, events []map[string]any, tier string, want bool) {
	t.Helper()
	start := findEvent(events, func(e map[string]any) bool { return e["kind"] == "run_start" })
	if start == nil {
		t.Fatal("no run_start line")
	}
	if start["tier"] != tier {
		t.Errorf("run_start tier %v, want %s", start["tier"], tier)
	}
	g, _ := start["net_guarantees"].(map[string]any)
	caps, _ := start["capabilities"].(map[string]any)
	if g["socket_families"] != want || caps[string(backend.CapSocketFamilies)] != want {
		t.Errorf("run_start net_guarantees.socket_families %v, capabilities[%s] %v, want both %v",
			g["socket_families"], backend.CapSocketFamilies, caps[string(backend.CapSocketFamilies)], want)
	}
}

// dumpRefusals logs the run's refused and gap lines when the test has failed.
func dumpRefusals(t *testing.T, events []map[string]any) {
	t.Helper()
	if !t.Failed() {
		return
	}
	for _, e := range events {
		if e["kind"] == "refused" || e["kind"] == "gap" {
			t.Logf("ledger: %v", e)
		}
	}
}

// fallbackIOUringCells is the fanotify fallback's half: p with the test seam, then q, the control, without it.
func fallbackIOUringCells(t *testing.T, bin string, p, q *planeProject) {
	t.Helper()
	res, events, out := uringRun(t, bin, p, PlaneFanotify, "TEGO_TEST_FALLBACK_IOURING=1")
	if !strings.Contains(out, "TEGO_TEST_FALLBACK_IOURING") {
		t.Error("the run did not warn that its test build admitted io_uring on the fallback")
	}
	if strings.HasPrefix(res["tcp-inline"], "unavailable") {
		t.Fatalf("io_uring stayed unavailable to the agent under the test seam: %q", res["tcp-inline"])
	}
	if res["tcp-inline"] == "refused errno="+strconv.Itoa(int(unix.EINVAL)) {
		t.Skip("this kernel has no IORING_OP_SOCKET (EINVAL)")
	}
	refusedSome := false
	for _, c := range uringCells {
		target := record.SocketTriple(c.c.family, c.c.typ, c.c.protocol)
		outside := c.c.create()
		want, wantLines := "ok", 0
		switch {
		case c.name == "tcp":
		case outside != nil:
			want = "refused errno=" + strconv.Itoa(errnoOf(outside)) // the kernel's own answer: the program never ran
		case c.c.inet():
			want, wantLines = "refused errno="+strconv.Itoa(int(unix.EPERM)), len(uringModes)
			refusedSome = true
		}
		for _, m := range uringModes {
			if got := res[c.name+"-"+m]; got != want {
				t.Errorf("%s through io_uring (%s): %q, want %q", c.name, m, got, want)
			}
		}
		if n := socketLines(events, target, record.MechanismCgroup); n != wantLines {
			t.Errorf("%s: %d refused lines with mechanism cgroup, want %d (one per mode)", target, n, wantLines)
		}
		if c.name != "sctp" {
			if n := socketLines(events, target, "<nil>"); n != 0 {
				t.Errorf("%s: %d refused lines of the supervisor's for an io_uring socket it never saw", target, n)
			}
		}
	}
	if !refusedSome {
		t.Fatal("this kernel made none of SCTP, UDP-Lite, MPTCP and SMC: nothing was refused")
	}
	wantSyscallControl(t, res, events)
	wantURingULP(t, res, events)
	// io_uring admitted with no plane: nothing decides an IORING_OP_SOCKET of another family, so the run says it has
	// no socket-family bound.
	wantSocketFamilies(t, events, "cgroup", false)
	dumpRefusals(t, events)

	// The control: the same contract without the seam is what a product build gets, io_uring refused (ENOSYS) on the
	// fallback with the warning naming why, so no socket reaches the program through it.
	res, events, out = uringRun(t, bin, q, PlaneFanotify)
	if !strings.Contains(out, "stays refused (ENOSYS)") || !strings.Contains(out, "IORING_OP_SOCKET") {
		t.Error("the run without the seam did not warn that io_uring stays refused and why")
	}
	for _, c := range append(uringCells, uringCell{name: "ulp"}) {
		for _, m := range uringModes {
			if got := res[c.name+"-"+m]; !strings.HasPrefix(got, "unavailable") {
				t.Errorf("%s through io_uring (%s) without the seam: %q, want io_uring unavailable (ENOSYS)", c.name, m, got)
			}
		}
	}
	for _, e := range events {
		if e["kind"] == "refused" && e["mechanism"] == record.MechanismCgroup {
			t.Errorf("a cgroup/sock_create line without the seam: %v", e)
		}
	}
	wantSyscallControl(t, res, events)
	wantSocketFamilies(t, events, "cgroup", true)
}

// planeIOUringCells is a plane mode's half, at tier cgroup or tier bpflsm: io_uring admitted in a product build, the
// plane refusing first.
func planeIOUringCells(t *testing.T, bin, tier, mode string, p *planeProject) {
	t.Helper()
	res, events, _ := uringRunAt(t, bin, p, tier, mode)
	if strings.HasPrefix(res["tcp-inline"], "unavailable") {
		t.Fatalf("io_uring unavailable to the agent in plane mode %s: %q", mode, res["tcp-inline"])
	}
	if res["tcp-inline"] == "refused errno="+strconv.Itoa(int(unix.EINVAL)) {
		t.Skip("this kernel has no IORING_OP_SOCKET (EINVAL)")
	}
	for _, c := range uringCells {
		target := record.SocketTriple(c.c.family, c.c.typ, c.c.protocol)
		want, wantLines := "refused errno="+strconv.Itoa(int(unix.EACCES)), len(uringModes)
		if c.name == "tcp" {
			want, wantLines = "ok", 0
		}
		for _, m := range uringModes {
			if got := res[c.name+"-"+m]; got != want {
				t.Errorf("%s through io_uring (%s): %q, want %q", c.name, m, got, want)
			}
		}
		if n := socketLines(events, target, record.MechanismPlane); n != wantLines {
			t.Errorf("%s: %d refused lines with mechanism plane, want %d (one per mode)", target, n, wantLines)
		}
		if n := socketLines(events, target, record.MechanismCgroup); n != 0 {
			t.Errorf("%s: %d lines of cgroup/sock_create's, which the plane's refusal leaves nothing to see", target, n)
		}
	}
	wantSyscallControl(t, res, events)
	wantURingULP(t, res, events)
	wantSocketFamilies(t, events, tier, true)
	dumpRefusals(t, events)
}
