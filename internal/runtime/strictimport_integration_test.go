// SPDX-License-Identifier: Apache-2.0

//go:build integration && linux

package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ADR 0128's descriptor-import guard on the real kernel, from a root launcher, under net.assurance: kernel. Where a
// decision plane runs the run (tiers cgroup and bpflsm, plane modes lsm and fmod_ret) the plane's socket_recvmsg
// refuses a receive that carries a control buffer, and the filter no longer answers every recvmsg ENOSYS, so the C
// library's interface lists work; where none does (tier cgroup on the fanotify fallback) the filter's ENOSYS stands.
// Two tests: TestRootStrictInterfaceLists is the interface lists, TestRootStrictImportStillClosed is the guard itself.

// strictPlanes are the plane modes a root run is asked for, and the tiers each is run at.
var strictPlanes = []struct{ tier, plane string }{
	{"bpflsm", "lsm"}, {"bpflsm", "fmod_ret"}, {"cgroup", "lsm"}, {"cgroup", "fmod_ret"},
}

// strictScene is a root run of one program under net.assurance: kernel, pinned to tier and plane (the test build's
// TEGO_TEST_PLANE). sock, when set, is a unix socket the run is allowed to connect to (the test listens on it).
func newStrictScene(t *testing.T, bin, tier, plane, sock string, command []string, allow []string, files map[string]string, mods ...func(string) string) *askReadScene {
	t.Helper()
	if _, _, ok := agentUID(t); !ok {
		t.Skip("needs SUDO_UID naming the invoking user, as `sudo go test` and test/vm/root-suites.sh give")
	}
	q := func(ss []string) string {
		out := make([]string, 0, len(ss))
		for _, s := range ss {
			out = append(out, fmt.Sprintf("%q", s))
		}
		return "[" + strings.Join(out, ", ") + "]"
	}
	netAllow := "net:\n  assurance: kernel\n"
	if sock != "" {
		netAllow += "  allow: [" + fmt.Sprintf("%q", "unix:"+sock) + "]\n"
	}
	contract := fmt.Sprintf(`version: 0
name: rootstrict
command: %s
tier: landlock
fs:
  write: ["./out/"]
exec:
  allow: %s
%senv:
  pass: ["PATH", "HOME", "NODE"]
limits:
  pids: 64
record: summary
`, q(command), q(allow), netAllow)
	for _, mod := range mods {
		contract = mod(contract)
	}
	s := &askReadScene{bin: bin}
	// The fixture compiles at the tier this test process offers, as newRouteScene's does, and the file tego runs
	// names the root tier; the assurance line is kept out of the fixture's compile, which lacks the kernel hooks.
	// An empty net: section reads as absent, so with no allowed socket the fixture's compile gets net: {}.
	compiled := strings.Replace(contract, "  assurance: kernel\n", "", 1)
	if sock == "" {
		compiled = strings.Replace(contract, "net:\n  assurance: kernel\n", "net: {}\n", 1)
	}
	s.f = newFixture(t, compiled)
	pinned := strings.Replace(contract, "tier: landlock\n", "tier: "+tier+"\n", 1)
	if err := os.WriteFile(filepath.Join(s.f.dir, "agent.yaml"), []byte(pinned), 0o600); err != nil {
		t.Fatal(err)
	}
	owned := []string{filepath.Join(s.f.dir, "agent.yaml")}
	for name, body := range files {
		p := filepath.Join(s.f.dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		owned = append(owned, p)
	}
	agentOwns(t, owned...)
	s.env = isolatedEnv(t, s.f)
	if plane != "" {
		s.env = append(s.env, "TEGO_TEST_PLANE="+plane)
	}
	return s
}

// requireStrictPlane skips the test unless this machine offers tier and runs it in plane mode plane (doctor --json
// under the same TEGO_TEST_PLANE), so a run asked for lsm mode on a boot without bpf in the LSM list is a skip with
// its reason, never a pass on another mode.
func requireStrictPlane(t *testing.T, s *askReadScene, tier, plane string) {
	t.Helper()
	testutil.RequireTier(t, s.tego(t, "doctor", "--require", tier), tier)
	if plane == "" || plane == "fanotify" {
		return
	}
	raw, err := s.tego(t, "doctor", "--json").Output()
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	var report struct {
		Plane *struct {
			Selected string `json:"selected"`
		} `json:"plane"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if report.Plane == nil || report.Plane.Selected != plane {
		t.Skipf("this machine does not run the decision plane in %s mode (doctor says %+v)", plane, report.Plane)
	}
}

// strictRun runs the scene's command to its end (with feed, which a test that feeds the run uses) and returns the run's
// lines.
func strictRun(t *testing.T, s *askReadScene, argv []string, feed func(ended <-chan struct{}) error) []*record.Event {
	return strictRunSkipping(t, s, argv, feed, false)
}

// strictRunSkipping is strictRun that, with skipUnavailable, skips the test where the run is refused before it starts
// for lack of the kernel network guarantees (ErrNetAssurance): the no-plane control below 6.7, where the unix destination
// hooks are the plane's, is no run at all. feed runs beside the run, in a goroutine of its own and so without t: it
// returns an error rather than failing, and ended closes when the run has. A run that was refused never reaches the
// peer feed waits for, so feed's error is the test's only when the run was not refused for that reason.
func strictRunSkipping(t *testing.T, s *askReadScene, argv []string, feed func(ended <-chan struct{}) error, skipUnavailable bool) []*record.Event {
	t.Helper()
	cmd := s.tego(t, append([]string{"run", filepath.Join(s.f.dir, "agent.yaml"), "--"}, argv...)...)
	cmd.Dir = s.f.dir
	var out strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	ended := make(chan struct{})
	fed := make(chan error, 1)
	if feed != nil {
		go func() { fed <- feed(ended) }()
	} else {
		fed <- nil
	}
	// The run's end is what the feed waits for, and the run waits for nothing the feed does after its sends.
	select {
	case err := <-done:
		close(ended)
		if code := exitCodeOf(t, err); code != 0 {
			if skipUnavailable && code == 125 && strings.Contains(out.String(), ErrNetAssurance.Error()) {
				t.Skipf("this run has no kernel network assurance without a plane here:\n%s", out.String())
			}
			t.Fatalf("tego run exited %d:\n%s", code, out.String())
		}
	case <-time.After(90 * time.Second):
		_ = cmd.Process.Kill()
		close(ended)
		t.Fatalf("tego run did not end in 90s:\n%s", out.String())
	}
	select {
	case err := <-fed:
		if err != nil {
			t.Errorf("feeding the run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("the feed did not end after the run did")
	}
	dirs := runDirs(t, s.f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v, want one\n%s", dirs, out.String())
	}
	anchored(t, dirs[0])
	return events(t, dirs[0])
}

// runPlane is the decision plane the run's run_start names, "" when it names none.
func runPlane(t *testing.T, evs []*record.Event) string {
	t.Helper()
	for _, e := range evs {
		if e.Kind != record.KindRunStart {
			continue
		}
		var p struct {
			DecisionPlane string `json:"decision_plane"`
		}
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			t.Fatal(err)
		}
		return p.DecisionPlane
	}
	t.Fatal("the run has no run_start")
	return ""
}

// noPlaneMode is whether a run_start's decision plane names no kernel plane: nothing, or the fanotify fallback a test
// build is pinned to with TEGO_TEST_PLANE=fanotify.
func noPlaneMode(p string) bool { return p == "" || p == "fanotify" }

// recvRefusals are the run's refused lines of op recvmsg, decoded.
func recvRefusals(t *testing.T, evs []*record.Event) []record.RefusedPayload {
	t.Helper()
	var out []record.RefusedPayload
	for _, e := range evs {
		if e.Kind != record.KindRefused {
			continue
		}
		var p record.RefusedPayload
		if err := e.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.Op == "recvmsg" {
			out = append(out, p)
		}
	}
	return out
}

// strictInterfaceProbe is what a program gets from the C library under net.assurance: kernel, and Node's own list when
// NODE names one.
const strictInterfaceProbe = `import errno, json, os, socket, subprocess, sys
res = {}
def attempt(name, f):
    try:
        res[name] = f()
    except OSError as e:
        res[name] = errno.errorcode.get(e.errno, str(e.errno))
def getifaddrs():
    import ctypes
    libc, head = ctypes.CDLL(None, use_errno=True), ctypes.c_void_p()
    if libc.getifaddrs(ctypes.byref(head)) != 0:
        raise OSError(ctypes.get_errno(), "getifaddrs")
    return "ok"
attempt("if_nameindex", lambda: "ok" if socket.if_nameindex() else "empty")
attempt("getifaddrs", getifaddrs)
attempt("addrconfig", lambda: "ok" if socket.getaddrinfo("127.0.0.1", 80, flags=socket.AI_ADDRCONFIG) else "empty")
node = os.environ.get("NODE")
if node:
    r = subprocess.run([node, "-e", 'process.stdout.write(Object.keys(require("os").networkInterfaces()).join(","))'],
                       capture_output=True, text=True)
    res["node"] = "ok" if r.returncode == 0 and "lo" in r.stdout.split(",") else "failed rc=%d %s" % (r.returncode, r.stderr[-300:])
json.dump(res, open(sys.argv[1], "w"))
`

// strictInterfaceScene is a root run of strictInterfaceProbe under net.assurance: kernel.
func strictInterfaceScene(t *testing.T, bin, tier, plane string) (*askReadScene, []string) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	allow := []string{python, resolved}
	node := ""
	if p, err := exec.LookPath("node"); err == nil {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			node = p
			allow = append(allow, p, r)
		}
	}
	s := newStrictScene(t, bin, tier, plane, "", []string{python}, allow, map[string]string{"probe.py": strictInterfaceProbe})
	if node != "" {
		s.env = append(s.env, "NODE="+node)
	}
	return s, []string{python, "probe.py", filepath.Join(s.f.out, "result.json")}
}

// TestRootStrictInterfaceLists is the root sibling of landlock's TestStrictFilterInterfaceLists: under
// net.assurance: kernel at tiers cgroup and bpflsm, in both plane modes, glibc's if_nameindex and getifaddrs and Node's
// os.networkInterfaces() all succeed, since the plane's socket_recvmsg admits a receive with no control buffer, and
// nothing in the run's lines is refused for them. The control, tier cgroup on the fanotify fallback (no plane), keeps the
// filter's answer: if_nameindex and getifaddrs fail ENOSYS, getaddrinfo goes on. Before the plane hook the plane runs
// answered ENOSYS too.
func TestRootStrictInterfaceLists(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: tiers cgroup and bpflsm")
	}
	bin := tegoBPFBinary(t)
	for _, tc := range strictPlanes {
		t.Run(tc.tier+"/"+tc.plane, func(t *testing.T) {
			s, argv := strictInterfaceScene(t, bin, tc.tier, tc.plane)
			requireStrictPlane(t, s, tc.tier, tc.plane)
			evs := strictRun(t, s, argv, nil)
			if got := runPlane(t, evs); got != tc.plane {
				t.Fatalf("the run's decision plane is %q, want %q", got, tc.plane)
			}
			var got map[string]string
			if err := json.Unmarshal([]byte(s.out("result.json")), &got); err != nil {
				t.Fatalf("the probe's result: %v", err)
			}
			for _, k := range []string{"if_nameindex", "getifaddrs", "addrconfig"} {
				if got[k] != "ok" {
					t.Errorf("%s = %q, want ok (all: %v)", k, got[k], got)
				}
			}
			if v, ok := got["node"]; ok && v != "ok" {
				t.Errorf("Node's os.networkInterfaces() = %q, want ok", v)
			}
			if n := familyLines(t, evs); n["allow/route-query"] == 0 || len(recvRefusals(t, evs)) != 0 {
				t.Errorf("netlink lines %v and %d recvmsg refusals, want route-query allows and no refusal", n, len(recvRefusals(t, evs)))
			}
		})
	}
	t.Run("control: no plane keeps the filter's answer", func(t *testing.T) {
		s, argv := strictInterfaceScene(t, bin, "cgroup", "fanotify")
		requireStrictPlane(t, s, "cgroup", "fanotify")
		evs := strictRunSkipping(t, s, argv, nil, true)
		if got := runPlane(t, evs); !noPlaneMode(got) {
			t.Fatalf("the control run has decision plane %q, want none", got)
		}
		var got map[string]string
		if err := json.Unmarshal([]byte(s.out("result.json")), &got); err != nil {
			t.Fatalf("the probe's result: %v", err)
		}
		if got["if_nameindex"] != "ENOSYS" || got["getifaddrs"] != "ENOSYS" || got["addrconfig"] != "ok" {
			t.Errorf("the control's lists %v, want if_nameindex and getifaddrs ENOSYS and addrconfig ok", got)
		}
	})
}

// strictHeldProbe is what a held open and a control-bearing receive come to inside one run: the reads the deputy
// answers (a benign file, and the two names the contracts below refuse), an SCM_RIGHTS receive on a socket pair by the
// agent, by a child it forks and by a program it execs (none of them the deputy, so the guard refuses each), and the C
// library's interface list, which needs a receive with no control buffer.
const strictHeldProbe = `import errno, json, os, socket, struct, subprocess, sys
res = {}
def attempt(name, f):
    try:
        res[name] = f()
    except OSError as e:
        res[name] = errno.errorcode.get(e.errno, str(e.errno))
def read(p):
    with open(p) as f:
        return f.read()
RECV = """
import errno, os, socket, struct, sys
a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
a.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", 0))])
before = len(os.listdir("/proc/self/fd"))
try:
    b.recvmsg(8, socket.CMSG_SPACE(4))
    r = "ok"
except OSError as e:
    r = errno.errorcode.get(e.errno, str(e.errno))
sys.stdout.write(r + " " + str(len(os.listdir("/proc/self/fd")) - before))
"""
attempt("read_benign", lambda: "ok" if read("out/benign") == "benign-bytes" else "wrong data")
attempt("read_env_local", lambda: "leaked" if read("out/.env.local") else "empty")
attempt("read_secret_env", lambda: "leaked" if read("out/secret.env") else "empty")
a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
attempt("send_fd", lambda: (a.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", 0))]), "ok")[1])
before = len(os.listdir("/proc/self/fd"))
attempt("recv_ctl", lambda: (b.recvmsg(8, socket.CMSG_SPACE(4)), "ok")[1])
res["recv_ctl_fds"] = len(os.listdir("/proc/self/fd")) - before
attempt("if_nameindex", lambda: "ok" if socket.if_nameindex() else "empty")
r, w = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(r)
    import io, contextlib
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        exec(RECV)
    os.write(w, out.getvalue().encode())
    os._exit(0)
os.close(w)
got = b""
while True:
    chunk = os.read(r, 64)
    if not chunk:
        break
    got += chunk
os.waitpid(pid, 0)
res["fork_recv_ctl"] = got.decode()
p = subprocess.run([sys.executable, "-c", RECV], capture_output=True, text=True)
res["exec_recv_ctl"] = p.stdout if p.returncode == 0 else "failed rc=%d %s" % (p.returncode, p.stderr[-300:])
attempt("read_benign_after", lambda: "ok" if read("out/benign") == "benign-bytes" else "wrong data")
json.dump(res, open(sys.argv[1], "w"))
`

// TestRootStrictHeldOpens is ADR 0128's amended guard with the open deputy: a run that holds its opens (fs.reads: held, or
// gate.completion: held with a gate rule on reads) under net.assurance: kernel, at tiers cgroup and bpflsm in both plane
// modes. The deputy runs in the run's cgroup and takes each request socket and dirfd with recvmsg and a control buffer;
// the plane's socket_recvmsg passes it alone, by the thread-group id and start time the launcher wrote into the run's
// slot (amendment 2026-11-21), so the run's filter leaves recvmsg to the plane as any kernel-assurance run's does. The
// held opens are answered (a benign read, before and after the receives below; the refused names stay refused), the C
// library's interface list works, and every control-bearing receive by any other task of the run is refused EACCES by
// the plane and installs nothing: the agent's own, a child's it forks, and a program's it execs (each with its own
// thread-group id), three refused recvmsg lines, rule socket-import. Before the exemption such a run kept the filter's
// ENOSYS for recvmsg, so its interface list failed and its receives were ENOSYS with no line; before that, the deputy's
// first receive after Arm was refused and every held open failed.
func TestRootStrictHeldOpens(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: tiers cgroup and bpflsm")
	}
	bin := tegoBPFBinary(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	variants := []struct {
		name    string
		mod     func(string) string
		refused string
	}{
		{"fs.reads: held", func(c string) string {
			return strings.Replace(c, "  write: [\"./out/\"]\n", "  write: [\"./out/\"]\n  reads: held\n", 1)
		}, "read_env_local"},
		{"gate.completion: held", func(c string) string {
			return c + "gate:\n  completion: held\n  rules:\n    - 'fs.read matches \"*.env\"': 90\n"
		}, "read_secret_env"},
	}
	for _, v := range variants {
		for _, tc := range strictPlanes {
			t.Run(v.name+"/"+tc.tier+"/"+tc.plane, func(t *testing.T) {
				files := map[string]string{"probe.py": strictHeldProbe, "out/benign": "benign-bytes", "out/.env.local": "TOKEN=1", "out/secret.env": "TOKEN=2"}
				s := newStrictScene(t, bin, tc.tier, tc.plane, "", []string{python}, []string{python, resolved}, files, v.mod)
				requireStrictPlane(t, s, tc.tier, tc.plane)
				result := filepath.Join(s.f.out, "result.json")
				evs := strictRun(t, s, []string{python, "probe.py", result}, nil)
				if got := runPlane(t, evs); got != tc.plane {
					t.Fatalf("the run's decision plane is %q, want %q", got, tc.plane)
				}
				var got map[string]any
				raw, err := os.ReadFile(result)
				if err != nil {
					t.Fatalf("the probe wrote nothing: %v", err)
				}
				if err := json.Unmarshal(raw, &got); err != nil {
					t.Fatalf("the probe's result %q: %v", raw, err)
				}
				if got["read_benign"] != "ok" {
					t.Errorf("the held read of a benign file = %v, want ok (all: %v)", got["read_benign"], got)
				}
				if got[v.refused] != "EACCES" {
					t.Errorf("%s = %v, want EACCES (all: %v)", v.refused, got[v.refused], got)
				}
				if got["read_benign_after"] != "ok" {
					t.Errorf("the held read after the receives = %v, want ok: the deputy must still answer (all: %v)", got["read_benign_after"], got)
				}
				if got["recv_ctl"] != "EACCES" {
					t.Errorf("the agent's SCM_RIGHTS receive = %v, want EACCES from the plane (all: %v)", got["recv_ctl"], got)
				}
				if got["recv_ctl_fds"] != float64(0) {
					t.Errorf("the control receive installed %v descriptors, want 0", got["recv_ctl_fds"])
				}
				for _, k := range []string{"fork_recv_ctl", "exec_recv_ctl"} {
					if got[k] != "EACCES 0" {
						t.Errorf("%s = %q, want \"EACCES 0\": a task of the run that is not the deputy is refused and gets no descriptor (all: %v)", k, got[k], got)
					}
				}
				if got["if_nameindex"] != "ok" {
					t.Errorf("if_nameindex = %v, want ok: the filter leaves recvmsg to the plane for a run that holds its opens (all: %v)", got["if_nameindex"], got)
				}
				rs := recvRefusals(t, evs)
				if len(rs) != 3 {
					t.Errorf("%d refused recvmsg lines, want 3 (the agent's, its child's, its exec'd program's): %+v", len(rs), rs)
				}
				for _, r := range rs {
					if r.Rule != "socket-import" || r.Mechanism != record.MechanismPlane || r.Reason != record.ReasonNetNotAllowed {
						t.Errorf("refused recvmsg line %+v, want rule socket-import, reason net-not-allowed, mechanism plane", r)
					}
				}
			})
		}
	}
}

// TestRootStrictImportStillClosed is the guard itself, the hole the filter's ENOSYS closed and the plane's
// socket_recvmsg now closes: an outside process (this test) listens on a unix socket the run may connect to and sends
// it four messages, three carrying a descriptor. The workload (test/workloads/strictimport) then receives them every way
// the guard has to answer, counting /proc/self/fd after each:
//   - recvmsg with a control buffer, plain and with MSG_PEEK, is refused EACCES and installs nothing (and the ledger has
//     one refused recvmsg line each, rule socket-import, mechanism plane);
//   - recvmsg with no control buffer, plain and with MSG_PEEK, takes the data with MSG_CTRUNC and installs nothing;
//   - read(2) and recvfrom(2), which pass no control buffer, take their messages and install nothing;
//   - a control receive on a UDP socket (IP_PKTINFO, SO_TIMESTAMP) is no import and is left alone: EAGAIN on an empty
//     socket, the datagram and its timestamp otherwise, and no ledger line (the refusals counted are the two above);
//   - recvmmsg(2) and pidfd_getfd(2) are ENOSYS, from the filter;
//   - on x86-64 a call through int 0x80 is ENOSYS or ends the process.
//
// The control, tier cgroup on the fanotify fallback, answers every recvmsg ENOSYS, as the filter always did.
func TestRootStrictImportStillClosed(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: tiers cgroup and bpflsm")
	}
	bin := tegoBPFBinary(t)
	work := filepath.Join(t.TempDir(), "strictimport")
	build := exec.Command("go", "build", "-o", work, "github.com/attention-span-ai/tego/test/workloads/strictimport")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, out)
	}
	agentReaches(t, work)
	check := func(t *testing.T, tier, plane string, plan bool) {
		sockDir, err := os.MkdirTemp("", "si-")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
		if err := os.Chmod(sockDir, 0o755); err != nil {
			t.Fatal(err)
		}
		sock := filepath.Join(sockDir, "peer.sock")
		s := newStrictScene(t, bin, tier, plane, sock, []string{work}, []string{work}, nil)
		requireStrictPlane(t, s, tier, plane)
		ln, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Close(ln) })
		if err := unix.Bind(ln, &unix.SockaddrUnix{Name: sock}); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(sock, 0o666); err != nil {
			t.Fatal(err)
		}
		if err := unix.Listen(ln, 1); err != nil {
			t.Fatal(err)
		}
		if err := unix.SetsockoptTimeval(ln, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 60}); err != nil {
			t.Fatal(err)
		}
		result := filepath.Join(s.f.out, "result.json")
		feed := func(ended <-chan struct{}) error {
			var conn int
			var err error
			for { // a signal (the run's child ending) interrupts a blocking accept
				if conn, _, err = unix.Accept(ln); err != unix.EINTR {
					break
				}
			}
			if err != nil {
				return fmt.Errorf("the run never connected: %w", err)
			}
			defer func() { _ = unix.Close(conn) }()
			null, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			defer func() { _ = unix.Close(null) }()
			for i, m := range []string{"m1", "m2", "m3", "m4"} {
				var oob []byte
				if i < 3 {
					oob = unix.UnixRights(null)
				}
				if err := unix.Sendmsg(conn, []byte(m), oob, nil, 0); err != nil {
					return fmt.Errorf("sending %s: %w", m, err)
				}
			}
			<-ended // the peer stays open for as long as the run reads
			return nil
		}
		evs := strictRunSkipping(t, s, []string{work, sock, result}, feed, !plan)
		var got map[string]string
		raw, err := os.ReadFile(result)
		if err != nil {
			t.Fatalf("the workload wrote nothing: %v", err)
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("the workload's result %q: %v", raw, err)
		}
		want := map[string]string{}
		refusals := 0
		if plan {
			if gotPlane := runPlane(t, evs); gotPlane != plane {
				t.Fatalf("the run's decision plane is %q, want %q", gotPlane, plane)
			}
			for k, v := range map[string]string{
				"ctl": "EACCES", "ctl_fds": "0", "ctl_peek": "EACCES", "ctl_peek_fds": "0",
				"nocontrol_peek": "ok", "nocontrol_peek_data": "m1", "nocontrol_peek_ctrunc": "yes", "nocontrol_peek_fds": "0",
				"nocontrol": "ok", "nocontrol_data": "m1", "nocontrol_ctrunc": "yes", "nocontrol_fds": "0",
				"read": "ok", "read_data": "m2", "read_fds": "0",
				"recvfrom": "ok", "recvfrom_data": "m3", "recvfrom_fds": "0",
				"udp_ctl_empty": "EAGAIN",
			} {
				want[k] = v
			}
			refusals = 2
		} else {
			if gotPlane := runPlane(t, evs); !noPlaneMode(gotPlane) {
				t.Fatalf("the control run has decision plane %q, want none", gotPlane)
			}
			for k, v := range map[string]string{
				"ctl": "ENOSYS", "ctl_peek": "ENOSYS", "nocontrol_peek": "ENOSYS", "nocontrol": "ENOSYS",
				"read": "ok", "read_data": "m1", "read_fds": "0", "recvfrom": "ok", "recvfrom_data": "m2", "recvfrom_fds": "0",
				"udp_ctl_empty": "ENOSYS",
			} {
				want[k] = v
			}
		}
		want["recvmmsg"], want["pidfd_getfd"] = "ENOSYS", "ENOSYS"
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s = %q, want %q (all: %v)", k, got[k], v, got)
			}
		}
		// A control receive on a UDP socket (IP_PKTINFO, SO_TIMESTAMP) carries no descriptor: the guard leaves it to the
		// protocol (EAGAIN with nothing queued), and where the run may send itself a datagram it takes it with its
		// timestamp. Neither writes a ledger line (the count below).
		if plan {
			if u := got["udp_ctl"]; u != "skipped" && (u != "ok" || got["udp_ctl_control"] != "delivered") {
				t.Errorf("a UDP datagram taken with a control buffer: %q, control %q, want ok with a timestamp delivered (or skipped)", u, got["udp_ctl_control"])
			}
		}
		// A call through the 32-bit entry is ENOSYS or ends the run, and only on x86-64 is there one to make.
		if i := got["int80"]; i != "ENOSYS" && i != "not returned" && i != "not applicable" {
			t.Errorf("int 0x80 answered %q, want ENOSYS, or the process ended before it returned", i)
		}
		rs := recvRefusals(t, evs)
		if len(rs) != refusals {
			t.Errorf("%d refused recvmsg lines, want %d: %+v", len(rs), refusals, rs)
		}
		for _, r := range rs {
			if r.Rule != "socket-import" || r.Mechanism != record.MechanismPlane || r.Reason != record.ReasonNetNotAllowed {
				t.Errorf("refused recvmsg line %+v, want rule socket-import, reason net-not-allowed, mechanism plane", r)
			}
		}
	}
	for _, tc := range strictPlanes {
		t.Run(tc.tier+"/"+tc.plane, func(t *testing.T) { check(t, tc.tier, tc.plane, true) })
	}
	t.Run("control: no plane answers every recvmsg ENOSYS", func(t *testing.T) { check(t, "cgroup", "fanotify", false) })
}
