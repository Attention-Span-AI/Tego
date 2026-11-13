// SPDX-License-Identifier: Apache-2.0

//go:build integration && linux

package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

// ADR 0128 on the real kernel: what a Node or Python agent asks of the network works under a net: section, and nothing
// the run sends changes the network, whoever asks and by whichever call.

// routeProbe runs each shape of netlink use and writes what each came to as JSON: "ok", or the errno's name, from the
// syscall or from the kernel's own ack. The shapes with a change add one address to lo, a change no other test looks
// at, each address its own so a success of one cannot make another fail EEXIST. `--clean` takes them away again.
const routeProbe = `import errno, fcntl, json, os, socket, struct, sys
RTM_NEWADDR, RTM_DELADDR, RTM_GETLINK, RTM_GETADDR = 20, 21, 18, 22
REQUEST, ACK, EXCL, CREATE, DUMP = 1, 4, 0x200, 0x400, 0x300
NLMSG_ERROR, NLMSG_DONE = 2, 3
LO = 1  # lo is the first interface of every network namespace

def msg(typ, flags, body):
    return struct.pack("=IHHII", 16 + len(body), typ, flags, 1, 0) + body

def dump(typ):
    return msg(typ, REQUEST | DUMP, bytes(4))

def addr(typ, ip, flags=0):
    ifa = struct.pack("=BBBBI", socket.AF_INET, 32, 0, 254, LO)
    return msg(typ, REQUEST | ACK | flags, ifa + struct.pack("=HH", 8, 2) + socket.inet_aton(ip))

def new(ip):
    return addr(RTM_NEWADDR, ip, CREATE | EXCL)

def route():
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
    s.bind((0, 0))
    s.settimeout(5)
    return s

def answer(s):
    count = 0
    while True:
        data = s.recv(65536)
        off = 0
        while off < len(data):
            size, typ = struct.unpack_from("=IH", data, off)
            if typ == NLMSG_DONE:
                return "ok" if count else "empty"
            if typ == NLMSG_ERROR:
                code = struct.unpack_from("=i", data, off + 16)[0]
                return "ok" if code == 0 else errno.errorcode.get(-code, str(-code))
            count += 1
            off += (size + 3) & ~3

def asked(send):
    s = route()
    send(s)
    return answer(s)

def flags():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cur = fcntl.ioctl(s, 0x8913, struct.pack("16sh14x", b"lo", 0))  # SIOCGIFFLAGS
    fcntl.ioctl(s, 0x8914, cur)  # SIOCSIFFLAGS, to the flags it has
    return "ok"

res = {}
def attempt(name, f):
    try:
        res[name] = f()
    except OSError as e:
        res[name] = errno.errorcode.get(e.errno, str(e.errno))

if sys.argv[1:] == ["--clean"]:
    for ip in ("10.77.0.1", "10.77.0.2", "10.77.0.3", "10.77.0.4", "10.77.0.5"):
        attempt(ip, lambda: asked(lambda s: s.send(addr(RTM_DELADDR, ip))))
    print(res)
    sys.exit(0)

status = dict(l.split(":\t", 1) for l in open("/proc/self/status").read().splitlines() if ":\t" in l)
res["euid"], res["capeff"], res["capbnd"] = str(os.geteuid()), status["CapEff"].strip(), status["CapBnd"].strip()
res["nnp"], res["exe"] = status["NoNewPrivs"].strip(), os.readlink("/proc/self/exe")
res["exe_stat"] = oct(os.stat(res["exe"]).st_mode) + " uid " + str(os.stat(res["exe"]).st_uid)

# What a program gets through the C library, Node's os.networkInterfaces and Python's socket module among them.
attempt("if_nameindex", lambda: "ok" if socket.if_nameindex() else "empty")
attempt("addrconfig", lambda: "ok" if socket.getaddrinfo("127.0.0.1", 80, flags=socket.AI_ADDRCONFIG) else "empty")
# The calls the C library, iproute2 and musl make.
attempt("dump_sendto", lambda: asked(lambda s: s.sendto(dump(RTM_GETLINK), (0, 0))))
attempt("dump_sendmsg", lambda: asked(lambda s: s.sendmsg([dump(RTM_GETADDR)], [], 0, (0, 0))))
attempt("dump_send", lambda: asked(lambda s: s.send(dump(RTM_GETLINK))))
attempt("dump_go", lambda: asked(lambda s: s.sendto(msg(RTM_GETLINK, REQUEST | DUMP, bytes(1)), (0, 0))))  # net.Interfaces's 17 bytes
# What a run could read before any of this, with no netlink at all (ADR 0128).
attempt("proc_net_route", lambda: "ok" if open("/proc/net/route").read() else "empty")
attempt("sys_class_net", lambda: "ok" if os.listdir("/sys/class/net") else "empty")
# A change, by each call there is: the two the supervisor reads, and the two only the kernel sees.
attempt("add_sendto", lambda: asked(lambda s: s.sendto(new("10.77.0.3"), (0, 0))))
attempt("add_sendmsg", lambda: asked(lambda s: s.sendmsg([new("10.77.0.4")], [], 0, (0, 0))))
attempt("add_behind_get", lambda: asked(lambda s: s.sendto(dump(RTM_GETLINK) + new("10.77.0.5"), (0, 0))))
attempt("add_send", lambda: asked(lambda s: s.send(new("10.77.0.1"))))
attempt("add_write", lambda: asked(lambda s: os.write(s.fileno(), new("10.77.0.2"))))
attempt("ifflags", flags)
# Everything else netlink reaches.
attempt("to_process", lambda: asked(lambda s: s.sendto(dump(RTM_GETLINK), (os.getppid(), 0))))
attempt("to_group", lambda: asked(lambda s: s.sendto(dump(RTM_GETLINK), (0, 1))))
attempt("connect", lambda: route().connect((0, 0)) or "ok")
attempt("generic", lambda: socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 16).close() or "ok")
attempt("sock_diag", lambda: socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, 4).close() or "ok")
json.dump(res, open(sys.argv[1], "w"))
`

// routeQueriesWork is what holds under every contract: the reads.
var routeQueriesWork = map[string]string{"if_nameindex": "ok", "addrconfig": "ok", "dump_sendto": "ok", "dump_sendmsg": "ok",
	"dump_send": "ok", "dump_go": "ok", "proc_net_route": "ok", "sys_class_net": "ok"}

// routeChangesRefused is what a net: section keeps refused at every tier: EACCES and a line from the supervisor, on the
// calls it reads, and the kernel's own EPERM on those it does not.
var routeChangesRefused = map[string]string{"add_sendto": "EACCES", "add_sendmsg": "EACCES", "add_behind_get": "EACCES",
	"add_send": "EPERM", "add_write": "EPERM", "ifflags": "EPERM", "to_process": "EACCES", "to_group": "EACCES",
	"connect": "EACCES", "generic": "EPROTONOSUPPORT", "sock_diag": "EPROTONOSUPPORT"}

func checkRouteProbe(t *testing.T, got map[string]string, wants ...map[string]string) {
	t.Helper()
	for _, want := range wants {
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s = %q, want %q (all: %v)", k, got[k], v, got)
			}
		}
	}
}

// familyLines counts a run's net lines to the netlink family by verdict and rule.
func familyLines(t *testing.T, evs []*record.Event) map[string]int {
	t.Helper()
	n := map[string]int{}
	for _, l := range lines(t, evs, record.KindNet) {
		if l["dst"] == "family(16)" {
			n[fmt.Sprintf("%v/%v", l["_verdict"], l["_rule"])]++
		}
	}
	return n
}

// TestIntegrationRouteQueries is ADR 0128 at tier 1. Under a net: section, with and without a listener policy (which
// notifies the bind every one of these opens with), the interface lists work and no refused line stands for a read:
// the counts are exact, so a query refused, by the send or by the bind, is one line too many. A change refused by the
// supervisor is one line each, and one sent by a call it does not read comes back EPERM from the kernel, whose test
// here is on an agent with no capability; TestRootRouteChangesRefused is the same for one that was root. With no net:
// section the reads work too, a change on a call the relay reads is refused the same, and the rest is ADR 0070's.
func TestIntegrationRouteQueries(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	unaddressed := map[string]string{"add_send": "EPERM", "add_write": "EPERM", "ifflags": "EPERM"}
	refusedByRelay := map[string]string{"add_sendto": "EACCES", "add_sendmsg": "EACCES", "add_behind_get": "EACCES",
		"to_process": "EACCES", "to_group": "EACCES", "connect": "EACCES"}
	for _, tc := range []struct {
		name  string
		net   string
		wants []map[string]string
		lines map[string]int // refused lines to the netlink family, every one of them
	}{
		{"net: {}", "net: {}\n", []map[string]string{routeQueriesWork, routeChangesRefused},
			map[string]int{"refused/route-change": 3, "refused/unmatched": 1, "refused/builtin.host_ipc": 2}},
		{"a listener policy", "net:\n  listen: [\"tcp://127.0.0.1:0\"]\n", []map[string]string{routeQueriesWork, routeChangesRefused},
			map[string]int{"refused/route-change": 3, "refused/unmatched": 1, "refused/builtin.host_ipc": 2}},
		{"no net: section", "", []map[string]string{routeQueriesWork, unaddressed, refusedByRelay,
			{"generic": "ok", "sock_diag": "ok"}},
			map[string]int{"refused/route-change": 3, "refused/builtin.host_ipc": 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, contractFor("routequery", []string{python}, []string{python, resolved})+tc.net)
			script := filepath.Join(f.dir, "probe.py")
			if err := os.WriteFile(script, []byte(routeProbe), 0o644); err != nil {
				t.Fatal(err)
			}
			agentOwns(t, script)
			out := filepath.Join(f.out, "result.json")
			if _, err := Run(context.Background(), f.rt, []string{python, script, out}, f.deps(t, nil)); err != nil {
				t.Fatalf("Run: %v", err)
			}
			raw, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("the probe wrote nothing: %v", err)
			}
			got := map[string]string{}
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			checkRouteProbe(t, got, tc.wants...)
			counts := familyLines(t, events(t, runDirs(t, f.root)[0]))
			if counts["allow/route-query"] == 0 {
				t.Errorf("no allow line for the queries: %v", counts)
			}
			delete(counts, "allow/route-query")
			if fmt.Sprint(counts) != fmt.Sprint(tc.lines) {
				t.Errorf("refused netlink lines %v, want %v", counts, tc.lines)
			}
		})
	}
}

// TestIntegrationNodeInterfaces is the program the item was found with: Node's os.networkInterfaces under a net:
// section, through libuv and glibc's getifaddrs. It failed EACCES and the run's ledger had a refused family(16).
func TestIntegrationNodeInterfaces(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skipf("no node: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(node)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, contractFor("routenode", []string{node}, []string{node, resolved})+"net: {}\n")
	script := filepath.Join(f.dir, "probe.js")
	const probe = `require("fs").writeFileSync(process.argv[2], JSON.stringify(Object.keys(require("os").networkInterfaces())))`
	if err := os.WriteFile(script, []byte(probe), 0o644); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, script)
	out := filepath.Join(f.out, "result.json")
	if _, err := Run(context.Background(), f.rt, []string{node, script, out}, f.deps(t, nil)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("node wrote nothing: %v", err)
	}
	var names []string
	if err := json.Unmarshal(raw, &names); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(names, " "), "lo") {
		t.Errorf("os.networkInterfaces gave %v, want lo among them", names)
	}
	counts := familyLines(t, events(t, runDirs(t, f.root)[0]))
	if counts["allow/route-query"] == 0 || len(counts) != 1 {
		t.Errorf("netlink lines %v, want allow/route-query alone", counts)
	}
}

// TestIntegrationGoInterfaces is Go's own net.Interfaces and net.InterfaceAddrs, which open a route socket themselves
// rather than go through the C library (bind, sendto with the 17 bytes dump_go sends, getsockname, recvfrom). ADR 0128
// names them among the callers it fixes, and until now only python3's copy of their bytes had run. The run's list is the
// test's own, since a run shares the host's network namespace, and each section reads the same with no refused line.
func TestIntegrationGoInterfaces(t *testing.T) {
	// Built from its package path, the form test/vm/go-shim.sh serves prebuilt in the root guest.
	bin := filepath.Join(t.TempDir(), "ifaces")
	build := exec.Command("go", "build", "-o", bin, "github.com/attention-span-ai/tego/test/workloads/ifaces")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, out)
	}
	agentReaches(t, bin)
	var want []string
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range ifs {
		want = append(want, i.Name)
	}
	for _, tc := range []struct{ name, net string }{
		{"net: {}", "net: {}\n"},
		{"a listener policy", "net:\n  listen: [\"tcp://127.0.0.1:0\"]\n"},
		{"no net: section", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, contractFor("routego", []string{bin}, []string{bin})+tc.net)
			out := filepath.Join(f.out, "result.json")
			if _, err := Run(context.Background(), f.rt, []string{bin, out}, f.deps(t, nil)); err != nil {
				t.Fatalf("Run: %v", err)
			}
			raw, err := os.ReadFile(out)
			if err != nil {
				t.Fatalf("the workload wrote nothing: %v", err)
			}
			var got struct {
				Names, Addrs []string
				Err          string
			}
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			if got.Err != "" || fmt.Sprint(got.Names) != fmt.Sprint(want) || len(got.Addrs) == 0 {
				t.Errorf("net.Interfaces in the run: %+v, want names %v and some addresses", got, want)
			}
			counts := familyLines(t, events(t, runDirs(t, f.root)[0]))
			if counts["allow/route-query"] == 0 || len(counts) != 1 {
				t.Errorf("netlink lines %v, want allow/route-query alone", counts)
			}
		})
	}
}

// loAddrs is lo's addresses in the test's own view, which is the host's: the run shares its network namespace.
func loAddrs(t *testing.T) string {
	t.Helper()
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	addrs, err := lo.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprint(addrs)
}

// newRouteScene is a root run of the probe as a setuid-root copy of python3, under a contract with setuid: true. The
// copy goes on the root filesystem: a test's temporary directory is on /tmp, which a guest and most hosts mount nosuid,
// where the setuid bit would do nothing.
func newRouteScene(t *testing.T, bin, tier, netSection string) (*askReadScene, string) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	base := "/var/tmp"
	if _, err := os.Stat(base); err != nil {
		base = "/" // a guest's initramfs has no /var/tmp, and its root is no mount of nosuid
	}
	dir, err := os.MkdirTemp(base, "tego-routeprobe-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		t.Fatal(err)
	}
	if st.Flags&unix.ST_NOSUID != 0 {
		t.Fatalf("%s is on a nosuid mount: the setuid copy would run with no root at all", dir)
	}
	suid := filepath.Join(dir, "python-suid")
	raw, err := os.ReadFile(resolved)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(suid, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(suid, 0o755|os.ModeSetuid); err != nil { // not 0o4755: os.FileMode keeps the bit elsewhere
		t.Fatal(err)
	}
	contract := fmt.Sprintf(`version: 0
name: rootroute
command: ["/bin/sh"]
tier: landlock
setuid: true
fs:
  write: ["./out/"]
exec:
  allow: ["/bin/sh", %q]
%senv:
  pass: ["PATH", "HOME"]
limits:
  pids: 64
record: summary
`, suid, netSection)
	s := &askReadScene{bin: bin}
	// As newAskMutationScene: the fixture compiles at the tier this test process offers, and the file tego runs
	// names the root tier.
	s.f = newFixture(t, strings.Replace(contract, "setuid: true\n", "", 1))
	pinned := strings.Replace(contract, "tier: landlock\n", "tier: "+tier+"\n", 1)
	if err := os.WriteFile(filepath.Join(s.f.dir, "agent.yaml"), []byte(pinned), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.f.dir, "probe.py"), []byte(routeProbe), 0o600); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/sh\nexec %q probe.py out/result.json\n", suid)
	if err := os.WriteFile(filepath.Join(s.f.dir, "agent.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, filepath.Join(s.f.dir, "agent.sh"), filepath.Join(s.f.dir, "probe.py"), filepath.Join(s.f.dir, "agent.yaml"))
	s.env = isolatedEnv(t, s.f)
	return s, python
}

// TestRootRouteChangesRefused is ADR 0128 for the one agent that can hold CAP_NET_ADMIN: under setuid: true a
// setuid-root program in a run under a net: section is root with every other capability, and changes nothing: not by a
// send the supervisor reads, nor by the send(2), write(2) and ioctl(2) only the kernel sees, because the run's bounding
// set has no CAP_NET_ADMIN to gain. Reads work as they do for anyone. The control is the same program with no net:
// section, which keeps the capability: its unaddressed changes land, which shows the probe's changes are real ones and
// the check of lo's addresses sees them, and the ones the relay reads stay refused.
func TestRootRouteChangesRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: tiers cgroup and bpflsm")
	}
	if _, _, ok := agentUID(t); !ok {
		t.Skip("needs SUDO_UID naming the invoking user, as `sudo go test` and test/vm/root-suites.sh give")
	}
	bin := tegoBPFBinary(t)
	const capSysAdmin = 21
	run := func(t *testing.T, tier, netSection string) (map[string]string, []*record.Event, string) {
		t.Helper()
		s, python := newRouteScene(t, bin, tier, netSection)
		t.Cleanup(func() {
			if out, err := exec.Command(python, filepath.Join(s.f.dir, "probe.py"), "--clean").CombinedOutput(); err != nil {
				t.Errorf("taking the probe's addresses off lo: %v\n%s", err, out)
			}
		})
		evs := s.runToEnd(t)
		got := map[string]string{}
		if err := json.Unmarshal([]byte(s.out("result.json")), &got); err != nil {
			t.Fatalf("the probe's result: %v (lines %v)", err, lines(t, evs, record.KindNet))
		}
		if got["euid"] != "0" {
			t.Fatalf("the setuid copy runs as euid %s (no_new_privs %s, %s %s): this run proves nothing about a root agent",
				got["euid"], got["nnp"], got["exe"], got["exe_stat"])
		}
		eff, err := strconv.ParseUint(got["capeff"], 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		if eff&(1<<capSysAdmin) == 0 {
			t.Fatalf("CapEff %x has no CAP_SYS_ADMIN: the setuid exec gained no root", eff)
		}
		return got, evs, loAddrs(t)
	}
	for _, tier := range []string{"cgroup", "bpflsm"} {
		t.Run(tier, func(t *testing.T) {
			probe, _ := newRouteScene(t, bin, tier, "net: {}\n")
			testutil.RequireTier(t, probe.tego(t, "doctor", "--require", tier), tier)
			if tier == "cgroup" {
				// Always exercise the listener availability change, even on a kernel with a working plane.
				t.Run("fanotify refuses setuid with built-in denied reads", func(t *testing.T) {
					for _, netSection := range []string{"net: {}\n", ""} {
						s, _ := newRouteScene(t, bin, tier, netSection)
						s.env = append(s.env, "TEGO_TEST_PLANE=fanotify")
						cmd := s.tego(t, "run", filepath.Join(s.f.dir, "agent.yaml"), "--", "/bin/sh", "agent.sh")
						cmd.Dir = s.f.dir
						out, err := cmd.CombinedOutput()
						if code := exitCodeOf(t, err); code != 125 || !strings.Contains(string(out), "cannot hold this contract's reads under setuid: true") {
							t.Fatalf("listener setuid run: exit %d, want 125 naming setuid refusal:\n%s", code, out)
						}
						if got := s.out("result.json"); got != "" {
							t.Fatalf("refused agent ran: %s", got)
						}
					}
				})
				raw, err := probe.tego(t, "doctor", "--json").Output()
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
				if report.Plane == nil {
					t.Fatal("root doctor report has no plane answer")
				}
				if report.Plane.Selected == "fanotify" {
					return
				}
			}
			t.Run("net section", func(t *testing.T) {
				got, evs, addrs := run(t, tier, "net: {}\n")
				checkRouteProbe(t, got, routeQueriesWork, routeChangesRefused)
				bnd, err := strconv.ParseUint(got["capbnd"], 16, 64)
				if err != nil {
					t.Fatal(err)
				}
				if bnd&(1<<unix.CAP_NET_ADMIN) != 0 {
					t.Errorf("CapBnd %x holds CAP_NET_ADMIN", bnd)
				}
				if strings.Contains(addrs, "10.77.0.") {
					t.Errorf("the run changed lo: %s", addrs)
				}
				counts := familyLines(t, evs)
				if counts["allow/route-query"] == 0 || counts["refused/route-change"] != 3 || counts["refused/unmatched"] != 1 || counts["refused/builtin.host_ipc"] != 2 {
					t.Errorf("netlink lines %v, want route-query, 3 refused route-change, 1 refused unmatched, 2 refused builtin.host_ipc", counts)
				}
			})
			t.Run("control: no net section keeps the capability", func(t *testing.T) {
				got, evs, addrs := run(t, tier, "")
				checkRouteProbe(t, got, routeQueriesWork, map[string]string{"add_send": "ok", "add_write": "ok", "ifflags": "ok",
					"add_sendto": "EACCES", "add_sendmsg": "EACCES", "add_behind_get": "EACCES"})
				for _, want := range []string{"10.77.0.1/32", "10.77.0.2/32"} {
					if !strings.Contains(addrs, want) {
						t.Errorf("lo has no %s: the probe's change did not land (%s; lines %v)", want, addrs, familyLines(t, evs))
					}
				}
				if strings.Contains(addrs, "10.77.0.3") || strings.Contains(addrs, "10.77.0.4") || strings.Contains(addrs, "10.77.0.5") {
					t.Errorf("a change the relay read landed: %s", addrs)
				}
			})
		})
	}
}
