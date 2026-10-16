// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// dgramProbe sends one DNS query to argv[1]:argv[2] in each way a program can: connect then send (glibc's
// connected resolver), and from an unconnected socket with sendto, sendmsg and sendmmsg (the last through
// ctypes, which Python's socket module does not wrap). It writes what each returned, "ok" or the errno's name.
const dgramProbe = `import ctypes, errno, json, socket, struct, sys
host, port, out = sys.argv[1], int(sys.argv[2]), sys.argv[3]
query = bytes.fromhex("abcd01000001000000000000076578616d706c6503636f6d0000010001")
res = {}
def attempt(key, f):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        f(s)
        res[key] = "ok"
    except OSError as e:
        res[key] = errno.errorcode.get(e.errno, str(e.errno))
    finally:
        s.close()
def connected(s):
    s.connect((host, port))
    s.send(query)
class iovec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]
class msghdr(ctypes.Structure):
    _fields_ = [("name", ctypes.c_void_p), ("namelen", ctypes.c_uint32), ("iov", ctypes.POINTER(iovec)),
                ("iovlen", ctypes.c_size_t), ("control", ctypes.c_void_p), ("controllen", ctypes.c_size_t),
                ("flags", ctypes.c_int)]
class mmsghdr(ctypes.Structure):
    _fields_ = [("hdr", msghdr), ("len", ctypes.c_uint)]
def sendmmsg(s):
    libc = ctypes.CDLL(None, use_errno=True)
    sa = ctypes.create_string_buffer(struct.pack("=H", socket.AF_INET) + struct.pack("!H", port) +
                                     socket.inet_aton(host) + bytes(8), 16)
    data = ctypes.create_string_buffer(query, len(query))
    iov = iovec(ctypes.cast(data, ctypes.c_void_p), len(query))
    m = mmsghdr()
    m.hdr.name, m.hdr.namelen = ctypes.cast(sa, ctypes.c_void_p), 16
    m.hdr.iov, m.hdr.iovlen = ctypes.pointer(iov), 1
    if libc.sendmmsg(s.fileno(), ctypes.byref(m), 1, 0) < 0:
        e = ctypes.get_errno()
        raise OSError(e, errno.errorcode.get(e, str(e)))
attempt("connect", connected)
attempt("sendto", lambda s: s.sendto(query, (host, port)))
attempt("sendmsg", lambda s: s.sendmsg([query], [], 0, (host, port)))
attempt("sendmmsg", sendmmsg)
json.dump(res, open(out, "w"))
`

// dgramForms are the probe's four results, in its order.
var dgramForms = []string{"connect", "sendto", "sendmsg", "sendmmsg"}

// runDgramProbe runs the probe at tier landlock under a contract with the given net: section, aimed at host:port,
// and returns its results and the run's net lines for that destination.
func runDgramProbe(t *testing.T, netSection, host string, port int, tweak func(*config.Machine)) (map[string]string, []*record.Event) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixtureWithMachine(t, contractFor("dgram-refuse", []string{python}, []string{python, resolved})+netSection, tweak)
	script := filepath.Join(f.dir, "probe.py")
	if err := os.WriteFile(script, []byte(dgramProbe), 0o644); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, script)
	out := filepath.Join(f.out, "result.json")
	if _, err := Run(context.Background(), f.rt, []string{python, script, host, strconv.Itoa(port), out}, f.deps(t, nil)); err != nil {
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
	dst := net.JoinHostPort(host, strconv.Itoa(port))
	var lines []*record.Event
	for _, e := range events(t, runDirs(t, f.root)[0]) {
		var p record.NetPayload
		if e.Kind == record.KindNet && e.DecodePayload(&p) == nil && p.Dst == dst {
			lines = append(lines, e)
		}
	}
	return got, lines
}

// bestEffortOf reads a net line's best_effort mark.
func bestEffortOf(t *testing.T, e *record.Event) bool {
	t.Helper()
	var p struct {
		BestEffort bool `json:"best_effort"`
	}
	if err := e.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	return p.BestEffort
}

// TestRefusedDatagramIsNotSent is finding F1 of the interactive-codex POC on the real kernel at tier landlock
// (supervisor R13b as amended 2026-10-16): a datagram whose destination the contract does not admit is refused
// with EACCES, whether its socket is connected or the address rides on sendto, sendmsg or sendmmsg, and a local
// UDP responder receives nothing. Before, the three unconnected forms were continued under a refused line marked
// best_effort and the responder got every one. The control admits the responder, which then gets the datagrams,
// so the empty count is the boundary's doing and not a responder that never listened.
func TestRefusedDatagramIsNotSent(t *testing.T) {
	for _, tc := range []struct {
		name    string
		admit   bool
		wantRes string
	}{
		{"refused", false, "EACCES"},
		{"admitted (control)", true, "ok"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			port := u.LocalAddr().(*net.UDPAddr).Port
			section := "net:\n  allow: []\n"
			if tc.admit {
				section = fmt.Sprintf("net:\n  allow: [\"127.0.0.1:%d\"]\n", port)
			}
			got, lines := runDgramProbe(t, section, "127.0.0.1", port, nil)
			for _, form := range dgramForms {
				if got[form] != tc.wantRes {
					t.Errorf("%s = %s, want %s (all: %v)", form, got[form], tc.wantRes, got)
				}
			}
			received := 0
			buf := make([]byte, 512)
			for {
				_ = u.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				if _, _, err := u.ReadFromUDP(buf); err != nil {
					break
				}
				received++
			}
			want := 0
			if tc.admit {
				want = len(dgramForms)
			}
			if received != want {
				t.Errorf("the responder received %d datagrams, want %d", received, want)
			}
			if len(lines) != len(dgramForms) {
				t.Fatalf("%d net lines for the responder, want one per form: %v", len(lines), lines)
			}
			for _, e := range lines {
				switch {
				case !tc.admit && (e.Verdict != record.VerdictRefused || e.Reason != record.ReasonNetNotAllowed || bestEffortOf(t, e)):
					t.Errorf("line %s/%s best_effort=%t, want an enforced refusal", e.Verdict, e.Reason, bestEffortOf(t, e))
				case tc.admit && e.Verdict != record.VerdictAllow:
					t.Errorf("line %s, want allow", e.Verdict)
				}
			}
		})
	}
}

// unixDgramProbe sends one datagram to the unix name argv[1] from an unconnected socket, with sendto and with
// sendmsg, and writes what each returned.
const unixDgramProbe = `import errno, json, socket, sys
path, out = sys.argv[1], sys.argv[2]
res = {}
for key, f in (("sendto", lambda s: s.sendto(b"x", path)), ("sendmsg", lambda s: s.sendmsg([b"y"], [], 0, path))):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        f(s)
        res[key] = "ok"
    except OSError as e:
        res[key] = errno.errorcode.get(e.errno, str(e.errno))
    finally:
        s.close()
json.dump(res, open(out, "w"))
`

// TestRefusedUnixDatagramIsNotSent is F1 for a unix datagram at tier landlock: a datagram to a unix name the
// contract does not admit — a socket the test bound outside every write entry — is refused with EACCES and the
// socket receives nothing; with the name declared it receives both.
func TestRefusedUnixDatagramIsNotSent(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	for _, declared := range []bool{false, true} {
		t.Run(fmt.Sprintf("declared=%t", declared), func(t *testing.T) {
			dir, err := os.MkdirTemp("", "ud")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			path := filepath.Join(dir, "r.sock")
			agentReaches(t, path)
			c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			if err := os.Chmod(path, 0o777); err != nil {
				t.Fatal(err)
			}
			section := "net:\n  allow: []\n"
			if declared {
				section = fmt.Sprintf("net:\n  allow: [\"unix:%s\"]\n", path)
			}
			f := newFixture(t, contractFor("unix-dgram", []string{python}, []string{python, resolved})+section)
			script := filepath.Join(f.dir, "probe.py")
			if err := os.WriteFile(script, []byte(unixDgramProbe), 0o644); err != nil {
				t.Fatal(err)
			}
			agentOwns(t, script)
			out := filepath.Join(f.out, "result.json")
			if _, err := Run(context.Background(), f.rt, []string{python, script, path, out}, f.deps(t, nil)); err != nil {
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
			want, wantN := "EACCES", 0
			if declared {
				want, wantN = "ok", 2
			}
			for _, form := range []string{"sendto", "sendmsg"} {
				if got[form] != want {
					t.Errorf("%s = %s, want %s (all: %v)", form, got[form], want, got)
				}
			}
			n := 0
			buf := make([]byte, 16)
			for {
				_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
				if _, _, err := c.ReadFrom(buf); err != nil {
					break
				}
				n++
			}
			if n != wantN {
				t.Errorf("the socket received %d datagrams, want %d", n, wantN)
			}
			for _, e := range events(t, runDirs(t, f.root)[0]) {
				var p record.NetPayload
				if e.Kind != record.KindNet || e.DecodePayload(&p) != nil || p.Dst != "unix:"+path {
					continue
				}
				if !declared && (e.Verdict != record.VerdictRefused || bestEffortOf(t, e)) {
					t.Errorf("line %s best_effort=%t, want an enforced refusal", e.Verdict, bestEffortOf(t, e))
				}
			}
		})
	}
}

// TestDNSOffRefusesConnectedAndUnconnectedLookups is F1's own case: under net.dns.mode: off the run has no
// resolver exception, so a lookup to the machine resolver is refused however it is sent. Codex's WebSocket client
// sent its lookups from an unconnected socket, which was recorded refused with best_effort and answered by the
// resolver; its start-up lookups, from a connected socket, were refused. The machine resolver is pinned to
// 127.0.0.53:53 so the case does not depend on this host's resolv.conf. The control, net.dns.mode: system,
// admits the same four forms under net.resolver: what the resolver then answers, if one listens, is not the
// question.
func TestDNSOffRefusesConnectedAndUnconnectedLookups(t *testing.T) {
	resolver := netip.MustParseAddrPort("127.0.0.53:53")
	pin := func(m *config.Machine) {
		m.Resolver = config.Setting[config.ResolverMode]{Value: config.ResolverMode{Servers: []netip.AddrPort{resolver}}}
	}
	for _, tc := range []struct {
		mode, wantRes string
		verdict       record.Verdict
	}{
		{"off", "EACCES", record.VerdictRefused},
		{"system", "ok", record.VerdictAllow},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			section := "net:\n  allow: []\n  dns:\n    mode: " + tc.mode + "\n"
			got, lines := runDgramProbe(t, section, "127.0.0.53", 53, pin)
			for _, form := range dgramForms {
				if got[form] != tc.wantRes {
					t.Errorf("%s = %s, want %s (all: %v)", form, got[form], tc.wantRes, got)
				}
			}
			if len(lines) != len(dgramForms) {
				t.Fatalf("%d net lines for the resolver, want one per form: %v", len(lines), lines)
			}
			for _, e := range lines {
				if e.Verdict != tc.verdict {
					t.Errorf("line %s rule %s, want %s", e.Verdict, e.Rule, tc.verdict)
				}
				if tc.verdict == record.VerdictRefused && bestEffortOf(t, e) {
					t.Errorf("the refusal of a lookup is marked best_effort, though it was enforced")
				}
			}
		})
	}
}
