// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// unixAskProbe connects argv[2] times, one after another, to the unix socket argv[1] names (a leading @ for an
// abstract name), and writes each connect's outcome to out/rc<i>: "ok" once the listener's greeting arrived, else
// the errno's name.
const unixAskProbe = `import errno, socket, sys
target, n = sys.argv[1], int(sys.argv[2])
addr = "\0" + target[1:] if target.startswith("@") else target
for i in range(1, n + 1):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(addr)
        s.settimeout(10)
        got = s.recv(2)
        r = "ok" if got == b"hi" else "short:" + repr(got)
    except OSError as e:
        r = errno.errorcode.get(e.errno, str(e.errno))
    s.close()
    with open("out/rc%d" % i, "w") as f:
        f.write(r)
`

// newAskUnixScene is a run whose agent, a Python probe, connects to a unix socket the test listens on outside every
// entry, which only the contract's net.ask unix: scope names, at tier with the tego binary bin: every connect is held
// for a person (ADR 0008).
func newAskUnixScene(t *testing.T, bin, tier, timeout, target string, connects int) *askReadScene {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	s := &askReadScene{bin: bin}
	contract := fmt.Sprintf(`version: 0
name: iaskunix
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/"]
exec:
  allow: ["/bin/sh", %q, %q]
net:
  ask: [%q]
env:
  pass: ["PATH", "HOME"]
ask:
  timeout: %s
limits:
  pids: 64
record: summary
`, python, resolved, "unix:"+target, timeout)
	// newFixture compiles for the tiers this test process offers, which a root tier is not (its binary carries no BPF
	// objects): the contract is compiled at tier landlock, and the file tego runs names the tier.
	s.f = newFixture(t, contract)
	if tier != "landlock" {
		pinned := strings.Replace(contract, "tier: landlock\n", "tier: "+tier+"\n", 1)
		if err := os.WriteFile(filepath.Join(s.f.dir, "agent.yaml"), []byte(pinned), 0o600); err != nil {
			t.Fatal(err)
		}
		agentOwns(t, filepath.Join(s.f.dir, "agent.yaml"))
	}
	if err := os.WriteFile(filepath.Join(s.f.dir, "probe.py"), []byte(unixAskProbe), 0o600); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/sh\nexec %q probe.py %q %d\n", python, target, connects)
	if err := os.WriteFile(filepath.Join(s.f.dir, "agent.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, filepath.Join(s.f.dir, "agent.sh"), filepath.Join(s.f.dir, "probe.py"))
	s.env = isolatedEnv(t, s.f)
	return s
}

// listenUnix serves a greeting on a unix socket at target, a path or (with a leading @) an abstract name, until the
// test ends, and counts the connections it accepted.
func listenUnix(t *testing.T, target string) *atomic.Int32 {
	t.Helper()
	ln, err := net.Listen("unix", target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(target, "@") {
		// As root (the KVM root suites) the agent runs as the invoking user, whose connect needs write permission.
		if err := os.Chmod(target, 0o777); err != nil {
			t.Fatal(err)
		}
		agentReaches(t, target) // every directory above the socket, its own included
	}
	accepted := new(atomic.Int32)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_, _ = c.Write([]byte("hi"))
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done })
	return accepted
}

// The net.ask unix: scope end to end at tier landlock (ASK-UNIX): the real tego binary runs a contract whose agent
// connects to a socket only that scope names; a person answers from separate tego processes over the run's real
// broker socket, or nobody answers. An approval is carried out by the R11 relay, as the agent, and reaches the
// listener; a denial or a timeout refuses the connect with that reason and the listener sees nothing; --always and
// ask.on_timeout: refuse_always stand for the next connect to the same name, as they do for a file. Everything is
// unprivileged: Landlock, the seccomp listener and the run's delegated cgroup.
func TestIntegrationAskUnixApproveDenyAndTimeout(t *testing.T) {
	bin := tegoBinary(t)
	for _, tc := range askUnixCases {
		t.Run(tc.name, func(t *testing.T) { runAskUnixCase(t, bin, "landlock", tc) })
	}
}

// TestRootAskUnix is the net.ask unix: scope end to end at the root tiers (ASK-UNIX), from a root launcher with the
// agent dropped to the invoking user: at tier cgroup and, where doctor says the machine has it, tier bpflsm, the
// approved pathname is relayed by the inode the relay resolved, which the run's kernel programs admit from the
// launcher's cgroup, and the approved abstract name by the one-connect grant the supervisor makes for it
// (Handle.GrantUnix), which connect_unix (6.7+) or the plane's socket_connect (below 6.7) consumes; a denial and a
// timeout connect nothing. Before the grant an approved abstract name was refused ask-unavailable at these tiers.
func TestRootAskUnix(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: tiers cgroup and bpflsm")
	}
	if _, _, ok := agentUID(t); !ok {
		t.Skip("needs SUDO_UID naming the invoking user, as `sudo go test` and test/vm/root-suites.sh give")
	}
	bin := tegoBPFBinary(t)
	for _, tier := range []string{"cgroup", "bpflsm"} {
		t.Run(tier, func(t *testing.T) {
			// Skipped only on doctor's answer that the machine lacks the tier; any other end of the probe fails. The
			// probe takes a scene's isolation, as every command of the test does.
			probe := newAskUnixScene(t, bin, tier, "30s", "@tego-askunix-probe", 1)
			testutil.RequireTier(t, probe.tego(t, "doctor", "--require", tier), tier)
			for _, tc := range askUnixCases {
				if tc.connects > 1 {
					continue // --always and refuse_always are the broker's, the same at every tier
				}
				t.Run(tc.name, func(t *testing.T) { runAskUnixCase(t, bin, tier, tc) })
			}
			// The relay is the same at every tier, and the kernel admits its /proc/self/fd/<n> name from the
			// launcher's cgroup, so the supervisor's decision on the place a name reaches is the one that holds here too.
			t.Run("scope places", func(t *testing.T) { runAskUnixPlaces(t, bin, tier) })
			t.Run("scope spellings", func(t *testing.T) { runAskUnixSpellings(t, bin, tier) })
		})
	}
}

// unixPlaceProbe binds and listens on out/app.sock, which the contract's first net.ask unix: scope names, and on
// out/own.sock beside it; out/ext.sock, the second scope's place, holds a listener outside the run. It makes a symlink
// and a hard link to each scope's socket and connects through each, then renames each socket away from its scope's
// place and connects under the new name. Each outcome goes to out/rc-<name>: "ok", else the errno's name.
const unixPlaceProbe = `import errno, os, socket
ls = []
for name in ("app.sock", "own.sock"):
    l = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    l.bind("out/" + name)
    l.listen(8)
    ls.append(l)
os.symlink("app.sock", "out/alias")
os.symlink("ext.sock", "out/extlink")
os.link("out/app.sock", "out/hard")
os.link("out/ext.sock", "out/exthard")
def connect(name):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect("out/" + name)
        r = "ok"
    except OSError as e:
        r = errno.errorcode.get(e.errno, str(e.errno))
    s.close()
    with open("out/rc-" + name, "w") as f:
        f.write(r)
for name in ("alias", "extlink", "hard", "exthard", "own.sock"):
    connect(name)
os.rename("out/app.sock", "out/moved")
connect("moved")
os.rename("out/ext.sock", "out/extmoved")
connect("extmoved")
os.rename("out/extmoved", "out/ext.sock")
`

// TestIntegrationAskUnixScopeIsAPlace is R11c's model end to end at tier landlock (ADR 0008's note of 2026-10-19): a
// net.ask unix: scope is a place. A connect whose name reaches it — here through a
// symlink the agent made — is asked, whoever bound the socket there: the run (out/app.sock) or a process outside it
// (out/ext.sock); nobody answers, so each is refused ask-timeout. Under any other name — a hard link, the name the
// socket was renamed to — a connect is decided on the socket it reaches, as R11a decides every one: the run's own
// socket is the write entry's, as a socket it bound there afresh would be, and the outside process's is refused
// unix-foreign.
func TestIntegrationAskUnixScopeIsAPlace(t *testing.T) {
	runAskUnixPlaces(t, tegoBinary(t), "landlock")
}

// runAskUnixPlaces runs TestIntegrationAskUnixScopeIsAPlace's scene with the tego binary bin at tier.
func runAskUnixPlaces(t *testing.T, bin, tier string) {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	project := unixSocketProject(t)
	scope, ext := filepath.Join(project, "out", "app.sock"), filepath.Join(project, "out", "ext.sock")
	contract := fmt.Sprintf(`version: 0
name: iaskplace
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/"]
exec:
  allow: ["/bin/sh", %q, %q]
net:
  ask: [%q, %q]
env:
  pass: ["PATH", "HOME"]
ask:
  timeout: 2s
limits:
  pids: 64
record: summary
`, python, resolved, "unix:"+scope, "unix:"+ext)
	s := &askReadScene{bin: bin, f: newFixtureIn(t, project, contract, nil)}
	if tier != "landlock" {
		pinned := strings.Replace(contract, "tier: landlock\n", "tier: "+tier+"\n", 1)
		if err := os.WriteFile(filepath.Join(s.f.dir, "agent.yaml"), []byte(pinned), 0o600); err != nil {
			t.Fatal(err)
		}
		agentOwns(t, filepath.Join(s.f.dir, "agent.yaml"))
	}
	accepted := listenUnix(t, ext)
	// As root (the KVM root suites) the agent runs as the invoking user, and fs.protected_hardlinks lets it link only
	// a socket file it owns.
	agentOwns(t, ext)
	if err := os.WriteFile(filepath.Join(s.f.dir, "probe.py"), []byte(unixPlaceProbe), 0o600); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/sh\nexec %q probe.py\n", python)
	if err := os.WriteFile(filepath.Join(s.f.dir, "agent.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, filepath.Join(s.f.dir, "agent.sh"), filepath.Join(s.f.dir, "probe.py"))
	s.env = isolatedEnv(t, s.f)
	evs := s.runToEnd(t)
	net := lines(t, evs, record.KindNet)
	for _, c := range []struct{ name, rc, verdict, rule, reason string }{
		{"alias", "EACCES", "refused", "net[unix:" + scope + "]", "ask-timeout"},
		{"extlink", "EACCES", "refused", "net[unix:" + ext + "]", "ask-timeout"},
		{"hard", "ok", "allow", "fs.write[./out/]", ""},
		{"moved", "ok", "allow", "fs.write[./out/]", ""},
		{"own.sock", "ok", "allow", "fs.write[./out/]", ""},
		{"exthard", "EACCES", "refused", "unix-foreign", ""},
		{"extmoved", "EACCES", "refused", "unix-foreign", ""},
	} {
		if rc := s.out("rc-" + c.name); rc != c.rc {
			t.Errorf("connect to out/%s came to %q; want %q", c.name, rc, c.rc)
		}
		found := false
		for _, l := range net {
			if l["dst"] == "unix:out/"+c.name {
				found = true
				if l["_rule"] != c.rule || l["_verdict"] != c.verdict || (c.reason != "" && l["_reason"] != c.reason) {
					t.Errorf("out/%s: net line %v, want %s %s %s", c.name, l, c.verdict, c.rule, c.reason)
				}
			}
		}
		if !found {
			t.Errorf("no net line for out/%s: %v", c.name, net)
		}
	}
	if answers := lines(t, evs, record.KindAnswer); len(answers) != 2 {
		t.Errorf("answer lines %v: want two, the connects through the symlinks to each scope's place", answers)
	}
	if n := accepted.Load(); n != 0 {
		t.Errorf("the listener outside the run accepted %d connections; want none", n)
	}
}

// askUnixCase is one cell of the ask's end-to-end tests.
type askUnixCase struct {
	name, timeout string
	abstract      bool
	connects      int
	answer        []string // the verb and flags a person answers with; nil for nobody
	rc            string   // every connect's outcome
	reason        string   // the refusal's reason, "" for an approval
	by            string   // the first answer's by, a prefix
}

var askUnixCases = []askUnixCase{
	{name: "approve", timeout: "30s", connects: 1, answer: []string{"approve"}, rc: "ok", by: "uid:"},
	{name: "deny", timeout: "30s", connects: 1, answer: []string{"deny"}, rc: "EACCES", reason: "ask-denied", by: "uid:"},
	{name: "nobody answers", timeout: "2s", connects: 1, rc: "EACCES", reason: "ask-timeout", by: "timeout"},
	{name: "approve an abstract name", timeout: "30s", abstract: true, connects: 1, answer: []string{"approve"}, rc: "ok", by: "uid:"},
	{name: "deny an abstract name", timeout: "30s", abstract: true, connects: 1, answer: []string{"deny"}, rc: "EACCES", reason: "ask-denied", by: "uid:"},
	{name: "approve --always", timeout: "30s", connects: 2, answer: []string{"approve", "--always"}, rc: "ok", by: "uid:"},
	{name: "refuse_always on timeout", timeout: "2s\n  on_timeout: refuse_always", connects: 2, rc: "EACCES", reason: "ask-timeout", by: "timeout always"},
}

// runAskUnixCase runs tc with the tego binary bin at tier.
func runAskUnixCase(t *testing.T, bin, tier string, tc askUnixCase) {
	t.Helper()
	target := "@tego-askunix-" + strconv.Itoa(os.Getpid()) + "-" + tier + "-" + strings.ReplaceAll(tc.name, " ", "-")
	if !tc.abstract {
		// Not t.TempDir(): its path is past sun_path's 108 bytes.
		dir, err := os.MkdirTemp("", "askunix")
		if err == nil {
			t.Cleanup(func() { _ = os.RemoveAll(dir) })
			dir, err = filepath.EvalSymlinks(dir)
		}
		if err != nil {
			t.Fatal(err)
		}
		target = filepath.Join(dir, "app.sock")
	}
	accepted := listenUnix(t, target)
	s := newAskUnixScene(t, bin, tier, tc.timeout, target, tc.connects)
	run, dir := s.start(t)
	req := s.pending(t, filepath.Base(dir))
	if req["op"] != "connect" || req["target"] != "unix:"+target || req["rule"] != "net[unix:"+target+"]" || req["hold"] != "connect" {
		t.Fatalf("held request %v", req)
	}
	if tc.answer != nil {
		s.answer(t, append([]string{tc.answer[0], filepath.Base(dir), req["ask_id"].(string)}, tc.answer[1:]...)...)
	}
	evs := s.finish(t, run, dir)
	for i := 1; i <= tc.connects; i++ {
		if rc := s.out(fmt.Sprintf("rc%d", i)); rc != tc.rc {
			t.Fatalf("connect %d came to %q; want %q; the run's net lines: %v", i, rc, tc.rc, lines(t, evs, record.KindNet))
		}
	}
	if want := map[bool]int{true: 0, false: tc.connects}[tc.reason != ""]; accepted.Load() != int32(want) {
		t.Fatalf("the listener accepted %d connections; want %d", accepted.Load(), want)
	}
	answers := lines(t, evs, record.KindAnswer)
	if len(answers) != tc.connects || !strings.HasPrefix(answers[0]["by"].(string), tc.by) || (tc.reason != "" && answers[0]["answer_reason"] != tc.reason) {
		t.Fatalf("answer lines %v", answers)
	}
	for _, a := range answers[1:] {
		if a["by"] != "standing:"+req["ask_id"].(string) {
			t.Fatalf("a later connect's answer %v: want one by standing:%s", a, req["ask_id"])
		}
	}
	var net []map[string]any
	for _, l := range lines(t, evs, record.KindNet) {
		if l["dst"] == "unix:"+target {
			net = append(net, l)
		}
	}
	if len(net) != tc.connects {
		t.Fatalf("%d net lines for the socket, want %d: %v", len(net), tc.connects, net)
	}
	for _, l := range net {
		ok := l["_rule"] == "net[unix:"+target+"]" && l["proto"] == "unix"
		if tc.reason == "" {
			ok = ok && l["_verdict"] == "allow" && l["_authority"] == "human"
		} else {
			ok = ok && l["_verdict"] == "refused" && l["_reason"] == tc.reason
		}
		if !ok {
			t.Fatalf("net line %v", l)
		}
	}
}
