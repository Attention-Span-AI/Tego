// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// spellingConnect is the probes' connect: the outcome of a connect to name goes to out/rc-<label>, "ok" or the
// errno's name.
const spellingConnect = `import errno, os, socket
def connect(label, name):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(name)
        r = "ok"
    except OSError as e:
        r = errno.errorcode.get(e.errno, str(e.errno))
    s.close()
    with open("out/rc-" + label, "w") as f:
        f.write(r)
def listen(name):
    l = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    l.bind(name)
    l.listen(8)
    return l
`

// spellingNamesProbe makes out/sub, which does not exist when the run starts, binds the scope's socket there, and
// connects to it by a relative name, by the canonical name getcwd gives, and by the scope's declared name, read from
// the file target; then it renames the socket away and connects under the new name.
const spellingNamesProbe = spellingConnect + `os.mkdir("out/sub")
a = listen("out/sub/app.sock")
connect("rel", "out/sub/app.sock")
connect("cwd", os.getcwd() + "/out/sub/app.sock")
connect("scope", open("target").read())
os.rename("out/sub/app.sock", "out/sub/moved")
connect("moved", "out/sub/moved")
`

// spellingRetryProbe binds a socket of the run's own in out/sub, which does not exist yet (ENOENT: nothing is bound),
// makes the directory, binds the same socket again, as a retrying server does, and connects to it.
const spellingRetryProbe = spellingConnect + `l = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    l.bind("out/sub/x.sock")
    r = "ok"
except OSError as e:
    r = errno.errorcode.get(e.errno, str(e.errno))
with open("out/rc-first", "w") as f:
    f.write(r)
os.mkdir("out/sub")
l.bind("out/sub/x.sock")
l.listen(4)
connect("x.sock", "out/sub/x.sock")
`

// spellingApproveProbe makes out/sub, binds a socket there, and connects by the name the file target holds.
const spellingApproveProbe = spellingConnect + `os.mkdir("out/sub")
a = listen("out/sub/app.sock")
connect("app.sock", open("target").read())
`

// spellingAliasProbe binds out/app.sock, which a scope declared through a bind mount of out/ at alias/ names, and
// connects to it by the write entry's name and then by the bind mount's.
const spellingAliasProbe = spellingConnect + `a = listen("out/app.sock")
connect("app.sock", "out/app.sock")
connect("alias", "alias/app.sock")
`

// spellingNamedProbe connects, in order, to each name the file target holds, one per line, labelled 0, 1, ...
const spellingNamedProbe = spellingConnect + `for i, name in enumerate(open("target").read().split("\n")):
    connect(str(i), name)
`

// spellingDotDotProbe makes out/e/f and out/x/y, and out/x/y/lnk, a symlink to out/e/f, then connects, in order, to
// each name the file target holds, one per line, labelled 0, 1, ...
const spellingDotDotProbe = spellingConnect + `os.makedirs("out/e/f")
os.makedirs("out/x/y")
os.symlink("../../e/f", "out/x/y/lnk")
for i, name in enumerate(open("target").read().split("\n")):
    connect(str(i), name)
`

// spellingChainProbe connects by out/l0 and writes how many seconds the connect took to out/t-chain.
const spellingChainProbe = spellingConnect + `import time
t0 = time.monotonic()
connect("chain", "out/l0")
with open("out/t-chain", "w") as f:
    f.write("%.3f" % (time.monotonic() - t0))
`

// spellingDanglingFinalProbe makes out/alias, a symlink to where the scope's own name, out/f.sock, leads — out/real,
// which does not exist — and connects by both names.
const spellingDanglingFinalProbe = spellingConnect + `os.symlink("real/y.sock", "out/alias")
connect("alias", "out/alias")
connect("scope", "out/f.sock")
`

// TestIntegrationAskUnixScopeSpellings is R11c at tier landlock for a scope whose path is spelled another way than the
// names the run passes (ADR 0008's note of 2026-10-19).
func TestIntegrationAskUnixScopeSpellings(t *testing.T) {
	runAskUnixSpellings(t, tegoBinary(t), "landlock")
}

// runAskUnixSpellings runs TestIntegrationAskUnixScopeSpellings's cells with the tego binary bin at tier:
//   - the project reached through a symlink, the scope declared through it in a directory the run makes: a connect by
//     a relative name, by getcwd's canonical name and by the declared name all reach the scope's place and are asked
//     (nobody answers: ask-timeout), and the socket renamed away is the run's own, the write entry's (before, the
//     relative and canonical names were refused unix-ask-scope with nobody asked);
//   - a bind of the run's own socket whose directory is missing binds nothing and is one supervisor observed line
//     with its ENOENT, and the same socket bound after the directory is made is the write entry's;
//   - a connect by a relative name in the symlinked project, approved, is relayed with a person's authority;
//   - a scope declared through a symlink that leads nowhere when the run starts, whose target directory the run
//     makes, is approved and relayed (before, refused unmatched);
//   - a relative and an absolute name with a ".." after a symlinked directory, before the scope's missing one, are
//     both asked (before, the relative one was placed by its lexically cleaned spelling and admitted unasked);
//   - a connect by a long chain of dangling links is placed in a bounded time, and decided at its place;
//   - as root, a scope declared through a bind mount of the write entry is asked by the bind mount's name, and the
//     run's socket there, reached by the write entry's name, is the run's own.
func runAskUnixSpellings(t *testing.T, bin, tier string) {
	t.Helper()
	symlinked := func(t *testing.T) (real, link string) {
		real = unixSocketProject(t)
		link = real + "-l"
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(link) })
		return real, link
	}
	writeTarget := func(t *testing.T, target string) func(string) {
		return func(dir string) {
			p := filepath.Join(dir, "target")
			if err := os.WriteFile(p, []byte(target), 0o644); err != nil {
				t.Fatal(err)
			}
			agentOwns(t, p)
		}
	}
	t.Run("symlinked project", func(t *testing.T) {
		real, link := symlinked(t)
		scope := filepath.Join(link, "out", "sub", "app.sock")
		s := spellingScene(t, bin, tier, link, scope, "2s", spellingNamesProbe, writeTarget(t, scope))
		evs := s.runToEnd(t)
		rule := "net[unix:" + scope + "]"
		for label, dst := range map[string]string{
			"rel": "out/sub/app.sock", "cwd": filepath.Join(real, "out", "sub", "app.sock"), "scope": scope,
		} {
			spellingWantAt(t, s, evs, label, dst, "EACCES", "refused", rule)
		}
		spellingWantAt(t, s, evs, "moved", "out/sub/moved", "ok", "allow", "fs.write[./out/]")
		if answers := lines(t, evs, record.KindAnswer); len(answers) != 3 {
			t.Errorf("answer lines %v: want three, one for each name that reaches the scope's place", answers)
		}
	})
	t.Run("retried bind", func(t *testing.T) {
		project := unixSocketProject(t)
		s := spellingScene(t, bin, tier, project, filepath.Join(project, "out", "app.sock"), "30s", spellingRetryProbe, nil)
		evs := s.runToEnd(t)
		if rc := s.out("rc-first"); rc != "ENOENT" {
			t.Errorf("the first bind came to %q; want ENOENT", rc)
		}
		// The first bind binds nothing: ADR 0113's frozen precheck meets the missing directory and completes it with
		// the lookup's ENOENT, as one supervisor line, observed and unmatched, at every tier (ADR 0019's CI portability
		// note). Every other line for the name is the write entry's.
		var rest []*record.Event
		failed := 0
		for _, e := range evs {
			if e.Kind == record.KindNet && e.Verdict == record.VerdictObserved {
				m := map[string]any{}
				if err := json.Unmarshal(e.Payload, &m); err != nil {
					t.Fatal(err)
				}
				if m["dst"] == "unix:out/sub/x.sock" && m["op"] == "bind" {
					failed++
					if e.Source != record.SourceSupervisor || e.Rule != "unmatched" || m["syscall_errno"] != float64(unix.ENOENT) {
						t.Errorf("the failed bind's line: %s %s %v, want the supervisor's, unmatched, ENOENT", e.Source, e.Rule, m)
					}
					continue
				}
			}
			rest = append(rest, e)
		}
		if failed != 1 {
			t.Errorf("%d observed lines for the bind whose directory was missing, want one", failed)
		}
		spellingWantAt(t, s, rest, "x.sock", "out/sub/x.sock", "ok", "allow", "fs.write[./out/]")
	})
	t.Run("approved by a relative name in a symlinked project", func(t *testing.T) {
		_, link := symlinked(t)
		scope := filepath.Join(link, "out", "sub", "app.sock")
		spellingApproved(t, spellingScene(t, bin, tier, link, scope, "30s", spellingApproveProbe, writeTarget(t, "out/sub/app.sock")),
			scope, "out/sub/app.sock")
	})
	t.Run("approved through a link that leads nowhere at start", func(t *testing.T) {
		project := unixSocketProject(t)
		scope := filepath.Join(project, "out", "dl", "app.sock")
		s := spellingScene(t, bin, tier, project, scope, "30s", spellingApproveProbe, func(dir string) {
			writeTarget(t, scope)(dir)
			if err := os.Symlink("sub", filepath.Join(project, "out", "dl")); err != nil {
				t.Fatal(err)
			}
		})
		spellingApproved(t, s, scope, scope)
	})
	t.Run("a link whose target holds .. after a symlinked directory", func(t *testing.T) {
		project := unixSocketProject(t)
		// The scope's place, real/x.sock, holds nothing: s leads nowhere, and only the place a lexical clean of its
		// target gives, x.sock, has a listener (outside the run, named by no entry).
		scope, lexical := filepath.Join(project, "s"), filepath.Join(project, "x.sock")
		var atLexical *atomic.Int32
		s := spellingScene(t, bin, tier, project, scope, "2s", spellingNamedProbe, func(dir string) {
			writeTarget(t, lexical+"\n"+scope)(dir)
			if err := os.MkdirAll(filepath.Join(project, "real", "deep"), 0o755); err != nil {
				t.Fatal(err)
			}
			for link, target := range map[string]string{"sub": "real/deep", "s": "sub/../x.sock"} {
				if err := os.Symlink(target, filepath.Join(project, link)); err != nil {
					t.Fatal(err)
				}
			}
			atLexical = listenUnix(t, lexical)
		})
		evs := s.runToEnd(t)
		spellingWantAt(t, s, evs, "0", lexical, "EACCES", "refused", "unmatched")
		spellingWantAt(t, s, evs, "1", scope, "EACCES", "refused", "net[unix:"+scope+"]")
		if answers := lines(t, evs, record.KindAnswer); len(answers) != 1 {
			t.Errorf("answer lines %v: want one, for the scope's name", answers)
		}
		if n := atLexical.Load(); n != 0 {
			t.Errorf("the listener outside the run at %s accepted %d connections; want none", lexical, n)
		}
	})
	t.Run("a name with .. after a symlinked directory, the scope's directory missing", func(t *testing.T) {
		// out/x/y/lnk/../../sub/app.sock leads to out/sub/app.sock, the scope's place, once out/sub is made; a lexical
		// clean gives out/x/sub/app.sock. Both spellings are asked (the relative one was placed by its cleaned spelling,
		// and the write entry admitted it with nobody asked).
		project := unixSocketProject(t)
		scope := filepath.Join(project, "out", "sub", "app.sock")
		rel := "out/x/y/lnk/../../sub/app.sock"
		abs := project + "/" + rel
		s := spellingScene(t, bin, tier, project, scope, "2s", spellingDotDotProbe, writeTarget(t, rel+"\n"+abs))
		evs := s.runToEnd(t)
		rule := "net[unix:" + scope + "]"
		spellingWantAt(t, s, evs, "0", rel, "EACCES", "refused", rule)
		spellingWantAt(t, s, evs, "1", abs, "EACCES", "refused", rule)
		if answers := lines(t, evs, record.KindAnswer); len(answers) != 2 {
			t.Errorf("answer lines %v: want two, one for each name", answers)
		}
	})
	t.Run("a long chain of dangling links", func(t *testing.T) {
		// Placing the name takes more names than the supervisor walks: it is
		// no scope's, decided at its place, the write entry's, and meets ENOENT, in a bounded time. Before, the
		// placement resolved every prefix of each link's target from the deepest down, and the connect took seconds
		// to tens of seconds.
		project := unixSocketProject(t)
		scope := filepath.Join(project, "out", "sub", "app.sock")
		// out/l0 .. out/l4 are a chain of symlinks each through 500 directories and back to the next, and out/l5 leads
		// through the same directories to 600 that do not exist. They are made before the run, as a previous run of
		// the agent could have made them: the plane refuses the agent an fs path deeper than 64 below its nearest
		// entry (enforce-plane), and the placement is the supervisor's at every tier. A filesystem that stores no
		// symlink target that long (xfs: 1024 bytes, against these 2.5 KB; AlmaLinux 9.8's /tmp, 2026-11-10) gets 200
		// directories and 300: each target then fits in 1,013 bytes, and the chain still takes about 2,500 names,
		// twice what the supervisor walks (agent.ResolveUnixPlace).
		s := spellingScene(t, bin, tier, project, scope, "2s", spellingChainProbe, func(string) {
			out := filepath.Join(project, "out")
			depth := 500
			probe := filepath.Join(out, "long-target")
			switch err := os.Symlink(strings.Repeat("x/", 1300), probe); {
			case errors.Is(err, unix.ENAMETOOLONG):
				depth = 200
				t.Logf("this filesystem refuses a 2.6 KB symlink target (%v): the chain goes through %d directories", err, depth)
			case err != nil:
				t.Fatal(err)
			default:
				if err := os.Remove(probe); err != nil {
					t.Fatal(err)
				}
			}
			down := strings.Repeat("m/", depth)
			if err := os.MkdirAll(filepath.Join(out, "deep", down), 0o755); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 5; i++ {
				target := "deep/" + down + strings.Repeat("../", depth+1) + "l" + strconv.Itoa(i+1)
				if err := os.Symlink(target, filepath.Join(out, "l"+strconv.Itoa(i))); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink("deep/"+down+strings.Repeat("n/", depth+100)+"app.sock", filepath.Join(out, "l5")); err != nil {
				t.Fatal(err)
			}
		})
		evs := s.runToEnd(t)
		spellingWantAt(t, s, evs, "chain", "out/l0", "ENOENT", "allow", "fs.write[./out/]")
		took, err := strconv.ParseFloat(s.out("t-chain"), 64)
		t.Logf("the connect took %q s", s.out("t-chain"))
		if err != nil || took > 1 {
			t.Errorf("the connect took %q s (%v); want under 1 s", s.out("t-chain"), err)
		}
	})
	t.Run("the scope's name a symlink that leads nowhere", func(t *testing.T) {
		project := unixSocketProject(t)
		scope := filepath.Join(project, "out", "f.sock")
		s := spellingScene(t, bin, tier, project, scope, "2s", spellingDanglingFinalProbe, func(string) {
			if err := os.Symlink("real/y.sock", scope); err != nil {
				t.Fatal(err)
			}
		})
		evs := s.runToEnd(t)
		rule := "net[unix:" + scope + "]"
		spellingWantAt(t, s, evs, "alias", "out/alias", "EACCES", "refused", rule)
		spellingWantAt(t, s, evs, "scope", "out/f.sock", "EACCES", "refused", rule)
		if answers := lines(t, evs, record.KindAnswer); len(answers) != 2 {
			t.Errorf("answer lines %v: want two, one for each name that leads to the scope's place", answers)
		}
	})
	t.Run("bind-mount alias", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("needs root for the bind mount")
		}
		project := unixSocketProject(t)
		out, alias := filepath.Join(project, "out"), filepath.Join(project, "alias")
		if err := os.Mkdir(alias, 0o755); err != nil {
			t.Fatal(err)
		}
		scope := filepath.Join(alias, "app.sock")
		s := spellingScene(t, bin, tier, project, scope, "2s", spellingAliasProbe, func(string) {
			if err := unix.Mount(out, alias, "", unix.MS_BIND, ""); err != nil {
				t.Fatalf("bind mount: %v", err)
			}
			t.Cleanup(func() { _ = unix.Unmount(alias, unix.MNT_DETACH) })
		})
		evs := s.runToEnd(t)
		spellingWantAt(t, s, evs, "app.sock", "out/app.sock", "ok", "allow", "fs.write[./out/]")
		spellingWantAt(t, s, evs, "alias", "alias/app.sock", "EACCES", "refused", "net[unix:"+scope+"]")
		if answers := lines(t, evs, record.KindAnswer); len(answers) != 1 {
			t.Errorf("answer lines %v: want one, for the bind mount's name", answers)
		}
	})
}

// spellingApproved runs s, approves the one connect it holds, which must be asked about the scope, and checks that
// the connect, to name, was relayed with a person's authority.
func spellingApproved(t *testing.T, s *askReadScene, scope, name string) {
	t.Helper()
	run, dir := s.start(t)
	req := s.pending(t, filepath.Base(dir))
	if req["target"] != "unix:"+scope || req["rule"] != "net[unix:"+scope+"]" {
		t.Fatalf("held request %v", req)
	}
	s.answer(t, "approve", filepath.Base(dir), req["ask_id"].(string))
	evs := s.finish(t, run, dir)
	if rc := s.out("rc-app.sock"); rc != "ok" {
		t.Errorf("the approved connect came to %q; want ok; net lines %v", rc, lines(t, evs, record.KindNet))
	}
	found := false
	for _, l := range lines(t, evs, record.KindNet) {
		if l["dst"] == "unix:"+name {
			found = true
			if l["_verdict"] != "allow" || l["_authority"] != "human" || l["_rule"] != "net[unix:"+scope+"]" {
				t.Errorf("approved connect's net line %v", l)
			}
		}
	}
	if !found {
		t.Errorf("no net line for the approved connect: %v", lines(t, evs, record.KindNet))
	}
}

// spellingScene is a run at tier of the tego binary bin in project whose contract has fs.write ./out/ and the
// net.ask unix: scope with the ask timeout timeout, and whose agent runs the python probe py; before, if any, runs
// once the fixture is made, with its directory.
func spellingScene(t *testing.T, bin, tier, project, scope, timeout, py string, before func(dir string)) *askReadScene {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	contract := fmt.Sprintf(`version: 0
name: iaskspell
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
`, python, resolved, "unix:"+scope, timeout)
	s := &askReadScene{bin: bin, f: newFixtureIn(t, project, contract, nil)}
	if tier != "landlock" {
		pinned := strings.Replace(contract, "tier: landlock\n", "tier: "+tier+"\n", 1)
		if err := os.WriteFile(filepath.Join(s.f.dir, "agent.yaml"), []byte(pinned), 0o600); err != nil {
			t.Fatal(err)
		}
		agentOwns(t, filepath.Join(s.f.dir, "agent.yaml"))
	}
	if before != nil {
		before(s.f.dir)
	}
	if err := os.WriteFile(filepath.Join(s.f.dir, "probe.py"), []byte(py), 0o600); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/sh\nexec %q probe.py\n", python)
	if err := os.WriteFile(filepath.Join(s.f.dir, "agent.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, filepath.Join(s.f.dir, "agent.sh"), filepath.Join(s.f.dir, "probe.py"))
	s.env = isolatedEnv(t, s.f)
	return s
}

// spellingWantAt checks the probe's connect labelled label, to the name dst: its outcome rc (out/rc-<label>) and its
// net line's verdict and rule, and for a refusal the reason ask-timeout when the rule is a scope's.
func spellingWantAt(t *testing.T, s *askReadScene, evs []*record.Event, label, dst, rc, verdict, rule string) {
	t.Helper()
	if got := s.out("rc-" + label); got != rc {
		t.Errorf("connect %s to %s came to %q; want %q", label, dst, got, rc)
	}
	found := false
	for _, l := range lines(t, evs, record.KindNet) {
		if l["dst"] == "unix:"+dst {
			found = true
			asked := strings.HasPrefix(rule, "net[unix:") && verdict == "refused"
			if l["_verdict"] != verdict || l["_rule"] != rule || (asked && l["_reason"] != "ask-timeout") {
				t.Errorf("%s: net line %v, want %s %s", dst, l, verdict, rule)
			}
		}
	}
	if !found {
		t.Errorf("no net line for %s: %v", dst, lines(t, evs, record.KindNet))
	}
}
