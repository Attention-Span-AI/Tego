// SPDX-License-Identifier: Apache-2.0

//go:build integration

package rulesview

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/inforce"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestMain fails the binary when the invoking user's real ~/.tego or shell history changed while the tests ran: the
// test below builds and starts the tego binary (tools/isocheck GO-4).
func TestMain(m *testing.M) {
	os.Exit(testutil.GuardedMain(m))
}

// dashPATH is the PATH the dashboard compiles the run's contract on here, which loadCopy reads from its own process
// (the test sets it): the system's, so a bare entry resolves to the same file whatever the developer's PATH holds. The
// run's PATH is the same behind a directory of its own that holds a copy of true, so true is the one program the run
// and the dashboard resolve to different files, as a dashboard whose PATH differs from the run's does.
const dashPATH = "/usr/bin:/bin"

// ruleKeysContract names every program the agent runs in each way a contract can name one: the command again, a bare
// name and the path it resolves to (one compiled rule), a link to that file and python3's target (another rule for
// the same file), a bare name and a path the run resolves to different files but the dashboard merges (true), two
// exec.allow entries with words for git, one of which re-runs git from its exec-path (git commit's maintenance), an
// exec.deny and an exec.ask entry; and a net.allow and a net.ask entry. Its arguments: the path cat resolves to, the
// link, python3's target, the path true resolves to on dashPATH, the allowed port and the asked port.
const ruleKeysContract = `version: 0
name: rulekeys
command: ["/bin/sh", "agent.sh"]
tier: landlock
fs:
  write: ["./out/", "./repo/", "/dev/null"]
exec:
  allow:
    - /bin/sh
    - cat
    - %q
    - %q
    - python3
    - %q
    - "true"
    - %q
    - "git status"
    - "git commit"
  deny: ["git push"]
  ask: ["git tag"]
net:
  allow: ["127.0.0.1:%d"]
  ask: ["127.0.0.1:%d"]
env:
  pass: ["PATH", "HOME"]
ask:
  timeout: 2s
limits:
  pids: 64
record: summary
`

// ruleKeysAgent runs each spelling once and writes its exit status to out/st, commits in ./repo/, then connects to the
// allowed, the asked and an unlisted port (ruleKeysProbe). true is the shell's own command, so exec runs the program
// PATH finds. Its arguments: the path cat resolves to, the link, python3's target, true's path on dashPATH, and the
// three ports.
const ruleKeysAgent = `cat /dev/null; echo "cat $?" >> out/st
%s /dev/null; echo "catpath $?" >> out/st
%s /dev/null; echo "catlink $?" >> out/st
python3 -c pass; echo "python3 $?" >> out/st
%s -c pass; echo "pythonfile $?" >> out/st
(exec true); echo "true $?" >> out/st
%s; echo "truepath $?" >> out/st
git status >/dev/null 2>&1; echo "status $?" >> out/st
(cd repo && git commit --allow-empty -q -m m >/dev/null 2>&1); echo "commit $?" >> out/st
git push >/dev/null 2>&1; echo "push $?" >> out/st
git tag t >/dev/null 2>&1; echo "tag $?" >> out/st
git log >/dev/null 2>&1; echo "log $?" >> out/st
python3 probe.py %d %d %d
`

// ruleKeysProbe connects to each port named and writes "<port> <outcome>" to out/net, "ok" or the errno's name. The
// asked connect is held until the ask times out, so its own timeout is longer.
const ruleKeysProbe = `import errno, socket, sys
with open("out/net", "w") as out:
    for port in sys.argv[1:]:
        s = socket.socket()
        s.settimeout(30)
        try:
            s.connect(("127.0.0.1", int(port)))
            r = "ok"
        except OSError as e:
            r = errno.errorcode.get(e.errno, str(e.errno))
        finally:
            s.close()
        out.write("%s %s\n" % (port, r))
`

// TestIntegrationRuleKeysAreARunsKeys holds the Rules page's view of a real run at tier landlock (InForce, which
// compiles the run's contract on the dashboard's PATH and counts each rule's hits from the run's ledger) and the line
// page's rule origin (RuleSource) to the run's own ledger. Every rule a line carries is a key some rule of the view
// lists, and the line page finds its origin, except two that no entry names: "unmatched", which the view counts in
// Unmatched, and a constrained tool's unlisted invocation (exec.args[git], git log here). That holds for the lines of
// git's helper image (git commit re-runs git from its exec-path), and for a path entry the run kept as a rule of its
// own while the dashboard, on its own PATH, merges it into a bare name's (true). And every entry the agent used shows
// hits: one that resolved to the file an earlier entry named (cat's path), one that names that file by another
// spelling (a link to cat; python3's target), both entries of true, the exec.allow entries with words (their lines
// carry the program's rule, exec[git], and the entry in command_rule), an exec.deny and an exec.ask entry, a net.allow
// entry, and a net.ask entry nobody answered; the entries that name one file on both PATHs show the same hits.
func TestIntegrationRuleKeysAreARunsKeys(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("runs the agent as the invoking user at tier landlock; a root launcher drops to another uid, which this test does not set up")
	}
	cat, python, truePath := onPath(t, "cat"), onPath(t, "python3"), onPath(t, "true")
	onPath(t, "git") // the program of the entries with words
	catFile, err := filepath.EvalSymlinks(cat)
	if err != nil {
		t.Fatal(err)
	}
	pythonFile, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	w := newKeysWorld(t)
	alt := filepath.Join(w.proj, "alt")
	if err := os.Mkdir(alt, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(alt, "cat")
	if err := os.Symlink(catFile, link); err != nil {
		t.Fatal(err)
	}
	// The run's own true: a copy, so another file than the one true is on dashPATH.
	trueBytes, err := os.ReadFile(truePath)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(w.runBin, "true"), string(trueBytes), 0o755)
	repo := filepath.Join(w.proj, "repo")
	for _, args := range [][]string{{"init", "-q", repo}, {"-C", repo, "config", "user.name", "rulekeys"}, {"-C", repo, "config", "user.email", "rulekeys@example.invalid"}} {
		c := exec.Command("git", args...)
		c.Env = append(os.Environ(), "HOME="+filepath.Join(w.base, "home"), "GIT_CONFIG_NOSYSTEM=1")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	allowPort, askPort, otherPort := listenLoopback(t), listenLoopback(t), listenLoopback(t)
	contract := filepath.Join(w.proj, "agent.yaml")
	writeFile(t, contract, fmt.Sprintf(ruleKeysContract, cat, link, pythonFile, truePath, allowPort, askPort), 0o600)
	writeFile(t, filepath.Join(w.proj, "agent.sh"), fmt.Sprintf(ruleKeysAgent, shQuote(cat), shQuote(link), shQuote(pythonFile),
		shQuote(truePath), allowPort, askPort, otherPort), 0o600)
	writeFile(t, filepath.Join(w.proj, "probe.py"), ruleKeysProbe, 0o600)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	run := exec.CommandContext(ctx, w.tego, "run", contract)
	run.Dir = w.proj
	run.Env = w.env
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("tego run: %v\n%s", err, out)
	}

	// The scene ran as written: each program ran or was refused at its execve (the shell's 126), the commit was made;
	// the allowed connect went through, the asked one waited for an answer that never came and was refused, and the
	// unlisted one was refused.
	st := lines(t, filepath.Join(w.proj, "out", "st"))
	for name, ran := range map[string]bool{"cat": true, "catpath": true, "catlink": true, "python3": true, "pythonfile": true,
		"true": true, "truepath": true, "status": true, "commit": true, "push": false, "tag": false, "log": false} {
		if code := st[name]; (code == "126") == ran || code == "" {
			t.Errorf("%s exited %q; want it %s", name, code, map[bool]string{true: "run", false: "refused at its execve (126)"}[ran])
		}
	}
	if st["commit"] != "0" {
		t.Errorf("git commit in ./repo/ exited %q, want 0", st["commit"])
	}
	nets := lines(t, filepath.Join(w.proj, "out", "net"))
	for port, want := range map[int]string{allowPort: "ok", askPort: "EACCES", otherPort: "EACCES"} {
		if got := nets[fmt.Sprint(port)]; got != want {
			t.Errorf("connect to port %d: %q, want %q", port, got, want)
		}
	}

	runID, events := runLedger(t, w.ledger)
	machine, _, err := config.LoadSources(config.Sources{EnvFile: w.cfg}, "", os.Getuid(), config.TrustAbort)
	if err != nil {
		t.Fatalf("the machine config: %v", err)
	}
	o := Options{Machine: machine}
	t.Setenv("PATH", dashPATH) // the dashboard's PATH, which loadCopy compiles on
	iv := InForce(ctx, w.ledger, runID, o)
	if iv.Err != "" || iv.Contract.Err != "" || !iv.View.Compiled || iv.View.Tier != "landlock" || iv.Positions != PositionsSource {
		t.Fatalf("the Rules page's view: err %q, compile %q, compiled %v, tier %q, positions %s (%s)\n%s", iv.Err, iv.Contract.Err,
			iv.View.Compiled, iv.View.Tier, iv.Positions, iv.PositionsWhy, iv.Contract.Diagnostics)
	}
	v := &iv.View
	t.Cleanup(func() {
		if t.Failed() {
			var b strings.Builder
			for _, e := range events {
				if e.Rule != "" {
					fmt.Fprintf(&b, "  %d %s %s %s\n", e.Seq, e.Kind, e.Verdict, e.Rule)
				}
			}
			var keys strings.Builder
			for _, r := range v.Rules() {
				if r.RuleKey != "" {
					fmt.Fprintf(&keys, "  %s %s %q %s %v hits %d\n", r.Group, r.Key, r.Entry, r.RuleKey, r.Covers, r.Hits)
				}
			}
			t.Logf("the run's rules:\n%s\nthe view's keys:\n%s", b.String(), keys.String())
		}
	})

	listed := map[string]bool{}
	for _, r := range v.Rules() {
		if r.RuleKey != "" {
			listed[r.RuleKey] = true
		}
		for _, k := range r.Covers {
			listed[k] = true
		}
	}
	helpers := map[string]bool{} // the names of git's helper images in the table the view was built from
	for _, r := range iv.Contract.Compiled.Exec {
		for _, s := range strings.Split(r.Source, ",") {
			if s == agent.ExecSourceHelper+":git" {
				helpers[r.RuleName()] = true
			}
		}
	}
	unmatched, unlisted, helperLines, trueLines := 0, 0, 0, 0
	for _, e := range events {
		if helpers[e.Rule] {
			helperLines++
		}
		if e.Rule == "exec["+truePath+"]" {
			trueLines++
		}
		switch {
		case e.Rule == "":
		case e.Rule == agent.UnmatchedRule:
			unmatched++
		case strings.HasPrefix(e.Rule, "exec.args["):
			// A constrained tool's unlisted invocation: the tool's default refused it, and no entry names it.
			unlisted++
		case !listed[e.Rule]:
			t.Errorf("line %d (%s, %s) carries rule %s, which no rule in force lists", e.Seq, e.Kind, e.Verdict, e.Rule)
		default:
			if ro, ok := RuleSource(ctx, w.ledger, runID, e.Rule, o); !ok || e.Kind == record.KindExec && ro.Group != inforce.GroupPrograms {
				t.Errorf("the line page's origin of line %d's rule %s: %+v (found %v)", e.Seq, e.Rule, ro, ok)
			}
		}
	}
	if unmatched == 0 || v.Unmatched != unmatched {
		t.Errorf("the view counts %d unmatched lines, the run wrote %d (want at least the unlisted connect's)", v.Unmatched, unmatched)
	}
	if unlisted == 0 {
		t.Error("the run wrote no exec.args line for git log, the one rule the view is not held to here")
	}
	if helperLines == 0 {
		t.Errorf("the run wrote no line for git's helper images %v: git commit's re-run of git from its exec-path, which the "+
			"view must list, did not happen", helpers)
	}
	if trueLines == 0 {
		t.Errorf("the run wrote no line named exec[%s]: it did not keep %s as a rule of its own, the case the dashboard's other PATH tests", truePath, truePath)
	}

	// Every entry the agent used shows hits; the entries that name one file on both PATHs show the same hits.
	hits := func(key, entry string) int {
		t.Helper()
		return rule(t, iv, key, entry).Hits
	}
	for _, e := range []struct{ key, entry string }{
		{"exec.allow", "/bin/sh"}, {"exec.allow", "cat"}, {"exec.allow", cat}, {"exec.allow", link}, {"exec.allow", "python3"},
		{"exec.allow", pythonFile}, {"exec.allow", "true"}, {"exec.allow", truePath}, {"exec.allow", "git status"},
		{"exec.allow", "git commit"}, {"exec.deny", "git push"}, {"exec.ask", "git tag"},
		{"net.allow", fmt.Sprintf("127.0.0.1:%d", allowPort)}, {"net.ask", fmt.Sprintf("127.0.0.1:%d", askPort)},
	} {
		if n := hits(e.key, e.entry); n == 0 {
			t.Errorf("%s %s shows no hits, though the agent used it", e.key, e.entry)
		}
	}
	if a, b, c := hits("exec.allow", "cat"), hits("exec.allow", cat), hits("exec.allow", link); a != b || a != c {
		t.Errorf("cat, %s and %s name one file but show %d, %d and %d hits", cat, link, a, b, c)
	}
	if a, b := hits("exec.allow", "python3"), hits("exec.allow", pythonFile); a != b {
		t.Errorf("python3 and %s name one file but show %d and %d hits", pythonFile, a, b)
	}
}

// keysWorld is the run's machine: a project, a ledger root, the machine config naming it, a directory on the run's
// PATH only, and the tego binary built with the test hooks, run with an environment that keeps every file it writes
// in the test's own directory.
type keysWorld struct {
	base, proj, ledger, cfg, runBin, tego string
	env                                   []string
}

func newKeysWorld(t *testing.T) *keysWorld {
	t.Helper()
	// A short name: the run's sockets live under <base>/x/tego/<run id>, and sun_path holds 107 bytes.
	base, err := os.MkdirTemp("", "k")
	if err != nil {
		t.Fatal(err)
	}
	if base, err = filepath.EvalSymlinks(base); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	w := &keysWorld{base: base, proj: filepath.Join(base, "p"), ledger: filepath.Join(base, "l"), runBin: filepath.Join(base, "rb"),
		cfg: filepath.Join(base, "cfg", "machine.yaml")}
	// config.Load refuses a layer whose file or directory another user can write, and a run refuses a ledger root
	// or a runtime directory others can enter.
	for dir, mode := range map[string]os.FileMode{base: 0o755, w.proj: 0o755, filepath.Join(w.proj, "out"): 0o755, w.ledger: 0o700,
		filepath.Dir(w.cfg): 0o755, filepath.Join(base, "x"): 0o700, filepath.Join(base, "home"): 0o755, filepath.Join(base, "bin"): 0o755,
		w.runBin: 0o755} {
		if err := os.MkdirAll(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, w.cfg, fmt.Sprintf("version: 0\nledger_root: %s\nstop_grace: 2s\n", w.ledger), 0o600)
	w.env = testutil.TegoEnv(t, base, "TEGO_CONFIG="+w.cfg, "XDG_RUNTIME_DIR="+filepath.Join(base, "x"),
		"PATH="+w.runBin+":"+dashPATH, "HOME="+filepath.Join(base, "home"), "HISTFILE=/dev/null")
	w.tego = filepath.Join(base, "bin", "tego")
	build := exec.Command("go", "build", "-tags", "tegotesthooks", "-trimpath", "-o", w.tego, "github.com/attention-span-ai/tego/cmd/tego")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build cmd/tego: %v\n%s", err, out)
	}
	return w
}

// onPath is name's file on dashPATH, as the dashboard's PATH search finds it; the test skips without one.
func onPath(t *testing.T, name string) string {
	t.Helper()
	for _, dir := range filepath.SplitList(dashPATH) {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p
		}
	}
	t.Skipf("no %s on %s", name, dashPATH)
	return ""
}

// listenLoopback is the port of a loopback listener open until the test ends; nothing accepts, so a connect the run
// allows completes in the backlog.
func listenLoopback(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l.Addr().(*net.TCPAddr).Port
}

// runLedger is the one run under root: its id and its lines, decoded.
func runLedger(t *testing.T, root string) (string, []record.Event) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(root, "r-*"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("want one run under %s, have %v (%v)", root, matches, err)
	}
	if id := filepath.Base(matches[0]); !ledger.IsRunID(id) {
		t.Fatalf("%s is not a run id", id)
	}
	b, err := os.ReadFile(filepath.Join(matches[0], "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var events []record.Event
	for i, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		e, err := record.Decode(line)
		if err != nil {
			t.Fatalf("line %d: %v", i+1, err)
		}
		events = append(events, *e)
	}
	if len(events) == 0 || events[0].Kind != record.KindRunStart {
		t.Fatalf("the run's ledger does not start with run_start: %d lines", len(events))
	}
	return filepath.Base(matches[0]), events
}

// lines reads a file of "<name> <value>" lines into a map.
func lines(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	m := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		name, value, _ := strings.Cut(sc.Text(), " ")
		m[name] = value
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return m
}

func writeFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

// shQuote quotes s as one word of a POSIX shell.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
