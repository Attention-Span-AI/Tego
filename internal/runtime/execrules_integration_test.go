// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

// execRulesContract renders a tier-1 contract with the given exec: section body (indented two spaces) and command.
// git opens /dev/null read-write at every start (sanitize_stdfds), so the contract grants it, as
// examples/agents/claude-code.yaml does.
func execRulesContract(name, command, execBody string) string {
	return fmt.Sprintf(`version: 0
name: %s
command: [%q]
tier: landlock
fs:
  write: ["./out/", "/dev/null"]
exec:
%s
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 256
record: summary
`, name, command, execBody)
}

// execLine is one exec line's verdict, rule and command-rule fields.
type execLine struct {
	verdict      record.Verdict
	rule         string
	argv         []string
	commandRule  string
	commandList  string
	commandMatch string
	commandVia   string
	argvFacts    string
}

// execLines reads every exec line of the one run under root.
func execLines(t *testing.T, root string) []execLine {
	t.Helper()
	dirs := runDirs(t, root)
	if len(dirs) != 1 {
		t.Fatalf("want one run under %s, have %v", root, dirs)
	}
	var out []execLine
	for _, e := range events(t, dirs[0]) {
		if e.Kind != record.KindExec {
			continue
		}
		var p struct {
			Argv         []string `json:"argv"`
			CommandRule  string   `json:"command_rule"`
			CommandList  string   `json:"command_list"`
			CommandMatch string   `json:"command_match"`
			CommandVia   string   `json:"command_via"`
			ArgvFacts    string   `json:"argv_facts"`
		}
		if err := e.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		out = append(out, execLine{verdict: e.Verdict, rule: e.Rule, argv: p.Argv, commandRule: p.CommandRule,
			commandList: p.CommandList, commandMatch: p.CommandMatch, commandVia: p.CommandVia, argvFacts: p.ArgvFacts})
	}
	return out
}

// runScript runs `tego run agent.yaml -- /bin/sh -c script` in the fixture and returns the output.
func runScript(t *testing.T, f *fixture, script string, env ...string) string {
	t.Helper()
	bin := tegoBinary(t)
	cfg := writeMachineConfig(t, f)
	run := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"), "--", "/bin/sh", "-c", script)
	run.Dir = f.dir
	run.Env = append(append(os.Environ(), "TEGO_CONFIG="+cfg), env...)
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("tego run: %v\n%s", err, out)
	}
	return string(out)
}

// statuses reads the "<name> <exit status>" lines a script appended to out/st.
func statuses(t *testing.T, f *fixture) map[string]int {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(f.out, "st"))
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]int{}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		name, code, _ := strings.Cut(l, " ")
		n, err := strconv.Atoi(code)
		if err != nil {
			t.Fatalf("status line %q", l)
		}
		m[name] = n
	}
	return m
}

// logOf is what the run's commands wrote to out/log, for a failure's message.
func logOf(f *fixture) string {
	b, _ := os.ReadFile(filepath.Join(f.out, "log"))
	return string(b)
}

// agentOwnsTree hands every file under each root to the agent's uid when the test runs as root under sudo, as
// agentOwns does one path: the test made the repositories as root, and git refuses a repository another uid owns
// ("dubious ownership").
func agentOwnsTree(t *testing.T, roots ...string) {
	t.Helper()
	for _, r := range roots {
		if err := filepath.WalkDir(r, func(p string, _ fs.DirEntry, err error) error {
			if err == nil {
				agentOwns(t, p)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// needGit skips without git.
func needGit(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("git")
	if err != nil {
		t.Skip("no git installed")
	}
	return p
}

// TestIntegrationExecDenySubcommand is ADR 0048 C6's first test, tier 1 on the real kernel: under a deny-list,
// every Context bypass of `git push` and `rm -r` is refused at its execve with EACCES (the shell reports 126), with
// its rule, how it matched and the interpretation that read it on the line; git status and a plain rm run.
func TestIntegrationExecDenySubcommand(t *testing.T) {
	needGit(t)
	f := newFixture(t, execRulesContract("xdeny", "/bin/sh", "  deny: [git push, rm -r]"))
	for _, d := range []string{"tree/sub", "tree2", "tree3"} {
		if err := os.MkdirAll(filepath.Join(f.out, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	core := ""
	if out, err := exec.Command("git", "--exec-path").Output(); err == nil {
		core = strings.TrimSpace(string(out))
	}
	cases := []struct{ name, cmd, via string }{
		{"C", "git -C . push", "name"},
		{"c", "git -c push.default=current push", "name"},
		{"gitdir", "git --git-dir=.git push", "name"},
		{"quoted", "git 'push' origin", "name"},
		{"argv0", "bash -c 'exec -a git-push git'", "name"},
		{"env", "env git push", "name"},
		{"timeout", "timeout 5 git push", "name"},
		{"shc", "sh -c 'git push'", "name"},
		{"rmfr", "rm -fr out/tree", "name"},
		{"rmlong", "rm out/tree2 --rec --forc", "name"},
		{"rmR", "rm -R out/tree3", "name"},
	}
	if core != "" {
		cases = append(cases, struct{ name, cmd, via string }{"dashed", core + "/git-push", "dashed"})
	}
	var script strings.Builder
	for _, c := range cases {
		fmt.Fprintf(&script, "%s >>out/log 2>&1; echo \"%s $?\" >> out/st\n", c.cmd, c.name)
	}
	script.WriteString("git status >>out/log 2>&1; echo \"status $?\" >> out/st\nrm -f out/nothing; echo \"rmf $?\" >> out/st\n")
	runScript(t, f, script.String())
	st := statuses(t, f)
	for _, c := range cases {
		if st[c.name] != 126 {
			t.Errorf("%s (%s): exit %d, want 126 (EACCES at execve)", c.name, c.cmd, st[c.name])
		}
	}
	if st["status"] == 126 || st["rmf"] != 0 {
		t.Errorf("git status exit %d, rm -f exit %d: neither may be refused", st["status"], st["rmf"])
	}
	for _, d := range []string{"tree", "tree2", "tree3"} {
		if _, err := os.Stat(filepath.Join(f.out, d)); err != nil {
			t.Errorf("out/%s is gone: a refused rm -r removed it", d)
		}
	}
	refused := 0
	for _, l := range execLines(t, f.root) {
		if l.verdict != record.VerdictRefused {
			continue
		}
		refused++
		if !strings.HasPrefix(l.rule, "exec.deny[") || l.commandList != "deny" || l.commandMatch == "" || l.commandVia == "" || l.argvFacts != record.ArgvFactsCopied {
			t.Errorf("refused line %+v lacks its command-rule fields", l)
		}
	}
	if refused < len(cases) {
		t.Errorf("%d refused exec lines for %d refused cases", refused, len(cases))
	}
}

// TestIntegrationExecAllowListSubcommands: under allow: [git status, git diff, git log, git st] git runs only as
// those; push is refused unlisted, and an alias works when listed: git's probe of the dashed git-st keeps its ENOENT
// (never EACCES), and the alias re-execs git status, which is allowed.
//
// The repository's commit is made with automatic maintenance off. A commit starts `git maintenance run --auto
// --detach`, and from git 2.55 the detached process holds .git/objects/maintenance.lock until it ends, after the
// commit has returned: agentOwnsTree's walk, as root, listed the lock and found it gone when it came to chown it
// (GitHub's root-suites, git 2.56, 2026-11-02: "lchown .../.git/objects/maintenance.lock: no such file or directory").
// With maintenance.auto false git starts no maintenance at all, so nothing but this test writes the tree it hands to
// the agent. The run loses nothing by it: of the commands it runs only the commit, which it refuses, would start one.
func TestIntegrationExecAllowListSubcommands(t *testing.T) {
	needGit(t)
	f := newFixture(t, execRulesContract("xallow", "/bin/sh", `  allow: ["git status", "git diff", "git log", "git st", "/bin/sh", "/bin/echo"]`))
	repo := filepath.Join(f.out, "repo")
	for _, args := range [][]string{{"init", "-q", repo}, {"-C", repo, "config", "alias.st", "status"}, {"-C", repo, "config", "user.email", "a@b"}, {"-C", repo, "config", "user.name", "a"},
		{"-C", repo, "config", "maintenance.auto", "false"}, {"-C", repo, "commit", "-q", "--allow-empty", "-m", "x"}} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	agentOwnsTree(t, repo)
	runScript(t, f, `cd out/repo
for c in status diff log st push commit; do git $c >>../log 2>&1; /bin/echo "$c $?" >> ../st; done`)
	st := statuses(t, f)
	for _, c := range []string{"status", "diff", "log", "st"} {
		if st[c] != 0 {
			t.Errorf("git %s: exit %d, want 0\n%s", c, st[c], logOf(f))
		}
	}
	for _, c := range []string{"push", "commit"} {
		if st[c] != 126 {
			t.Errorf("git %s: exit %d, want 126 (unlisted)", c, st[c])
		}
	}
	// git st exiting 0 is the probe's proof: answered EACCES, git would fail "cannot exec 'git-st'" and never expand
	// the alias.
	// A shell retries a refused execve on every PATH directory that holds the name (/bin and /usr/bin on a merged
	// /usr), so refusals are counted by the command line they refused.
	unlisted, admitted := map[string]bool{}, 0
	for _, l := range execLines(t, f.root) {
		switch {
		case l.verdict == record.VerdictRefused && l.rule == "exec.args[git]":
			unlisted[strings.Join(l.argv, " ")] = true
		case l.verdict == record.VerdictAllow && l.commandList == "allow":
			admitted++
		}
	}
	if len(unlisted) != 2 || admitted < 4 {
		t.Errorf("unlisted refusals %v (want git push and git commit), %d admitted lines (want at least 4)", unlisted, admitted)
	}
}

// TestIntegrationExecAllowHelperClosure: git runs git. Under allow: [git fetch, git push, git commit, git gc] against a
// local bare repository, a commit with auto-maintenance, a push over the file transport, a fetch and gc all succeed:
// each helper exec git runs for itself is in its operation's closure and carries command_via closure. The test finds
// git's exec-path from the installed git, so it does not depend on Ubuntu's layout.
func TestIntegrationExecAllowHelperClosure(t *testing.T) {
	needGit(t)
	f := newFixture(t, execRulesContract("xclosure", "/bin/sh",
		`  allow: ["git fetch", "git push", "git commit", "git gc", "/bin/sh", "/bin/echo"]`))
	work, bare := filepath.Join(f.out, "work"), filepath.Join(f.out, "remote.git")
	for _, args := range [][]string{{"init", "-q", "--bare", bare}, {"init", "-q", work}, {"-C", work, "config", "user.email", "a@b"},
		{"-C", work, "config", "user.name", "a"}, {"-C", work, "config", "gc.auto", "1"}, {"-C", work, "config", "maintenance.autoDetach", "false"},
		{"-C", work, "config", "gc.autoDetach", "false"}, {"-C", work, "remote", "add", "origin", bare}} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	agentOwnsTree(t, work, bare)
	runScript(t, f, `cd out/work
git commit -q --allow-empty -m one >>../log 2>&1; /bin/echo "commit $?" >> ../st
git commit -q --allow-empty -m two >>../log 2>&1; /bin/echo "commit2 $?" >> ../st
git push -q origin HEAD:refs/heads/main >>../log 2>&1; /bin/echo "push $?" >> ../st
git fetch -q origin >>../log 2>&1; /bin/echo "fetch $?" >> ../st
git gc -q >>../log 2>&1; /bin/echo "gc $?" >> ../st`)
	st := statuses(t, f)
	for _, c := range []string{"commit", "commit2", "push", "fetch", "gc"} {
		if st[c] != 0 {
			t.Errorf("git %s: exit %d, want 0\n%s", c, st[c], logOf(f))
		}
	}
	closure := 0
	for _, l := range execLines(t, f.root) {
		if l.verdict == record.VerdictRefused {
			t.Errorf("a helper exec was refused: %+v", l)
		}
		if l.commandVia == "closure" {
			closure++
		}
	}
	if closure == 0 {
		t.Error("no exec line carries command_via closure: the helpers ran unnamed")
	}
}

// TestIntegrationExecRuleAmbiguous: a deny entry matches when any reading does. git's autocorrection of psuh and an
// unknown global option that may take the next token are both refused, command_match ambiguous; git lfs is not.
func TestIntegrationExecRuleAmbiguous(t *testing.T) {
	needGit(t)
	f := newFixture(t, execRulesContract("xamb", "/bin/sh", "  deny: [git push]"))
	runScript(t, f, `git psuh >>out/log 2>&1; echo "psuh $?" >> out/st
git --frobnicate push status >>out/log 2>&1; echo "unknown $?" >> out/st
git lfs >>out/log 2>&1; echo "lfs $?" >> out/st`)
	st := statuses(t, f)
	if st["psuh"] != 126 || st["unknown"] != 126 {
		t.Errorf("psuh exit %d, an unknown option exit %d: want 126 each", st["psuh"], st["unknown"])
	}
	if st["lfs"] == 126 {
		t.Error("git lfs was refused under deny git push")
	}
	amb := map[string]bool{}
	for _, l := range execLines(t, f.root) {
		if l.verdict == record.VerdictRefused && l.commandMatch == "ambiguous" {
			amb[strings.Join(l.argv, " ")] = true
		}
	}
	if len(amb) != 2 {
		t.Errorf("ambiguous refusals %v, want git psuh and git --frobnicate push status", amb)
	}
}

// TestIntegrationExecRuleRaceTier1 is ADR 0048 C6's TOCTOU test. A fixture installed as git records its argv[1]; the
// contract denies git push in deny-list mode; each attempt's child flips a buffer between diff and push on one thread
// while its main thread execs git with it. The closed direction is asserted: every exec whose copy read push is
// refused (EACCES), and no line says allow for a copy that read push. The disclosed race is measured: attempts that ran
// the fixture with push while their line says allow. On zero wins (a single-vCPU runner) that sub-assertion is logged
// and skipped, never failed.
func TestIntegrationExecRuleRaceTier1(t *testing.T) {
	attempts := 3000
	if testing.Short() {
		attempts = 300
	}
	f := newFixture(t, execRulesContract("xrace", "/bin/sh", "  deny: [git push]"))
	bin := t.TempDir()
	racer := filepath.Join(bin, "execracer")
	if out, err := exec.Command("go", "build", "-o", racer, "github.com/attention-span-ai/tego/test/workloads/execracer").CombinedOutput(); err != nil {
		t.Skipf("cannot build the racer: %v\n%s", err, out)
	}
	ran := filepath.Join(f.out, "ran")
	git := filepath.Join(f.out, "git")
	if err := os.WriteFile(git, []byte("#!/bin/sh\necho \"$1\" >> "+ran+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(f.out, "report")
	runScript(t, f, fmt.Sprintf("%s %s %d %s", racer, git, attempts, report))
	rep, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var n, eacces, ranN, other int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(rep)), "attempts=%d eacces=%d ran=%d other=%d", &n, &eacces, &ranN, &other); err != nil {
		t.Fatalf("report %q: %v", rep, err)
	}
	ranBytes, _ := os.ReadFile(ran)
	ranPush := strings.Count(string(ranBytes), "push\n")
	var refused, allowedPush, allowed int
	for _, l := range execLines(t, f.root) {
		if len(l.argv) != 2 || l.argv[0] != "git" {
			continue
		}
		switch l.verdict {
		case record.VerdictRefused:
			// The copy is push, or a torn mix between the words that git would autocorrect to push.
			refused++
			if l.rule != "exec.deny[git push]" || l.argvFacts != record.ArgvFactsCopied {
				t.Errorf("refused line %+v", l)
			}
		case record.VerdictAllow:
			allowed++
			if l.argv[1] == "push" {
				allowedPush++
			}
		}
	}
	if allowedPush != 0 {
		t.Errorf("%d lines say allow for a copy that read push", allowedPush)
	}
	if refused != eacces {
		t.Errorf("%d refused lines, %d attempts answered EACCES: every copy that read push is refused, and only those", refused, eacces)
	}
	t.Logf("attempts %d: refused %d, ran %d (push %d), other %d; allowed lines %d", n, eacces, ranN, ranPush, other, allowed)
	if ranPush == 0 {
		t.Logf("no attempt won the race (ran push after a copy of diff): the disclosed race was not observed on this machine")
	} else {
		t.Logf("the disclosed race (ADR 0048 R5): %d of %d attempts ran push after the supervisor's copy allowed another word", ranPush, n)
	}
}

// TestIntegrationExecRuleLinkRaceTier1: a deny-list run never continues an exec its walk did not reach (ADR 0048 (3)).
// The racer flips out/l between a symlink to a git fixture and nothing while it execs out/l as `git push`, 3000
// times (300 under -short). Each walk either reaches the fixture, and deny: [git push] refuses it (EACCES), or finds
// no link, and the supervisor answers that ENOENT itself. Continued, the kernel's own lookup found the link a moment
// later: before the fix 1020 of 3000 attempts ran git push on lines that said "allow unmatched". Asserted: the fixture
// never ran, and no exec line of out/l says allow.
func TestIntegrationExecRuleLinkRaceTier1(t *testing.T) {
	attempts := 3000
	if testing.Short() {
		attempts = 300
	}
	f := newFixture(t, execRulesContract("xlinkrace", "/bin/sh", "  deny: [git push]"))
	bin := t.TempDir()
	racer := filepath.Join(bin, "execracer")
	if out, err := exec.Command("go", "build", "-o", racer, "github.com/attention-span-ai/tego/test/workloads/execracer").CombinedOutput(); err != nil {
		t.Skipf("cannot build the racer: %v\n%s", err, out)
	}
	ran := filepath.Join(f.out, "ran")
	git := filepath.Join(f.out, "git")
	if err := os.WriteFile(git, []byte("#!/bin/sh\necho \"$1\" >> "+ran+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(f.out, "report")
	runScript(t, f, fmt.Sprintf("%s -link %s %s %d %s", racer, git, f.out, attempts, report))
	rep, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var n, eacces, ranN, other int
	if _, err := fmt.Sscanf(strings.TrimSpace(string(rep)), "attempts=%d eacces=%d ran=%d other=%d", &n, &eacces, &ranN, &other); err != nil {
		t.Fatalf("report %q: %v", rep, err)
	}
	ranBytes, _ := os.ReadFile(ran)
	if ranN != 0 || len(ranBytes) != 0 {
		t.Errorf("git push ran %d times (fixture lines %q): an exec no command rule decided was continued", ranN, ranBytes)
	}
	link := filepath.Join(f.out, "l")
	var refused, observed int
	for _, l := range execLines(t, f.root) {
		if len(l.argv) != 2 || l.argv[0] != "git" {
			continue
		}
		switch l.verdict {
		case record.VerdictRefused:
			refused++
		case record.VerdictObserved:
			observed++
		case record.VerdictAllow:
			t.Errorf("an exec of %s as git push was allowed: %+v", link, l)
		}
	}
	if eacces == 0 {
		t.Errorf("no attempt was refused EACCES: the walk never reached the link, so the race was not run")
	}
	t.Logf("attempts %d: refused %d (lines %d), lookup errno %d (observed lines %d), ran %d", n, eacces, refused, other, observed, ranN)
}

// TestIntegrationExecRuleShebangInterpreter: any ruled tool can be a #! interpreter, which the kernel loads inside the
// same execve with no notification of its own (ADR 0048 (3)). Under deny: [rm -r] in deny-list mode, a script whose
// first line is `#!<rm> -rf`, run as `./out/s out/tree`, is `rm -rf ./out/s out/tree` and refused at its execve (the
// shell reports 126), via shebang; an execute-only copy, whose head an unprivileged supervisor cannot read, is refused
// too (image-unreadable as the user, the rule itself as root). A script whose #! interpreter is out/x, a symlink to
// rm, is read by the walked interpreter's name and identity, not only by the #! line's "x", and is refused the same
// way. Every tree survives. Before the first fix the script deleted its tree, on a line that said "allow unmatched";
// before the second the symlinked interpreter did.
func TestIntegrationExecRuleShebangInterpreter(t *testing.T) {
	rm, err := exec.LookPath("rm")
	if err != nil {
		t.Skip("no rm")
	}
	f := newFixture(t, execRulesContract("xshebang", "/bin/sh", "  deny: [rm -r]"))
	for _, d := range []string{"tree/sub", "tree2/sub", "tree3/sub"} {
		if err := os.MkdirAll(filepath.Join(f.out, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(f.out, "x")
	if err := os.Symlink(rm, link); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, link)
	for name, c := range map[string]struct {
		interp string
		mode   os.FileMode
	}{"s": {rm, 0o755}, "e": {rm, 0o111}, "l": {link, 0o755}} {
		p := filepath.Join(f.out, name)
		if err := os.WriteFile(p, []byte("#!"+c.interp+" -rf\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		agentOwns(t, p)
		if err := os.Chmod(p, c.mode); err != nil {
			t.Fatal(err)
		}
	}
	runScript(t, f, `./out/s out/tree >>out/log 2>&1; echo "s $?" >> out/st
./out/e out/tree2 >>out/log 2>&1; echo "e $?" >> out/st
./out/l out/tree3 >>out/log 2>&1; echo "l $?" >> out/st`)
	st := statuses(t, f)
	for _, c := range []string{"s", "e", "l"} {
		if st[c] != 126 {
			t.Errorf("./out/%s: exit %d, want 126 (EACCES at execve)\n%s", c, st[c], logOf(f))
		}
	}
	for _, d := range []string{"tree", "tree2", "tree3"} {
		if _, err := os.Stat(filepath.Join(f.out, d, "sub")); err != nil {
			t.Errorf("out/%s/sub is gone: the #! line's rm -rf ran", d)
		}
	}
	rules := map[string]string{}
	for _, l := range execLines(t, f.root) {
		if len(l.argv) > 0 && (l.argv[0] == "./out/s" || l.argv[0] == "./out/e" || l.argv[0] == "./out/l") {
			rules[l.argv[0]] = string(l.verdict) + " " + l.rule + " " + l.commandVia
		}
	}
	for _, c := range []string{"./out/s", "./out/l"} {
		if got := rules[c]; got != "refused exec.deny[rm -r] shebang" {
			t.Errorf("%s line: %q, want refused exec.deny[rm -r] via shebang", c, got)
		}
	}
	want := "refused image-unreadable "
	if os.Geteuid() == 0 {
		want = "refused exec.deny[rm -r] shebang"
	}
	if got := rules["./out/e"]; got != want {
		t.Errorf("./out/e line: %q, want %q", got, want)
	}
}

// TestIntegrationExecRuleShebangCRLF: the #! line is read as binfmt_script reads it, which trims only spaces and tabs,
// so a CRLF line's '\r' is part of the interpreter's name. Under deny: [rm -r], a script `#!<abs>/out/y\r`, with
// out/y a symlink to true and `out/y\r` a symlink to rm, run as `./out/c -r out/tree`, is the kernel's `rm -r` and
// refused at its execve (126), via shebang, and the tree survives. Before the fix the supervisor walked out/y, read
// `true`, and allowed the exec unmatched while the kernel ran rm -r.
func TestIntegrationExecRuleShebangCRLF(t *testing.T) {
	rm, err := exec.LookPath("rm")
	if err != nil {
		t.Skip("no rm")
	}
	tr, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no true")
	}
	f := newFixture(t, execRulesContract("xcrlf", "/bin/sh", "  deny: [rm -r]"))
	if err := os.MkdirAll(filepath.Join(f.out, "tree", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	y := filepath.Join(f.out, "y")
	for target, name := range map[string]string{tr: y, rm: y + "\r"} {
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
		agentOwns(t, name)
	}
	p := filepath.Join(f.out, "c")
	if err := os.WriteFile(p, []byte("#!"+y+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, p)
	if err := os.Chmod(p, 0o755); err != nil {
		t.Fatal(err)
	}
	runScript(t, f, `./out/c -r out/tree >>out/log 2>&1; echo "c $?" >> out/st`)
	if st := statuses(t, f); st["c"] != 126 {
		t.Errorf("./out/c: exit %d, want 126 (EACCES at execve)\n%s", st["c"], logOf(f))
	}
	if _, err := os.Stat(filepath.Join(f.out, "tree", "sub")); err != nil {
		t.Error("out/tree/sub is gone: the kernel ran rm -r through y\\r")
	}
	var got string
	for _, l := range execLines(t, f.root) {
		if len(l.argv) > 0 && l.argv[0] == "./out/c" {
			got = string(l.verdict) + " " + l.rule + " " + l.commandVia
		}
	}
	if got != "refused exec.deny[rm -r] shebang" {
		t.Errorf("./out/c line: %q, want refused exec.deny[rm -r] via shebang", got)
	}
}

// TestIntegrationExecRuleNonRegularImage: in a run with command rules, an exec of a FIFO or a character device is
// refused image-unreadable with EACCES, the kernel's own answer, and the supervisor never opens it to read a #!
// line (TestExecImageHeadOpensOnlyRegular holds the open itself).
func TestIntegrationExecRuleNonRegularImage(t *testing.T) {
	f := newFixture(t, execRulesContract("xnonreg", "/bin/sh", "  deny: [rm -r]"))
	fifo := filepath.Join(f.out, "f")
	if err := unix.Mkfifo(fifo, 0o755); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, fifo)
	if err := os.Chmod(fifo, 0o755); err != nil {
		t.Fatal(err)
	}
	runScript(t, f, `./out/f >>out/log 2>&1; echo "f $?" >> out/st
/dev/null >>out/log 2>&1; echo "n $?" >> out/st`)
	st := statuses(t, f)
	for _, c := range []string{"f", "n"} {
		if st[c] != 126 {
			t.Errorf("%s: exit %d, want 126 (EACCES at execve)\n%s", c, st[c], logOf(f))
		}
	}
	rules := map[string]string{}
	for _, l := range execLines(t, f.root) {
		if len(l.argv) > 0 {
			rules[l.argv[0]] = string(l.verdict) + " " + l.rule
		}
	}
	for _, c := range []string{"./out/f", "/dev/null"} {
		if got := rules[c]; got != "refused image-unreadable" {
			t.Errorf("%s line: %q, want refused image-unreadable", c, got)
		}
	}
}

// TestIntegrationExecRuleNotExecutable: in a run with command rules, the #! line of a file the kernel refuses the
// task (EACCES, before it reads a byte) is never read. A `chmod 644` script naming a missing interpreter is answered
// EACCES (126) and observed, never refused interpreter-unresolved with ENOENT (127), which the supervisor answered
// first before the fix. Run as root, a root-only script (0700) is the same to the dropped agent: the root supervisor
// read it, and the errno told the agent whether it starts with a #! line and whether the path it names resolves.
func TestIntegrationExecRuleNotExecutable(t *testing.T) {
	f := newFixture(t, execRulesContract("xnox", "/bin/sh", "  deny: [rm -r]"))
	script := "./out/p >>out/log 2>&1; echo \"p $?\" >> out/st\n"
	p := filepath.Join(f.out, "p")
	if err := os.WriteFile(p, []byte("#!/nonexistent/interp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, p)
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	names := []string{"./out/p"}
	if _, _, ok := agentUID(t); ok {
		r := filepath.Join(f.out, "r")
		if err := os.WriteFile(r, []byte("#!/nonexistent/interp\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		script += "./out/r >>out/log 2>&1; echo \"r $?\" >> out/st\n"
		names = append(names, "./out/r")
	}
	runScript(t, f, script)
	st := statuses(t, f)
	lines := map[string]string{}
	for _, l := range execLines(t, f.root) {
		if len(l.argv) > 0 {
			lines[l.argv[0]] = string(l.verdict) + " " + l.rule
		}
	}
	for _, n := range names {
		if code := st[strings.TrimPrefix(n, "./out/")]; code != 126 {
			t.Errorf("%s: exit %d, want 126 (EACCES at execve, the kernel's own answer)\n%s", n, code, logOf(f))
		}
		if got := lines[n]; got != "observed unmatched" {
			t.Errorf("%s line: %q, want observed unmatched", n, got)
		}
	}
}
