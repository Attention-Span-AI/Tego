// SPDX-License-Identifier: Apache-2.0

package execmatch_test

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
)

// TestAutocorrectPort holds the help_unknown_cmd port to tokens measured against git 2.51.0 (ADR 0048's table):
// psh, pusg, psuh, puhs, Push, "push " and pυsh reach push; pus reaches nothing (push and pull tie).
func TestAutocorrectPort(t *testing.T) {
	c := execmatch.NewCandidates(rows.Git().Builtins, rows.Git().Common)
	for _, tok := range []string{"psh", "pusg", "psuh", "puhs", "Push", "push ", "pυsh"} {
		if got, ok := execmatch.Autocorrect(tok, c); !ok || got != "push" {
			t.Errorf("Autocorrect(%q) = %q, %v; want push", tok, got, ok)
		}
	}
	for _, tok := range []string{"pus", "push", "s", "", strings.Repeat("x", 80), "sh", "gui"} {
		if got, ok := execmatch.Autocorrect(tok, c); ok && got == "push" {
			t.Errorf("Autocorrect(%q) = %q", tok, got)
		}
	}
	if got, ok := execmatch.Autocorrect("stauts", c); !ok || got != "status" {
		t.Errorf("stauts: %q %v", got, ok)
	}
}

// TestClosure: git's helper closure is transitive and admits helpers on the allow side only.
func TestClosure(t *testing.T) {
	c := execmatch.Closure(rows.Git(), "fetch")
	for _, h := range []string{"maintenance", "rev-list", "remote-https", "gc", "repack", "pack-objects", "worktree prune"} {
		if !c[h] {
			t.Errorf("fetch's closure lacks %s: %v", h, c)
		}
	}
	if c["push"] || c["fetch"] {
		t.Errorf("fetch's closure holds push or itself: %v", c)
	}
	ix := index(t, "allow: git fetch", "deny: git gc")
	if got := decide(ix, "git", "rev-list", "--objects", "--stdin"); got != "allowed exec.allow[git fetch]" {
		t.Errorf("rev-list under allow git fetch: %s", got)
	}
	if got := decide(ix, "git", "worktree", "prune", "--expire", "now"); got != "allowed exec.allow[git fetch]" {
		t.Errorf("worktree prune: %s", got)
	}
	if got := decide(ix, "git", "worktree", "add", "x"); got != "refused exec.args[git]" {
		t.Errorf("worktree add is not in the closure: %s", got)
	}
	if got := decide(ix, "git", "gc", "--auto"); got != "refused exec.deny[git gc]" {
		t.Errorf("a deny entry still refuses a closure member: %s", got)
	}
	if got := decide(ix, "git", "push"); got != "refused exec.args[git]" {
		t.Errorf("push is not in fetch's closure: %s", got)
	}
	f := execmatch.Facts{Requested: "/usr/lib/git-core/git-upload-pack", Image: "git", Argv0: "git-upload-pack", Argv: []string{"git-upload-pack", "/r.git"}, ArgvComplete: true}
	if r := ix.Decide(&f); r.Outcome != execmatch.OutcomeAllowed || r.Via != execmatch.ViaClosure || r.ClosureOf == nil {
		t.Errorf("git-upload-pack under allow git fetch: %+v", r)
	}
}

// TestUnconstrainedByImplicitGrant: a tool an implicit grant names keeps any arguments, and a bare name entry lifts
// the constraint while a bare path entry does not.
func TestUnconstrainedByImplicitGrant(t *testing.T) {
	p, _ := execmatch.Parse("git status", execmatch.ListAllow, rows.Builtin())
	ix := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{p}, execmatch.IndexOptions{Unconstrained: map[string]bool{"git": true}})
	if ix.Constrained("git") {
		t.Error("an implicit grant leaves git constrained")
	}
	if got := decide(index(t, "allow: git status", "allow: git"), "git", "push"); got != "none" {
		t.Errorf("a bare git entry lifts the constraint: %s", got)
	}
	if got := decide(index(t, "allow: git status", "allow: /usr/bin/git"), "git", "push"); got != "refused exec.args[git]" {
		t.Errorf("a bare path entry does not lift it: %s", got)
	}
}

// TestPrecedence: deny before ask before allow, whatever the specificity; no exception syntax.
func TestPrecedence(t *testing.T) {
	ix := index(t, "allow: git push --dry-run", "deny: git push", "ask: git push origin")
	if got := decide(ix, "git", "push", "--dry-run", "origin"); got != "refused exec.deny[git push]" {
		t.Errorf("an allow cannot carve a hole in a deny: %s", got)
	}
	ix = index(t, "ask: npm install", "allow: npm install")
	if got := decide(ix, "npm", "install"); got != "refused exec.ask[npm install]" {
		t.Errorf("ask refuses before allow: %s", got)
	}
}

// TestStagedFinal: a decision on an argv prefix is final only when more of argv cannot change it (ADR 0048 (3)).
func TestStagedFinal(t *testing.T) {
	ix := index(t, "deny: git push", "allow: git add", "allow: git log --oneline", "deny: rm -r")
	prefix := func(argv ...string) execmatch.Result {
		f := execmatch.Facts{Requested: argv[0], Image: argv[0], Argv0: argv[0], Argv: argv, ArgvComplete: false}
		return ix.Decide(&f)
	}
	if r := prefix("git", "push"); !r.Final || r.Outcome != execmatch.OutcomeRefused {
		t.Errorf("a deny match on the prefix is final: %+v", r)
	}
	if r := prefix("git", "add", "a", "b"); !r.Final || r.Outcome != execmatch.OutcomeAllowed {
		t.Errorf("allow git add on its prefix is final: %+v", r)
	}
	if r := prefix("git", "log"); r.Final {
		t.Errorf("allow git log --oneline needs the tail: %+v", r)
	}
	if r := prefix("git", "-C"); r.Final {
		t.Errorf("an unlocated subcommand is not final: %+v", r)
	}
	if r := prefix("rm", "x", "y"); r.Final {
		t.Errorf("deny rm -r can still match the tail: %+v", r)
	}
	if r := prefix("ls", "-l"); !r.Final || r.Guarded {
		t.Errorf("an unguarded exec is final: %+v", r)
	}
	if r := prefix("python3", "-u"); r.Final {
		t.Errorf("an interpreter whose script is not read yet is not final: %+v", r)
	}
	// A prefix that ends at node's -p, or at -e before its code, has not read whether code follows: node runs the script
	// after `-p --title t`, so the decision waits for the rest of argv.
	for _, argv := range [][]string{{"node", "-p"}, {"node", "--no-print"}, {"node", "--print=v"}, {"node", "-e"}} {
		if r := prefix(argv...); r.Final {
			t.Errorf("%v as a prefix: settled, want the rest of argv read: %+v", argv, r)
		}
	}
	// Nor does code settle node before its script is read: node reads -i after the code, and then runs the script.
	if r := prefix("node", "-p", "code"); r.Final {
		t.Errorf("node -p code as a prefix: settled, want the rest of argv read (node -p code -i app.js runs app.js): %+v", r)
	}
	if r := prefix("node", "-e", "code", "app.js"); !r.Final {
		t.Errorf("node reads no option past its script: node -e code app.js as a prefix is settled: %+v", r)
	}
	// Ending at --trace-events-enabled=v, node's options have ended and the script is the next token, whatever it is.
	if r := prefix("node", "--trace-events-enabled=v"); r.Final {
		t.Errorf("node --trace-events-enabled=v as a prefix: settled, want the script read: %+v", r)
	}
	// --build-snapshot-config makes node run a builder its file names: refused on any prefix that holds it.
	if r := prefix("node", "--build_snapshot_config"); !r.Final || r.Outcome != execmatch.OutcomeRefused || r.Rule() != execmatch.RuleCommandUnresolved {
		t.Errorf("node --build_snapshot_config as a prefix: %+v, want refused %s", r, execmatch.RuleCommandUnresolved)
	}
	if r := prefix("python3", "-c", "code"); !r.Final {
		t.Errorf("python's -c ends its options: python3 -c code as a prefix is settled: %+v", r)
	}
}

// TestGuarded: names alone tell whether an exec needs argv past argv[0].
func TestGuarded(t *testing.T) {
	ix := index(t, "deny: git push")
	g := func(req, img, a0 string) bool {
		return ix.Guarded(&execmatch.Facts{Requested: req, Image: img, Argv0: a0})
	}
	if !g("/usr/bin/git", "git", "git") || !g("/x/git-push", "x", "x") || !g("/usr/bin/busybox", "busybox", "busybox") || !g("/usr/bin/python3", "python3.13", "python3") {
		t.Error("git, a dashed name, a multicall binary and an interpreter are guarded")
	}
	if g("/usr/bin/ls", "ls", "ls") {
		t.Error("ls is not guarded under deny git push")
	}
	if index(t).Guarded(&execmatch.Facts{Requested: "git"}) {
		t.Error("no rules guard nothing")
	}
}

// TestMatchAllocatesNothing: matching a normalized invocation allocates nothing (ADR 0048 C1a).
func TestMatchAllocatesNothing(t *testing.T) {
	ix := index(t, "deny: git push --force", "allow: git log --oneline", "deny: mytool deploy --force")
	ps := ix.Patterns()
	git := ix.Interpretations(&execmatch.Facts{Requested: "git", Image: "git", Argv0: "git", Argv: strings.Fields("git -C . push -f origin main"), ArgvComplete: true})
	gen := ix.Interpretations(&execmatch.Facts{Requested: "mytool", Image: "mytool", Argv0: "mytool", Argv: strings.Fields("mytool deploy --force"), ArgvComplete: true})
	allocs := testing.AllocsPerRun(200, func() {
		for _, p := range ps {
			for i := range git {
				p.Match(&git[i])
			}
			for i := range gen {
				p.Match(&gen[i])
			}
		}
	})
	if allocs != 0 {
		t.Errorf("Match allocates %v per run", allocs)
	}
}

// BenchmarkMatch is one pattern against one normalized invocation.
func BenchmarkMatch(b *testing.B) {
	ix := index(b, "deny: git push --force")
	inv := ix.Interpretations(&execmatch.Facts{Requested: "git", Image: "git", Argv0: "git", Argv: strings.Fields("git -C . push -f origin main"), ArgvComplete: true})
	p := ix.Patterns()[0]
	b.ReportAllocs()
	for b.Loop() {
		p.Match(&inv[0])
	}
}

// TestShebangStageByImageAndIdentity: a #! interpreter is read by its #! path, by the walked image's name and by its
// identity, as a direct image is (ADR 0048 (2)). '#!/tmp/x -rf', with /tmp/x a symlink to rm, runs rm -rf on the
// script's operands; read by the #! path alone it was "x", unguarded, and continued.
func TestShebangStageByImageAndIdentity(t *testing.T) {
	rmID := execmatch.ID{Dev: 8, Ino: 4242}
	p, err := execmatch.Parse("rm -r", execmatch.ListDeny, rows.Builtin())
	if err != nil {
		t.Fatal(err)
	}
	ix := execmatch.NewIndex(rows.Builtin(), []*execmatch.Pattern{p}, execmatch.IndexOptions{Identities: map[execmatch.ID]string{rmID: "rm"}})
	script := func(st execmatch.Stage) *execmatch.Facts {
		return &execmatch.Facts{
			Requested: "s", Path: "./out/s", Image: "s", Argv0: "./out/s", Argv: []string{"./out/s", "out/tree"}, ArgvComplete: true,
			ID: execmatch.ID{Dev: 8, Ino: 7}, HasID: true, Form: execmatch.FormScript, Interp: []execmatch.Stage{st},
		}
	}
	cases := []struct {
		name string
		st   execmatch.Stage
	}{
		{"by the walked image's name", execmatch.Stage{Path: "/tmp/x", Arg: "-rf", Image: "rm"}},
		{"by identity alone", execmatch.Stage{Path: "/tmp/x", Arg: "-rf", Image: "x", ID: rmID, HasID: true}},
		{"by both", execmatch.Stage{Path: "/tmp/x", Arg: "-rf", Image: "rm", ID: rmID, HasID: true}},
	}
	for _, c := range cases {
		f := script(c.st)
		if !ix.Guarded(f) {
			t.Errorf("%s: a symlinked rm interpreter is not guarded", c.name)
		}
		r := ix.Decide(f)
		if r.Outcome != execmatch.OutcomeRefused || r.Rule() != "exec.deny[rm -r]" || r.Via != execmatch.ViaShebang {
			t.Errorf("%s: %s via %s, want refused exec.deny[rm -r] via shebang", c.name, r.Outcome, r.Via)
		}
	}
	// An identity the walk did not vouch for (HasID false) is not read, and a name that is no ruled tool stays
	// unguarded.
	f := script(execmatch.Stage{Path: "/tmp/x", Arg: "-rf", Image: "x", ID: rmID})
	if ix.Guarded(f) {
		t.Error("a stage's unvouched identity guarded it")
	}
	if r := ix.Decide(f); r.Outcome != execmatch.OutcomeNone {
		t.Errorf("an unruled interpreter: %s", r.Outcome)
	}
	// git reached as a #! interpreter named git-push runs push: the stage's name reads its dashed form, and the
	// walked image (git) reads it from argv[0].
	ix = index(t, "deny: git push")
	for _, st := range []execmatch.Stage{{Path: "/tmp/git-push", Image: "git-push"}, {Path: "/tmp/git-push", Image: "git"}} {
		f := &execmatch.Facts{Requested: "s", Path: "./s", Image: "s", Argv0: "./s", Argv: []string{"./s", "origin"}, ArgvComplete: true,
			Form: execmatch.FormScript, Interp: []execmatch.Stage{st}}
		if r := ix.Decide(f); r.Outcome != execmatch.OutcomeRefused || r.Rule() != "exec.deny[git push]" {
			t.Errorf("#!%s (image %s): %s %s", st.Path, st.Image, r.Outcome, r.Rule())
		}
	}
}

// TestDispatchDepthFailsClosed: a multicall dispatcher that re-dispatches to itself (busybox has a `busybox`
// applet) must not let a denied applet slip past the dispatch-depth bound (2026-10-06). Under
// deny: [rm -r], `busybox rm -r x` is refused via multicall; so is every nesting `busybox ... busybox rm -r x`,
// however deep: when the chain is longer than the matcher resolves, the decision fails closed (command-unresolved,
// via overflow) rather than dropping the rm interpretation and allowing the exec. The round-5 reviewer deleted a
// tree with `busybox`x5 + `rm -r` while the ledger said allow unmatched.
func TestDispatchDepthFailsClosed(t *testing.T) {
	ix := index(t, "deny: rm -r")
	for k := 0; k <= 10; k++ {
		argv := make([]string, 0, k+3)
		for i := 0; i < k; i++ {
			argv = append(argv, "busybox")
		}
		argv = append(argv, "busybox", "rm", "-r", "x") // the image is busybox; k extra leading busybox words
		f := execmatch.Facts{Requested: "busybox", Image: "busybox", Argv0: "busybox", Argv: argv, ArgvComplete: true}
		r := ix.Decide(&f)
		if r.Outcome != execmatch.OutcomeRefused {
			t.Errorf("busybox x%d then rm -r: %s %q, want refused (a denied applet behind the dispatch bound must fail closed)", k+1, r.Outcome, r.Rule())
			continue
		}
		// A resolved chain names the entry; a truncated one fails closed under command-unresolved.
		if rule := r.Rule(); rule != "exec.deny[rm -r]" && rule != "command-unresolved" {
			t.Errorf("busybox x%d then rm -r: rule %q, want exec.deny[rm -r] or command-unresolved", k+1, rule)
		}
	}
	// A deep nesting that ends in an applet no rule names is still allowed to be refused (fail closed): busybox x8
	// then `true` is unresolved past the bound, so it is refused command-unresolved rather than allowed by a wrong
	// resolution. A single `busybox true` (resolvable, true unruled) is allowed.
	shallow := execmatch.Facts{Requested: "busybox", Image: "busybox", Argv0: "busybox", Argv: []string{"busybox", "true"}, ArgvComplete: true}
	if r := ix.Decide(&shallow); r.Outcome != execmatch.OutcomeNone {
		t.Errorf("busybox true (resolvable, unruled applet): %s %q, want none", r.Outcome, r.Rule())
	}
}
