// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// commandFixture is a fixture with git, rm (as a link to a one-link gnurm) and npm in its bin directory, and a git
// exec-path beside it holding git's own git and a dashed helper.
func commandFixture(t *testing.T) *fixture {
	t.Helper()
	f := newFixture(t)
	for _, n := range []string{"git", "gnurm", "npm"} {
		f.file(filepath.Join(f.bin, n), string(elf64("", 2)), 0o755)
	}
	if err := os.Symlink("gnurm", filepath.Join(f.bin, "rm")); err != nil {
		t.Fatal(err)
	}
	core := filepath.Join(f.root, "lib", "git-core")
	if err := os.MkdirAll(core, 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(core, "git"), string(elf64("", 2)), 0o755)
	f.file(filepath.Join(core, "git-remote-https"), string(elf64("", 2)), 0o755)
	if err := os.Symlink("git", filepath.Join(core, "git-push")); err != nil {
		t.Fatal(err)
	}
	return f
}

// decideArgv is the table's command-rule decision for an exec of argv by name.
func decideArgv(rt *RuleTable, argv ...string) execmatch.Result {
	f := execmatch.Facts{Requested: argv[0], Image: argv[0], Argv0: argv[0], Argv: argv, ArgvComplete: true}
	return rt.ExecCommands.Index.Decide(&f)
}

// TestCompileExecCommands: compile builds RuleTable.ExecCommands, the patterns indexed by tool (ADR 0048 (4)), and
// prints one line per pattern with its row, its reading and its notes, then the mode with the file that set it.
func TestCompileExecCommands(t *testing.T) {
	f := commandFixture(t)
	c := f.load("version: 0\nname: p\ncommand: [static-tool]\nexec:\n  allow: [git status, git diff, git log --oneline, npm]\n  deny: [git push, rm -r]\n")
	rt, _ := f.compile(c)
	if rt.ExecCommands == nil || rt.ExecCommands.Index.Empty() {
		t.Fatal("no command rules compiled")
	}
	for argv, want := range map[string]execmatch.Outcome{
		"git push origin":      execmatch.OutcomeRefused,
		"git status -s":        execmatch.OutcomeAllowed,
		"git log --oneline -3": execmatch.OutcomeAllowed,
		"git log -3":           execmatch.OutcomeRefused,
		"git commit -m x":      execmatch.OutcomeRefused,
		"rm -rf x":             execmatch.OutcomeRefused,
		"npm publish":          execmatch.OutcomeNone,
	} {
		if got := decideArgv(rt, strings.Fields(argv)...); got.Outcome != want {
			t.Errorf("%s: %s (%s), want %s", argv, got.Outcome, got.Rule(), want)
		}
	}
	var out bytes.Buffer
	if err := PrintRuleTable(&out, rt); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	t.Logf("%s", text)
	for _, want := range []string{
		"exec deny  git push",
		"row git 2.51.0 (probed)",
		"subcommand push; any options and operands",
		"also refuses (autocorrect):",
		"exec allow git log --oneline",
		"requires --oneline; every other option free",
		"exec deny  rm -r",
		"row rm GNU coreutils 9.5 (probed)",
		"exec: images restricted (allow, set by agent.yaml), 5 command rules",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("print lacks %q:\n%s", want, text)
		}
	}
}

// TestCompileExecCommandsOwnCommand: a deny or ask entry that matches the run's own command is an exec-rule error
// (the run could not start); one that matches an MCP server's command warns, naming the server.
func TestCompileExecCommandsOwnCommand(t *testing.T) {
	f := commandFixture(t)
	c := f.load("version: 0\nname: p\ncommand: [git, push]\nexec:\n  deny: [git push]\n")
	_, ds, err := Compile(c, f.machine, f.opts()...)
	if err == nil || !hasFinding(ds, CodeExecRule, SeverityError) || !strings.Contains(render(ds), "the run's own command") {
		t.Errorf("deny matching the command: %v\n%s", err, render(ds))
	}
	c = f.load("version: 0\nname: p\ncommand: [static-tool]\nmcp:\n  - name: pub\n    command: [npm, publish]\nexec:\n  deny: [npm publish]\n")
	_, ds = f.compile(c)
	if !hasFinding(ds, CodeExecRule, SeverityWarning) || !strings.Contains(render(ds), `mcp "pub"`) {
		t.Errorf("deny matching an mcp command:\n%s", render(ds))
	}
}

// TestCompileExecCommandsWarnings are ADR 0048 (9)'s warnings, each one an author can act on.
func TestCompileExecCommandsWarnings(t *testing.T) {
	f := commandFixture(t)
	work := filepath.Join(f.project, "out")
	cases := []struct {
		name, exec, extra, code, want string
	}{
		{"deny-list beside fs.write", "  deny: [git push]\n", "fs: {write: [" + work + "]}\n", CodeExecRuleCoverage, "a copy of git under another name is not git"},
		// With no write entry a copy still runs from a memfd, or from a file the agent deleted, and
		// an agent can map a program's file into itself with no exec at all; a deny-list never said so.
		{"deny-list beside fs.write names the memfd", "  deny: [git push]\n", "fs: {write: [" + work + "]}\n", CodeExecRuleCoverage, "a copy run from a memfd"},
		{"deny-list without fs.write", "  deny: [git push]\n", "", CodeExecRuleCoverage, "a copy of git run from a memfd or from a file it deleted is not git to these rules"},
		{"deny-list without fs.write maps", "  deny: [git push]\n", "", CodeExecRuleCoverage, "maps a program's file into its own process"},
		{"allow names options", "  allow: [git log --oneline]\n", "", CodeExecRuleCoverage, "required, not a whitelist"},
		{"implicit grant shadows", "  allow: [static-tool --x]\n", "", CodeExecRuleCoverage, "keeps any arguments"},
		{"constrained beside bare", "  allow: [git status, git]\n", "", CodeRedundantRule, "the bare entry"},
		{"ask is reserved", "  ask: [npm install]\n", "", CodeUnenforced, "completion_unsupported"},
		// An ask-only section is a deny-list too, and its warning names the asked tool and what an
		// ask entry decides, not "a denied program" and a deny entry; one that sets exec.anonymous is told to drop it.
		{"ask-only deny-list names the asked tool", "  ask: [npm install]\n", "", CodeExecRuleCoverage, "a copy of npm run from a memfd or from a file it deleted is not npm"},
		{"ask-only deny-list says what an ask entry decides", "  ask: [npm install]\n", "", CodeExecRuleCoverage, "an ask entry decides a command by its name"},
		{"deny-list with anonymous is told to drop it", "  deny: [git push]\n  anonymous: true\n", "", CodeExecRuleCoverage, "drop exec.anonymous"},
	}
	for _, tc := range cases {
		c := f.load("version: 0\nname: p\ncommand: [static-tool]\n" + tc.extra + "exec:\n" + tc.exec)
		rt, ds, err := Compile(c, f.machine, f.opts()...)
		if err != nil && tc.name != "implicit grant shadows" {
			t.Errorf("%s: %v\n%s", tc.name, err, render(ds))
			continue
		}
		_ = rt
		found := false
		for _, d := range ds {
			if d.Code == tc.code && strings.Contains(d.Message+" "+d.Fix, tc.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: want %s holding %q:\n%s", tc.name, tc.code, tc.want, render(ds))
		}
	}
	// The ask-only section's warning says nothing of a deny entry it does not have.
	c := f.load("version: 0\nname: p\ncommand: [static-tool]\nexec:\n  ask: [npm install]\n")
	_, ds, _ := Compile(c, f.machine, f.opts()...)
	for _, d := range ds {
		if d.Code == CodeExecRuleCoverage && (strings.Contains(d.Message, "a deny entry") || strings.Contains(d.Message, "a denied program")) {
			t.Errorf("an ask-only section's warning speaks of a deny entry: %s", d.Message)
		}
	}
}

// TestCompileExecHelperImages: an allow entry naming git, bare or constrained, grants git's own helper images in its
// exec-path (the git another inode than the PATH one, and the dashed helpers the closure needs); the rules see them.
func TestCompileExecHelperImages(t *testing.T) {
	f := commandFixture(t)
	core := filepath.Join(f.root, "lib", "git-core")
	c := f.load("version: 0\nname: p\ncommand: [static-tool]\nexec:\n  allow: [git fetch]\n")
	rt, _ := f.compile(c)
	got := map[string]bool{}
	for _, r := range rt.Exec {
		got[r.Path] = true
	}
	for _, p := range []string{filepath.Join(core, "git"), filepath.Join(core, "git-remote-https")} {
		if !got[p] {
			t.Errorf("helper image %s not granted: %v", p, got)
		}
	}
	if !slicesContains(rt.ExecCommands.Helpers, filepath.Join(core, "git")) {
		t.Errorf("helpers %v", rt.ExecCommands.Helpers)
	}
	c = f.load("version: 0\nname: p\ncommand: [static-tool]\nexec:\n  allow: [ls]\n")
	f.file(filepath.Join(f.bin, "ls"), string(elf64("", 2)), 0o755)
	rt, _ = f.compile(c)
	for _, r := range rt.Exec {
		if strings.HasPrefix(r.Path, core) {
			t.Errorf("a contract naming no git grants %s", r.Path)
		}
	}
}

// TestCompileExecIdentities: a ruled command resolved to a file of one link is that tool by identity, so a copy of
// gnurm reached by another name is still rm (ADR 0048 (2), interpretation 2).
func TestCompileExecIdentities(t *testing.T) {
	f := commandFixture(t)
	c := f.load("version: 0\nname: p\ncommand: [static-tool]\nexec:\n  deny: [rm -r]\n")
	rt, _ := f.compile(c)
	var id execmatch.ID
	found := false
	for k, tool := range rt.ExecCommands.Identities {
		if tool == "rm" {
			id, found = k, true
		}
	}
	if !found {
		t.Fatalf("no identity for rm: %v", rt.ExecCommands.Identities)
	}
	fx := execmatch.Facts{Requested: "/elsewhere/zap", Image: "zap", Argv0: "zap", ID: id, HasID: true, Argv: []string{"zap", "-r", "x"}, ArgvComplete: true}
	if r := rt.ExecCommands.Index.Decide(&fx); r.Outcome != execmatch.OutcomeRefused || r.Via != execmatch.ViaIdentity {
		t.Errorf("rm by identity: %s via %s", r.Outcome, r.Via)
	}
}

// TestCompileExecLoaders: compile keeps the identity of every file a loader's name names in the library directories,
// through a link, a hard link to one counting, and nothing else there (ADR 0048 (3)). A run with
// command rules carries the host's loaders in its index; the dev box's own is one.
func TestCompileExecLoaders(t *testing.T) {
	dir := t.TempDir()
	ld := filepath.Join(dir, "ld-linux-x86-64.so.2")
	for _, p := range []string{ld, filepath.Join(dir, "libc.so.6")} {
		if err := os.WriteFile(p, []byte("\x7fELF"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(ld, filepath.Join(dir, "elsewhere")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("libc.so.6", filepath.Join(dir, "ld-musl-x86_64.so.1")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "ld.so"), 0o755); err != nil {
		t.Fatal(err)
	}
	idOf := func(p string) execmatch.ID {
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			t.Fatal(err)
		}
		return execmatch.ID{Dev: uint64(st.Dev), Ino: st.Ino}
	}
	got := execLoaders([]string{dir, filepath.Join(dir, "missing")})
	want := map[execmatch.ID]bool{idOf(ld): true, idOf(filepath.Join(dir, "libc.so.6")): true}
	if len(got) != len(want) || !got[idOf(ld)] || !got[idOf(filepath.Join(dir, "libc.so.6"))] {
		t.Errorf("loaders %v, want %v", got, want)
	}
	f := commandFixture(t)
	rt, _ := f.compile(f.load("version: 0\nname: p\ncommand: [static-tool]\nexec:\n  deny: [rm -r]\n"))
	if p, err := filepath.EvalSymlinks("/lib64/ld-linux-x86-64.so.2"); err == nil {
		if !rt.ExecCommands.Index.Loader(idOf(p)) {
			t.Errorf("the host's loader %s is no loader to the index", p)
		}
	}
}

// TestBestEffortExecRules: a table with command rules lists exec.rules/argv at every tier (P1 decides on copied argv
// everywhere), and compile warns once per tier the run can land in.
func TestBestEffortExecRules(t *testing.T) {
	f := commandFixture(t)
	c := f.load("version: 0\nname: p\ncommand: [static-tool]\nexec:\n  deny: [git push]\n")
	rt, ds := f.compile(c)
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		if !slicesContains(rt.BestEffortCellsAt(tier, ""), BestEffortExecRules) {
			t.Errorf("%s: best_effort %v", tier, rt.BestEffortCellsAt(tier, ""))
		}
	}
	n := 0
	for _, d := range ds {
		if d.Code == CodeUnenforced && strings.Contains(d.Message, BestEffortExecRules) {
			n++
		}
	}
	if n == 0 {
		t.Errorf("no best-effort warning:\n%s", render(ds))
	}
	c = f.load("version: 0\nname: p\ncommand: [static-tool]\nexec:\n  allow: [git]\n")
	rt, _ = f.compile(c)
	if slicesContains(rt.BestEffortCellsAt(backend.TierLandlock, ""), BestEffortExecRules) {
		t.Error("a table with no command rule lists exec.rules/argv")
	}
}

// TestCompileWarnsImageUnreadableAtLandlock: in a run with command rules every image's #! line is read, and at tier
// landlock the supervisor runs as the agent's user, so an image that user cannot read (RHEL's sudo, mode 4111) is
// refused image-unreadable even where no rule names it (ADR 0048 R13). compile says so at tier landlock alone; the
// root tiers' supervisor reads every image on a local file system, which the warning qualifies. A table with no
// command rule reads no head and warns nothing.
func TestCompileWarnsImageUnreadableAtLandlock(t *testing.T) {
	f := commandFixture(t)
	for tier, want := range map[string]int{"landlock": 1, "cgroup": 0, "bpflsm": 0} {
		c := f.load("version: 0\nname: p\ncommand: [static-tool]\ntier: " + tier + "\nexec:\n  deny: [git push]\n")
		_, ds := f.compile(c)
		n := 0
		for _, d := range ds {
			if strings.Contains(d.Message, "image-unreadable") {
				n++
				if d.Tier != backend.TierLandlock {
					t.Errorf("tier %s: the warning holds at %q, want landlock alone", tier, d.Tier)
				}
				// A root supervisor is refused too on a root-squashed NFS export and a FUSE mount without
				// allow_other or allow_root: the warning never says it reads every image.
				if !strings.Contains(d.Message, "root_squash") || !strings.Contains(d.Message, "allow_root") {
					t.Errorf("tier %s: the warning says a root supervisor reads every image, with no exception: %s", tier, d.Message)
				}
			}
		}
		if n != want {
			t.Errorf("tier %s: %d image-unreadable warnings, want %d:\n%s", tier, n, want, render(ds))
		}
	}
	c := f.load("version: 0\nname: p\ncommand: [static-tool]\nexec:\n  allow: [git]\n")
	if _, ds := f.compile(c); strings.Contains(render(ds), "image-unreadable") {
		t.Errorf("a table with no command rule warns image-unreadable:\n%s", render(ds))
	}
}

// TestCompileListsBroadenedGateRules: compile lists each existing gate exec rule whose reading the shared matcher
// broadened (ADR 0048 (5)), with its command reading.
func TestCompileListsBroadenedGateRules(t *testing.T) {
	f := commandFixture(t)
	c := f.load("version: 0\nname: p\ncommand: [static-tool]\ngate:\n  rules:\n    - \"exec matches \\\"rm -rf\\\"\": 90\n")
	rt, _ := f.compile(c)
	var out bytes.Buffer
	if err := PrintRuleTable(&out, rt); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "gate.rules[0] also matches as a command pattern: with --force --recursive") &&
		!strings.Contains(out.String(), "gate.rules[0] also matches as a command pattern: with --recursive --force") {
		t.Errorf("print:\n%s", out.String())
	}
}

// slicesContains reports whether s holds v.
func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
