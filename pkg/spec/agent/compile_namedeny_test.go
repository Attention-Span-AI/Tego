// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestNameDenyClassification is ADR 0043 Terms' classification of a deny_read glob's final component: a literal of
// two bytes or more is an exact entry, such a literal of three or more and one trailing `*` a prefix entry,
// ASCII-folded; a suffix, a class, a `?`, a bare `*`, an escape or a literal under the floor is none.
func TestNameDenyClassification(t *testing.T) {
	for _, tc := range []struct {
		in      string
		literal string
		prefix  bool
		ok      bool
	}{
		{".env", ".env", false, true},
		{"secret.json", "secret.json", false, true},
		{".ENV", ".env", false, true},
		{".env*", ".env", true, true},
		{"Key*", "key", true, true},
		{"ab", "ab", false, true},
		{"a", "", false, false},
		{"ab*", "", false, false},
		{"k*", "", false, false},
		{"*", "", false, false},
		{"*.pem", "", false, false},
		{"a?c", "", false, false},
		{"[ab]x", "", false, false},
		{`a\*b`, "", false, false},
		{"x*y", "", false, false},
		{"abc**", "", false, false},
	} {
		lit, prefix, ok := NameEntryOf(tc.in)
		if lit != tc.literal || prefix != tc.prefix || ok != tc.ok {
			t.Errorf("NameEntryOf(%q) = %q, %v, %v; want %q, %v, %v", tc.in, lit, prefix, ok, tc.literal, tc.prefix, tc.ok)
		}
	}
	for _, tc := range []struct{ glob, base string }{
		{"/p/*/secret.json", "/p"},
		{"/p/sub/.env*", "/p/sub"},
		{"/p/a*/b/c.json", "/p"},
		{"/*/x", "/"},
	} {
		if got := globBase(tc.glob); got != tc.base {
			t.Errorf("globBase(%q) = %q, want %q", tc.glob, got, tc.base)
		}
	}
}

// TestBuiltInNameEntries: the built-in .env list compiles to two name entries, exact `.env` and the `.env.` prefix
// with the scan's exceptions, scoped to the scan's roots by their resolved paths; a working directory beneath the
// contract's directory is dropped as a scope its parent covers, one beneath a dependency directory is kept (the
// parent does not cover it), and the entries come last in NameDeny's deciding order (ADR 0043 Terms, D3).
func TestBuiltInNameEntries(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"out/\"]\n  deny_read: [\"secrets/*/api.key\"]\n")
	rt, ds := f.compile(c)
	if len(rt.NameDeny) != 3 {
		t.Fatalf("NameDeny = %+v, want the declared entry and the built-in pair\n%s", rt.NameDeny, render(ds))
	}
	decl, exact, prefix := rt.NameDeny[0], rt.NameDeny[1], rt.NameDeny[2]
	if decl.BuiltIn || decl.Literal != "api.key" || decl.Prefix || decl.Raw != "secrets/*/api.key" {
		t.Errorf("declared entry %+v", decl)
	}
	if len(decl.Scopes) != 1 || decl.Scopes[0].Canonical != filepath.Join(f.project, "secrets") {
		t.Errorf("declared entry's scope %+v, want the glob's literal base", decl.Scopes)
	}
	if !exact.BuiltIn || exact.Literal != ".env" || exact.Prefix {
		t.Errorf("built-in exact entry %+v", exact)
	}
	if !prefix.BuiltIn || prefix.Literal != ".env." || !prefix.Prefix || strings.Join(prefix.Except, ",") != ".env.example,.env.sample,.env.template,.env.dist" {
		t.Errorf("built-in prefix entry %+v", prefix)
	}
	if len(exact.Scopes) != 1 || exact.Scopes[0].Canonical != f.project || exact.Scopes[0].Spelling != f.project {
		t.Errorf("built-in scopes %+v, want the project once (the contract's directory is the working directory)", exact.Scopes)
	}

	sub := filepath.Join(f.project, "out")
	rt, _ = f.compile(c, WithCwd(sub))
	if got := rt.NameDeny[1].Scopes; len(got) != 1 || got[0].Canonical != f.project {
		t.Errorf("working directory %s beneath the contract's: scopes %+v, want the contract's directory alone", sub, got)
	}
	dep := filepath.Join(f.project, "node_modules", "x")
	rt, _ = f.compile(c, WithCwd(dep))
	if got := rt.NameDeny[1].Scopes; len(got) != 2 || got[1].Canonical != dep {
		t.Errorf("working directory %s beneath a dependency directory: scopes %+v, want both roots", dep, got)
	}
}

// TestLandlockOnlyReachPrintsNothingNew: a table no run of which can land at tier cgroup or bpflsm has no name
// entry, and its print says nothing new (ADR 0043 Consequences 11); one that can prints its entries, saying no tier
// applies them yet.
func TestLandlockOnlyReachPrintsNothingNew(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"out/\"]\n  deny_read: [\"secrets/*/api.key\"]\n")
	rt, _ := f.compile(c, WithTiers(backend.TierLandlock))
	if len(rt.NameDeny) != 0 || len(rt.NameExempt) != 0 {
		t.Fatalf("a landlock-only reach compiled name entries %+v", rt.NameDeny)
	}
	var buf bytes.Buffer
	if err := PrintRuleTable(&buf, rt); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "names ") {
		t.Errorf("a landlock-only table printed a names section:\n%s", buf.String())
	}
	rt, _ = f.compile(c)
	buf.Reset()
	if err := PrintRuleTable(&buf, rt); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"names     3 entries, beneath their scopes at tiers cgroup and bpflsm", ".env.*", "fs.deny_read[" + f.project + "/**/.env]", "fs.deny_read[secrets/*/api.key]"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("the print lacks %q:\n%s", want, buf.String())
		}
	}
}

// FuzzEnvNameRuleMatchesScan is ADR 0043 D2's tie between the built-in scan and its name entries: every name the
// scan matches, a built-in entry matches, and the entries match exactly the names whose `.env` or `.env.` part,
// folded, the scan would match with the rest as spelled (the exceptions compare as the scan spells them,
// Implementation notes C2). Both are made of one list of literals and exceptions (isEnvFile, BuiltInEnvEntries), so
// they cannot drift.
func FuzzEnvNameRuleMatchesScan(f *testing.F) {
	for _, s := range []string{".env", ".env.local", ".ENV", ".Env.Local", ".env.example", ".ENV.EXAMPLE", ".env.", ".envrc",
		"env", ".env.sample", ".env.dist.x", ".env.template", "x.env", ".env..", ".env/", "\x00.env"} {
		f.Add(s)
	}
	entries := BuiltInEnvEntries([]NameScope{{Canonical: "/p", Spelling: "/p"}})
	f.Fuzz(func(t *testing.T, name string) {
		checkEnvNameRule(t, entries, name)
	})
}

func checkEnvNameRule(t *testing.T, entries []NameDenyRule, name string) {
	t.Helper()
	match := false
	for i := range entries {
		match = match || entries[i].Matches(name)
	}
	if isEnvFile(name) && !match {
		t.Fatalf("the scan matches %q and no built-in name entry does", name)
	}
	n := min(len(name), len(builtInEnvPrefix))
	literalFolded := FoldName(name[:n]) + name[n:]
	if match != isEnvFile(literalFolded) {
		t.Fatalf("%q (literal part folded: %q): entries match=%v, the scan %v", name, literalFolded, match, isEnvFile(literalFolded))
	}
}

// TestEnvNameRuleMatchesScanCorpus runs FuzzEnvNameRuleMatchesScan's property over a fixed corpus of 10,000 names
// built from the alphabet the scan's literals use, so it holds on every run, not only under -fuzz.
func TestEnvNameRuleMatchesScanCorpus(t *testing.T) {
	entries := BuiltInEnvEntries([]NameScope{{Canonical: "/p", Spelling: "/p"}})
	r := rand.New(rand.NewSource(43))
	parts := []string{".", "env", "ENV", "Env", "example", "SAMPLE", "template", "dist", "local", "x", "", "e", "n", "v"}
	for range 10000 {
		var b strings.Builder
		for range 1 + r.Intn(5) {
			b.WriteString(parts[r.Intn(len(parts))])
		}
		checkEnvNameRule(t, entries, b.String())
	}
}

// TestNameEntryFolding: ASCII case folds, every other byte compares exactly (ADR 0043 D2), and the plane's key is a
// function of the folded literal and its form.
func TestNameEntryFolding(t *testing.T) {
	if FoldName(".Env.Local") != ".env.local" || FoldName("ÄBC") != "Äbc" {
		t.Errorf("FoldName: %q, %q", FoldName(".Env.Local"), FoldName("ÄBC"))
	}
	e := BuiltInEnvEntries(nil)[1]
	for name, want := range map[string]bool{".env.local": true, ".ENV.LOCAL": true, ".env.example": false, ".ENV.example": false,
		".env.Example": true, ".env.EXAMPLE": true, ".env": false, ".envx": false, ".env.": true} {
		if got := e.Matches(name); got != want {
			t.Errorf("prefix entry matches %q: %v, want %v", name, got, want)
		}
	}
	a, _ := NameKey(".ENV", false)
	b, _ := NameKey(".env", false)
	c, _ := NameKey(".env", true)
	if a != b || a == c || a>>63 != 0 || c>>63 != 0 || a&(1<<62) != 0 || c&(1<<62) == 0 || a == 0 {
		t.Errorf("NameKey: exact %#x / %#x, prefix %#x", a, b, c)
	}
	if _, ok := NameKey(strings.Repeat("x", 256), false); ok {
		t.Error("a 256-byte literal has a key")
	}
	if _, ok := NameKey("", true); ok {
		t.Error("an empty literal has a key")
	}
}

// TestNameClimb is ADR 0043 D4's scope test by path: a scope at any depth within the walk's bound covers, a
// dependency directory strictly between the scope and the file stops it, a scope that is itself named like one
// covers its own base, dependency names compare case-exactly, and a climb that passes 64 levels before it decides is
// unresolved (refused, fail closed).
func TestNameClimb(t *testing.T) {
	scopes := []NameScope{{Canonical: "/p"}, {Canonical: "/p/node_modules/q"}}
	deep := func(n int) string { return "/p/" + strings.Repeat("d/", n-1) + ".env" }
	for _, tc := range []struct {
		path               string
		covered, unresolve bool
		scope              int
	}{
		{"/p/.env", true, false, 0},
		{"/p/a/b/.env", true, false, 0},
		{"/p/node_modules/x/.env", false, false, -1},
		{"/p/node_modules/q/.env", true, false, 1},
		{"/p/node_modules/q/vendor/.env", false, false, -1},
		{"/p/Vendor/.env", true, false, 0},
		{"/x/.env", false, false, -1},
		{"/p", false, false, -1},
		{deep(64), true, false, 0},
		{deep(65), false, true, -1},
	} {
		scope, _, covered, unresolved := NameClimb(scopes, tc.path)
		if covered != tc.covered || unresolved != tc.unresolve || scope != tc.scope {
			t.Errorf("%s: scope %d covered %v unresolved %v; want %d %v %v", tc.path, scope, covered, unresolved, tc.scope, tc.covered, tc.unresolve)
		}
	}
}

// TestDependencyNamesCompareExactly: the dependency directories are the scan's list, compared byte for byte as the
// scan compares them (ADR 0043 Terms), so `Vendor/` is scanned and covered alike.
func TestDependencyNamesCompareExactly(t *testing.T) {
	if IsEnvSkipDir("Vendor") || IsEnvSkipDir("NODE_MODULES") || !IsEnvSkipDir("node_modules") || len(EnvSkipDirs) != 6 {
		t.Error("the dependency directories compare exactly, six of them")
	}
	for _, d := range EnvSkipDirs {
		if !IsEnvSkipDir(d) {
			t.Errorf("IsEnvSkipDir(%q) is false", d)
		}
	}
	f := newFixture(t)
	for _, d := range []string{"Vendor", "vendor"} {
		if err := os.MkdirAll(filepath.Join(f.project, d), 0o755); err != nil {
			t.Fatal(err)
		}
		f.file(filepath.Join(f.project, d, ".env"), "X=1", 0o600)
	}
	rt, _ := f.compile(f.load("version: 0\nname: a\ncommand: [python]\n"))
	if findFS(rt, FSDenyRead, filepath.Join(f.project, "Vendor", ".env")) == nil || findFS(rt, FSDenyRead, filepath.Join(f.project, "vendor", ".env")) != nil {
		t.Error("the scan does not compare its skip list exactly")
	}
}

// TestAskEntryNamingACoveredFileWarns: no fs.ask entry exempts a covered file (ADR 0043 D3), so compile says an ask of
// one is refused without a prompt.
func TestAskEntryNamingACoveredFileWarns(t *testing.T) {
	f := newFixture(t)
	f.file(filepath.Join(f.project, "config", "app.env"), "X=1", 0o600)
	f.file(filepath.Join(f.project, "config", ".env.local"), "X=1", 0o600)
	c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"out/\"]\n  ask: [\"config/.env.local\", \"config/app.env\"]\n")
	rt, ds, err := Compile(c, f.machine, f.opts()...)
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, render(ds))
	}
	n := 0
	for _, d := range ds {
		if d.Code == CodeUnenforced && strings.Contains(d.Message, "refused without a prompt") {
			n++
			if !strings.Contains(d.Message, "config/.env.local") {
				t.Errorf("the warning names another entry: %s", d.Message)
			}
		}
	}
	if n != 1 || len(rt.FSAsk) != 2 {
		t.Errorf("%d warnings, %d ask entries, want one warning for the covered file\n%s", n, len(rt.FSAsk), render(ds))
	}
}

// TestNameDenyScopeOnAliasingFilesystemWarns: a scope on a filesystem that gives one file other spellings than
// ASCII case (vfat's 8.3 aliases) is said so (ADR 0043 Residuals).
func TestNameDenyScopeOnAliasingFilesystemWarns(t *testing.T) {
	f := newFixture(t)
	mi := filepath.Join(f.root, "mountinfo")
	f.file(mi, "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n2 1 8:3 / "+f.project+" rw - vfat /dev/sda3 rw\n", 0o644)
	_, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"out/\"]\n"), WithMountInfo(mi))
	if !strings.Contains(render(ds), "on vfat, which gives one file other spellings") {
		t.Errorf("no warning for a scope on vfat:\n%s", render(ds))
	}
}

// TestCompactionFactsBoundedByTheScanBudget: the casefold facts are read inside the .env scan's own time limit (I6);
// past it no directory is opened, and every row keeps its unknown fact, which keeps the row.
func TestCompactionFactsBoundedByTheScanBudget(t *testing.T) {
	f := newFixture(t)
	k := &compiler{rt: &RuleTable{NameDeny: BuiltInEnvEntries([]NameScope{{Canonical: f.project}})}}
	b := &fsBuilder{k: k, envEnd: time.Now().Add(-time.Second)}
	for i := 0; i <= NameCompactAt; i++ {
		b.rules = append(b.rules, FSRule{Kind: FSDenyRead, Path: filepath.Join(f.project, ".env"), Resolved: filepath.Join(f.project, ".env"), Regular: true, Filesystem: "ext4"})
	}
	b.compactionFacts()
	for _, r := range b.rules {
		if r.DirCaseExact {
			t.Fatal("a casefold fact was read past the scan's time limit")
		}
	}
	b.envEnd = time.Now().Add(time.Minute)
	b.compactionFacts()
	if want := dirCaseExact(f.project); b.rules[0].DirCaseExact != want {
		t.Errorf("inside the limit: DirCaseExact = %v, the directory says %v", b.rules[0].DirCaseExact, want)
	}
}

// TestNameDenyRuleNames is ADR 0043 D8's naming: a declared glob by its own name, the built-in by a label naming the
// scope that decided, which `**` keeps apart from any declared entry's name.
func TestNameDenyRuleNames(t *testing.T) {
	es := BuiltInEnvEntries([]NameScope{{Canonical: "/p", Spelling: "/p"}, {Canonical: "/", Spelling: "/"}})
	if got := es[0].RuleName(0); got != "fs.deny_read[/p/**/.env]" {
		t.Errorf("exact label %q", got)
	}
	if got := es[1].RuleName(1); got != "fs.deny_read[/**/.env.*]" {
		t.Errorf("prefix label at / %q", got)
	}
	d := NameDenyRule{Literal: "api.key", Raw: "secrets/*/api.key"}
	if got := d.RuleName(0); got != "fs.deny_read[secrets/*/api.key]" {
		t.Errorf("declared name %q", got)
	}
}

// TestNameDenyZeroMatchGlob: a whole glob that matches nothing now still gets its name entry, since files created
// later are what the entry is for; one whose base does not exist gets none.
func TestNameDenyZeroMatchGlob(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  deny_read: [\"config/*/token.json\", \"nowhere/*/token.json\"]\n")
	rt, ds := f.compile(c)
	var got []string
	for _, e := range rt.NameDeny {
		if !e.BuiltIn {
			got = append(got, e.Raw)
		}
	}
	if strings.Join(got, " ") != "config/*/token.json" {
		t.Errorf("declared name entries %v, want the glob whose base exists\n%s", got, render(ds))
	}
}

// TestWriteEntryDropsBuiltInEnv is ADR 0043 D3's compile change: a write entry of the top-level contract file at an
// existing .env file the built-in list holds drops the file from the list, with a warning naming both, where it was
// a contradiction; it is an exemption of the name entries, and not a redundant entry.
func TestWriteEntryDropsBuiltInEnv(t *testing.T) {
	f := newFixture(t)
	env := filepath.Join(f.project, ".env")
	rt, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"out/\", \".env\"]\n"))
	if findFS(rt, FSDenyRead, env) != nil {
		t.Errorf("%s stayed in the built-in list", env)
	}
	warned := false
	for _, d := range ds {
		warned = warned || (d.Code == CodeUnenforced && strings.Contains(d.Message, env) && strings.Contains(d.Message, "leaves that list"))
		if d.Code == CodeRedundantRule {
			t.Errorf("redundant-rule on the exemption: %s", d.Message)
		}
	}
	if !warned {
		t.Errorf("no warning naming the dropped file:\n%s", render(ds))
	}
	if len(rt.NameExempt) != 1 || rt.NameExempt[0].Parent != f.project || rt.NameExempt[0].Name != ".env" ||
		rt.FS[rt.NameExempt[0].Write].Path != env {
		t.Errorf("NameExempt = %+v, want the write entry at %s", rt.NameExempt, env)
	}
}

// TestSymlinkedWriteEntryExemptsItsTarget: D3 takes the exemption's place from the write entry's resolved path, so a
// declared link to a .env file exempts the target's name in the target's directory, and the target leaves the built-in
// list, not the link's spelling.
func TestSymlinkedWriteEntryExemptsItsTarget(t *testing.T) {
	f := newFixture(t)
	target := filepath.Join(f.project, "config", ".env.local")
	f.file(target, "X=1", 0o600)
	if err := os.Symlink(target, filepath.Join(f.project, "lnk")); err != nil {
		t.Fatal(err)
	}
	rt, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"out/\", \"lnk\"]\n"))
	if findFS(rt, FSDenyRead, target) != nil {
		t.Errorf("%s stayed in the built-in list\n%s", target, render(ds))
	}
	if len(rt.NameExempt) != 1 || rt.NameExempt[0].Parent != filepath.Join(f.project, "config") || rt.NameExempt[0].Name != ".env.local" {
		t.Errorf("NameExempt = %+v, want the link's target", rt.NameExempt)
	}
}

// TestProfileWriteEntryKeepsTheContradiction: a write entry a profile declares at a built-in .env file stays the
// contradiction it was (ADR 0043 D3: a profile cannot remove a built-in protection), and a declared deny_read at a
// write entry's path stays one too.
func TestProfileWriteEntryKeepsTheContradiction(t *testing.T) {
	f := newFixture(t)
	env := filepath.Join(f.project, ".env")
	src := writeProfile(t, f, "envw", "fs:\n  write: [\""+env+"\"]\n")
	path := filepath.Join(f.project, "agent.yaml")
	f.file(path, "version: 0\nname: a\nextends: envw\ncommand: [python]\nfs:\n  write: [\"out/\"]\n", 0o644)
	c, ds, err := Load(path, src)
	if err != nil {
		t.Fatalf("load: %v\n%s", err, render(ds))
	}
	if _, cds, err := Compile(c, f.machine, f.opts()...); err == nil || !hasCode(cds, CodeContradiction) {
		t.Errorf("a profile's write entry at %s compiled: %v\n%s", env, err, render(cds))
	}
	c = f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"out/\", \"secrets/key.pem\"]\n  deny_read: [\"secrets/key.pem\"]\n")
	if _, cds, err := Compile(c, f.machine, f.opts()...); err == nil || !hasCode(cds, CodeContradiction) {
		t.Errorf("a declared deny_read at a write entry's path compiled: %v\n%s", err, render(cds))
	}
}

// TestMissingWriteEntryMatchingANameWarns: a write entry that does not exist is a directory run creates, which no
// name entry decides; when its name would match one, compile says how to let the agent use such a file.
func TestMissingWriteEntryMatchingANameWarns(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"out/\", \".env.test\"]\n")
	_, ds := f.compile(c)
	if !strings.Contains(render(ds), "to let the agent use a .env.test file, create it before the run and name it in fs.write") {
		t.Errorf("no warning for the missing .env.test write entry:\n%s", render(ds))
	}
}

// TestCompactionFactsRecorded: compile records the facts ADR 0043 D6 compacts a covered row on from the Lstat it
// already makes: a regular file, its link count, a file that is itself a mount point; and the directory's casefold
// flag only once the table passes NameCompactAt keyed paths.
func TestCompactionFactsRecorded(t *testing.T) {
	f := newFixture(t)
	env := filepath.Join(f.project, ".env")
	linked := filepath.Join(f.project, "config", ".env.l")
	f.file(linked, "X=1", 0o600)
	if err := os.Link(linked, filepath.Join(f.project, "out", "other")); err != nil {
		t.Fatal(err)
	}
	mi := filepath.Join(f.root, "mountinfo")
	f.file(mi, "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n2 1 8:1 /x "+env+" rw - ext4 /dev/sda1 rw\n", 0o644)
	rt, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"out/\"]\n"), WithMountInfo(mi))
	e, l := findFS(rt, FSDenyRead, env), findFS(rt, FSDenyRead, linked)
	if e == nil || l == nil {
		t.Fatalf("missing built-in entries\n%s", render(ds))
	}
	if !e.Regular || e.Nlink != 1 || !e.FileMountPoint || e.IsMountPoint {
		t.Errorf("%s: %+v, want a regular file of one link that is a file mount point", env, *e)
	}
	if !l.Regular || l.Nlink != 2 || l.FileMountPoint {
		t.Errorf("%s: %+v, want two links", linked, *l)
	}
	if e.DirCaseExact || l.DirCaseExact {
		t.Error("the casefold flag was read for a table under NameCompactAt keyed paths")
	}
}

// TestCompactionFactsReadPastTheThreshold: past NameCompactAt keyed paths, the casefold flag is read per directory
// where the filesystem has one (ext4, f2fs, tmpfs), and recorded case-exact when the flag is clear.
func TestCompactionFactsReadPastTheThreshold(t *testing.T) {
	f := newFixture(t)
	many := filepath.Join(f.project, "many")
	for i := range NameCompactAt {
		d := filepath.Join(many, strconv.Itoa(i))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		f.file(filepath.Join(d, ".env"), "X=1", 0o600)
	}
	rt, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"out/\"]\n"))
	r := findFS(rt, FSDenyRead, filepath.Join(many, "7", ".env"))
	if r == nil {
		t.Fatalf("missing a scanned .env\n%s", render(ds))
	}
	switch r.Filesystem {
	case "ext4", "f2fs", "tmpfs":
	default:
		t.Skipf("the fixture lies on %q, which has no casefold flag to read", r.Filesystem)
	}
	if want := dirCaseExact(filepath.Dir(r.Canonical())); r.DirCaseExact != want || !want {
		t.Errorf("DirCaseExact = %v, the directory's flags say %v (a casefolded test directory?)", r.DirCaseExact, want)
	}
}

// TestNameDenyCaps is ADR 0043's allocation: the built-in entries first, each entry with the exemptions that apply
// to it, and an entry that does not fit whole left out with the cap it passes, while an exemption is allotted only
// with an entry it applies to.
func TestNameDenyCaps(t *testing.T) {
	p := []NameScope{{Canonical: "/p", Spelling: "/p"}}
	cands := BuiltInEnvEntries(p)
	var exempts []NameExemptRule
	for i := range 7 {
		exempts = append(exempts, NameExemptRule{Parent: "/p/a" + strconv.Itoa(i), Name: ".env", Write: i})
	}
	exempts = append(exempts, NameExemptRule{Parent: "/q", Name: ".env", Write: 9}) // covered by no entry
	cands = append(cands, NameDenyRule{Literal: "token.json", Raw: "/r/*/token.json", Scopes: []NameScope{{Canonical: "/r"}}})
	kept, keptX, left := FitNameEntries(cands, exempts)
	if len(kept) != 2 || !kept[0].BuiltIn || !kept[1].BuiltIn {
		t.Fatalf("kept %+v, want the built-in pair", kept)
	}
	if len(keptX) != 7 {
		t.Errorf("kept %d exemptions, want the seven beneath /p", len(keptX))
	}
	if len(left) != 1 || left[0].Entry.Literal != "token.json" || !strings.Contains(left[0].Why, "8 scope directories") {
		t.Errorf("left %+v, want the declared entry out over the scope cap", left)
	}

	// Rows: the built-in pair takes six (the exact and prefix rows and the four exception rows); 58 declared
	// literals more fill the slot, the 59th is out.
	cands = BuiltInEnvEntries(p)
	for i := range 59 {
		cands = append(cands, NameDenyRule{Literal: "rowsname" + strconv.Itoa(i), Raw: "x", Scopes: p}) // one lead, "rowsname"
	}
	kept, _, left = FitNameEntries(cands, nil)
	if len(kept) != 2+58 || len(left) != 1 || !strings.Contains(left[0].Why, "64 name rows") {
		t.Errorf("%d kept, left %+v; want the 59th declared literal out over the row cap", len(kept), left)
	}

	// Prefix lengths, leads and arms.
	cands = nil
	for i := range 5 {
		cands = append(cands, NameDenyRule{Literal: strings.Repeat("k", 3+i), Prefix: true, Raw: "x", Scopes: p})
	}
	if _, _, left = FitNameEntries(cands, nil); len(left) != 1 || !strings.Contains(left[0].Why, "4 prefix lengths") {
		t.Errorf("five prefix lengths: left %+v", left)
	}
	cands = nil
	for i := range 9 {
		cands = append(cands, NameDenyRule{Literal: "lead" + strconv.Itoa(i), Raw: "x", Scopes: p})
	}
	if _, _, left = FitNameEntries(cands, nil); len(left) != 1 || !strings.Contains(left[0].Why, "8 name leads") {
		t.Errorf("nine leads: left %+v", left)
	}
	cands = nil
	for range 9 {
		cands = append(cands, NameDenyRule{Literal: "same.json", Raw: "x", Scopes: p})
	}
	if _, _, left = FitNameEntries(cands, nil); len(left) != 1 || !strings.Contains(left[0].Why, "8 arms") {
		t.Errorf("nine entries on one row: left %+v", left)
	}
	// Entries: the tag names 64; eight literals share a lead, eight arms a row, so 65 entries fit every other cap.
	cands = nil
	for i := range 65 {
		cands = append(cands, NameDenyRule{Literal: "rowsname" + strconv.Itoa(i/8), Raw: "x" + strconv.Itoa(i), Scopes: p})
	}
	if kept, _, left := FitNameEntries(cands, nil); len(kept) != 64 || len(left) != 1 || !strings.Contains(left[0].Why, "64 name entries") {
		t.Errorf("65 entries: %d kept, left %+v", len(kept), left)
	}
	if got := MinimalNameLeads(BuiltInEnvEntries(p)); strings.Join(got, ",") != ".env" {
		t.Errorf("the built-in pair's leads %v, want .env alone", got)
	}
}

// TestNameDenyKeyCollisionLeavesTheLaterEntryOut: an entry whose name key equals a row already allotted to another
// literal is left out whole, never written over that row (ADR 0043 D9). No pair of real literals is known to collide,
// so the test forces one through the key function.
func TestNameDenyKeyCollisionLeavesTheLaterEntryOut(t *testing.T) {
	was := nameKeyOf
	t.Cleanup(func() { nameKeyOf = was })
	nameKeyOf = func(literal string, prefix bool) (uint64, bool) {
		if literal == "evil.json" {
			return NameKey(".env", false)
		}
		return NameKey(literal, prefix)
	}
	p := []NameScope{{Canonical: "/p"}}
	cands := append(BuiltInEnvEntries(p), NameDenyRule{Literal: "evil.json", Raw: "x", Scopes: p})
	kept, _, left := FitNameEntries(cands, nil)
	if len(kept) != 2 || len(left) != 1 || !strings.Contains(left[0].Why, "collides with the row of .env") {
		t.Errorf("kept %d, left %+v", len(kept), left)
	}
}

// TestNameEntriesLeftOutAreRecorded: a name-eligible entry the caps leave out is recorded in the table
// (RuleTable.NameLeftOut), one per unenforced warning, so the run's fs.deny_read.created_later reads false (ADR 0043
// Terms, D7: "none left out by a cap or a collision"); a table whose entries all fit records none and is whole. Ten
// declared globs beneath ten directories pass the plane's 8 scopes, so the later ones are left out.
func TestNameEntriesLeftOutAreRecorded(t *testing.T) {
	f := newFixture(t)
	var globs []string
	for i := range 10 {
		dir := filepath.Join(f.project, "w", "d"+strconv.Itoa(i), "x")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		f.file(filepath.Join(dir, "secret.txt"), "s", 0o600)
		globs = append(globs, strconv.Quote("w/d"+strconv.Itoa(i)+"/*/secret.txt"))
	}
	c := f.load("version: 0\nname: a\ncommand: [python]\ntier: bpflsm\nfs:\n  write: [\"./w\"]\n  deny_read: [" +
		strings.Join(globs, ", ") + "]\n")
	rt, ds := f.compile(c)
	warned := 0
	for _, d := range ds {
		if strings.Contains(d.Message, "has no name entry") {
			warned++
		}
	}
	if len(rt.NameLeftOut) == 0 || len(rt.NameLeftOut) != warned || rt.NameEntriesWhole() {
		t.Fatalf("%d left out, %d warned, whole %v; want every left-out entry recorded and the table not whole\n%s",
			len(rt.NameLeftOut), warned, rt.NameEntriesWhole(), render(ds))
	}
	if len(rt.NameDeny) == 0 {
		t.Fatalf("no name entry kept\n%s", render(ds))
	}
	for _, l := range rt.NameLeftOut {
		if l.Entry.Literal != "secret.txt" || !strings.Contains(l.Why, "8 scope directories") {
			t.Errorf("left out %q (%s), want a declared secret.txt glob over the scope cap", l.Entry.Raw, l.Why)
		}
		// Its glob warning still says later files are not covered (TestNameGlobWarningSaysLaterFilesAreCovered).
		for _, d := range ds {
			if strings.Contains(d.Message, strconv.Quote(l.Entry.Raw)+" covers") && !strings.Contains(d.Message, "files created later are not covered") {
				t.Errorf("the left-out glob's warning claims later files: %q", d.Message)
			}
		}
	}

	g := newFixture(t)
	whole, _ := g.compile(g.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"out/\"]\n"))
	if len(whole.NameDeny) == 0 || len(whole.NameLeftOut) != 0 || !whole.NameEntriesWhole() {
		t.Errorf("the built-in pair alone: %d entries, %d left out, whole %v", len(whole.NameDeny), len(whole.NameLeftOut),
			whole.NameEntriesWhole())
	}
}

// TestNameGlobWarningSaysLaterFilesAreCovered: a deny_read glob that keeps its name entry covers
// files created later at tiers cgroup and bpflsm, so its glob warning says so and that tier landlock does not, where
// compile's names section says the same; a glob with no name entry (its final component a pattern), or one the caps
// left out, keeps the old text.
func TestNameGlobWarningSaysLaterFilesAreCovered(t *testing.T) {
	f := newFixture(t)
	for _, d := range []string{"config/a", "config/b", "empty", "data"} {
		if err := os.MkdirAll(filepath.Join(f.project, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.file(filepath.Join(f.project, "config", "a", "token.json"), "t", 0o600)
	f.file(filepath.Join(f.project, "data", "x.key"), "k", 0o600)
	c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  deny_read: [\"config/*/token.json\", \"empty/*/token.json\", \"data/*.key\"]\n")
	rt, ds := f.compile(c)
	glob := map[string]string{}
	for _, d := range ds {
		for _, raw := range []string{"config/*/token.json", "empty/*/token.json", "data/*.key"} {
			if strings.Contains(d.Message, strconv.Quote(raw)) && strings.Contains(d.Message, "created later") {
				glob[raw] = d.Message
			}
		}
	}
	later := "files created later are covered at tiers cgroup and bpflsm by its name entry, not at tier landlock"
	if m := glob["config/*/token.json"]; !strings.Contains(m, "covers the 1 file(s) that exist now; "+later) {
		t.Errorf("the kept name glob's warning: %q\n%s", m, render(ds))
	}
	if m := glob["empty/*/token.json"]; !strings.Contains(m, "matches nothing now; "+later) {
		t.Errorf("the kept name glob that matches nothing: %q\n%s", m, render(ds))
	}
	if m := glob["data/*.key"]; !strings.Contains(m, "files created later are not covered") {
		t.Errorf("a glob with no name entry: %q\n%s", m, render(ds))
	}
	if len(rt.NameDeny) < 2 {
		t.Fatalf("%d name entries, want the two declared ones beside the built-in pair", len(rt.NameDeny))
	}
}

// TestContractHashIgnoresNameDeny: name entries are compile output, never contract input (ADR 0043 Terms), so a
// .env file more in the project changes NameDeny's facts and not contract_hash.
func TestContractHashIgnoresNameDeny(t *testing.T) {
	f := newFixture(t)
	c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"out/\"]\n")
	a, _ := f.compile(c)
	f.file(filepath.Join(f.project, "config", ".env.late"), "X=1", 0o600)
	b, _ := f.compile(c)
	if a.Hash != b.Hash || len(a.NameDeny) == 0 {
		t.Errorf("hash changed with the .env files, or no name entries: %x %x %d", a.Hash, b.Hash, len(a.NameDeny))
	}
}

// TestBindExposedScope is ADR 0043 D6 (f)'s mount fact: a directory at or beneath a scope mounted outside it exposes
// the scope, one mounted inside it or another device's mount does not.
func TestBindExposedScope(t *testing.T) {
	mt := &mountTable{probed: true}
	for _, line := range []string{
		"1 0 8:1 / / rw - ext4 /dev/sda1 rw",
		"2 1 8:2 / /home rw - ext4 /dev/sda2 rw",
		"3 1 8:2 /u/p/sub /mnt/x rw - ext4 /dev/sda2 rw",
		"4 1 8:2 /u/p/in /home/u/p/in2 rw - ext4 /dev/sda2 rw",
		"5 1 0:30 / /tmp rw - tmpfs tmpfs rw",
	} {
		m, ok := parseMountLine(line)
		if !ok {
			t.Fatalf("parse %q", line)
		}
		mt.mounts = append(mt.mounts, m)
	}
	// lookup takes the longest mount point first, as loadMountTable sorts them.
	mt.mounts = []mount{mt.mounts[3], mt.mounts[2], mt.mounts[1], mt.mounts[4], mt.mounts[0]}
	for scope, want := range map[string]bool{"/home/u/p": true, "/home/u/p/sub": true, "/home/u/q": false, "/tmp/w": false, "/home/u/p/in": true} {
		if got := mt.bindExposed(scope); got != want {
			t.Errorf("bindExposed(%s) = %v, want %v", scope, got, want)
		}
	}
}

// TestBindExposedUnknownPlace at ADR 0043 D6 (f): a table that
// shows no mount holding the scope (a chroot's, which skips the mount above a root that is no mount point) cannot say
// where the scope lies in its filesystem, and one that cannot be read shows nothing, so neither can show that no bind
// exposes it: the scope counts as exposed, and its rows are kept. Only a disabled probe (WithMountInfo("")) has no
// mount facts by the caller's choice.
func TestBindExposedUnknownPlace(t *testing.T) {
	dir := t.TempDir()
	unheld := filepath.Join(dir, "mountinfo")
	if err := os.WriteFile(unheld, []byte("3 1 8:2 /u/p/sub /mnt/x rw - ext4 /dev/sda2 rw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		path string
		want bool
	}{
		"a table without the scope's mount": {unheld, true},
		"an unreadable table":               {filepath.Join(dir, "missing"), true},
		"the probe disabled":                {"", false},
	} {
		mt, _ := loadMountTable(c.path)
		if got := mt.bindExposed("/home/u/q"); got != c.want {
			t.Errorf("%s: bindExposed = %v, want %v", name, got, c.want)
		}
	}
}
