// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// askReadContract is a tier-landlock contract with the given fs: lines (each a full YAML line under fs:).
func askReadContract(fsLines ...string) string {
	return "version: 0\nname: ask-read\ncommand: [\"python\"]\ntier: landlock\nexec:\n  allow: [\"python\"]\nfs:\n" +
		strings.Join(fsLines, "\n") + "\n"
}

// errorsWith is the error diagnostics of ds whose message contains every part.
func errorsWith(ds []Diagnostic, code string, parts ...string) []Diagnostic {
	var out []Diagnostic
	for _, d := range ds {
		if d.Severity != SeverityError || d.Code != code {
			continue
		}
		all := true
		for _, p := range parts {
			all = all && strings.Contains(d.Message, p)
		}
		if all {
			out = append(out, d)
		}
	}
	return out
}

// warningsWith is errorsWith for warnings.
func warningsWith(ds []Diagnostic, code string, parts ...string) []Diagnostic {
	var out []Diagnostic
	for _, d := range ds {
		if d.Severity != SeverityWarning || d.Code != code {
			continue
		}
		all := true
		for _, p := range parts {
			all = all && strings.Contains(d.Message, p)
		}
		if all {
			out = append(out, d)
		}
	}
	return out
}

// compileErr compiles c with the fixture's options and returns the diagnostics and the error.
func (f *fixture) compileErr(c *Contract, extra ...CompileOption) (*RuleTable, []Diagnostic, error) {
	f.t.Helper()
	return Compile(c, f.machine, f.opts(extra...)...)
}

// An fs.ask_read entry compiles as a deny_read entry marked AskRead: Evaluate refuses a read beneath it at tier
// landlock, naming the entry fs.ask_read[...], the ask configuration is compiled so the broker starts, and the
// contract hash carries the key.
func TestAskReadCompilesAsAHeldDenyRead(t *testing.T) {
	f := newFixture(t)
	secretDir := filepath.Join(f.root, "vault")
	if err := os.MkdirAll(secretDir, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(secretDir, "token")
	f.file(secret, "real", 0o600)
	c := f.load(askReadContract(`  write: ["out/"]`, `  ask_read: ["`+secret+`"]`))
	rt, ds := f.compile(c)
	r := findFS(rt, FSDenyRead, secret)
	if r == nil || !r.AskRead || r.Unenforced || r.RuleName() != "fs.ask_read["+secret+"]" {
		t.Fatalf("ask_read entry %+v; diagnostics %s", r, render(ds))
	}
	if !rt.HasAskRead() || len(rt.AskReadRules()) != 1 {
		t.Fatalf("HasAskRead %v rules %d", rt.HasAskRead(), len(rt.AskReadRules()))
	}
	if rt.AskConfig == nil || rt.AskConfig.MaxPending != 64 {
		t.Fatalf("ask configuration not compiled for fs.ask_read alone: %+v", rt.AskConfig)
	}
	got := rt.Evaluate(Action{Kind: ActionFSRead, Path: secret}, backend.TierLandlock)
	if got.Verdict != VerdictRefused || got.Rule != "fs.ask_read["+secret+"]" {
		t.Fatalf("Evaluate read = %+v: a held read is refused until a person answers it, under its own rule", got)
	}
	if other := rt.Evaluate(Action{Kind: ActionFSRead, Path: filepath.Join(f.root, "elsewhere")}, backend.TierLandlock); other.Verdict != VerdictAllow {
		t.Fatalf("a read outside the entry = %+v, want allow", other)
	}
	canon, err := c.Canonical()
	if err != nil || !strings.Contains(string(canon), "ask_read:") {
		t.Fatalf("canonical form lost fs.ask_read: %v\n%s", err, canon)
	}
	withKey, err := c.Hash()
	if err != nil {
		t.Fatal(err)
	}
	without, err := f.load(askReadContract(`  write: ["out/"]`)).Hash()
	if err != nil || withKey == without {
		t.Fatalf("contract_hash does not cover fs.ask_read (%v)", err)
	}
	for _, own := range []string{filepath.Join(f.home, ".tego"), f.ledger, hostStateDir} {
		found := false
		for _, s := range rt.OwnState {
			found = found || s == own
		}
		if !found {
			t.Errorf("OwnState %v lacks %s", rt.OwnState, own)
		}
	}
}

// fs.ask_read holds a read at tier landlock only: a contract pinned to a root tier, or left to a machine whose
// highest tier is one, is refused rather than compiled into denies that never ask.
func TestAskReadRefusedAtTiersThatCannotHoldARead(t *testing.T) {
	f := newFixture(t)
	secret := filepath.Join(f.root, "token")
	f.file(secret, "real", 0o600)
	for _, tc := range []struct {
		name, tier string
		opts       []CompileOption
		ok         bool
	}{
		{"pinned cgroup", "tier: cgroup", nil, false},
		{"pinned bpflsm", "tier: bpflsm", nil, false},
		{"auto on a machine that builds cgroup", "tier: auto", []CompileOption{WithTiers(backend.TierLandlock, backend.TierCgroup)}, false},
		{"auto on a build with landlock alone", "tier: auto", []CompileOption{WithTiers(backend.TierLandlock)}, true},
		{"pinned landlock", "tier: landlock", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			y := strings.Replace(askReadContract(`  ask_read: ["`+secret+`"]`), "tier: landlock", tc.tier, 1)
			c := f.load(y)
			_, ds, err := f.compileErr(c, tc.opts...)
			refused := errorsWith(ds, CodeUnenforced, "fs.ask_read holds a read for a person at tier landlock only")
			if tc.ok {
				if err != nil || len(refused) != 0 {
					t.Fatalf("want compiled: %v\n%s", err, render(ds))
				}
				return
			}
			if err == nil || len(refused) != 1 {
				t.Fatalf("want the tier refused: %v\n%s", err, render(ds))
			}
		})
	}
	// An observe run cannot ask at all, ask_read included: no contract pins observe (it is --observe), and the
	// runtime refuses an ask table with an observe backend (internal/runtime TestAskReadRefusedWithoutTierLandlock).
}

// The conflicts fs.ask_read has with the other fs entries, each decided at compile.
func TestAskReadConflictsAreDecidedAtCompile(t *testing.T) {
	f := newFixture(t)
	vault := filepath.Join(f.root, "vault")
	inner := filepath.Join(vault, "inner")
	for _, d := range []string{inner, filepath.Join(f.home, ".tego", "runs")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.file(filepath.Join(vault, "token"), "real", 0o600)
	f.file(filepath.Join(inner, "deeper"), "real", 0o600)
	f.file(filepath.Join(f.home, ".aws", "credentials"), "aws", 0o600)
	f.file(filepath.Join(f.home, ".tego", "config.yaml"), "version: 0\n", 0o600)
	f.file(filepath.Join(f.project, "out", "result"), "x", 0o600)
	for _, tc := range []struct {
		name  string
		lines []string
		code  string   // the error's code, "" for a contract that compiles
		parts []string // in the error's message
	}{
		{"same path as a declared deny_read", []string{`  deny_read: ["` + vault + `"]`, `  ask_read: ["` + vault + `"]`}, CodeContradiction, []string{"a deny is never lifted by an ask"}},
		{"inside a declared deny_read", []string{`  deny_read: ["` + vault + `"]`, `  ask_read: ["` + inner + `"]`}, CodeContradiction, []string{"a deny is never lifted by an ask"}},
		{"inside a write entry", []string{`  write: ["out/"]`, `  ask_read: ["out/result"]`}, CodeUnenforced, []string{"lies inside write entry", "without asking"}},
		{"is a write entry", []string{`  write: ["` + vault + `"]`, `  ask_read: ["` + vault + `"]`}, CodeUnenforced, []string{"lies inside write entry"}},
		{"inside tego's own directory", []string{`  ask_read: ["` + filepath.Join(f.home, ".tego", "config.yaml") + `"]`}, CodeContradiction, []string{"tego's own state"}},
		{"the ledger root", []string{`  ask_read: ["` + f.ledger + `"]`}, CodeContradiction, []string{"tego's own state"}},
		{"an fs.ask scope inside it", []string{`  ask: ["` + inner + `"]`, `  ask_read: ["` + vault + `"]`}, CodeContradiction, []string{"would never ask"}},
		{"the whole filesystem", []string{`  ask_read: ["/"]`}, CodeSchema, []string{"holds the whole filesystem"}},
		{"a missing path", []string{`  ask_read: ["` + filepath.Join(vault, "absent") + `"]`}, CodePathMissing, []string{"does not exist"}},
		{"an exec directory over it", []string{`  ask_read: ["` + filepath.Join(f.bin, "not-exec") + `"]`}, CodeUnenforced, []string{"exec.allow directory"}},
		{"an exec grant inside it", []string{`  ask_read: ["` + f.bin + `"]`}, CodeUnenforced, []string{"holds exec grant"}},
		{"a deny_read nested inside it", []string{`  deny_read: ["` + inner + `"]`, `  ask_read: ["` + vault + `"]`}, "", nil},
		{"a write entry nested inside it", []string{`  write: ["` + inner + `"]`, `  ask_read: ["` + vault + `"]`}, "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			y := askReadContract(tc.lines...)
			if tc.name == "an exec directory over it" {
				y = strings.Replace(y, `allow: ["python"]`, `allow: ["python", "`+f.bin+`/"]`, 1)
			}
			c := f.load(y)
			rt, ds, err := f.compileErr(c)
			if tc.code == "" {
				if err != nil {
					t.Fatalf("want compiled: %v\n%s", err, render(ds))
				}
				if len(rt.AskReadRules()) != 1 {
					t.Fatalf("ask_read rules %+v", rt.AskReadRules())
				}
				return
			}
			if err == nil || len(errorsWith(ds, tc.code, tc.parts...)) == 0 {
				t.Fatalf("want a %s error naming %q: %v\n%s", tc.code, tc.parts, err, render(ds))
			}
		})
	}
	// A deny_read nested in an ask_read entry is nearer, and refuses; the rest is held.
	c := f.load(askReadContract(`  deny_read: ["`+inner+`"]`, `  ask_read: ["`+vault+`"]`))
	rt, _ := f.compile(c)
	if got := rt.Evaluate(Action{Kind: ActionFSRead, Path: filepath.Join(inner, "deeper")}, backend.TierLandlock); got.Rule != "fs.deny_read["+inner+"]" {
		t.Fatalf("nested deny_read read = %+v", got)
	}
	if got := rt.Evaluate(Action{Kind: ActionFSRead, Path: filepath.Join(vault, "token")}, backend.TierLandlock); got.Rule != "fs.ask_read["+vault+"]" {
		t.Fatalf("held read = %+v", got)
	}
	// A glob is refused by the schema at Load, as fs.ask's is.
	path := filepath.Join(f.project, "agent.yaml")
	f.file(path, askReadContract(`  ask_read: ["`+vault+`/*"]`), 0o644)
	if _, ds, err := Load(path, f.profiles()); err == nil || !strings.Contains(render(ds), "fs.ask_read requires literal paths") {
		t.Fatalf("glob: %v\n%s", err, render(ds))
	}
}

// An entry of the top-level contract at a built-in deny_read entry's path replaces it, and one beneath a built-in
// entry is nearer than it: the person who wrote the contract chose to be asked for that secret, and compile says so.
// From a profile either is a contradiction.
func TestAskReadAndTheBuiltInList(t *testing.T) {
	f := newFixture(t)
	creds := filepath.Join(f.home, ".aws", "credentials")
	f.file(creds, "aws", 0o600)
	netrc := filepath.Join(f.home, ".netrc")

	c := f.load(askReadContract(`  ask_read: ["~/.netrc", "~/.aws/credentials"]`))
	rt, ds := f.compile(c)
	if r := findFS(rt, FSDenyRead, netrc); r == nil || !r.AskRead {
		t.Fatalf("~/.netrc entry %+v: the ask_read entry replaces the built-in one", r)
	}
	for _, r := range rt.FS {
		if r.Kind == FSDenyRead && r.BuiltIn && r.Path == netrc {
			t.Fatalf("the built-in ~/.netrc entry stayed beside the ask_read one: %+v", r)
		}
	}
	if len(warningsWith(ds, CodeUnenforced, "relaxes the built-in deny_read entry "+netrc+", which it replaces", "run_start ask_read_relaxes")) != 1 {
		t.Fatalf("no warning names the replaced built-in entry:\n%s", render(ds))
	}
	aws := filepath.Join(f.home, ".aws")
	if len(warningsWith(ds, CodeUnenforced, "relaxes the built-in deny_read entry "+aws+", inside which it lies", "run_start ask_read_relaxes")) != 1 {
		t.Fatalf("no warning names the enclosing built-in entry:\n%s", render(ds))
	}
	// ADR 0057 D4: the table names each relaxed built-in entry, for run_start.
	want := []AskReadRelax{{Rule: "fs.ask_read[~/.netrc]", BuiltIn: netrc, How: AskReadReplaces}, {Rule: "fs.ask_read[~/.aws/credentials]", BuiltIn: aws, How: AskReadInside}}
	if !slices.Equal(rt.AskReadRelaxes, want) {
		t.Fatalf("AskReadRelaxes = %+v, want %+v", rt.AskReadRelaxes, want)
	}
	// An entry that relaxes nothing names nothing.
	plain := filepath.Join(f.project, "vault")
	if err := os.MkdirAll(plain, 0o700); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(plain, "token"), "t", 0o600)
	if rt2, _ := f.compile(f.load(askReadContract(`  ask_read: ["` + plain + `"]`))); len(rt2.AskReadRelaxes) != 0 {
		t.Fatalf("an entry outside the built-in list relaxed %+v", rt2.AskReadRelaxes)
	}
	if got := rt.Evaluate(Action{Kind: ActionFSRead, Path: creds}, backend.TierLandlock); got.Rule != "fs.ask_read[~/.aws/credentials]" {
		t.Fatalf("held credential read = %+v", got)
	}
	if got := rt.Evaluate(Action{Kind: ActionFSRead, Path: filepath.Join(f.home, ".aws", "config")}, backend.TierLandlock); got.Verdict != VerdictRefused || !strings.HasPrefix(got.Rule, "fs.deny_read[") {
		t.Fatalf("the rest of ~/.aws = %+v, want the built-in refusal", got)
	}

	// The same entries from a profile lift nothing: each is a contradiction.
	profiles := filepath.Join(f.root, "askprofiles")
	if err := os.MkdirAll(profiles, 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(profiles, "lift.yaml"), "fs:\n  ask_read: [\"~/.netrc\"]\n", 0o644)
	path := filepath.Join(f.project, "agent.yaml")
	f.file(path, "version: 0\nname: ask-read\nextends: lift\ncommand: [\"python\"]\ntier: landlock\nexec:\n  allow: [\"python\"]\n", 0o644)
	pc, ds, err := Load(path, dirSource{root: profiles})
	if err != nil {
		t.Fatalf("load: %v\n%s", err, render(ds))
	}
	if _, ds, err = f.compileErr(pc); err == nil || len(errorsWith(ds, CodeContradiction, "comes from a profile")) != 1 {
		t.Fatalf("a profile lifted a built-in entry: %v\n%s", err, render(ds))
	}
}

// fs.ask_read concatenates across extends like every list, each entry keeping where it was declared.
func TestAskReadMergeConcatenates(t *testing.T) {
	f := newFixture(t)
	a, b := filepath.Join(f.root, "a"), filepath.Join(f.root, "b")
	f.file(a, "a", 0o600)
	f.file(b, "b", 0o600)
	profiles := filepath.Join(f.root, "askprofiles")
	if err := os.MkdirAll(profiles, 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(profiles, "base.yaml"), "fs:\n  ask_read: [\""+a+"\"]\n", 0o644)
	path := filepath.Join(f.project, "agent.yaml")
	f.file(path, "version: 0\nname: ask-read\nextends: base\ncommand: [\"python\"]\ntier: landlock\nexec:\n  allow: [\"python\"]\nfs:\n  ask_read: [\""+b+"\", \""+b+"\"]\n", 0o644)
	c, ds, err := Load(path, dirSource{root: profiles})
	if err != nil {
		t.Fatalf("load: %v\n%s", err, render(ds))
	}
	if len(c.FS.AskRead) != 3 || c.FS.AskRead[0] != a || c.FS.AskRead[1] != b {
		t.Fatalf("merged ask_read %v", c.FS.AskRead)
	}
	if len(warningsWith(ds, CodeRedundantRule, "fs.ask_read entry")) != 1 {
		t.Fatalf("the duplicate is not warned:\n%s", render(ds))
	}
	rt, _ := f.compile(c)
	rules := rt.AskReadRules()
	if len(rules) != 2 || !strings.HasSuffix(rules[0].Pos.File, "base.yaml") || rules[1].Pos.File != path {
		t.Fatalf("compiled ask_read rules %+v", rules)
	}
}

// ADR 0057 D3, one rule for both asks beneath a write entry: an ordinary grant takes precedence over an ask. An
// fs.ask scope at or beneath a write entry would never ask, and is warned (redundant-rule): nothing is less protected
// than the write grant says. An fs.ask_read entry there is refused (unenforced): it is also the deny_read keeping a
// secret, which the write grant would let the agent read outright. A write entry nested inside an fs.ask_read entry is
// nearer and decides beneath itself, and compiles.
func TestAsksBeneathAWriteEntry(t *testing.T) {
	f := newFixture(t)
	f.file(filepath.Join(f.project, "out", "result"), "x", 0o600)
	for _, held := range []string{"out/held", "out/"} {
		c := f.load(askReadContract(`  write: ["out/"]`, `  ask: ["`+held+`"]`))
		rt, ds := f.compile(c)
		if len(rt.FSAsk) != 1 || len(warningsWith(ds, CodeRedundantRule, "fs.ask \""+held+"\"", "lies inside write entry out/", "the scope never asks")) != 1 {
			t.Fatalf("fs.ask %q inside a write entry:\n%s", held, render(ds))
		}
	}
	c := f.load(askReadContract(`  write: ["out/"]`, `  ask: ["elsewhere/"]`))
	if _, ds := f.compile(c); len(warningsWith(ds, CodeRedundantRule, "the scope never asks")) != 0 {
		t.Fatalf("an fs.ask scope outside every write entry was warned:\n%s", render(ds))
	}
	c = f.load(askReadContract(`  write: ["out/"]`, `  ask_read: ["out/result"]`))
	if _, ds, err := f.compileErr(c); err == nil || len(errorsWith(ds, CodeUnenforced, "lies inside write entry", "without asking")) != 1 {
		t.Fatalf("fs.ask_read inside a write entry: %v\n%s", err, render(ds))
	}
}
