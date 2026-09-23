// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// writeProfile adds one profile to the fixture's copied profile directory, so a test can extend
// something it wrote itself.
func writeProfile(t *testing.T, f *fixture, name, body string) ProfileSource {
	t.Helper()
	src := f.profiles() // copies testdata/profiles under the fixture on first call
	if err := os.WriteFile(filepath.Join(f.root, "profiles", name+".yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return src
}

// builtInPaths are three rows of the built-in deny_read list the fixture creates on disk.
func builtInPaths(f *fixture) []string {
	return []string{filepath.Join(f.home, ".ssh"), filepath.Join(f.home, ".netrc"), filepath.Join(f.project, ".env")}
}

// diagAt reports whether ds holds a diagnostic with code at file:line.
func diagAt(ds []Diagnostic, code, file string, line int) bool {
	for _, d := range ds {
		if d.Code == code && d.File == file && d.Line == line {
			return true
		}
	}
	return false
}

// TestDenyReadEmptyOutvotedByTheChainKeepsTheBuiltInList holds R6's tri-state to the merged
// contract. R5 unions deny_read over the extends chain, so a contract that writes `deny_read: []`
// over a profile declaring an entry merges to a populated list, and a populated deny_read keeps the
// built-in list (R6's third arm). Honouring the `[]` anyway produced a merged contract no agent.yaml
// can spell — declared entries without the built-in list — so Canonical wrote it down as the
// populated list alone: contract_hash equalled the same contract without the `[]`, and the ledger's
// contract.yaml recompiled with the list on while the run had it off (R13). The list stays on, and
// Load says the `[]` did nothing instead of claiming it disabled the list.
func TestDenyReadEmptyOutvotedByTheChainKeepsTheBuiltInList(t *testing.T) {
	f := newFixture(t)
	src := writeProfile(t, f, "aws-only", "fs:\n  deny_read: [\"~/.aws\"]\n")
	path := filepath.Join(f.project, "agent.yaml")
	f.file(path, "version: 0\nname: a\nextends: aws-only\ncommand: [python]\nfs:\n  deny_read: []\n", 0o644)

	c, ds, err := Load(path, src)
	if err != nil {
		t.Fatalf("load: %v\n%s", err, render(ds))
	}
	// R5: the profile's entry is still there.
	if len(c.FS.DenyRead) != 1 || c.FS.DenyRead[0] != "~/.aws" {
		t.Fatalf("merged deny_read = %v, want the profile's entry to survive (R5)", c.FS.DenyRead)
	}
	if hasCode(ds, CodeDenyReadDisabled) {
		t.Errorf("warned that the built-in list is disabled, but the merged deny_read is populated:\n%s", render(ds))
	}
	if !diagAt(ds, CodeRedundantRule, path, 6) {
		t.Errorf("the outvoted deny_read: [] at %s:6 did not warn redundant-rule:\n%s", path, render(ds))
	}

	rt, cds := f.compile(c)
	if findFS(rt, FSDenyRead, filepath.Join(f.home, ".aws")) == nil {
		t.Errorf("the profile's declared deny_read entry is missing from the table:\n%s", render(cds))
	}
	for _, want := range builtInPaths(f) {
		if findFS(rt, FSDenyRead, want) == nil {
			t.Errorf("built-in deny_read %s missing under a populated merged list (R6)", want)
		}
	}
}

// TestDenyReadEmptyProfileOutvotedByTheContract is the same rule from the other side: a profile's
// `deny_read: []` cannot switch the credential list off under a contract that declares its own
// deny_read entry, and the warning lands on the profile line that wrote it.
func TestDenyReadEmptyProfileOutvotedByTheContract(t *testing.T) {
	f := newFixture(t)
	src := writeProfile(t, f, "no-builtin", "fs:\n  deny_read: []\n")
	path := filepath.Join(f.project, "agent.yaml")
	f.file(path, "version: 0\nname: a\nextends: no-builtin\ncommand: [python]\nfs:\n  deny_read: [\"secrets/\"]\n", 0o644)

	c, ds, err := Load(path, src)
	if err != nil {
		t.Fatalf("load: %v\n%s", err, render(ds))
	}
	if hasCode(ds, CodeDenyReadDisabled) || !diagAt(ds, CodeRedundantRule, filepath.Join(f.root, "profiles", "no-builtin.yaml"), 2) {
		t.Errorf("the profile's outvoted deny_read: [] must warn redundant-rule at its own line, never deny-read-disabled:\n%s", render(ds))
	}
	rt, _ := f.compile(c)
	for _, want := range append(builtInPaths(f), filepath.Join(f.project, "secrets")) {
		if findFS(rt, FSDenyRead, want) == nil {
			t.Errorf("deny_read %s missing: a populated merged list keeps the built-in list (R6)", want)
		}
	}
}

// TestDenyReadEmptyAcrossTheChainDisables keeps the switch working under extends where the merged
// list is empty: a profile that says nothing about deny_read, or says `[]` itself, leaves the
// contract's `deny_read: []` in charge, and the list is off with the warning that says so.
func TestDenyReadEmptyAcrossTheChainDisables(t *testing.T) {
	for _, profile := range []string{"record: full\n", "fs:\n  deny_read: []\n"} {
		f := newFixture(t)
		src := writeProfile(t, f, "p", profile)
		path := filepath.Join(f.project, "agent.yaml")
		f.file(path, "version: 0\nname: a\nextends: p\ncommand: [python]\nfs:\n  deny_read: []\n", 0o644)
		c, ds, err := Load(path, src)
		if err != nil {
			t.Fatalf("load: %v\n%s", err, render(ds))
		}
		if !diagAt(ds, CodeDenyReadDisabled, path, 6) || hasCode(ds, CodeRedundantRule) {
			t.Errorf("profile %q: want deny-read-disabled at %s:6 and nothing called redundant:\n%s", profile, path, render(ds))
		}
		rt, _ := f.compile(c)
		for _, gone := range builtInPaths(f) {
			if r := findFS(rt, FSDenyRead, gone); r != nil {
				t.Errorf("profile %q: deny_read: [] warned the built-in list off, but %s is compiled", profile, gone)
			}
		}
	}
}

// TestDenyReadPopulatedUnderExtendsKeepsTheBuiltInList is the control that must not regress: without
// the explicit `deny_read: []`, a contract that merely *adds* an entry over a profile keeps the
// built-in credential list, which is the fail-open the tri-state's third arm was written to close.
func TestDenyReadPopulatedUnderExtendsKeepsTheBuiltInList(t *testing.T) {
	f := newFixture(t)
	src := writeProfile(t, f, "aws-only2", "fs:\n  deny_read: [\"~/.aws\"]\n")
	path := filepath.Join(f.project, "agent.yaml")
	f.file(path, "version: 0\nname: a\nextends: aws-only2\ncommand: [python]\nfs:\n  deny_read: [\"secrets/\"]\n", 0o644)

	c, ds, err := Load(path, src)
	if err != nil {
		t.Fatalf("load: %v\n%s", err, render(ds))
	}
	if hasCode(ds, CodeDenyReadDisabled) {
		t.Fatalf("a populated deny_read warned as disabled: %v", codes(ds))
	}
	rt, cds := f.compile(c)
	for _, want := range []string{
		filepath.Join(f.home, ".aws"),
		filepath.Join(f.home, ".ssh"),
		filepath.Join(f.home, ".netrc"),
		filepath.Join(f.project, ".env"),
		filepath.Join(f.project, "secrets"),
	} {
		if findFS(rt, FSDenyRead, want) == nil {
			t.Errorf("deny_read %s missing: a populated list compiles the declared entries plus the built-in one (R6)\n%s", want, render(cds))
		}
	}
}

// denySet is the set of deny_read paths a table compiles, for comparing two tables.
func denySet(rt *RuleTable) map[string]bool {
	out := map[string]bool{}
	for _, r := range rt.FS {
		if r.Kind == FSDenyRead {
			out[r.Path] = true
		}
	}
	return out
}

// TestCanonicalCarriesTheDenyReadSwitch pins R13 to what it is for: contract_hash and the ledger's
// contract.yaml stand for the policy a run had. omitempty dropped `deny_read: []`, so
// `fs: {deny_read: []}` and `fs: {}` hashed identically while one compiled the built-in credential
// list and the other did not, and recompiling contract.yaml (what `tego drift` does) switched the
// list back on for a run that had it off.
//
// The property checked is the one the hash needs, over every deny_read shape including the extends
// ones: two contracts whose Canonical bytes are equal compile to equal deny sets, and Canonical
// reloads to a contract that compiles to the deny set the run had.
func TestCanonicalCarriesTheDenyReadSwitch(t *testing.T) {
	f := newFixture(t)
	src := writeProfile(t, f, "aws", "fs:\n  deny_read: [\"~/.aws\"]\n")
	type shape struct {
		name  string
		body  string
		canon []byte
		deny  map[string]bool
	}
	shapes := []*shape{
		{name: "fs: {}", body: "fs: {}\n"},
		{name: "deny_read: []", body: "fs:\n  deny_read: []\n"},
		{name: "no fs", body: ""},
		{name: "extends, deny_read: []", body: "extends: aws\nfs:\n  deny_read: []\n"},
		{name: "extends", body: "extends: aws\n"},
	}
	path := filepath.Join(f.project, "agent.yaml")
	for _, s := range shapes {
		f.file(path, "version: 0\nname: a\ncommand: [python]\n"+s.body, 0o644)
		c, ds, err := Load(path, src)
		if err != nil {
			t.Fatalf("%s: load: %v\n%s", s.name, err, render(ds))
		}
		if s.canon, err = c.Canonical(); err != nil {
			t.Fatal(err)
		}
		rt, _ := f.compile(c)
		s.deny = denySet(rt)

		// contract.yaml is Canonical's bytes; drift reloads and recompiles them. The reload keeps
		// extends:, so it goes through the same profile source.
		f.file(path, string(s.canon), 0o644)
		c2, ds, err := Load(path, src)
		if err != nil {
			t.Fatalf("%s: canonical bytes do not reload: %v\n%s\n%s", s.name, err, s.canon, render(ds))
		}
		rt2, _ := f.compile(c2)
		if !sameSet(s.deny, denySet(rt2)) {
			t.Errorf("%s: contract.yaml recompiles to a different deny set:\nrun:    %v\nreload: %v\n%s", s.name, s.deny, denySet(rt2), s.canon)
		}
	}
	for i, a := range shapes {
		for _, b := range shapes[i+1:] {
			if bytes.Equal(a.canon, b.canon) && !sameSet(a.deny, b.deny) {
				t.Errorf("%q and %q share canonical bytes, and so contract_hash, but compile to different deny sets:\n%v\n%v\n%s",
					a.name, b.name, a.deny, b.deny, a.canon)
			}
		}
	}
	// The premise of the pair the hash used to confuse: the two really do compile differently.
	if sameSet(shapes[0].deny, shapes[1].deny) {
		t.Fatalf("fixture no longer separates fs: {} from deny_read: []: %v", shapes[0].deny)
	}
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}
