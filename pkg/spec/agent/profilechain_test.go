// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// loadList loads contract over profiles held in memory and fails t on an error.
func loadList(t *testing.T, contract string, profiles ProfileSource) (*Contract, []Diagnostic) {
	t.Helper()
	c, ds, err := LoadBytes("c.yaml", []byte(contract), profiles)
	if err != nil {
		t.Fatalf("%v\n%s", err, render(ds))
	}
	return c, ds
}

// TestExtendsListMergesInOrder: extends is one name or a list, and a list merges its parents left to right by the
// classes of ADR 0065 D4, each parent resolved with its own parents first, then the contract on top (ADR 0066).
func TestExtendsListMergesInOrder(t *testing.T) {
	src := mapSource{
		"a":    "extends: root\nfs:\n  write: [/a]\n  deny_read: [/a-secret]\n  assurance: best-effort\nenv:\n  set: {K: same, A: a}\nexec:\n  assurance: kernel\n",
		"b":    "fs:\n  write: [/b]\n  deny_read: [/b-secret]\n  assurance: kernel\nenv:\n  set: {K: same, B: b}\nexec:\n  assurance: best-effort\nlimits:\n  pids: 7\n",
		"root": "fs:\n  write: [/root]\n",
	}
	c, _ := loadList(t, "version: 0\nname: c\nextends: [a, b]\ncommand: [x]\nfs:\n  write: [/c]\n", src)
	if got := strings.Join(c.Extends, ","); got != "a,b" {
		t.Errorf("extends = %q, want the top file's own list", got)
	}
	if got := strings.Join(c.FS.Write, ","); got != "/root,/a,/b,/c" {
		t.Errorf("fs.write = %s: concat runs each parent's chain, then the next parent, then the contract", got)
	}
	if got := strings.Join(c.FS.DenyRead, ","); got != "/a-secret,/b-secret" {
		t.Errorf("fs.deny_read = %s: the union of both parents", got)
	}
	if c.Env.Set["K"] != "same" || c.Env.Set["A"] != "a" || c.Env.Set["B"] != "b" {
		t.Errorf("env.set = %v: key by key, a key both parents set to one value no conflict", c.Env.Set)
	}
	if c.FS.Assurance != FSAssuranceKernel || c.Exec.Assurance != ExecAssuranceKernel {
		t.Errorf("fs.assurance %s, exec.assurance %s: the stricter of the parents, whichever wrote it", c.FS.Assurance, c.Exec.Assurance)
	}
	if p, ok := c.Pos("limits.pids"); !ok || p.File != "profiles/b.yaml" || *c.Limits.Pids != 7 {
		t.Errorf("limits.pids at %+v: a key one parent alone writes is that parent's", p)
	}
	if p, ok := c.Pos("fs.write.0"); !ok || p.File != "profiles/root.yaml" {
		t.Errorf("fs.write.0 at %+v, want the grandparent's line", p)
	}
	var names []string
	for _, u := range c.Profiles() {
		names = append(names, u.Name)
		if u.Source != ProfileDir {
			t.Errorf("%s served by %q, want dir", u.Name, u.Source)
		}
		if want := sha256.Sum256([]byte(src[u.Name])); u.SHA256 != want {
			t.Errorf("%s sha256 %x, want the bytes read %x", u.Name, u.SHA256, want)
		}
	}
	if got := strings.Join(names, ","); got != "root,a,b" {
		t.Errorf("Profiles() = %s, want the merge order root,a,b", got)
	}

	// The scalar form is a one-name list.
	one, _ := loadList(t, "version: 0\nname: c\nextends: b\ncommand: [x]\n", src)
	if !slices.Equal(one.Extends, ExtendsList{"b"}) || *one.Limits.Pids != 7 {
		t.Errorf("extends: b read as %v", one.Extends)
	}
}

// TestExtendsConflictBetweenParents: a contract-wins key two parents set to different values is extends-conflict at
// both parents' lines, unless the contract sets it, which then decides; two parents agreeing on a value are no
// conflict, and the merged key keeps the first parent's origin (ADR 0065 D4 as amended).
func TestExtendsConflictBetweenParents(t *testing.T) {
	src := mapSource{
		"a": "command: [a-cmd]\nlimits:\n  wall: 60s\n  pids: 5\nrecord: full\n",
		"b": "command: [b-cmd]\nlimits:\n  wall: 1m\n  pids: 6\nrecord: full\n",
		"c": "command: [b-cmd, x]\n",
		"d": "command: [x, b-cmd]\n",
	}
	_, ds, err := LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: [a, b]\ncommand: [mine]\n"), src)
	if err == nil {
		t.Fatalf("limits.pids set to 5 and 6 by two parents loaded: %s", render(ds))
	}
	if !diagAt(ds, CodeExtendsConflict, "profiles/a.yaml", 4) || !diagAt(ds, CodeExtendsConflict, "profiles/b.yaml", 4) {
		t.Errorf("want extends-conflict at both pids lines:\n%s", render(ds))
	}
	for _, d := range ds {
		if d.Code == CodeExtendsConflict && !(strings.Contains(d.Message, "profiles/a.yaml:4") && strings.Contains(d.Message, "profiles/b.yaml:4")) {
			t.Errorf("the conflict must name both files: %s", d.Message)
		}
		if d.Code == CodeExtendsConflict && !strings.Contains(d.Message, "limits.pids") {
			t.Errorf("only limits.pids conflicts (command is the contract's, wall is one value, record agrees): %s", d.Error())
		}
	}

	// The contract settles every conflict it writes.
	c, ds := loadList(t, "version: 0\nname: c\nextends: [a, b]\ncommand: [mine]\nlimits:\n  pids: 9\n", src)
	if *c.Limits.Pids != 9 || c.Command[0] != "mine" || hasCode(ds, CodeExtendsConflict) {
		t.Errorf("settled by the contract: pids %d command %v\n%s", *c.Limits.Pids, c.Command, render(ds))
	}
	// One value written twice keeps the first parent's origin.
	if p, _ := c.Pos("limits.wall"); p.File != "profiles/a.yaml" || *c.Limits.Wall != Duration(60e9) {
		t.Errorf("limits.wall at %+v, want the first parent's line", p)
	}
	if p, _ := c.Pos("record"); p.File != "profiles/a.yaml" {
		t.Errorf("record at %+v, want the first parent's line", p)
	}

	// command is a list compared in order and length: the contract must choose.
	_, ds, err = LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: [c, d]\n"), src)
	if err == nil || !diagAt(ds, CodeExtendsConflict, "profiles/c.yaml", 1) || !diagAt(ds, CodeExtendsConflict, "profiles/d.yaml", 1) {
		t.Errorf("two parents' commands in another order must conflict: %v\n%s", err, render(ds))
	}

	// A conflict inside a profile is that profile's to settle: the contract above it cannot.
	src["mid"] = "extends: [a, b]\n"
	_, ds, err = LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: mid\ncommand: [x]\nlimits:\n  pids: 9\n"), src)
	if err == nil || !hasCode(ds, CodeExtendsConflict) {
		t.Errorf("a profile whose own parents conflict loaded: %v\n%s", err, render(ds))
	}
}

// TestExtendsEnvSetKeyConflict: an env.set key two parents set to different values is extends-conflict at both lines
// (ADR 0066 D3, amending ADR 0065 D4), as a contract-wins key is: a later profile's PATH decides what every exec name
// resolves to, and its HTTPS_PROXY where every connect goes, so it must never silently replace an earlier one's. The
// file naming the list settles it by setting the key; keys only one parent sets, or both set alike, merge as before.
func TestExtendsEnvSetKeyConflict(t *testing.T) {
	src := mapSource{
		"a": "env:\n  set:\n    PATH: /usr/bin\n    LANG: C.UTF-8\n    A: a\n",
		"b": "env:\n  set:\n    PATH: /home/team/bin\n    LANG: C.UTF-8\n    B: b\n",
	}
	_, ds, err := LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: [a, b]\ncommand: [x]\n"), src)
	if err == nil || !diagAt(ds, CodeExtendsConflict, "profiles/a.yaml", 3) || !diagAt(ds, CodeExtendsConflict, "profiles/b.yaml", 3) {
		t.Fatalf("env.set.PATH set to /usr/bin and /home/team/bin by two parents: err %v\n%s", err, render(ds))
	}
	for _, d := range ds {
		if d.Code == CodeExtendsConflict && !strings.Contains(d.Message, "env.set.PATH") {
			t.Errorf("only PATH conflicts (LANG is one value, A and B one parent's each): %s", d.Error())
		}
	}
	c, ds := loadList(t, "version: 0\nname: c\nextends: [a, b]\ncommand: [x]\nenv:\n  set:\n    PATH: /opt/bin\n", src)
	if c.Env.Set["PATH"] != "/opt/bin" || c.Env.Set["LANG"] != "C.UTF-8" || c.Env.Set["A"] != "a" || c.Env.Set["B"] != "b" || hasCode(ds, CodeExtendsConflict) {
		t.Errorf("settled by the contract: env.set %v\n%s", c.Env.Set, render(ds))
	}
	if p, _ := c.Pos("env.set.LANG"); p.File != "profiles/a.yaml" {
		t.Errorf("env.set.LANG at %+v: one value written twice keeps the first parent's line", p)
	}
	// Only the file naming the list settles it.
	src["mid"] = "extends: [a, b]\n"
	if _, ds, err := LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: mid\ncommand: [x]\nenv:\n  set:\n    PATH: /opt/bin\n"), src); err == nil || !hasCode(ds, CodeExtendsConflict) {
		t.Errorf("a profile whose parents' env.set.PATH conflicts loaded: %v\n%s", err, render(ds))
	}
}

// TestExtendsConflictInAProfileWhateverComesFirst: a profile whose own parents conflict is in error under every
// contract (ADR 0066 D3), also when one of those parents was reached first through an earlier entry and so merges
// at that earlier position: merging it once never hides it from the conflict check of a later list that names it.
func TestExtendsConflictInAProfileWhateverComesFirst(t *testing.T) {
	src := mapSource{
		"c": "command: [c-cmd]\nlimits:\n  pids: 7\n",
		"d": "command: [d-cmd]\nlimits:\n  pids: 1000\n",
		"b": "extends: [c, d]\n",
		"e": "extends: c\nlimits:\n  pids: 1000\n",
	}
	for _, top := range []string{"[b]", "[e, b]", "[c, b]", "[d, b]"} {
		_, ds, err := LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: "+top+"\ncommand: [top]\nlimits:\n  pids: 1\n"), src)
		if err == nil || !diagAt(ds, CodeExtendsConflict, "profiles/c.yaml", 3) || !diagAt(ds, CodeExtendsConflict, "profiles/d.yaml", 3) ||
			!diagAt(ds, CodeExtendsConflict, "profiles/c.yaml", 1) || !diagAt(ds, CodeExtendsConflict, "profiles/d.yaml", 1) {
			t.Errorf("extends: %s: b's parents c and d conflict on limits.pids and command, which only b can settle: err %v\n%s", top, err, render(ds))
		}
		for _, d := range ds {
			if d.Code == CodeExtendsConflict && !strings.Contains(d.Message, "profiles/b.yaml") {
				t.Errorf("extends: %s: the conflict is b's, not the contract's: %s", top, d.Message)
			}
		}
	}
	// b settling its own conflict loads under any order, and c, reached first through e, still merges once.
	src["b"] = "extends: [c, d]\ncommand: [b-cmd]\nlimits:\n  pids: 1000\n"
	c, ds := loadList(t, "version: 0\nname: c\nextends: [e, b]\ncommand: [top]\n", src)
	var names []string
	for _, u := range c.Profiles() {
		names = append(names, u.Name)
	}
	if got := strings.Join(names, ","); got != "c,e,d,b" || *c.Limits.Pids != 1000 || c.Command[0] != "top" {
		t.Errorf("Profiles() = %s, pids %d, command %v\n%s", got, *c.Limits.Pids, c.Command, render(ds))
	}
}

// conflictVerdict loads a contract extending top, own appended to it, and reports whether it loaded and its
// extends-conflict findings, each as "file:line in <the file whose extends list conflicts>", sorted.
func conflictVerdict(src mapSource, top, own string) (bool, []string) {
	_, ds, err := LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: "+top+"\ncommand: [top]\n"+own), src)
	var got []string
	for _, d := range ds {
		if d.Code != CodeExtendsConflict {
			continue
		}
		owner, _, _ := strings.Cut(strings.SplitN(d.Message, "two profiles ", 2)[1], " extends")
		got = append(got, fmt.Sprintf("%s:%d in %s", d.File, d.Line, owner))
	}
	slices.Sort(got)
	return err == nil, got
}

// TestExtendsVerdictNeverDependsOnOrder: whether a list conflicts is decided on each parent resolved in full, every
// ancestor included, so it never depends on which entry of a list above it reached a shared ancestor first, at any
// depth (ADR 0066 D3). A branch that overrides a value a shared ancestor set conflicts with a branch that inherits
// it, under either order: each parent is what it resolves to, however it came by its values.
func TestExtendsVerdictNeverDependsOnOrder(t *testing.T) {
	pids := func(n int) string { return fmt.Sprintf("limits:\n  pids: %d\n", n) }
	diamond := mapSource{"base": pids(7), "a": "extends: base\n" + pids(1000), "b": "extends: base\n"}
	cases := []struct {
		name  string
		src   mapSource
		own   string
		tops  []string
		load  bool
		wants []string
	}{
		{
			// a overrides base's pids and b inherits them: the conflict is the contract's own list's.
			name: "diamond", src: diamond, tops: []string{"[a, b]", "[b, a]"},
			wants: []string{"profiles/a.yaml:3 in c.yaml", "profiles/base.yaml:2 in c.yaml"},
		},
		{name: "diamond settled", src: diamond, own: pids(5), tops: []string{"[a, b]", "[b, a]"}, load: true},
		{
			// w's own parents y (b's pids 7, inherited) and z (pids 1000) conflict, which no file above w settles.
			name: "a grandparent reached first",
			src:  mapSource{"b": pids(7), "y": "extends: b\n", "z": pids(1000), "w": "extends: [y, z]\n", "v": "extends: b\n" + pids(1000)},
			own:  pids(5), tops: []string{"[w]", "[w, v]", "[v, w]", "[w, b]", "[b, w]"},
			wants: []string{"profiles/b.yaml:2 in profiles/w.yaml", "profiles/z.yaml:2 in profiles/w.yaml"},
		},
		{
			name: "a grandparent reached first, directly",
			src:  mapSource{"c": pids(7), "q": "extends: c\n", "w": pids(1000), "z": "extends: [q, w]\n"},
			own:  pids(1), tops: []string{"[z]", "[q, z]", "[c, z]", "[c, q, z]"},
			wants: []string{"profiles/c.yaml:2 in profiles/z.yaml", "profiles/w.yaml:2 in profiles/z.yaml"},
		},
		{
			// q overrides c's pids and w inherits them: z's own list conflicts, whatever reached w first.
			name: "an override against an inherited value",
			src:  mapSource{"c": pids(7), "q": "extends: c\n" + pids(1), "w": "extends: c\n", "z": "extends: [q, w]\n"},
			own:  pids(5), tops: []string{"[z]", "[w, z]", "[c, z]", "[q, z]"},
			wants: []string{"profiles/c.yaml:2 in profiles/z.yaml", "profiles/q.yaml:3 in profiles/z.yaml"},
		},
		{
			// p merges only other here, base being x's already, and resolves to base's pids all the same: a parent
			// that merges something fresh is still checked as what it resolves to, not as what it merged.
			name:  "a parent that merges one entry and was beaten to the other",
			src:   mapSource{"base": pids(7), "x": "extends: base\n" + pids(1000), "other": "env:\n  pass: [FOO]\n", "p": "extends: [base, other]\n"},
			tops:  []string{"[x, p]", "[p, x]"},
			wants: []string{"profiles/base.yaml:2 in c.yaml", "profiles/x.yaml:3 in c.yaml"},
		},
	}
	for _, tc := range cases {
		for _, top := range tc.tops {
			loaded, got := conflictVerdict(tc.src, top, tc.own)
			if loaded != tc.load || strings.Join(got, ", ") != strings.Join(tc.wants, ", ") {
				t.Errorf("%s: extends %s: loaded %v, conflicts %q; want loaded %v, %q", tc.name, top, loaded, got, tc.load, tc.wants)
			}
		}
	}
}

// TestWholeViewStaysTheSizeOfItsKeys: a whole view counts a shared ancestor once per path to it, so it holds the
// scalar keys only: with its lists it would grow by the width of each level, here 4^7 copies of each bottom entry,
// while the merged contract holds each entry once.
func TestWholeViewStaysTheSizeOfItsKeys(t *testing.T) {
	const width, levels = 4, 7
	src := mapSource{}
	level := func(k int) string {
		var names []string
		for i := range width {
			names = append(names, fmt.Sprintf("l%d_%d", k, i))
		}
		return "[" + strings.Join(names, ", ") + "]"
	}
	for k := 1; k <= levels; k++ {
		for i := range width {
			body := fmt.Sprintf("extends: %s\n", level(k+1))
			if k == levels {
				body = fmt.Sprintf("fs:\n  write: [/w%d]\nlimits:\n  pids: 7\n", i)
			}
			src[fmt.Sprintf("l%d_%d", k, i)] = body
		}
	}
	l := &loader{profiles: src, top: "c.yaml"}
	merged, whole, below := l.load("c.yaml", []byte("version: 0\nname: c\nextends: "+level(1)+"\ncommand: [x]\n"), "", nil)
	if len(l.ds.list) != 0 || merged == nil || len(below) != levels {
		t.Fatalf("below %v\n%s", below, render(l.ds.list))
	}
	if got := strings.Join(merged.FS.Write, ","); got != "/w0,/w1,/w2,/w3" || *merged.Limits.Pids != 7 {
		t.Errorf("merged fs.write = %s: each bottom entry merges once", got)
	}
	if whole.FS != nil && whole.FS.Write != nil || *whole.Limits.Pids != 7 {
		t.Errorf("the whole view holds %d fs.write entries; it holds the scalar keys only", len(whole.FS.Write))
	}
}

// TestExtendsAssuranceOutvotedWhateverComesFirst: a profile's best-effort is outvoted by the kernel its own ancestor
// requires, and warned at its line, also when an earlier entry reached that ancestor first (ADR 0066 D3).
func TestExtendsAssuranceOutvotedWhateverComesFirst(t *testing.T) {
	src := mapSource{
		"b": "fs:\n  assurance: kernel\nexec:\n  assurance: kernel\n",
		"q": "extends: b\n",
		"y": "extends: q\nfs:\n  assurance: best-effort\nexec:\n  assurance: best-effort\n",
		"v": "extends: b\n",
	}
	for _, top := range []string{"[y]", "[v, y]"} {
		_, ds := loadList(t, "version: 0\nname: c\nextends: "+top+"\ncommand: [x]\n", src)
		if !diagAt(ds, CodeRedundantRule, "profiles/y.yaml", 3) || !diagAt(ds, CodeRedundantRule, "profiles/y.yaml", 5) {
			t.Errorf("extends %s: y's best-effort, outvoted by b's kernel, is not warned\n%s", top, render(ds))
		}
	}
}

// TestExtendsDuplicatesAcrossFilesMergeSilently: an entry two files of the chain both declare is no finding, while
// an entry one file declares twice still warns redundant-rule at its line (ADR 0066).
func TestExtendsDuplicatesAcrossFilesMergeSilently(t *testing.T) {
	src := mapSource{
		"a": "fs:\n  write: [/tmp, /a]\nenv:\n  pass: [LANG]\n",
		"b": "fs:\n  write: [/tmp, /b, /b]\n",
	}
	c, ds := loadList(t, "version: 0\nname: c\nextends: [a, b]\ncommand: [x]\nfs:\n  write: [/tmp]\nenv:\n  pass: [LANG]\n", src)
	if got := strings.Join(c.FS.Write, ","); got != "/tmp,/a,/tmp,/b,/b,/tmp" {
		t.Errorf("fs.write = %s: every file's entries are kept", got)
	}
	var redundant []Diagnostic
	for _, d := range ds {
		if d.Code == CodeRedundantRule {
			redundant = append(redundant, d)
		}
	}
	if len(redundant) != 1 || redundant[0].File != "profiles/b.yaml" || !strings.Contains(redundant[0].Message, `"/b"`) {
		t.Errorf("want one redundant-rule, at b's second /b:\n%s", render(ds))
	}
}

// TestDuplicateCheckCostIsLinear: a contract that repeats every entry of the profile it extends (a learned contract
// re-listing a preset's paths) is checked for duplicates in about n, not n² (E24: map-based, never pairwise). The
// check once scanned every entry between a repeat and its first copy: 8,000 repeats cost about 60 times what 1,000
// did (seconds), where a linear check costs about 8 times.
func TestDuplicateCheckCostIsLinear(t *testing.T) {
	loads := func(n int) func() time.Duration {
		var profile, contract strings.Builder
		profile.WriteString("fs:\n  write:\n")
		contract.WriteString("version: 0\nname: c\nextends: base\ncommand: [x]\nfs:\n  write:\n")
		for i := range n {
			fmt.Fprintf(&profile, "    - /p/%d\n", i)
			fmt.Fprintf(&contract, "    - /p/%d\n", i)
		}
		src := mapSource{"base": profile.String()}
		data := []byte(contract.String())
		return func() time.Duration {
			start := processCPU(t)
			c, ds, err := LoadBytes("c.yaml", data, src)
			took := processCPU(t) - start
			if err != nil || len(c.FS.Write) != 2*n || hasCode(ds, CodeRedundantRule) {
				t.Fatalf("n=%d: err %v; a repeat across files is no finding\n%s", n, err, render(ds))
			}
			return took
		}
	}
	small, large := bestInterleaved(3, loads(1_000), loads(8_000))
	t.Logf("load: %v of CPU at 1,000 repeats, %v at 8,000", small, large)
	if large > 24*small+20*time.Millisecond {
		t.Errorf("the duplicate check costs %v at 8,000 repeats against %v at 1,000: it grows faster than the entries", large, small)
	}
}

// TestExtendsDiamondMergesOnce: a profile reached twice merges once, at its first position, so its entries are not
// doubled and its MCP server is not declared twice (E26).
func TestExtendsDiamondMergesOnce(t *testing.T) {
	src := mapSource{
		"base": "fs:\n  write: [/base]\nmcp:\n  - {name: fs, command: [fs-mcp]}\n",
		"a":    "extends: base\nfs:\n  write: [/a]\n",
		"b":    "extends: base\nfs:\n  write: [/b]\n",
	}
	c, ds := loadList(t, "version: 0\nname: c\nextends: [a, b]\ncommand: [x]\n", src)
	if got := strings.Join(c.FS.Write, ","); got != "/base,/a,/b" || len(c.MCP) != 1 {
		t.Errorf("fs.write = %s, %d mcp: base merges once, under a\n%s", got, len(c.MCP), render(ds))
	}
	var names []string
	for _, u := range c.Profiles() {
		names = append(names, u.Name)
	}
	if got := strings.Join(names, ","); got != "base,a,b" {
		t.Errorf("Profiles() = %s, want base once at its first position", got)
	}
	// A name the list repeats merges once and warns.
	c, ds = loadList(t, "version: 0\nname: c\nextends: [a, a]\ncommand: [x]\n", src)
	if got := strings.Join(c.FS.Write, ","); got != "/base,/a" || !diagAt(ds, CodeRedundantRule, "c.yaml", 3) {
		t.Errorf("extends: [a, a]: fs.write %s\n%s", got, render(ds))
	}
}

// TestExtendsCycleAndDepthAnywhere: a cycle through any entry of a list is E5's error, and depth 8 counts the
// longest chain, a chain reached a second time through a profile already merged included (E15).
func TestExtendsCycleAndDepthAnywhere(t *testing.T) {
	src := mapSource{"a": "fs:\n  write: [/a]\n", "b": "extends: [a, c]\n", "c": "extends: b\n"}
	_, ds, err := LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: [a, b]\ncommand: [x]\n"), src)
	if err == nil || !hasCode(ds, CodeExtendsCycle) || !strings.Contains(render(ds), "b -> c -> b") {
		t.Errorf("a cycle in the second entry: %v\n%s", err, render(ds))
	}

	deep := mapSource{}
	for i := 1; i < 8; i++ {
		deep[fmt.Sprintf("p%d", i)] = fmt.Sprintf("extends: p%d\n", i+1)
	}
	deep["p8"] = "fs:\n  write: [/p8]\n"
	if _, ds, err := LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: [p1]\ncommand: [x]\n"), deep); err != nil {
		t.Fatalf("a chain of 8 profiles: %v\n%s", err, render(ds))
	}
	// p3 is first reached at depth 3, five profiles beneath it: reached again beneath q3 at depth 4 it would make
	// the chain 9 long, though the walk does not merge it there again.
	deep["q1"], deep["q2"], deep["q3"] = "extends: q2\n", "extends: q3\n", "extends: p3\n"
	_, ds, err = LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: [p1, q1]\ncommand: [x]\n"), deep)
	if err == nil || !hasCode(ds, CodeExtendsTooDeep) || !strings.Contains(render(ds), "q1 -> q2 -> q3 -> p3 -> p4 -> p5 -> p6 -> p7 -> p8") {
		t.Errorf("the longest chain through a profile merged already: %v\n%s", err, render(ds))
	}
}

// TestExtendsListSchema: the list holds 1 to 8 profile names (ADR 0066).
func TestExtendsListSchema(t *testing.T) {
	src := mapSource{"a": "fs: {}\n"}
	nine := "[" + strings.Repeat("a, ", 8) + "a]"
	for name, extends := range map[string]string{
		"empty list":    "[]",
		"nine names":    nine,
		"a mapping":     "{a: 1}",
		"a nested list": "[[a]]",
		"a bad name":    "[a, ../x]",
		"a null entry":  "[a, ~]",
		"a . segment":   "[a, base/./py]",
		"a trailing .":  "[a, base/.]",
	} {
		_, ds, err := LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: "+extends+"\ncommand: [x]\n"), src)
		if err == nil || !hasCode(ds, CodeSchema) {
			t.Errorf("%s (extends: %s) loaded: %v\n%s", name, extends, err, render(ds))
		}
	}
	eight := "[" + strings.Repeat("a, ", 7) + "a]"
	if _, ds, err := LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: "+eight+"\ncommand: [x]\n"), src); err != nil {
		t.Errorf("eight names: %v\n%s", err, render(ds))
	}
}

// TestProfileNameHasOneSpelling: each profile file has exactly one name (ADR 0066 D1), so merge-once and the cycle
// check, which compare names, see a profile reached twice as one. `base/./py` read profiles/base/py.yaml as `base/py`
// does: `extends: [base/py, base/./py]` merged the file twice, declared its MCP server twice (E26) and blamed its
// author for a repeat they never wrote. The JSON Schema's profileName pattern is the Go rule itself.
func TestProfileNameHasOneSpelling(t *testing.T) {
	dir := filepath.Join("testdata", "extends", "profiles")
	_, ds, err := LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: [base/py, base/./py]\ncommand: [x]\n"), dirSource{root: dir})
	if err == nil || !hasCode(ds, CodeSchema) || !strings.Contains(render(ds), `"base/./py" is not a profile name`) {
		t.Errorf("a second spelling of base/py: %v\n%s", err, render(ds))
	}

	data, err := os.ReadFile(filepath.Join(repoRoot, "spec", "agent", "v0", "agent.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs struct {
			ProfileName struct{ Pattern string } `json:"profileName"`
		} `json:"$defs"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	if got := schema.Defs.ProfileName.Pattern; got != profileRE.String() {
		t.Fatalf("$defs.profileName.pattern = %s, Go's rule %s", got, profileRE)
	}
	for name, ok := range map[string]bool{
		"base": true, "base/python-dev": true, "tego/python": true, "a.b/c_d": true, "a/.hidden": true, "a/b.": true,
		"../x": false, "a/../b": false, "a..b": false, "a//b": false, "a/": false, "/a": false, "a/./b": false,
		"a/.": false, ".a": false, "A": false, "a b": false, "": false,
		// A revision pin (ADR 0068): @ and a revision number from 1, on a built-in name only.
		"tego/no-secrets@1": true, "tego/a/b@12": true, "base@1": false, "base/py@1": false, "tego@1": false,
		"tego/x@0": false, "tego/x@01": false, "tego/x@": false, "tego/x@1a": false, "tego/x@1/y": false,
		"tego/x@1@2": false, "tego/x@1234567890": false,
	} {
		msg, _ := checkProfileName(name)
		if (msg == "") != ok {
			t.Errorf("checkProfileName(%q) = %q, want accepted %v", name, msg, ok)
		}
	}
}

// TestSingleNameExtendsHashUnchanged: a contract extending one profile by a single name keeps the canonical form and
// contract_hash it had before extends took a list (R13, ADR 0066); the hash below was taken on the code before.
func TestSingleNameExtendsHashUnchanged(t *testing.T) {
	dir := filepath.Join("testdata", "extends")
	c, ds, err := Load(filepath.Join(dir, "single.yaml"), dirSource{root: filepath.Join(dir, "profiles")})
	if err != nil {
		t.Fatalf("%v\n%s", err, render(ds))
	}
	got, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(filepath.Join(dir, "single.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("canonical form changed:\n%s\nwant:\n%s", got, want)
	}
	if h, _ := c.Hash(); hex.EncodeToString(h[:]) != "53717c06c9b4b27e5577a52842e6997bad168c2060d4f55e203c8849b83943f6" {
		t.Errorf("contract_hash of a single-name contract changed: %x", h)
	}
}

// TestCanonicalOfMergedList: a list is written back as a list, after the merged entries of every parent, and the
// canonical form reloads to itself with every name sealed to an empty profile, as tego drift reloads contract.yaml.
func TestCanonicalOfMergedList(t *testing.T) {
	dir := filepath.Join("testdata", "extends")
	c, ds, err := Load(filepath.Join(dir, "list.yaml"), dirSource{root: filepath.Join(dir, "profiles")})
	if err != nil {
		t.Fatalf("%v\n%s", err, render(ds))
	}
	got, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join(dir, "list.golden")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("canonical form of a merged list:\n%s\nwant:\n%s", got, want)
	}
	sealed := sealedSource{}
	again, ds, err := LoadBytes("contract.yaml", got, sealed)
	if err != nil {
		t.Fatalf("the canonical form does not reload sealed: %v\n%s", err, render(ds))
	}
	if b, _ := again.Canonical(); string(b) != string(got) {
		t.Errorf("canonical not a fixed point under sealed profiles:\n%s", b)
	}
}

// sealedSource resolves every name, built-in ones included, to an empty profile (internal/cli's sealedProfiles).
type sealedSource struct{}

func (sealedSource) Resolve(name string) (string, []byte, error) {
	return "(sealed " + name + ")", []byte("{}\n"), nil
}

// countingSource is a profiles directory that counts every read and can say it holds a file without reading it.
type countingSource struct {
	files map[string]string
	reads *[]string
}

func (s countingSource) Resolve(name string) (string, []byte, error) {
	*s.reads = append(*s.reads, name)
	data, ok := s.files[name]
	if !ok {
		return "", nil, fmt.Errorf("profile %q: %w", name, os.ErrNotExist)
	}
	return "dir/" + name + ".yaml", []byte(data), nil
}

func (s countingSource) Holds(name string) (string, bool) {
	_, ok := s.files[name]
	return "dir/" + name + ".yaml", ok
}

// TestBuiltinNamesNeverReadTheProfilesDirectory: a name under tego/ resolves only through the built-in sources a
// ProfileChain registers; the profiles directory is never read for it, and a file it holds under tego/ draws
// shadowed-builtin (ADR 0066 D2). This package ships no built-in profile: the built-in source here is a fake.
func TestBuiltinNamesNeverReadTheProfilesDirectory(t *testing.T) {
	var reads []string
	dir := countingSource{files: map[string]string{"team": "fs:\n  write: [/team]\n"}, reads: &reads}
	builtin := mapSource{"tego/base": "fs:\n  write: [/builtin]\n"}
	chain := (&ProfileChain{}).WithBuiltin(builtin).WithDir(dir)

	c, _ := loadList(t, "version: 0\nname: c\nextends: [tego/base, team]\ncommand: [x]\n", chain)
	if got := strings.Join(c.FS.Write, ","); got != "/builtin,/team" {
		t.Errorf("fs.write = %s", got)
	}
	if !slices.Equal(reads, []string{"team"}) {
		t.Errorf("the profiles directory was read for %v; want team alone", reads)
	}
	if u := c.Profiles(); len(u) != 2 || u[0].Source != ProfileBuiltin || u[1].Source != ProfileDir {
		t.Errorf("Profiles() = %+v, want tego/base builtin then team dir", u)
	}

	// A built-in name no built-in source holds is not found, and still never read from the directory.
	reads = nil
	_, ds, err := LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: tego/none\ncommand: [x]\n"), chain)
	if !errors.Is(err, ErrProfileNotFound) || len(reads) != 0 || !strings.Contains(render(ds), "built-in profile") {
		t.Errorf("tego/none: %v, directory reads %v\n%s", err, reads, render(ds))
	}

	// A file the directory holds under tego/ is never read, and the extends naming it is an error.
	dir.files["tego/base"] = "fs:\n  write: [/shadow]\n"
	reads = nil
	_, ds, err = LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: tego/base\ncommand: [x]\n"), chain)
	if err == nil || !diagAt(ds, CodeShadowedBuiltin, "c.yaml", 3) || len(reads) != 0 || !strings.Contains(render(ds), "dir/tego/base.yaml") {
		t.Errorf("a shadowing file: %v, reads %v\n%s", err, reads, render(ds))
	}

	// A source that is no ProfileChain is a profiles directory: it never serves a built-in name, and its file under
	// tego/ is reported as a ProfileChain's directory's is.
	reads = nil
	_, ds, err = LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: tego/base\ncommand: [x]\n"), dir)
	if err == nil || !hasCode(ds, CodeShadowedBuiltin) || len(reads) != 0 {
		t.Errorf("a plain source served tego/base: %v, reads %v", err, reads)
	}
	_, _, err = LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: tego/base\ncommand: [x]\n"), mapSource{"tego/base": "fs: {}\n"})
	if !errors.Is(err, ErrProfileNotFound) {
		t.Errorf("a plain source that cannot say what it holds served tego/base: %v", err)
	}
}

// TestBuiltinProfileExtendsOnlyBuiltins: a built-in profile's own extends resolves through the built-in sources alone
// (ADR 0066 D2), so no profiles-directory file supplies part of a preset under the preset's name. A built-in naming
// `team` was merged with the directory's team.yaml, its fs.write and net.allow included, with no diagnostic.
func TestBuiltinProfileExtendsOnlyBuiltins(t *testing.T) {
	var reads []string
	dir := countingSource{files: map[string]string{"team": "fs:\n  write: [/from-user-dir]\nnet:\n  allow: [evil.example:443]\n"}, reads: &reads}
	builtin := mapSource{
		"tego/py":   "extends: team\nfs:\n  write: [/py]\n",
		"tego/base": "fs:\n  write: [/base]\n",
		"tego/ok":   "extends: [tego/base]\nfs:\n  write: [/ok]\n",
	}
	chain := (&ProfileChain{}).WithBuiltin(builtin).WithDir(dir)
	_, ds, err := LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: tego/py\ncommand: [x]\n"), chain)
	if !errors.Is(err, ErrProfileNotFound) || !diagAt(ds, CodeExtendsNotFound, "profiles/tego/py.yaml", 1) || len(reads) != 0 ||
		!strings.Contains(render(ds), "a built-in profile extends only built-in profiles") {
		t.Errorf("tego/py extending team: %v, directory reads %v\n%s", err, reads, render(ds))
	}
	// The contract itself may still list both: team is then the contract's own choice, recorded as dir.
	c, _ := loadList(t, "version: 0\nname: c\nextends: [tego/ok, team]\ncommand: [x]\n", chain)
	if got := strings.Join(c.FS.Write, ","); got != "/base,/ok,/from-user-dir" {
		t.Errorf("fs.write = %s", got)
	}
	if u := c.Profiles(); len(u) != 3 || u[0].Source != ProfileBuiltin || u[1].Source != ProfileBuiltin || u[2].Source != ProfileDir {
		t.Errorf("Profiles() = %+v", u)
	}
}

// namedSource is a built-in source that can list the names it serves (ProfileNamer).
type namedSource struct{ mapSource }

func (s namedSource) Names() []string {
	var names []string
	for n := range s.mapSource {
		names = append(names, n)
	}
	return names
}

// TestUnknownBuiltinNameListsTheKnownOnes: a tego/ name no built-in source holds is extends-not-found, and its fix
// lists every name the built-in sources that can list theirs serve, sorted, so a typo in a preset's name or a
// revision pin that does not exist is answered with the names to choose from (ADR 0068).
func TestUnknownBuiltinNameListsTheKnownOnes(t *testing.T) {
	chain := (&ProfileChain{}).
		WithBuiltin(namedSource{mapSource{"tego/no-prod": "net: {allow: []}\n", "tego/no-prod@1": "net: {allow: []}\n"}}).
		WithBuiltin(mapSource{"tego/unlisted": "{}\n"}).
		WithBuiltin(namedSource{mapSource{"tego/agent": "{}\n"}})
	for _, name := range []string{"tego/no-prd", "tego/no-prod@2"} {
		_, ds, err := LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: "+name+"\ncommand: [x]\n"), chain)
		if !errors.Is(err, ErrProfileNotFound) || !diagAt(ds, CodeExtendsNotFound, "c.yaml", 3) ||
			!strings.Contains(render(ds), "the built-in profiles are tego/agent, tego/no-prod, tego/no-prod@1") {
			t.Errorf("%s: %v\n%s", name, err, render(ds))
		}
	}
	// With no source that lists its names, the fix says so in general terms, as before.
	_, ds, _ := LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: tego/x\ncommand: [x]\n"), (&ProfileChain{}).WithBuiltin(mapSource{}))
	if r := render(ds); strings.Contains(r, "the built-in profiles are") || !strings.Contains(r, "check the name against tego's built-in profiles") {
		t.Errorf("no namer:\n%s", r)
	}
}

// TestProfileChainOrder: the first source holding a name serves it, and an error other than not-found stops there,
// so a profile that exists and cannot be read is never passed over for a later source's.
func TestProfileChainOrder(t *testing.T) {
	first, second := mapSource{"x": "fs:\n  write: [/first]\n"}, mapSource{"x": "fs:\n  write: [/second]\n", "y": "fs:\n  write: [/y]\n"}
	chain := (&ProfileChain{}).WithDir(first).WithDir(second)
	c, _ := loadList(t, "version: 0\nname: c\nextends: [x, y]\ncommand: [x]\n", chain)
	if got := strings.Join(c.FS.Write, ","); got != "/first,/y" {
		t.Errorf("fs.write = %s", got)
	}
	stopped := (&ProfileChain{}).WithDir(errSource{}).WithDir(second)
	_, ds, err := LoadBytes("c.yaml", []byte("version: 0\nname: c\nextends: x\ncommand: [x]\n"), stopped)
	if err == nil || !strings.Contains(render(ds), "permission denied") {
		t.Errorf("an unreadable profile was passed over: %v\n%s", err, render(ds))
	}
	if (&ProfileChain{}).WithDir(locatedSource{}).Location("tego/x") != "" {
		t.Error("a built-in name has no file to create")
	}
}

// pinnedSource is a built-in source that serves one file under a name and its revision pin, as presets.Source
// serves tego/<preset> and tego/<preset>@<n> for the newest revision.
type pinnedSource map[string]string

func (s pinnedSource) Resolve(name string) (string, []byte, error) {
	base, _, _ := strings.Cut(name, "@")
	data, ok := s[base]
	if !ok {
		return "", nil, fmt.Errorf("profile %q: %w", name, os.ErrNotExist)
	}
	return "<builtin>/" + strings.TrimPrefix(base, BuiltinPrefix) + ".yaml", []byte(data), nil
}

// TestExtendsNameAndPinOfOneFileMergeOnce: two names a built-in source serves from one file, a preset and its pin
// to the revision it is, are one profile. A list naming both merges the file once, at its first position, with one
// redundant-rule warning at the second name's line in the contract; it used to merge the bytes twice and warn once
// per repeated entry, each warning pointing into the built-in file the user cannot edit. A diamond
// that reaches the file under the other name merges once silently, as a diamond by one name does.
func TestExtendsNameAndPinOfOneFileMergeOnce(t *testing.T) {
	chain := (&ProfileChain{}).WithBuiltin(pinnedSource{
		"tego/x": "env:\n  pass: [PATH, HOME]\nfs:\n  write: [/dev/null]\n",
	}).WithDir(mapSource{"team": "extends: tego/x@1\nfs:\n  write: [/team]\n"})
	for _, list := range []string{"[tego/x, tego/x@1]", "[tego/x@1, tego/x]"} {
		c, ds := loadList(t, "version: 0\nname: c\nextends: "+list+"\ncommand: [x]\n", chain)
		if got := strings.Join(c.Env.Pass, ","); got != "PATH,HOME" || len(ds) != 1 || !diagAt(ds, CodeRedundantRule, "c.yaml", 3) {
			t.Errorf("%s: env.pass %s\n%s", list, got, render(ds))
		}
		if u := c.Profiles(); len(u) != 1 {
			t.Errorf("%s: Profiles() = %+v, want the file once", list, u)
		}
	}
	c, ds := loadList(t, "version: 0\nname: c\nextends: [tego/x, team]\ncommand: [x]\n", chain)
	if got := strings.Join(c.FS.Write, ","); got != "/dev/null,/team" || len(ds) != 0 {
		t.Errorf("a diamond through the pin: fs.write %s\n%s", got, render(ds))
	}
}
