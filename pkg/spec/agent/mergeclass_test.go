// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"reflect"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// mergeFixture is a test-only root with one key of every merge class, merged by mergeFixtureRows: the classes are
// tested here, on keys of their own, and contractMergeRows only assigns them (merge_table_test.go).
type mergeFixture struct {
	List    []string          `yaml:"list"`
	Deny    []string          `yaml:"deny"`
	Set     map[string]string `yaml:"set"`
	Value   string            `yaml:"value"`
	Count   *int              `yaml:"count"`
	Sec     *fixtureSection   `yaml:"sec"`
	Plain   fixtureSection    `yaml:"plain"`
	Reads   string            `yaml:"reads"`
	Sockets bool              `yaml:"sockets"`
	Rev     string            `yaml:"rev"`
	Own     int               `yaml:"own"`
	Node    yaml.Node         `yaml:"node"`
	Opt     yaml.Node         `yaml:"opt"`
	Whole   *fixtureSection   `yaml:"whole"`
}

type fixtureSection struct {
	List  []string `yaml:"list"`
	Value string   `yaml:"value"`
}

var mergeFixtureRows = []mergeRow{
	keyRow("list", classConcat),
	keyRow("deny", classUnion),
	keyRow("set", classKeyMerge),
	keyRow("value", classContractWins),
	keyRow("count", classContractWins),
	keyRow("sec", classSection),
	keyRow("sec.list", classConcat),
	keyRow("sec.value", classContractWins),
	keyRow("plain", classSection),
	keyRow("plain.list", classConcat),
	keyRow("plain.value", classContractWins),
	stricterRow("reads", []string{"held", "auto", "direct"}, "direct"),
	stricterRow("sockets", []string{"false", "true"}, "true"),
	keyRow("rev", classRefusedInProfile),
	keyRow("own", classOwn),
	{path: "node", class: classContractWins, rule: mergeRule{empty: emptyResetsInContract}},
	{path: "opt", class: classContractWins, rule: mergeRule{empty: emptyIsAbsent}},
	// A mapping of class contract-wins is one value: its keys have no rows (the shape ADR 0065 gives check).
	keyRow("whole", classContractWins),
}

var fixtureTable = mustMergeTable(reflect.TypeFor[mergeFixture](), mergeFixtureRows)

// fixtureFile decodes one fixture file and records where each non-null key was written, as Load's schema walk does.
func fixtureFile(t *testing.T, file, src string) (*mergeFixture, origins) {
	t.Helper()
	var v mergeFixture
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(src), &root); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	if err := root.Decode(&v); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	o := origins{}
	var walk func(n *yaml.Node, path string)
	walk = func(n *yaml.Node, path string) {
		if n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null" {
			return
		}
		if path != "" {
			o[path] = Pos{File: file, Line: n.Line, Col: n.Column}
		}
		sep := "."
		if path == "" {
			sep = ""
		}
		switch n.Kind {
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				walk(n.Content[i+1], path+sep+n.Content[i].Value)
			}
		case yaml.SequenceNode:
			for i, e := range n.Content {
				walk(e, path+sep+strconv.Itoa(i))
			}
		}
	}
	if len(root.Content) > 0 {
		walk(root.Content[0], "")
	}
	return &v, o
}

// mergeFixtures merges contract c over profile p as Load does: each profile file is held to its rules first (a
// middle file of a chain is one, so midProfile holds c to them too), then the table merges.
func mergeFixtures(t *testing.T, p, c string, midProfile bool) (*mergeFixture, origins, []Diagnostic) {
	t.Helper()
	pv, po := fixtureFile(t, "profile.yaml", p)
	cv, co := fixtureFile(t, "contract.yaml", c)
	var ds diags
	fixtureTable.profileRules(reflect.ValueOf(pv).Elem(), po, &ds)
	if midProfile {
		fixtureTable.profileRules(reflect.ValueOf(cv).Elem(), co, &ds)
	}
	m := newMerger(po, co)
	var r mergeFixture
	fixtureTable.merge(m, reflect.ValueOf(pv).Elem(), reflect.ValueOf(cv).Elem(), reflect.ValueOf(&r).Elem())
	return &r, m.out, ds.list
}

func wantFrom(t *testing.T, o origins, key, file string) {
	t.Helper()
	if got, ok := o[key]; !ok || got.File != file {
		t.Errorf("origin of %s = %+v (%v), want %s", key, got, ok, file)
	}
}

func wantNoOrigin(t *testing.T, o origins, key string) {
	t.Helper()
	if got, ok := o[key]; ok {
		t.Errorf("origin of %s = %+v, want none", key, got)
	}
}

func TestMergeClassConcat(t *testing.T) {
	r, o, _ := mergeFixtures(t, "list: [a, b]\n", "list: [c]\n", false)
	if !reflect.DeepEqual(r.List, []string{"a", "b", "c"}) {
		t.Fatalf("list = %q, want the profile's entries first", r.List)
	}
	wantFrom(t, o, "list.1", "profile.yaml")
	wantFrom(t, o, "list.2", "contract.yaml")
	wantFrom(t, o, "list", "contract.yaml")
	if r, _, _ := mergeFixtures(t, "list: [a]\n", "list: []\n", false); !reflect.DeepEqual(r.List, []string{"a"}) {
		t.Errorf("a contract's list: [] removed the profile's entries: %q", r.List)
	}
	if r, _, _ := mergeFixtures(t, "value: x\n", "list: []\n", false); r.List == nil || len(r.List) != 0 {
		t.Errorf("an explicitly empty list merged as %#v, want non-nil and empty", r.List)
	}
	if r, o, _ := mergeFixtures(t, "value: x\n", "value: y\n", false); r.List != nil {
		t.Errorf("a list no file wrote merged as %#v, want nil", r.List)
	} else {
		wantNoOrigin(t, o, "list")
	}
}

func TestMergeClassUnion(t *testing.T) {
	for _, tc := range []struct {
		name, p, c string
		want       []string
	}{
		{"contract-empty-keeps-profile", "deny: [x]\n", "deny: []\n", []string{"x"}},
		{"both", "deny: [x]\n", "deny: [y, x]\n", []string{"x", "y", "x"}},
		{"contract-absent", "deny: [x]\n", "value: v\n", []string{"x"}},
		{"profile-empty", "deny: []\n", "value: v\n", []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, o, _ := mergeFixtures(t, tc.p, tc.c, false)
			if !reflect.DeepEqual(r.Deny, tc.want) {
				t.Fatalf("deny = %#v, want %#v: a union never loses a profile entry", r.Deny, tc.want)
			}
			if len(tc.want) > 0 {
				wantFrom(t, o, "deny.0", "profile.yaml")
			}
		})
	}
}

func TestMergeClassKeyMerge(t *testing.T) {
	r, o, _ := mergeFixtures(t, "set: {A: '1', B: '2'}\n", "set: {B: '3', C: '4'}\n", false)
	if want := map[string]string{"A": "1", "B": "3", "C": "4"}; !reflect.DeepEqual(r.Set, want) {
		t.Fatalf("set = %v, want %v: the contract wins per key", r.Set, want)
	}
	wantFrom(t, o, "set.A", "profile.yaml")
	wantFrom(t, o, "set.B", "contract.yaml")
	wantFrom(t, o, "set.C", "contract.yaml")
	if r, _, _ := mergeFixtures(t, "value: x\n", "value: y\n", false); r.Set != nil {
		t.Errorf("a map no file wrote merged as %#v", r.Set)
	}
}

func TestMergeClassContractWins(t *testing.T) {
	r, o, _ := mergeFixtures(t, "value: p\ncount: 1\n", "value: ''\n", false)
	if r.Value != "" || r.Count == nil || *r.Count != 1 {
		t.Fatalf("value = %q count = %v: the contract's written value wins, even an empty one, else the profile's", r.Value, r.Count)
	}
	wantFrom(t, o, "value", "contract.yaml")
	wantFrom(t, o, "count", "profile.yaml")
	if r, o, _ := mergeFixtures(t, "count: 1\n", "count: 2\n", false); *r.Count != 2 {
		t.Errorf("count = %d, want the contract's", *r.Count)
	} else {
		wantFrom(t, o, "count", "contract.yaml")
	}
	if r, o, _ := mergeFixtures(t, "own: 1\n", "own: 2\n", false); r.Value != "" {
		t.Errorf("value no file wrote = %q", r.Value)
	} else {
		wantNoOrigin(t, o, "value")
	}

	// A yaml.Node key: the contract's empty mapping resets, a profile's is absent (gate, ask); an empty node is
	// absent in either file under emptyIsAbsent (docker).
	for _, tc := range []struct {
		name, p, c string
		node, opt  string // the merged node's yaml, "" for the zero node
	}{
		{"profile-inherited", "node: {a: 1}\nopt: {b: 2}\n", "value: v\n", "{a: 1}\n", "{b: 2}\n"},
		{"contract-replaces", "node: {a: 1}\nopt: {b: 2}\n", "node: {c: 3}\nopt: {d: 4}\n", "{c: 3}\n", "{d: 4}\n"},
		{"contract-empty", "node: {a: 1}\nopt: {b: 2}\n", "node: {}\nopt: {}\n", "{}\n", "{b: 2}\n"},
		{"profile-empty", "node: {}\nopt: {}\n", "value: v\n", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _, _ := mergeFixtures(t, tc.p, tc.c, false)
			for _, n := range []struct {
				key  string
				got  *yaml.Node
				want string
			}{{"node", &r.Node, tc.node}, {"opt", &r.Opt, tc.opt}} {
				got := ""
				if n.got.Kind != 0 {
					out, err := yaml.Marshal(n.got)
					if err != nil {
						t.Fatal(err)
					}
					got = string(out)
				}
				if got != n.want {
					t.Errorf("%s = %q, want %q", n.key, got, n.want)
				}
			}
		})
	}
}

// TestMergeClassContractWinsMapping: a mapping of class contract-wins (ADR 0065's check) is replaced whole: a
// contract that writes any of it takes none of the profile's keys, and the merged keys point at the contract only.
func TestMergeClassContractWinsMapping(t *testing.T) {
	r, o, _ := mergeFixtures(t, "whole: {value: a, list: [x]}\n", "whole: {value: b}\n", false)
	if r.Whole == nil || r.Whole.Value != "b" || r.Whole.List != nil {
		t.Fatalf("whole = %+v, want the contract's mapping alone", r.Whole)
	}
	wantFrom(t, o, "whole", "contract.yaml")
	wantFrom(t, o, "whole.value", "contract.yaml")
	wantNoOrigin(t, o, "whole.list")
	wantNoOrigin(t, o, "whole.list.0")
	if r, o, _ := mergeFixtures(t, "whole: {list: [x]}\n", "value: v\n", false); r.Whole == nil || !reflect.DeepEqual(r.Whole.List, []string{"x"}) {
		t.Errorf("whole = %+v, want the profile's mapping inherited", r.Whole)
	} else {
		wantFrom(t, o, "whole.list.0", "profile.yaml")
	}
	if _, problems := compileMergeTable(reflect.TypeFor[mergeFixture](), append(mergeFixtureRows[:len(mergeFixtureRows):len(mergeFixtureRows)],
		keyRow("whole.value", classContractWins))); len(problems) != 1 || !strings.Contains(problems[0], `no section row "whole"`) {
		t.Errorf("a row beneath a contract-wins mapping: %q, want it refused", problems)
	}
}

func TestMergeClassSection(t *testing.T) {
	if r, o, _ := mergeFixtures(t, "value: x\n", "value: y\n", false); r.Sec != nil {
		t.Errorf("a pointer section no file wrote merged as %+v, want nil", r.Sec)
	} else {
		wantFrom(t, o, "value", "contract.yaml")
		wantNoOrigin(t, o, "sec")
	}
	r, o, _ := mergeFixtures(t, "sec: {value: a, list: [x]}\nplain: {value: b}\n", "sec: {list: [y]}\n", false)
	if r.Sec == nil || r.Sec.Value != "a" || !reflect.DeepEqual(r.Sec.List, []string{"x", "y"}) || r.Plain.Value != "b" {
		t.Fatalf("sec = %+v plain = %+v: a section's keys merge by their own rows", r.Sec, r.Plain)
	}
	wantFrom(t, o, "sec", "contract.yaml")
	wantFrom(t, o, "sec.value", "profile.yaml")
	wantFrom(t, o, "sec.list.1", "contract.yaml")
	wantFrom(t, o, "plain", "profile.yaml")
	if r, _, _ := mergeFixtures(t, "value: x\n", "sec: {}\n", false); r.Sec == nil {
		t.Errorf("a section the contract wrote empty merged as nil")
	}
}

func TestMergeClassStricter(t *testing.T) {
	for _, tc := range []struct {
		name, p, c string
		mid        bool   // the contract is itself a profile (a middle file of the chain)
		reads      string // the merged reads
		sockets    bool
		from       string // the file reads' origin is in, "" for none
		warnAt     string // the file:line profile-cannot-loosen is warned at, "" for none
	}{
		{"profile-stricter", "reads: held\n", "reads: auto\n", false, "held", false, "profile.yaml", ""},
		{"contract-stricter", "reads: auto\n", "reads: held\n", false, "held", false, "contract.yaml", ""},
		{"tie-is-the-contracts", "reads: auto\n", "reads: auto\n", false, "auto", false, "contract.yaml", ""},
		{"profile-only", "reads: auto\n", "own: 1\n", false, "auto", false, "profile.yaml", ""},
		{"contract-only", "own: 1\n", "reads: auto\n", false, "auto", false, "contract.yaml", ""},
		{"contract-loosens-overrides", "reads: held\n", "reads: direct\n", false, "direct", false, "contract.yaml", ""},
		{"profile-loosens-ignored", "reads: direct\n", "own: 1\n", false, "", false, "", "profile.yaml:1"},
		{"profile-loosens-contract-stands", "reads: direct\n", "reads: auto\n", false, "auto", false, "contract.yaml", "profile.yaml:1"},
		{"middle-profile-loosens-ignored", "reads: held\n", "reads: direct\n", true, "held", false, "profile.yaml", "contract.yaml:1"},
		{"bool-contract-loosens", "sockets: false\n", "sockets: true\n", false, "", true, "", ""},
		{"bool-profile-loosens-ignored", "sockets: true\n", "own: 1\n", false, "", false, "", "profile.yaml:1"},
		{"bool-stricter-stands", "sockets: false\n", "own: 1\n", false, "", false, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, o, ds := mergeFixtures(t, tc.p, tc.c, tc.mid)
			if r.Reads != tc.reads || r.Sockets != tc.sockets {
				t.Fatalf("reads = %q sockets = %v, want %q %v", r.Reads, r.Sockets, tc.reads, tc.sockets)
			}
			if tc.from == "" {
				wantNoOrigin(t, o, "reads")
			} else {
				wantFrom(t, o, "reads", tc.from)
			}
			var warned []string
			for _, d := range ds {
				if d.Code == CodeProfileCannotLoosen && !d.IsError() {
					warned = append(warned, d.File+":"+strconv.Itoa(d.Line))
					if !strings.Contains(d.Fix, "top-level contract") {
						t.Errorf("fix %q does not name the top-level contract", d.Fix)
					}
				} else {
					t.Errorf("unexpected diagnostic %+v", d)
				}
			}
			if want := []string{tc.warnAt}; tc.warnAt == "" && len(warned) != 0 || tc.warnAt != "" && !reflect.DeepEqual(warned, want) {
				t.Errorf("profile-cannot-loosen at %q, want %q", warned, tc.warnAt)
			}
		})
	}
}

func TestMergeClassRefusedInProfile(t *testing.T) {
	r, o, ds := mergeFixtures(t, "own: 1\nrev: r1\n", "rev: r2\n", false)
	if r.Rev != "r2" || len(ds) != 1 {
		t.Fatalf("rev = %q, diagnostics %+v", r.Rev, ds)
	}
	d := ds[0]
	if !d.IsError() || d.Code != CodeSchema || d.File != "profile.yaml" || d.Line != 2 || d.Fix != "set rev in the top-level contract" {
		t.Errorf("a profile's rev: %+v, want a schema error at profile.yaml:2 with fix 'set rev in the top-level contract'", d)
	}
	wantFrom(t, o, "rev", "contract.yaml")
	if r, o, ds := mergeFixtures(t, "rev: r1\n", "own: 1\n", false); r.Rev != "" || len(ds) != 1 {
		t.Errorf("a profile's rev was inherited: %q %+v", r.Rev, ds)
	} else {
		wantNoOrigin(t, o, "rev")
	}
	if _, _, ds := mergeFixtures(t, "own: 1\n", "rev: r2\n", true); len(ds) != 1 || ds[0].File != "contract.yaml" {
		t.Errorf("a middle profile's rev: %+v, want one error at its own file", ds)
	}
	if r, _, ds := mergeFixtures(t, "own: 1\n", "rev: r2\n", false); r.Rev != "r2" || len(ds) != 0 {
		t.Errorf("the top-level contract's rev: %q %+v", r.Rev, ds)
	}
}

func TestMergeClassOwn(t *testing.T) {
	r, o, _ := mergeFixtures(t, "own: 1\n", "value: v\n", false)
	if r.Own != 0 {
		t.Fatalf("own = %d: the top file's own value is never inherited", r.Own)
	}
	wantNoOrigin(t, o, "own")
	if r, o, _ := mergeFixtures(t, "own: 1\n", "own: 2\n", false); r.Own != 2 {
		t.Errorf("own = %d, want the contract's", r.Own)
	} else {
		wantFrom(t, o, "own", "contract.yaml")
	}
}
