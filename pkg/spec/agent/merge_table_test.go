// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// TestExtendsNameRequiredAtTheTopFile: name is the top file's own (class own, ADR 0065), as version is. A contract
// with no name: that extends a profile writing one was refused "name is required" at the profile's name: line, a
// line that holds a name, because the merge carried the profile's origin of a value it did not carry.
func TestExtendsNameRequiredAtTheTopFile(t *testing.T) {
	_, ds, err := LoadBytes("child.yaml", []byte("version: 0\nextends: p\ncommand: [x]\n"), mapSource{"p": "version: 0\nname: base\n"})
	if err == nil {
		t.Fatalf("a contract with no name: loaded over a profile that writes one\n%s", render(ds))
	}
	for _, d := range ds {
		if strings.Contains(d.Message, "name is required") {
			if d.File != "child.yaml" || d.Line != 1 {
				t.Fatalf("name is required at %s:%d, want the top file child.yaml:1\n%s", d.File, d.Line, render(ds))
			}
			return
		}
	}
	t.Fatalf("no name is required diagnostic\n%s", render(ds))
}

// TestEveryContractKeyHasAMergeClass: every key of Contract and of its sections, by yaml tag and recursively through
// the section rows, has a row in the merge table (ADR 0065). A key a package adds with no row fails here, before
// any merge could treat it by accident; a fixture table with a row taken out shows the check names that key.
func TestEveryContractKeyHasAMergeClass(t *testing.T) {
	if missing := mergeTableMissing(contractTable); len(missing) != 0 {
		t.Errorf("contract keys with no merge class: %q: add each a row in contractMergeRows with the class ADR 0065 gives it", missing)
	}
	for _, drop := range []string{"reads", "sec.value", "plain.list"} {
		var rows []mergeRow
		for _, r := range mergeFixtureRows {
			if r.path != drop {
				rows = append(rows, r)
			}
		}
		tab, problems := compileMergeTable(reflect.TypeFor[mergeFixture](), rows)
		if len(problems) != 0 {
			t.Fatalf("without %s: %q", drop, problems)
		}
		if got := mergeTableMissing(tab); !reflect.DeepEqual(got, []string{drop}) {
			t.Errorf("a table without %s reports %q missing", drop, got)
		}
	}
}

// TestMergeTableRowsNameRealKeys: every row names a key of its section, after that section's own row, in a class the
// key's type can take. A row naming no key (a renamed tag, a typo) fails here rather than merge nothing.
func TestMergeTableRowsNameRealKeys(t *testing.T) {
	if _, problems := compileMergeTable(reflect.TypeFor[Contract](), contractMergeRows); len(problems) != 0 {
		t.Errorf("merge table rows: %q", problems)
	}
	for _, tc := range []struct {
		row  mergeRow
		dup  bool // keep the fixture's own row for the path too
		want string
	}{
		{keyRow("nope", classContractWins), false, "nope: names no key"},
		{keyRow("sec.nope", classContractWins), false, "sec.nope: names no key"},
		{keyRow("nope.list", classConcat), false, `nope.list: no section row "nope"`},
		{keyRow("value.x", classConcat), false, `value.x: no section row "value"`},
		{keyRow("list", classConcat), true, "list: a second row"},
		{keyRow("own", classSection), false, "own: a section row on a int"},
		{keyRow("value", classConcat), false, "value: a concat row on a string"},
		{keyRow("list", classKeyMerge), false, "list: a keymerge row"},
		{stricterRow("count", []string{"1", "2"}), false, "count: a stricter row on a *int"},
		{stricterRow("reads", []string{"held"}), false, "reads: a stricter row orders fewer than two values"},
		{stricterRow("reads", []string{"held", "auto", "held"}), false, `reads: value "held" ordered twice`},
		{stricterRow("reads", []string{"held", "auto"}, "direct"), false, `reads: loosening value "direct" is not in its order`},
		{mergeRow{path: "value", class: classContractWins, rule: mergeRule{empty: emptyIsAbsent}}, false, "value: an empty-node rule"},
		{mergeRow{path: "list", class: classConcat, rule: mergeRule{order: []string{"a", "b"}}}, false, "list: a value order"},
	} {
		var rows []mergeRow
		for _, r := range mergeFixtureRows {
			if r.path != tc.row.path || tc.dup {
				rows = append(rows, r)
			}
		}
		_, problems := compileMergeTable(reflect.TypeFor[mergeFixture](), append(rows, tc.row))
		if len(problems) != 1 || !strings.HasPrefix(problems[0], tc.want) {
			t.Errorf("row %+v: problems %q, want one starting %q", tc.row, problems, tc.want)
		}
	}
}

// TestContractMergeClassesADR0065 pins the classes R5 and ADR 0065 state for the keys whose class is a security
// property, so a row edited to a weaker class fails by name.
func TestContractMergeClassesADR0065(t *testing.T) {
	want := map[string]mergeClass{
		"version": classOwn, "name": classOwn, "extends": classOwn, "command": classContractWins,
		"fs": classSection, "fs.deny_read": classUnion, "fs.write": classConcat, "fs.assurance": classStricter,
		"exec.assurance": classStricter, "exec.allow": classConcat, "env.set": classKeyMerge, "tier": classContractWins,
		"net.assurance": classContractWins, "ask": classContractWins, "gate": classContractWins, "limits.memory": classContractWins,
	}
	got := map[string]mergeRow{}
	for _, r := range contractMergeRows {
		got[r.path] = r
	}
	for k, c := range want {
		if got[k].class != c {
			t.Errorf("%s is %s, want %s", k, got[k].class, c)
		}
	}
	for _, k := range []string{"fs.assurance", "exec.assurance"} {
		if r := got[k].rule; !reflect.DeepEqual(r.order, []string{"kernel", "best-effort"}) || len(r.loosening) != 0 {
			t.Errorf("%s orders %q loosening %q, want kernel over best-effort and none loosening", k, r.order, r.loosening)
		}
	}
}

// TestR5ListsEveryMergeClassRow: agent-contract R5's class table names every key of the merge table under its class,
// and nothing else, so the spec a profile author reads is the table the merge runs.
func TestR5ListsEveryMergeClassRow(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "p0", "agent-contract.md"))
	if err != nil {
		t.Fatal(err)
	}
	const marker = "**Merge classes (R5).**"
	_, after, ok := strings.Cut(string(src), marker)
	if !ok {
		t.Fatalf("agent-contract.md has no %q table", marker)
	}
	doc := map[string]string{}
	inTable := false
	for _, line := range strings.Split(after, "\n") {
		if !strings.HasPrefix(line, "|") {
			if inTable {
				break
			}
			continue
		}
		inTable = true
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if len(cells) < 2 || !strings.HasPrefix(strings.TrimSpace(cells[0]), "`") {
			continue
		}
		class := strings.Trim(strings.TrimSpace(cells[0]), "`")
		// A keys cell lists backticked keys; prose in it (a class no key takes yet) names none.
		for _, k := range strings.Split(cells[1], ",") {
			if k = strings.TrimSpace(k); len(k) > 2 && strings.HasPrefix(k, "`") && strings.HasSuffix(k, "`") {
				doc[strings.Trim(k, "`")] = class
			}
		}
	}
	code := map[string]string{}
	byClass := map[mergeClass][]string{}
	for _, r := range contractMergeRows {
		code[r.path] = r.class.String()
		byClass[r.class] = append(byClass[r.class], "`"+r.path+"`")
	}
	if !reflect.DeepEqual(doc, code) {
		var want strings.Builder
		for k := classSection; k <= classOwn; k++ {
			fmt.Fprintf(&want, "| `%s` | %s |\n", k, strings.Join(byClass[k], ", "))
		}
		t.Errorf("R5's merge class table does not match contractMergeRows; the table's rows are:\n%s", want.String())
	}
}

// TestContractWinsSwitchesAreRecorded: a boolean key of class contract-wins is a switch a profile can turn on for
// every contract that extends it, where host_sockets' class (stricter, true loosening) would ignore the profile's
// true. ADR 0065 D6 names each such switch and why it stays contract-wins, so a package that adds one with that class
// fails here until the ADR records the choice; every key D6 lists is a row of the class it gives.
func TestContractWinsSwitchesAreRecorded(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "adr", "0065-contract-merge-classes.md"))
	if err != nil {
		t.Fatal(err)
	}
	const marker = "**D6."
	_, after, ok := strings.Cut(string(src), marker)
	if !ok {
		t.Fatalf("ADR 0065 has no %q decision", marker)
	}
	listed := map[string]string{}
	inTable := false
	for _, line := range strings.Split(after, "\n") {
		if !strings.HasPrefix(line, "|") {
			if inTable {
				break
			}
			continue
		}
		inTable = true
		cells := strings.Split(strings.Trim(line, "|"), "|")
		if key := strings.TrimSpace(cells[0]); len(cells) >= 2 && len(key) > 2 && strings.HasPrefix(key, "`") {
			listed[strings.Trim(key, "`")] = strings.Trim(strings.TrimSpace(cells[1]), "`")
		}
	}
	slotType := map[int]reflect.Type{}
	byPath := map[string]tableRow{}
	for _, r := range contractTable.rows {
		byPath[r.path] = r
		if r.class == classSection {
			slotType[r.slot] = r.sub
		}
	}
	for _, r := range contractTable.rows {
		st := contractTable.root
		if r.parent >= 0 {
			st = slotType[r.parent]
		}
		if r.class == classContractWins && st.Field(r.field).Type.Kind() == reflect.Bool {
			if _, ok := listed[r.path]; !ok {
				t.Errorf("%s is a contract-wins switch a profile can turn on; ADR 0065 D6 does not record why it is not stricter with true loosening", r.path)
			}
		}
	}
	for key, class := range listed {
		switch r, ok := byPath[key]; {
		case !ok:
			t.Errorf("ADR 0065 D6 lists %s, which has no row in the merge table", key)
		case r.class.String() != class:
			t.Errorf("ADR 0065 D6 lists %s as %s; the merge table has %s", key, class, r.class)
		}
	}
}

// TestLoadHoldsProfilesToTheirRules runs the profile rules through Load with tier taken as refused-in-profile and
// record as a stricter key with one loosening value, so the wiring every V1 key of those classes relies on is
// exercised before one exists: a profile's (bottom or middle) is reported at its own line once; the top file's
// counts.
func TestLoadHoldsProfilesToTheirRules(t *testing.T) {
	saved := contractTable
	t.Cleanup(func() { contractTable = saved })
	var rows []mergeRow
	for _, r := range contractMergeRows {
		switch r.path {
		case "tier":
			r = keyRow("tier", classRefusedInProfile)
		case "record":
			r = stricterRow("record", []string{"full", "summary", "off"}, "off")
		}
		rows = append(rows, r)
	}
	contractTable = mustMergeTable(reflect.TypeFor[Contract](), rows)

	profiles := mapSource{
		"base": "version: 0\ntier: landlock\nrecord: off\n",
		"mid":  "version: 0\nextends: base\nrecord: off\n",
	}
	_, ds, err := LoadBytes("child.yaml", []byte("version: 0\nname: a\nextends: mid\ncommand: [x]\n"), profiles)
	if err == nil {
		t.Fatalf("a profile setting a refused-in-profile key loaded\n%s", render(ds))
	}
	var got []string
	for _, d := range ds {
		got = append(got, d.Severity+" "+d.File+":"+strconv.Itoa(d.Line)+" "+d.Code)
	}
	want := []string{
		"error profiles/base.yaml:2 schema",
		"warning profiles/base.yaml:3 profile-cannot-loosen",
		"warning profiles/mid.yaml:3 profile-cannot-loosen",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("diagnostics %q, want %q\n%s", got, want, render(ds))
	}

	c, ds, err := LoadBytes("child.yaml", []byte("version: 0\nname: a\nextends: p\ncommand: [x]\ntier: landlock\nrecord: off\n"),
		mapSource{"p": "version: 0\nrecord: full\n"})
	if err != nil || c.Tier != "landlock" || c.Record != "off" {
		t.Fatalf("the top-level contract's tier and loosening record: %+v %v\n%s", c, err, render(ds))
	}
}
