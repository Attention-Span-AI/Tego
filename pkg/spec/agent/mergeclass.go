// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// mergeClass is how one contract key combines across extends (R5, SEMANTICS §1, ADR 0065). Every key of Contract and
// of its sections has exactly one row in contractMergeRows naming its class, so a new key adds a row and the merge
// loop is not edited.
type mergeClass uint8

const (
	// classSection is a mapping whose own keys have rows: it is absent from the merge only when no file wrote it
	// (a pointer section stays nil), and its keys merge by their own rows.
	classSection mergeClass = iota + 1
	// classConcat is an ordered list: the profile's entries, then the contract's. An empty list a file writes
	// contributes no entry; the merged list is nil only when neither file wrote the key.
	classConcat
	// classUnion is a list of what a run is denied: every file's entries, the profile's first, and no rule of any
	// file removes an entry another file declared (fs.deny_read, R5's "never loses entries"). It combines as concat
	// does today; the class is what forbids a key from ever taking an override.
	classUnion
	// classKeyMerge is a map[string]string merged key-wise: the contract's value wins for a key both files set (env.set),
	// and a key two parents of one extends list set differently is extends-conflict (ADR 0066 D3).
	classKeyMerge
	// classContractWins is a value the contract replaces whole when it wrote the key, else the profile's when it did,
	// else the zero value. A list of this class (command) is one value.
	classContractWins
	// classStricter is a value from an ordered set (mergeRule.order, strictest first): across files the stricter
	// wins, the contract's on a tie. A value marked loosening counts only when the top-level contract writes it,
	// where it overrides; a profile that writes one has it ignored, warned profile-cannot-loosen at its line.
	classStricter
	// classRefusedInProfile is the top-level contract's alone: a profile that sets the key is a schema error at its
	// line, with the fix "set <key> in the top-level contract".
	classRefusedInProfile
	// classOwn is the top file's own value, never inherited, which a profile may still write for itself (version,
	// name: a profile is a file of its own; extends: the profile's names its own parent, already merged beneath it).
	classOwn
)

var mergeClassNames = [...]string{
	classSection:          "section",
	classConcat:           "concat",
	classUnion:            "union",
	classKeyMerge:         "keymerge",
	classContractWins:     "contract-wins",
	classStricter:         "stricter",
	classRefusedInProfile: "refused-in-profile",
	classOwn:              "own",
}

func (k mergeClass) String() string {
	if int(k) < len(mergeClassNames) && mergeClassNames[k] != "" {
		return mergeClassNames[k]
	}
	return "class(" + strconv.Itoa(int(k)) + ")"
}

// emptyNode says how a contract-wins yaml.Node key reads an empty node (agent-contract R5's `ask` note).
type emptyNode uint8

const (
	// emptyIsValue: an empty value is a value like any other. Every key that is no yaml.Node.
	emptyIsValue emptyNode = iota
	// emptyResetsInContract: the contract's empty mapping replaces the profile's (an explicit reset), while a
	// profile's empty mapping is absent, so nothing is inherited from it (gate, ask).
	emptyResetsInContract
	// emptyIsAbsent: an empty node is absent in either file (docker, schema-only).
	emptyIsAbsent
)

// mergeRule holds the parameters a row's class takes.
type mergeRule struct {
	// order is a stricter key's values, strictest first; loosening names those of them that count only from the
	// top-level contract. A written value outside order ranks below every listed one.
	order, loosening []string
	// empty is how a contract-wins yaml.Node key reads an empty node.
	empty emptyNode
	// code is a refused-in-profile key's diagnostic code, CodeSchema when "".
	code string
}

// mergeRow is one key's row: its dotted yaml path, its class and the class's parameters.
type mergeRow struct {
	path  string
	class mergeClass
	rule  mergeRule
}

// keyRow is a mergeRow with no parameters; stricterRow is a key of an ordered value set.
func keyRow(path string, class mergeClass) mergeRow { return mergeRow{path: path, class: class} }

func stricterRow(path string, order []string, loosening ...string) mergeRow {
	return mergeRow{path: path, class: classStricter, rule: mergeRule{order: order, loosening: loosening}}
}

// mergeTable is a set of rows compiled against the struct type they merge: each row knows its field and the
// section that holds it, and a section's rows follow it.
type mergeTable struct {
	root     reflect.Type
	rows     []tableRow
	sections int // section rows, each with its own slot
}

type tableRow struct {
	mergeRow
	field  int          // the field's index in its section's struct
	parent int          // the slot of the section holding the field; -1 for a key of the root
	slot   int          // a section's slot, -1 for any other row
	sub    reflect.Type // a section's struct type
}

// yamlKey is the key yaml.v3 reads a struct field under, "" for one it never reads.
func yamlKey(f reflect.StructField) string {
	if !f.IsExported() {
		return ""
	}
	tag := f.Tag.Get("yaml")
	if tag == "-" {
		return ""
	}
	key, _, _ := strings.Cut(tag, ",")
	if key == "" {
		key = strings.ToLower(f.Name)
	}
	return key
}

// sectionStruct is the struct type a section row recurses into, nil when typ is no section.
func sectionStruct(typ reflect.Type) reflect.Type {
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct || typ == reflect.TypeFor[yaml.Node]() {
		return nil
	}
	return typ
}

// compileMergeTable resolves rows against root and reports every row that names no key of it or whose class the
// key's type cannot take. Missing rows are mergeTableMissing's.
func compileMergeTable(root reflect.Type, rows []mergeRow) (*mergeTable, []string) {
	t := &mergeTable{root: root}
	var problems []string
	at := map[string]int{}
	for _, r := range rows {
		bad := func(format string, args ...any) {
			problems = append(problems, r.path+": "+fmt.Sprintf(format, args...))
		}
		if _, dup := at[r.path]; dup {
			bad("a second row for one key")
			continue
		}
		parent, st := -1, root
		if i := strings.LastIndexByte(r.path, '.'); i >= 0 {
			pi, ok := at[r.path[:i]]
			if !ok || t.rows[pi].class != classSection {
				bad("no section row %q before it", r.path[:i])
				continue
			}
			parent, st = t.rows[pi].slot, t.rows[pi].sub
		}
		key := r.path[strings.LastIndexByte(r.path, '.')+1:]
		field := -1
		for i := range st.NumField() {
			if yamlKey(st.Field(i)) == key {
				field = i
				break
			}
		}
		if field < 0 {
			bad("names no key of %s", st.Name())
			continue
		}
		typ := st.Field(field).Type
		if msg := classFits(r, typ); msg != "" {
			bad("%s", msg)
			continue
		}
		at[r.path] = len(t.rows)
		tr := tableRow{mergeRow: r, field: field, parent: parent, slot: -1}
		if r.class == classSection {
			tr.slot, tr.sub = t.sections, sectionStruct(typ)
			t.sections++
		}
		t.rows = append(t.rows, tr)
	}
	return t, problems
}

// classFits says why a key of type typ cannot take r's class, "" when it can.
func classFits(r mergeRow, typ reflect.Type) string {
	isNode := typ == reflect.TypeFor[yaml.Node]()
	if r.rule.empty != emptyIsValue && (r.class != classContractWins || !isNode) {
		return "an empty-node rule on a key that is no contract-wins yaml.Node"
	}
	if (len(r.rule.order) > 0 || len(r.rule.loosening) > 0) && r.class != classStricter {
		return "a value order on a key that is not stricter"
	}
	switch r.class {
	case classSection:
		if sectionStruct(typ) == nil {
			return fmt.Sprintf("a section row on a %s", typ)
		}
	case classConcat, classUnion:
		if typ.Kind() != reflect.Slice {
			return fmt.Sprintf("a %s row on a %s", r.class, typ)
		}
	case classKeyMerge:
		if typ != reflect.TypeFor[map[string]string]() {
			return fmt.Sprintf("a keymerge row on a %s: it merges a map[string]string", typ)
		}
	case classStricter:
		if typ.Kind() != reflect.String && typ.Kind() != reflect.Bool {
			return fmt.Sprintf("a stricter row on a %s: its values must be strings or booleans", typ)
		}
		if len(r.rule.order) < 2 {
			return "a stricter row orders fewer than two values"
		}
		for i, v := range r.rule.order {
			if slices.Contains(r.rule.order[:i], v) {
				return fmt.Sprintf("value %q ordered twice", v)
			}
		}
		for _, v := range r.rule.loosening {
			if !slices.Contains(r.rule.order, v) {
				return fmt.Sprintf("loosening value %q is not in its order", v)
			}
		}
	case classContractWins, classRefusedInProfile, classOwn:
	default:
		return fmt.Sprintf("unknown class %s", r.class)
	}
	return ""
}

// mergeTableMissing lists every key of root, by yaml tag and recursively through the section rows, that has no row.
func mergeTableMissing(t *mergeTable) []string {
	have := make(map[string]mergeClass, len(t.rows))
	for _, r := range t.rows {
		have[r.path] = r.class
	}
	var missing []string
	var walk func(st reflect.Type, prefix string)
	walk = func(st reflect.Type, prefix string) {
		for i := range st.NumField() {
			key := yamlKey(st.Field(i))
			if key == "" {
				continue
			}
			path := prefix + key
			class, ok := have[path]
			if !ok {
				missing = append(missing, path)
				continue
			}
			if sub := sectionStruct(st.Field(i).Type); sub != nil && class == classSection {
				walk(sub, path+".")
			}
		}
	}
	walk(t.root, "")
	return missing
}

// mustMergeTable compiles a table that must cover root exactly; a bad row is a programming error, which the
// table's own tests name first.
func mustMergeTable(root reflect.Type, rows []mergeRow) *mergeTable {
	t, problems := compileMergeTable(root, rows)
	problems = append(problems, mergeTableMissing(t)...)
	if len(problems) > 0 {
		panic("agent: merge table: " + strings.Join(problems, "; "))
	}
	return t
}

// merger carries the origins of one merge: the profile's and the contract's, indexed by prefix, and the merged
// contract's, which every row fills for the keys it merges so each merged entry still points at its file and line.
type merger struct {
	po, co origins
	pi, ci *originIndex
	out    origins
	// parents is set when the two files are sibling parents of one extends list (combineParents, ADR 0065 D4)
	// rather than a profile and the file laid over it: neither is the top-level contract, a stricter tie keeps the
	// first, and a contract-wins key both wrote with different values is a conflict, kept in conflicts.
	parents   bool
	conflicts []extendsConflict
	// scalars is set for a whole view (mergeScalars): the concat and union rows are left out.
	scalars bool
	// written is, when not nil, every contract-wins key the file laid on top wrote, which settles a conflict
	// between the parents beneath it.
	written map[string]bool
}

func newMerger(po, co origins) *merger {
	return &merger{po: po, co: co, pi: indexOrigins(po), ci: indexOrigins(co), out: origins{}}
}

// list records origins for a concatenated list: the profile's np entries first, then the contract's nc entries,
// renumbered, and the key itself.
func (m *merger) list(key string, np, nc int) {
	for i := range np {
		m.out.copyPrefix(key+"."+strconv.Itoa(i), m.pi, key+"."+strconv.Itoa(i))
	}
	for j := range nc {
		m.out.copyPrefix(key+"."+strconv.Itoa(np+j), m.ci, key+"."+strconv.Itoa(j))
	}
	m.key(key)
}

// key records where a list or mapping key itself was written, the contract's position first.
func (m *merger) key(key string) {
	if p, ok := m.co[key]; ok {
		m.out[key] = p
	} else if p, ok := m.po[key]; ok {
		m.out[key] = p
	}
}

// frame is a section's three values (profile, contract, merged) while its rows merge; an invalid r is a section
// no file wrote, whose rows are skipped.
type frame struct{ p, c, r reflect.Value }

// merge lays c over p into r, one row at a time: p, c and r are values of the table's root type, r zero.
func (t *mergeTable) merge(m *merger, p, c, r reflect.Value) {
	frames := make([]frame, t.sections)
	for i := range t.rows {
		row := &t.rows[i]
		f := frame{p, c, r}
		if row.parent >= 0 {
			if f = frames[row.parent]; !f.r.IsValid() {
				continue
			}
		}
		pf, cf, rf := f.p.Field(row.field), f.c.Field(row.field), f.r.Field(row.field)
		switch row.class {
		case classSection:
			frames[row.slot] = m.section(row.path, pf, cf, rf)
		case classConcat, classUnion:
			if !m.scalars {
				m.concat(row.path, pf, cf, rf)
			}
		case classKeyMerge:
			m.keyMerge(row.path, pf, cf, rf)
		case classContractWins:
			m.contractWins(row, pf, cf, rf)
		case classStricter:
			m.stricter(row, pf, cf, rf)
		case classOwn, classRefusedInProfile:
			// The contract's own value, and its position only: a profile's, refused or not, is never carried
			// (validateMerged asks the merged origins whether version was written).
			rf.Set(cf)
			if _, ok := m.co[row.path]; ok {
				m.out.copyPrefix(row.path, m.ci, row.path)
			}
		}
	}
}

// contractWins takes the contract's value when it wrote the key, else the profile's. Between two parents
// (m.parents) neither file is the top-level contract: one that alone wrote the key gives it, and two that wrote
// different values are a conflict, the first's value kept until the file naming them settles it.
func (m *merger) contractWins(row *tableRow, pf, cf, rf reflect.Value) {
	cw, pw := m.wrote(m.co, row, cf, !m.parents), m.wrote(m.po, row, pf, false)
	switch {
	case m.parents && cw && pw:
		if !sameValue(pf, cf) {
			m.conflicts = append(m.conflicts, extendsConflict{path: row.path, first: m.po[row.path], then: m.co[row.path]})
		}
		m.take(row.path, pf, rf, m.pi)
	case cw:
		m.take(row.path, cf, rf, m.ci)
		if m.written != nil {
			m.written[row.path] = true
		}
	case pw:
		m.take(row.path, pf, rf, m.pi)
	}
}

// section opens a section for its rows: a pointer section no file wrote stays nil.
func (m *merger) section(key string, pf, cf, rf reflect.Value) frame {
	if rf.Kind() == reflect.Pointer {
		if pf.IsNil() && cf.IsNil() {
			return frame{}
		}
		rf.Set(reflect.New(rf.Type().Elem()))
		pf, cf, rf = deref(pf), deref(cf), rf.Elem()
	}
	m.key(key)
	return frame{pf, cf, rf}
}

// deref is the struct a section pointer holds, a zero one for nil.
func deref(v reflect.Value) reflect.Value {
	if v.IsNil() {
		return reflect.New(v.Type().Elem()).Elem()
	}
	return v.Elem()
}

// concat appends the contract's entries to the profile's; nil stays nil when neither file wrote the key, and an
// explicitly empty list stays non-nil.
func (m *merger) concat(key string, pf, cf, rf reflect.Value) {
	if pf.IsNil() && cf.IsNil() {
		return
	}
	np, nc := pf.Len(), cf.Len()
	if ps, ok := pf.Addr().Interface().(*[]string); ok {
		// Most lists are []string: appended in place, without a reflect header for each.
		cs := cf.Addr().Interface().(*[]string)
		*rf.Addr().Interface().(*[]string) = append(append(make([]string, 0, np+nc), *ps...), *cs...)
	} else {
		rf.Set(reflect.AppendSlice(reflect.AppendSlice(reflect.MakeSlice(rf.Type(), 0, np+nc), pf), cf))
	}
	m.list(key, np, nc)
}

// keyMerge merges two string maps key-wise, the contract's value last so it wins. Between two parents (m.parents)
// neither file is the contract: a key both wrote with one value keeps the first's origin, and one they wrote with
// different values is a conflict, as a contract-wins key's is (ADR 0066 D3), the first's value kept until the file
// naming them settles it: a later profile's PATH or HTTPS_PROXY must never silently replace an earlier one's.
func (m *merger) keyMerge(key string, pf, cf, rf reflect.Value) {
	p, c := pf.Interface().(map[string]string), cf.Interface().(map[string]string)
	if p == nil && c == nil {
		return
	}
	r := make(map[string]string, len(p)+len(c))
	m.key(key)
	for k, v := range p {
		r[k] = v
		m.out.copyPrefix(key+"."+k, m.pi, key+"."+k)
	}
	var conflicts []string
	for k, v := range c {
		path := key + "." + k
		if pv, both := p[k]; m.parents && both {
			if pv != v {
				conflicts = append(conflicts, path)
			}
			continue
		}
		r[k] = v
		m.out.copyPrefix(path, m.ci, path)
		if m.written != nil {
			m.written[path] = true
		}
	}
	slices.Sort(conflicts)
	for _, path := range conflicts {
		m.conflicts = append(m.conflicts, extendsConflict{path: path, first: m.po[path], then: m.co[path]})
	}
	rf.Set(reflect.ValueOf(r))
}

// wrote reports whether the file whose origins o are wrote row's key, reading an empty node by row's rule.
func (m *merger) wrote(o origins, row *tableRow, v reflect.Value, contract bool) bool {
	if _, ok := o[row.path]; !ok {
		return false
	}
	switch row.rule.empty {
	case emptyIsValue:
		return true
	case emptyResetsInContract:
		return contract || !nodeIsEmpty(v)
	case emptyIsAbsent:
		return !nodeIsEmpty(v)
	}
	panic("agent: merge table: unknown empty-node rule")
}

// nodeIsEmpty reads a yaml.Node field in place (every merged field is addressable), so no node is copied.
func nodeIsEmpty(v reflect.Value) bool { return nodeEmpty(v.Addr().Interface().(*yaml.Node)) }

// take sets the merged key to v and copies its origins from x.
func (m *merger) take(key string, v, rf reflect.Value, x *originIndex) {
	rf.Set(v)
	m.out.copyPrefix(key, x, key)
}

// stricter keeps the stricter of two written values, the contract's on a tie, and the contract's loosening value
// over either; a profile's loosening value was refused at its own file (profileRules) and is not a candidate.
func (m *merger) stricter(row *tableRow, pf, cf, rf reflect.Value) {
	_, cw := m.co[row.path]
	_, pw := m.po[row.path]
	pw = pw && !row.loosens(pf)
	switch {
	case m.parents && cw && pw:
		// Two parents: the stricter, the first on a tie; neither's loosening value counts, each being a profile
		// (profileRules cleared any).
		if row.rank(cf) < row.rank(pf) {
			m.take(row.path, cf, rf, m.ci)
		} else {
			m.take(row.path, pf, rf, m.pi)
		}
	case cw && (!pw || row.loosens(cf) || row.rank(cf) <= row.rank(pf)):
		m.take(row.path, cf, rf, m.ci)
	case pw:
		m.take(row.path, pf, rf, m.pi)
	}
}

// stricterValue is a stricter key's value in the spelling its order lists.
func stricterValue(v reflect.Value) string {
	if v.Kind() == reflect.Bool {
		return strconv.FormatBool(v.Bool())
	}
	return v.String()
}

// rank is v's place in r's order, 0 the strictest; a value the order does not list ranks below every listed one.
func (r *tableRow) rank(v reflect.Value) int {
	if i := slices.Index(r.rule.order, stricterValue(v)); i >= 0 {
		return i
	}
	return len(r.rule.order)
}

// loosens reports whether v is a value r marks loosening, which counts only from the top-level contract.
func (r *tableRow) loosens(v reflect.Value) bool {
	return slices.Contains(r.rule.loosening, stricterValue(v))
}

// profileRules holds one profile file to the rules a profile alone is held to, at the file's own lines: a key of
// class refused-in-profile it sets is a schema error, and a loosening value it writes for a stricter key is
// ignored with a warning. Each is cleared from the file, so no merge carries it, and each file is reported once.
func (t *mergeTable) profileRules(v reflect.Value, o origins, ds *diags) {
	frames := make([]reflect.Value, t.sections)
	for i := range t.rows {
		row := &t.rows[i]
		parent := v
		if row.parent >= 0 {
			if parent = frames[row.parent]; !parent.IsValid() {
				continue
			}
		}
		f := parent.Field(row.field)
		pos, wrote := o[row.path]
		switch {
		case row.class == classSection:
			if f.Kind() == reflect.Pointer {
				if f.IsNil() {
					continue
				}
				f = f.Elem()
			}
			frames[row.slot] = f
			continue
		case !wrote:
			continue
		case row.class == classRefusedInProfile:
			code := row.rule.code
			if code == "" {
				code = CodeSchema
			}
			ds.errorf(pos, code, "%s is the top-level contract's own: a profile cannot set it", row.path).
				fix("set %s in the top-level contract", row.path)
		case row.class == classStricter && row.loosens(f):
			ds.warnf(pos, CodeProfileCannotLoosen, "%s: %s loosens it, which only the top-level contract can do: this profile's value is ignored", row.path, stricterValue(f)).
				fix("set %s: %s in the top-level contract, or remove it here", row.path, stricterValue(f))
		default:
			continue
		}
		f.Set(reflect.Zero(f.Type()))
		for k := range o {
			if k == row.path || strings.HasPrefix(k, row.path+".") {
				delete(o, k)
			}
		}
	}
}
