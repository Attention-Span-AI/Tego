// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Hidden is what a page shows in place of an env.set value.
const Hidden = "(value hidden)"

// Shown is the contract's text and compile table as a page may show them: every env.set value is replaced by
// Hidden, so the raw details of the Rules page carry variable names and never a value (env.set values are often
// secrets; inforce's env group names them the same way). The text keeps its line count, so a position that names a
// copy line still points at the same line.
func (c Contract) Shown() (text, table string) {
	text, table = RedactEnvText(c.Text), c.Table
	if c.Compiled != nil && len(c.Compiled.Set) > 0 {
		table = redactEnvTable(table, c.Compiled.Set)
	}
	return text, table
}

// Unreadable is the first line a page shows in place of a contract text that names "set" but does not parse as YAML:
// the env.set values cannot be found in it, so none of it is shown (fail closed).
const Unreadable = "# (text hidden: it could not be read as YAML, so its env.set values could not be found)"

// RedactEnvText is a contract's YAML text with each value of its env.set mapping replaced by Hidden, line for line:
// a value that spans lines (a block scalar, a quoted scalar folded over lines, a flow mapping over lines) keeps its
// lines, emptied. An alias in env.set also hides the anchored value it names wherever that is defined, and env or
// set reached through an alias or a merge key (<<) is found there. Text that names "set" but does not parse comes
// back as Unreadable followed by empty lines; text that is not a mapping, or holds no env.set, comes back unchanged.
func RedactEnvText(text string) string {
	if !strings.Contains(text, "set") {
		return text
	}
	var doc yaml.Node
	if yaml.Unmarshal([]byte(text), &doc) != nil {
		blank := make([]string, strings.Count(text, "\n")+1)
		blank[0] = Unreadable
		return strings.Join(blank, "\n")
	}
	if len(doc.Content) == 0 {
		return text
	}
	set := mapValue(mapValue(doc.Content[0], "env"), "set")
	if set == nil {
		return text
	}
	r := redactor{lines: strings.Split(text, "\n"), starts: keyLines(doc.Content[0]), seen: map[*yaml.Node]bool{}}
	r.node(set, set.Column-1)
	return strings.Join(r.lines, "\n")
}

// redactor empties values in a contract's lines, keeping the line count.
type redactor struct {
	lines []string
	// starts is the sorted lines every mapping key starts on.
	starts []int
	// seen guards against hiding one anchored node twice (and against a cycle).
	seen map[*yaml.Node]bool
}

// node hides n, the value of a key at column indent+1: a block mapping's values one by one (its keys, variable
// names, stay), a scalar from its column, and a flow node or anything else as one span. An alias is hidden and so is
// the anchored node it names.
func (r *redactor) node(n *yaml.Node, indent int) {
	if n == nil || r.seen[n] {
		return
	}
	r.seen[n] = true
	switch {
	case n.Kind == yaml.AliasNode:
		r.hide(n.Line, n.Column, indent, Hidden)
		// The anchored node may sit under any key at any depth; indent 0 empties every continuation line of it.
		r.node(n.Alias, 0)
	case n.Kind == yaml.ScalarNode && n.Tag == "!!null":
		// "set:" with nothing: no value to hide.
	case n.Kind == yaml.ScalarNode:
		r.hide(n.Line, n.Column, indent, Hidden)
	case n.Kind == yaml.MappingNode && n.Style&yaml.FlowStyle == 0:
		for i := 0; i+1 < len(n.Content); i += 2 {
			r.node(n.Content[i+1], n.Content[i].Column-1)
		}
	default:
		// A flow mapping ({A: x, B: y}) over one line or many, a sequence or anything else: hide the whole node.
		r.span(n)
	}
}

// hide empties line l from column col (1-based) to its end and puts with in its place, then empties every later
// line of the value: each line before the next key that is blank or indented deeper than indent.
func (r *redactor) hide(l, col, indent int, with string) {
	if l < 1 || l > len(r.lines) {
		return
	}
	if ln := r.lines[l-1]; col-1 <= len(ln) {
		r.lines[l-1] = ln[:col-1] + with
	}
	for k := l + 1; k < r.nextKey(l) && k <= len(r.lines); k++ {
		if s := r.lines[k-1]; strings.TrimSpace(s) == "" || len(s)-len(strings.TrimLeft(s, " \t")) > indent {
			r.lines[k-1] = ""
		}
	}
}

// span hides n and every line after its first up to the first key after its last descendant, which holds its
// closing bracket: n's own keys are inside that range, so no value of it survives on a later line.
func (r *redactor) span(n *yaml.Node) {
	l := n.Line
	if l < 1 || l > len(r.lines) {
		return
	}
	if ln := r.lines[l-1]; n.Column-1 <= len(ln) {
		r.lines[l-1] = ln[:n.Column-1] + "{" + Hidden + "}"
	}
	for k := l + 1; k < r.nextKey(lastLine(n)) && k <= len(r.lines); k++ {
		r.lines[k-1] = ""
	}
}

// nextKey is the first key line after line l, one past the last line when there is none.
func (r *redactor) nextKey(l int) int {
	if i := sort.SearchInts(r.starts, l+1); i < len(r.starts) {
		return r.starts[i]
	}
	return len(r.lines) + 1
}

// lastLine is the greatest line n or any node under it starts on.
func lastLine(n *yaml.Node) int {
	l := n.Line
	for _, c := range n.Content {
		l = max(l, lastLine(c))
	}
	return l
}

// mapValue is the value of key in the mapping m, nil when m is not a mapping or has no such key. An alias is
// followed, and a key the mapping merges in (<<: *base, or a list of them) counts as its own.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m != nil && m.Kind == yaml.AliasNode {
		m = m.Alias
	}
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key && m.Content[i].Tag != "!!merge" {
			return m.Content[i+1]
		}
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Tag != "!!merge" {
			continue
		}
		merged := []*yaml.Node{m.Content[i+1]}
		if v := m.Content[i+1]; v.Kind == yaml.SequenceNode {
			merged = v.Content
		}
		for _, b := range merged {
			if v := mapValue(b, key); v != nil {
				return v
			}
		}
	}
	return nil
}

// keyLines is the sorted lines every mapping key of n starts on: where the value before it ends at the latest.
func keyLines(n *yaml.Node) []int {
	var out []int
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.MappingNode {
			for i := 0; i < len(n.Content); i += 2 {
				out = append(out, n.Content[i].Line)
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(n)
	sort.Ints(out)
	return out
}

// redactEnvTable replaces the set= field of agent.PrintRuleTable's env line (its last field) with the names alone.
func redactEnvTable(table string, set map[string]string) string {
	names := make([]string, 0, len(set))
	for k := range set {
		names = append(names, k+"="+Hidden)
	}
	sort.Strings(names)
	lines := strings.Split(table, "\n")
	for i, l := range lines {
		if !strings.HasPrefix(strings.TrimLeft(l, " "), "env ") {
			continue
		}
		if j := strings.Index(l, " set="); j >= 0 {
			lines[i] = l[:j] + " set=" + strings.Join(names, ",")
		}
	}
	return strings.Join(lines, "\n")
}
