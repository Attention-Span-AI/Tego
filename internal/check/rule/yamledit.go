// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

// Change is one list edit: Entry added to, or removed from, the list at Key ("fs.deny_read", "exec.allow"). A removal
// takes every item of the list that spells Entry: a file may list an entry twice (compile warns redundant-rule), and a
// copy left would keep the rule.
type Change struct {
	Remove bool
	Key    string
	Entry  string
	// Comment is the line comment an added entry carries.
	Comment string
}

// String is the change as one line: "fs.deny_read += ./secret.txt".
func (c Change) String() string {
	if c.Remove {
		return c.Key + " -= " + c.Entry
	}
	return c.Key + " += " + c.Entry
}

// NetAdded is the entries changes add to net.allow or net.ask, in order: the destinations a change allows or asks
// about, which the next run resolves at its start where they name a host.
func NetAdded(changes []Change) []string {
	var out []string
	for _, c := range changes {
		if !c.Remove && (c.Key == "net.allow" || c.Key == "net.ask") {
			out = append(out, c.Entry)
		}
	}
	return out
}

// parse reads text as one YAML document whose top is a mapping.
func parse(text []byte) (*yaml.Node, *yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(text, &doc); err != nil {
		return nil, nil, fmt.Errorf("the contract is not YAML: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, nil, errors.New("the contract is not a YAML mapping")
	}
	return &doc, doc.Content[0], nil
}

// encode is the node tree as text, two spaces an indent level.
func encode(doc *yaml.Node) ([]byte, error) {
	var b bytes.Buffer
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// lookup is m's value for key and its key node's index, nil when m is not a mapping or has no such key.
func lookup(m *yaml.Node, key string) (*yaml.Node, int) {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, -1
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1], i
		}
	}
	return nil, -1
}

// list is the scalar values of the list at a dotted key ("fs.write"), nil when absent.
func list(top *yaml.Node, key string) []string {
	sec, field, _ := strings.Cut(key, ".")
	m, _ := lookup(top, sec)
	s, _ := lookup(m, field)
	if s == nil || s.Kind != yaml.SequenceNode {
		return nil
	}
	out := make([]string, 0, len(s.Content))
	for _, n := range s.Content {
		if n.Kind == yaml.ScalarNode {
			out = append(out, n.Value)
		}
	}
	return out
}

// spells reports whether the list item n is the entry: a scalar whose value it is, as list reads it.
func spells(n *yaml.Node, entry string) bool { return n.Kind == yaml.ScalarNode && n.Value == entry }

// copies is how many items of the list s spell entry.
func copies(s *yaml.Node, entry string) int {
	n := 0
	for _, it := range s.Content {
		if spells(it, entry) {
			n++
		}
	}
	return n
}

// has reports whether the dotted key is present (a list, even empty, or a null).
func has(top *yaml.Node, key string) bool {
	sec, field, _ := strings.Cut(key, ".")
	m, _ := lookup(top, sec)
	if field == "" {
		return m != nil
	}
	s, _ := lookup(m, field)
	return s != nil
}

// dropEmptied reports whether the list at key, its last entry removed from section m, loses its key instead of
// becoming `[]`: fs.deny_read always (`deny_read: []` would switch the built-in list off), and an ask list
// (fs.ask_read, fs.ask, net.ask) when its section keeps another key, since an empty ask list says nothing (a
// section left with no key at all would read as null, which for net: is a different contract).
func dropEmptied(key string, m *yaml.Node) bool {
	switch key {
	case "fs.deny_read":
		return true
	case "fs.ask_read", "fs.ask", "net.ask":
		return m != nil && len(m.Content) > 2
	}
	return false
}

// applyTree makes c on the tree. A removal takes every item that spells the entry. A new list key goes first in its
// section, a new section last in the file; a list left empty is `[]`, except one dropEmptied drops (fs.deny_read:
// `deny_read: []` would switch the built-in list off).
func applyTree(top *yaml.Node, c Change) error {
	sec, field, _ := strings.Cut(c.Key, ".")
	m, _ := lookup(top, sec)
	if c.Remove {
		s, si := lookup(m, field)
		if s == nil || s.Kind != yaml.SequenceNode {
			return fmt.Errorf("the contract has no %s list", c.Key)
		}
		n := len(s.Content)
		s.Content = slices.DeleteFunc(s.Content, func(it *yaml.Node) bool { return spells(it, c.Entry) })
		switch {
		case len(s.Content) == n:
			return fmt.Errorf("%s has no entry %q", c.Key, c.Entry)
		case len(s.Content) > 0:
		case dropEmptied(c.Key, m):
			m.Content = append(m.Content[:si], m.Content[si+2:]...)
		default:
			s.Style = yaml.FlowStyle
		}
		return nil
	}
	if m == nil || m.Kind == yaml.ScalarNode && m.Tag == "!!null" {
		if m == nil {
			m = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			top.Content = append(top.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: sec}, m)
		} else {
			*m = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		}
	}
	if m.Kind != yaml.MappingNode {
		return fmt.Errorf("the contract's %s: is not a mapping", sec)
	}
	m.Style &^= yaml.FlowStyle
	s, _ := lookup(m, field)
	if s == nil {
		s = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		m.Content = append([]*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: field}, s}, m.Content...)
	} else if s.Kind == yaml.ScalarNode && s.Tag == "!!null" {
		*s = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	}
	if s.Kind != yaml.SequenceNode {
		return fmt.Errorf("the contract's %s is not a list", c.Key)
	}
	s.Style &^= yaml.FlowStyle
	s.Content = append(s.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: c.Entry, LineComment: c.Comment})
	return nil
}

// edit applies the changes to text one at a time: each is spliced into the text where that keeps every other byte
// and the result parses to the tree the change makes; otherwise the tree is written out whole (comments and order
// kept, indentation made two spaces).
func edit(text []byte, changes []Change) ([]byte, error) {
	cur := text
	for _, c := range changes {
		doc, top, err := parse(cur)
		if err != nil {
			return nil, err
		}
		before := cloneLines(cur)
		if err := applyTree(top, c); err != nil {
			return nil, err
		}
		want, err := encode(doc)
		if err != nil {
			return nil, err
		}
		if spliced, ok := splice(before, c); ok && sameData(spliced, want) {
			cur = spliced
			continue
		}
		cur = want
	}
	return cur, nil
}

// sameData reports whether a and b parse to the same tree, comments aside: a splice keeps each comment on the line
// it was written on, where the tree's encoder may move it.
func sameData(a, b []byte) bool {
	bare := func(text []byte) []byte {
		doc, _, err := parse(text)
		if err != nil {
			return nil
		}
		var strip func(n *yaml.Node)
		strip = func(n *yaml.Node) {
			n.HeadComment, n.LineComment, n.FootComment = "", "", ""
			for _, c := range n.Content {
				strip(c)
			}
		}
		strip(doc)
		out, _ := encode(doc)
		return out
	}
	ta := bare(a)
	return ta != nil && bytes.Equal(ta, bare(b))
}

func cloneLines(b []byte) []byte { return append([]byte(nil), b...) }

// scalarText is entry as a plain or quoted one-line YAML scalar.
func scalarText(entry string) (string, bool) {
	b, err := yaml.Marshal(entry)
	if err != nil {
		return "", false
	}
	s := strings.TrimSuffix(string(b), "\n")
	return s, !strings.Contains(s, "\n")
}

// parserLines is text cut after each "\n", and whether those are the lines the parser numbers: lines[n.Line-1] is
// then the line a node n says it is on. They are for UTF-8 text that ends its lines with LF or CR LF. The parser
// (yaml.v3, which reads YAML 1.1's line breaks) also ends a line at a CR no LF follows, at NEL (U+0085), LS (U+2028)
// and PS (U+2029), and it decodes UTF-16 behind a byte order mark: a node of such a text names another of these
// lines, or none, so ok is false and nothing is read by line from it.
func parserLines(text []byte) (lines []string, ok bool) {
	s := string(text)
	if !utf8.ValidString(s) {
		return nil, false
	}
	for i, r := range s {
		switch r {
		case '\r':
			if !strings.HasPrefix(s[i+1:], "\n") {
				return nil, false
			}
		case 0x85, 0x2028, 0x2029:
			return nil, false
		}
	}
	return strings.SplitAfter(s, "\n"), true
}

// splice makes c in the text itself: an entry added after the last item of a block list, or a new list key put first
// in a block section, or a new section at the end; an entry removed with its own line, each copy's. ok is false where
// it cannot say the edit is that simple, and for a text whose lines are not the parser's (parserLines), where a
// node's Line would be read from another line; what it does make, edit checks against the tree anyway.
func splice(text []byte, c Change) ([]byte, bool) {
	_, top, err := parse(text)
	if err != nil {
		return nil, false
	}
	lines, ok := parserLines(text)
	if !ok {
		return nil, false
	}
	sec, field, _ := strings.Cut(c.Key, ".")
	m, _ := lookup(top, sec)
	if c.Remove {
		s, si := lookup(m, field)
		if s != nil && s.Kind == yaml.SequenceNode && s.Style&yaml.FlowStyle != 0 {
			if k, n := m.Content[si], copies(s, c.Entry); n > 0 && n == len(s.Content) && dropEmptied(c.Key, m) &&
				k.Line == s.Line && k.Line >= 1 && k.Line <= len(lines) {
				// The key's whole line goes, as the tree drops the key (sameData checks it).
				return []byte(strings.Join(append(lines[:k.Line-1:k.Line-1], lines[k.Line:]...), "")), true
			}
			return spliceFlow(lines, m.Content[si], s, c.Entry, "")
		}
		if s == nil || s.Kind != yaml.SequenceNode {
			return nil, false
		}
		var drop []int // each copy's line, 0-based, in file order
		for i, n := range s.Content {
			if !spells(n, c.Entry) {
				continue
			}
			if n.Line < 1 || n.Line > len(lines) || i+1 < len(s.Content) && s.Content[i+1].Line == n.Line {
				return nil, false
			}
			if _, ok := itemDash(lines[n.Line-1], n.Column); !ok {
				return nil, false
			}
			drop = append(drop, n.Line-1)
		}
		switch {
		case len(drop) == 0:
			return nil, false
		case len(drop) < len(s.Content):
			out := make([]string, 0, len(lines)-len(drop))
			for i, l := range lines {
				if !slices.Contains(drop, i) {
					out = append(out, l)
				}
			}
			return []byte(strings.Join(out, "")), true
		}
		// Every item goes: the key's line and the items' lines, which follow it one to a line, become `field: []`,
		// or go with the key.
		k := m.Content[si]
		for j, l := range drop {
			if k.Line < 1 || l != k.Line+j {
				return nil, false
			}
		}
		var repl []string
		if !dropEmptied(c.Key, m) {
			repl = []string{strings.Repeat(" ", k.Column-1) + field + ": []\n"}
		}
		out := append(append(append([]string{}, lines[:k.Line-1]...), repl...), lines[k.Line+len(drop):]...)
		return []byte(strings.Join(out, "")), true
	}
	item, ok := scalarText(c.Entry)
	if !ok {
		return nil, false
	}
	if c.Comment != "" {
		item += " " + c.Comment
	}
	if m == nil {
		if len(lines) > 0 && !strings.HasSuffix(lines[len(lines)-1], "\n") {
			lines[len(lines)-1] += "\n"
		}
		return []byte(strings.Join(lines, "") + sec + ":\n  " + field + ":\n    - " + item + "\n"), true
	}
	if m.Kind != yaml.MappingNode || m.Style&yaml.FlowStyle != 0 || len(m.Content) == 0 {
		return nil, false
	}
	s, si := lookup(m, field)
	if s == nil {
		k := m.Content[0]
		if k.Line < 1 || k.Line > len(lines) {
			return nil, false
		}
		ind := strings.Repeat(" ", k.Column-1)
		add := ind + field + ":\n" + ind + "  - " + item + "\n"
		out := append(append(append([]string{}, lines[:k.Line-1]...), add), lines[k.Line-1:]...)
		return []byte(strings.Join(out, "")), true
	}
	if s.Kind == yaml.SequenceNode && s.Style&yaml.FlowStyle != 0 {
		return spliceFlow(lines, m.Content[si], s, "", item)
	}
	if s.Kind != yaml.SequenceNode || len(s.Content) == 0 {
		return nil, false
	}
	last := s.Content[len(s.Content)-1]
	if last.Kind != yaml.ScalarNode || last.Line < 1 || last.Line > len(lines) {
		return nil, false
	}
	d, ok := itemDash(lines[last.Line-1], last.Column)
	if !ok {
		return nil, false
	}
	add := lines[last.Line-1][:d] + "- " + item + "\n"
	out := append(append(append([]string{}, lines[:last.Line]...), add), lines[last.Line:]...)
	return []byte(strings.Join(out, "")), true
}

// spliceFlow edits a one-line flow list (`allow: ["bash", "date"]  # note`, as tego init writes them) in place: remove
// drops that item, each copy of it, from the brackets; a non-empty add instead turns the list into a block list under
// its key, the rest of the key's line (its comment) kept, as the tree edit does. ok is false for a list over several
// lines or an item it cannot delimit; edit checks the result against the tree either way.
func spliceFlow(lines []string, k, s *yaml.Node, remove, add string) ([]byte, bool) {
	if k.Line != s.Line || s.Line < 1 || s.Line > len(lines) || s.Column < 1 {
		return nil, false
	}
	line, open := lines[s.Line-1], s.Column-1
	if open >= len(line) || line[open] != '[' {
		return nil, false
	}
	var items []string
	end := open + 1
	for _, n := range s.Content {
		st := n.Column - 1
		if n.Kind != yaml.ScalarNode || n.Line != s.Line || st < end || st >= len(line) {
			return nil, false
		}
		end = flowItemEnd(line, st)
		if end < 0 {
			return nil, false
		}
		if n.Value != remove {
			items = append(items, line[st:end])
		}
		if j := end + len(line[end:]) - len(strings.TrimLeft(line[end:], " ")); j < len(line) && line[j] == ',' {
			end = j + 1
		}
	}
	end += len(line[end:]) - len(strings.TrimLeft(line[end:], " "))
	if end >= len(line) || line[end] != ']' {
		return nil, false
	}
	out := append([]string{}, lines[:s.Line-1]...)
	if add == "" {
		out = append(out, line[:open]+"["+strings.Join(items, ", ")+"]"+line[end+1:])
	} else {
		ind := strings.Repeat(" ", k.Column-1) + "  - "
		out = append(out, strings.TrimRight(line[:open], " ")+line[end+1:])
		for _, it := range append(items, add) {
			out = append(out, ind+it+"\n")
		}
	}
	return []byte(strings.Join(append(out, lines[s.Line:]...), "")), true
}

// flowItemEnd is where the flow-list scalar starting at line[i] ends (a quoted one at its closing quote), -1 if it
// does not end on the line.
func flowItemEnd(line string, i int) int {
	switch q := line[i]; q {
	case '"', '\'':
		for j := i + 1; j < len(line); j++ {
			switch {
			case q == '"' && line[j] == '\\':
				j++
			case line[j] == q && q == '\'' && j+1 < len(line) && line[j+1] == q:
				j++
			case line[j] == q:
				return j + 1
			}
		}
		return -1
	}
	k := strings.IndexAny(line[i:], ",]")
	if k < 0 {
		return -1
	}
	return i + len(strings.TrimRight(line[i:i+k], " "))
}

// itemDash is where the dash of a one-item line "<indent>-  value" is, the value starting at column col (1-based);
// ok is false for any other line, and for a column past the line's end (the byte before the value, a space after
// the dash, must be in the line), so no byte outside the line is read.
func itemDash(line string, col int) (int, bool) {
	d := col - 2
	if d < 1 || d >= len(line) {
		return 0, false
	}
	for d > 0 && line[d-1] == ' ' {
		d--
	}
	d--
	if d < 0 || line[d] != '-' || line[d+1] != ' ' || strings.TrimLeft(line[:d], " ") != "" {
		return 0, false
	}
	return d, true
}
