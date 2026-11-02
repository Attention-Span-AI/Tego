// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"errors"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// setWord finds the word set in text that is not one YAML document, where a key may wrap it in any of YAML's ways:
// plain or quoted, at a line's start or after "{" or "," (a flow mapping), tagged (!!str set), explicit (? set),
// anchored, before a comment. A word that merely holds the letters (assets/, settings.json, reset) is not one.
var setWord = regexp.MustCompile(`\bset\b`)

// setSpelled finds what could spell a "set" key without its three letters side by side: a double-quoted escape that
// spells a letter ("s\x65t", "\u0073et", "\U00000073et") or joins two lines into one word ("se\" at a line's end,
// before any line break YAML counts: LF, CR, NEL, LS or PS), or a zero byte (UTF-16, which YAML reads too, puts one
// beside each of the letters).
var setSpelled = regexp.MustCompile(`\\[xuU\n\r\x{85}\x{2028}\x{2029}]|\x00`)

// SetsEnv says whether a contract text sets environment values (an env.set key). parsed says the text read as one
// YAML document (parseOne: a second one, which the compiler refuses, is not read past); when it did not, sets is true
// whenever the text could spell a "set" key (setWord, setSpelled), so an unreadable text is held back whenever it may
// hold a value, and a parse error in an ordinary text still reaches its line diagnostics.
func SetsEnv(text string) (sets, parsed bool) {
	doc, err := parseOne(text)
	if err != nil {
		return setWord.MatchString(text) || setSpelled.MatchString(text), false
	}
	if len(doc.Content) == 0 {
		return false, true
	}
	return mapValue(mapValue(doc.Content[0], "env"), "set") != nil, true
}

// ErrEnvEdit is a free edit that changes env.set beyond removing variables: a page never shows or carries a value, so
// a value is set or changed in a terminal.
var ErrEnvEdit = errors.New("env.set values are set in a terminal: a page never shows or carries them")

// errEnvShape is env.set in a form whose values cannot be put back exactly; the editor is not offered for it.
var errEnvShape = errors.New("its env.set uses YAML anchors, aliases, merge keys, a flow mapping or nested values")

// EditableEnv is the text the advanced YAML editor opens on, for a contract text that sets environment values: each
// env.set value replaced by Hidden (RedactEnvText), so the page never carries one, and RestoreEnv puts them back on
// save. It refuses (and the editor is not offered) when text is not one YAML document or its env.set is not a plain
// block mapping of variable names to plain or quoted values with no anchor, alias or merge key: such a value could not
// be put back exactly, or could show through somewhere else in the text.
func EditableEnv(text string) (string, error) {
	cur, err := envEntries(text, true)
	if err != nil {
		return "", err
	}
	shown := RedactEnvText(text)
	// Fail closed: the shown text must read back as the same names with every value hidden.
	back, err := envEntries(shown, false)
	if err != nil || len(back) != len(cur) {
		return "", errEnvShape
	}
	for k, v := range cur {
		b, ok := back[k]
		if !ok || b.null != v.null || (!v.null && b.node.Value != Hidden) {
			return "", errEnvShape
		}
	}
	return shown, nil
}

// envEntry is one variable of env.set: its value node, and whether that is YAML null ("NAME:" with nothing).
type envEntry struct {
	node *yaml.Node
	null bool
}

// envEntries is text's env.set by variable name, reached directly: env and set are keys of the document's own
// mappings (no alias, no merge key), set is a mapping (a block mapping when block is set) with no merge key and no
// repeated name, and every value is a scalar with no anchor, tag or alias. A text without env.set gives an empty map;
// one that is not one YAML document (parseOne) an error.
func envEntries(text string, block bool) (map[string]envEntry, error) {
	doc, err := parseOne(text)
	if err != nil {
		return nil, err
	}
	out := map[string]envEntry{}
	if len(doc.Content) == 0 {
		return out, nil
	}
	root := doc.Content[0]
	set := mapValue(mapValue(root, "env"), "set")
	if set == nil {
		return out, nil
	}
	if set != directValue(directValue(root, "env"), "set") || set.Kind != yaml.MappingNode || (block && set.Style&yaml.FlowStyle != 0) {
		return nil, errEnvShape
	}
	for i := 0; i+1 < len(set.Content); i += 2 {
		k, v := set.Content[i], set.Content[i+1]
		if k.Kind != yaml.ScalarNode || k.Tag == "!!merge" || k.Anchor != "" || v.Kind != yaml.ScalarNode || v.Anchor != "" ||
			(v.Tag != "!!str" && v.Tag != "!!null" && v.Tag != "!!int" && v.Tag != "!!bool" && v.Tag != "!!float") {
			return nil, errEnvShape
		}
		if _, dup := out[k.Value]; dup {
			return nil, errEnvShape
		}
		out[k.Value] = envEntry{node: v, null: v.Tag == "!!null"}
	}
	return out, nil
}

// directValue is key's value in the mapping m itself: nil when m is not a mapping (an alias is not followed) or
// lacks the key (a merge key is not followed).
func directValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key && m.Content[i].Tag != "!!merge" {
			return m.Content[i+1]
		}
	}
	return nil
}

// RestoreEnv is posted, a free edit opened on EditableEnv(current), with every Hidden placeholder of its env.set put
// back to current's value: the value's own source text when it was one line, else the value double-quoted, so the
// lines keep their numbers. restored lists the values put back, for a caller that must keep them off a page. A
// posted text that is not one YAML document comes back unchanged (its compile error names the line, or the second
// document); one that adds a variable, gives one a value other than Hidden, or puts env.set behind an anchor, alias
// or merge key is ErrEnvEdit. Removing a variable, or env.set, is allowed: it carries no value.
func RestoreEnv(posted, current string) (text string, restored []string, err error) {
	if _, err := parseOne(posted); err != nil {
		return posted, nil, nil
	}
	if sets, _ := SetsEnv(posted); !sets {
		return posted, nil, nil
	}
	want, err := envEntries(posted, false)
	if err != nil {
		return "", nil, ErrEnvEdit
	}
	cur, cerr := envEntries(current, true)
	if cerr != nil {
		return "", nil, ErrEnvEdit
	}
	curLines := strings.Split(current, "\n")
	lines := strings.Split(posted, "\n")
	// Placeholders are put back right to left on each line, so an earlier column stays where it was.
	type put struct {
		line, at, n int
		with        string
	}
	var puts []put
	for name, w := range want {
		c, ok := cur[name]
		switch {
		case !ok:
			return "", nil, ErrEnvEdit
		case w.null || c.null:
			if w.null != c.null {
				return "", nil, ErrEnvEdit
			}
			continue
		case w.node.Value != Hidden:
			return "", nil, ErrEnvEdit
		}
		at, n, ok := placeholderAt(lines, w.node)
		if !ok {
			return "", nil, ErrEnvEdit
		}
		with := sourceOf(curLines, c.node)
		if strings.TrimSpace(lines[w.node.Line-1][at+n:]) != "" || with == "" {
			with = quoted(c.node.Value)
		}
		if with == "" {
			return "", nil, ErrEnvEdit
		}
		puts = append(puts, put{line: w.node.Line - 1, at: at, n: n, with: with})
		restored = append(restored, c.node.Value)
	}
	for len(puts) > 0 {
		// Take the rightmost placeholder left on the lowest line.
		j := 0
		for i, p := range puts {
			if p.line < puts[j].line || (p.line == puts[j].line && p.at > puts[j].at) {
				j = i
			}
		}
		p := puts[j]
		lines[p.line] = lines[p.line][:p.at] + p.with + lines[p.line][p.at+p.n:]
		puts = append(puts[:j], puts[j+1:]...)
	}
	text = strings.Join(lines, "\n")
	// Fail closed: the text written must hold exactly the posted names with current's values.
	got, err := envEntries(text, false)
	if err != nil || len(got) != len(want) {
		return "", nil, ErrEnvEdit
	}
	for name, g := range got {
		if c, ok := cur[name]; !ok || g.null != c.null || g.node.Value != c.node.Value {
			return "", nil, ErrEnvEdit
		}
	}
	return text, restored, nil
}

// placeholderAt is the byte offset and length of the Hidden scalar n stands for on its line: plain, or single- or
// double-quoted. False when the line does not hold it at n's column.
func placeholderAt(lines []string, n *yaml.Node) (at, size int, ok bool) {
	if n.Line < 1 || n.Line > len(lines) {
		return 0, 0, false
	}
	ln := lines[n.Line-1]
	at = runeOffset(ln, n.Column-1)
	if at < 0 {
		return 0, 0, false
	}
	for _, form := range []string{Hidden, `"` + Hidden + `"`, `'` + Hidden + `'`} {
		if strings.HasPrefix(ln[at:], form) {
			return at, len(form), true
		}
	}
	return 0, 0, false
}

// sourceOf is the source text of current's one-line value n (from its column to the line's end, a comment included),
// or "" when it does not read back alone as the same value (it continues on later lines).
func sourceOf(lines []string, n *yaml.Node) string {
	if n.Line < 1 || n.Line > len(lines) || n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		return ""
	}
	at := runeOffset(lines[n.Line-1], n.Column-1)
	if at < 0 {
		return ""
	}
	src := strings.TrimRight(lines[n.Line-1][at:], " \t")
	if !readsAs(src, n.Value) {
		return ""
	}
	return src
}

// quoted is v as a one-line YAML double-quoted scalar, "" when it does not read back as v.
func quoted(v string) string {
	q := strconv.Quote(v)
	if !readsAs(q, v) {
		return ""
	}
	return q
}

// readsAs says the YAML scalar source src, as a mapping value, reads as the string v.
func readsAs(src, v string) bool {
	var doc yaml.Node
	if yaml.Unmarshal([]byte("k: "+src+"\n"), &doc) != nil || len(doc.Content) == 0 {
		return false
	}
	n := directValue(doc.Content[0], "k")
	return n != nil && n.Kind == yaml.ScalarNode && n.Value == v && n.Anchor == "" && n.Tag != "!!null"
}

// runeOffset is the byte offset of the col'th rune (0-based) of s, -1 past its end; yaml.v3 counts columns in runes.
func runeOffset(s string, col int) int {
	i := 0
	for off := range s {
		if i == col {
			return off
		}
		i++
	}
	if i == col {
		return len(s)
	}
	return -1
}
