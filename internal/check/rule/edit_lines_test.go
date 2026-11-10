// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// otherBreaks are the line breaks the parser counts that cutting a text at "\n" does not see: a CR no LF follows,
// NEL (U+0085), LS (U+2028) and PS (U+2029). yaml.v3 reads YAML 1.1's line breaks.
var otherBreaks = []struct{ name, brk string }{
	{"CR", "\r"}, {"NEL", string(rune(0x85))}, {"LS", string(rune(0x2028))}, {"PS", string(rune(0x2029))},
}

// TestEditOnOtherLineBreaks: an edit of a text that breaks a line with CR alone, NEL, LS or PS makes exactly its
// change and loses nothing else. A node's Line counts those breaks, so the lines "\n" cuts are not the lines the
// nodes name, and the line splice is not made on such a text (parserLines): the tree writes it.
//
// The first text is the nightly fuzz's crash (testdata/fuzz/FuzzApplyEdits/26c3908ce564734d, there with CR): the
// parser puts the item `0` on line 3 and the empty item on line 4, "\n" cutting puts them on lines 2 and 3, and the
// splice read `0`'s dash from the last line, "    -", one byte past its end. The second is the same misreading where
// it stayed inside the line: the item's "\n" line also held the comment on the parser's next line, and went whole.
func TestEditOnOtherLineBreaks(t *testing.T) {
	for _, c := range otherBreaks {
		t.Run(c.name, func(t *testing.T) {
			res, err := applyEdits(t, "fs:\n ask_read:"+c.brk+"    - 0\n    -", "/h", Edit{OpAdd, "fs.deny_read", "0"})
			if err != nil {
				t.Fatal(err)
			}
			_, top, err := parse(res.Text)
			if err != nil {
				t.Fatalf("%v\n%q", err, res.Text)
			}
			if !hasString(top, "fs.deny_read", "0") || slices.Contains(list(top, "fs.ask_read"), "0") {
				t.Errorf("deny_read %q, ask_read %q, want the entry moved:\n%q", list(top, "fs.deny_read"), list(top, "fs.ask_read"), res.Text)
			}

			res, err = applyEdits(t, "fs:\n  write:\n    - a"+c.brk+"# why b\n    - b\n", "/h", Edit{OpRemove, "fs.write", "a"})
			if err != nil {
				t.Fatal(err)
			}
			if _, top, err = parse(res.Text); err != nil {
				t.Fatalf("%v\n%q", err, res.Text)
			}
			if got := list(top, "fs.write"); !slices.Equal(got, []string{"b"}) || !strings.Contains(string(res.Text), "# why b") {
				t.Errorf("write %q, want [b] and its comment kept:\n%q", got, res.Text)
			}
		})
	}
}

// TestParserLines: where parserLines says ok, every node is on the line it names (lines[n.Line-1] holds its value
// at its column) and the lines are the whole text, for LF and for CR LF. A text with another break it refuses, and
// there the lines "\n" cuts do hold a node on another line than the one it names; and a text in UTF-16, which the
// parser decodes behind a byte order mark, and whose edit the tree still makes.
func TestParserLines(t *testing.T) {
	// onLines reports whether every plain scalar of text's tree starts at its Line and Column of lines.
	onLines := func(text string, lines []string) bool {
		doc, _, err := parse([]byte(text))
		if err != nil {
			t.Fatalf("%v\n%q", err, text)
		}
		on := true
		var walk func(n *yaml.Node)
		walk = func(n *yaml.Node) {
			if n.Kind == yaml.ScalarNode && n.Style == 0 && n.Value != "" {
				on = on && n.Line >= 1 && n.Line <= len(lines) && n.Column-1 <= len(lines[n.Line-1]) &&
					strings.HasPrefix(lines[n.Line-1][n.Column-1:], n.Value)
			}
			for _, c := range n.Content {
				walk(c)
			}
		}
		walk(doc)
		return on
	}
	for _, text := range []string{editBase, strings.ReplaceAll(editBase, "\n", "\r\n"), "fs:\n  write:\n    - a\n    - b",
		"fs:\r\n  write:\r\n    - a\r\n    -"} {
		lines, ok := parserLines([]byte(text))
		if !ok || strings.Join(lines, "") != text || !onLines(text, lines) {
			t.Errorf("parserLines(%q) = %q, %v: not the text's lines as its nodes name them", text, lines, ok)
		}
	}
	for _, c := range otherBreaks {
		text := "fs:\n  write:\n    - a" + c.brk + "    - b\n"
		if lines, ok := parserLines([]byte(text)); ok {
			t.Errorf("%s: parserLines(%q) = %q, but the parser ends a line there too", c.name, text, lines)
		}
		if onLines(text, strings.SplitAfter(text, "\n")) {
			t.Errorf("%s: every node of %q is on its \"\\n\" line, so the text shows nothing", c.name, text)
		}
	}
	// A break at the very end, and one after an LF, count as well.
	for _, text := range []string{"a: 1\r", "a: 1\n\rb: 2\n", "a: 1" + string(rune(0x2028))} {
		if lines, ok := parserLines([]byte(text)); ok {
			t.Errorf("parserLines(%q) = %q, but the parser ends a line there too", text, lines)
		}
	}
	utf16 := "\xff\xfe" // UTF-16LE
	for _, b := range []byte("fs:\n  write:\n    - a\n") {
		utf16 += string([]byte{b, 0})
	}
	if _, top, err := parse([]byte(utf16)); err != nil || !slices.Equal(list(top, "fs.write"), []string{"a"}) {
		t.Fatalf("the parser does not read UTF-16 behind its byte order mark: %v", err)
	}
	if lines, ok := parserLines([]byte(utf16)); ok {
		t.Errorf("parserLines took UTF-16 text: %q", lines)
	}
	res, err := applyEdits(t, utf16, "/h", Edit{OpAdd, "fs.write", "z"})
	if err != nil {
		t.Fatal(err)
	}
	if _, top, err := parse(res.Text); err != nil || !slices.Equal(list(top, "fs.write"), []string{"a", "z"}) {
		t.Errorf("an edit of UTF-16 text: %v\n%q", err, res.Text)
	}
}

// TestItemDashStaysInItsLine: whatever the line and the column, itemDash reads no byte outside the line, and a line
// it takes is an item's: spaces, the dash, a space, and the value's column after them, in the line or at its end.
func TestItemDashStaysInItsLine(t *testing.T) {
	if d, ok := itemDash("    -", 7); ok {
		t.Errorf(`itemDash("    -", 7) = %d: the column is past the line`, d)
	}
	var walk func(line string)
	walk = func(line string) {
		for col := -2; col <= len(line)+4; col++ {
			d, ok := itemDash(line, col)
			if !ok {
				continue
			}
			if d < 0 || d+1 >= len(line) || line[d] != '-' || line[d+1] != ' ' || strings.Trim(line[:d], " ") != "" ||
				d+1 > col-2 || col-1 > len(line) {
				t.Fatalf("itemDash(%q, %d) = %d", line, col, d)
			}
		}
		if len(line) < 6 {
			for _, b := range " -x\n" {
				walk(line + string(b))
			}
		}
	}
	walk("")
}
