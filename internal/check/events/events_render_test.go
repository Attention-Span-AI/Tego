// SPDX-License-Identifier: Apache-2.0

package events

import (
	"bytes"
	"strings"
	"testing"
)

// TestTablePadsByCharactersNotBytes: a rule name with non-ASCII text is wider in bytes than on screen; the
// column after it must start at the same screen column on every row.
func TestTablePadsByCharactersNotBytes(t *testing.T) {
	lines := fsLines(t, 2, func(i int) string {
		if i == 0 {
			return "fs.write[./données]"
		}
		return "fs.write[./data-x]"
	})
	var out bytes.Buffer
	if _, err := Table(t.Context(), &out, readerOf(t, lines), Filter{}); err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(strings.TrimSpace(out.String()), "\n")
	col := -1
	for _, row := range rows[1:] {
		j := strings.Index(row, "/home/u/proj")
		if j < 0 {
			t.Fatalf("row %q has no path", row)
		}
		c := len([]rune(row[:j]))
		if col >= 0 && c != col {
			t.Fatalf("detail column at %d and %d screen columns:\n%s", col, c, out.String())
		}
		col = c
	}
}

// countingWriter counts Write calls.
type countingWriter struct {
	bytes.Buffer
	calls int
}

func (c *countingWriter) Write(p []byte) (int, error) { c.calls++; return c.Buffer.Write(p) }

// TestJSONWritesInBlocks: --json is the view people pipe; one write(2) per event is a syscall per line.
func TestJSONWritesInBlocks(t *testing.T) {
	lines := fsLines(t, 200, func(int) string { return "fs.read[.]" })
	var w countingWriter
	if n, err := JSON(t.Context(), &w, readerOf(t, lines), Filter{}); err != nil || n != 200 {
		t.Fatalf("JSON = %d, %v", n, err)
	}
	if w.calls > 50 {
		t.Fatalf("%d writes for 200 events, want buffered blocks", w.calls)
	}
	if got := strings.Count(w.String(), "\n"); got != 200 {
		t.Fatalf("%d lines, want 200", got)
	}
}

// TestCellsAreOneLineOfFourCells: --cells is the table's own verdict, rule and detail cells, one line per event and
// four tab-separated cells on it, whatever the agent put in a path or a rule: a tab or a line break in a cell is
// escaped (record.Printable), two spaces in a row stay as they are, and the limit and the filter apply as they do to
// the table.
func TestCellsAreOneLineOfFourCells(t *testing.T) {
	lines := fsLines(t, 3, func(i int) string {
		return [...]string{"fs.write[./a\tb  c\nd]", "-", "fs.read[.]"}[i]
	})
	var out bytes.Buffer
	n, err := CellsOf(t.Context(), &out, readerOf(t, lines), readerOf(t, lines).Entries(), Filter{})
	if err != nil || n != 3 {
		t.Fatalf("CellsOf = %d, %v", n, err)
	}
	got := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	want := []string{
		"0\tallow\tfs.write[./a\\tb  c\\nd]\topen /home/u/proj/a.txt",
		"1\tallow\t-\topen /home/u/proj/a.txt",
		"2\tallow\tfs.read[.]\topen /home/u/proj/a.txt",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("cells:\n%q\nwant\n%q", got, want)
	}
	out.Reset()
	if n, err := CellsOf(t.Context(), &out, readerOf(t, lines), readerOf(t, lines).Entries(), Filter{Limit: 2}); err != nil || n != 2 ||
		strings.Count(out.String(), "\n") != 2 {
		t.Fatalf("limit 2: %d, %v, %q", n, err, out.String())
	}
}
