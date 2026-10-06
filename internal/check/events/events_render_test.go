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
