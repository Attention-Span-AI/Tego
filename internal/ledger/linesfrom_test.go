// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLinesFrom: reading on from an offset yields only the lines that begin at it or later; a line the offset cuts and
// a torn tail are skipped, and an offset of 0 is Lines.
func TestLinesFrom(t *testing.T) {
	dir := t.TempDir()
	const one, two, three = `{"a":1}`, `{"b":22}`, `{"c":333}`
	body := one + "\n" + two + "\n" + three + "\n" + `{"torn`
	if err := os.WriteFile(filepath.Join(dir, EventsFile), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	size, err := r.Size()
	if err != nil || size != int64(len(body)) {
		t.Fatalf("Size = %d, %v; want %d", size, err, len(body))
	}
	after1 := int64(len(one) + 1)
	for _, c := range []struct {
		name string
		off  int64
		want []string
	}{
		{"a line's start", after1, []string{two, three}},
		{"inside a line", after1 - 3, []string{two, three}},
		{"one past a line's start", after1 + 1, []string{three}},
		{"the torn tail", int64(len(body)) - 3, nil},
		{"past the end", int64(len(body)) + 10, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			var got []string
			for l, err := range r.LinesFrom(c.off) {
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, string(l))
			}
			if strings.Join(got, "|") != strings.Join(c.want, "|") {
				t.Errorf("LinesFrom(%d) = %q, want %q", c.off, got, c.want)
			}
		})
	}
}
