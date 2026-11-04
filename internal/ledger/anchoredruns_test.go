// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnchoredRunsValidatesEveryCompleteLine(t *testing.T) {
	const id = "r-12345678-0000000000000-abcdef"
	line := id + " " + strings.Repeat("a", 64) + "\n"
	for _, tc := range []struct {
		name, body string
		want       int
		bad        bool
	}{
		{"empty", "", 0, false}, {"one", line, 1, false}, {"duplicate", line + line, 1, false},
		{"torn", line + "unfinished", 1, false}, {"bad line", line + "bad\n", 0, true},
		{"conflicting heads", line + id + " " + strings.Repeat("b", 64) + "\n", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "chain.log")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			ids, err := AnchoredRuns(path)
			if errors.Is(err, ErrCorruptLedger) != tc.bad || (err == nil && len(ids) != tc.want) {
				t.Fatalf("%v %v", ids, err)
			}
		})
	}
	if ids, err := AnchoredRuns(filepath.Join(t.TempDir(), "missing")); err != nil || len(ids) != 0 {
		t.Fatalf("missing: %v %v", ids, err)
	}
}
