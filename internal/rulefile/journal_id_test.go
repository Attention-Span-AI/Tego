// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestRevertIDIsNotAPath (SEC-5): Revert looks a change up by its id's equality with a journal entry's, never as a
// path; an id that spells a traversal or an absolute path is ErrNoChange, and nothing is written: not the contract,
// not the journal, and no file where the id points.
func TestRevertIDIsNotAPath(t *testing.T) {
	g, path := fixture(t)
	es := chain(t, g, path)
	before := mustRead(t, path)
	journal, err := ReadJournal(g.LedgerRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"../x", "/etc/passwd", "rc-x/../y", es[0].ID + "/../" + es[1].ID, "../" + es[0].ID,
		filepath.Join(g.LedgerRoot, es[0].ID), ""} {
		if _, err := Revert(t.Context(), g, id, RevertOptions{Change: Change{Via: "dashboard"}}); !errors.Is(err, ErrNoChange) {
			t.Errorf("Revert(%q): %v, want ErrNoChange", id, err)
		}
	}
	if got := mustRead(t, path); got != before {
		t.Errorf("a Revert of a path-like id changed the contract to %q", got)
	}
	after, err := ReadJournal(g.LedgerRoot)
	if err != nil || len(after) != len(journal) {
		t.Errorf("a Revert of a path-like id journaled: %d entries, was %d (%v)", len(after), len(journal), err)
	}
	for _, p := range []string{filepath.Join(filepath.Dir(g.LedgerRoot), "x"), filepath.Join(g.LedgerRoot, "y")} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("a Revert of a path-like id made %s", p)
		}
	}
	if _, err := Blob(g.LedgerRoot, "../"+es[0].NewSHA256); !errors.Is(err, ErrNoChange) {
		t.Errorf("Blob of a traversal: %v, want ErrNoChange", err)
	}
}
