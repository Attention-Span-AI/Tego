// SPDX-License-Identifier: Apache-2.0

package runlock

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestRootOwnedDecidesFromThreeFacts: a permission refusal, a caller that is not root, and a folder root owns; any
// other combination is not a root-launched run and keeps the system's own words (N125 (a): the commands and the
// dashboard ask this one helper).
func TestRootOwnedDecidesFromThreeFacts(t *testing.T) {
	denied := &fs.PathError{Op: "open", Path: "x/lock", Err: fs.ErrPermission}
	for _, c := range []struct {
		name string
		err  error
		uid  int
		ok   bool
		euid int
		want bool
	}{
		{"refused, a person, root's folder", denied, 0, true, 1000, true},
		{"refused, a person, their own folder", denied, 1000, true, 1000, false},
		{"refused, a person, owner unknown", denied, 0, false, 1000, false},
		{"refused, root, root's folder", denied, 0, true, 0, false},
		{"not a permission refusal", errors.New("input/output error"), 0, true, 1000, false},
		{"no error", nil, 0, true, 1000, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			defer SetRootOwnedSeams(func(string) (int, bool) { return c.uid, c.ok }, func() int { return c.euid })()
			if got := RootOwned("x", c.err); got != c.want {
				t.Errorf("RootOwned = %v, want %v", got, c.want)
			}
		})
	}
}

// TestRootOwnedDoesNotFollowALink: the owner is the folder's own, never a link's target: a link planted where a run
// folder belongs, pointing at a directory root owns, is not a root-launched run (the dashboard's copy read it so; the
// commands' did not, and the two are one now).
func TestRootOwnedDoesNotFollowALink(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root caller owns the link too, and is never the person this refusal is for")
	}
	link := filepath.Join(t.TempDir(), "r-link")
	if err := os.Symlink("/", link); err != nil { // "/" is root's
		t.Fatal(err)
	}
	uid, ok := runFolderOwner(link)
	if !ok || uid != os.Geteuid() {
		t.Fatalf("owner of the link = %d (ok %v), want the link's own owner %d", uid, ok, os.Geteuid())
	}
	if RootOwned(link, &fs.PathError{Op: "open", Path: link, Err: fs.ErrPermission}) {
		t.Error("a link to a root-owned folder was called a root-launched run")
	}
}
