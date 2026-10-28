// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestIntegrationBoundaryAdoptionMakesTheOwnersRecords: as root, a boundary adoption of an owner who has never run
// tego makes that owner's ~/.tego before it compiles (makeOwnRecords), so R6a's deny attaches for the whole
// adoption: the directory is the owner's, with its passwd group and mode 0700, as its
// first `tego run` would have made it, never root's. A name already there is left as it is and never followed: a
// link to a directory elsewhere does not get that directory chowned. One that cannot be chowned (a group lookup that
// fails) is removed again rather than left root's. It needs root to chown: root-suites.sh runs it in a KVM guest.
func TestIntegrationBoundaryAdoptionMakesTheOwnersRecords(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: makes a directory for another uid and chowns it (root-suites.sh)")
	}
	const owner, group = 4242, 4343
	prev := adoptGroupOf
	adoptGroupOf = func(uid int) (int, error) {
		if uid != owner {
			return 0, errors.New("no such user")
		}
		return group, nil
	}
	t.Cleanup(func() { adoptGroupOf = prev })
	home := t.TempDir()
	if err := os.Chown(home, owner, group); err != nil {
		t.Fatal(err)
	}
	if err := makeOwnRecords(home, owner); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(ownRecords(home))
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 || st.Uid != owner || st.Gid != group {
		t.Errorf("the owner's ~/.tego: mode %v uid %d gid %d, want a directory of mode 0700 owned by %d:%d", fi.Mode(),
			st.Uid, st.Gid, owner, group)
	}
	if err := makeOwnRecords(home, owner); err != nil {
		t.Errorf("a ~/.tego already there: %v", err)
	}

	// A link the owner left at the name, to a directory root owns: left alone, its target not chowned.
	linked := t.TempDir()
	if err := os.Chown(linked, owner, group); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "roots")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, ownRecords(linked)); err != nil {
		t.Fatal(err)
	}
	if err := makeOwnRecords(linked, owner); err != nil {
		t.Errorf("a link at ~/.tego: %v, want it left for the compile to judge", err)
	}
	if fi, err := os.Stat(target); err != nil || fi.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Errorf("the link's target after makeOwnRecords: %v %v, want it still root's", fi, err)
	}

	// A uid whose group cannot be found: the directory is not left behind, root's.
	bare := t.TempDir()
	if err := os.Chown(bare, owner+1, group); err != nil {
		t.Fatal(err)
	}
	if err := makeOwnRecords(bare, owner+1); err == nil || errors.Is(err, errHomeNotOwners) {
		t.Errorf("a uid with no passwd group: %v, want the group lookup's error", err)
	}
	if _, err := os.Lstat(ownRecords(bare)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a ~/.tego that could not be chowned is left: %v", err)
	}

	// A home the owner may not write (root's, mode 0755, as a service account's / or /var/www): nothing is made, so
	// root hands the owner no directory it could not make; one its group may write and
	// it is in (adoptGroupsOf) is the owner's to write, and the directory is made there.
	prevGroups := adoptGroupsOf
	adoptGroupsOf = func(uid int) ([]int, error) { return []int{group}, nil }
	t.Cleanup(func() { adoptGroupsOf = prevGroups })
	roots := t.TempDir()
	if err := os.Chmod(roots, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := makeOwnRecords(roots, owner); !errors.Is(err, errHomeNotOwners) {
		t.Errorf("a home the owner may not write: %v, want errHomeNotOwners", err)
	}
	if _, err := os.Lstat(ownRecords(roots)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a ~/.tego was made in a home the owner may not write: %v", err)
	}
	shared := t.TempDir()
	if err := os.Chown(shared, 0, group); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := makeOwnRecords(shared, owner); err != nil {
		t.Errorf("a home the owner's group may write: %v", err)
	}
	if fi, err := os.Lstat(ownRecords(shared)); err != nil || fi.Sys().(*syscall.Stat_t).Uid != owner {
		t.Errorf("the owner's ~/.tego in a home its group may write: %v %v, want the owner's directory", fi, err)
	}
}
