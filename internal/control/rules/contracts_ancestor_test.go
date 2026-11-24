// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"os"
	"path/filepath"
	"testing"
)

// TestContractsViewFollowsAnAncestor: The listing's view of a contract (writable, why not) is kept per
// version of the file, and that version was the file and its own folder only. A folder above it made a link (the
// guards refuse a contract reached through one, Guard.NoSymlinks) left the file's and its folder's identity as they
// were, so the contract stayed listed as editable. Every ancestor, not followed, is in the key now (kind, identity,
// mode, owner), so the view changes with a link above it and again when the folder is put back. The save path does not
// rely on the view: every plan and write reads the file through the guards (readView's comment).
func TestContractsViewFollowsAnAncestor(t *testing.T) {
	f := newFixture(t)
	up := filepath.Dir(f.proj) // a folder above the contract's own
	if got := f.ref(t, f.contract); !got.Writable {
		t.Fatalf("first listing: %+v, want writable", got)
	}
	moved := up + "-moved"
	if err := os.Rename(up, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(moved, up); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(up); _ = os.Rename(moved, up) })
	// The premise: a service that kept nothing refuses it, so the guards do see the link above the folder.
	fresh, err := (&Service{Ledger: f.ledger, Home: f.s.Home, live: f.s.live}).Contracts()
	if err != nil {
		t.Fatal(err)
	}
	var seen bool
	for _, c := range fresh {
		if c.Path == f.contract {
			seen = true
			if c.Writable {
				t.Fatalf("a service with no memo shows %+v writable: the guards do not refuse this, the test needs another case", c)
			}
		}
	}
	if !seen {
		t.Fatalf("the fresh listing lacks %s", f.contract)
	}
	if got := f.ref(t, f.contract); got.Writable || got.Why == "" {
		t.Fatalf("a link above the folder: %+v, want not writable with a reason", got)
	}
	if err := os.Remove(up); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(moved, up); err != nil {
		t.Fatal(err)
	}
	if got := f.ref(t, f.contract); !got.Writable {
		t.Fatalf("the folder put back: %+v, want writable again", got)
	}
}
