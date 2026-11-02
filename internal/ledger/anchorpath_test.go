// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestAnchorPathIsTheHomesWhateverTheLedgerRoot: an account whose passwd home exists anchors in its ~/.tego/chain.log,
// and its ledger root is never resolved for it (CHAIN-ANCHOR-PATH, P0-DESIGN §3.3).
func TestAnchorPathIsTheHomesWhateverTheLedgerRoot(t *testing.T) {
	home := t.TempDir()
	got, err := AnchorPath(home, func() (string, error) { return "", errors.New("the ledger root must not be resolved") })
	if err != nil || got != filepath.Join(home, StateDir, ChainLogFile) {
		t.Fatalf("AnchorPath(%q) = %q, %v; want %s/.tego/chain.log", home, got, err, home)
	}
}

// TestAnchorPathWithoutAHome: no home, a home that does not exist or is not a directory, and a relative one each
// anchor beside the ledger root; a ledger root that cannot be resolved is the error, as it is.
func TestAnchorPathWithoutAHome(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	root := func() (string, error) { return "/srv/tego/runs/", nil }
	for _, home := range []string{"", filepath.Join(dir, "missing"), file, "relative/home"} {
		got, err := AnchorPath(home, root)
		if err != nil || got != "/srv/tego/"+ChainLogFile {
			t.Errorf("home %q: %q, %v; want the chain.log beside /srv/tego/runs", home, got, err)
		}
	}
	bad := errors.New("no ledger root")
	if _, err := AnchorPath("", func() (string, error) { return "", bad }); !errors.Is(err, bad) {
		t.Fatalf("an unresolvable ledger root: %v, want its error", err)
	}
}

// TestAnchorPathWithAsksItsProbe: the probe AnchorPathWith is given decides whether a home is there, so the sweep can
// judge another account's home and a test one not on this machine.
func TestAnchorPathWithAsksItsProbe(t *testing.T) {
	root := func() (string, error) { return "/srv/tego/runs", nil }
	there := func(p string) bool { return p == "/home/v" }
	if got, _ := AnchorPathWith("/home/v", there, root); got != "/home/v/.tego/"+ChainLogFile {
		t.Errorf("a home the probe finds: %q", got)
	}
	if got, _ := AnchorPathWith("/home/w", there, root); got != "/srv/tego/"+ChainLogFile {
		t.Errorf("a home the probe does not find: %q", got)
	}
}

// TestHomeExistsKeepsAHomeItCannotRuleOut: only a home that definitely does not exist moves the anchor; one that
// exists, or cannot be stat'ed for another reason, keeps it.
func TestHomeExistsKeepsAHomeItCannotRuleOut(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !HomeExists(dir) || HomeExists(filepath.Join(dir, "missing")) || HomeExists(file) || HomeExists(filepath.Join(file, "under")) {
		t.Fatal("HomeExists misreads a directory, a missing path, a file or a path under a file")
	}
	// A home on the way to which a directory cannot be searched is kept: EACCES is not "it does not exist".
	if os.Geteuid() != 0 {
		locked := filepath.Join(dir, "locked")
		if err := os.Mkdir(filepath.Join(dir, "locked"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(locked, "home"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(locked, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
		if !HomeExists(filepath.Join(locked, "home")) {
			t.Error("a home that cannot be stat'ed (EACCES) moved the anchor")
		}
	}
}
