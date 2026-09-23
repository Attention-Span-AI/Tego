// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteEntrySymlinkHidesTheRunDirectory pins R10 against a symlinked ledger root. The run opens
// every fs entry O_PATH *without* O_NOFOLLOW, which follows the link and pins its target, so an entry
// whose declared name does not enclose the ledger root can still govern it. Comparing the names the
// author typed answers a question the kernel never asks.
//
// The regression this guards is the one R10 exists to prevent: the agent holding write access to the
// append-only hash-chained ledger of its own run. `ledger_root: <link>` pointing inside a declared
// write directory is an ordinary admin move (runs on a bigger disk), needs no mistake by the contract
// author, and used to compile clean.
func TestWriteEntrySymlinkHidesTheRunDirectory(t *testing.T) {
	f := newFixture(t)
	work := filepath.Join(f.project, "work")
	real := filepath.Join(work, ".tego")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.root, "ledger-link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	m := *f.machine
	m.LedgerRoot.Value = link

	c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"work\"]\n")
	_, ds, err := Compile(c, &m, f.opts()...)
	if !errors.Is(err, ErrContractOverlap) {
		t.Fatalf("compile of a write entry that resolves onto the ledger root: err = %v, want ErrContractOverlap\n%s", err, render(ds))
	}
	if !hasCode(ds, CodeContradiction) {
		t.Fatalf("no contradiction diagnostic:\n%s", render(ds))
	}
	// The message has to name the link as well as its target, or the author cannot see why their
	// entry overlaps a path that lexically sits somewhere else entirely.
	msg := render(ds)
	if !strings.Contains(msg, link) || !strings.Contains(msg, real) {
		t.Errorf("diagnostic names neither the declared ledger root nor its target:\n%s", msg)
	}
}

// TestDenyReadUnderSymlinkedWriteEntryIsUnenforced is the same lexical-versus-inode gap on the other
// safety check: Landlock unions the rights of every rule on a path, so a write entry whose target
// encloses a deny_read entry makes that deny unenforceable in tier 1. `compile` must say so
// (SEMANTICS §2, R15) instead of reporting the secret as protected.
func TestDenyReadUnderSymlinkedWriteEntryIsUnenforced(t *testing.T) {
	f := newFixture(t)
	vault := filepath.Join(f.root, "vault")
	keys := filepath.Join(vault, "keys")
	if err := os.MkdirAll(keys, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.project, "data")
	if err := os.Symlink(vault, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	c := f.load("version: 0\nname: a\ncommand: [python]\ntier: landlock\nfs:\n  reads: direct\n  write: [\"data\"]\n  deny_read: [\"" + keys + "\"]\n")
	rt, ds := f.compile(c)

	r := findFS(rt, FSDenyRead, keys)
	if r == nil {
		t.Fatalf("no deny_read entry for %s:\n%s", keys, render(ds))
	}
	if !r.Unenforced {
		t.Errorf("deny_read %s reported enforceable, but write entry %s resolves to %s which encloses it", keys, link, vault)
	}
	if !hasCode(ds, CodeUnenforced) {
		t.Errorf("no unenforced warning for the landlock tier:\n%s", render(ds))
	}
	// Evaluate has to agree with the marker, or `compile --test` certifies the read as denied.
	got := rt.Evaluate(Action{Kind: ActionFSRead, Path: filepath.Join(keys, "id_ed25519")}, "landlock")
	if got.Verdict != VerdictAllow || !strings.HasSuffix(got.Rule, UnenforcedSuffix) {
		t.Errorf("landlock read of the shadowed secret = %+v, want allow with the unenforced marker", got)
	}
}

// TestResolvedIsSetOnEveryEntry keeps FSRule.Resolved honest: every consumer that asks a containment
// question reads it, so an entry that never got one would silently compare against "".
func TestResolvedIsSetOnEveryEntry(t *testing.T) {
	_, rt := evalFixture(t)
	for _, r := range rt.FS {
		if r.Resolved == "" {
			t.Errorf("%s entry %s has no Resolved path", r.Kind, r.Path)
		}
		if !filepath.IsAbs(r.Resolved) {
			t.Errorf("%s entry %s: Resolved %q is not absolute", r.Kind, r.Path, r.Resolved)
		}
	}
}

// A write entry that is itself a link to the ledger root's parent is refused as R10 refuses the ledger root's
// own link: the entry is compared by where it leads (FSRule.Resolved). The runtime's checkRunDir compares the
// declared names only, and relies on this.
func TestWriteEntrySymlinkToTheLedgerRootsParent(t *testing.T) {
	f := newFixture(t)
	if err := os.MkdirAll(f.ledger, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.project, "state")
	if err := os.Symlink(filepath.Dir(f.ledger), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	c := f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"state\"]\n")
	_, ds, err := Compile(c, f.machine, f.opts()...)
	if !errors.Is(err, ErrContractOverlap) || !hasCode(ds, CodeContradiction) {
		t.Fatalf("a write entry linking to the ledger root's parent: err = %v, want ErrContractOverlap\n%s", err, render(ds))
	}
}
