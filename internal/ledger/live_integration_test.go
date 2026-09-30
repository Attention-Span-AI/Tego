// SPDX-License-Identifier: Apache-2.0

//go:build integration

package ledger

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The live index under the hand-over rule, as root: what a root launcher lists in a user's ledger root is
// the user's, as the run directory is once it is closed, and a link the user leaves where root is about to
// list or sweep is never followed. These skip for anyone else and run as root in the KVM guest, beside the
// rest of the SUDO-LEDGER-OWNERSHIP suite (handover_integration_test.go).

// TestIntegrationRootLiveIndexIsTheUsers: the index directory root creates in the user's ledger root, and the
// entry it creates there, are handed to the user, so the user's own unprivileged run can list its runs
// beside root's and its sweep can clear the entry of a root run that ended.
func TestIntegrationRootLiveIndexIsTheUsers(t *testing.T) {
	requireRoot(t)
	home := userHome(t)
	root := filepath.Join(home, ".tego", "runs")
	if err := MakeRunDir(root, testRef.ID); err != nil {
		t.Fatal(err)
	}
	w, err := Open(filepath.Join(root, testRef.ID), testRef, WithAnchor(&memAnchor{}),
		WithClock(newStepClock(time.Now(), 1, time.Millisecond)), WithFreshRunDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := MarkLive(root, testRef.ID); err != nil {
		t.Fatalf("MarkLive: %v", err)
	}
	for _, p := range []string{filepath.Join(root, LiveDir), filepath.Join(root, LiveDir, testRef.ID)} {
		wantOwner(t, p, nobody)
	}
	if err := w.WriteRunStart(startPayload()); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	if err := ClearLive(root, testRef.ID); err != nil {
		t.Fatalf("ClearLive: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, LiveDir, testRef.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the entry of an ended root run is still there: %v", err)
	}
}

// TestIntegrationRootRefusesALinkedLiveIndex: the user replaces their index with a link to a directory root
// owns. Root's MarkLive refuses it and creates nothing behind it, and root's sweep does not read through it:
// it falls back to the pass over every run and removes no entry behind the link.
func TestIntegrationRootRefusesALinkedLiveIndex(t *testing.T) {
	requireRoot(t)
	home := userHome(t)
	root := filepath.Join(home, ".tego", "runs")
	if err := MakeDirs(root); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "victim")
	if err := os.Mkdir(victim, 0o755); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(victim, runID(fixedStart, "vict01"))
	if err := os.WriteFile(planted, []byte("root's\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, LiveDir)
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(link, nobody, nobody); err != nil { // the user planted it
		t.Fatal(err)
	}
	if err := MarkLive(root, testRef.ID); !errors.Is(err, ErrLinkRefused) {
		t.Fatalf("MarkLive through the link: %v, want ErrLinkRefused", err)
	}
	rep, err := SweepLive(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if !errors.Is(rep.Errors[LiveDir], ErrLinkRefused) {
		t.Errorf("the sweep's index error: %v, want ErrLinkRefused", rep.Errors[LiveDir])
	}
	entries, _ := os.ReadDir(victim)
	if len(entries) != 1 || entries[0].Name() != filepath.Base(planted) {
		t.Fatalf("the directory behind the link holds %v, want only what was there", entries)
	}
	wantOwner(t, planted, 0)
}

// TestIntegrationRootSweepStaysInTheLedgerRoot: an entry the user lists under a run id whose path in their
// ledger root is a link to a root run elsewhere is no run: root's sweep neither ends that run nor hands it
// over, and clears the entry.
func TestIntegrationRootSweepStaysInTheLedgerRoot(t *testing.T) {
	requireRoot(t)
	home := userHome(t)
	root := filepath.Join(home, ".tego", "runs")
	if err := MakeDirs(root); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(t.TempDir(), "srv")
	if err := os.Mkdir(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(elsewhere, testRef.ID)
	w, err := Open(dir, testRef, WithAnchor(&memAnchor{}), WithClock(newStepClock(time.Now(), 1, time.Millisecond)))
	if err != nil {
		t.Fatal(err)
	}
	startRun(t, w, 1)
	w.release()
	w.closeDirs() // a lost root run outside the user's ledger root
	link := filepath.Join(root, testRef.ID)
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(link, nobody, nobody); err != nil {
		t.Fatal(err)
	}
	if err := MarkLive(root, testRef.ID); err != nil {
		t.Fatal(err)
	}
	rep, err := SweepLive(context.Background(), root, WithWriterOptions(WithAnchor(&memAnchor{})))
	if err != nil || len(rep.Errors) != 0 || slices.Contains(rep.Swept, testRef.ID) {
		t.Fatalf("SweepLive: %+v %v", rep, err)
	}
	if s := stateOf(t, dir); s != StateLost {
		t.Errorf("the run outside the ledger root is %s, want it untouched (lost)", s)
	}
	wantOwner(t, dir, 0)
	if _, err := os.Lstat(filepath.Join(root, LiveDir, testRef.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the entry naming a link is still there: %v", err)
	}
}
