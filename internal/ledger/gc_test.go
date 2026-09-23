// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// makeRun writes a run under root started at `at` and leaves it in the requested state.
func makeRun(t *testing.T, root string, at time.Time, rand6 string, state RunState) record.RunRef {
	t.Helper()
	ref := record.RunRef{ID: runID(at, rand6), Agent: "retriever"}
	w, err := Open(filepath.Join(root, ref.ID), ref, WithAnchor(&memAnchor{}),
		WithClock(newStepClock(at, 1_000_000_000, time.Millisecond)))
	if err != nil {
		t.Fatal(err)
	}
	if state == StateEmpty {
		w.release()
		return ref
	}
	startRun(t, w, 2)
	switch state {
	case StateEnded:
		if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
			t.Fatal(err)
		}
	case StateLost:
		tearTail(t, w) // died mid-line
		w.release()
	case StateRunning:
		t.Cleanup(func() { _ = w.Close(record.RunEndPayload{Reason: record.RunEndStopped}) })
	}
	return ref
}

func TestGC(t *testing.T) {
	root := t.TempDir()
	now := fixedStart.Add(40 * 24 * time.Hour)
	keep := 30 * 24 * time.Hour
	oldEnded := makeRun(t, root, fixedStart, "a00001", StateEnded)
	newEnded := makeRun(t, root, now.Add(-time.Hour), "a00002", StateEnded)
	oldLost := makeRun(t, root, fixedStart.Add(time.Minute), "a00003", StateLost)
	newLost := makeRun(t, root, now.Add(-2*time.Hour), "a00004", StateLost)
	running := makeRun(t, root, fixedStart.Add(2*time.Minute), "a00005", StateRunning)
	oldEmpty := makeRun(t, root, fixedStart.Add(3*time.Minute), "a00006", StateEmpty)
	_ = os.Mkdir(filepath.Join(root, "not-a-run"), 0o700)
	_ = os.WriteFile(filepath.Join(root, ChainLogFile), nil, 0o600)

	var hooked []string
	hook := func(_ context.Context, _ sys.Lender, run record.RunRef) error {
		hooked = append(hooked, run.ID)
		return nil
	}
	anchor := &memAnchor{}
	opts := []GCOption{WithNow(func() time.Time { return now }), WithSweepHook(hook),
		WithWriterOptions(WithAnchor(anchor))}

	dry, err := GC(context.Background(), root, keep, true, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if len(dry.Deleted) != 3 || len(dry.Swept) != 2 || len(hooked) != 0 {
		t.Fatalf("dry run: %+v hooked %v", dry, hooked)
	}
	if s := stateOf(t, filepath.Join(root, oldLost.ID)); s != StateLost {
		t.Fatalf("dry run must not sweep: %s", s)
	}

	rep, err := GC(context.Background(), root, keep, false, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Errors) != 0 {
		t.Fatalf("errors: %v", rep.Errors)
	}
	want := map[string][]string{
		"deleted": {oldEnded.ID, oldLost.ID, oldEmpty.ID},
		"kept":    {newEnded.ID, newLost.ID, running.ID},
		"swept":   {oldLost.ID, newLost.ID},
	}
	got := map[string][]string{"deleted": rep.Deleted, "kept": rep.Kept, "swept": rep.Swept}
	for k, ids := range want {
		if !sameSet(got[k], ids) {
			t.Errorf("%s = %v, want %v", k, got[k], ids)
		}
	}
	if !sameSet(hooked, []string{oldLost.ID, newLost.ID}) {
		t.Errorf("hook ran for %v", hooked)
	}
	for _, id := range rep.Deleted {
		if _, err := os.Stat(filepath.Join(root, id)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s not removed", id)
		}
	}
	if s := stateOf(t, filepath.Join(root, newLost.ID)); s != StateEnded {
		t.Fatalf("swept run: %s, want ended", s)
	}
	events := readAll(t, filepath.Join(root, newLost.ID))
	var end record.RunEndPayload
	last := events[len(events)-1]
	if last.Kind != record.KindRunEnd || last.DecodePayload(&end) != nil || end.Reason != record.RunEndOrphaned || end.ExitCode != identity.ExitLauncher {
		t.Fatalf("swept run_end: %+v", last)
	}
	if h, ok, _ := anchor.Head(newLost.ID); !ok || h != last.ID {
		t.Fatal("swept run anchored")
	}
	if rep := verify(t, filepath.Join(root, newLost.ID), anchor); rep.Lines != 6 || !rep.Anchored {
		t.Fatalf("swept run chain: %+v", rep)
	}
	if s := stateOf(t, filepath.Join(root, running.ID)); s != StateRunning {
		t.Fatal("running run touched")
	}
	if _, err := os.Stat(filepath.Join(root, "not-a-run")); err != nil {
		t.Fatal("non-run entry touched")
	}
	// Re-running at once is a no-op.
	again, _ := GC(context.Background(), root, keep, false, opts...)
	if len(again.Deleted) != 0 || len(again.Swept) != 0 || len(again.Kept) != 3 {
		t.Fatalf("second gc: %+v", again)
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
	}
	for _, n := range m {
		if n != 0 {
			return false
		}
	}
	return true
}

func TestGCHookFailureKeepsRun(t *testing.T) {
	root := t.TempDir()
	lost := makeRun(t, root, fixedStart, "b00001", StateLost)
	rep, err := GC(context.Background(), root, time.Hour, false,
		WithSweepHook(func(context.Context, sys.Lender, record.RunRef) error { return errors.New("cgroup busy") }))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Errors[lost.ID] == nil || len(rep.Deleted) != 0 {
		t.Fatalf("%+v", rep)
	}
	if s := stateOf(t, filepath.Join(root, lost.ID)); s != StateLost {
		t.Fatalf("state %s", s)
	}
}

// TestGCFinishesPartiallyRemovedRun pins §7's "gc crash mid-RemoveAll" row: a directory a previous gc pass
// only partly removed (events.jsonl and lock already gone, a leftover empty blobs/ dir still present) must not
// make the next gc pass error out -- it is "treated as already-gone-enough" and finished off.
//
// Also pins record-ledger.md E22: a partly removed run directory is finished by the next gc.
func TestGCFinishesPartiallyRemovedRun(t *testing.T) {
	root := t.TempDir()
	old := makeRun(t, root, fixedStart, "e00001", StateEnded)
	dir := filepath.Join(root, old.ID)
	if err := os.Remove(filepath.Join(dir, EventsFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, LockFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("the directory itself must still be there for this fixture to mean anything: %v", err)
	}
	now := fixedStart.Add(40 * 24 * time.Hour)
	rep, err := GC(context.Background(), root, 30*24*time.Hour, false, WithNow(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("a partially-removed run must not fail the whole sweep: %v", err)
	}
	if len(rep.Errors) != 0 {
		t.Fatalf("errors: %v", rep.Errors)
	}
	if !sameSet(rep.Deleted, []string{old.ID}) {
		t.Fatalf("deleted = %v, want [%s]", rep.Deleted, old.ID)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the leftover directory must end up fully gone: %v", err)
	}
}

// TestGCLeavesKeptRunBytesUnchanged pins I6 and the gc doc's own words: "a surviving run's events.jsonl is
// byte-identical to before." A run gc decides to keep (too young to reap) must come out of the sweep with
// every byte exactly as it was -- gc only ever deletes a whole directory, never edits one in place.
//
// Also pins record-ledger.md I6: gc never opens a surviving run's ledger for writing.
func TestGCLeavesKeptRunBytesUnchanged(t *testing.T) {
	root := t.TempDir()
	now := fixedStart.Add(time.Hour)
	kept := makeRun(t, root, now.Add(-time.Minute), "f00001", StateEnded) // well within keep
	before, err := os.ReadFile(filepath.Join(root, kept.ID, EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := GC(context.Background(), root, 24*time.Hour, false, WithNow(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	if !sameSet(rep.Kept, []string{kept.ID}) {
		t.Fatalf("kept = %v, want [%s]", rep.Kept, kept.ID)
	}
	after, err := os.ReadFile(filepath.Join(root, kept.ID, EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("gc rewrote a kept run's ledger: %d bytes before, %d after", len(before), len(after))
	}
}

func TestGCRootErrors(t *testing.T) {
	if _, err := GC(context.Background(), filepath.Join(t.TempDir(), "missing"), time.Hour, false); err == nil {
		t.Fatal("missing root must error")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	root := t.TempDir()
	makeRun(t, root, fixedStart, "c00001", StateEnded)
	if _, err := GC(ctx, root, time.Hour, false); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
}

// Also pins record-ledger.md E10: cross-run ordering and retention use the run id's time36 before any ts.
func TestRunTimeSources(t *testing.T) {
	if got, ok := timeFromRunID(testRef.ID); !ok || !got.Equal(fixedStart) {
		t.Fatalf("time36: %v %v", got, ok)
	}
	if _, ok := timeFromRunID("r-x"); ok {
		t.Fatal("malformed id parsed")
	}
	if !IsRunID(testRef.ID) || IsRunID("r-3f9c2a1b-short-a1b2c3") || IsRunID("R-"+testRef.ID[2:]) {
		t.Fatal("IsRunID")
	}
	// Fallback to the last ts when the id carries no time, then to the directory mtime.
	root := t.TempDir()
	dir := filepath.Join(root, "r-00000000-0000000000000-000000")
	_ = os.Mkdir(dir, 0o700)
	if got := runTime(&fsRunRepository{root: root}, "r-00000000-0000000000000-000000"); got.IsZero() {
		t.Fatal("mtime fallback")
	}
	w, _ := Open(dir, record.RunRef{ID: "r-00000000-0000000000000-000000", Agent: "a"}, WithAnchor(&memAnchor{}),
		WithClock(newStepClock(fixedStart, 1, time.Second)))
	startRun(t, w, 1)
	_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
	if got := runTime(&fsRunRepository{root: root}, "r-00000000-0000000000000-000000"); got.Sub(fixedStart) > 10*time.Second || got.Before(fixedStart) {
		t.Fatalf("ts fallback: %v", got)
	}
}

// Also pins record-ledger.md I7: a run's state is read from the directory, with no registry.
func TestRepository(t *testing.T) {
	root := t.TempDir()
	ended := makeRun(t, root, fixedStart, "d00001", StateEnded)
	empty := makeRun(t, root, fixedStart.Add(time.Second), "d00002", StateEmpty)
	_ = os.Mkdir(filepath.Join(root, "junk"), 0o700)
	_ = os.WriteFile(filepath.Join(root, runID(fixedStart.Add(2*time.Second), "d00003")), nil, 0o600) // a file, not a dir
	repo := NewRunRepository(root)
	ctx := context.Background()
	refs, err := repo.List(ctx)
	if err != nil || len(refs) != 2 {
		t.Fatalf("List = %v %v", refs, err)
	}
	for _, ref := range refs {
		switch ref.ID {
		case ended.ID:
			if ref.Agent != "retriever" {
				t.Errorf("agent %q", ref.Agent)
			}
		case empty.ID:
			if ref.Agent != "" {
				t.Errorf("empty run agent %q", ref.Agent)
			}
		default:
			t.Errorf("unexpected %s", ref.ID)
		}
	}
	if s, err := repo.State(ctx, ended.ID); s != StateEnded || err != nil {
		t.Fatalf("State = %s %v", s, err)
	}
	if s, err := repo.State(ctx, runID(fixedStart, "nope00")); s != StateEmpty || err != nil {
		t.Fatalf("State(absent) = %s %v", s, err)
	}
	if _, err := repo.Open(ctx, "junk"); !errors.Is(err, ErrBadRunRef) {
		t.Fatalf("Open(junk) = %v", err)
	}
	if _, err := repo.Lock(ctx, ended.ID, record.RunRef{ID: empty.ID, Agent: "a"}); !errors.Is(err, ErrBadRunRef) {
		t.Fatalf("Lock mismatch = %v", err)
	}
	if _, err := repo.Lock(ctx, ended.ID, ended); !errors.Is(err, ErrRunEnded) {
		t.Fatalf("Lock(ended) = %v", err)
	}
	w, err := repo.Lock(ctx, empty.ID, record.RunRef{ID: empty.ID, Agent: "a"})
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close(record.RunEndPayload{Reason: record.RunEndError, Detail: "never started"})
	// A corrupt run is reported once and does not hide the others.
	_ = os.WriteFile(filepath.Join(root, ended.ID, EventsFile), []byte("garbage\n"), 0o600)
	refs, err = repo.List(ctx)
	if err == nil || len(refs) != 2 {
		t.Fatalf("List with a corrupt run: %v %v", refs, err)
	}
}

// TestGCRemovalStaysInTheOpenedRoot pins GC's confinement: a ledger root swapped for a symlink after the
// listing, the moment before the removal (WithNow runs there), must not redirect the removal to a
// same-named directory the link points at. Removing by path deleted the decoy's contents. The removal goes
// through the handle GC opened before listing, and GC first checks that the path still names that
// directory (sameRoot): here it does not, so the run is reported and nothing is removed on either side.
func TestGCRemovalStaysInTheOpenedRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "runs")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	old := makeRun(t, root, fixedStart, "d00001", StateEnded)
	decoy := filepath.Join(base, "elsewhere", old.ID)
	if err := os.MkdirAll(decoy, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(decoy, "keep-me")
	if err := os.WriteFile(sentinel, []byte("not the ledger's"), 0o600); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(base, "runs.listed")
	swapped := false
	now := fixedStart.Add(40 * 24 * time.Hour)
	clock := func() time.Time {
		if !swapped {
			swapped = true
			if err := os.Rename(root, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(base, "elsewhere"), root); err != nil {
				t.Fatal(err)
			}
		}
		return now
	}
	rep, err := GC(context.Background(), root, 30*24*time.Hour, false, WithNow(clock))
	if err != nil {
		t.Fatal(err)
	}
	if !swapped {
		t.Fatal("the swap never ran: the fixture proves nothing")
	}
	if len(rep.Deleted) != 0 || rep.Errors[old.ID] == nil {
		t.Fatalf("deleted = %v, errors %v: a root the path no longer names must be reported, not removed from", rep.Deleted, rep.Errors)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("the removal followed the swapped path and deleted a directory outside the ledger root: %v", err)
	}
	if _, err := os.Stat(filepath.Join(moved, old.ID, "events.jsonl")); err != nil {
		t.Fatalf("nothing may be removed once the path and the handle disagree: %v", err)
	}
}

// TestGCDecidesNothingFromADecoyRoot is the other half: a root swapped after GC opened it and before it
// listed makes every path-based read (List, State, the lock probe, the age) describe the decoy. A decoy run
// that reads as ended and old, named like a live run in the real root, used to get that live run removed
// through the handle. Descriptor-bound reads must see the real live run, keep it and leave the decoy alone.
func TestGCDecidesNothingFromADecoyRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "runs")
	decoyRoot := filepath.Join(base, "decoy")
	for _, d := range []string{root, decoyRoot} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	live := makeRun(t, root, fixedStart, "e00001", StateRunning)
	twin := makeRun(t, decoyRoot, fixedStart, "e00001", StateEnded)
	if twin.ID != live.ID {
		t.Fatalf("the decoy must name the live run: %s vs %s", twin.ID, live.ID)
	}
	moved := filepath.Join(base, "runs.real")
	swap := func(o *gcOptions) {
		o.opened = func() {
			if err := os.Rename(root, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(decoyRoot, root); err != nil {
				t.Fatal(err)
			}
		}
	}
	now := fixedStart.Add(40 * 24 * time.Hour)
	rep, err := GC(context.Background(), root, 30*24*time.Hour, false, WithNow(func() time.Time { return now }), swap)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Deleted) != 0 || len(rep.Kept) != 1 || rep.Kept[0] != live.ID {
		t.Fatalf("deleted = %v, kept = %v, errors %v: the real live run must be kept", rep.Deleted, rep.Kept, rep.Errors)
	}
	if _, err := os.Stat(filepath.Join(moved, live.ID, "events.jsonl")); err != nil {
		t.Fatalf("the live run in the real root was removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(decoyRoot, twin.ID, "events.jsonl")); err != nil {
		t.Fatalf("the decoy was touched: %v", err)
	}
}
