// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// dyingAnchor is a launcher killed inside Close between run_end and the chain.log append: Append writes
// nothing (the error it returns stands for the process being gone), and Head reads the real anchor.
type dyingAnchor struct{ ChainAnchor }

func (dyingAnchor) Append(string, string) error { return errors.New("killed before the anchor line") }

// endedUnanchored leaves a run whose launcher died inside Close after run_end and before its anchor line, its
// entry still listed (ClearLive runs after Close), with anchor as the anchor its launcher would have used.
func endedUnanchored(t *testing.T, root string, anchor ChainAnchor, rand6 string) record.RunRef {
	t.Helper()
	ref := record.RunRef{ID: runID(fixedStart, rand6), Agent: "retriever"}
	w, err := Open(filepath.Join(root, ref.ID), ref, WithAnchor(dyingAnchor{anchor}),
		WithClock(newStepClock(fixedStart, 1_000_000_000, time.Millisecond)))
	if err != nil {
		t.Fatal(err)
	}
	if err := MarkLive(root, ref.ID); err != nil {
		t.Fatal(err)
	}
	startRun(t, w, 2)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); !errors.Is(err, ErrAnchorWrite) {
		t.Fatalf("Close: %v, want the anchor to have failed", err)
	}
	return ref
}

// TestSweepLiveAnchorsAnEndedRunWithNoAnchorLine: a launcher that died inside Close
// between run_end and the chain.log append left an ended run with no anchor, which `events --verify` read as
// ErrAnchorMissing forever; the sweep cleared its entry after one tail read and never looked at the anchor. The
// entry is still listed then, so the sweep anchors the run at its own verified head before clearing it, and
// runs the ended hook for the scope the launcher may have left (L1). gc's pass has no index and leaves it.
func TestSweepLiveAnchorsAnEndedRunWithNoAnchorLine(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	anchor := NewFileChainAnchor(filepath.Join(t.TempDir(), ChainLogFile))
	ref := endedUnanchored(t, root, anchor, "anch01")
	dir := filepath.Join(root, ref.ID)
	if _, err := VerifyRunDir(context.Background(), dir, anchor); !errors.Is(err, ErrAnchorMissing) {
		t.Fatalf("before the sweep: verify %v, want ErrAnchorMissing", err)
	}

	// gc walks every run directory and consults no index: an ended run is nothing for it to do.
	if _, err := GC(context.Background(), root, keepAll, false, WithWriterOptions(WithAnchor(anchor))); err != nil {
		t.Fatalf("GC: %v", err)
	}
	if _, ok, _ := anchor.Head(ref.ID); ok {
		t.Fatal("gc anchored a run: only the live index names a run whose launcher died in Close")
	}

	var ended []record.RunRef
	hook := func(_ context.Context, _ sys.Lender, run record.RunRef) (bool, error) {
		ended = append(ended, run)
		return true, nil
	}
	rep, err := SweepLive(context.Background(), root, WithWriterOptions(WithAnchor(anchor)), WithEndedHook(hook))
	if err != nil || len(rep.Errors) != 0 {
		t.Fatalf("SweepLive: %v %v", err, rep.Errors)
	}
	vr, err := VerifyRunDir(context.Background(), dir, anchor)
	if err != nil || !vr.Anchored {
		t.Fatalf("after the sweep: verify %+v %v, want anchored", vr, err)
	}
	if listed(t, root, ref.ID) {
		t.Error("the entry of the anchored run is still listed")
	}
	if !slices.Equal(ended, []record.RunRef{ref}) {
		t.Errorf("ended hook ran for %v, want once for %v", ended, ref)
	}
	if slices.Contains(rep.Swept, ref.ID) {
		t.Error("an ended run is anchored, not swept: it must not be reported as orphaned")
	}
	// A second sweep has nothing to do, and a second anchor line would make Head refuse the run.
	if _, err := SweepLive(context.Background(), root, WithWriterOptions(WithAnchor(anchor))); err != nil {
		t.Fatal(err)
	}
	if vr, err := VerifyRunDir(context.Background(), dir, anchor); err != nil || !vr.Anchored {
		t.Fatalf("after a second sweep: %+v %v", vr, err)
	}
}

// TestSweepLiveLeavesAnEndedRunWhoseLockIsHeld: a lock held on an ended run is a launcher still inside Close,
// between run_end and its own anchor line, or a process of the run holding a dead launcher's lock. Neither is
// anchored under it; the entry stays and the next sweep, with the lock free, anchors the run.
func TestSweepLiveLeavesAnEndedRunWhoseLockIsHeld(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	anchor := NewFileChainAnchor(filepath.Join(t.TempDir(), ChainLogFile))
	ref := endedUnanchored(t, root, anchor, "anch02")
	lk, err := os.Open(filepath.Join(root, ref.ID, LockFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(lk.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	hooked := 0
	hook := func(context.Context, sys.Lender, record.RunRef) (bool, error) { hooked++; return true, nil }
	if rep, err := SweepLive(context.Background(), root, WithWriterOptions(WithAnchor(anchor)), WithEndedHook(hook)); err != nil || len(rep.Errors) != 0 {
		t.Fatalf("SweepLive: %v %v", err, rep.Errors)
	}
	if _, ok, _ := anchor.Head(ref.ID); ok {
		t.Fatal("anchored under a lock another holder has")
	}
	if !listed(t, root, ref.ID) {
		t.Fatal("the entry of a run whose lock is held was cleared")
	}
	if hooked != 1 {
		t.Errorf("ended hook ran %d times, want once: it is what ends a dead launcher's lock holder", hooked)
	}
	_ = lk.Close()
	if _, err := SweepLive(context.Background(), root, WithWriterOptions(WithAnchor(anchor))); err != nil {
		t.Fatal(err)
	}
	if vr, err := VerifyRunDir(context.Background(), filepath.Join(root, ref.ID), anchor); err != nil || !vr.Anchored {
		t.Fatalf("with the lock free: %+v %v", vr, err)
	}
}

// TestSweepLiveDoesNotAnchorABrokenChain: the anchor vouches for a chain, so one that does not verify is
// reported and left unanchored, where `events --verify` says what is wrong with it; its entry is cleared, or
// every sweep would report it again.
func TestSweepLiveDoesNotAnchorABrokenChain(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	anchor := NewFileChainAnchor(filepath.Join(t.TempDir(), ChainLogFile))
	ref := endedUnanchored(t, root, anchor, "anch03")
	path := filepath.Join(root, ref.ID, EventsFile)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b = bytes.Replace(b, []byte(`"seq":1`), []byte(`"seq":7`), 1)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := SweepLive(context.Background(), root, WithWriterOptions(WithAnchor(anchor)))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Errors[ref.ID] == nil {
		t.Error("a chain that does not verify must be reported")
	}
	if _, ok, _ := anchor.Head(ref.ID); ok {
		t.Fatal("a chain that does not verify was anchored")
	}
	if listed(t, root, ref.ID) {
		t.Error("the entry stays, so every sweep reports the same run again")
	}
}

// TestSweepLiveKeepsAnEndedRunWhoseHookFails: the ended hook is what removes a scope the dead launcher left
// populated or busy; when it fails the entry stays for the next sweep, as a lost run's does.
func TestSweepLiveKeepsAnEndedRunWhoseHookFails(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	anchor := NewFileChainAnchor(filepath.Join(t.TempDir(), ChainLogFile))
	ref := endedUnanchored(t, root, anchor, "anch04")
	fail := func(context.Context, sys.Lender, record.RunRef) (bool, error) {
		return false, errors.New("scope still busy")
	}
	rep, err := SweepLive(context.Background(), root, WithWriterOptions(WithAnchor(anchor)), WithEndedHook(fail))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Errors[ref.ID] == nil || !listed(t, root, ref.ID) {
		t.Fatalf("a failed ended hook: errors %v, listed %v; want reported and kept", rep.Errors, listed(t, root, ref.ID))
	}
	if _, ok, _ := anchor.Head(ref.ID); !ok {
		t.Error("the anchor is repaired whatever the hook does")
	}
	notYet := func(context.Context, sys.Lender, record.RunRef) (bool, error) { return false, nil }
	rep, err = SweepLive(context.Background(), root, WithWriterOptions(WithAnchor(anchor)), WithEndedHook(notYet))
	if err != nil || len(rep.Errors) != 0 || !listed(t, root, ref.ID) {
		t.Fatalf("a hook that is not done yet: %v %v, listed %v; want kept without an error", err, rep.Errors, listed(t, root, ref.ID))
	}
}

// TestEndListedKeepsTheEntryOfARepairCutShort: repairAnchor classified any Verify
// error as a chain that does not verify, so a read cut short (a cancelled context, EIO) cleared the entry and the
// run was never anchored. Only a verification failure clears it; a read failure keeps it, and the next sweep
// anchors the run.
func TestEndListedKeepsTheEntryOfARepairCutShort(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	anchor := NewFileChainAnchor(filepath.Join(t.TempDir(), ChainLogFile))
	ref := endedUnanchored(t, root, anchor, "anch09")
	rd, err := openDir(root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rd.Close() }()
	repo := pinnedRepository(root, rd, WithAnchor(anchor))
	o := &gcOptions{now: time.Now, writer: []Option{WithAnchor(anchor)}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	keep, err := endListed(ctx, repo, ref.ID, o)
	if !keep {
		t.Fatalf("a repair cut short by a cancelled context cleared the entry (err %v): the run is never anchored", err)
	}
	if err == nil || errors.Is(err, errUnanchorable) {
		t.Fatalf("a repair cut short: err %v, want a reported failure that is not errUnanchorable", err)
	}
	if _, err := SweepLive(context.Background(), root, WithWriterOptions(WithAnchor(anchor))); err != nil {
		t.Fatal(err)
	}
	if vr, err := VerifyRunDir(context.Background(), filepath.Join(root, ref.ID), anchor); err != nil || !vr.Anchored {
		t.Fatalf("the next sweep: %+v %v, want anchored", vr, err)
	}
}

// failingAnchor is an anchor whose Append, and with headErr its Head, fail as a full disk or an unreadable
// chain.log would, for a while.
type failingAnchor struct {
	ChainAnchor
	headErr bool
}

func (failingAnchor) Append(string, string) error { return errors.New("no space left on device") }

func (a failingAnchor) Head(run string) (string, bool, error) {
	if a.headErr {
		return "", false, errors.New("input/output error")
	}
	return a.ChainAnchor.Head(run)
}

// TestSweepLiveKeepsAnEndedRunWhoseRepairFailedForNow: a repair that failed on the
// anchor, not on the ledger (Append refused, or the anchor could not be read), cleared the entry all the same,
// and no later sweep ever met the run again: it stayed unanchored, [ledger-corrupt] under `events --verify`,
// forever. The entry stays, the failure is reported, and the next sweep with a working anchor repairs it.
func TestSweepLiveKeepsAnEndedRunWhoseRepairFailedForNow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headErr bool
	}{{"append fails", false}, {"head fails", true}} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "runs")
			anchor := NewFileChainAnchor(filepath.Join(t.TempDir(), ChainLogFile))
			ref := endedUnanchored(t, root, anchor, "anch05")
			rep, err := SweepLive(context.Background(), root,
				WithWriterOptions(WithAnchor(failingAnchor{ChainAnchor: anchor, headErr: tc.headErr})))
			if err != nil {
				t.Fatal(err)
			}
			if rep.Errors[ref.ID] == nil {
				t.Error("a failed repair must be reported")
			}
			if !listed(t, root, ref.ID) {
				t.Fatal("the entry of a run whose repair failed for now was cleared: no sweep would meet it again")
			}
			if _, err := SweepLive(context.Background(), root, WithWriterOptions(WithAnchor(anchor))); err != nil {
				t.Fatal(err)
			}
			if vr, err := VerifyRunDir(context.Background(), filepath.Join(root, ref.ID), anchor); err != nil || !vr.Anchored {
				t.Fatalf("with the anchor working again: %+v %v, want anchored", vr, err)
			}
			if listed(t, root, ref.ID) {
				t.Error("the entry of the repaired run is still listed")
			}
		})
	}
}

// TestSweepLiveDoesNotRepairUnderAMissingLock: tryLock read a missing lock file as
// free and took nothing, so two sweeps meeting the same unanchored run could both append its line, and Head then
// refused the run as two heads. With no lock to hold, the repair is skipped.
func TestSweepLiveDoesNotRepairUnderAMissingLock(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	anchor := NewFileChainAnchor(filepath.Join(t.TempDir(), ChainLogFile))
	ref := endedUnanchored(t, root, anchor, "anch06")
	if err := os.Remove(filepath.Join(root, ref.ID, LockFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := SweepLive(context.Background(), root, WithWriterOptions(WithAnchor(anchor))); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := anchor.Head(ref.ID); ok {
		t.Fatal("anchored with no lock held: a concurrent sweep could append the same line")
	}
}

// TestSweepsLeaveAForeignRunAlone: a run another host minted had only its kill and
// its reclaim skipped. The sweep still appended run_end{orphaned} to it — its lock is a lock on this machine
// only, and its launcher may be alive on its own — and the live sweep anchored it in this host's anchor. GC,
// SweepLive's lost path and its ended path now leave it alone, and its entry stays.
func TestSweepsLeaveAForeignRunAlone(t *testing.T) {
	foreign := WithForeignRun(func(string) bool { return true })
	hooked := 0
	hook := WithSweepHook(func(context.Context, sys.Lender, record.RunRef) error { hooked++; return nil })
	ended := WithEndedHook(func(context.Context, sys.Lender, record.RunRef) (bool, error) { hooked++; return true, nil })

	root := filepath.Join(t.TempDir(), "runs")
	anchor := NewFileChainAnchor(filepath.Join(t.TempDir(), ChainLogFile))
	w, lost := openLive(t, root, fixedStart, "frgn01")
	if err := MarkLive(root, lost.ID); err != nil {
		t.Fatal(err)
	}
	startRun(t, w, 1)
	die(w)
	unanchored := endedUnanchored(t, root, anchor, "frgn02")

	if _, err := GC(context.Background(), root, keepAll, false, foreign, hook, WithWriterOptions(WithAnchor(anchor))); err != nil {
		t.Fatal(err)
	}
	if _, err := SweepLive(context.Background(), root, foreign, hook, ended, WithWriterOptions(WithAnchor(anchor))); err != nil {
		t.Fatal(err)
	}
	if last, _ := lastOf(t, filepath.Join(root, lost.ID)); last == record.KindRunEnd {
		t.Error("run_end appended to another host's run")
	}
	if _, ok, _ := anchor.Head(unanchored.ID); ok {
		t.Error("another host's run anchored in this host's anchor")
	}
	if hooked != 0 {
		t.Errorf("hooks ran %d times for another host's runs", hooked)
	}
	if !listed(t, root, lost.ID) || !listed(t, root, unanchored.ID) {
		t.Error("another host's entries were cleared")
	}
}
