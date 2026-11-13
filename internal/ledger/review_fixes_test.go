// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestStateNeverReadsLostForALiveWriter: Close appends run_end and only then releases the lock (§4), so a
// State racing it must read running or ended. Reading the tail before probing the lock let a run that ended in
// between read as lost. The window is microseconds wide; the loop makes hitting it near-certain.
func TestStateNeverReadsLostForALiveWriter(t *testing.T) {
	root := t.TempDir()
	lost := 0
	for i := range 1500 {
		ref := record.RunRef{ID: runID(fixedStart, fmt.Sprintf("st%04d", i)), Agent: "retriever"}
		w, err := Open(filepath.Join(root, ref.ID), ref, WithAnchor(&memAnchor{}))
		if err != nil {
			t.Fatal(err)
		}
		startRun(t, w, 1)
		rd, err := OpenReader(filepath.Join(root, ref.ID))
		if err != nil {
			t.Fatal(err)
		}
		stop := make(chan struct{})
		var wg sync.WaitGroup
		n := 0
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if s, err := rd.State(); err == nil && s == StateLost {
					n++
				}
			}
		}()
		if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
			t.Fatal(err)
		}
		close(stop)
		wg.Wait()
		lost += n
		_ = rd.Close()
	}
	if lost != 0 {
		t.Fatalf("State read a live-then-ended run as lost %d times", lost)
	}
}

// TestLockDoesNotRecreateARemovedRunDir: a sweeper that read a run as lost and then met gc's removal of it
// must not make the directory again and write a run_end-only ledger and an anchor line for a run that is gone.
func TestLockDoesNotRecreateARemovedRunDir(t *testing.T) {
	root := t.TempDir()
	ref := makeRun(t, root, fixedStart, "gh0001", StateLost)
	if err := os.RemoveAll(filepath.Join(root, ref.ID)); err != nil {
		t.Fatal(err)
	}
	repo := NewRunRepository(root, WithAnchor(&memAnchor{}))
	if _, err := repo.Lock(context.Background(), ref.ID, ref); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Lock on a removed run = %v, want os.ErrNotExist", err)
	}
	if _, err := os.Stat(filepath.Join(root, ref.ID)); !os.IsNotExist(err) {
		t.Fatalf("Lock recreated the run directory: %v", err)
	}
	anchor := &memAnchor{}
	hooks := 0
	o := &gcOptions{sweep: func(context.Context, sys.Lender, record.RunRef) error { hooks++; return nil }}
	swept, err := sweep(context.Background(), NewRunRepository(root, WithAnchor(anchor)), ref, o)
	if swept || err != nil || hooks != 0 {
		t.Fatalf("sweep of a removed run = swept %v err %v hooks %d, want false, nil, 0", swept, err, hooks)
	}
	if _, ok, _ := anchor.Head(ref.ID); ok {
		t.Fatal("a ghost run was anchored")
	}
	if _, err := os.Stat(filepath.Join(root, ref.ID)); !os.IsNotExist(err) {
		t.Fatalf("sweep recreated the run directory: %v", err)
	}
}

// An unknown state refuses retention before any removal is attempted, whatever the directory permissions.
func TestGCRetainsUnknownStateBeforeRemoval(t *testing.T) {
	root := t.TempDir()
	now := fixedStart.Add(40 * 24 * time.Hour)
	ref := makeRun(t, root, fixedStart, "je0001", StateEnded)
	dir := filepath.Join(root, ref.ID)
	unreadableLedger(t, dir) // skips as root
	// r-x on the run directory: removal would also fail if GC wrongly reached it.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	rep, err := GC(context.Background(), root, 30*24*time.Hour, false, WithNow(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	got := rep.Errors[ref.ID]
	if got == nil || !strings.Contains(got.Error(), "events") || strings.Contains(got.Error(), "remove") || len(rep.Deleted) != 0 {
		t.Fatalf("unknown state: %+v; want the state error without an attempted removal", rep)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("unknown run removed: %v", err)
	}
}

// TestResumedRunSyncsTheDeadWritersBlobs: blobs the dead writer stored are named by lines Close will fsync and
// anchor, so Close must make them durable too, though this store never saw them written (R6).
func TestResumedRunSyncsTheDeadWritersBlobs(t *testing.T) {
	root := t.TempDir()
	ref := record.RunRef{ID: runID(fixedStart, "bl0001"), Agent: "retriever"}
	dir := filepath.Join(root, ref.ID)
	w, err := Open(dir, ref, WithAnchor(&memAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	startRun(t, w, 1)
	if _, err := w.Blob(bytes.Repeat([]byte("b"), 8192)); err != nil {
		t.Fatal(err)
	}
	die(w)
	w2, err := Open(dir, ref, WithAnchor(&memAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w2.Close(record.RunEndPayload{Reason: record.RunEndOrphaned}) })
	w2.blobs.mu.Lock()
	all := w2.blobs.overflow || len(w2.blobs.pending) > 0
	w2.blobs.mu.Unlock()
	if !all {
		t.Fatal("a resumed run's Close would fsync none of the blobs its dead writer stored")
	}
}
