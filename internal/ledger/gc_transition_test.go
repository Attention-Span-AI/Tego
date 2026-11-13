// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// An empty sample is not evidence that cleanup stays unnecessary until removal. The clock seam starts and
// loses or ends a real Writer after that sample and the empty sweep, before GC takes the removal lock.
func TestGCRetentionRechecksEmptyTransitions(t *testing.T) {
	for _, tc := range []struct {
		name  string
		state RunState
		err   error
	}{
		{"lost cleanup fails", StateLost, os.ErrPermission},
		{"lost cleanup succeeds", StateLost, nil},
		{"ended cleanup fails", StateEnded, os.ErrPermission},
		{"ended cleanup unfinished", StateEnded, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			ref := record.RunRef{ID: runID(fixedStart, "r5tran"), Agent: "retriever"}
			if err := MakeRunDir(root, ref.ID); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(root, ref.ID)
			started := false
			later := WithNow(func() time.Time {
				if !started {
					started = true
					w, err := Open(dir, ref, WithAnchor(&memAnchor{}),
						WithContract([]byte("version: 0\nname: retriever\ncommand: [true]\n")))
					if err != nil {
						t.Fatal(err)
					}
					start := startPayload()
					start.RecordMinor = record.MinorLiveControl
					if err := w.WriteRunStart(start); err != nil {
						t.Fatal(err)
					}
					gap := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor}
					if err := gap.SetPayload(record.GapPayload{What: record.GapEnforce, Why: record.GapRunPaused,
						LiveControl: &record.LiveControlChange{Op: record.LiveOpPause, By: "test", Serial: 1, At: fixedStart.UTC()}}); err != nil {
						t.Fatal(err)
					}
					if err := w.Append(gap); err != nil {
						t.Fatal(err)
					}
					if tc.state == StateEnded {
						err = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
					} else {
						err = w.Abandon()
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				return fixedStart.Add(time.Hour)
			})
			calls := 0
			cleanup := func(lent sys.Lender, got record.RunRef) {
				calls++
				requireLentRun(t, lent, statDir(t, dir))
				if got != ref {
					t.Errorf("cleanup run = %+v, want %+v", got, ref)
				}
			}
			sweepHook := WithSweepHook(func(_ context.Context, lent sys.Lender, got record.RunRef) error {
				if tc.state != StateLost {
					t.Error("ended transition used the lost cleanup hook")
				}
				cleanup(lent, got)
				return tc.err
			})
			endedHook := WithEndedHook(func(_ context.Context, lent sys.Lender, got record.RunRef) (bool, error) {
				if tc.state != StateEnded {
					t.Error("lost transition used the ended cleanup hook")
				}
				cleanup(lent, got)
				return false, tc.err
			})
			rep, err := GC(context.Background(), root, 0, false, later, sweepHook, endedHook)
			if err != nil || len(rep.Deleted) != 0 || calls != 1 || !errors.Is(rep.Errors[ref.ID], tc.err) {
				t.Fatalf("transition cleanup: %+v, %v, calls=%d; want retained and one cleanup", rep, err, calls)
			}
			requireState(t, dir, tc.state)
		})
	}
}

func TestGCRetentionKeepsAnUnknownLockedState(t *testing.T) {
	root := t.TempDir()
	ref := record.RunRef{ID: runID(fixedStart, "r5unkn"), Agent: "retriever"}
	if err := MakeRunDir(root, ref.ID); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, ref.ID)
	later := WithNow(func() time.Time {
		if err := os.WriteFile(filepath.Join(dir, EventsFile), []byte("broken ledger\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return fixedStart.Add(time.Hour)
	})
	rep, err := GC(context.Background(), root, 0, false, later)
	if err != nil || len(rep.Deleted) != 0 || !errors.Is(rep.Errors[ref.ID], ErrCorruptLedger) {
		t.Fatalf("unknown locked state: %+v, %v; want retained corruption error", rep, err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("unknown state's retry record removed: %v", err)
	}
}

func TestSweepKeepsAnEmptyRunWithUnknownContract(t *testing.T) {
	for _, failure := range []string{"unreadable file", "invalid agent"} {
		t.Run(failure, func(t *testing.T) {
			root := t.TempDir()
			ref := makeRun(t, root, fixedStart, "r5cntr", StateEmpty)
			dir := filepath.Join(root, ref.ID)
			contract := filepath.Join(dir, ContractFile)
			if failure == "unreadable file" {
				if err := os.Mkdir(contract, 0o700); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(contract, []byte("name: ../invalid\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := MarkLive(root, ref.ID); err != nil {
				t.Fatal(err)
			}
			hook := WithSweepHook(func(context.Context, sys.Lender, record.RunRef) error {
				t.Error("unknown agent must not pick a scope to clean up")
				return nil
			})
			rep, err := SweepLive(context.Background(), root, hook)
			if err != nil || len(rep.Errors) != 1 {
				t.Fatalf("unknown contract: %+v, %v; want retained error", rep, err)
			}
			if _, err := os.Stat(filepath.Join(root, LiveDir, ref.ID)); err != nil {
				t.Fatalf("unknown contract lost its retry entry: %v", err)
			}
		})
	}
}

func TestSweepKeepsAnEmptyRunThatBecameLostBeforeItsLock(t *testing.T) {
	root, source := t.TempDir(), t.TempDir()
	ref := makeRun(t, root, fixedStart, "r5late", StateEmpty)
	makeRun(t, source, fixedStart, "r5late", StateLost)
	ledger, err := os.ReadFile(filepath.Join(source, ref.ID, EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := MarkLive(root, ref.ID); err != nil {
		t.Fatal(err)
	}
	transition := func(o *gcOptions) {
		o.locked = func(id string) {
			if err := os.WriteFile(filepath.Join(root, id, EventsFile), ledger, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	hook := WithSweepHook(func(context.Context, sys.Lender, record.RunRef) error {
		t.Error("empty sweep must defer the newly lost run to the ordinary sweep")
		return nil
	})
	rep, err := SweepLive(context.Background(), root, transition, hook)
	if err != nil || len(rep.Errors) != 0 {
		t.Fatalf("transitioned live entry: %+v, %v", rep, err)
	}
	if _, err := os.Stat(filepath.Join(root, LiveDir, ref.ID)); err != nil {
		t.Fatalf("newly lost run lost its retry entry: %v", err)
	}
}
