// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestGCLeavesEndedRunsWhoseCleanupIsUncertain(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"not finished", nil},
		{"scope unreadable", os.ErrPermission},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			ref := makeRun(t, root, fixedStart, "endgc0", StateEnded)
			later := WithNow(func() time.Time { return fixedStart.Add(time.Hour) })
			hook := WithEndedHook(func(_ context.Context, dir sys.Lender, got record.RunRef) (bool, error) {
				requireLentRun(t, dir, statDir(t, filepath.Join(root, ref.ID)))
				if got != ref {
					t.Errorf("cleanup run = %+v, want %+v", got, ref)
				}
				return false, tc.err
			})
			rep, err := GC(context.Background(), root, 0, false, later, hook)
			if err != nil || len(rep.Deleted) != 0 || !errors.Is(rep.Errors[ref.ID], tc.err) {
				t.Fatalf("uncertain cleanup: %+v, %v", rep, err)
			}
			if _, err := os.Stat(filepath.Join(root, ref.ID)); err != nil {
				t.Fatalf("ended run's retry record was removed: %v", err)
			}
			complete := WithEndedHook(func(context.Context, sys.Lender, record.RunRef) (bool, error) { return true, nil })
			rep, err = GC(context.Background(), root, 0, false, later, complete)
			if err != nil || len(rep.Errors) != 0 || len(rep.Deleted) != 1 {
				t.Fatalf("completed cleanup: %+v, %v", rep, err)
			}
		})
	}
}

func TestGCEndedRetentionUsesTheLockedDirectory(t *testing.T) {
	root := t.TempDir()
	ref := makeRun(t, root, fixedStart, "endgc1", StateEnded)
	testutil.NoFDLeak(t)
	swap, moved := swapRunAfterLock(t, root, ref.ID)
	var lent []unix.Stat_t
	hook := WithEndedHook(func(_ context.Context, dir sys.Lender, got record.RunRef) (bool, error) {
		lent = append(lent, lentStat(t, dir))
		if got != ref {
			t.Errorf("cleanup run = %+v, want %+v", got, ref)
		}
		return true, nil
	})
	later := WithNow(func() time.Time { return fixedStart.Add(time.Hour) })
	rep, err := GC(context.Background(), root, 0, false, later, hook, swap)
	if err != nil || len(rep.Deleted) != 0 || len(rep.Errors) != 1 {
		t.Fatalf("replacement after the lock: %+v, %v; want a refusal", rep, err)
	}
	requireLentOnce(t, lent, statDir(t, moved))
	for _, path := range []string{moved, filepath.Join(root, ref.ID)} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("directory removed after the name was replaced: %s: %v", path, err)
		}
	}
}
