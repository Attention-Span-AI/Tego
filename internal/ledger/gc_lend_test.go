// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"maps"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestHooksAreLentTheRunDirectoryForTheCallAlone: the sweep, reclaim and ended hooks are each lent their run's own
// directory, and the pass closes it when the hook returns (lendRun): a lender a hook kept lends nothing afterwards
// (sys.ErrClosed), and no descriptor outlives the passes (ADR 0023 A8).
func TestHooksAreLentTheRunDirectoryForTheCallAlone(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	lost := makeRun(t, root, fixedStart, "lend01", StateLost)
	running := makeRun(t, root, fixedStart, "lend02", StateRunning)
	ended := makeRun(t, root, fixedStart, "lend03", StateEnded)
	if err := MarkLive(root, ended.ID); err != nil {
		t.Fatal(err)
	}
	// After the fixtures: the lost run's dead launcher keeps its directories open, as makeRun leaves them, and the
	// running run's Writer stays open until the test's end.
	testutil.NoFDLeak(t)
	var kept []sys.Lender
	calls := map[string]string{}
	lent := func(hook string, dir sys.Lender, ref record.RunRef) {
		var st unix.Stat_t
		if err := dir.Borrow(func(n int) error { return unix.Fstat(n, &st) }); err != nil {
			t.Errorf("%s hook for %s: the lent directory: %v", hook, ref.ID, err)
		}
		if want := statDir(t, filepath.Join(root, ref.ID)); st.Dev != want.Dev || st.Ino != want.Ino {
			t.Errorf("the %s hook for %s was lent another directory", hook, ref.ID)
		}
		calls[hook] = ref.ID
		kept = append(kept, dir)
	}
	opts := []GCOption{
		WithWriterOptions(WithAnchor(&memAnchor{})),
		WithSweepHook(func(_ context.Context, dir sys.Lender, ref record.RunRef) error {
			lent("sweep", dir, ref)
			return nil
		}),
		WithReclaimHook(func(_ context.Context, dir sys.Lender, ref record.RunRef) bool {
			lent("reclaim", dir, ref)
			return false
		}),
		WithEndedHook(func(_ context.Context, dir sys.Lender, ref record.RunRef) (bool, error) {
			lent("ended", dir, ref)
			return true, nil
		}),
	}
	if rep, err := GC(ctx, root, keepAll, false, opts...); err != nil || len(rep.Errors) != 0 {
		t.Fatalf("GC: %+v, %v", rep, err)
	}
	if rep, err := SweepLive(ctx, root, opts...); err != nil || len(rep.Errors) != 0 {
		t.Fatalf("SweepLive: %+v, %v", rep, err)
	}
	if want := map[string]string{"sweep": lost.ID, "reclaim": running.ID, "ended": ended.ID}; !maps.Equal(calls, want) {
		t.Fatalf("hooks ran %v, want %v", calls, want)
	}
	for _, dir := range kept {
		if err := dir.Borrow(func(int) error { return nil }); !errors.Is(err, sys.ErrClosed) {
			t.Errorf("a lender kept past its hook's call lends: %v, want sys.ErrClosed", err)
		}
	}
}
