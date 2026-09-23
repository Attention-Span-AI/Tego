// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// startedRun leaves a run directory with run_start and no run_end, as a launcher that died would.
func startedRun(t *testing.T, root, id string) {
	t.Helper()
	w := openRun(t, root, id)
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "landlock"}); err != nil {
		t.Fatalf("run_start: %v", err)
	}
	// Releasing the lock without run_end is exactly what a killed launcher leaves behind. Close
	// writes run_end, so the lock is dropped by closing the writer's own descriptors instead.
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatalf("close: %v", err)
	}
	truncateRunEnd(t, filepath.Join(root, id))
}

// truncateRunEnd removes the last line of a run's ledger, leaving a started-but-never-ended run.
func truncateRunEnd(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, ledger.EventsFile)
	b := readFile(t, path)
	last := -1
	for i := len(b) - 2; i >= 0; i-- {
		if b[i] == '\n' {
			last = i + 1
			break
		}
	}
	if last < 0 {
		t.Fatalf("%s has one line only", path)
	}
	writeFile(t, path, b[:last])
}

// Also pins runtime-launch.md E13: a run left with no run_end is ended as orphaned.
func TestSweepEndsOnlyTheOrphans(t *testing.T) {
	root := t.TempDir()
	const (
		orphan = "r-00000000-000000000000a-orphan"
		ended  = "r-00000000-000000000000b-ended0"
		live   = "r-00000000-000000000000c-live00"
	)
	startedRun(t, root, orphan)

	w := openRun(t, root, ended)
	if err := w.WriteRunStart(record.RunStartPayload{Tier: "landlock"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}

	livew := openRun(t, root, live) // still holds its lock: R12's probe must refuse it
	if err := livew.WriteRunStart(record.RunStartPayload{Tier: "landlock"}); err != nil {
		t.Fatal(err)
	}
	defer livew.Close(record.RunEndPayload{Reason: record.RunEndExit})

	res, err := Sweep(context.Background(), root, KeepForever, WithSweepManager(nil), WithSweepDryRun(false))
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if res.Orphaned != 1 {
		t.Fatalf("orphaned %d, want 1 (errs %v)", res.Orphaned, res.Errs)
	}
	if res.Scanned != 3 {
		t.Fatalf("scanned %d, want 3", res.Scanned)
	}
	if res.Deleted != 0 {
		t.Fatalf("KeepForever deleted %d run(s)", res.Deleted)
	}
	if got := lastReason(t, filepath.Join(root, orphan)); got != record.RunEndOrphaned {
		t.Fatalf("orphan ended with %q, want orphaned", got)
	}
	if got := lastReason(t, filepath.Join(root, ended)); got != record.RunEndExit {
		t.Fatalf("an ended run was rewritten: %q", got)
	}
	if got := lastKind(t, filepath.Join(root, live)); got == record.KindRunEnd {
		t.Fatal("the live run was ended by the sweep")
	}
}

func TestSweepIsIdempotent(t *testing.T) {
	root := t.TempDir()
	startedRun(t, root, "r-00000000-000000000000a-orphan")
	ctx := context.Background()
	if _, err := Sweep(ctx, root, KeepForever); err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	res, err := Sweep(ctx, root, KeepForever)
	if err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if res.Orphaned != 0 {
		t.Fatalf("second pass swept %d run(s)", res.Orphaned)
	}
}

func TestSweepMissingRoot(t *testing.T) {
	res, err := Sweep(context.Background(), filepath.Join(t.TempDir(), "never-used"), KeepForever)
	if err != nil || res.Scanned != 0 {
		t.Fatalf("res %+v err %v, want an empty pass", res, err)
	}
}

func TestSweepRetentionDeletesEndedRuns(t *testing.T) {
	root := t.TempDir()
	const ended = "r-00000000-000000000000b-ended0"
	w := openRun(t, root, ended)
	if err := w.WriteRunStart(record.RunStartPayload{Tier: "landlock"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	later := func() time.Time { return time.Now().Add(48 * time.Hour) }
	res, err := Sweep(context.Background(), root, 24*time.Hour, WithSweepClock(later))
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if res.Deleted != 1 {
		t.Fatalf("deleted %d, want 1", res.Deleted)
	}
}

// BenchmarkSweepNRuns measures one pass over a ledger root of ended runs: what `tego run` pays at
// startup before it launches anything (docs/p0/runtime-launch.md §9 "Benchmarks").
func BenchmarkSweepNRuns(b *testing.B) {
	for _, n := range []int{10, 100} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			root := b.TempDir()
			for i := range n {
				id := fmt.Sprintf("r-00000000-%013d-%06d", i, i)
				w, err := ledger.Open(filepath.Join(root, id), record.RunRef{ID: id, Agent: "bench"},
					ledger.WithAnchor(benchAnchor{}))
				if err != nil {
					b.Fatal(err)
				}
				if err := w.WriteRunStart(record.RunStartPayload{Tier: "landlock"}); err != nil {
					b.Fatal(err)
				}
				if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
					b.Fatal(err)
				}
			}
			ctx := context.Background()
			b.ReportAllocs()
			for b.Loop() {
				if _, err := Sweep(ctx, root, KeepForever); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkSweepLiveNRuns measures the sweep `tego run` and `tego stop` make before they act, over a
// ledger root of N sealed runs: runs that ended and left the live index, as every run that exits does. Its
// cost must not grow with N (P4: the pass over every run cost each start about 73 µs per stored run).
func BenchmarkSweepLiveNRuns(b *testing.B) {
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			root := b.TempDir()
			for i := range n {
				id := fmt.Sprintf("r-00000000-%013d-%06d", i, i)
				w, err := ledger.Open(filepath.Join(root, id), record.RunRef{ID: id, Agent: "bench"},
					ledger.WithAnchor(benchAnchor{}))
				if err != nil {
					b.Fatal(err)
				}
				if err := ledger.MarkLive(root, id); err != nil {
					b.Fatal(err)
				}
				if err := w.WriteRunStart(record.RunStartPayload{Tier: "landlock"}); err != nil {
					b.Fatal(err)
				}
				if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
					b.Fatal(err)
				}
				if err := ledger.ClearLive(root, id); err != nil {
					b.Fatal(err)
				}
			}
			ctx := context.Background()
			b.ReportAllocs()
			for b.Loop() {
				if _, err := SweepLive(ctx, root); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestSweepLiveEndsOnlyListedOrphans is the runtime's index sweep over the ledger's: the listed orphan
// is killed first and ended, an orphan the index does not name is left for gc's full pass, and nothing
// is deleted.
//
// Also pins runtime-launch.md R20: run and stop sweep only the live index; gc alone passes over every run.
func TestSweepLiveEndsOnlyListedOrphans(t *testing.T) {
	root := t.TempDir()
	const (
		listed   = "r-00000000-000000000000a-listed"
		unlisted = "r-00000000-000000000000b-notlst"
	)
	startedRun(t, root, listed)
	if err := ledger.MarkLive(root, listed); err != nil {
		t.Fatal(err)
	}
	startedRun(t, root, unlisted)
	cg := &fakeCgroups{root: t.TempDir()}
	res, err := SweepLive(context.Background(), root, WithSweepManager(cg))
	if err != nil || len(res.Errs) != 0 {
		t.Fatalf("SweepLive: %v %v", err, res.Errs)
	}
	if res.Orphaned != 1 || res.Deleted != 0 {
		t.Fatalf("result %+v, want one orphan ended and nothing deleted", res)
	}
	if got := lastReason(t, filepath.Join(root, listed)); got != record.RunEndOrphaned {
		t.Errorf("the listed orphan ended with %q, want orphaned", got)
	}
	if got := lastKind(t, filepath.Join(root, unlisted)); got == record.KindRunEnd {
		t.Error("the sweep ended a run the index does not name")
	}
	res, err = Sweep(context.Background(), root, KeepForever, WithSweepManager(cg))
	if err != nil || res.Orphaned != 1 {
		t.Fatalf("gc's pass: %+v %v, want it to end the unlisted orphan", res, err)
	}
}

// benchAnchor keeps the benchmark out of the host-wide chain.log.
type benchAnchor struct{}

func (benchAnchor) Append(string, string) error       { return nil }
func (benchAnchor) Head(string) (string, bool, error) { return "", false, nil }

// TestAnOrphanedStopMarkerIsSweptWithItsRun is runtime-launch.md E12: `tego stop` made stop.request and the
// launcher was kill -9'd before it read it. The marker means nothing to the record: the sweep ends the run as
// orphaned like any other, leaves the marker where it is (it is no schema, and no part of what the sweep
// judges), and gc removes it with the whole run directory at retention.
func TestAnOrphanedStopMarkerIsSweptWithItsRun(t *testing.T) {
	root := t.TempDir()
	const orphan = "r-00000000-000000000000a-orphan"
	startedRun(t, root, orphan)
	dir := filepath.Join(root, orphan)
	if err := RequestStop(dir); err != nil {
		t.Fatal(err)
	}
	res, err := Sweep(context.Background(), root, KeepForever)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if res.Orphaned != 1 || len(res.Errs) != 0 {
		t.Fatalf("orphaned %d (errs %v), want 1 with the marker beside it", res.Orphaned, res.Errs)
	}
	if got := lastReason(t, dir); got != record.RunEndOrphaned {
		t.Fatalf("the marked orphan ended with %q, want orphaned", got)
	}
	if !StopRequested(dir) {
		t.Fatal("the sweep touched the marker")
	}
	later := func() time.Time { return time.Now().Add(48 * time.Hour) }
	res, err = Sweep(context.Background(), root, 24*time.Hour, WithSweepClock(later))
	if err != nil {
		t.Fatalf("retention Sweep: %v", err)
	}
	if res.Deleted != 1 {
		t.Fatalf("deleted %d, want the run and its marker gone", res.Deleted)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the run directory, marker included, is still there: %v", err)
	}
}
