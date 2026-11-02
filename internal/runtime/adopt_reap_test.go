// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const adoptReapTestRun = "r-00000000-000000000000a-adreap"

// orphanedAdoption is the record an adoption of adoptReapTestRun leaves its reaper or a release: the run directory in
// runs, and the scope under the fixture's cgroup mount, made and empty (its processes have left or exited since).
func orphanedAdoption(t *testing.T, f *adoptFixture, runs string) adoptRecord {
	t.Helper()
	scope := filepath.Join(f.host.mount, "tego.slice", adopt.ScopeName(adoptReapTestRun))
	if err := os.MkdirAll(scope, 0o755); err != nil {
		t.Fatal(err)
	}
	return adoptRecord{Run: adoptReapTestRun, Agent: "tester", Dir: filepath.Join(runs, adoptReapTestRun),
		Mount: f.host.mount, Scope: scope, From: adoptSession, Anchor: filepath.Join(t.TempDir(), "chain.log")}
}

// reaperDirFD opens dir O_PATH, as an adopter hands its reaper the run directory (descriptor 4).
func reaperDirFD(t *testing.T, dir string) int {
	t.Helper()
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

// treeUnder lists every path under base, relative to it.
func treeUnder(t *testing.T, base string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(base, func(path string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(base, path)
		out = append(out, rel)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestReleaseOrphanMakesNothingWhereTheRunIsGone is TestTheReaperMakesNothingInARunDirectoryBeingRemoved for an
// adoption. A run that ended with a process left in its scope keeps its record, marked released. Its reaper, waking
// as the adopter exits, opens the ended run's ledger at once, while `tego gc` or a test's RemoveAll may be taking the
// run directory; `tego adopt --release` opens it by the record's path whenever it comes, after retention may have
// removed the run. Either open made what was missing: the lock, an empty events.jsonl and blobs/, and by path the run
// directory and the ledger root as well. A removal under way then failed with "directory not empty", and the empty
// ledger read as a run that never started. Now nothing is made, and the release goes on: no run is left to end.
func TestReleaseOrphanMakesNothingWhereTheRunIsGone(t *testing.T) {
	removeAll := func(t *testing.T, path string) {
		t.Helper()
		if err := os.RemoveAll(path); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name string
		// reaper says the release is the reaper's, through the run directory it inherited, opened before the removal;
		// otherwise it is `tego adopt --release`'s, by the record's path.
		reaper bool
		remove func(t *testing.T, runs, dir string)
	}{
		{"the reaper, the run's files being removed", true, func(t *testing.T, _, dir string) {
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range entries {
				removeAll(t, filepath.Join(dir, e.Name()))
			}
		}},
		{"the reaper, the run directory removed", true, func(t *testing.T, _, dir string) { removeAll(t, dir) }},
		{"a release, the run directory removed", false, func(t *testing.T, _, dir string) { removeAll(t, dir) }},
		{"a release, the ledger root removed", false, func(t *testing.T, runs, _ string) { removeAll(t, runs) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAdoptFixture(t)
			base := t.TempDir()
			runs := filepath.Join(base, "runs")
			rec := orphanedAdoption(t, f, runs)
			rec.Released, rec.Left = true, 1
			w := openRun(t, runs, adoptReapTestRun)
			if err := w.WriteRunStart(record.RunStartPayload{Tier: "cgroup"}); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
				t.Fatal(err)
			}
			dirfd := -1
			if tc.reaper {
				dirfd = reaperDirFD(t, rec.Dir)
			}
			tc.remove(t, runs, rec.Dir)
			before := treeUnder(t, base)
			out, err := releaseOrphan(&adoptStore{dir: f.state}, rec, f.host.env(), dirfd, "the adopter died", nil)
			if err != nil {
				t.Fatalf("releaseOrphan: %v; a run that is gone has no run_end to write", err)
			}
			if out.Ended {
				t.Error("run_end written for a run that is gone")
			}
			if !out.Removed {
				t.Error("the scope was not removed: the release stopped at the run's ledger")
			}
			if after := treeUnder(t, base); !slices.Equal(after, before) {
				t.Errorf("the release made files where the run was: %v, where the removal left %v", after, before)
			}
		})
	}
}

// TestReleaseOrphanThroughTheReapersDescriptor: a reaper that makes nothing still ends what it should when the run's
// files are there. A run its adopter started and never ended gets run_end orphaned, written through the run directory
// the reaper inherited. One whose adopter died before run_start is left as it is, an empty ledger that reads as a run
// that never started, for the sweep to remove.
func TestReleaseOrphanThroughTheReapersDescriptor(t *testing.T) {
	t.Run("started", func(t *testing.T) {
		f := newAdoptFixture(t)
		runs := t.TempDir()
		rec := orphanedAdoption(t, f, runs)
		startedRun(t, runs, adoptReapTestRun)
		out, err := releaseOrphan(&adoptStore{dir: f.state}, rec, f.host.env(), reaperDirFD(t, rec.Dir),
			"the adopter died", nil)
		if err != nil || !out.Ended {
			t.Fatalf("releaseOrphan of a started run: ended %v, %v; want its run_end written", out.Ended, err)
		}
		if got := lastReason(t, rec.Dir); got != record.RunEndOrphaned {
			t.Errorf("run_end reason %q, want %q", got, record.RunEndOrphaned)
		}
	})
	t.Run("never started", func(t *testing.T) {
		f := newAdoptFixture(t)
		runs := t.TempDir()
		rec := orphanedAdoption(t, f, runs)
		if err := openRun(t, runs, adoptReapTestRun).Abandon(); err != nil {
			t.Fatal(err)
		}
		before := treeUnder(t, runs)
		out, err := releaseOrphan(&adoptStore{dir: f.state}, rec, f.host.env(), reaperDirFD(t, rec.Dir),
			"the adopter died", nil)
		if err != nil || out.Ended {
			t.Fatalf("releaseOrphan of a run that never started: ended %v, %v; want it left as it is", out.Ended, err)
		}
		if after := treeUnder(t, runs); !slices.Equal(after, before) {
			t.Errorf("the run directory holds %v after the release, %v before", after, before)
		}
		if evs := events(t, rec.Dir); len(evs) != 0 {
			t.Errorf("%d line(s) written to a run that never started", len(evs))
		}
	})
}
