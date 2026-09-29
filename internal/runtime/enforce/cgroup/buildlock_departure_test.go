// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestALastLauncherOutRidesOutAProbesMomentaryHold is ADR 0022 (2) against the build lock's other takers: a sweep,
// a ring reclaim or a reaper holds the lock exclusively for a moment, and the build's only launcher that asked
// lastOut inside it read itself not last. It then neither stamped the idle start, so a stamp hours old made the
// next sweep remove at once a build whose run had just ended, nor started the timer. It stamps before it asks and
// asks once more.
func TestALastLauncherOutRidesOutAProbesMomentaryHold(t *testing.T) {
	var timers []string
	now := time.Unix(1_700_000_000, 0)
	var probe *os.File
	f := newFixture(t, func(o *Options) {
		o.Machine = machineLinger(time.Hour)
		o.Now = func() time.Time { return now }
		o.startTimer = func(hash string) error { timers = append(timers, hash); return nil }
		o.lastOutPause = func() {
			if probe != nil {
				_ = probe.Close() // the probe's moment is over
			}
		}
	})
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := h.Attach(f.run.CgroupID); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	lock := filepath.Join(f.dir, "bpf-testhash.lock")
	then := time.Unix(1_600_000_000, 0)
	if err := os.Chtimes(lock, then, then); err != nil {
		t.Fatal(err)
	}
	// A shared hold stands in for the probe's exclusive one, which the launcher's own shared hold forbids: either
	// makes the launcher's lastOut fail.
	if probe, err = os.Open(lock); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = probe.Close() }()
	if err := unix.Flock(int(probe.Fd()), unix.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	if err := h.Detach(); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Stat(lock, &st); err != nil {
		t.Fatal(err)
	}
	if got := time.Unix(st.Mtim.Unix()); !got.Equal(now) {
		t.Errorf("the build lock's mtime is %v, want the departure time %v", got, now)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if len(timers) != 1 {
		t.Fatalf("timers started: %v, want one: the launcher was the last out", timers)
	}
}

// TestTwoDeparturesExactlyOneIsLast: two launchers of one build that leave together each
// asked lastOut while the other still held its shared lock, and each took its own shared hold back after
// failing, so both answered false and nobody unpinned the build. Exactly one of them must be last.
//
// Also pins runtime-launch.md I6: with two holders exactly one departure sees itself last.
func TestTwoDeparturesExactlyOneIsLast(t *testing.T) {
	dir := t.TempDir()
	a, err := acquireBuildLock(dir, "h")
	if err != nil {
		t.Fatal(err)
	}
	b, err := acquireBuildLock(dir, "h")
	if err != nil {
		t.Fatal(err)
	}
	la, err := a.lastOut()
	if err != nil {
		t.Fatal(err)
	}
	lb, err := b.lastOut()
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
	_ = b.Close()
	if la == lb {
		t.Fatalf("lastOut answered %v and %v: exactly one departing launcher must be last", la, lb)
	}
}
