// SPDX-License-Identifier: Apache-2.0

package runact

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
)

// lockHere flocks dir's run lock from this process, as a launcher holds it: flock is per open file description, so
// the probe's own open reads it as held.
func lockHere(t *testing.T, dir string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, ledger.LockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
}

// TestPause: a pause and a resume of a live run land in its overlay with the dashboard as their by, asking twice
// changes nothing, and an ended run or a caller inside a run is refused.
func TestPause(t *testing.T) {
	defer func(f func() (bool, error)) { selfInRun = f }(selfInRun)
	selfInRun = func() (bool, error) { return false, nil }
	root, dir := liveDir(t, `"tier":"landlock","command":["sh"]`)
	if err := liveblock.MarkControl(dir); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := Pause(ctx, root, liveRun, true); !errors.Is(err, ErrPauseNotRunning) {
		t.Fatalf("pause of an ended run: %v, want ErrPauseNotRunning", err)
	}
	if _, err := Pause(ctx, root, "r-nope", true); !errors.Is(err, ErrBadRun) {
		t.Fatalf("pause of no run: %v, want ErrBadRun", err)
	}
	lockHere(t, dir)
	for _, tc := range []struct {
		on     bool
		word   string
		serial uint64
	}{{true, WordPaused, 1}, {true, WordAlreadyPaused, 1}, {false, WordResumed, 2}, {false, WordNotPaused, 2}} {
		p, err := Pause(ctx, root, liveRun, tc.on)
		if err != nil || p.Word != tc.word || p.Serial != tc.serial {
			t.Fatalf("Pause(%v) = %+v, %v; want %q at serial %d", tc.on, p, err, tc.word, tc.serial)
		}
		if a := PauseRequest(root, liveRun); a.Paused != (tc.word == WordPaused || tc.word == WordAlreadyPaused) || a.Serial != tc.serial || a.At.IsZero() {
			t.Fatalf("PauseRequest after %q = %+v", tc.word, a)
		}
	}
	o, err := liveblock.Read(dir, liveRun)
	if err != nil || len(o.Changes) != 2 || !strings.HasSuffix(o.Changes[0].By, " dashboard") {
		t.Fatalf("overlay %+v, %v", o, err)
	}
	for _, f := range []func() (bool, error){
		func() (bool, error) { return true, nil },
		func() (bool, error) { return true, errors.New("cgroup namespace") },
	} {
		selfInRun = f
		for _, on := range []bool{true, false} {
			if _, err := Pause(ctx, root, liveRun, on); !errors.Is(err, ErrGoverned) {
				t.Fatalf("Pause(%v) from inside a run: %v, want ErrGoverned", on, err)
			}
		}
	}
}

// TestPauseOlderLauncher: a run whose launcher did not mark that it reads a pause (an older Tego, an adoption, no
// cgroup of its own) is refused a pause and a resume alike, nothing reaches its overlay, whose later live blocks an
// older launcher could then not read, and PauseRequest says it takes none. A mark that is a symlink does not count.
func TestPauseOlderLauncher(t *testing.T) {
	defer func(f func() (bool, error)) { selfInRun = f }(selfInRun)
	selfInRun = func() (bool, error) { return false, nil }
	root, dir := liveDir(t, `"tier":"landlock","command":["sh"],"record_minor":24`)
	lockHere(t, dir)
	target := filepath.Join(t.TempDir(), "mark")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, setup := range []func(){func() {}, func() {
		if err := os.Symlink(target, filepath.Join(dir, liveblock.ControlName)); err != nil {
			t.Fatal(err)
		}
	}} {
		setup()
		for _, on := range []bool{true, false} {
			if _, err := Pause(context.Background(), root, liveRun, on); !errors.Is(err, ErrPauseUnsupported) {
				t.Fatalf("Pause(%v) of an unmarked run: %v, want ErrPauseUnsupported", on, err)
			}
		}
		if _, err := liveblock.Read(dir, liveRun); err == nil {
			t.Fatal("a refused pause wrote the overlay")
		}
		if PauseRequest(root, liveRun).Takes {
			t.Fatal("PauseRequest says an unmarked run takes a pause")
		}
	}
}
