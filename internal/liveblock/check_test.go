// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

const checkRun = "r-3f9c2a1b-0dllq06ts7402-check1"

// TestCheckBlock holds the one set of checks every writer of a block makes (runact for the dashboard, `tego block` and
// `tego unblock`): which rule refuses, with which sentinel, in which words, and that a run that has ended is refused a
// removal as it is a block.
func TestCheckBlock(t *testing.T) {
	soon := time.Now().Add(time.Hour)
	full := Target{Run: checkRun, Running: true, Timed: true, NarrowKinds: true, ReadsSeen: true}
	for _, tc := range []struct {
		name  string
		t     Target
		kind  Kind
		add   bool
		until time.Time
		want  error
		words string // RunWords' sentence; Error says "the run" in place of the run's id
	}{
		{"block on an ended run", Target{Run: checkRun}, KindExec, true, time.Time{}, ErrNotRunning,
			checkRun + " is not running, so a live block would enforce nothing"},
		{"unblock on an ended run", Target{Run: checkRun}, KindExec, false, time.Time{}, ErrNotRunning,
			checkRun + " is not running: its live blocks ended with it, so there is nothing to remove"},
		{"unblock for a while on an ended run", Target{Run: checkRun, Timed: true}, KindPath, false, soon, ErrNotRunning,
			checkRun + " is not running: its live blocks ended with it, so there is nothing to remove"},
		{"a limit an older launcher does not read", Target{Run: checkRun, Running: true}, KindExec, true, soon, ErrNoTimeLimits,
			checkRun + ": " + ErrNoTimeLimits.Error()},
		{"an unblock's limit too", Target{Run: checkRun, Running: true}, KindExec, false, soon, ErrNoTimeLimits,
			checkRun + ": " + ErrNoTimeLimits.Error()},
		{"a read block on an older launcher", Target{Run: checkRun, Running: true, ReadsSeen: true}, KindRead, true, time.Time{},
			ErrOldLauncher, checkRun + " was started by an older tego that has no read blocks, so it would not put this one in force"},
		{"a write block on an older launcher", Target{Run: checkRun, Running: true}, KindWrite, true, time.Time{}, ErrOldLauncher,
			checkRun + " was started by an older tego that has no write blocks, so it would not put this one in force"},
		{"a read block whose reads are unseen", Target{Run: checkRun, Running: true, NarrowKinds: true}, KindRead, true,
			time.Time{}, ErrReadsUnseen,
			checkRun + " does not see its reads (they are neither held nor recorded), so a read block would refuse nothing"},
		{"the older kinds on an older launcher", Target{Run: checkRun, Running: true}, KindPath, true, time.Time{}, nil, ""},
		{"a write block whose reads are unseen", Target{Run: checkRun, Running: true, NarrowKinds: true}, KindWrite, true,
			time.Time{}, nil, ""},
		{"removing a read block on an older launcher", Target{Run: checkRun, Running: true}, KindRead, false, time.Time{}, nil, ""},
		{"a timed read block on a full run", full, KindRead, true, soon, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckBlock(tc.t, tc.kind, tc.add, tc.until)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("CheckBlock = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) || RunWords(err) != tc.words {
				t.Fatalf("CheckBlock = %v (%q), want %v in the words %q", err, RunWords(err), tc.want, tc.words)
			}
			if page := strings.Replace(tc.words, checkRun, "the run", 1); tc.want == ErrNoTimeLimits {
				if err.Error() != ErrNoTimeLimits.Error() {
					t.Errorf("Error = %q, want ErrNoTimeLimits' own words", err)
				}
			} else if err.Error() != page {
				t.Errorf("Error = %q, want %q", err, page)
			}
		})
	}
}

// TestCheckFence holds the checks of a lift, a grant and a restore, in their order: not running, a limit the launcher
// does not read, Locked, outside the fence.
func TestCheckFence(t *testing.T) {
	soon := time.Now().Add(time.Hour)
	for _, tc := range []struct {
		name  string
		t     Target
		until time.Time
		want  error
		words string
	}{
		{"an ended run", Target{Run: checkRun, Adjustable: true, Fenced: true}, time.Time{}, ErrNotRunning,
			checkRun + " is not running, so nothing would apply it; a run's fence starts refused again in its next run"},
		{"a limit before Locked", Target{Run: checkRun, Running: true}, soon, ErrNoTimeLimits, checkRun + ": " + ErrNoTimeLimits.Error()},
		{"a Locked run", Target{Run: checkRun, Running: true, Timed: true}, soon, ErrLocked,
			checkRun + " is Locked: the kernel holds it to its contract while it runs, so nothing loosens until its next run"},
		{"outside the fence", Target{Run: checkRun, Running: true, Timed: true, Adjustable: true}, time.Time{}, ErrOutsideFence,
			"read:/srv/x is outside " + checkRun + "'s fence, so it cannot change while the run runs"},
		{"inside the fence", Target{Run: checkRun, Running: true, Timed: true, Adjustable: true, Fenced: true}, soon, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckFence(tc.t, KindRead, "/srv/x", tc.until)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("CheckFence = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.want) || RunWords(err) != tc.words {
				t.Fatalf("CheckFence = %v (%q), want %v in the words %q", err, RunWords(err), tc.want, tc.words)
			}
			if tc.want != ErrNoTimeLimits && err.Error() != strings.Replace(tc.words, checkRun, "the run", 1) {
				t.Errorf("Error = %q, want the words with \"the run\"", err)
			}
		})
	}
}

// TestLiftKey: a key that cannot be read is ErrNoKey, keeping why (the file's own error) both in the words and for
// errors.Is; a key the launcher made is read.
func TestLiftKey(t *testing.T) {
	dir := t.TempDir()
	_, err := LiftKey(dir, checkRun)
	if !errors.Is(err, ErrNoKey) || !errors.Is(err, os.ErrNotExist) ||
		!strings.HasPrefix(RunWords(err), checkRun+"'s live key cannot be read, so no lift can be asked: ") ||
		!strings.HasPrefix(err.Error(), "the run's live key cannot be read") {
		t.Fatalf("LiftKey with no key = %v (%q), want ErrNoKey naming the run", err, RunWords(err))
	}
	want, err := WriteKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := LiftKey(dir, checkRun); err != nil || string(got) != string(want) {
		t.Fatalf("LiftKey = %x, %v", got, err)
	}
	if RunWords(errors.New("plain")) != "plain" {
		t.Error("RunWords of another error is not its Error")
	}
}

// TestBlockWord: the words of an add and a removal, changed or not.
func TestBlockWord(t *testing.T) {
	for _, tc := range []struct {
		add, changed bool
		want         string
	}{{true, true, "blocked"}, {true, false, "already blocked"}, {false, true, "block removed"}, {false, false, "was not blocked"}} {
		if got := BlockWord(tc.add, tc.changed); got != tc.want {
			t.Errorf("BlockWord(%t, %t) = %q, want %q", tc.add, tc.changed, got, tc.want)
		}
	}
}
