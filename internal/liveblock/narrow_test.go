// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestAddOnlyNarrows: an add on a block the overlay already holds never shortens it, so a block, which may be placed
// from inside a run, can never loosen one. A shorter limit, or any limit on a block with no end, changes nothing; a
// longer one, or none, lengthens it; a dormant block is put back in force now and keeps its own end, or no end.
func TestAddOnlyNarrows(t *testing.T) {
	week := t0.Add(7 * 24 * time.Hour)
	short := t0.Add(3 * time.Minute)
	cases := []struct {
		name      string
		held      Entry
		until     time.Time
		changed   bool
		wantUntil time.Time
	}{
		{"any limit on a block with no end", Entry{}, t0.Add(61 * time.Second), false, time.Time{}},
		{"a shorter limit", Entry{Until: week}, short, false, week},
		{"the same limit", Entry{Until: week}, week, false, week},
		{"a longer limit", Entry{Until: short}, week, true, week},
		{"no limit on a timed block", Entry{Until: week}, time.Time{}, true, time.Time{}},
		{"a dormant block with no end", Entry{From: t0.Add(time.Hour)}, t0.Add(4 * time.Minute), true, time.Time{}},
		{"a dormant block with a longer end", Entry{Until: week, From: t0.Add(time.Hour)}, short, true, week},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := New(testRun)
			o.V = VersionTimed
			held := c.held
			held.Kind, held.Value, held.By, held.At = KindExec, "/usr/bin/curl", "uid:1000 pid:1 operator", t0.Add(-time.Hour)
			o.Blocks = []Entry{held}
			ch, ok, err := o.AddUntil(KindExec, "/usr/bin/curl", "uid:1000 pid:2 agent", t0, c.until)
			if err != nil || ok != c.changed {
				t.Fatalf("AddUntil = %+v, %v, %v; want changed %v", ch, ok, err, c.changed)
			}
			e, _ := o.Find(KindExec, "/usr/bin/curl")
			if !c.changed {
				if e != held || len(o.Changes) != 0 || o.Serial != 0 {
					t.Fatalf("no change was made, but the block is %+v and the changes %+v", e, o.Changes)
				}
				return
			}
			if !e.Until.Equal(c.wantUntil) || !e.From.IsZero() || !ch.Until.Equal(c.wantUntil) {
				t.Fatalf("block %+v, change %+v; want until %v and in force now", e, ch, c.wantUntil)
			}
			if _, err := o.Encode(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestLimitSlack: a limit asked for at exactly MinSpan by a caller's earlier now still passes the overlay's own check,
// made a few seconds later inside Update; one well short of it does not, and CheckUntil itself keeps its bound.
func TestLimitSlack(t *testing.T) {
	asked := t0.Add(MinSpan)
	for _, late := range []time.Duration{time.Millisecond, 3 * time.Second} {
		o := New(testRun)
		if _, _, err := o.AddUntil(KindExec, "/bin/ls", "b", t0.Add(late), asked); err != nil {
			t.Fatalf("a 1 minute limit checked %v later: %v", late, err)
		}
	}
	if _, _, err := New(testRun).AddUntil(KindExec, "/bin/ls", "b", t0.Add(10*time.Second), asked); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a limit 50 s away: %v, want ErrInvalid", err)
	}
	if err := CheckUntil(t0.Add(time.Second), asked); !errors.Is(err, ErrInvalid) {
		t.Fatalf("CheckUntil lost its bound: %v", err)
	}
}

// TestKeyIgnoresUmask: under a umask that would make the key 0400, WriteKey still leaves it 0600, so ReadKey takes it.
func TestKeyIgnoresUmask(t *testing.T) {
	dir := t.TempDir()
	old := unix.Umask(0o277)
	t.Cleanup(func() { unix.Umask(old) })
	key, err := WriteKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	unix.Umask(old)
	got, err := ReadKey(dir)
	if err != nil || string(got) != string(key) {
		t.Fatalf("ReadKey after WriteKey under umask 0277: %v", err)
	}
}
