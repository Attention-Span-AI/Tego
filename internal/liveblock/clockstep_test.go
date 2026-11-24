// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Two boots of one machine, as the kernel names them.
const (
	bootA = "0b3c1f6e-1111-4a2b-8c3d-000000000001"
	bootB = "0b3c1f6e-2222-4a2b-8c3d-000000000002"
)

// stepClock replaces readClock with a reading the test sets whole: the wall clock, BOOTTIME and the boot it counts from.
func stepClock(t *testing.T, c Clock) *fakeClock {
	t.Helper()
	f := installClock(t, c.Wall, c.Boot)
	f.c.BootID = c.BootID
	return f
}

// writeBlock makes one write of the overlay in dir: fn's change, or, with a nil fn, a change that touches no timed
// block (an untimed block on a path named by serial), which is all a write needs to run dropEnded.
func writeBlock(t *testing.T, dir string, fn func(o *Overlay) error) *Overlay {
	t.Helper()
	o, err := Update(context.Background(), dir, testRun, func(o *Overlay) (bool, error) {
		if fn != nil {
			return true, fn(o)
		}
		_, _, err := o.Add(KindPath, "/srv/other-"+time.Duration(o.Serial).String(), "uid:1 pid:2 cli", t0)
		return true, err
	})
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func timedBlock(o *Overlay) (Entry, bool) {
	for _, e := range o.Blocks {
		if e.Key() == "path:/srv/x" {
			return e, true
		}
	}
	return Entry{}, false
}

// pinnedBlock writes a block on /srv/x that ends two hours after t0, at wall t0 and BOOTTIME one hour in boot A, and
// returns the entry as the file holds it: pinned at three hours of boot A.
func pinnedBlock(t *testing.T, dir string) (*fakeClock, Entry) {
	t.Helper()
	fc := stepClock(t, Clock{Wall: t0, Boot: time.Hour, BootID: bootA})
	writeBlock(t, dir, func(o *Overlay) error {
		_, _, err := o.AddUntil(KindPath, "/srv/x", "uid:1 pid:2 cli", t0, t0.Add(2*time.Hour))
		return err
	})
	o, err := Read(dir, testRun)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := timedBlock(o)
	if !ok || e.Boot != bootA || e.UntilBoot != 3*time.Hour {
		t.Fatalf("the block is kept as %+v, want its until pinned at 3h of boot %s", e, bootA)
	}
	return fc, e
}

// inForce is the launcher's rule for the block at c, with the pin the launcher takes from the entry (UntilPin).
func inForce(e Entry, c Clock) bool {
	pin, ok := e.UntilPin(c)
	return !Ended(e.Until, pin, ok, c)
}

// A wall clock stepped forward more than a day past a block's limit, in the boot it was pinned in, does not let a
// writer drop the block: the launcher holds it until BOOTTIME reaches the pin too, and the writer keeps the entry by
// the same two clocks (ADR 0125 decision 4, amendment 2026-11-18). The wall clock alone, with a day's margin, decided
// before, and the next write dropped a block still in force.
func TestForwardStepKeepsABlockTheLauncherHolds(t *testing.T) {
	dir := t.TempDir()
	fc, e := pinnedBlock(t, dir)
	until := e.Until
	fc.c = Clock{Wall: until.Add(25 * time.Hour), Boot: time.Hour + 10*time.Minute, BootID: bootA} // +25 h step, ten minutes later
	if !inForce(e, fc.c) {
		t.Fatal("the launcher's rule ended the block at a forward step")
	}
	if _, ok := timedBlock(writeBlock(t, dir, nil)); !ok {
		t.Fatal("a write dropped a block the launcher still holds in force")
	}
	// The Set the launcher compiles from the entry's pin refuses at that reading.
	o, err := Read(dir, testRun)
	if err != nil {
		t.Fatal(err)
	}
	set := Compile(o, Resolved{Boot: map[string]time.Duration{DeadlineKey(e.Key(), e.Until): e.UntilBoot}})
	if _, ok := set.MatchPath("/srv/x", AccessRead); !ok {
		t.Fatal("the Set stopped refusing at a forward step")
	}
	// BOOTTIME reaches the pin: the limit has ended, and the entry stays listed for its day, on both clocks.
	fc.c.Boot = 3 * time.Hour
	if inForce(e, fc.c) {
		t.Fatal("the block did not end when both clocks had passed its limit")
	}
	if _, ok := set.MatchPath("/srv/x", AccessRead); ok {
		t.Fatal("the Set refuses past the limit on both clocks")
	}
	if _, ok := timedBlock(writeBlock(t, dir, nil)); !ok {
		t.Fatal("an entry was dropped the moment its limit ended: the launcher writes its line from the file")
	}
	fc.c.Boot = 3*time.Hour + endedKeep
	if _, ok := timedBlock(writeBlock(t, dir, nil)); ok {
		t.Fatal("an entry ended a day ago on both clocks is still in the file")
	}
}

// After a restart the pin's boot is gone and its launcher with it: the wall clock decides alone.
func TestRestartLetsTheWallClockDecide(t *testing.T) {
	dir := t.TempDir()
	fc, e := pinnedBlock(t, dir)
	fc.c = Clock{Wall: e.Until.Add(25 * time.Hour), Boot: time.Hour + 10*time.Minute, BootID: bootA}
	if _, ok := timedBlock(writeBlock(t, dir, nil)); !ok {
		t.Fatal("dropped in its own boot")
	}
	fc.c = Clock{Wall: e.Until.Add(25 * time.Hour), Boot: 5 * time.Minute, BootID: bootB} // restarted, same wall clock
	if _, ok := e.UntilPin(fc.c); ok {
		t.Fatal("a pin of another boot was taken as this boot's")
	}
	if _, ok := timedBlock(writeBlock(t, dir, nil)); ok {
		t.Fatal("after a restart, a block a day past its limit by the wall clock is still in the file")
	}
	// Inside the day it is kept, restarted or not.
	dir = t.TempDir()
	fc.c = Clock{Wall: t0, Boot: time.Hour, BootID: bootA}
	writeBlock(t, dir, func(o *Overlay) error {
		_, _, err := o.AddUntil(KindPath, "/srv/x", "uid:1 pid:2 cli", t0, t0.Add(2*time.Hour))
		return err
	})
	fc.c = Clock{Wall: e.Until.Add(time.Hour), Boot: 5 * time.Minute, BootID: bootB}
	if _, ok := timedBlock(writeBlock(t, dir, nil)); !ok {
		t.Fatal("after a restart, an entry an hour past its limit was dropped inside its day")
	}
}

// A wall clock stepped back keeps a block in force past its BOOTTIME pin: a narrowing ends on the later side, so a
// step may lengthen it and never shortens it (ADR 0125 decision 4). The writer keeps the entry for as long.
func TestBackwardStepExtendsABlock(t *testing.T) {
	dir := t.TempDir()
	fc, e := pinnedBlock(t, dir)
	fc.c = Clock{Wall: e.Until.Add(-time.Hour), Boot: 3*time.Hour + 2*endedKeep, BootID: bootA} // BOOTTIME two days past the pin
	if !inForce(e, fc.c) {
		t.Fatal("a backward step ended a block before its limit by the wall clock")
	}
	if _, ok := timedBlock(writeBlock(t, dir, nil)); !ok {
		t.Fatal("a write dropped a block a backward step keeps in force")
	}
	fc.c.Wall = e.Until.Add(time.Minute)
	if inForce(e, fc.c) {
		t.Fatal("the block outlived both clocks")
	}
	if _, ok := timedBlock(writeBlock(t, dir, nil)); !ok {
		t.Fatal("dropped inside its day by the wall clock")
	}
	fc.c.Wall = e.Until.Add(endedKeep + time.Minute)
	if _, ok := timedBlock(writeBlock(t, dir, nil)); ok {
		t.Fatal("an entry a day past its limit on both clocks is still in the file")
	}
}

// An entry with no pin, as a tego from before pins wrote it and as one is written where the boot cannot be named, is
// kept and dropped as it always was: by the wall clock with its day, whatever BOOTTIME says. Its bytes carry neither
// new field.
func TestUnpinnedEntryIsDroppedByTheWallClock(t *testing.T) {
	dir := t.TempDir()
	fc := stepClock(t, Clock{Wall: t0, Boot: time.Hour}) // no boot identity: nothing is pinned
	writeBlock(t, dir, func(o *Overlay) error {
		_, _, err := o.AddUntil(KindPath, "/srv/x", "uid:1 pid:2 cli", t0, t0.Add(2*time.Hour))
		return err
	})
	b, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"boot"`) || strings.Contains(string(b), `"until_boot"`) {
		t.Fatalf("an unpinned entry was written with a pin: %s", b)
	}
	until := t0.Add(2 * time.Hour)
	fc.c = Clock{Wall: until.Add(23 * time.Hour), Boot: time.Hour + time.Minute, BootID: bootA}
	if e, ok := timedBlock(writeBlock(t, dir, nil)); !ok || e.Boot != "" || e.UntilBoot != 0 {
		t.Fatalf("an unpinned entry inside its day: kept %v as %+v; a later write must not pin it", ok, e)
	}
	fc.c = Clock{Wall: until.Add(25 * time.Hour), Boot: time.Hour + 2*time.Minute, BootID: bootA}
	if _, ok := timedBlock(writeBlock(t, dir, nil)); ok {
		t.Fatal("an unpinned entry a day past its limit by the wall clock is still in the file")
	}
}

// A limit is pinned once, by the write that made it: a later write under a stepped clock keeps the pin, a longer
// limit is a new limit with its own, and a pinned entry is kept while this boot cannot be named.
func TestALimitIsPinnedOnce(t *testing.T) {
	dir := t.TempDir()
	fc, e := pinnedBlock(t, dir)
	fc.c = Clock{Wall: t0.Add(40 * time.Hour), Boot: time.Hour + time.Minute, BootID: bootA}
	if got, _ := timedBlock(writeBlock(t, dir, nil)); got.Boot != e.Boot || got.UntilBoot != e.UntilBoot {
		t.Fatalf("a later write moved the pin: %+v, was %+v", got, e)
	}
	fc.c = Clock{Wall: t0.Add(40 * time.Hour), Boot: time.Hour + time.Minute}
	if _, ok := timedBlock(writeBlock(t, dir, nil)); !ok {
		t.Fatal("a pinned entry was dropped while this boot could not be named")
	}
	fc.c = Clock{Wall: t0.Add(time.Hour), Boot: 2 * time.Hour, BootID: bootA}
	longer := t0.Add(5 * time.Hour)
	writeBlock(t, dir, func(o *Overlay) error {
		_, _, err := o.AddUntil(KindPath, "/srv/x", "uid:1 pid:3 cli", fc.c.Wall, longer)
		return err
	})
	o, err := Read(dir, testRun)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := timedBlock(o); !got.Until.Equal(longer) || got.UntilBoot != 6*time.Hour || got.Boot != bootA {
		t.Fatalf("a longer limit is kept as %+v, want its own pin at 6h", got)
	}
}

// A pin in a file is both fields, on an entry with a limit, well formed; anything else is no overlay to follow.
func TestValidateRefusesAMalformedPin(t *testing.T) {
	for name, edit := range map[string]func(e *Entry){
		"a pin and no limit":    func(e *Entry) { e.Until = time.Time{} },
		"a boot and no instant": func(e *Entry) { e.UntilBoot = 0 },
		"an instant and no boot": func(e *Entry) {
			e.Boot = ""
		},
		"a boot that is no identity": func(e *Entry) { e.Boot = "../boot" },
		"an instant before the boot": func(e *Entry) { e.UntilBoot = -time.Second },
	} {
		o := New(testRun)
		if _, _, err := o.AddUntil(KindPath, "/srv/x", "uid:1 pid:2 cli", t0, t0.Add(2*time.Hour)); err != nil {
			t.Fatal(err)
		}
		o.Blocks[0].Boot, o.Blocks[0].UntilBoot = bootA, 3*time.Hour
		o.V = o.MinVersion()
		if err := o.Validate(testRun); err != nil {
			t.Fatalf("a well-formed pin is refused: %v", err)
		}
		edit(&o.Blocks[0])
		o.V = VersionLink
		if err := o.Validate(testRun); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
