// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fakeClock is a clock a test moves by hand.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newTestResults(max int, timed bool) (*Results[string, int], *fakeClock) {
	c := &fakeClock{t: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	r := NewResults[string, int](max, timed)
	r.now = c.now
	return r, c
}

// stamp is a run stamp of a file of size bytes whose tail hashes as tail, live or not.
func stamp(ino uint64, size int64, tail byte, live bool) RunStamp {
	s := RunStamp{events: fileID{dev: 1, ino: ino, size: size, mtime: size}, Live: live}
	s.tail[0] = tail
	return s
}

// TestResultsKeyedOnTheRunAndTheRest: a result is reused while the run's stamp and the rest of the key are the same,
// and computed again when either moves; a failed result is not kept; the oldest slot leaves past the bound.
func TestResultsKeyedOnTheRunAndTheRest(t *testing.T) {
	r, c := newTestResults(2, false)
	n := 0
	get := func(slot string, s RunStamp, key string) int {
		return r.Get(slot, s, key, func() (int, bool) { n++; return n, true })
	}
	ended := stamp(1, 100, 'a', false)
	if v := get("a", ended, "k"); v != 1 {
		t.Fatalf("first = %d", v)
	}
	c.t = c.t.Add(time.Minute)
	if v := get("a", ended, "k"); v != 1 {
		t.Fatalf("same stamp and key = %d, want the kept 1", v)
	}
	if v := get("a", ended, "k2"); v != 2 {
		t.Fatalf("another key = %d, want computed again", v)
	}
	if v := get("a", stamp(1, 120, 'b', false), "k2"); v != 3 {
		t.Fatalf("an appended run = %d, want computed again", v)
	}
	if v := get("a", stamp(1, 120, 'c', false), "k2"); v != 4 {
		t.Fatalf("a run rewritten to the same size = %d, want computed again", v)
	}
	c.t = c.t.Add(maxResultAge)
	if v := get("a", stamp(1, 120, 'c', false), "k2"); v != 5 {
		t.Fatalf("a result past maxResultAge = %d, want computed again", v)
	}
	// A failed computation is not kept.
	if v := r.Get("b", ended, "k", func() (int, bool) { return -1, false }); v != -1 {
		t.Fatalf("failed = %d", v)
	}
	if v := get("b", ended, "k"); v != 6 {
		t.Fatalf("after a failure = %d, want computed", v)
	}
	// Bound 2: a, b held; using a, then adding c drops b (least recently used).
	get("a", stamp(1, 120, 'c', false), "k2")
	get("c", ended, "k")
	if _, ok := r.slots["b"]; ok || len(r.slots) != 2 || r.order.Len() != 2 {
		t.Fatalf("slots after the bound: %v", r.slots)
	}
	if r.Computes() != int64(n)+1 { // the failed computation counts too
		t.Errorf("Computes = %d, want %d", r.Computes(), n+1)
	}
}

// TestResultsLiveRunReusedAtMostTwoSeconds: a live run's costly result is reused for liveEvery after it finished
// while its file only grew; a cheap one, a file replaced or another key is computed again at once; an ended run's
// stamp ends the reuse.
func TestResultsLiveRunReusedAtMostTwoSeconds(t *testing.T) {
	r, c := newTestResults(8, false)
	n := 0
	costly := func(d time.Duration) func() (int, bool) {
		return func() (int, bool) { n++; c.t = c.t.Add(d); return n, true }
	}
	start := c.t
	r.Get("a", stamp(1, 100, 'a', true), "k", costly(300*time.Millisecond))
	c.t = start.Add(time.Second)
	if v := r.Get("a", stamp(1, 140, 'b', true), "k", costly(300*time.Millisecond)); v != 1 {
		t.Fatalf("1 s after a costly live result = %d, want it reused", v)
	}
	if v := r.Get("a", stamp(2, 140, 'b', true), "k", costly(0)); v != 2 {
		t.Fatalf("a replaced live file = %d, want computed", v)
	}
	if v := r.Get("a", stamp(2, 160, 'c', true), "k", costly(0)); v != 3 {
		t.Fatalf("a cheap live result = %d, want computed again", v)
	}
	c.t = start.Add(3 * time.Second)
	r.Get("a", stamp(2, 200, 'd', true), "k", costly(400*time.Millisecond))
	c.t = c.t.Add(500 * time.Millisecond)
	if v := r.Get("a", stamp(2, 220, 'e', true), "k2", costly(0)); v != 5 {
		t.Fatalf("another key = %d, want computed", v)
	}
	r.Get("a", stamp(2, 240, 'f', true), "k", costly(400*time.Millisecond))
	c.t = c.t.Add(500 * time.Millisecond)
	if v := r.Get("a", stamp(2, 260, 'g', false), "k", costly(0)); v != 7 {
		t.Fatalf("the run ended = %d, want computed", v)
	}
	r.Get("a", stamp(2, 300, 'h', true), "k", costly(400*time.Millisecond))
	c.t = c.t.Add(liveEvery)
	if v := r.Get("a", stamp(2, 320, 'i', true), "k", costly(0)); v != 9 {
		t.Fatalf("past liveEvery = %d, want computed", v)
	}
}

// TestResultsLiveWindowGrowsWithCost: a live run's result that cost 3 s is reused for twice that after it finished,
// and a viewer who comes while another request computes the run's next result gets the kept one, not a second
// computation.
func TestResultsLiveWindowGrowsWithCost(t *testing.T) {
	r, c := newTestResults(8, false)
	n := 0
	compute := func(d time.Duration) func() (int, bool) {
		return func() (int, bool) { n++; c.t = c.t.Add(d); return n, true }
	}
	r.Get("a", stamp(1, 100, 'a', true), "k", compute(3*time.Second)) // finished at +3 s
	c.t = c.t.Add(5 * time.Second)
	if v := r.Get("a", stamp(1, 140, 'b', true), "k", compute(0)); v != 1 {
		t.Fatalf("5 s after a 3 s result finished = %d, want it reused (window 6 s)", v)
	}
	c.t = c.t.Add(time.Second + time.Millisecond)
	v := r.Get("a", stamp(1, 160, 'c', true), "k", func() (int, bool) {
		n++
		// Another viewer while this computation runs: the kept result, no second computation.
		if w := r.Get("a", stamp(1, 170, 'd', true), "k", compute(0)); w != 1 {
			t.Errorf("a viewer during a computation = %d, want the kept 1", w)
		}
		c.t = c.t.Add(3 * time.Second)
		return n, true
	})
	if v != 2 || n != 2 {
		t.Fatalf("past the window = %d after %d computations, want 2 after 2", v, n)
	}
	if len(r.busy) != 0 {
		t.Errorf("busy after the computations: %v", r.busy)
	}
	// Ended: no stale reuse, in flight or not.
	if v := r.Get("a", stamp(1, 200, 'e', false), "k", compute(0)); v != 3 {
		t.Fatalf("the run ended = %d, want computed", v)
	}
}

// TestResultsTimedLiveRun: a result that reads the clock (the receipt) is never reused as exact for a live run, only
// within liveEvery when costly; for an ended run it is.
func TestResultsTimedLiveRun(t *testing.T) {
	r, c := newTestResults(8, true)
	n := 0
	compute := func(d time.Duration) func() (int, bool) {
		return func() (int, bool) { n++; c.t = c.t.Add(d); return n, true }
	}
	live := stamp(1, 100, 'a', true)
	r.Get("a", live, "", compute(0))
	if v := r.Get("a", live, "", compute(0)); v != 2 {
		t.Fatalf("a cheap timed live result = %d, want computed again", v)
	}
	r.Get("a", live, "", compute(time.Second))
	if v := r.Get("a", live, "", compute(0)); v != 3 {
		t.Fatalf("a costly timed live result = %d, want reused within liveEvery", v)
	}
	ended := stamp(1, 120, 'b', false)
	r.Get("a", ended, "", compute(0))
	c.t = c.t.Add(time.Minute)
	if v := r.Get("a", ended, "", compute(0)); v != 4 {
		t.Fatalf("an ended run's timed result = %d, want reused", v)
	}
}

// TestResultsOlderComputationDoesNotOverwrite: a computation that started before another one stored its result
// does not replace that newer result.
func TestResultsOlderComputationDoesNotOverwrite(t *testing.T) {
	r, c := newTestResults(8, false)
	older, newer := stamp(1, 100, 'a', false), stamp(1, 140, 'b', false)
	v := r.Get("a", older, "k", func() (int, bool) {
		c.t = c.t.Add(time.Millisecond)
		r.Get("a", newer, "k", func() (int, bool) { return 2, true })
		return 1, true
	})
	if v != 1 {
		t.Fatalf("outer = %d", v)
	}
	if got := r.Get("a", newer, "k", func() (int, bool) { return 3, true }); got != 2 {
		t.Fatalf("after the older computation finished = %d, want the newer 2 kept", got)
	}
}

// holdLock takes run dir's lock as a writer holds it, until the test ends or release lets it go.
func holdLock(t testing.TB, dir string) (release func()) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release = func() { once.Do(func() { _ = f.Close() }) }
	t.Cleanup(release)
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	return release
}

// fixtureRun writes the first n lines of spec/record/v1/fixtures/run-fixture.jsonl as its run under a new root and
// returns the root, the run id and every line.
func fixtureRun(t *testing.T, n int) (string, string, [][]byte) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "run-fixture.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(data, []byte("\n"))
	if len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	const run = "r-3f9c2a1b-0dllq06ts7400-k7m2pq"
	root := t.TempDir()
	writeRun(t, root, run, string(bytes.Join(lines[:n], nil)))
	return root, run, lines
}

// TestStampRunFollowsTheFile: the stamp moves with an append and a replaced file, says live only while the lock is
// held and the last line is not run_end, and refuses what is not a run.
func TestStampRunFollowsTheFile(t *testing.T) {
	root, run, lines := fixtureRun(t, 50)
	s1, ok := StampRun(root, run)
	if !ok || s1.Live {
		t.Fatalf("stamp = %+v, %v; want readable and not live (no lock held)", s1, ok)
	}
	if s, _ := StampRun(root, run); s != s1 {
		t.Fatal("an unchanged file stamped differently")
	}
	holdLock(t, filepath.Join(root, run))
	if s, _ := StampRun(root, run); !s.Live || s.events != s1.events {
		t.Fatalf("lock held: %+v, want live", s)
	}
	appendLines(t, root, run, string(bytes.Join(lines[50:len(lines)-1], nil)))
	s2, _ := StampRun(root, run)
	if s2 == s1 || !s2.Live || !s2.grewFrom(s1) {
		t.Fatalf("after an append: %+v", s2)
	}
	appendLines(t, root, run, string(lines[len(lines)-1]))
	if s, _ := StampRun(root, run); s.Live {
		t.Fatal("a run whose last line is run_end stamped live while the lock is still held")
	}
	if _, ok := StampRun(root, "../etc"); ok {
		t.Error("a path that is not a run id was stamped")
	}
	if _, ok := StampRun(root, "r-missing"); ok {
		t.Error("a missing run was stamped")
	}
}

// TestReceiptKeptPerRunVersion: the Receipt tab is computed once while the run's file is the same, and is the
// uncached receipt again after an append.
func TestReceiptKeptPerRunVersion(t *testing.T) {
	root, run, lines := fixtureRun(t, 50)
	before := receipts.Computes()
	a, err := LoadReceipt(t.Context(), root, run)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadReceipt(t.Context(), root, run)
	if err != nil || b != a || receipts.Computes() != before+1 {
		t.Fatalf("second load: same %v, computes %d (want %d), %v", b == a, receipts.Computes()-before, 1, err)
	}
	appendLines(t, root, run, string(bytes.Join(lines[50:], nil)))
	c, err := LoadReceipt(t.Context(), root, run)
	if err != nil {
		t.Fatal(err)
	}
	want, err := loadReceipt(t.Context(), root, run)
	if err != nil {
		t.Fatal(err)
	}
	if c == a || !reflect.DeepEqual(c, want) || receipts.Computes() != before+2 {
		t.Fatalf("after an append: stale %v, equal to uncached %v, computes %d", c == a, reflect.DeepEqual(c, want), receipts.Computes()-before)
	}
	if !c.Ended || a.Ended {
		t.Errorf("ended: before the append %v, after %v", a.Ended, c.Ended)
	}
}
