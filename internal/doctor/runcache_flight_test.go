// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

func mustFlight(t *testing.T, c *runCache, k runCacheKey) *probeFlight {
	t.Helper()
	f, err := c.acquireFlight(context.Background(), k, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(f.close)
	return f
}

func TestRunProbeFlightCancellationAndDeadline(t *testing.T) {
	c, _ := testCache(t)
	k := testKey()
	held := mustFlight(t, c, k)
	for _, cancel := range []bool{true, false} {
		ctx, stop := context.WithCancel(context.Background())
		if cancel {
			stop()
		}
		start := time.Now()
		f, err := c.acquireFlight(ctx, k, 30*time.Millisecond)
		stop()
		want := context.DeadlineExceeded
		if cancel {
			want = context.Canceled
		}
		if f != nil || !errors.Is(err, want) || time.Since(start) > time.Second {
			t.Fatalf("cancel=%v lease=%v err=%v elapsed=%s", cancel, f, err, time.Since(start))
		}
	}
	held.close()
	// Both failed waits released their descriptors; the same persistent name can
	// be held again without removing it or carrying a poisoned lock.
	_ = mustFlight(t, c, k)
}

func TestRunProbeFlightRejectsUnsafeFilesystemAndChangedInode(t *testing.T) {
	for _, mode := range []string{"symlink", "hardlink", "fifo", "public", "content", "directory", "foreign-owner"} {
		t.Run(mode, func(t *testing.T) {
			c, _ := testCache(t)
			dir, err := c.flightDirectory()
			if err != nil {
				t.Fatal(err)
			}
			if err := unix.Close(dir); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(c.base, "run", "tego", probeFlightDir, probeFlightName(testKey()))
			external := filepath.Join(c.base, "untouched")
			if err := os.WriteFile(external, []byte("external"), 0o600); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "symlink":
				err = os.Symlink(external, name)
			case "hardlink":
				err = os.Link(external, name)
			case "fifo":
				err = unix.Mkfifo(name, 0o600)
			case "public":
				err = os.WriteFile(name, nil, 0o644)
			case "content":
				err = os.WriteFile(name, []byte("unexpected"), 0o600)
			case "directory":
				err = os.Mkdir(name, 0o600)
			case "foreign-owner":
				err = os.WriteFile(name, nil, 0o600)
				c.owner++ // exact stat ownership check, no privileged chown
			}
			if err != nil {
				t.Fatal(err)
			}
			lease, err := c.acquireFlight(context.Background(), testKey(), 50*time.Millisecond)
			if lease != nil || err == nil {
				t.Fatalf("unsafe %s lock accepted: %v %v", mode, lease, err)
			}
			if b, err := os.ReadFile(external); err != nil || string(b) != "external" {
				t.Fatalf("external control changed: %q %v", b, err)
			}
		})
	}
	c, _ := testCache(t)
	f := mustFlight(t, c, testKey())
	name := probeFlightName(testKey())
	if err := unix.Unlinkat(f.dir, name, 0); err != nil {
		t.Fatal(err)
	}
	newFD, err := c.flightFile(f.dir, name, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(newFD) }()
	if _, err := c.lockFlight(context.Background(), f.dir, f.fd, name); err == nil {
		t.Fatal("removed held inode was accepted as the replacement lock name")
	}
}

func TestRunProbeFlightBoundsPersistentNamesAndSeparatesFullKeys(t *testing.T) {
	c, _ := testCache(t)
	k := testKey()
	first := mustFlight(t, c, k)
	other := testKey()
	other.BootID = "another-boot"
	if probeFlightName(other) == probeFlightName(k) {
		t.Fatal("full key was reduced to the privilege/build cache filename")
	}
	// Another full key can hold its own lease while the first expensive probe is
	// held. Only creation is serialized, not independent probe execution.
	_ = mustFlight(t, c, other)
	// Every lock file held: a lock file nobody holds is reclaimed at the limit
	// (TestRunProbeFlightReclaimsUnheldLockFilesAtTheLimit), a held one never is.
	for i := 2; i < maxRunProbeFlights; i++ {
		other.Process.UID = i
		_ = mustFlight(t, c, other)
	}
	other.Process.UID = maxRunProbeFlights + 1
	if f, err := c.acquireFlight(context.Background(), other, time.Second); f != nil || err == nil {
		t.Fatal("new lock inode exceeded the bounded admission limit")
	}
	first.close()
	_ = mustFlight(t, c, k) // existing keys remain usable at the limit
	entries, err := os.ReadDir(filepath.Join(c.base, "run", "tego", probeFlightDir))
	if err != nil || len(entries) != maxRunProbeFlights+1 {
		t.Fatalf("persistent entries=%d err=%v", len(entries), err)
	}
}

// TestRunProbeFlightReclaimsUnheldLockFilesAtTheLimit (v73 review, races-4): the key a lock file is named for
// holds the run's cgroup and binary, so a long-lived machine meets a new key with every session scope, unit
// or rebuild. At the limit a new key takes the place of a lock file nobody holds, under the admission lock,
// so only 128 runs coordinating at once exhaust it; a held one is never taken.
func TestRunProbeFlightReclaimsUnheldLockFilesAtTheLimit(t *testing.T) {
	c, _ := testCache(t)
	other := testKey()
	other.BootID = "another-boot"
	held := mustFlight(t, c, other) // a run of another key, still probing
	heldName := probeFlightName(other)
	for i := 1; i < maxRunProbeFlights; i++ {
		other.Process.UID = 2000 + i
		mustFlight(t, c, other).close() // runs of other keys that ended
	}
	f, err := c.acquireFlight(context.Background(), testKey(), time.Second)
	if err != nil {
		t.Fatalf("a new key at the limit of unheld lock files was refused: %v", err)
	}
	f.close()
	dir := filepath.Join(c.base, "run", "tego", probeFlightDir)
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) > maxRunProbeFlights+1 {
		t.Fatalf("the lock files outgrew the limit: entries=%d err=%v", len(entries), err)
	}
	if err := c.flightNamed(held.dir, held.fd, heldName); err != nil {
		t.Fatalf("a held lock file was reclaimed: %v", err)
	}
}

// TestRunProbeFlightTakesAReclaimedNameAgain: a run waiting on a lock file that is reclaimed under it (the
// reclaimer held the lock, then unlinked the name) neither fails nor holds the unlinked inode: it opens the
// name again, creating it, and coordinates on that.
func TestRunProbeFlightTakesAReclaimedNameAgain(t *testing.T) {
	c, _ := testCache(t)
	k := testKey()
	holder := mustFlight(t, c, k)
	name := probeFlightName(k)
	waiting := make(chan struct{}, 1)
	c.waiting = func(n string) {
		if n == name {
			waiting <- struct{}{}
		}
	}
	type result struct {
		f   *probeFlight
		err error
	}
	done := make(chan result, 1)
	go func() {
		f, err := c.acquireFlight(context.Background(), k, 5*time.Second)
		done <- result{f, err}
	}()
	select {
	case <-waiting:
	case <-time.After(5 * time.Second):
		t.Fatal("the run did not wait on the held lock")
	}
	if err := unix.Unlinkat(holder.dir, name, 0); err != nil {
		t.Fatal(err)
	}
	holder.close()
	r := <-done
	if r.err != nil {
		t.Fatalf("a reclaimed lock name failed the waiting run: %v", r.err)
	}
	defer r.f.close()
	if err := c.flightNamed(r.f.dir, r.f.fd, name); err != nil {
		t.Fatalf("the run holds a lock its name no longer leads to: %v", err)
	}
}

func TestForRunProbeFlightRevalidatesCallerBeforeReadingLeaderAnswer(t *testing.T) {
	for _, readable := range []bool{true, false} {
		t.Run(map[bool]string{true: "changed-key", false: "key-unreadable"}[readable], func(t *testing.T) {
			c, _ := testCache(t)
			k := testKey()
			var changed atomic.Bool
			c.key = func(string, int) (runCacheKey, bool) {
				if changed.Load() {
					other := testKey()
					other.Process.CapEff = "restricted"
					return other, readable
				}
				return k, true
			}
			leader := mustFlight(t, c, k)
			publisher := *c // another process has its own cache diagnostic field
			var n calls
			ch := passingChecks(&n)
			miss, done := make(chan struct{}), make(chan probeState, 1)
			btf := ch.btf
			ch.btf = func() Result { close(miss); return btf() }
			go func() {
				done <- scope{reach: backend.TierCgroup, root: true, checks: ch, cache: c}.run(context.Background())
			}()
			select {
			case <-miss:
			case <-time.After(time.Second):
				t.Fatal("follower did not miss the unpublished answer")
			}
			p, rows, fan, fs := vouchingAnswer()
			publisher.record(k, p, rows, passingPlane(""), nil, fan, fs)
			changed.Store(true)
			leader.close()
			select {
			case st := <-done:
				if st.cached != nil || n.n[CheckPrograms] != 1 || n.n[CheckFanotify] != 1 {
					t.Fatalf("changed authority reused the leader answer: cached=%v calls=%v", st.cached != nil, n.n)
				}
			case <-time.After(time.Second):
				t.Fatal("follower did not fall back to its own probe")
			}
		})
	}
}

func TestForRunProbeFlightCancelledWaitDoesNotProbeOrPublish(t *testing.T) {
	c, path := testCache(t)
	held := mustFlight(t, c, testKey())
	ctx, cancel := context.WithCancel(context.Background())
	var n calls
	ch := passingChecks(&n)
	miss, done := make(chan struct{}), make(chan probeState, 1)
	btf := ch.btf
	ch.btf = func() Result { close(miss); return btf() }
	go func() { done <- scope{reach: backend.TierCgroup, root: true, checks: ch, cache: c}.run(ctx) }()
	select {
	case <-miss:
	case <-time.After(time.Second):
		t.Fatal("follower did not reach its initial miss")
	}
	cancel()
	select {
	case <-done:
		if n.n[CheckPrograms] != 0 || n.n[CheckFanotify] != 0 {
			t.Fatalf("cancelled waiter probed: %v", n.n)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt the owned wait")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cancelled waiter published a cache entry: %v", err)
	}
	held.close()
	_ = mustFlight(t, c, testKey())
}

// TestForRunProbeFlightWaitersOfAnUncacheableAnswerProbeTogether (v73 review, doctor-1): a run waits on its
// key's flight only for an answer it could then read. When the holder ends without keeping one (D7 or D8 did
// not vouch, or the plane faulted again), each run that waited probes without holding the flight, so the runs
// that queued behind one probe take one more probe's time together, not one probe each in turn: on a machine
// whose answer never vouches, N runs started together used to start N probe times apart, up to 30 s each.
func TestForRunProbeFlightWaitersOfAnUncacheableAnswerProbeTogether(t *testing.T) {
	const waiters = 3
	for _, failure := range []string{"programs", "plane"} {
		t.Run(failure, func(t *testing.T) {
			c, _ := testCache(t)
			k := testKey()
			waiting := make(chan struct{}, 4*waiters)
			c.waiting = func(name string) {
				if name == probeFlightName(k) {
					waiting <- struct{}{}
				}
			}
			if failure == "plane" {
				// An entry whose plane faulted: each run answers the plane alone, under the flight.
				p, rows, fan, fs := vouchingAnswer()
				faulted := passingPlane("")
				faulted.Modes[0].Faulted = true
				c.record(k, p, rows, faulted, passingPlaneRows(), fan, fs)
				if e, ok := c.load(k); !ok || e.Plane != nil {
					t.Fatalf("no partial entry to start from: %v %+v", ok, e.Plane)
				}
			}
			held := mustFlight(t, c, k) // a holder that will end without keeping an answer
			entered, release := make(chan struct{}, waiters), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			t.Cleanup(unblock)
			type result struct {
				st probeState
				n  calls
			}
			done := make(chan result, waiters)
			for range waiters {
				go func() {
					var n calls
					ch := passingChecks(&n)
					block := func() { entered <- struct{}{}; <-release }
					switch failure {
					case "programs":
						programs := ch.programs
						ch.programs = func(root bool, uid int, v Version, tier, capture []hook) (Result, []HookResult) {
							block()
							p, rows := programs(root, uid, v, tier, capture)
							p.OK = false
							return p, rows
						}
					case "plane":
						plane := ch.plane
						ch.plane = func(root bool, uid int, release, pin string, keep bool) (*PlaneState, []HookResult) {
							block()
							p, rows := plane(root, uid, release, pin, keep)
							p.Modes[0].Faulted = true
							return p, rows
						}
					}
					own := *c // each run is its own process with its own diagnostic field
					done <- result{scope{reach: backend.TierCgroup, root: true, checks: ch, cache: &own}.run(context.Background()), n}
				}()
			}
			for i := range waiters {
				select {
				case <-waiting:
				case <-time.After(5 * time.Second):
					t.Fatalf("only %d of %d runs reached the held flight", i, waiters)
				}
			}
			held.close()
			for i := range waiters {
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					t.Fatalf("only %d of %d waiters probed while another's probe ran: they probe one after another", i, waiters)
				}
			}
			unblock()
			for range waiters {
				r := <-done
				wantPrograms := 1
				if failure == "plane" {
					wantPrograms = 0 // D7 and D8 came from the partial entry
				}
				if r.n.n[CheckPrograms] != wantPrograms || r.n.plane != 1 {
					t.Errorf("waiter probed D7 %d and the plane %d times: %v", r.n.n[CheckPrograms], r.n.plane, r.n.n)
				}
			}
		})
	}
}

func TestForRunProbeFlightRefusalSurvivesSuccessfulFreshPublication(t *testing.T) {
	c, path := testCache(t)
	dir, err := c.flightDirectory()
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(dir); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(filepath.Dir(path), probeFlightDir, probeFlightName(testKey()))
	if err := os.WriteFile(name, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	var n calls
	st := scope{reach: backend.TierCgroup, root: true, checks: passingChecks(&n), cache: c}.run(context.Background())
	if n.n[CheckPrograms] != 1 || n.n[CheckFanotify] != 1 || st.cached != nil {
		t.Fatalf("unsafe coordination did not use the ordinary fresh checks: %+v cached=%v", n.n, st.cached != nil)
	}
	if _, ok := c.load(testKey()); !ok {
		t.Fatal("a successful fresh probe did not publish its real validated answer")
	}
	if !strings.Contains(st.coordinationNote, "private") || st.cacheNote != "" {
		t.Fatalf("successful cache I/O erased the coordination refusal, or it was called the cache's: coordination %q, cache %q",
			st.coordinationNote, st.cacheNote)
	}
}

func TestForRunProbeFlightRefusalRevalidatesBeforeFreshPublication(t *testing.T) {
	for _, readable := range []bool{true, false} {
		t.Run(map[bool]string{true: "changed-key", false: "key-unreadable"}[readable], func(t *testing.T) {
			c, path := testCache(t)
			dir, err := c.flightDirectory()
			if err != nil {
				t.Fatal(err)
			}
			if err := unix.Close(dir); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(filepath.Dir(path), probeFlightDir, probeFlightName(testKey()))
			if err := os.WriteFile(name, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			reads := 0
			c.key = func(string, int) (runCacheKey, bool) {
				reads++
				k := testKey()
				if reads > 1 {
					k.Process.CapEff = "another-caller"
					return k, readable
				}
				return k, true
			}
			var n calls
			st := scope{reach: backend.TierCgroup, root: true, checks: passingChecks(&n), cache: c}.run(context.Background())
			if reads < 2 || st.cached != nil || n.n[CheckPrograms] != 1 || n.n[CheckFanotify] != 1 ||
				len(n.keep) != 1 || n.keep[0] || !strings.Contains(st.coordinationNote, "private") {
				t.Errorf("refused coordination reused old authority: reads=%d cached=%v calls=%v keep=%v note=%q",
					reads, st.cached != nil, n.n, n.keep, st.coordinationNote)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("changed authority published under the earlier key: %v", err)
			}
		})
	}
}

// TestForRunProbeCoordinationIsNotAnUnusableCache (v73 review, doctor-3 and races-4): the run-probe cache note
// says the cache is unusable, so it carries only the cache's own refusals. A refused cache directory is named
// once, by the cache, not again by the flight that could not open it either; and a run that could not
// coordinate (128 runs of other keys holding every lock file) still read and wrote the cache, so its note is
// empty and the reason is the coordination note's.
func TestForRunProbeCoordinationIsNotAnUnusableCache(t *testing.T) {
	t.Run("refused-directory", func(t *testing.T) {
		c, _ := testCache(t)
		dir := filepath.Join(c.base, "run", "tego")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, os.ModeSticky|0o770); err != nil { // the packaged root:tego form
			t.Fatal(err)
		}
		var n calls
		st := scope{reach: backend.TierCgroup, root: true, checks: passingChecks(&n), cache: c}.run(context.Background())
		refusal := "not a directory only root may write"
		if strings.Count(st.cacheNote, refusal) != 1 || st.coordinationNote != "" {
			t.Errorf("the refusal is not named once, by the cache: cache %q, coordination %q", st.cacheNote, st.coordinationNote)
		}
	})
	t.Run("lock-limit", func(t *testing.T) {
		c, path := testCache(t)
		other := testKey()
		other.BootID = "another-boot"
		for i := range maxRunProbeFlights {
			other.Process.UID = 2000 + i
			_ = mustFlight(t, c, other) // runs of other keys, still probing
		}
		var n calls
		st := scope{reach: backend.TierCgroup, root: true, checks: passingChecks(&n), cache: c}.run(context.Background())
		if n.n[CheckPrograms] != 1 || st.cached != nil {
			t.Fatalf("an uncoordinated run did not probe: %v cached=%v", n.n, st.cached != nil)
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("an uncoordinated run did not keep its answer: %v", err)
		}
		if st.cacheNote != "" {
			t.Errorf("a cache that read and wrote is reported unusable: %q", st.cacheNote)
		}
		if note := st.report(nil, "").CoordinationNote(); !strings.Contains(note, "all 128 lock files are held") ||
			strings.Count(note, "probe coordination") > 0 {
			t.Errorf("the coordination note does not say why, once: %q", note)
		}
	})
	t.Run("wait-ran-out", func(t *testing.T) {
		c, _ := testCache(t)
		_ = mustFlight(t, c, testKey())
		_, err := c.acquireFlight(context.Background(), testKey(), 30*time.Millisecond)
		if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "held its lock for 30ms") {
			t.Errorf("a wait that ran out is not said as one: %v", err)
		}
	})
}
