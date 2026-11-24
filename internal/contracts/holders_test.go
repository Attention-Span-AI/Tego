// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// A full pool whose holders are all older than any check can live is stuck by definition (fix29): the request is
// refused at once. Anything less certain keeps the wait. The tests inject the holders' start times and the clock.

// holderFixture swaps the holder reader and the clock for a test and gives back how many times the reader was asked,
// and for which names.
type holderFixture struct {
	asked [][]string
}

func fixHolders(t *testing.T, now time.Duration, starts map[string]time.Duration, readErr, clockErr error) *holderFixture {
	t.Helper()
	f := &holderFixture{}
	prevRead, prevClock := readHolders, sinceBoot
	readHolders = func(names []string) (map[string]time.Duration, error) {
		f.asked = append(f.asked, append([]string(nil), names...))
		if readErr != nil {
			return nil, readErr
		}
		out := map[string]time.Duration{}
		for _, name := range names {
			if start, ok := starts[name]; ok {
				out[name] = start
			}
		}
		return out, nil
	}
	sinceBoot = func() (time.Duration, error) { return now, clockErr }
	t.Cleanup(func() { readHolders, sinceBoot = prevRead, prevClock })
	return f
}

// waitForSlot runs a slot wait of a pool of size 2, held by names, with a start-up budget of within, and returns
// how long it took and what it said.
func waitForSlot(t *testing.T, within time.Duration) (time.Duration, error) {
	t.Helper()
	ctx, closeSession := WithHelperSession(context.Background())
	defer closeSession()
	ctx = context.WithValue(ctx, budgetKey{}, &budget{startup: within, location: 5 * time.Second})
	begin := time.Now()
	_, err := exchange(ctx, nil)
	return time.Since(begin), err
}

func wantStuckAtOnce(t *testing.T, took time.Duration, err error, budget time.Duration, count int) {
	t.Helper()
	if took > budget/2 {
		t.Fatalf("the refusal came after %v, want it at once (the wait was %v): %v", took, budget, err)
	}
	want := fmt.Sprintf("%d earlier checks are still stuck on a location that does not answer", count)
	if !IsHelpersStuck(err) || !IsLocationUnavailable(err) || !strings.Contains(err.Error(), want) || !errors.Is(err, context.DeadlineExceeded) ||
		strings.Contains(err.Error(), "very busy") || strings.Contains(err.Error(), "cannot tell whether they are busy") {
		t.Fatalf("the refusal does not say that %d checks are stuck: %v", count, err)
	}
}

func wantWaitKept(t *testing.T, took time.Duration, err error, budget time.Duration) {
	t.Helper()
	if took < budget*9/10 {
		t.Fatalf("the wait ended after %v, before the start-up budget (%v)", took, budget)
	}
	if IsHelpersStuck(err) || !IsStartFailure(err) || !strings.Contains(err.Error(), "2 filesystem helpers are still alive") ||
		!strings.Contains(err.Error(), "cannot tell whether they are busy or stuck") {
		t.Fatalf("the wait ended with something other than the capacity words: %v", err)
	}
}

func TestFullPoolOfHoldersOlderThanAnyCheckRefusesAtOnce(t *testing.T) {
	names := stuckPool(t, 2)
	limit := helperMaxLifetime()
	now := 10 * limit
	f := fixHolders(t, now, map[string]time.Duration{names[0]: 0, names[1]: now - limit - time.Second}, nil, nil)
	const budget = 3 * time.Second
	took, err := waitForSlot(t, budget)
	wantStuckAtOnce(t, took, err, budget, 2)
	if len(f.asked) != 1 || len(f.asked[0]) != 2 {
		t.Fatalf("the holders were read %v, want once for both slots", f.asked)
	}
}

func TestFullPoolWithOneYoungHolderKeepsTheWait(t *testing.T) {
	names := stuckPool(t, 2)
	limit := helperMaxLifetime()
	now := 10 * limit
	fixHolders(t, now, map[string]time.Duration{names[0]: 0, names[1]: now - limit/2}, nil, nil)
	const budget = 400 * time.Millisecond
	took, err := waitForSlot(t, budget)
	wantWaitKept(t, took, err, budget)
}

func TestFullPoolWithOneHolderAgeUnreadableKeepsTheWait(t *testing.T) {
	names := stuckPool(t, 2)
	now := 10 * helperMaxLifetime()
	// The second holder is not found (no entry): another uid's, another pid namespace's, or its stat could not be read.
	fixHolders(t, now, map[string]time.Duration{names[0]: 0}, nil, nil)
	const budget = 400 * time.Millisecond
	took, err := waitForSlot(t, budget)
	wantWaitKept(t, took, err, budget)
}

func TestFullPoolWhoseHoldersCannotBeIdentifiedKeepsTheWait(t *testing.T) {
	now := 10 * helperMaxLifetime()
	t.Run("the reader failed", func(t *testing.T) {
		stuckPool(t, 2)
		fixHolders(t, now, nil, errors.New("no /proc"), nil)
		const budget = 300 * time.Millisecond
		took, err := waitForSlot(t, budget)
		wantWaitKept(t, took, err, budget)
	})
	t.Run("nothing was found", func(t *testing.T) {
		stuckPool(t, 2)
		fixHolders(t, now, nil, nil, nil)
		const budget = 300 * time.Millisecond
		took, err := waitForSlot(t, budget)
		wantWaitKept(t, took, err, budget)
	})
	t.Run("the clock failed", func(t *testing.T) {
		names := stuckPool(t, 2)
		fixHolders(t, now, map[string]time.Duration{names[0]: 0, names[1]: 0}, nil, errors.New("no clock"))
		const budget = 300 * time.Millisecond
		took, err := waitForSlot(t, budget)
		wantWaitKept(t, took, err, budget)
	})
}

// A holder exactly as old as the longest a healthy helper lives is not older than it: the wait stays. One nanosecond
// more and it is stuck.
func TestHolderAtTheBoundaryOfTheMaximumLifetime(t *testing.T) {
	limit := helperMaxLifetime()
	now := 10 * limit
	t.Run("exactly the maximum", func(t *testing.T) {
		names := stuckPool(t, 2)
		fixHolders(t, now, map[string]time.Duration{names[0]: 0, names[1]: now - limit}, nil, nil)
		const budget = 300 * time.Millisecond
		took, err := waitForSlot(t, budget)
		wantWaitKept(t, took, err, budget)
	})
	t.Run("one nanosecond past it", func(t *testing.T) {
		names := stuckPool(t, 2)
		fixHolders(t, now, map[string]time.Duration{names[0]: 0, names[1]: now - limit - 1}, nil, nil)
		const budget = 3 * time.Second
		took, err := waitForSlot(t, budget)
		wantStuckAtOnce(t, took, err, budget, 2)
	})
}

// A slot this process knows to be stuck (its own record) is not asked of the reader: only the holders nothing is known
// about are, and the refusal names the whole pool.
func TestFullPoolOfOwnStuckAndOldOtherHoldersRefusesAtOnce(t *testing.T) {
	names := stuckPool(t, 2)
	markStuck(&helperWorker{slot: names[0], pid: os.Getpid(), start: processStart(os.Getpid())})
	now := 10 * helperMaxLifetime()
	f := fixHolders(t, now, map[string]time.Duration{names[1]: 0}, nil, nil)
	const budget = 3 * time.Second
	took, err := waitForSlot(t, budget)
	wantStuckAtOnce(t, took, err, budget, 2)
	if len(f.asked) != 1 || len(f.asked[0]) != 1 || f.asked[0][0] != names[1] {
		t.Fatalf("the reader was asked %v, want only the slot nothing was known about (%s)", f.asked, names[1])
	}
}

// A pool with a free slot never reads the holders: it takes the slot.
func TestPoolWithAFreeSlotDoesNotReadTheHolders(t *testing.T) {
	allWorkers, governed, pool := processWorkers, governedWorkers, helperReservationPool
	processWorkers, governedWorkers = helperPools(3)
	helperReservationPool = fmt.Sprintf("tego.contracts-test.free.%d.%d", os.Getpid(), time.Now().UnixNano())
	t.Cleanup(func() { processWorkers, governedWorkers, helperReservationPool = allWorkers, governed, pool })
	for slot := range 2 {
		name := fmt.Sprintf("@%s.%d.%d", helperReservationPool, os.Geteuid(), slot)
		holder, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: name, Net: "unixgram"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = holder.Close() })
	}
	f := fixHolders(t, 10*helperMaxLifetime(), map[string]time.Duration{}, nil, nil)
	reservation, lease, err := reserveHelper(admissionCtx(t), uint32(os.Geteuid()), false)
	if err != nil {
		t.Fatalf("a pool with a free slot refused: %v", err)
	}
	closeReservation(reservation)
	closePipe(lease)
	if len(f.asked) != 0 {
		t.Fatalf("the holders were read %v with a slot free", f.asked)
	}
}

// The maximum lifetime is made of the constants of the bounds a helper is abandoned at, so it cannot drift from them.
func TestHelperMaxLifetimeIsMadeOfTheBounds(t *testing.T) {
	want := StartTimeout + 4*CheckTimeout + PauseLimit + helperLifetimeMargin
	if got := helperMaxLifetime(); got != want {
		t.Fatalf("helperMaxLifetime() = %v, want the start-up budget, the location cap, the pause allowance and the margin: %v", got, want)
	}
	if 4*CheckTimeout != locationCap() {
		t.Fatalf("the location cap is %v, the lifetime counts %v", locationCap(), 4*CheckTimeout)
	}
	// The worker's own clock may outlive the cap by its backstop; the margin covers it, and the start of a process.
	if helperLifetimeMargin <= workerBackstop() {
		t.Fatalf("the margin %v does not cover the worker's backstop %v", helperLifetimeMargin, workerBackstop())
	}
	// Longer than anything one request can keep a healthy helper for.
	if helperMaxLifetime() <= startTimeout+locationCap()+PauseLimit {
		t.Fatalf("the maximum lifetime %v is not past the bounds", helperMaxLifetime())
	}
}

// The real reader, on this machine: a child process that holds the reservation as its fd 2 is found, its start time is
// read from its own stat, and a reservation held only as another descriptor is not found.
func TestProcHolderStartsFindsTheProcessThatHoldsTheReservationAsFd2(t *testing.T) {
	pool := fmt.Sprintf("tego.contracts-test.holder.%d.%d", os.Getpid(), time.Now().UnixNano())
	held := "@" + pool + ".held"
	elsewhere := "@" + pool + ".elsewhere"
	free := "@" + pool + ".free"
	listen := func(name string) *net.UnixConn {
		c, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: name, Net: "unixgram"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	reservation := listen(held)
	other := listen(elsewhere)
	_ = other
	lease, err := reservation.File()
	if err != nil {
		t.Fatal(err)
	}
	// The child is the stand-in for a helper: its standard error is the reservation, as reserveHelper gives it.
	cmd := exec.Command("sleep", "60")
	cmd.Stderr = lease
	before, err := sinceBoot()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	_ = lease.Close()
	// The parent closes its own socket as the request does, so the child alone holds the slot.
	_ = reservation.Close()
	starts, err := procHolderStarts([]string{held, elsewhere, free})
	if err != nil {
		t.Fatal(err)
	}
	after, _ := sinceBoot()
	got, ok := starts[held]
	if !ok {
		t.Fatalf("the holder of %s (pid %d) was not found: %v", held, pid, starts)
	}
	// The start time has the resolution of a clock tick.
	if got < before-20*time.Millisecond || got > after {
		t.Fatalf("the holder started at %v since boot, want between %v and %v", got, before, after)
	}
	if _, ok := starts[elsewhere]; ok {
		t.Fatal("a reservation held as a descriptor other than 2 was claimed to be identified")
	}
	if _, ok := starts[free]; ok {
		t.Fatal("a name nobody holds was claimed to be identified")
	}
}

// The helpers are undumpable, so no other process of the user may read their descriptors (/proc/<pid>/fd/2), which is
// how a holder was identified before (fix29). A real helper's holder is still found, by the lock the worker takes on its
// reservation (/proc/locks names the pid that took it, whoever may read that process), and the start time read from its
// own stat is its own.
func TestProcHolderStartsFindsARealUndumpableHelper(t *testing.T) {
	standsAt(t, false, nil)
	prev := helperReservationPool
	helperReservationPool = fmt.Sprintf("tego.contracts-test.%x", sha256.Sum256([]byte(t.Name()+fmt.Sprint(os.Getpid()))))
	t.Cleanup(func() { helperReservationPool = prev })
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	as, err := readHelperCredentials()
	if err != nil {
		t.Fatal(err)
	}
	w, err := startHelper(admissionCtx(t), as)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.close)
	if err := w.cmd.Wait(); err != nil {
		t.Fatalf("launcher: %v", err)
	}
	pid := workerOf(t, w) // the worker's first frame: it has taken its lock before it says anything
	if _, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/2", pid)); err == nil && os.Geteuid() != 0 {
		t.Fatalf("the worker's descriptors are readable: it is not undumpable, and this test proves nothing")
	}
	// The lock table alone must name the worker: as root the descriptor scan below finds it without the lock.
	inodes, err := reservationInodes([]string{w.slot})
	if err != nil {
		t.Fatal(err)
	}
	if lh := lockHolders(inodes); lh[pid] != w.slot {
		t.Fatalf("the lock table does not name the worker (pid %d) as the holder of %s: %v", pid, w.slot, lh)
	}
	starts, err := procHolderStarts([]string{w.slot})
	if err != nil {
		t.Fatal(err)
	}
	got, ok := starts[w.slot]
	if !ok {
		t.Fatalf("the holder of %s (pid %d) was not found: %v", w.slot, pid, starts)
	}
	if want := time.Duration(processStart(pid) * proc.NanosPerTick); got != want {
		t.Fatalf("the holder's start is %v, want its own %v", got, want)
	}
}

// A flock on a file of another filesystem whose inode number equals a reservation socket's names no holder: a
// process of the user could otherwise pass for the holder of a slot it does not hold.
func TestALockOnAnotherFilesystemNamesNoHolder(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "lock")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	inodes := map[string]string{"@not-a-reservation": strconv.FormatUint(st.Ino, 10)}
	if got := lockHolders(inodes); len(got) != 0 {
		t.Fatalf("a lock on a file of another filesystem named a holder: %v", got)
	}
}
