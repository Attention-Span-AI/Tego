// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/testutil/answertest"
)

// A governed program's checks can never use up what a person's check needs. Their workers' kernel reservations
// outlive the request until each worker exits, so on a busy machine a burst of governed checks whose workers exit
// slowly holds slots for a while: here every slot a governed request may take is held by a reservation whose worker
// has not exited. A governed check then gets the bounded refusal it got before, after the one-second admission wait;
// the person's check is admitted on a reserved slot; and the bound on all slots still holds.
// testAdmissionWait is how long these tests give a slot wait that must refuse: the production wait is the exchange's
// start-up budget (StartTimeout), far too long for a test whose pool is full on purpose.
const testAdmissionWait = time.Second * raceScale

// admissionCtx is a context that ends after testAdmissionWait.
func admissionCtx(t testing.TB) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), testAdmissionWait)
	t.Cleanup(cancel)
	return ctx
}

func TestHelperReservationKeepsPersonsSlotsFromGovernedBurst(t *testing.T) {
	prev := helperReservationPool
	helperReservationPool = fmt.Sprintf("tego.contracts-test.%x", sha256.Sum256([]byte(t.Name()+fmt.Sprint(os.Getpid()))))
	t.Cleanup(func() { helperReservationPool = prev })
	uid := uint32(os.Getuid())
	var leases []*os.File
	t.Cleanup(func() {
		for _, lease := range leases {
			closePipe(lease)
		}
	})
	hold := func(governed bool) error {
		listener, lease, err := reserveHelper(admissionCtx(t), uid, governed)
		if err != nil {
			return err
		}
		// The request closes its end; the lease is the worker's fd 2, alive until the worker exits.
		closeReservation(listener)
		leases = append(leases, lease)
		return nil
	}
	shared := cap(processWorkers) - helperReserve(cap(processWorkers))
	for i := range shared {
		if err := hold(true); err != nil {
			t.Fatalf("governed check %d of %d: %v", i+1, shared, err)
		}
	}
	start := time.Now()
	err := hold(true)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%d filesystem helpers are still alive", cap(processWorkers))) {
		t.Fatalf("a governed check past the governed share: %v, want the bounded refusal", err)
	}
	if waited := time.Since(start); waited < testAdmissionWait/2 {
		t.Errorf("the governed refusal came after %v, want the admission wait (%v)", waited, testAdmissionWait)
	}
	// The person's check, then the rest of the reserve.
	for i := range max(helperReserve(cap(processWorkers)), 1) {
		if err := hold(false); err != nil {
			t.Fatalf("the person's check %d behind a governed burst: %v; want it admitted on a reserved slot", i+1, err)
		}
	}
	if err := hold(false); err == nil || !strings.Contains(err.Error(), "filesystem helpers are still alive") {
		t.Fatalf("a check past all %d slots: %v, want the bounded refusal", cap(processWorkers), err)
	}
}

// The same within this process: governed workers take at most the governed share of processWorkers.
func TestHelperAdmissionKeepsPersonsWorkersFromGovernedBurst(t *testing.T) {
	var releases []func()
	t.Cleanup(func() {
		for _, release := range releases {
			release()
		}
	})
	admit := func(governed bool) error {
		ctx, cancel := context.WithTimeout(context.Background(), testAdmissionWait)
		defer cancel()
		release, err := admitWorker(ctx, governed)
		if err == nil {
			releases = append(releases, release)
		}
		return err
	}
	for i := range cap(processWorkers) - helperReserve(cap(processWorkers)) {
		if err := admit(true); err != nil {
			t.Fatalf("governed worker %d: %v", i+1, err)
		}
	}
	if err := admit(true); err == nil || !strings.Contains(err.Error(), "filesystem helpers are still alive") {
		t.Fatalf("a governed worker past the governed share: %v, want the bounded refusal", err)
	}
	for i := range max(helperReserve(cap(processWorkers)), 1) {
		if err := admit(false); err != nil {
			t.Fatalf("the person's worker %d behind a governed burst: %v", i+1, err)
		}
	}
	if err := admit(false); err == nil {
		t.Fatalf("a worker past all %d slots was admitted", cap(processWorkers))
	}
	for _, release := range releases {
		release()
	}
	releases = nil
	if len(processWorkers) != 0 || len(governedWorkers) != 0 {
		t.Fatalf("released workers left %d slots and %d governed slots taken", len(processWorkers), len(governedWorkers))
	}
}

// A request of a process outside every run is governed only when its context says so, and the question is asked
// once, when first needed.
func TestGovernedCallerAsksOnce(t *testing.T) {
	standsAt(t, false, nil)
	if GovernedCaller(context.Background()) {
		t.Fatal("an unmarked request is governed")
	}
	asked := 0
	ctx := WithGovernedCaller(context.Background(), func() bool { asked++; return true })
	if asked != 0 {
		t.Fatal("marking asked")
	}
	first, second := GovernedCaller(ctx), GovernedCaller(ctx)
	if !first || !second || asked != 1 {
		t.Fatalf("governed %v then %v, asked %d times, want true twice, asked once", first, second, asked)
	}
}

// standsAt makes this process's run membership, as GovernedCaller reads it, in and err, for the test.
func standsAt(t *testing.T, in bool, err error) {
	t.Helper()
	prevSelf, prevGoverned := selfAnswer, processGoverned
	selfAnswer = func() runscope.Answer {
		switch {
		case err != nil:
			return answertest.Recorded(runscope.CauseProbeError, 0)
		case in:
			return answertest.Inside(runscope.CauseGoverned)
		}
		return answertest.Outside()
	}
	processGoverned = membership()
	t.Cleanup(func() { selfAnswer, processGoverned = prevSelf, prevGoverned })
}

// A helper request that carries no marker is classified by this process's own run membership, once: inside a run,
// or where it cannot tell, it is a governed program's and never takes a reserved slot, whatever entry point made it
// (finding 1 of the review of the root-suite fixes: tego-control's rules, guide and setup commands set no marker and
// took the reserve first). A marker never makes a process inside a run ungoverned. Only a process shown to be outside
// every run takes the reserve with an unmarked request.
func TestUnmarkedRequestIsGovernedInsideARun(t *testing.T) {
	notOutside := func(t *testing.T, ctx context.Context) {
		t.Helper()
		prev := helperReservationPool
		helperReservationPool = fmt.Sprintf("tego.contracts-test.%x", sha256.Sum256([]byte(t.Name()+fmt.Sprint(os.Getpid()))))
		t.Cleanup(func() { helperReservationPool = prev })
		uid := uint32(os.Getuid())
		var leases []*os.File
		t.Cleanup(func() {
			for _, lease := range leases {
				closePipe(lease)
			}
		})
		for range cap(processWorkers) - helperReserve(cap(processWorkers)) {
			listener, lease, err := reserveHelper(admissionCtx(t), uid, true)
			if err != nil {
				t.Fatal(err)
			}
			closeReservation(listener)
			leases = append(leases, lease)
		}
		listener, lease, err := reserveHelper(admissionCtx(t), uid, GovernedCaller(ctx))
		if err == nil {
			closeReservation(listener)
			leases = append(leases, lease)
			t.Fatal("a request of a process inside a run, or one that cannot tell, took a reserved slot")
		}
		if !strings.Contains(err.Error(), "filesystem helpers are still alive") {
			t.Fatalf("got %v, want the bounded refusal a governed request gets", err)
		}
	}
	t.Run("inside a run, unmarked", func(t *testing.T) {
		standsAt(t, true, nil)
		notOutside(t, context.Background())
	})
	t.Run("cannot tell, unmarked", func(t *testing.T) {
		standsAt(t, false, errors.New("runscope: read /proc/self/cgroup: permission denied"))
		notOutside(t, context.Background())
	})
	t.Run("inside a run, marked as a person's", func(t *testing.T) {
		standsAt(t, true, nil)
		notOutside(t, WithGovernedCaller(context.Background(), func() bool { return false }))
	})
	t.Run("outside every run, unmarked", func(t *testing.T) {
		asked := 0
		standsAt(t, false, nil)
		prev := selfAnswer
		selfAnswer = func() runscope.Answer { asked++; return prev() }
		first, second := GovernedCaller(context.Background()), GovernedCaller(context.Background())
		if first || second || asked != 1 {
			t.Fatalf("a process outside every run: governed, or asked %d times, want ungoverned and asked once", asked)
		}
	})
}

// The local governed bound and the kernel names a governed request may try derive from one value (helperReserve):
// for every pool size the governed workers' bound is the pool less its reserve, a governed request tries exactly that
// many names and none of the reserve, and any other request tries the reserve first. The bound was fixed at
// helperLimit-personHelperReserve while the names scaled with the pool, so a test's smaller pool got a governed bound
// that did not follow it.
func TestGovernedBoundAndReserveAreOneValue(t *testing.T) {
	prevAll, prevGoverned := processWorkers, governedWorkers
	t.Cleanup(func() { processWorkers, governedWorkers = prevAll, prevGoverned })
	for _, limit := range []int{4, 8, 16, helperLimit, 64} {
		processWorkers, governedWorkers = helperPools(limit)
		governed, other := helperSlots(true), helperSlots(false)
		reserve := helperReserve(limit)
		if cap(processWorkers) != limit || cap(governedWorkers) != limit-reserve || len(governed) != limit-reserve ||
			len(other) != limit {
			t.Errorf("pool %d: governed bound %d, governed names %d, other names %d, want %d, %d and %d", limit,
				cap(governedWorkers), len(governed), len(other), limit-reserve, limit-reserve, limit)
		}
		for _, slot := range governed {
			if slot >= limit-reserve {
				t.Errorf("pool %d: a governed request tries reserved name %d", limit, slot)
			}
		}
		for i, slot := range other[:reserve] {
			if slot < limit-reserve {
				t.Errorf("pool %d: another request's try %d is shared name %d, want the reserve first", limit, i, slot)
			}
		}
	}
}
