// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// fenceHostRunner is a fenced runner whose net entry names fenceHost:5432, with liveLookup answering from answer (an
// error, or the addresses it holds when called) and counting its calls, and liveNow reading *now.
func fenceHostRunner(t *testing.T, fenceHost string, now *liveblock.Clock, answer func() ([]netip.Addr, error)) (*runner, *int) {
	t.Helper()
	r := fenceRunner(t)
	r.rt.Live.Entries[1].Value = fenceHost + ":5432"
	lookups := 0
	oldLookup, oldNow := liveLookup, liveNow
	liveLookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		if host != fenceHost {
			return nil, errors.New("no such host")
		}
		lookups++
		return answer()
	}
	*now = liveblock.ReadClock()
	liveNow = func() liveblock.Clock { return *now }
	t.Cleanup(func() { liveLookup, liveNow = oldLookup, oldNow })
	return r, &lookups
}

// refusedAt reports whether the Set b holds refuses a connect to addr:5432 that no contract host admitted.
func refusedAt(b *liveBlocks, addr string) bool {
	_, ok := b.Load().MatchInet(netip.AddrPortFrom(netip.MustParseAddr(addr), 5432), "", nil)
	return ok
}

// TestFenceHostAddressesAreRefreshed: a fence host's addresses are looked up again once they are
// liveRefreshAge old on CLOCK_BOOTTIME, on the poll tick with no overlay change; a refresh adds the new answer to every
// address the host answered before (nothing is dropped below maxHostAddrs), and a refresh that
// fails keeps every address held (never loosen on a failed lookup) and is tried again only liveLookupRetry later.
func TestFenceHostAddressesAreRefreshed(t *testing.T) {
	const fenceHost = "db.example.test"
	var now liveblock.Clock
	answer := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	var fail error
	r, lookups := fenceHostRunner(t, fenceHost, &now, func() ([]netip.Addr, error) {
		if fail != nil {
			return nil, fail
		}
		return answer, nil
	})
	ctx := context.Background()
	b, err := r.startLiveBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if *lookups != 1 || !refusedAt(b, "192.0.2.1") {
		t.Fatalf("start: lookups %d, 192.0.2.1 refused %v; want one lookup and its address refused", *lookups, refusedAt(b, "192.0.2.1"))
	}
	// Younger than liveRefreshAge: polled, not looked up.
	now.Boot += liveRefreshAge - time.Second
	r.pollLiveBlocks(ctx, b)
	if *lookups != 1 {
		t.Fatalf("lookups %d before the addresses were %v old: want none more", *lookups, liveRefreshAge)
	}
	// The host moved: the next poll past the age refuses the new address and still the old one.
	answer = []netip.Addr{netip.MustParseAddr("192.0.2.2")}
	now.Boot += time.Second
	r.pollLiveBlocks(ctx, b)
	if *lookups != 2 {
		t.Fatalf("lookups %d: want the host looked up again on the tick once its addresses are %v old", *lookups, liveRefreshAge)
	}
	if !refusedAt(b, "192.0.2.2") || !refusedAt(b, "192.0.2.1") {
		t.Fatalf("after a refresh: new %v, previous %v refused; want both", refusedAt(b, "192.0.2.2"), refusedAt(b, "192.0.2.1"))
	}
	// A second refresh keeps every answer: the first is still refused.
	answer = []netip.Addr{netip.MustParseAddr("192.0.2.3")}
	now.Boot += liveRefreshAge
	r.pollLiveBlocks(ctx, b)
	if *lookups != 3 || !refusedAt(b, "192.0.2.3") || !refusedAt(b, "192.0.2.2") || !refusedAt(b, "192.0.2.1") {
		t.Fatalf("second refresh: lookups %d, refused .3 %v .2 %v .1 %v; want 3 lookups and every answer refused",
			*lookups, refusedAt(b, "192.0.2.3"), refusedAt(b, "192.0.2.2"), refusedAt(b, "192.0.2.1"))
	}
	// A refresh that fails keeps what is held, and waits liveLookupRetry before it tries again.
	fail = errors.New("i/o timeout")
	now.Boot += liveRefreshAge
	r.pollLiveBlocks(ctx, b)
	if *lookups != 4 || !refusedAt(b, "192.0.2.3") || !refusedAt(b, "192.0.2.2") {
		t.Fatalf("failed refresh: lookups %d, refused .3 %v .2 %v; want the addresses kept", *lookups, refusedAt(b, "192.0.2.3"),
			refusedAt(b, "192.0.2.2"))
	}
	for range 5 {
		now.Boot += 10 * time.Second
		r.pollLiveBlocks(ctx, b)
	}
	if *lookups != 4 {
		t.Fatalf("lookups %d within a minute of a failed refresh: want none more", *lookups)
	}
	// A lookup that answers no address is a failure too: nothing is dropped.
	fail = nil
	answer = nil
	now.Boot += liveLookupRetry
	r.pollLiveBlocks(ctx, b)
	if *lookups != 5 || !refusedAt(b, "192.0.2.3") || !refusedAt(b, "192.0.2.2") {
		t.Fatalf("empty answer: lookups %d, refused .3 %v .2 %v; want the addresses kept", *lookups, refusedAt(b, "192.0.2.3"),
			refusedAt(b, "192.0.2.2"))
	}
	answer = []netip.Addr{netip.MustParseAddr("192.0.2.4")}
	now.Boot += liveLookupRetry
	r.pollLiveBlocks(ctx, b)
	if *lookups != 6 || !refusedAt(b, "192.0.2.4") || !refusedAt(b, "192.0.2.3") || !refusedAt(b, "192.0.2.1") {
		t.Fatalf("retry after failures: lookups %d, refused .4 %v .3 %v .1 %v; want the new answer and every one before",
			*lookups, refusedAt(b, "192.0.2.4"), refusedAt(b, "192.0.2.3"), refusedAt(b, "192.0.2.1"))
	}
	// Through it all the declared host refuses.
	if _, ok := b.Load().MatchInet(netip.AddrPortFrom(netip.MustParseAddr("203.0.113.5"), 5432), fenceHost, nil); !ok {
		t.Fatal("the fence entry is not refused by its declared host")
	}
}

// TestFenceFailedLookupIsRetriedOnTheTick: a fence host whose lookup failed at the start is tried
// again on the poll tick once liveLookupRetry has passed, though the overlay never changes, and not before.
func TestFenceFailedLookupIsRetriedOnTheTick(t *testing.T) {
	const fenceHost = "db.example.test"
	var now liveblock.Clock
	resolves := false
	r, lookups := fenceHostRunner(t, fenceHost, &now, func() ([]netip.Addr, error) {
		if !resolves {
			return nil, errors.New("i/o timeout")
		}
		return []netip.Addr{netip.MustParseAddr("192.0.2.77")}, nil
	})
	ctx := context.Background()
	b, err := r.startLiveBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resolves = true
	for range 5 {
		now.Boot += 10 * time.Second
		r.pollLiveBlocks(ctx, b)
	}
	if *lookups != 1 || refusedAt(b, "192.0.2.77") {
		t.Fatalf("within a minute of the failure: lookups %d, address refused %v; want no retry yet", *lookups, refusedAt(b, "192.0.2.77"))
	}
	now.Boot += liveLookupRetry
	r.pollLiveBlocks(ctx, b)
	if *lookups != 2 || !refusedAt(b, "192.0.2.77") {
		t.Fatalf("a minute after the failure, overlay unchanged: lookups %d, address refused %v; want the retry on the tick",
			*lookups, refusedAt(b, "192.0.2.77"))
	}
	r.pollLiveBlocks(ctx, b)
	if *lookups != 2 {
		t.Fatalf("lookups %d: a host found is not looked up again before liveRefreshAge", *lookups)
	}
}

// TestFenceRefreshKeepsALiftedHost: a lifted net entry's host is refreshed too (fenceRes outlives every lift), so the
// restore refuses it at once by the refreshed addresses, and the lift stays in force across the refresh.
func TestFenceRefreshKeepsALiftedHost(t *testing.T) {
	const fenceHost = "db.example.test"
	var now liveblock.Clock
	answer := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	r, lookups := fenceHostRunner(t, fenceHost, &now, func() ([]netip.Addr, error) { return answer, nil })
	ctx := context.Background()
	b, err := r.startLiveBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	value := fenceHost + ":5432"
	key := b.fence.(*liveFence).key
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		_, e := o.Lift(liveblock.KindNet, value, "uid:1 pid:3 cli", time.Now(), time.Time{}, key)
		return e
	})
	r.pollLiveBlocks(ctx, b)
	if refusedAt(b, "192.0.2.1") {
		t.Fatal("the lift was not applied")
	}
	answer = []netip.Addr{netip.MustParseAddr("192.0.2.2")}
	now.Boot += liveRefreshAge
	r.pollLiveBlocks(ctx, b)
	if *lookups != 2 {
		t.Fatalf("lookups %d: want the lifted host refreshed too", *lookups)
	}
	if refusedAt(b, "192.0.2.2") || refusedAt(b, "192.0.2.1") {
		t.Fatal("a refresh put a lifted entry back in force")
	}
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		_, e := o.Restore(liveblock.KindNet, value, "uid:1 pid:3 cli", time.Now())
		return e
	})
	r.pollLiveBlocks(ctx, b)
	if !refusedAt(b, "192.0.2.2") || !refusedAt(b, "192.0.2.1") || *lookups != 2 {
		t.Fatalf("restore: refused .2 %v .1 %v, lookups %d; want both answers refused at once with no lookup",
			refusedAt(b, "192.0.2.2"), refusedAt(b, "192.0.2.1"), *lookups)
	}
}

// TestFenceHostAddressesAreCapped: a host that answers a new address on every refresh is refused by
// at most maxHostAddrs of them, the ones answered longest ago dropped first, and an address answered again counts as
// answered last, so it is kept.
func TestFenceHostAddressesAreCapped(t *testing.T) {
	const fenceHost = "db.example.test"
	var now liveblock.Clock
	n := 0
	addr := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{198, 51, byte(i / 250), byte(1 + i%250)}) }
	r, _ := fenceHostRunner(t, fenceHost, &now, func() ([]netip.Addr, error) {
		// Each answer is a new address, and the first one again.
		return []netip.Addr{addr(n), addr(0)}, nil
	})
	ctx := context.Background()
	b, err := r.startLiveBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	const refreshes = maxHostAddrs + 10
	for range refreshes {
		n++
		now.Boot += liveRefreshAge
		r.pollLiveBlocks(ctx, b)
	}
	if got := len(b.fenceRes.Addrs[fenceHost]); got != maxHostAddrs {
		t.Fatalf("host refused by %d addresses after %d refreshes, want the cap %d", got, refreshes, maxHostAddrs)
	}
	if !refusedAt(b, addr(0).String()) {
		t.Fatal("the address answered on every lookup was dropped")
	}
	if !refusedAt(b, addr(refreshes).String()) || !refusedAt(b, addr(refreshes-maxHostAddrs+2).String()) {
		t.Fatal("a recent answer is not refused")
	}
	if refusedAt(b, addr(1).String()) {
		t.Fatal("the address answered longest ago is still refused past the cap")
	}
}

// TestFenceRefreshDoesNotDelayARestoreOrAPause: with three fence hosts due and a resolver that hangs
// until its deadline, a restore, a new block and a pause the overlay brings are in force before the first lookup
// starts, and the refresh holds the poll for one liveLookupWait, not one per host. The hosts are stamped failed with the
// clock read after the lookups and keep every address held.
func TestFenceRefreshDoesNotDelayARestoreOrAPause(t *testing.T) {
	f := &fakeFreezer{}
	f.install(t)
	var mu sync.Mutex
	var events []string
	event := func(e string) { mu.Lock(); events = append(events, e); mu.Unlock() }
	freeze := freezeCgroup
	freezeCgroup = func(cg cgroup.Cgroup, on bool) error {
		event("freeze")
		return freeze(cg, on)
	}
	hosts := []string{"a.example.test", "b.example.test", "c.example.test"}
	r := fenceRunner(t)
	r.rt.Live.Entries[1].Value = hosts[0] + ":5432"
	for _, h := range hosts[1:] {
		r.rt.Live.Entries = append(r.rt.Live.Entries, agent.LiveEntry{Kind: agent.LiveKindNet, Value: h + ":5432", Source: agent.LiveSourceNew})
	}
	var hang atomic.Bool
	var b *liveBlocks
	var at atomic.Pointer[liveblock.Set] // the Set in force when the first hanging lookup started
	oldLookup, oldNow := liveLookup, liveNow
	// The clock runs with the wall, from a base the test moves: the stamps a refresh makes show when it read it.
	var clockMu sync.Mutex
	base, t0 := liveblock.ReadClock(), time.Now()
	liveNow = func() liveblock.Clock {
		clockMu.Lock()
		defer clockMu.Unlock()
		c := base
		c.Boot += time.Since(t0)
		return c
	}
	liveLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		if !slices.Contains(hosts, host) {
			return nil, errors.New("no such host")
		}
		if !hang.Load() {
			return []netip.Addr{netip.MustParseAddr("192.0.2." + strconv.Itoa(1+slices.Index(hosts, host)))}, nil
		}
		event("lookup")
		at.CompareAndSwap(nil, b.Load())
		<-ctx.Done()
		return nil, ctx.Err()
	}
	t.Cleanup(func() { liveLookup, liveNow = oldLookup, oldNow })
	ctx := context.Background()
	var err error
	b, err = r.startLiveBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	key := b.fence.(*liveFence).key
	liftRead(t, r, key, "uid:1 pid:3 cli", time.Now(), time.Time{})
	r.pollLiveBlocks(ctx, b)
	if _, ok := b.Load().MatchPath(fenceRead+"/q3.csv", liveblock.AccessRead); ok {
		t.Fatal("the lift was not applied")
	}
	// Every host is due; the resolver now hangs. One overlay change restores the read entry, adds a block and pauses.
	hang.Store(true)
	clockMu.Lock()
	base.Boot += liveRefreshAge
	clockMu.Unlock()
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		if _, err := o.Restore(liveblock.KindRead, fenceRead, "uid:1 pid:3 cli", time.Now()); err != nil {
			return err
		}
		if _, _, err := o.Add(liveblock.KindPath, "/srv/new", "uid:1 pid:3 cli", time.Now()); err != nil {
			return err
		}
		o.Pause("cli", time.Now())
		return nil
	})
	start, before := time.Now(), liveNow().Boot
	r.pollLiveBlocks(ctx, b)
	took := time.Since(start)
	if took >= liveLookupWait+liveLookupWait/2 {
		t.Fatalf("the poll took %v with %d hosts due: want about one liveLookupWait (%v), not one per host", took, len(hosts), liveLookupWait)
	}
	s := at.Load()
	if s == nil {
		t.Fatal("no lookup ran: the hosts were not refreshed")
	}
	if _, ok := s.MatchPath(fenceRead+"/q3.csv", liveblock.AccessRead); !ok {
		t.Fatal("the restore was not in force when the refresh began")
	}
	if _, ok := s.MatchPath("/srv/new/x", liveblock.AccessWrite); !ok {
		t.Fatal("the new block was not in force when the refresh began")
	}
	mu.Lock()
	got := slices.Clone(events)
	mu.Unlock()
	if len(got) == 0 || got[0] != "freeze" {
		t.Fatalf("events %q: want the pause's freeze before any lookup", got)
	}
	for i, h := range hosts {
		if d := b.fenceFailed[h] - before; d < liveLookupWait {
			t.Fatalf("host %s stamped failed %v into the poll: want the clock read after the lookups, %v or more", h, d, liveLookupWait)
		}
		if !refusedAt(b, "192.0.2."+strconv.Itoa(1+i)) {
			t.Fatalf("host %s: a failed refresh dropped its address", h)
		}
	}
}
