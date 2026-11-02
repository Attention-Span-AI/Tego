// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
)

// blockHostRunner is a Locked run's runner, with no fence, whose liveLookup answers for host from answer (an error, or
// the addresses it holds when called) and counts its lookups, every other host failing, and whose liveNow reads *now.
func blockHostRunner(t *testing.T, host string, now *liveblock.Clock, answer func() ([]netip.Addr, error)) (*runner, *int) {
	t.Helper()
	r := pauseRunner(t)
	lookups := 0
	oldLookup, oldNow := liveLookup, liveNow
	liveLookup = func(_ context.Context, h string) ([]netip.Addr, error) {
		if h != host {
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

// changeBlock adds (add true) or removes a block of kind on value in r's overlay.
func changeBlock(t *testing.T, r *runner, add bool, kind liveblock.Kind, value string) {
	t.Helper()
	updateOverlay(t, r.dir, string(r.id), func(o *liveblock.Overlay) error {
		var err error
		if add {
			_, _, err = o.Add(kind, value, "uid:1 pid:2 cli", time.Now())
		} else {
			_, _, err = o.Remove(kind, value, "uid:1 pid:2 cli", time.Now())
		}
		return err
	})
}

// refusedByName reports whether the Set b holds refuses a connect to an address no lookup answered that the contract
// admitted under host: the block's declared host.
func refusedByName(b *liveBlocks, host string) bool {
	_, ok := b.Load().MatchInet(netip.AddrPortFrom(netip.MustParseAddr("203.0.113.5"), 443), host, nil)
	return ok
}

// TestBlockedHostAddressesAreRefreshed: under a contract with no net: section nothing admits a connect under a host's
// name, so a host block refuses one by the addresses the launcher's lookups of the host answered. They were looked up
// when the block was read and then only at the overlay's next change, so in a quiet overlay a host that moved to
// another address (a CDN's rotation) passed the block for the rest of the run. The host is now looked up again on the
// poll tick once its addresses are liveBlockRefreshAge old, each answer added to every one before; a lookup that fails
// or answers no address keeps every address held and is tried again liveLookupRetry later.
func TestBlockedHostAddressesAreRefreshed(t *testing.T) {
	const host = "cdn.example.test"
	var now liveblock.Clock
	answer := []netip.Addr{netip.MustParseAddr("198.51.100.1")}
	var fail error
	r, lookups := blockHostRunner(t, host, &now, func() ([]netip.Addr, error) {
		if fail != nil {
			return nil, fail
		}
		return answer, nil
	})
	ctx := context.Background()
	b := &liveBlocks{}
	changeBlock(t, r, true, liveblock.KindNet, host)
	r.pollLiveBlocks(ctx, b)
	if *lookups != 1 || !refusedAt(b, "198.51.100.1") {
		t.Fatalf("block read: lookups %d, 198.51.100.1 refused %v; want one lookup and its answer refused", *lookups,
			refusedAt(b, "198.51.100.1"))
	}
	// Younger than liveBlockRefreshAge: polled, not looked up.
	now.Boot += liveBlockRefreshAge - time.Second
	r.pollLiveBlocks(ctx, b)
	if *lookups != 1 {
		t.Fatalf("lookups %d before the addresses were %v old: want none more", *lookups, liveBlockRefreshAge)
	}
	// The host moved and the overlay did not change: the next poll past the age refuses the new address and the old.
	answer = []netip.Addr{netip.MustParseAddr("198.51.100.2")}
	now.Boot += time.Second
	r.pollLiveBlocks(ctx, b)
	if *lookups != 2 || !refusedAt(b, "198.51.100.2") || !refusedAt(b, "198.51.100.1") {
		t.Fatalf("refresh: lookups %d, refused .2 %v .1 %v; want the host looked up again on the tick and both answers refused",
			*lookups, refusedAt(b, "198.51.100.2"), refusedAt(b, "198.51.100.1"))
	}
	// A refresh that fails keeps every address held, and waits liveLookupRetry before it tries again.
	fail = errors.New("i/o timeout")
	now.Boot += liveBlockRefreshAge
	r.pollLiveBlocks(ctx, b)
	if *lookups != 3 || !refusedAt(b, "198.51.100.2") || !refusedAt(b, "198.51.100.1") {
		t.Fatalf("failed refresh: lookups %d, refused .2 %v .1 %v; want both kept", *lookups, refusedAt(b, "198.51.100.2"),
			refusedAt(b, "198.51.100.1"))
	}
	for range 5 {
		now.Boot += 10 * time.Second
		r.pollLiveBlocks(ctx, b)
	}
	if *lookups != 3 {
		t.Fatalf("lookups %d within %v of a failed refresh: want none more", *lookups, liveLookupRetry)
	}
	// A lookup that answers no address is a failure too: nothing is dropped.
	fail, answer = nil, nil
	now.Boot += liveLookupRetry
	r.pollLiveBlocks(ctx, b)
	if *lookups != 4 || !refusedAt(b, "198.51.100.2") || !refusedAt(b, "198.51.100.1") {
		t.Fatalf("empty answer: lookups %d, refused .2 %v .1 %v; want both kept", *lookups, refusedAt(b, "198.51.100.2"),
			refusedAt(b, "198.51.100.1"))
	}
	answer = []netip.Addr{netip.MustParseAddr("198.51.100.3")}
	now.Boot += liveLookupRetry
	r.pollLiveBlocks(ctx, b)
	if *lookups != 5 || !refusedAt(b, "198.51.100.3") || !refusedAt(b, "198.51.100.2") || !refusedAt(b, "198.51.100.1") {
		t.Fatalf("retry after failures: lookups %d, refused .3 %v .2 %v .1 %v; want the new answer and every one before",
			*lookups, refusedAt(b, "198.51.100.3"), refusedAt(b, "198.51.100.2"), refusedAt(b, "198.51.100.1"))
	}
	// Through it all the block refuses by its declared host, and an address the host never answered is not refused.
	if !refusedByName(b, host) {
		t.Fatal("the block does not refuse by its declared host")
	}
	if refusedAt(b, "203.0.113.5") {
		t.Fatal("an address the host never answered is refused")
	}
}

// TestBlockedHostKeepsItsAddressesAcrossStates: each new state of the overlay looks every blocked host up again, as it
// always did, but what that lookup answers is now added to what the block refused before. The Set held the new answer
// alone: a lookup that failed at an unrelated change (another block added) dropped every address the block refused
// by, and one that answered another address dropped the ones before.
func TestBlockedHostKeepsItsAddressesAcrossStates(t *testing.T) {
	const host = "cdn.example.test"
	var now liveblock.Clock
	answer := []netip.Addr{netip.MustParseAddr("198.51.100.1")}
	var fail error
	r, lookups := blockHostRunner(t, host, &now, func() ([]netip.Addr, error) {
		if fail != nil {
			return nil, fail
		}
		return answer, nil
	})
	ctx := context.Background()
	b := &liveBlocks{}
	changeBlock(t, r, true, liveblock.KindNet, host)
	r.pollLiveBlocks(ctx, b)
	// The resolver fails at the next state: the address stays refused.
	fail = errors.New("i/o timeout")
	changeBlock(t, r, true, liveblock.KindExec, "/bin/ls")
	r.pollLiveBlocks(ctx, b)
	if *lookups != 2 || !refusedAt(b, "198.51.100.1") {
		t.Fatalf("a failed lookup at a new state: lookups %d, 198.51.100.1 refused %v; want the host looked up and its address kept",
			*lookups, refusedAt(b, "198.51.100.1"))
	}
	// It answers another address at the state after: both are refused.
	fail, answer = nil, []netip.Addr{netip.MustParseAddr("198.51.100.2")}
	changeBlock(t, r, true, liveblock.KindPath, "/srv/other")
	r.pollLiveBlocks(ctx, b)
	if *lookups != 3 || !refusedAt(b, "198.51.100.2") || !refusedAt(b, "198.51.100.1") {
		t.Fatalf("another answer at a new state: lookups %d, refused .2 %v .1 %v; want both", *lookups,
			refusedAt(b, "198.51.100.2"), refusedAt(b, "198.51.100.1"))
	}
	// Each lookup at a state is a refresh: the tick does not look the host up again before liveBlockRefreshAge.
	now.Boot += liveBlockRefreshAge - time.Second
	r.pollLiveBlocks(ctx, b)
	if *lookups != 3 {
		t.Fatalf("lookups %d: a host looked up at a state is not looked up again on the tick before %v", *lookups, liveBlockRefreshAge)
	}
}

// TestBlockedHostFailedLookupIsRetriedOnTheTick: a host block whose lookup failed when the block was read refuses by
// its declared host alone, which under a contract with no net: section is nothing. It was looked up again only at a
// store, so in a quiet overlay never. It is now tried again on the poll tick liveLookupRetry later, and not before.
func TestBlockedHostFailedLookupIsRetriedOnTheTick(t *testing.T) {
	const host = "cdn.example.test"
	var now liveblock.Clock
	resolves := false
	r, lookups := blockHostRunner(t, host, &now, func() ([]netip.Addr, error) {
		if !resolves {
			return nil, errors.New("i/o timeout")
		}
		return []netip.Addr{netip.MustParseAddr("198.51.100.77")}, nil
	})
	ctx := context.Background()
	b := &liveBlocks{}
	changeBlock(t, r, true, liveblock.KindNet, host)
	r.pollLiveBlocks(ctx, b)
	if *lookups != 1 || refusedAt(b, "198.51.100.77") || !refusedByName(b, host) {
		t.Fatalf("failed lookup: lookups %d, address refused %v, host refused %v; want one lookup, the block by its host alone",
			*lookups, refusedAt(b, "198.51.100.77"), refusedByName(b, host))
	}
	resolves = true
	for range 5 {
		now.Boot += 10 * time.Second
		r.pollLiveBlocks(ctx, b)
	}
	if *lookups != 1 {
		t.Fatalf("lookups %d within %v of the failure, overlay unchanged: want no retry yet", *lookups, liveLookupRetry)
	}
	now.Boot += liveLookupRetry
	r.pollLiveBlocks(ctx, b)
	if !refusedAt(b, "198.51.100.77") {
		t.Fatalf("%v after the failure, overlay unchanged: lookups %d and the address is not refused; want the retry on the tick",
			liveLookupRetry, *lookups)
	}
	n := *lookups
	now.Boot += liveBlockRefreshAge - time.Second
	r.pollLiveBlocks(ctx, b)
	if *lookups != n {
		t.Fatalf("lookups %d after %d: a host found is not looked up again before %v", *lookups, n, liveBlockRefreshAge)
	}
}

// TestUnblockedHostIsForgotten: a host's addresses are held while a block names it. Once the block is removed the
// host is no longer looked up, and a block on it added later starts from what its host answers then.
func TestUnblockedHostIsForgotten(t *testing.T) {
	const host = "cdn.example.test"
	var now liveblock.Clock
	answer := []netip.Addr{netip.MustParseAddr("198.51.100.1")}
	r, lookups := blockHostRunner(t, host, &now, func() ([]netip.Addr, error) { return answer, nil })
	ctx := context.Background()
	b := &liveBlocks{}
	changeBlock(t, r, true, liveblock.KindNet, host)
	r.pollLiveBlocks(ctx, b)
	now.Boot += liveBlockRefreshAge
	answer = []netip.Addr{netip.MustParseAddr("198.51.100.2")}
	r.pollLiveBlocks(ctx, b)
	changeBlock(t, r, false, liveblock.KindNet, host)
	r.pollLiveBlocks(ctx, b)
	n := *lookups
	if refusedAt(b, "198.51.100.1") || refusedAt(b, "198.51.100.2") {
		t.Fatal("a removed block's addresses are still refused")
	}
	now.Boot += 3 * liveBlockRefreshAge
	r.pollLiveBlocks(ctx, b)
	if *lookups != n {
		t.Fatalf("lookups %d after %d: a host no block names is not looked up", *lookups, n)
	}
	answer = []netip.Addr{netip.MustParseAddr("198.51.100.3")}
	changeBlock(t, r, true, liveblock.KindNet, host)
	r.pollLiveBlocks(ctx, b)
	if *lookups != n+1 || !refusedAt(b, "198.51.100.3") {
		t.Fatalf("block added again: lookups %d after %d, .3 refused %v; want its host looked up and its answer refused",
			*lookups, n, refusedAt(b, "198.51.100.3"))
	}
	if refusedAt(b, "198.51.100.1") || refusedAt(b, "198.51.100.2") {
		t.Fatal("a block added again refuses what its host answered under the block that was removed")
	}
}

// TestBlockedHostAddressesAreCapped: what the refreshes add is capped as for a fence host (maxHostAddrs, the address
// answered longest ago dropped first), but what the last state's lookup answered, all the Set refused before refreshes,
// is never dropped.
func TestBlockedHostAddressesAreCapped(t *testing.T) {
	const host = "cdn.example.test"
	var now liveblock.Clock
	n := 0
	addr := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{198, 51, byte(i / 250), byte(1 + i%250)}) }
	r, _ := blockHostRunner(t, host, &now, func() ([]netip.Addr, error) { return []netip.Addr{addr(n)}, nil })
	ctx := context.Background()
	b := &liveBlocks{}
	changeBlock(t, r, true, liveblock.KindNet, host)
	r.pollLiveBlocks(ctx, b)
	const refreshes = maxHostAddrs + 10
	for range refreshes {
		n++
		now.Boot += liveBlockRefreshAge
		r.pollLiveBlocks(ctx, b)
	}
	if got := len(b.blockHosts.addrs[host]); got != maxHostAddrs {
		t.Fatalf("host held with %d addresses after %d refreshes, want the cap %d", got, refreshes, maxHostAddrs)
	}
	if !refusedAt(b, addr(0).String()) {
		t.Fatal("the answer of the block's own lookup was dropped by the cap")
	}
	if !refusedAt(b, addr(refreshes).String()) || !refusedAt(b, addr(refreshes-maxHostAddrs+1).String()) {
		t.Fatal("a recent answer is not refused")
	}
	if refusedAt(b, addr(1).String()) {
		t.Fatal("the refresh answered longest ago is still refused past the cap")
	}
}

// TestBlockedFenceHostIsRefreshedAsABlock: a host a fence entry and a block both name is held for the run, as the
// fence's, and looked up again every liveBlockRefreshAge while a block names it, every liveRefreshAge after.
func TestBlockedFenceHostIsRefreshedAsABlock(t *testing.T) {
	const fenceHost = "db.example.test"
	var now liveblock.Clock
	answer := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	r, lookups := fenceHostRunner(t, fenceHost, &now, func() ([]netip.Addr, error) { return answer, nil })
	ctx := context.Background()
	b, err := r.startLiveBlocks(ctx)
	if err != nil {
		t.Fatal(err)
	}
	changeBlock(t, r, true, liveblock.KindNet, fenceHost)
	r.pollLiveBlocks(ctx, b)
	if *lookups != 1 {
		t.Fatalf("lookups %d: a block on a fence host is not looked up again at its state (the fence holds it)", *lookups)
	}
	answer = []netip.Addr{netip.MustParseAddr("192.0.2.2")}
	now.Boot += liveBlockRefreshAge
	r.pollLiveBlocks(ctx, b)
	if *lookups != 2 || !refusedAt(b, "192.0.2.2") || !refusedAt(b, "192.0.2.1") {
		t.Fatalf("blocked fence host after %v: lookups %d, refused .2 %v .1 %v; want it refreshed as a block's",
			liveBlockRefreshAge, *lookups, refusedAt(b, "192.0.2.2"), refusedAt(b, "192.0.2.1"))
	}
	changeBlock(t, r, false, liveblock.KindNet, fenceHost)
	r.pollLiveBlocks(ctx, b)
	now.Boot += liveBlockRefreshAge
	r.pollLiveBlocks(ctx, b)
	if *lookups != 2 || !refusedAt(b, "192.0.2.2") || !refusedAt(b, "192.0.2.1") {
		t.Fatalf("unblocked fence host: lookups %d, refused .2 %v .1 %v; want the fence's addresses kept, no refresh before %v",
			*lookups, refusedAt(b, "192.0.2.2"), refusedAt(b, "192.0.2.1"), liveRefreshAge)
	}
	now.Boot += liveRefreshAge
	r.pollLiveBlocks(ctx, b)
	if *lookups != 3 {
		t.Fatalf("lookups %d: want the fence host refreshed once its addresses are %v old", *lookups, liveRefreshAge)
	}
}
