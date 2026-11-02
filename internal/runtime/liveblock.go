// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"maps"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// liveBlockPoll is how often the launcher looks at the run's overlay (internal/liveblock): a block takes effect within
// about this long plus a lookup of its host. A time limit takes effect at its instant (every match checks it); its
// ledger line is written on the next poll.
const liveBlockPoll = 500 * time.Millisecond

// liveNow reads the two clocks a time limit is judged on; replaced in tests.
var liveNow = liveblock.ReadClock

// fenceHook is an Adjustable run's fence (ADR 0125, livefence.go); nil on a Locked run.
type fenceHook interface {
	// Apply takes the overlay's lift and restore changes since the last poll in serial order (unreadable: the overlay
	// could not be read or was removed, or changes were lost from it; see pollLiveBlocks), records what took effect,
	// and reports whether its refusals changed. With unreadable it drops every lift, so each fence entry refuses again
	// (ADR 0125 decision 5: fail closed in both directions). It is never handed the same lift twice: a lift whose MAC
	// the launcher already handed it (one copied into an overlay written again after a removal) is refused before
	// Apply, with a live-lift-refused {mac} line (pollLiveBlocks, usedLift).
	Apply(ctx context.Context, now liveblock.Clock, changes []liveblock.Change, unreadable bool) bool
	// Tick ends lifts whose limit has passed, one line each, and reports whether its refusals changed.
	Tick(ctx context.Context, now liveblock.Clock) bool
	// Refusals are the fence refusals in force or due (Fence true; From set on a lift that ends).
	Refusals() []liveblock.Entry
	// Pins are the BOOTTIME pins of the refusals' From instants, by DeadlineKey.
	Pins() map[string]time.Duration
	// RefusedRule is the rule a refused lift of kind on value is recorded under: its fence entry's, or the request's
	// (liveblock.LiftRule) when it names none.
	RefusedRule(kind liveblock.Kind, value string) string
}

// liveBlocks is the run's live blocks as the supervisor reads them (supervisor.Options.LiveBlocks), and the launcher's
// own state of the overlay file it compiled them from.
type liveBlocks struct {
	set atomic.Pointer[liveblock.Set]
	// sig is the overlay file the set was compiled from, or the one last found unreadable.
	sig liveblock.Signature
	// serial is the last change of the overlay now followed that the run's ledger has a line for. It goes back to 0
	// when the overlay is removed or written again with a lower serial: a new file's changes start again at 1.
	serial uint64
	// used are the MACs of every lift handed to the fence this run, so a lift copied from an overlay that was removed
	// is not applied twice (the MAC binds the serial, and a new file reuses serials). It never shrinks.
	used map[string]bool
	// last is the overlay last read; its blocks stay in force while the file cannot be read. nil: none, or removed.
	last *liveblock.Overlay
	// res is what the last compile resolved, reused when only the fence's refusals changed: what the stores' lookups
	// answered, each host's and program's from the last store that looked it up. A block's host whose lookup failed is
	// not in it, so the next store looks it up again.
	res liveblock.Resolved
	// fenceFiles is each fence exec entry's program identity once found, kept for the run as fenceHosts are.
	fenceFiles map[string]liveblock.FileID
	// fenceHosts are the fence refusals' hosts, kept for the run. Unlike res they are never pruned to the entries a Set
	// holds, so a lift does not drop an entry's addresses and its restore refuses by them at once, with no lookup. A
	// host whose lookup failed is held with no addresses until a retry finds some.
	fenceHosts hostBook
	// blockHosts are the hosts the overlay's blocks name, each held while a block names it (a host a fence refusal names
	// is fenceHosts' alone): every address its lookups answered while the block stands, at a store or on the poll tick.
	// The Set refuses a blocked host by all of them beside what the last store's lookup answered (refusing).
	blockHosts hostBook
	// blocked are the hosts the overlay's blocks named at the last store, in either book: each is looked up again every
	// liveBlockRefreshAge (refreshAge).
	blocked map[string]bool
	// pins are the BOOTTIME pins of every until and from seen, by DeadlineKey: each is made the first time its
	// instant is seen and never derived again, so a later wall-clock step does not move it (ADR 0125 decision 4).
	pins map[string]time.Duration
	// done are the expiry lines already written, by DeadlineKey: each limit's end is recorded once.
	done map[string]bool
	// fence is an Adjustable run's fence; nil on a Locked run.
	fence fenceHook
	// polled is set by the first poll, which compiles whatever the overlay's state.
	polled bool
}

// Load is the set now; nil blocks nothing.
func (b *liveBlocks) Load() *liveblock.Set { return b.set.Load() }

// watchLiveBlocks polls the run directory's overlay until ctx ends: each new state is read, compiled with the
// addresses of its blocked hosts and the identities of its blocked programs, and put in force by one atomic store;
// every add and remove since the last one gets its gap line (MinorLiveBlock), and every time limit that ended its
// expiry line (MinorLiveModes). A file that is not there is no blocks. One that cannot be read keeps the blocks last
// in force and writes one gap live-block-unreadable per state of the file (fail closed: a block is never dropped
// because its file broke), and drops every lift of an Adjustable run's fence.
func (r *runner) watchLiveBlocks(ctx context.Context, b *liveBlocks) error {
	t := time.NewTicker(liveBlockPoll)
	defer t.Stop()
	for {
		r.pollLiveBlocks(ctx, b)
		select {
		case <-ctx.Done():
			// The run is ending: a paused run is thawed so no frozen scope outlives it (livepause.go).
			r.thawForStop(ctx)
			return nil
		case <-t.C:
		}
	}
}

// markRealReader tells writers that this launcher reads a block's real path (liveblock.Entry.Real, VersionReal): it
// makes the run directory's liveblock.RealName once the live-block poll runs. `tego block` and the dashboard store a
// real path only for a run that has the mark (liveblock.TakesReal), so an older launcher, which would refuse the whole
// overlay once it was VersionReal, never meets one. A mark that cannot be made is logged: blocks through a link then
// refuse their value alone, as before the real path, and the writers say so.
func (r *runner) markRealReader() {
	if r.dir == "" {
		return
	}
	if err := liveblock.MarkReal(r.dir); err != nil {
		r.log.Warn("live blocks: the run's real-path mark could not be made, so a block through a link refuses its value alone", "err", err)
	}
}

// pollLiveBlocks reads the overlay when it changed: its blocks are compiled and put in force, and its changes since
// the last poll get their lines, a pause or a resume once applied to the run's cgroup (livepause.go), a lift or a
// restore once the fence applied it. An unchanged overlay only has a pause or resume that failed tried again. Every
// poll then records the time limits that ended (expireLive).
func (r *runner) pollLiveBlocks(ctx context.Context, b *liveBlocks) {
	now := liveNow()
	defer func() {
		r.expireLive(ctx, b, now)
		// A blocked or fence host whose lookup failed a minute ago, or whose addresses are their refresh age old
		// (refreshAge), is looked up here, on the poll tick, after every change the overlay brought (blocks, restores,
		// a pause) is in force: a run whose overlay never changes would otherwise refuse a failed host by its declared
		// name alone, and a moved one by stale addresses, for good, and a refresh run inside a store would hold that
		// store's restore and pause for the lookups.
		if b.refreshHosts(ctx, now) {
			b.store(ctx, true, now)
		}
	}()
	sig := liveblock.Stat(r.dir)
	if sig == b.sig && b.polled {
		r.retryPause(ctx)
		return
	}
	// The first poll always compiles, whatever the overlay's state, so an Adjustable run's fence refusals are in force
	// from its start.
	first := !b.polled
	b.polled = true
	o, err := liveblock.Read(r.dir, string(r.id))
	switch {
	case errors.Is(err, os.ErrNotExist):
		b.sig = sig
		r.overlayGone(ctx, b, now)
		b.last = nil
		b.store(ctx, false, now)
		return
	case err != nil:
		b.sig = sig
		r.log.Warn("live blocks: overlay unreadable; the blocks last read stay in force", "err", err)
		r.emitLiveGap(record.GapLiveBlockUnreadable, 0, nil)
		// On the first poll there is no Set yet: an overlay unreadable at the run's start stored none, and the run
		// started with every fence entry open (fail open). Apply is asked first, for its lines.
		if b.fence != nil && (b.fence.Apply(ctx, now, nil, true) || first) {
			b.store(ctx, true, now)
		}
		return
	}
	if replaced(b.last, o, b.serial) {
		// The overlay was removed and written again between two polls: the file now read is a new one.
		r.overlayGone(ctx, b, now)
	}
	b.last = o
	b.pin(now)
	b.store(ctx, false, now)
	b.sig = sig
	changes, lost := o.Since(b.serial)
	if lost > 0 {
		r.emitLiveGap(record.GapLiveBlockLost, int(lost), nil)
		// Blocks are state (the file lists them), but a lift's end is a change: a restore trimmed from the file never
		// reaches the fence, and its lift would stay in force. Lost changes therefore drop every lift, as an
		// unreadable overlay does (fail closed), before the changes that survived are applied.
		if b.fence != nil && b.fence.Apply(ctx, now, nil, true) {
			b.store(ctx, true, now)
		}
	}
	var fence []liveblock.Change
	for _, c := range changes {
		switch {
		case c.Control():
			r.applyControl(ctx, c)
			continue
		case c.Fence():
			fence = append(fence, c)
			continue
		}
		why := record.GapLiveBlockAdded
		if c.Op == liveblock.OpRemove {
			why = record.GapLiveBlockRemoved
		}
		r.emitLiveGap(why, 0, &record.LiveBlockChange{Op: c.Op, Kind: string(c.Kind), Value: c.Value, Rule: c.Rule(),
			By: c.By, Serial: c.Serial, At: c.At, Until: c.Until})
	}
	// The fence's lines are queued before a loosened set is stored (ADR 0125 decision 5): Apply writes them, and only
	// then is the set compiled with its new refusals.
	switch {
	case len(fence) == 0:
	case b.fence == nil:
		// A Locked run has no fence: a lift loosens nothing, and a restore narrows nothing there is to narrow.
		for _, c := range fence {
			if c.Op == liveblock.OpLift {
				r.emitLiveGap(record.GapLiveLiftRefused, 0, &record.LiveBlockChange{Op: record.LiveOpLift, Kind: string(c.Kind),
					Value: c.Value, Rule: liveblock.LiftRule(c.Kind, c.Value), By: c.By, Serial: c.Serial, At: c.At, Until: c.Until,
					Refused: record.LiveRefusedLocked})
			}
		}
	default:
		fence = slices.DeleteFunc(fence, func(c liveblock.Change) bool {
			if c.Op != liveblock.OpLift || b.useLift(c.MAC) {
				return false
			}
			r.emitLiveGap(record.GapLiveLiftRefused, 0, &record.LiveBlockChange{Op: record.LiveOpLift, Kind: string(c.Kind),
				Value: c.Value, Rule: b.fence.RefusedRule(c.Kind, c.Value), By: c.By, Serial: c.Serial, At: c.At, Until: c.Until,
				Refused: record.LiveRefusedMAC})
			return true
		})
		if len(fence) > 0 && b.fence.Apply(ctx, now, fence, false) {
			b.store(ctx, true, now)
		}
	}
	r.wantPaused(ctx, o.Paused, o.Serial)
	b.serial = o.Serial
}

// maxUsedLifts bounds the lift MACs a run remembers (liveBlocks.used); past it every further lift is refused, since
// the launcher could no longer tell it from a replay (fail closed).
const maxUsedLifts = 1 << 14

// useLift reports whether a lift with this MAC may reach the fence, and remembers it: false for a MAC already handed
// to the fence this run (a replay) and, past maxUsedLifts, for every new one.
func (b *liveBlocks) useLift(mac string) bool {
	if b.used[mac] || len(b.used) >= maxUsedLifts {
		return false
	}
	if b.used == nil {
		b.used = map[string]bool{}
	}
	b.used[mac] = true
	return true
}

// replaced reports whether o is not the overlay last read (last, whose changes the ledger has lines for up to serial)
// carried on but a new file written after a removal: its serial went down, or the change it lists at serial is not
// the one last listed there. A new file that trimmed that change away is caught by the changes it lost (Since).
func replaced(last, o *liveblock.Overlay, serial uint64) bool {
	if o.Serial < serial {
		return true
	}
	if last == nil || serial == 0 {
		return false
	}
	was, ok1 := changeAt(last, serial)
	now, ok2 := changeAt(o, serial)
	return ok1 && ok2 && !sameChange(was, now)
}

// changeAt is the change o lists at serial.
func changeAt(o *liveblock.Overlay, serial uint64) (liveblock.Change, bool) {
	i := slices.IndexFunc(o.Changes, func(c liveblock.Change) bool { return c.Serial == serial })
	if i < 0 {
		return liveblock.Change{}, false
	}
	return o.Changes[i], true
}

// sameChange reports whether a and b are one change, read from two states of one file.
func sameChange(a, b liveblock.Change) bool {
	return a.Serial == b.Serial && a.Op == b.Op && a.Kind == b.Kind && a.Value == b.Value && a.By == b.By &&
		a.MAC == b.MAC && a.At.Equal(b.At) && a.Until.Equal(b.Until)
}

// overlayGone handles an overlay that is no longer the one the launcher followed: removed, or removed and written
// again with a lower serial. Its blocks are no longer asked for, but no remove was recorded, so a run that had blocks
// gets one gap live-block-unreadable; an Adjustable run's fence drops every lift (fail closed); and the next file's
// changes, which start again at serial 1, get their lines (serial back to 0). A lift copied from the old file is still
// refused as a replay (used).
func (r *runner) overlayGone(ctx context.Context, b *liveBlocks, now liveblock.Clock) {
	if b.last != nil && len(b.last.Blocks) > 0 {
		r.emitLiveGap(record.GapLiveBlockUnreadable, 0, nil)
	}
	if b.fence != nil && b.last != nil {
		b.fence.Apply(ctx, now, nil, true)
	}
	b.serial = 0
}

// pin makes the BOOTTIME pin of every until and from of the last overlay's blocks that has none yet.
func (b *liveBlocks) pin(now liveblock.Clock) {
	if b.last == nil {
		return
	}
	for _, e := range b.last.Blocks {
		for _, t := range [...]time.Time{e.Until, e.From} {
			if t.IsZero() {
				continue
			}
			if b.pins == nil {
				b.pins = map[string]time.Duration{}
			}
			k := liveblock.DeadlineKey(e.Key(), t)
			if _, ok := b.pins[k]; !ok {
				b.pins[k] = now.Pin(t)
			}
		}
	}
}

// store compiles the last overlay's blocks and the fence's refusals and puts them in force by one atomic store. With
// reuse it keeps what the last compile resolved and resolves only entries it does not hold; without, every host and
// program of the overlay's blocks is resolved again, as each new overlay state always was. A fence refusal's host and
// program are resolved once, at the first store that holds them, and kept for the run in fenceHosts and fenceFiles,
// through every lift and restore: a fence entry is the contract's, fixed for the run, and looking every net fence host
// up again on each overlay change delayed each block by up to liveLookupWait per host, as a restore's lookup delayed
// the refusal by address it restores. A fence host whose lookup failed is tried again on the poll tick
// liveLookupRetry later at the soonest; until then it is refused by its declared host alone. A block's host is held in
// blockHosts while a block names it, and the Set refuses it by every address a lookup of it answered meanwhile, beside
// what the last store's lookup answered (refusing): a lookup that fails or answers other addresses, at a new state
// or on the tick, drops none. Every held host is also looked up again on the poll tick once its addresses are its
// refreshAge old, or liveLookupRetry after a failed lookup (refreshHosts), outside every store, so a store an overlay
// change makes never waits for that refresh.
//
// When anything is to be looked up, the Set compiled with what is already known goes in force first: a new block, or
// a refusal that comes back, then refuses at once by its text and by any address already known for its host, not
// only after the lookups. Every resolution that Set holds is one the last compile made, so it refuses at least what
// the last Set refused for every entry both hold.
//
// A block whose until has Ended at now is left out. The Set already stops matching it at that instant, but its Has*
// are structural: kept in, an ended block would go on refusing what the supervisor could not walk (an exec whose
// path walk failed, an unwalked path) and keep the kernel exec handoff off for the rest of the run, since the file
// drops it only at a write more than 24 h later (liveblock.Update). A dormant block (From set) stays: it refuses again.
func (b *liveBlocks) store(ctx context.Context, reuse bool, now liveblock.Clock) {
	var entries []liveblock.Entry
	var serial uint64
	if b.last != nil {
		serial = b.last.Serial
		for _, e := range b.last.Blocks {
			if !e.Until.IsZero() {
				pin, ok := b.pins[liveblock.DeadlineKey(e.Key(), e.Until)]
				if liveblock.Ended(e.Until, pin, ok, now) {
					continue
				}
			}
			entries = append(entries, e)
		}
	}
	boot := maps.Clone(b.pins)
	if b.fence != nil {
		entries = append(entries, b.fence.Refusals()...)
		if p := b.fence.Pins(); len(p) > 0 {
			if boot == nil {
				boot = map[string]time.Duration{}
			}
			maps.Copy(boot, p)
		}
	}
	b.holdBlocked(entries)
	put := func(res liveblock.Resolved) {
		res = b.refusing(res)
		res.Boot = boot
		b.set.Store(liveblock.CompileEntries(entries, serial, res))
	}
	// keep is what is not resolved again: the fence's resolutions, and with reuse the last compile's too. It is a copy,
	// so keepFound can tell a host this store looked up from one it carried.
	fenced := liveblock.Resolved{Addrs: maps.Clone(b.fenceHosts.addrs), Files: maps.Clone(b.fenceFiles)}
	keep := fenced
	if reuse {
		keep = mergeResolved(b.res, fenced)
	}
	known, _, _ := resolveLiveBlocks(ctx, entries, mergeResolved(b.res, fenced), false)
	_, pending, _ := resolveLiveBlocks(ctx, entries, keep, false)
	put(known)
	res := known
	if pending {
		var failed []string
		res, _, failed = resolveLiveBlocks(ctx, entries, keep, true)
		b.keepFound(entries, keep, res, failed, liveNow()) // stamped after the lookups, as refreshHosts stamps
	}
	b.res = res
	if pending {
		put(res)
	}
}

// holdBlocked notes the hosts entries' blocks name (blocked) and drops from blockHosts every host no block names any
// more, or that a fence refusal names: a host is held, and looked up again, only while a block names it.
func (b *liveBlocks) holdBlocked(entries []liveblock.Entry) {
	b.blocked = map[string]bool{}
	for _, e := range entries {
		if host, ok := liveHost(e); ok && !e.Fence {
			b.blocked[host] = true
		}
	}
	for host := range b.blockHosts.addrs {
		if _, fenced := b.fenceHosts.addrs[host]; fenced || !b.blocked[host] {
			b.blockHosts.drop(host)
		}
	}
}

// refusing is res with each host blockHosts holds refused by every address held for it as well as by the ones res
// holds, what the last store's lookup of the host answered: the Set refused a blocked host by that answer alone before
// its addresses were kept, and still does, whatever the cap on blockHosts drops.
func (b *liveBlocks) refusing(res liveblock.Resolved) liveblock.Resolved {
	if len(b.blockHosts.addrs) == 0 {
		return res
	}
	addrs := make(map[string][]netip.Addr, len(res.Addrs)+len(b.blockHosts.addrs))
	maps.Copy(addrs, res.Addrs)
	for host, held := range b.blockHosts.addrs {
		if len(held) > 0 {
			addrs[host] = unionAddrs(addrs[host], held)
		}
	}
	res.Addrs = addrs
	return res
}

// unionAddrs is every address of a and of b, unmapped, sorted, once each.
func unionAddrs(a, b []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(a)+len(b))
	for _, x := range slices.Concat(a, b) {
		out = append(out, x.Unmap())
	}
	slices.SortFunc(out, func(x, y netip.Addr) int { return x.Compare(y) })
	return slices.Compact(out)
}

// liveLookupRetry is how long a host whose lookup failed waits before it is looked up again (hostBook.failed).
const liveLookupRetry = time.Minute

// liveRefreshAge is how old a fence host's addresses get before they are looked up again (hostBook.at): long enough
// that a resolver is asked a few times an hour per host, short enough that a host that moved is refused at its new
// addresses within minutes, not after the run. A connect the contract admits under a fence entry's host is refused by
// that declared host too (supervisor.liveNet).
const liveRefreshAge = 5 * time.Minute

// liveBlockRefreshAge is how old the addresses of a host a block names get before it is looked up again: as often as
// the run's DNS set looks a contract's host entry up again (agent.DefaultDNSTTL, which dns.DefaultMinTTL floors),
// since the standard resolver does not report a record's own TTL. Under a contract with no net: section nothing admits
// a connect under a host's name, so a host block refuses by these addresses alone: one its host moved to since the
// last lookup passes the block until a lookup answers it.
const liveBlockRefreshAge = max(agent.DefaultDNSTTL, dns.DefaultMinTTL)

// refreshAge is how old host's addresses get before it is looked up again: liveBlockRefreshAge while a block names
// it, liveRefreshAge for a fence host no block names.
func (b *liveBlocks) refreshAge(host string) time.Duration {
	if b.blocked[host] {
		return liveBlockRefreshAge
	}
	return liveRefreshAge
}

// liveLookupParallel bounds how many hosts one refresh looks up at once.
const liveLookupParallel = 16

// maxHostAddrs bounds the addresses a host is held with (hostBook.seen): past it the address answered longest ago is
// dropped, so a host that answers a new address on every lookup cannot grow the Set without end.
const maxHostAddrs = 64

// hostBook is what the launcher holds of a set of hosts between their lookups: every address each host's lookups
// answered, when they were last found and when a lookup last failed, on CLOCK_BOOTTIME, which a wall-clock step does
// not move. A lookup that succeeds adds what it answered to every address the host answered before (see): nothing is
// dropped below maxHostAddrs. One that fails or answers no address changes nothing (never loosen on a failed lookup)
// and is stamped in failed, so the host is tried again liveLookupRetry later, not on every poll.
type hostBook struct {
	// addrs is what a Set refuses each host by: every address in seen, sorted. A host whose every lookup failed is held
	// with none, refused by its declared host alone, until a lookup finds some.
	addrs map[string][]netip.Addr
	// seen is every address each host's lookups answered, the one last answered last, at most maxHostAddrs per host:
	// addrs holds all of them, so a refresh only adds refusals until that cap.
	seen map[string][]netip.Addr
	// at is when each host's addresses were last found, failed when its last lookup failed, if it did.
	at, failed map[string]time.Duration
}

// due is every host h holds that is due a lookup at now, sorted: one whose last lookup failed at least liveLookupRetry
// ago, or one whose addresses were found at least age(host) ago. A host held with neither stamp is due (never the
// case: found and fail stamp every host they hold).
func (h *hostBook) due(now liveblock.Clock, age func(host string) time.Duration) []string {
	var out []string
	for host := range h.addrs {
		if at, failed := h.failed[host]; failed {
			if now.Boot-at >= liveLookupRetry {
				out = append(out, host)
			}
			continue
		}
		if at, ok := h.at[host]; !ok || now.Boot-at >= age(host) {
			out = append(out, host)
		}
	}
	slices.Sort(out)
	return out
}

// found records a lookup of host at at that answered addrs, an answer with no address as a failure, and reports
// whether the host's addresses changed.
func (h *hostBook) found(host string, addrs []netip.Addr, at time.Duration) bool {
	if len(addrs) == 0 {
		h.fail(host, at)
		return false
	}
	if h.at == nil {
		h.at = map[string]time.Duration{}
	}
	delete(h.failed, host)
	h.at[host] = at
	return h.see(host, addrs)
}

// fail records a lookup of host at at that failed: a host not held yet is held with no addresses, one held keeps
// every address it has.
func (h *hostBook) fail(host string, at time.Duration) {
	if h.addrs == nil {
		h.addrs = map[string][]netip.Addr{}
	}
	if _, held := h.addrs[host]; !held {
		h.addrs[host] = nil
	}
	if h.failed == nil {
		h.failed = map[string]time.Duration{}
	}
	h.failed[host] = at
}

// drop forgets host and every address held for it.
func (h *hostBook) drop(host string) {
	delete(h.addrs, host)
	delete(h.seen, host)
	delete(h.at, host)
	delete(h.failed, host)
}

// answer records what lookupAll answered for hosts at at (a host it has no answer for failed), and reports whether
// any host's addresses changed.
func (h *hostBook) answer(hosts []string, answers map[string][]netip.Addr, at time.Duration) bool {
	changed := false
	for _, host := range hosts {
		if h.found(host, answers[host], at) {
			changed = true
		}
	}
	return changed
}

// refreshHosts looks up every fence and blocked host that is due (hostBook.due, by refreshAge) with one lookupAll, so a
// refresh holds the poll for liveLookupWait at most however many hosts are due and however the resolver behaves, and
// reports whether any host's addresses changed. A lookup still running at the deadline is a failed one. Every stamp is
// the clock read after the lookups, so a slow refresh does not leave its hosts due again at once.
func (b *liveBlocks) refreshHosts(ctx context.Context, now liveblock.Clock) bool {
	fence, blocked := b.fenceHosts.due(now, b.refreshAge), b.blockHosts.due(now, b.refreshAge)
	if len(fence)+len(blocked) == 0 {
		return false
	}
	answers := lookupAll(ctx, slices.Concat(fence, blocked))
	at := liveNow().Boot
	fenceChanged := b.fenceHosts.answer(fence, answers, at)
	blockChanged := b.blockHosts.answer(blocked, answers, at)
	return fenceChanged || blockChanged
}

// lookupAll looks hosts up, at most liveLookupParallel at once, all under one liveLookupWait deadline, and is the
// answer of each host whose lookup succeeded by then. It returns at the deadline whatever liveLookup does: a lookup
// still running then ends on its own and writes into a buffer no one reads.
func lookupAll(ctx context.Context, hosts []string) map[string][]netip.Addr {
	lctx, cancel := context.WithTimeout(ctx, liveLookupWait)
	defer cancel()
	type answer struct {
		host  string
		addrs []netip.Addr
		err   error
	}
	out := make(chan answer, len(hosts)) // buffered: a lookup that outlives the deadline never blocks its goroutine
	sem := make(chan struct{}, liveLookupParallel)
	for _, host := range hosts {
		go func() {
			select {
			case sem <- struct{}{}:
			case <-lctx.Done():
				out <- answer{host: host, err: lctx.Err()}
				return
			}
			defer func() { <-sem }()
			addrs, err := liveLookup(lctx, host)
			out <- answer{host: host, addrs: addrs, err: err}
		}()
	}
	got := map[string][]netip.Addr{}
	for range hosts {
		select {
		case a := <-out:
			if a.err == nil {
				got[a.host] = a.addrs
			}
		case <-lctx.Done():
			return got
		}
	}
	return got
}

// see adds addrs to what host has answered (seen), each address unmapped and moved to the end as the one answered
// last, drops the ones answered longest ago past maxHostAddrs, and sets the host's addresses to all of them, sorted; it
// reports whether those changed.
func (h *hostBook) see(host string, addrs []netip.Addr) bool {
	if h.seen == nil {
		h.seen = map[string][]netip.Addr{}
	}
	if h.addrs == nil {
		h.addrs = map[string][]netip.Addr{}
	}
	seen := h.seen[host]
	for _, a := range addrs {
		a = a.Unmap()
		seen = slices.DeleteFunc(seen, func(x netip.Addr) bool { return x == a })
		seen = append(seen, a)
	}
	if over := len(seen) - maxHostAddrs; over > 0 {
		seen = slices.Delete(seen, 0, over)
	}
	h.seen[host] = seen
	sorted := slices.Clone(seen)
	slices.SortFunc(sorted, func(x, y netip.Addr) int { return x.Compare(y) })
	if old, held := h.addrs[host]; held && slices.Equal(sorted, old) {
		return false
	}
	h.addrs[host] = sorted
	return true
}

// keepFound records what a store's lookups found for entries (res) and which hosts' lookups failed, each stamped now:
// each fence refusal's program in fenceFiles and host in fenceHosts, then each block's host in blockHosts, unless
// fenceHosts holds it. A host keep held was carried, not looked up, and is left to refreshHosts. A fence host whose
// lookup failed is held in res too, with no addresses, so no store looks it up again before refreshHosts does; a
// block's is not, so the next store looks it up again, as it always did.
func (b *liveBlocks) keepFound(entries []liveblock.Entry, keep, res liveblock.Resolved, failed []string, now liveblock.Clock) {
	// lookupFailed records into book what this store's lookup of host gave, if the store made one, and reports whether
	// that lookup failed.
	lookupFailed := func(book *hostBook, host string) bool {
		if _, carried := keep.Addrs[host]; carried {
			return false
		}
		switch addrs, found := res.Addrs[host]; {
		case found:
			book.found(host, addrs, now.Boot)
		case slices.Contains(failed, host):
			book.fail(host, now.Boot)
			return true
		}
		return false
	}
	for _, e := range entries {
		if !e.Fence {
			continue
		}
		if id, ok := res.Files[e.Value]; ok && e.Kind == liveblock.KindExec {
			if b.fenceFiles == nil {
				b.fenceFiles = map[string]liveblock.FileID{}
			}
			b.fenceFiles[e.Value] = id
		}
		if host, ok := liveHost(e); ok && lookupFailed(&b.fenceHosts, host) {
			res.Addrs[host] = nil
		}
	}
	for _, e := range entries {
		if host, ok := liveHost(e); ok && !e.Fence {
			if _, fenced := b.fenceHosts.addrs[host]; !fenced {
				lookupFailed(&b.blockHosts, host)
			}
		}
	}
}

// mergeResolved is a's resolutions and b's, b's where both hold one.
func mergeResolved(a, b liveblock.Resolved) liveblock.Resolved {
	out := liveblock.Resolved{Addrs: map[string][]netip.Addr{}, Files: map[string]liveblock.FileID{}}
	maps.Copy(out.Addrs, a.Addrs)
	maps.Copy(out.Addrs, b.Addrs)
	maps.Copy(out.Files, a.Files)
	maps.Copy(out.Files, b.Files)
	return out
}

// expireLive writes the line of every time limit of the last overlay's blocks that ended by now, once each: a gap
// live-block-expired for a block whose until has Ended (both clocks passed it), and live-unblock-expired for a
// dormant block whose from has Begun (either clock reached it). The Set already stopped, or started, refusing at the
// instant; this is its record. A block that ended is then compiled out of the Set (store). It then lets the fence end
// lifts whose limit passed, and puts its new refusals in force.
func (r *runner) expireLive(ctx context.Context, b *liveBlocks, now liveblock.Clock) {
	ended := false
	if b.last != nil {
		for _, e := range b.last.Blocks {
			if !e.Until.IsZero() {
				k := liveblock.DeadlineKey(e.Key(), e.Until)
				pin, ok := b.pins[k]
				if !b.done[k] && liveblock.Ended(e.Until, pin, ok, now) {
					r.emitExpiry(b, record.GapLiveBlockExpired, e, liveblock.OpAdd, e.Until, now)
					ended = true
				}
			}
			if !e.From.IsZero() {
				k := liveblock.DeadlineKey(e.Key(), e.From)
				pin, ok := b.pins[k]
				if !b.done[k] && liveblock.Begun(e.From, pin, ok, now) {
					r.emitExpiry(b, record.GapLiveUnblockExpired, e, liveblock.OpRemove, e.From, now)
				}
			}
		}
	}
	ticked := b.fence != nil && b.fence.Tick(ctx, now)
	if ended || ticked {
		b.store(ctx, true, now)
	}
}

// emitExpiry writes one expiry line of block e, whose limit until was set by its last change of op (its add, or the
// remove that made it dormant): that change's by and serial, or e's by and the overlay's serial when the overlay no
// longer lists it, and the instant now.
func (r *runner) emitExpiry(b *liveBlocks, why string, e liveblock.Entry, op string, until time.Time, now liveblock.Clock) {
	if b.done == nil {
		b.done = map[string]bool{}
	}
	b.done[liveblock.DeadlineKey(e.Key(), until)] = true
	by, serial := e.By, b.last.Serial
	for i := len(b.last.Changes) - 1; i >= 0; i-- {
		if c := b.last.Changes[i]; c.Op == op && c.Kind == e.Kind && c.Value == e.Value {
			by, serial = c.By, c.Serial
			break
		}
	}
	r.emitLiveGap(why, 0, &record.LiveBlockChange{Op: record.LiveOpExpire, Kind: string(e.Kind), Value: e.Value,
		Rule: liveblock.Rule(e.Kind, e.Value), By: by, Serial: serial, At: now.Wall.UTC().Round(time.Millisecond), Until: until})
}

// emitLiveGap queues one gap what=enforce line about the run's live blocks.
func (r *runner) emitLiveGap(why string, count int, c *record.LiveBlockChange) {
	ev := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor}
	if err := ev.SetPayload(record.GapPayload{What: record.GapEnforce, Why: why, Count: count, LiveBlock: c}); err != nil {
		return
	}
	if r.queue != nil {
		r.queue.Emit(ev)
	}
}

// liveLookupWait bounds the lookup of one blocked host.
const liveLookupWait = 2 * time.Second

// liveLookup looks one blocked host up; replaced in tests.
var liveLookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// resolveLiveBlocks is what entries name beyond their text: each blocked host's addresses (a host the lookup fails
// for is still matched by the declared host an entry admitted it under) and each blocked absolute program's identity.
// What prev already holds is kept and not looked up again (a host prev holds with no addresses included). With lookup
// false nothing is looked up: the result holds only what prev held, and pending reports whether some entry would be
// looked up. failed are the hosts whose lookup failed.
func resolveLiveBlocks(ctx context.Context, entries []liveblock.Entry, prev liveblock.Resolved, lookup bool) (res liveblock.Resolved, pending bool, failed []string) {
	res = liveblock.Resolved{Addrs: map[string][]netip.Addr{}, Files: map[string]liveblock.FileID{}}
	for _, e := range entries {
		switch e.Kind {
		case liveblock.KindExec:
			if strings.HasPrefix(e.Value, "/") && !strings.HasSuffix(e.Value, "/") {
				if id, ok := prev.Files[e.Value]; ok {
					res.Files[e.Value] = id
					continue
				}
				pending = true
				if !lookup {
					continue
				}
				var st unix.Stat_t
				if unix.Stat(e.Value, &st) == nil {
					res.Files[e.Value] = liveblock.FileID{Dev: st.Dev, Ino: st.Ino}
				}
			}
		case liveblock.KindNet:
			host, ok := liveHost(e)
			if !ok {
				continue
			}
			if addrs, ok := prev.Addrs[host]; ok {
				res.Addrs[host] = addrs
				continue
			}
			pending = true
			if !lookup {
				continue
			}
			if _, done := res.Addrs[host]; done || slices.Contains(failed, host) {
				continue // two entries of one host: looked up once
			}
			lctx, cancel := context.WithTimeout(ctx, liveLookupWait)
			addrs, err := liveLookup(lctx, host)
			cancel()
			if err != nil {
				failed = append(failed, host)
				continue
			}
			res.Addrs[host] = addrs
		}
	}
	return res, pending, failed
}

// liveHost is the host name a net entry names, if it names one: not an address, a unix socket or an abstract name.
func liveHost(e liveblock.Entry) (string, bool) {
	if e.Kind != liveblock.KindNet {
		return "", false
	}
	host := e.Value
	if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.Contains(host, "]") {
		host = host[:i]
	}
	if host == "" || strings.HasPrefix(host, "/") || strings.HasPrefix(host, "@") || strings.HasPrefix(host, "[") {
		return "", false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return "", false
	}
	return host, true
}
