// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/startphase"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// attachKernel is Prepare's fifth step: load and pin the objects, write the run's verdict rows and place its
// rings. The run's run-set row is not written here but by Arm, after the child stage's execve (ADR 0021 (2)).
//
// Every piece registers its undo as it succeeds, so a failure in the middle leaves the kernel exactly as it
// was: no half-populated map, no orphaned pin, no row pointing at a slot that is about to be freed (§8 I10).
func (h *Handle) attachKernel(ctx context.Context) error {
	newKernel := h.opts.newKernel
	if newKernel == nil {
		newKernel = newBPFKernel
	}
	// The undo is registered for whatever came back, before the error is looked at. A load that failed
	// half way — the second object rejected by the verifier, a tracepoint missing from this kernel's BTF —
	// has already pinned the first object's maps and programs and attached and pinned some of the shared
	// links, and a pinned link stays attached host-wide after the fd that made it is gone. Closing the
	// value would leave every one of those behind, which is the "abort Prepare, no partial pins" of §7 and
	// the "no leaked pin" of §8 I10; only releaseKernel asks the build lock the last-out question that
	// decides whether they may be removed. newKernel therefore returns the partially built value alongside
	// its error (kernel.go).
	k, err := newKernel(ctx, h)
	if k != nil {
		h.undo(func() error { return h.releaseKernel(k) })
	}
	if err != nil {
		return err
	}
	h.kern = k

	// A slot is reclaimed from a launcher that died without a Detach (slots.go), and the verdict maps are
	// pinned, so that launcher's rows can still be sitting under this run's run_idx. They go before this
	// run's own rows do, or the new run silently inherits a dead run's destinations (§5 R12, §8 I5).
	if err := k.purgeSlot(h.slot); err != nil {
		return err
	}
	// The slot's plane row maps, made once per slot and kept (plane.go); the rows are written at the end of
	// Prepare, from the inherited plan's descriptors (fillPlane).
	if err := h.preparePlaneSlot(k); err != nil {
		return err
	}
	// Registered before the write, not after it. populate walks the rows one bpf(2) call at a time and stops
	// at the first refusal, so the ordinary failure — ErrMapFull, the 4096-row budget of §7 — leaves every
	// row it had already written in a map that is pinned and outlives this launcher. An undo registered
	// afterwards never runs for the step that made the mess, and releaseSlot then hands the index on because
	// rowsLeft only knows about removals that failed, not about rows that were never offered for removal.
	// Deleting a key that was never written is not an error (removeRules, §8 I10), so covering the partial
	// write costs nothing and closes §5 R12 here rather than leaving it to the next run's purgeSlot — which
	// would hold up to 4096 dead rows against every *other* run's budget until that one slot is reused.
	h.undo(h.removeRules)
	if err := k.populate(h.rules); err != nil {
		return err
	}
	// The run's rings go in before its run-set row: a program that finds the row and no ring counts a miss and
	// emits nothing, so with the row first the run's first samples would be lost (ADR 0026 (1)). A placement
	// that failed half way needs no undo: a ring it left at the slot is the slot's, as one a run leaves is, for
	// the slot's next run to reuse (ADR 0026 (6) as amended). Above the pool the slot's own undo
	// (releaseSlotAndPark) has those rings trimmed, as Detach does.
	return h.placeRings()
}

// runRow is the run's run-set value: its slot, descendants=1, the tier, the record mode and the generation, and its
// flags. RunActivity is set exactly when the run's limits bound stall_after, in every record mode (limits R4): it is
// what has trace_proc stamp the run's allowed actions under record: off and the TLS probes its calls in every mode
// (tego_activity), which the run's watcher pulls once a tick; a run no stall check reads is never stamped.
func (h *Handle) runRow() ebpfbindings.Run {
	row := ebpfbindings.Run{
		RunIdx:      h.slot,
		Descendants: 1,
		Tier:        uint8(tierByte(h.opts.RunTier())),
		Record:      uint8(h.recordMode),
		Plane:       ebpfbindings.RunPlaneOf(h.planeMode),
		Gen:         h.gen,
	}
	if h.planeMode != "" && h.table != nil && h.table.Listen != nil {
		row.Flags |= ebpfbindings.RunListenerResults
	}
	if h.table != nil && h.table.Limits.Bounded(agent.BudgetStallAfter) {
		row.Flags |= ebpfbindings.RunActivity
	}
	return row
}

// Arm is ADR 0021 (2)'s one arming point, Prepare's sixth and seventh steps moved to after the child stage's
// execve: it inserts the run's cgroup into the run set with descendants=1, adopts the children that already
// exist (§5 R11), and marks the mounts the policy decides on, each for the permission events a rule there can
// refuse (§5 R8). The runtime calls it once the stage has reported on the control pipe, which the stage does
// only after its execve of this binary has returned, and before the ack, so the agent does not yet exist.
//
// Everything the run set and the marks key on therefore starts with the agent's own first execve: the stage's
// exec of tego is never a permission event of this group (no ignore mark, no admission by identity, no static
// binary needed: E39 closed by ordering), never a record of the run, and a deny_read over the tego binary is
// decided like any other file. The marks go on with this process armed (internal/platform/proc.Arm, taken by
// the listener before its first mark and released once the last is gone), so it starts no process while they
// exist (ADR 0021 (3)).
//
// A failure leaves what was placed for Detach to remove, as any other failure after Prepare does. Arm is not
// idempotent: a second call is refused.
func (h *Handle) Arm() error {
	defer startphase.Begin(h.opts.Phase, "arm")()
	h.netMu.Lock()
	defer h.netMu.Unlock()
	if !h.prepared || h.detached || h.kern == nil {
		return ErrNotPrepared
	}
	if h.armed {
		return fmt.Errorf("%w: run %s is already armed", ErrNotPrepared, h.run.ID)
	}
	h.armed = true
	val := h.runRow()
	if err := h.addCgroup(h.run.CgroupID, val); err != nil {
		return err
	}
	if err := h.adoptExisting(val); err != nil {
		return err
	}
	if h.fan == nil {
		return nil
	}
	// Each mount is marked for the events this listener can refuse there, never more (policy.masks, §5 R8): an
	// event nothing can refuse costs its opener a round trip through this process and changes no verdict.
	for _, m := range h.policy.mounts {
		if err := h.fan.markFor(m, h.policy.masks[m]); err != nil {
			return err
		}
	}
	return nil
}

// removeRules deletes this run's verdict rows and remembers a failure. A row that is still in a pinned map
// still references this run's run_idx, so the slot must not be handed on while one is left: releaseSlot
// reads rowsLeft and refuses, which is the fail-closed half of §5 R12 and §8 I5.
func (h *Handle) removeRules() error {
	if err := h.kern.removeRules(h.rules); err != nil {
		h.rowsLeft = true
		return err
	}
	// One-shot approvals exist even when the contract requests no packet or
	// listener controls; teardown must remove those rows too.
	if k, ok := h.kern.(*bpfKernel); ok {
		if err := k.purgeApprovals(h.slot); err != nil {
			h.rowsLeft = true
			return err
		}
	}
	return nil
}

// removeRun deletes one cgroup's run-set row and breadcrumb, and remembers a failure for the same reason
// removeRules does: a surviving run-set row carries this run's run_idx in its value (§5 R12, §8 I5).
func (h *Handle) removeRun(id uint64) error {
	if err := h.kern.removeRun(id); err != nil {
		h.rowsLeft = true
		return err
	}
	return nil
}

// releaseKernel is the load step's undo. Closing the handles is not enough on this path: a pinned link stays
// attached host-wide after the fd that made it is gone, and a pinned map keeps its memory, so a Prepare that
// failed at a later step would leave the whole build attached with nobody draining the ring buffer — the
// "no partial pins" of §7 and the "no leaked pin" of §8 I10. So this asks the build lock the question Detach
// asks, and unpins first when this launcher is the only one holding the build (§5 R14). Unpinning has to
// precede close: unpin works through the map, program and link handles close releases.
func (h *Handle) releaseKernel(k kernel) error {
	var errs []error
	if err := h.leaveBuild(k); err != nil {
		errs = append(errs, err)
	}
	if err := k.close(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// addCgroup inserts one cgroup into the run set and remembers it, so teardown removes exactly the rows this
// run created and never scans the whole map (§4).
func (h *Handle) addCgroup(id uint64, val ebpfbindings.Run) error {
	if id == 0 {
		return fmt.Errorf("%w: run %s has no cgroup id", ErrNotPrepared, h.run.ID)
	}
	if err := h.kern.insertRun(id, val); err != nil {
		return err
	}
	if h.cgroups == nil {
		h.cgroups = map[uint64]struct{}{}
	}
	if _, dup := h.cgroups[id]; !dup {
		h.cgroups[id] = struct{}{}
		h.undo(func() error { return h.removeRun(id) })
	}
	return nil
}

// adoptExisting closes the half of the descendant race that cgroup_mkdir cannot: a cgroup created inside the
// run's scope before the tracepoint was attached. It walks the run's own subtree once, which is the scope §5
// R11 gives P0 — cross-daemon lineage adoption is P2.
//
// A subtree that cannot be read refuses Arm, so the run fails before run_start: only a subtree or an entry that
// has vanished (ENOENT) is skipped. A descendant missed would lose its tracing and uprobe records, not its
// network enforcement, which the programs attached to the run's cgroup apply to the whole subtree (§6 E11).
func (h *Handle) adoptExisting(val ebpfbindings.Run) error {
	root := filepath.Join(h.run.mount(), h.run.CgroupPath)
	entries, err := readSubtree(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("cgroup: scan %s for existing descendants: %w", root, err)
	}
	for _, rel := range entries {
		id, err := cgroupIDOfPath(h.run.mount(), filepath.Join(h.run.CgroupPath, rel))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue // it was removed between the walk and the stat
			}
			return err
		}
		if err := h.addCgroup(id, val); err != nil {
			return err
		}
	}
	return nil
}

// readSubtree lists every directory beneath root, relative to it. cgroupfs has no symlinks and no files that
// are directories, so a plain recursive read is exact and bounded by the subtree's own depth.
func readSubtree(root string) ([]string, error) {
	var out []string
	var walk func(rel string) error
	walk = func(rel string) error {
		entries, err := os.ReadDir(filepath.Join(root, rel))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil // removed while walking
			}
			return err
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			child := filepath.Join(rel, e.Name())
			out = append(out, child)
			if err := walk(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk("."); err != nil {
		return nil, err
	}
	for i, p := range out {
		out[i] = filepath.Clean(p)
	}
	return out, nil
}

// startFanotify creates the permission group, with no mark: Arm marks the mounts the policy decides on, after
// the child stage's execve (ADR 0021 (2)). A contract that gives this listener nothing to refuse gets no group
// at all, which is why an unruled mount pays nothing (§5 R8).
//
// Once Arm has marked them, an open on a marked mount — by any process on the host, because a mark is
// mount-scoped, and on an ordinary single-root box the marked mount is "/" (§6 E34) — blocks until RunListener
// answers it. A caller therefore starts RunListener in the same errgroup as every other run worker, or calls
// Close; Close releases every blocked opener, because the kernel fails open when a permission group goes away.
//
// Marked at Prepare, as they were, the marks existed while the launcher started the child stage: Go's os/exec
// suspends the forking thread (CLONE_VFORK) until the child's execve is past its point of no return, holding
// its scheduler slot, and that execve opened the tego binary on a marked mount, a permission event only this
// process answers. A garbage collection that began in that window waited for the suspended thread, the thread
// for the exec, and the exec for RunListener: the launcher stopped for good, and every open on the marked
// mounts, host-wide, waited behind it (§6 E39). An ignore mark on the stage's binary and a static-only
// build kept that one file out of the group, and E39's cycle stayed open for a second tego build or another
// listener's opens. Arming after the exec, with no process start while any mark exists, closes it for all.
func (h *Handle) startFanotify() error {
	if len(h.policy.mounts) == 0 || h.planeMode != "" {
		return nil // a plane decides this run's opens and execs in the kernel: no group, no mark (enforce-plane R22)
	}
	newListener := h.opts.newListener
	if newListener == nil {
		newListener = func(h *Handle) (*fanotifyListener, error) {
			l, err := newFanotifyListener(h.policy, h.run, h.opts.Events, h.opts.FanotifyDeadline)
			if err != nil {
				return nil, err
			}
			l.now = h.opts.Now
			return l, nil
		}
	}
	l, err := newListener(h)
	if err != nil {
		return err
	}
	h.fan = l
	h.undo(func() error { return l.Close() })
	return nil
}

// Attach binds the run's cgroup to the eight network programs (six below 6.7, where connect_unix and
// sendmsg_unix are not loaded, §5 R7). It runs before the agent is created (docs/p0/runtime-launch.md §4.1: prepareEnforcement
// precedes the launcher's start), so no process of the run exists yet, and every process and descendant
// cgroup the run later has is covered by the attachment: the kernel runs a program attached to a cgroup for
// the sockets of that cgroup's whole subtree (§4, §5 R1, R2, R11).
//
// The cgroup id argument exists for the api.Handle contract; this backend attaches by path, because a
// bpf_link is created against a cgroup directory. A mismatch between the two is refused rather than
// silently attaching to the wrong cgroup.
//
// The attachment is told which run it enforces through the cgroup's tego_net_owners storage (§5 R1, R2),
// keyed by the id of the directory the links attach to. That id is read from the directory itself and must
// equal the run's, so the storage the programs read and the breadcrumb rows Detach removes name one cgroup.
//
// The storage also names this process's own cgroup, the relay's (relayCgroup): connect_unix admits the
// /proc/self/fd/<n> name the supervisor relays a resolved unix connect under from that cgroup only.
//
// A contract with no net: section gets no network program at all (RuleMaps.Unrestricted): SEMANTICS §1
// denies nothing there, and a deciding program would refuse every destination it has no row for, which is
// all of them, including every connect the supervisor admits and relays.
func (h *Handle) Attach(cgroupID uint64) error {
	h.netMu.Lock()
	defer h.netMu.Unlock()
	if !h.prepared || h.kern == nil {
		return ErrNotPrepared
	}
	if cgroupID != 0 && h.run.CgroupID != 0 && cgroupID != h.run.CgroupID {
		return fmt.Errorf("%w: asked to attach cgroup %d, prepared for %d", ErrNotPrepared, cgroupID, h.run.CgroupID)
	}
	path := filepath.Join(h.run.mount(), h.run.CgroupPath)
	id, err := cgroupIDOfPath(h.run.mount(), h.run.CgroupPath)
	if err != nil {
		return err
	}
	if id != h.run.CgroupID {
		return fmt.Errorf("%w: %s is cgroup %d, but the run was prepared for %d", ErrNotPrepared, path, id,
			h.run.CgroupID)
	}
	if h.rules.Unrestricted {
		return nil
	}
	relay, err := h.relayCgroup(id)
	if err != nil {
		return err
	}
	return h.kern.attachCgroup(path, ebpfbindings.NetOwner{CgroupID: id, RunIdx: h.slot, RelayCgroupID: relay,
		Flags: socketFlags(h.table), Gen: h.gen})
}

// socketFlags is the owner storage's NetOwner* bits for cgroup/sock_create (§5 R4): the ping-socket admission of
// the table's NetSocketPolicy, the predicate the seccomp filter's socket arm and the plane's slot header read too,
// so the three answer a ping socket alike. The owner's Gen is the run's, which the program stamps on its own
// refusal record (R5): it reads the attachment's storage, never the run set, whose row exists only from Arm.
func socketFlags(rt *agent.RuleTable) uint32 {
	if rt.Builtins != nil && rt.NetUnrestricted() {
		return netOwnerUnixOnly
	}
	if rt.NetSocketPolicy().ICMP {
		return ebpfbindings.NetOwnerICMP
	}
	return 0
}

// relayCgroup is the id of this process's own cgroup: the supervisor relays every unix connect of the agent
// from this process, on a thread of it (supervisor.md R11), and cgroup v2 keeps every thread of a process in
// one cgroup. It is read from /proc/self/cgroup under the run's own mount, the one the run's cgroup path is
// relative to. A cgroup that cannot be named, or that is the run's own (a launcher inside the cgroup it
// enforces, where the agent's processes would share it), refuses the attach rather than leave connect_unix
// unable to tell the relay from the agent (§5 R7).
func (h *Handle) relayCgroup(runID uint64) (uint64, error) {
	self := h.opts.selfCgroup
	if self == nil {
		self = func() (string, error) { return cgroupPathOfPID(os.Getpid()) }
	}
	rel, err := self()
	if err != nil {
		return 0, fmt.Errorf("%w: name this launcher's own cgroup, where relayed unix connects come from: %w",
			ErrNotPrepared, err)
	}
	id, err := cgroupIDOfPath(h.run.mount(), rel)
	if err != nil {
		return 0, fmt.Errorf("%w: this launcher's own cgroup %s: %w", ErrNotPrepared, rel, err)
	}
	if id == runID || inSubtree(h.run.CgroupPath, rel) {
		return 0, fmt.Errorf("%w: this launcher's cgroup %s is the run's own %s or beneath it; connect_unix "+
			"could not tell the supervisor's relayed connects from the agent's", ErrNotPrepared, rel, h.run.CgroupPath)
	}
	return id, nil
}

// RefreshNet rewrites this run's verdict rows for a refreshed table: the same net entries as the table Prepare
// compiled, with the addresses each host entry resolves to now. The supervisor re-resolves host entries on
// their TTL and matches against the new addresses (supervisor R8), and it relays each connect it allows on
// the agent's socket, which the run's connect4/6 decides as well (§5 R1, R5). Rows left at Prepare's
// addresses refuse, with EPERM, every connect to an address the host has rotated to since (§6 E7).
//
// Only a host entry's addresses may change. An entry whose shape differs (another count of entries, or another
// Raw, host, port, protocol, verdict, prefix, unix path or runtime grant) is refused, because a policy change
// mid-run is not a refresh and the kernel would enforce a table the supervisor does not. So is a new address
// for an entry no lookup re-resolves — a literal address (Static) or an entry with no host — since its
// addresses are the contract itself and the supervisor's set never moves them (internal/platform/dns). An
// entry the refresh gives no address keeps its previous ones, as the supervisor's set does with a failed
// lookup (supervisor R8a).
//
// The rows move without a gap for any address in both sets: rows whose key the refreshed table no longer
// produces are deleted, then every row it does produce is written, so an unchanged address's row is never
// absent. Until both steps succeed, the rows teardown removes cover both sets, so a refresh that fails part
// way leaves nothing Detach does not remove (§5 R12, §8 I5, I10). Safe to call concurrently with Detach;
// after Detach it returns ErrNotPrepared.
func (h *Handle) RefreshNet(rt *agent.RuleTable) error {
	h.netMu.Lock()
	defer h.netMu.Unlock()
	if !h.prepared || h.detached || h.kern == nil || h.table == nil {
		return ErrNotPrepared
	}
	if rt == nil {
		return ErrNoTable
	}
	net, err := refreshedNet(h.table.Net, rt.Net)
	if err != nil {
		return err
	}
	next := *h.table
	next.Net = net
	fresh, err := BuildRuleMaps(&next, h.slot, h.run.Resolvers, h.unixPlane())
	if err != nil {
		return err
	}
	if err := rebaseTimelines(&fresh, &h.timelineNext); err != nil {
		return err
	}
	control := h.rules.Control
	if control != nil {
		fresh.Rules = append(fresh.Rules, control.Rules...)
	}
	oldTimelines := h.rules.Timelines
	if h.rules.Unrestricted {
		h.table, h.rules = &next, fresh
		return nil // no program reads the rows of a run that has none (Attach)
	}
	stale := staleRows(h.rules, fresh)
	// Teardown removes h.rules; between here and the end it must name every row either set may have left.
	h.rules = unionRows(h.rules, fresh)
	if len(stale.Exact)+len(stale.CIDR) > 0 {
		if err := h.kern.removeRules(stale); err != nil {
			return err
		}
	}
	if err := h.kern.populate(fresh); err != nil {
		return err
	}
	// Verdict rows no longer reference the previous chain ids. Remove those
	// only after all replacements succeed, never overwrite a live chain.
	if len(oldTimelines) != 0 {
		if err := h.kern.removeRules(RuleMaps{Timelines: oldTimelines}); err != nil {
			return err
		}
	}
	fresh.Control = control
	h.table, h.rules = &next, fresh
	return nil
}

// refreshedNet checks that a refreshed net section is the prepared one with only its addresses changed, and
// returns it with R8a applied: an entry the refresh left without an address keeps the prepared addresses.
func refreshedNet(prepared, refreshed []agent.NetRule) ([]agent.NetRule, error) {
	if len(prepared) != len(refreshed) {
		return nil, fmt.Errorf("%w: a refresh has %d net entries, the prepared table %d", ErrRefreshShape,
			len(refreshed), len(prepared))
	}
	out := make([]agent.NetRule, len(refreshed))
	for i := range refreshed {
		p, r := prepared[i], refreshed[i]
		if !sameEntry(p, r) {
			return nil, fmt.Errorf("%w: entry %d is %q, prepared as %q", ErrRefreshShape, i, r.Raw, p.Raw)
		}
		if len(r.IPs) == 0 {
			r.IPs = p.IPs
		}
		if (p.Static || p.Host == "") && !p.ExpiresAt.Equal(r.ExpiresAt) {
			return nil, fmt.Errorf("%w: static entry %d expiry changed", ErrRefreshShape, i)
		}
		if (p.Static || p.Host == "") && !sameAddrs(p.IPs, r.IPs) {
			return nil, fmt.Errorf("%w: entry %d (%q) is no host a lookup re-resolves, and its addresses changed",
				ErrRefreshShape, i, p.Raw)
		}
		out[i] = r
	}
	return out, nil
}

// sameEntry compares everything about two entries but what a TTL refresh changes (IPs, ResolvedAt, TTL) and
// the source position, which names where it was declared rather than what it admits.
func sameEntry(a, b agent.NetRule) bool {
	if (a.CIDR == nil) != (b.CIDR == nil) || (a.CIDR != nil && *a.CIDR != *b.CIDR) {
		return false
	}
	return a.Raw == b.Raw && a.Host == b.Host && a.Port == b.Port && a.Proto == b.Proto &&
		a.Verdict == b.Verdict && a.UnixPath == b.UnixPath && a.Abstract == b.Abstract &&
		a.Static == b.Static && a.Runtime == b.Runtime
}

// sameAddrs reports whether two address lists name the same set, compared the way the rows are keyed (an
// IPv4 address and its v4-mapped form are one destination) and in any order.
func sameAddrs(a, b []netip.Addr) bool {
	set := func(in []netip.Addr) map[netip.Addr]bool {
		out := make(map[netip.Addr]bool, len(in))
		for _, x := range in {
			out[x.Unmap().WithZone("")] = true
		}
		return out
	}
	sa, sb := set(a), set(b)
	if len(sa) != len(sb) {
		return false
	}
	for x := range sa {
		if !sb[x] {
			return false
		}
	}
	return true
}

// staleRows returns the rows of old whose key next does not produce.
func staleRows(old, next RuleMaps) RuleMaps {
	keep := make(map[ebpfbindings.NetKey]bool, len(next.Exact))
	for _, r := range next.Exact {
		keep[r.Key] = true
	}
	keepCIDR := make(map[ebpfbindings.NetLPMKey]bool, len(next.CIDR))
	for _, r := range next.CIDR {
		keepCIDR[r.Key] = true
	}
	var out RuleMaps
	for _, r := range old.Exact {
		if !keep[r.Key] {
			out.Exact = append(out.Exact, r)
		}
	}
	for _, r := range old.CIDR {
		if !keepCIDR[r.Key] {
			out.CIDR = append(out.CIDR, r)
		}
	}
	return out
}

// unionRows is next with every row of old whose key next lacks appended: the set teardown must remove while
// a refresh is between its two writes. Its names are next's, which a refresh does not change.
func unionRows(old, next RuleMaps) RuleMaps {
	out := next
	stale := staleRows(old, next)
	out.Exact = append(append([]NetRow(nil), next.Exact...), stale.Exact...)
	out.CIDR = append(append([]CIDRRow(nil), next.CIDR...), stale.CIDR...)
	out.Control = old.Control
	out.Timelines = append(append([]TimelineRow(nil), next.Timelines...), old.Timelines...)
	return out
}

// RunListener answers fanotify permission events until the context ends. A run's errgroup owns it. When the
// run is cancelled, the listener's workers have ended and its group is closed by the time it returns, and so
// has its closer, unless a close the closer holds is still waiting on its filesystem after
// fanCloserJoinTimeout, in which case the closer finishes on its own, after the run (§6 E35, §9).
//
// It must be started promptly after Prepare: the marks are already in place, and until this loop runs every
// open on a marked mount waits for an answer (see startFanotify).
//
// A non-nil return is fatal to the run: the kernel fails *open* when a permission listener disappears, the
// opposite of seccomp's fail-closed, so the caller cancels and kills rather than continuing in that window
// (§6 E15). It comes back as soon as the listener fails, with the marks already down, removed by one
// fanotify_mark call that names no path and so waits on no marked filesystem; the workers' last answers, the
// group's close and the closer's queue finish on a goroutine the listener leaves behind, since a close can wait
// on its filesystem for as long as that filesystem does not answer, and the kill must not wait with it (§6 E35).
// Those can outlive the run and Detach, and what the workers still record then can reach the run's queue after
// its final drain, where nothing writes it; the listener counts those events in a gap before it returns, and
// WaitListener waits for them (§7). A run whose contract has no fs rules has no listener, and this waits for
// the run's cancellation and returns nil.
func (h *Handle) RunListener(ctx context.Context) error {
	if h.fan == nil {
		<-ctx.Done()
		return nil
	}
	if err := h.fan.loop(ctx); err != nil {
		return fmt.Errorf("%w: %w", ErrListenerDied, err)
	}
	return nil
}

// SetSupervisorExecLines hands the listener the run's supervisor's answer to whether a refused open is an exec's
// open of its image whose line the supervisor writes (supervisor.Loop.ExecLine): the exec's one line, so the
// listener writes none for that open (supervisor R7a). The runtime calls it once the supervisor exists, before
// the agent runs; a run with no listener ignores it. enforce.SupervisorExecLines is the facade's assertion.
func (h *Handle) SetSupervisorExecLines(fn func(tid int, dev, ino uint64) bool) {
	if h.fan == nil || fn == nil {
		return
	}
	h.fan.execLine.Store(&fn)
}

// WaitListener returns once the workers of this run's fanotify listener have answered every event they held
// and handed on what they recorded for each, or with ctx's error if ctx ends first. A listener that fails
// returns before its workers (RunListener), and they end within three of E16's deadlines after that, so a
// caller that waits here between the run group's Wait and its final drain writes every line they record (§6
// E35). internal/runtime's shutdown calls it there through api.ListenerWaiter, bounded by its killTimeout;
// a line recorded after that bound would still be lost, and the listener's GapFanotifyAbandoned line counts
// the events it could be for. A run with no listener, or whose listener never ran, has nothing to wait for,
// and this returns nil at once.
func (h *Handle) WaitListener(ctx context.Context) error {
	if h.fan == nil {
		return nil
	}
	return h.fan.waitWorkers(ctx)
}

// Detach releases everything this run created, in the order §4 and §5 R15 require:
//
//  1. this run's cgroup links, so no hook can write another breadcrumb;
//  2. the run's rows — run-set membership, breadcrumbs, verdict rows — by the cgroup ids this handle
//     tracked, never by scanning a host-wide map, then the run's rings at its slot;
//  3. the fanotify marks and the group;
//  4. the run_idx slot, only once nothing references it any more (§5 R12, §8 I5);
//  5. the shared pins, but only when the exclusive build lock says this is the last launcher out (§5 R14).
//
// Errors are joined rather than returned at the first failure, so one stuck step never strands the rest. It
// is idempotent and safe after a partial Prepare.
func (h *Handle) Detach() error {
	h.netMu.Lock()
	defer h.netMu.Unlock()
	if h.detached {
		return nil
	}
	h.detached = true

	var errs []error
	if h.kern != nil {
		if err := h.kern.detachCgroup(); err != nil {
			errs = append(errs, err)
		}
		// cgroup_track may have materialized descendants since Prepare. cgroup_rmdir removes each row as its
		// cgroup goes away, but a scan here removes them at once rather than leaving them against the run
		// set's 4096-row budget until the kernel gets round to it (§6 E11).
		h.collectDescendants()
		for id := range h.cgroups {
			if err := h.removeRun(id); err != nil {
				errs = append(errs, err)
			}
		}
		h.cgroups = nil
		if err := h.removeRules(); err != nil {
			errs = append(errs, err)
		}
		// The plane's rows and header of the slot, now that no run-set row names it: T4's clear, in the kernel. A
		// clear that fails leaves rows of this run's gen, which no later run of the slot has, so they are absent to
		// it; the slot's next Prepare clears them (purgeSlot). A row that could not be removed (rowsLeft) still
		// carries the slot and decides for its tasks: its rows stay, so they are decided by their own run's
		// contract, and the slot, kept allocated, goes to no other run until the reaper takes both (R6).
		if h.plane != nil && !h.rowsLeft {
			if err := h.plane.clearSlot(h.slot); err != nil {
				errs = append(errs, err)
			}
		}
		if err := h.closePins(); err != nil {
			errs = append(errs, err)
		}
		// The run's rings stay at its slot (ADR 0026 (6) as amended): the slot's next run reuses them, drained, and
		// its readers drop what this run's programs still write, by generation. So a row that could not be removed
		// keeps its tasks recorded, into rings nothing takes away while the row carries the slot.
	}
	if h.fan != nil {
		if err := h.fan.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if err := h.releaseSlotAndPark(); err != nil {
		errs = append(errs, err)
	}

	if h.kern != nil {
		if err := h.leaveBuild(h.kern); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Close releases every descriptor the handle owns. It runs Detach first when the caller has not, so a
// forgotten Detach can never leak a slot or a row, and is safe to call twice (§8 I10).
func (h *Handle) Close() error {
	if h.closed {
		return nil
	}
	h.closed = true

	var errs []error
	if err := h.Detach(); err != nil {
		errs = append(errs, err)
	}
	if h.kern != nil {
		if err := h.kern.close(); err != nil {
			errs = append(errs, err)
		}
		h.kern = nil
	}
	if h.lock != nil {
		if err := h.lock.Close(); err != nil {
			errs = append(errs, err)
		}
		h.lock = nil
	}
	// The build lingers (ADR 0022): its timer starts once this launcher, the last out, holds nothing of it.
	if h.lingering {
		h.lingering = false
		if err := h.startTimer(); err != nil {
			errs = append(errs, err)
		}
	}
	// The verified state directory the slot table holds is the handle's too: a failed Prepare closes it by its
	// undo, a successful one here, last, since the teardown above still reads the table through it.
	if h.slots != nil {
		if err := h.slots.close(); err != nil {
			errs = append(errs, err)
		}
	}
	h.undos = nil
	return errors.Join(errs...)
}

// collectDescendants adds every cgroup currently nested under the run's scope to the set of rows teardown
// removes. It is best effort: a subtree that is already gone needs no removal, and a descendant that appears
// after this is removed by cgroup_rmdir when its cgroup does.
func (h *Handle) collectDescendants() {
	entries, err := readSubtree(filepath.Join(h.run.mount(), h.run.CgroupPath))
	if err != nil {
		return
	}
	for _, rel := range entries {
		id, err := cgroupIDOfPath(h.run.mount(), filepath.Join(h.run.CgroupPath, rel))
		if err != nil {
			continue
		}
		if h.cgroups == nil {
			h.cgroups = map[uint64]struct{}{}
		}
		h.cgroups[id] = struct{}{}
	}
}

// tierByte is the tier number a run-set row carries: 1 landlock, 2 cgroup, 3 bpflsm.
func tierByte(t backend.Tier) int {
	switch t {
	case backend.TierLandlock:
		return 1
	case backend.TierCgroup:
		return 2
	case backend.TierBPFLSM:
		return 3
	case backend.TierObserve, backend.TierAuto:
		fallthrough
	default:
		return 0
	}
}
