// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestPrepareScrubsARecycledSlotsLeftoverRows is the fail-open half of enforce-cgroup-observe.md §5 R12, §8 I5 and §6 E32. The verdict maps are
// LIBBPF_PIN_BY_NAME, so they outlive the launcher that wrote them, and the slot table hands a dead launcher's
// run_idx to the next run (slots.go's dead-owner reclaim). Nothing else in Prepare looks at what is already
// keyed by the slot it was given: connect4/6 does one exact lookup on (run_idx, family, proto, port, addr) and
// allows on a hit, so a dead run's allow row would grant the new run a destination its own contract never
// named — and the breadcrumb would file it under the dead run's rule index.
func TestPrepareScrubsARecycledSlotsLeftoverRows(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	// The host state a launcher killed between populate and Detach leaves behind: allow rows for run_idx 0
	// naming a destination no later contract mentions.
	const deadSlot = 0
	staleAddr := netip.MustParseAddr("203.0.113.9")
	staleExact, err := ebpfbindings.NetKeys(deadSlot, ebpfbindings.ProtoTCP, staleAddr, 443)
	if err != nil {
		t.Fatalf("build the dead run's exact keys: %v", err)
	}
	staleCIDR, err := ebpfbindings.NetLPMKeys(deadSlot, ebpfbindings.ProtoTCP, netip.MustParsePrefix("203.0.113.0/24"), 443)
	if err != nil {
		t.Fatalf("build the dead run's cidr keys: %v", err)
	}
	allow := ebpfbindings.NetVerdict{Verdict: uint8(ebpfbindings.VerdictAllow), RuleIdx: 7}
	for _, k := range staleExact {
		f.kernel.net.exact[k] = allow
	}
	for _, k := range staleCIDR {
		f.kernel.net.cidr[k] = allow
	}

	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer h.Close()
	if h.Slot() != deadSlot {
		t.Fatalf("slot = %d; this test needs the run to be handed the dead run's index", h.Slot())
	}

	for _, k := range staleExact {
		if _, live := f.kernel.net.exact[k]; live {
			t.Fatalf("%s:%d survived into run %q on slot %d: a reused index inherited a dead run's allow row (§5 R12, §8 I5)",
				staleAddr, 443, f.run.ID, h.Slot())
		}
	}
	for _, k := range staleCIDR {
		if _, live := f.kernel.net.cidr[k]; live {
			t.Fatalf("a dead run's cidr allow row survived onto slot %d (§5 R12, §8 I5)", h.Slot())
		}
	}

	// Only this run's own rows may be keyed by the slot afterwards.
	if got, want := f.kernel.net.rowsFor(h.Slot()), len(h.Rules().Exact)+len(h.Rules().CIDR)+len(h.Rules().Unix); got != want {
		t.Fatalf("%d rows keyed by slot %d, want this run's own %d", got, h.Slot(), want)
	}

	// The scrub has to precede the run's own rows, not follow them, or it would delete what it just wrote.
	order := strings.Join(f.kernel.calls, ",")
	if !strings.HasPrefix(order, "purgeSlot,populate") {
		t.Fatalf("call order %q: the slot must be scrubbed before this run's rows go in", order)
	}
	if len(f.kernel.purged) != 1 || f.kernel.purged[0] != h.Slot() {
		t.Fatalf("purged %v, want exactly the run's own slot %d", f.kernel.purged, h.Slot())
	}
}

// TestPrepareFailsWhenTheSlotCannotBeScrubbed is the fail-closed reading of the same case (enforce-cgroup-observe.md §6 E32): if the leftovers
// cannot be proven gone, the run must not start on that index rather than start beside them.
func TestPrepareFailsWhenTheSlotCannotBeScrubbed(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.kernel.failAt = "purgeSlot"

	if _, err := f.backend.Prepare(context.Background(), f.table, f.run); err == nil {
		t.Fatal("Prepare succeeded although the slot's leftover rows could not be removed")
	}
	if f.kernel.exactRows != 0 {
		t.Fatalf("%d rows were written after the scrub failed", f.kernel.exactRows)
	}
	slots, err := openSlotTable(t, f.dir, "testhash")
	if err != nil {
		t.Fatalf("openSlotTable: %v", err)
	}
	if n, err := slots.held(); err != nil || n != 0 {
		t.Fatalf("held = %d, %v; a Prepare that never wrote a row must free its slot (§8 I10)", n, err)
	}
}

// TestDetachKeepsTheSlotWhenARowSurvives pins the other direction of enforce-cgroup-observe.md §5 R12 and §8 I5 — "freed only after every map row
// referencing it is gone (Detach blocks release on this)" — against the ordinary joined-error teardown, which
// would otherwise note the failure and hand the index on anyway. The slot record holds this process's pid, so
// keeping it costs nothing permanent: the next launcher reclaims it once this one is gone, and scrubs it first.
func TestDetachKeepsTheSlotWhenARowSurvives(t *testing.T) {
	t.Parallel()
	for _, step := range []string{"removeRules", "removeRun"} {
		t.Run(step, func(t *testing.T) {
			f := newFixture(t)
			h := f.prepareArmed(t)
			defer h.Close()

			f.kernel.failAt = step
			err := h.Detach()
			if err == nil {
				t.Fatalf("Detach succeeded although %s failed", step)
			}
			if !strings.Contains(err.Error(), "run slot 0 stays allocated") {
				t.Fatalf("Detach error does not say the slot is held back: %v", err)
			}
			slots, openErr := openSlotTable(t, f.dir, "testhash")
			if openErr != nil {
				t.Fatalf("openSlotTable: %v", openErr)
			}
			if n, heldErr := slots.held(); heldErr != nil || n != 1 {
				t.Fatalf("held = %d, %v; a slot whose rows survive must stay allocated (§5 R12, §8 I5)", n, heldErr)
			}
		})
	}
}

// TestFailedPrepareKeepsTheSlotWhenARowSurvives is the same invariant on Prepare's unwind path, which reaches
// releaseSlot through its own registered undo rather than through Detach.
func TestFailedPrepareKeepsTheSlotWhenARowSurvives(t *testing.T) {
	t.Parallel()
	f := newFixture(t, func(o *Options) {
		o.newListener = func(*Handle) (*fanotifyListener, error) {
			return nil, ErrFanotify
		}
	})
	f.kernel.failAt = "removeRules"

	if _, err := f.backend.Prepare(context.Background(), f.table, f.run); err == nil {
		t.Fatal("Prepare succeeded with a failing listener")
	}
	slots, err := openSlotTable(t, f.dir, "testhash")
	if err != nil {
		t.Fatalf("openSlotTable: %v", err)
	}
	if n, err := slots.held(); err != nil || n != 1 {
		t.Fatalf("held = %d, %v; an unwind that could not remove its rows must keep the slot (§5 R12, §8 I5)", n, err)
	}
}

// TestFailedPrepareUnpinsWhenItIsTheLastLauncherOut is §7's "abort Prepare, no partial pins" and §8 I10's "no
// leaked pin". Closing the handles is not enough: a pinned link stays attached host-wide after the fd that
// made it is gone, so a Prepare that failed at step 7 or 8 would leave this build's maps, programs and
// tracepoint links in the kernel with no tego process alive and nobody draining the ring buffer. The
// successful path's Detach already asks the build lock this question; the unwind never did.
func TestFailedPrepareUnpinsWhenItIsTheLastLauncherOut(t *testing.T) {
	t.Parallel()
	f := newFixture(t, func(o *Options) {
		o.Inherit = func(context.Context, *agent.RuleTable, Run) (Inherited, error) {
			return nil, errors.New("no landlock here")
		}
	})

	if _, err := f.backend.Prepare(context.Background(), f.table, f.run); err == nil {
		t.Fatal("Prepare succeeded with a failing Inherit")
	}
	if !f.kernel.unpinned {
		t.Fatal("a sole launcher whose Prepare failed left the build's pins behind (§7, §8 I10)")
	}
	if !f.kernel.closed {
		t.Fatal("the kernel state was not closed on the unwind")
	}
	order := strings.Join(f.kernel.calls, ",")
	if unpin, closed := strings.LastIndex(order, "unpin"), strings.LastIndex(order, "close"); unpin > closed {
		t.Fatalf("call order %q: unpin works through the handles close releases, so it must come first", order)
	}
}

// TestFailedPrepareKeepsPinsWhileAnotherLauncherRuns is the other half of §5 R14: the unwind may only remove
// what no other launcher of this build is using, so a failed Prepare beside a live run leaves the pins alone.
func TestFailedPrepareKeepsPinsWhileAnotherLauncherRuns(t *testing.T) {
	f := newFixture(t, func(o *Options) {
		o.Inherit = func(context.Context, *agent.RuleTable, Run) (Inherited, error) {
			return nil, errors.New("no landlock here")
		}
	})
	stop := holdLockInChild(t, f.dir, "testhash")
	defer stop()

	if _, err := f.backend.Prepare(context.Background(), f.table, f.run); err == nil {
		t.Fatal("Prepare succeeded with a failing Inherit")
	}
	if f.kernel.unpinned {
		t.Fatal("a failed Prepare unpinned a build another launcher is still running (§5 R14)")
	}
	if !f.kernel.closed {
		t.Fatal("the kernel state was not closed on the unwind")
	}
}

// TestLoadFailedPartWayUnpinsWhatItAlreadyCreated is §7's "abort Prepare, no partial pins" and §8 I10's "no
// leaked pin" for a failure of step 5 *itself*, which the Inherit-failure test above cannot reach.
//
// The three objects are loaded one after another and every piece is pinned the moment it exists: the
// collection loader pins the LIBBPF_PIN_BY_NAME maps, pinProgram pins each program, attachShared attaches
// and pins each host-wide tracing link. So the ordinary failures of that step — the second object rejected
// by the verifier, a tracepoint missing from this kernel's BTF — leave maps, programs and *live* attachments
// in the kernel. Closing the descriptors removes none of them, because a pinned link stays attached
// host-wide after the fd that made it is gone; what was left behind was the whole build, attached, with
// nobody draining the ring buffer and no tego process alive to notice. Only the load step's undo asks the
// build lock the last-out question that may remove them, and it was registered one statement too late to
// run for the step that created them.
func TestLoadFailedPartWayUnpinsWhatItAlreadyCreated(t *testing.T) {
	t.Parallel()
	loadFailed := errors.New("bpf program load failed: cgroup_track rejected by the verifier")
	partial := newFakeKernel()
	f := newFixture(t, func(o *Options) {
		o.newKernel = func(context.Context, *Handle) (kernel, error) { return partial, loadFailed }
	})

	_, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err == nil {
		t.Fatal("Prepare succeeded although the objects never finished loading")
	}
	if !errors.Is(err, loadFailed) {
		t.Fatalf("Prepare = %v; the loader's own error must reach the caller unchanged", err)
	}
	if !partial.unpinned {
		t.Fatal("a load that failed part way left this build's maps, programs and tracing links pinned and " +
			"attached with no launcher alive (§7 no partial pins, §8 I10)")
	}
	if !partial.closed {
		t.Fatal("the half-built kernel state was never closed")
	}
	order := strings.Join(partial.calls, ",")
	if unpin, closed := strings.LastIndex(order, "unpin"), strings.LastIndex(order, "close"); unpin > closed {
		t.Fatalf("call order %q: unpin works through the handles close releases, so it must come first", order)
	}
	slots, err := openSlotTable(t, f.dir, "testhash")
	if err != nil {
		t.Fatalf("openSlotTable: %v", err)
	}
	if n, err := slots.held(); err != nil || n != 0 {
		t.Fatalf("held = %d, %v; a Prepare that wrote no row must free its slot (§8 I10)", n, err)
	}
}

// TestLoadFailedPartWayKeepsPinsWhileAnotherLauncherRuns is the same case against §5 R14: the half-built
// state is still this build's shared state, and another launcher of the build is using it, so the unwind may
// close its own handles and nothing more.
func TestLoadFailedPartWayKeepsPinsWhileAnotherLauncherRuns(t *testing.T) {
	partial := newFakeKernel()
	f := newFixture(t, func(o *Options) {
		o.newKernel = func(context.Context, *Handle) (kernel, error) {
			return partial, errors.New("bpf program load failed: cgroup_track rejected by the verifier")
		}
	})
	stop := holdLockInChild(t, f.dir, "testhash")
	defer stop()

	if _, err := f.backend.Prepare(context.Background(), f.table, f.run); err == nil {
		t.Fatal("Prepare succeeded although the objects never finished loading")
	}
	if partial.unpinned {
		t.Fatal("a failed load unpinned a build another launcher is still running (§5 R14)")
	}
	if !partial.closed {
		t.Fatal("the half-built kernel state was never closed")
	}
}

// partialPopulateKernel is a kernel whose populate writes some rows and then fails, which is how the real one
// fails: k.populate walks the compiled rows one bpf(2) map update at a time and returns at the first refusal,
// so an ErrMapFull on row n leaves rows 0..n-1 in the kernel.
type partialPopulateKernel struct {
	*fakeKernel
	// writes is how many exact rows go in before the map refuses the next one.
	writes int
}

func (k *partialPopulateKernel) populate(rules RuleMaps) error {
	k.calls = append(k.calls, "populate")
	for i, row := range rules.Exact {
		if i >= k.writes {
			return fmt.Errorf("%w: tego_net_exact: no space for row %d", ErrMapFull, i)
		}
		k.net.exact[row.Key] = row.Val
		k.exactRows++
	}
	return nil
}

// TestPrepareRemovesTheRowsAPartialPopulateWrote is §5 R12 and §8 I5 against the failure that actually
// produces orphaned verdict rows.
//
// The rows live in tego_net_exact and tego_net_cidr, which are LIBBPF_PIN_BY_NAME and so outlive the
// launcher that wrote them. populate stops at the first map update the kernel refuses — the 4096-row budget
// of §7, reported as ErrMapFull — and everything it wrote before that point stays, keyed by this run's
// run_idx. The unwind must remove those: releaseSlot cannot notice them, because rowsLeft records only
// removals that failed, and it frees the index; and until some later run is handed that same index and
// scrubs it (purgeSlot), the dead rows count against the one budget every other run on the host shares —
// so the run that exhausted the map leaves it more exhausted than it found it.
func TestPrepareRemovesTheRowsAPartialPopulateWrote(t *testing.T) {
	t.Parallel()
	const wrote = 2
	var k *partialPopulateKernel
	f := newFixture(t, func(o *Options) {
		o.newKernel = func(context.Context, *Handle) (kernel, error) { return k, nil }
	})
	k = &partialPopulateKernel{fakeKernel: f.kernel, writes: wrote}

	_, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err == nil {
		t.Fatal("Prepare succeeded although the verdict map refused a row")
	}
	if !errors.Is(err, ErrMapFull) {
		t.Fatalf("Prepare = %v, want ErrMapFull unchanged", err)
	}
	if got := k.net.rowsFor(0); got != 0 {
		t.Fatalf("%d verdict rows of slot 0 survived a Prepare that never finished writing them (want %d "+
			"written then all removed): a pinned map keeps them against every other run's budget, and the "+
			"slot was handed back with rows still keyed by it (§5 R12, §8 I5)", got, wrote)
	}
	slots, err := openSlotTable(t, f.dir, "testhash")
	if err != nil {
		t.Fatalf("openSlotTable: %v", err)
	}
	if n, err := slots.held(); err != nil || n != 0 {
		t.Fatalf("held = %d, %v; the rows are gone, so the slot is free (§8 I10)", n, err)
	}
}
