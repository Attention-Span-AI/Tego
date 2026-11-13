// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"syscall"

	"golang.org/x/net/bpf"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A run's half of the decision plane (plane.go): which mode it decides in, the rows it fills, and the name the
// ledger and the capability line give its decisions.

// PlaneFanotify is the name of the decisions a run without a plane mode gets: tier cgroup's fanotify listener (ADR
// 0021), as doctor names the fallback.
const PlaneFanotify = "fanotify"

// choosePlane settles the run's plane mode before anything is loaded: Options.Plane's mode, with the table's rows
// (Run.PlaneRows, or compiled here). A table the plane cannot hold (more rows than a slot's maps, decide.ErrPlaneCap;
// an exec entry that does not allow, decide.ErrPlaneExecVerdict) runs on the fanotify listener instead, which
// decides it whole, and says so (DecisionPlane, the run's log): a plane that left rows out would enforce less
// than the contract, the quieter run enforce-plane I7 forbids. Rows the caller handed over (Run.PlaneRows) that
// no longer hold are ErrPlaneRowsChanged, never the fallback: tier 1 was composed from them. The fallback is tier 2's alone: at tier bpflsm the
// same failure (a hard link made between tier3Plane's check and this one, say) is an error wrapping
// ErrPlaneCannotHold, which Prepare returns and unwinds on, never a tier-3 run on the listener (R19, §6 E13). So
// is a table with built-in deny_write targets whose contract says fs.assurance: kernel, with no plane mode or one
// that cannot hold it: the listener's supervisor refuses those targets only best effort (enforce-landlock R5a,
// ADR 0041 D1 (a)); by default such a table takes the listener like any other.
func (h *Handle) choosePlane(rt *agent.RuleTable) error {
	if h.opts.Plane.Mode == "" {
		if rt.DenyWriteNeedsPlane() {
			return fmt.Errorf("%w: %s requires a kernel decision plane under fs.assurance: kernel; narrow fs.write, enable a "+
				"working lsm/fmod_ret plane, or drop fs.assurance: kernel", ErrPlaneCannotHold, rt.DenyWrite[0].RuleName())
		}
		return nil
	}
	rows := h.run.PlaneRows
	var err error
	if rows == nil {
		if rows, err = decide.CompilePlane(rt); h.run.PlaneErr != nil {
			err = h.run.PlaneErr
		}
	}
	if err == nil {
		err = PlaneHoldableAt(rows, h.run.Mounts)
	}
	if err != nil {
		if h.opts.tier3() || rt.DenyWriteNeedsPlane() {
			return fmt.Errorf("%w: %w", ErrPlaneCannotHold, err)
		}
		if h.run.PlaneRows != nil {
			// The rows were handed over, so tier 1 may have been composed for a plane (io_uring admitted, the memfd
			// arm dropped), and that filter cannot be rebuilt here: falling back to the listener would keep the
			// plane-only relaxations on a run no plane decides. The rows held when the caller checked them
			// (PlaneHoldable) and no longer do, a hard link made in between, say; the caller composes again without
			// them (Run.PlaneErr) and the run takes the fallback then.
			return fmt.Errorf("%w: %w", ErrPlaneRowsChanged, err)
		}
		h.planeWhy = err
		if h.run.Log != nil {
			h.run.Log.Warn("the decision plane cannot hold this contract; the run decides through fanotify",
				"mode", string(h.opts.Plane.Mode), "err", err)
		}
		return nil
	}
	h.planeMode, h.planeRows = h.opts.Plane.Mode, rows
	h.planeExecs = execPolicyOf(rt).Decides
	return nil
}

// ErrPlaneSharedInode is a table two of whose fs rows are one file under two names (hard links of a file two
// entries name, a deny_read and a write entry, say). The plane keys one fs row per inode (enforce-plane §2.4 condition
// 4), and the fill refuses the second, failing every run of the table with exit 125; found here, before anything is
// loaded, tier cgroup runs such a table on the listener and tier bpflsm refuses it with the reason (TIER3-PLAN T11).
// Exec entries on one inode are not a clash: each listed link has its own row (§6 E15).
var ErrPlaneSharedInode = errors.New("two fs entries the plane keys are one file under two names")

// sharedInode reports the first two fs rows of rows naming one inode now. Each row is stated as the plane keys it: a
// NoFollow row (a deny_write target declared through a symlink, enforce-plane R11) at the link's own inode, the rest
// following a final symlink, so a link and its target are two rows, not one file under two names. A path that cannot
// be stated is left to the fill, which skips an absent one and refuses the rest; a file linked or unlinked after this
// check is the fill's to catch, and it fails closed.
func sharedInode(rows *decide.PlaneRows) error {
	type key struct{ dev, ino uint64 }
	seen := make(map[key]string, len(rows.FS))
	for _, r := range rows.FS {
		stat := os.Stat
		if _, noFollow := slices.BinarySearch(rows.NoFollow, r.Path); noFollow {
			stat = os.Lstat
		}
		fi, err := stat(r.Path)
		if err != nil {
			continue
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		k := key{uint64(st.Dev), st.Ino} //nolint:unconvert // Dev is uint64 on amd64 and arm64 alike, not everywhere
		if other, dup := seen[k]; dup {
			return fmt.Errorf("%w: fs rows %s and %s", ErrPlaneSharedInode, other, r.Path)
		}
		seen[k] = r.Path
	}
	return nil
}

// PlaneHoldableAt checks rows against the snapshot acquired for this Prepare.
func PlaneHoldableAt(rows *decide.PlaneRows, mounts *MountSnapshot) error {
	if err := sharedInode(rows); err != nil {
		return err
	}
	return detachedParts(rows, func() *mountSnapshot {
		if mounts == nil {
			return ReadMounts()
		}
		return mounts
	})
}

// ErrPlaneDetachedPart is a table with a row that refuses reads in a tree a part of which the launcher's mount table
// shows outside it: a bind mount of a directory or of one file inside a deny_read directory, elsewhere. The plane's
// walk crosses mounts (ADR 0025), so from a file there it meets the bind's root and then its mount point, never the
// entry's row, and beneath a granted sibling it allowed the read (conformance mounts-bind/read-bind-alias-file, every
// plane axis, 2026-11-11). The plane cannot hold such a table: tier cgroup falls back to the listener, which refuses the run at Prepare, and tier bpflsm refuses it before the run
// starts. A bind of the entry itself, of its parent or of its whole filesystem is no such part: the walk from a file
// beneath it passes the entry's own directory.
var ErrPlaneDetachedPart = errors.New("a bind mount shows part of a deny_read tree outside it, where the decision plane's walk never meets the entry")

// detachedParts reports the first row that refuses reads whose tree has a part mounted outside it in the mount table
// snapshot reads (mountSnapshot.detached, agent.MountTable.DetachedParts), read once, at the first such row. A table
// that cannot be read, disagrees with the system, or holds no mount of such a row cannot show that none is, and fails
// the same way (fail closed).
func detachedParts(rows *decide.PlaneRows, snapshot func() *mountSnapshot) error {
	var snap *mountSnapshot
	for _, r := range rows.FS {
		if r.Kind&decide.PlaneReadDeny == 0 || r.Path == "" {
			continue
		}
		if snap == nil {
			snap = snapshot()
		}
		parts, err := snap.detached(r.Path)
		switch {
		case err != nil:
			return fmt.Errorf("%w: %w: the parts of %s mounted elsewhere cannot be listed: %w", ErrPlaneDetachedPart, ErrMountTable, r.Path, err)
		case len(parts) > 0:
			return fmt.Errorf("%w: %s shows a part of %s", ErrPlaneDetachedPart, parts[0], r.Path)
		}
	}
	return nil
}

// tier3Plane is tier bpflsm's precondition, checked at the top of Prepare: the plane handed over is in LSM mode, and
// the table's rows fit it, compiled here when the caller did not (run.PlaneRows is set to them, so choosePlane uses
// the same rows). A caller whose compile failed (run.PlaneErr) is refused with its error, never compiled again. choosePlane's fallback to the listener is tier 2's alone: a tier-3 run has no listener, and a
// plane that left rows out would enforce less than the contract (enforce-plane R19, §6 E13, I7), so both refuse.
func tier3Plane(p PlaneSetup, rt *agent.RuleTable, run *Run) error {
	if p.Mode != ebpfbindings.PlaneLSM {
		got := string(p.Mode)
		if got == "" {
			got = "none (the fanotify fallback)"
		}
		return fmt.Errorf("%w: the plane selected is %s; run tego doctor, which names what LSM mode needs here",
			ErrNeedsLSMMode, got)
	}
	rows, err := run.PlaneRows, error(nil)
	switch {
	case rows != nil:
	case run.PlaneErr != nil:
		// The caller's compile failed (its rows with the mounted roots over the cap, or this launcher's descriptor
		// cap, decide.PlaneRows.FitFDs, which only the caller reads): compiling again here, without them, would drop
		// the error and the rows R12 keys, as choosePlane refuses to.
		err = run.PlaneErr
	default:
		rows, err = decide.CompilePlane(rt)
	}
	if err == nil {
		err = PlaneHoldableAt(rows, run.Mounts)
	}
	if err != nil {
		if errors.Is(err, ErrPlaneDetachedPart) {
			return fmt.Errorf("%w: %w; remove the mounts showing denied content elsewhere; tier cgroup also refuses this layout", ErrPlaneCannotHold, err)
		}
		// A row or descriptor budget failure can mask a whole-tree alias that the
		// plane would hold. Switching to the listener would then refuse too.
		if run.Mounts == nil {
			run.Mounts = ReadMounts()
		}
		listener := newPolicyAt(rt, run.CgroupPath, run.Mounts.view(), mountKeyOf)
		if listener.aliasErr != nil {
			return fmt.Errorf("%w: %w; tier cgroup also refuses this layout: %w", ErrPlaneCannotHold, err, listener.aliasErr)
		}
		return fmt.Errorf("%w: %w; narrow the fs, deny_read and exec.allow entries; tier cgroup (--tier cgroup, or tier: cgroup in the contract) is an option only if its listener can hold the complete contract", ErrPlaneCannotHold, err)
	}
	run.PlaneRows = rows
	return nil
}

// preparePlaneSlot is attachKernel's plane step, beside the slot's purge: the loaded plane, the slot's row maps, and
// the clear of whatever rows the slot still holds, a launcher's that died before its Detach cleared them included
// (the plane's half of purgeSlot, T4's clear). Rows of another gen are absent to this run anyway (R6); cleared, they
// no longer count against its slot's cap.
func (h *Handle) preparePlaneSlot(k kernel) error {
	if h.planeMode == "" {
		return nil
	}
	h.plane = k.planeOf()
	if h.plane == nil {
		return fmt.Errorf("%w: the decision plane in %s mode was not loaded", ErrProgramLoad, h.planeMode)
	}
	if h.opts.planeWrap != nil {
		h.plane = h.opts.planeWrap(h.plane)
	}
	if err := h.plane.prepareSlot(h.slot); err != nil {
		return err
	}
	return h.plane.clearSlot(h.slot)
}

// fillPlane is Prepare's last step: the run's rows, keyed by the inodes the inherited Landlock plan holds O_PATH
// descriptors of, written with the run's gen before Arm inserts the run-set row that makes them decide (R15, R16).
// A fill that does not come out as planned fails Prepare, and nothing runs.
func (h *Handle) fillPlane(rt *agent.RuleTable) error {
	if h.plane == nil {
		return nil
	}
	held := h.opts.planeHeld
	var listenHeld heldFD
	if src, ok := h.inherited.(interface{ PlaneListenParent(path string) (int, bool) }); ok {
		listenHeld = src.PlaneListenParent
	}
	if held == nil {
		src, ok := h.inherited.(interface{ PlaneHeld(path string) (int, bool) })
		if !ok {
			return fmt.Errorf("%w: the decision plane keys its rows by the inherited Landlock plan's descriptors, "+
				"and this run inherits none", ErrNotPrepared)
		}
		held = src.PlaneHeld
	}
	unixPol, err := h.planeUnixPolicy()
	if err != nil {
		return err
	}
	// Registered first: a fill that failed part way left rows of this run's gen, which no later run of the slot
	// has, and the clear takes them now rather than at the slot's next Prepare.
	h.undo(func() error { return h.plane.clearSlot(h.slot) })
	// A run asked to be pinned that cannot be runs unpinned and says why; its handle reports no pins (ExecPins), so no
	// supervisor writes one and no exec is refused for the want of one.
	pin, err := h.execPinRequest()
	if err != nil {
		if h.run.Log != nil {
			h.run.Log.Info("exec pins off", "err", err)
		}
		h.pinOff = err.Error()
		pin = nil
	}
	rep, err := h.plane.fill(planeFillRequest{Slot: h.slot, Gen: h.gen, Rows: h.planeRows, Held: held,
		ListenHeld: listenHeld, KeyringAllowed: rt.Contract != nil && rt.Contract.Keyring,
		Exec: execPolicyOf(rt), Unix: unixPol, Net: netPolicyOf(rt), Pin: pin})
	if err != nil {
		return fmt.Errorf("cgroup: fill the decision plane's rows: %w", err)
	}
	h.planeKeyed, h.planeFilled = rep.Keyed, true
	if pin != nil {
		if err := h.openPins(pin); err != nil {
			return fmt.Errorf("cgroup: open the slot's exec pin map: %w", err)
		}
		h.undo(h.closePins)
	}
	if h.run.Log != nil {
		h.run.Log.Debug("decision plane filled", "mode", string(h.planeMode), "fs_rows", rep.Rows,
			"exec_rows", rep.ExecRows, "cleared", rep.Cleared, "fill", rep.Fill, "check", rep.Check)
	}
	return nil
}

// unixPlane is the plane rows BuildRuleMaps leaves the unix row pairs of compacted files out by: the run's rows when
// a plane mode decides it, nil on the listener, whose run keeps every pair (fsUnixRows).
func (h *Handle) unixPlane() *decide.PlaneRows {
	if h.planeMode == "" {
		return nil
	}
	return h.planeRows
}

// planeUnixPolicy is the run's unix policy for the plane's step D hooks (enforce-plane R14): where the plane decides
// unix names (below 6.7, where cgroup/connect_unix is not loaded) and the contract has a net: section, the plane
// decides them as connect_unix would, admitting the supervisor's /proc/self/fd/<n> relay from this launcher's cgroup
// (relayCgroup, which Attach writes into the network programs' owner on 6.7+). With no net: section nothing is
// decided (SEMANTICS §1), as no network program is attached then.
func (h *Handle) planeUnixPolicy() (planeUnixPolicy, error) {
	if !h.plane.decidesUnix() || h.rules.Unrestricted {
		return planeUnixPolicy{}, nil
	}
	relay, err := h.relayCgroup(h.run.CgroupID)
	if err != nil {
		return planeUnixPolicy{}, err
	}
	return planeUnixPolicy{Decides: true, Relay: relay}, nil
}

// PlaneChoice names what decides this run's opens, execs and fs mutations: lsm or fmod_ret, the plane's mode, or
// fanotify, the listener; why is the reason a run asked for a plane mode got fanotify instead, nil otherwise. It is
// what the run's log and the conformance runner read (enforce-plane §4, R24).
func (h *Handle) PlaneChoice() (plane string, why error) {
	if h.planeMode != "" {
		return string(h.planeMode), nil
	}
	return PlaneFanotify, h.planeWhy
}

// DecisionPlane is enforce.DecisionPlaneReporter: the plane's mode, the ledger's decision_plane (lsm or fmod_ret),
// "" for the fanotify fallback, and whether its bprm_check decides this run's execs (the contract has an exec:
// section). The runtime names the mode on the plane's lines, leaves a continued exec's line to the kernel, and has
// the supervisor refuse a chmod the plane would refuse (supervisor Options.KernelExecs and PlaneAttrs).
func (h *Handle) DecisionPlane() (mode string, execs bool) {
	if h.planeMode == "" {
		return "", false
	}
	return string(h.planeMode), h.planeExecs
}

func (h *Handle) ExecOutcomes() bool {
	k, ok := h.kern.(interface{ execOutcomes() bool })
	return ok && k.execOutcomes()
}

// PlaneKeyed is enforce.PlaneKeyedReporter: the files this run's fs rows were written at (planeFillPlan.keyed), each
// by its row's canonical path and the device and inode the fill found it at, and ok false when no plane row was
// filled (no plane, or a Prepare that has not filled). A row keys an inode, so it decides every name of that inode as
// it decides its own path, whatever happens to the path after the fill: an adoption asks it which inode its deny of
// the agent owner's records holds, and which keyed file a file the agent held is under another name (ADR 0055).
func (h *Handle) PlaneKeyed() ([]PlaneKeyed, bool) {
	if h.plane == nil || h.planeMode == "" || !h.planeFilled {
		return nil, false
	}
	return slices.Clone(h.planeKeyed), true
}

// PlaneCount is one counter of a run's plane slot: Why is its record.GapPlane* name, Count its value.
type PlaneCount struct {
	Why   string
	Count uint64
}

// PlaneCounters is enforce.PlaneCounterReporter: the run's slot's fail-closed counters (tego_plane_counts), each
// named by the gap why the runtime records it under, zeros included, in the struct's order. The runtime asks once,
// after the run's cgroup emptied and before run_end, so the counts are final and no clear has run: Detach clears the
// slot's rows but never its counters, which only the slot's next prepareSlot zeroes. A run with no plane has none.
func (h *Handle) PlaneCounters() ([]PlaneCount, error) {
	if h.plane == nil || h.planeMode == "" {
		return nil, nil
	}
	c, err := h.plane.counts(h.slot)
	if err != nil {
		return nil, err
	}
	return planeCounts(c), nil
}

// planeCounts names each counter of c by its gap why, in the struct's order.
func planeCounts(c ebpfbindings.PlaneCounts) []PlaneCount {
	return []PlaneCount{
		{Why: record.GapPlaneMismatch, Count: c.Mismatch},
		{Why: record.GapPlaneUnresolved, Count: c.Unresolved},
		{Why: record.GapPlaneBound, Count: c.Bound},
		{Why: record.GapPlaneNoRows, Count: c.NoRows},
	}
}

// preparePlaneFilter assembles, once the plane is loaded and filled, the inherited filter less what the plane's
// attached hooks decide (landlock.Handle.PlaneFilter, enforce-plane R27). Nothing is assembled without a plane or
// an inherited filter that can say, and SeccompFilter hands the result out only once UsePlaneFilter is called:
// every notification is kept until then (fail closed).
func (h *Handle) preparePlaneFilter() error {
	if h.plane == nil || h.inherited == nil {
		return nil
	}
	pf, ok := h.inherited.(interface {
		PlaneFilter(hooks map[string]bool) ([]bpf.RawInstruction, []string, error)
	})
	if !ok {
		return nil
	}
	prog, dropped, err := pf.PlaneFilter(h.plane.hooks())
	if err != nil {
		return fmt.Errorf("cgroup: assemble the filter the decision plane leaves: %w", err)
	}
	if len(dropped) == 0 {
		return nil
	}
	h.planeFilter, h.planeDropped = prog, dropped
	return nil
}

// UsePlaneFilter is enforce.PlaneFilterer: the runtime calls it, before the child stage takes SeccompFilter, when
// the run's kernel recorder writes and names the line of each action the plane decides (ADR 0016's producer table,
// ADR 0024 (14); runtime.PathHookNamer). From then on SeccompFilter leaves out the notifications the plane's
// loaded hooks decide (under record: full, all but the open family). It returns what is left out, empty when nothing
// is (no plane, an fs ask entry, no hook that decides a notified syscall).
func (h *Handle) UsePlaneFilter() (dropped []string) {
	if len(h.planeFilter) == 0 {
		return nil
	}
	h.usePlaneFilter = true
	if h.run.Log != nil {
		h.run.Log.Debug("the decision plane decides what the filter no longer notifies", "mode", string(h.planeMode),
			"dropped", h.planeDropped)
	}
	return append([]string(nil), h.planeDropped...)
}

// PlaneMode is the run's plane mode, "" for the fanotify fallback.
func (h *Handle) PlaneMode() ebpfbindings.PlaneMode { return h.planeMode }

// ListenerDevices returns the devices the listener actually marked for opens.
// No alias policy is handed over: alias layouts are refused before a listener runs.
func (h *Handle) ListenerDevices() (marked func(dev uint64) bool, ok bool) {
	if h == nil || h.planeMode != "" || h.opts.tier3() || h.policy == nil {
		return nil, false
	}
	return func(dev uint64) bool { _, in := h.policy.openDevs[dev]; return in }, true
}
