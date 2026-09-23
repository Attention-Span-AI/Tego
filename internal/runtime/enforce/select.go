// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"context"
	"errors"
	"fmt"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"sort"
	"strings"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/bpflsm"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/observe"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Diagnostic is one Select finding in the shared file:line: message [code] format.
type Diagnostic = identity.Diagnostic

// Select picks the tier a run uses and constructs its backend (docs/p0/identity-config.md §5 R17,
// R18; enforce-landlock.md §4). The machine config supplies the ceiling — a concrete tier name is
// both ceiling and pin; the contract's own tier: pin wins when set; probe says what this machine can
// provide, and is produced by internal/doctor as (*doctor.Report).Probe() — the eight functional
// probes of R27, never a kernel-version comparison. The import direction is doctor -> enforce, so
// the probe crosses as a plain backend.Probe value and this package never learns how it was found.
//
// The ceiling/pin/probe algorithm itself is backend.Select; this function adds the build filter
// (Buildable: a tier the probe reports that this binary cannot construct is treated as unavailable
// with a warning, never selected), the Landlock ABI probe threaded into the backend (R19) and the
// diagnostics. doctor's probe already carries the same filter, so for `tego run` it is a second
// reading of one answer rather than a second opinion. A nil Backend with an error diagnostic means
// exit 125 [tier-unavailable]; a warning reports a tier the contract pinned that the machine could not
// provide, or a contract setting the selected tier leaves without effect; an auto contract running below
// the tier Compile resolved it to is not warned about. TierObserve is never a
// candidate: reach it with Observe.
func Select(m *config.Machine, rt *agent.RuleTable, probe backend.Probe, opts ...SelectOption) (Backend, []Diagnostic) {
	var o selectOptions
	for _, opt := range opts {
		opt(&o)
	}
	var ds []Diagnostic
	file := ""
	if rt != nil {
		file = rt.ContractPath
	}
	ceiling, pin := ceilingAndPin(m, rt)
	available := backend.Probe{}
	for _, t := range sortedTiers(probe) {
		if !probe[t] {
			continue
		}
		switch {
		case !t.Valid() || t == backend.TierObserve:
			// A probe key that is not a selectable tier is a bug in the prober, not a machine
			// capability; say so precisely rather than blaming this binary's build.
			ds = append(ds, Diagnostic{File: file, Code: backend.CodeTierUnavailable, Severity: identityWarning,
				Message: fmt.Sprintf("the capability probe reported %q, which is not a selectable tier", t)})
		case Buildable(t) != nil:
			d := Diagnostic{File: file, Code: backend.CodeTierUnavailable, Severity: identityWarning,
				Message: fmt.Sprintf("tier %s is available on this machine but %v", t, notBuiltWhy(t))}
			var nb *NotBuiltError
			if errors.As(Buildable(t), &nb) {
				d.Fix = nb.Fix
			}
			ds = append(ds, d)
		case t == backend.TierBPFLSM && o.lsmPlane() != nil:
			// Tier bpflsm is the plane in LSM mode, so a probe offering it with no such plane handed over offers a
			// tier nothing can construct. doctor's derivation never does (LSM mode's probe is one of the tier's
			// checks); a caller that did is told, never given tier 3 by another mode (enforce-plane R19).
			ds = append(ds, Diagnostic{File: file, Code: backend.CodeTierUnavailable, Severity: identityWarning,
				Message: fmt.Sprintf("tier %s is available on this machine but %v", t, o.lsmPlane())})
		default:
			available[t] = true
		}
	}
	if o.only != "" {
		// The run asked for one tier by name, so it is pinned to it: a refusal names that tier and why it
		// is missing, never "no enforcement tier available", which on a machine offering another tier is
		// false (identity-config.md §7: "tier <name> pinned but not available: <fix>").
		if !o.only.AtOrBelow(backend.TierBPFLSM) {
			return nil, append(ds, unavailable(file, fmt.Errorf("%w: %q is not a selectable tier", backend.ErrTierUnavailable, o.only)))
		}
		if !available[o.only] {
			fix := o.pinnedWhy(o.only)
			if o.only == backend.TierBPFLSM && probe[o.only] && Buildable(o.only) == nil && o.lsmPlane() != nil {
				fix = o.lsmPlane().Error()
			}
			return nil, append(ds, unavailable(file, &backend.TierUnavailableError{Tier: o.only, Pinned: true, Fix: fix}))
		}
		o.offered = available
		available = backend.Probe{o.only: true}
	}
	tier, err := backend.Select(ceiling, pin, available)
	if err != nil {
		return nil, append(ds, unavailable(file, o.explain(err)))
	}
	if tier == backend.TierBPFLSM && o.only == "" && !pinnedAt(pin, backend.TierBPFLSM) {
		// An auto run is given tier bpflsm only for a table the plane holds (enforce-plane §2.4 condition 7, §2.10
		// condition 2): Prepare refuses one it cannot (ErrPlaneCannotHold, exit 125), and auto means the highest
		// tier that runs the contract, so it falls to tier cgroup, where the plane runs it if it fits the tier's
		// rows and the listener decides it otherwise, and says why. A pinned bpflsm keeps the refusal.
		if why := planeCannotHold(rt); why != nil {
			delete(available, backend.TierBPFLSM)
			if tier, err = backend.Select(ceiling, pin, available); err != nil {
				return nil, append(ds, unavailable(file, o.explain(err)))
			}
			ds = append(ds, Diagnostic{File: file, Code: agent.CodeUnenforced, Severity: identityWarning,
				Message: fmt.Sprintf("tier bpflsm cannot hold this contract in the decision plane (%v); running at tier %s", why, tier),
				Fix:     "narrow the fs, deny_read and exec.allow entries to run it at tier bpflsm; the run's capability matrix lists what this tier cannot enforce"})
		}
	}
	plane := o.plane
	if tier == backend.TierBPFLSM {
		plane = o.lsm
	}
	// enforce-landlock R5a, ADR 0041 D1 (a): a table with built-in deny_write targets runs where no plane decides
	// them (tier landlock, tier cgroup on the listener) with the supervisor's best-effort refusal, unless its
	// contract says fs.assurance: kernel; then a run that no plane would decide is refused here, before launch, as
	// Prepare would refuse it (landlock.Prepare, cgroup's choosePlane).
	if rt != nil && rt.DenyWriteNeedsPlane() {
		var why error
		if tier == backend.TierLandlock || plane.Mode == "" {
			why = landlock.ErrNegativeWriteNeedsPlane
		} else {
			why = planeCannotHold(rt)
		}
		if why != nil {
			return nil, append(ds, Diagnostic{File: file, Code: backend.CodeTierUnavailable, Severity: identityError,
				Message: fmt.Sprintf("tier %s cannot enforce %s without a kernel decision plane, and the contract sets fs.assurance: kernel: %v",
					tier, rt.DenyWrite[0].RuleName(), why),
				Fix: "use cgroup/bpflsm with a working decision plane, narrow fs.write to directories that contain no protected targets, " +
					"or drop fs.assurance: kernel to run with the supervisor's best-effort refusal (run_start best_effort deny_write/default)"})
		}
	}
	b, err := construct(tier, m, plane)
	if err != nil {
		return nil, append(ds, unavailable(file, err))
	}
	// A contract that leaves its tier to the machine (no tier:, or auto) was compiled at the highest tier the
	// ceiling allows, and running below that is what auto means, not a finding: every such run on a machine
	// without tier 3 printed "tier bpflsm is not available on this machine" under [tier-unavailable], the
	// code of the exit-125 refusal, on a run that went ahead (R17). The run's own capability
	// line says what its tier could do. Only a table whose contract named its tier can meet another here.
	if rt != nil && rt.Tier != "" && rt.Tier != tier && contractPinned(rt) {
		ds = append(ds, Diagnostic{File: file, Code: backend.CodeTierUnavailable, Severity: identityWarning,
			Message: fmt.Sprintf("tier %s is not available on this machine; running at %s", rt.Tier, tier),
			Fix:     "the run's capability matrix lists what this tier cannot enforce"})
	}
	// admitted follows the plane this tier runs with: tier 3's comes in o.lsm, and o.plane says nothing about it.
	if d, ok := ioUringIgnored(rt, file, tier, plane.Mode != "" && ioUringDecided()); ok {
		ds = append(ds, d)
	}
	return b, ds
}

// pinnedAt reports a pin (the contract's tier: or the machine config's concrete tier) naming t.
func pinnedAt(pin, t backend.Tier) bool { return pin == t }

// planeCannotHold is why the decision plane cannot hold rt's rows, nil when it can: exactly the check Prepare makes
// (holdablePlaneRows): over a slot's maps, the mounted-root rows below a deny_write target included, or an exec
// entry it cannot express (decide.CompilePlane, PlaneRows.WithMounts), two fs entries one file under two names
// (cgroup.PlaneHoldable), or more keyed paths than this launcher can hold a descriptor each for (PlaneRows.FitFDs,
// PlaneFDCap). A nil table is none of these.
func planeCannotHold(rt *agent.RuleTable) error {
	if rt == nil {
		return nil
	}
	_, err := holdablePlaneRows(rt)
	return err
}

// PlaneFDCap is how many descriptors this launcher can hold for a run's Landlock plan (landlock.FDBudget.Cap, 0
// when that is 0 or less), -1 only when the budget cannot be read: the cap a table's plane keys are held to besides
// the plane's own (§2.4 condition 6). A budget below the reserve is a cap of 0, not -1, so selection refuses what
// Prepare's budget would (PlaneRows.FitFDs reads a negative cap as unknown). `tego compile` reports a table over it
// (decide.PlaneDiagnostic).
func PlaneFDCap() int {
	b, err := readPlaneFDBudget()
	if err != nil {
		return -1
	}
	return max(b.Cap(), 0)
}

// readPlaneFDBudget is landlock.ReadFDBudget, a variable so tests can give PlaneFDCap a budget below its reserve.
var readPlaneFDBudget = landlock.ReadFDBudget

// planeFDCap is PlaneFDCap, a variable so tests can give selection a small budget.
var planeFDCap = PlaneFDCap

// SelectOption adds to one Select call what its caller knows and the probe cannot carry.
type SelectOption func(*selectOptions)

type selectOptions struct {
	only backend.Tier
	// plane is the decision plane's mode doctor selected for tier cgroup (Plane), zero for the fanotify fallback.
	plane cgroupenforce.PlaneSetup
	// lsm is tier bpflsm's plane (LSMPlane), zero when none was handed over; lsmErr is why there is none.
	lsm    cgroupenforce.PlaneSetup
	lsmErr error
	reason func(backend.Tier) string
	// offered is what the machine offers and this binary builds, before Only narrowed it to one tier: a pin
	// that --tier left out may be missing from it too, and a refusal then has to say why (explain).
	offered backend.Probe
}

// Only offers the selection tier t alone, as `tego run --tier` asks: t is the run's pin, a machine without
// it is refused with t named, and the run never falls to a lower tier in its place.
func Only(t backend.Tier) SelectOption { return func(o *selectOptions) { o.only = t } }

// PlaneSetup is tier cgroup's decision-plane mode, as the tier-2 backend takes it (cgroup.PlaneSetup).
type PlaneSetup = cgroupenforce.PlaneSetup

// Plane gives Select the decision plane's mode doctor selected for tier cgroup (doctor's Report.PlaneFor, with its
// answer's pin), which a tier-cgroup backend then decides its runs' opens, execs and fs mutations in, with no
// fanotify mark (docs/p0/enforce-plane.md R18, R22). The import direction is doctor -> enforce, so the choice
// crosses as a value, like the probe does. Without it tier cgroup runs on the fanotify listener.
func Plane(p PlaneSetup) SelectOption {
	return func(o *selectOptions) { o.plane = p }
}

// LSMPlane gives Select tier bpflsm's plane: the decision plane in LSM mode, as doctor's Report.PlaneFor answers for
// tier bpflsm (TIER3-PLAN T7, enforce-plane R19), or err, doctor's reason there is none (its fix included). Tier
// bpflsm is constructed only from a plane in LSM mode: without one it is not offered, and a run that pinned it is
// refused with that reason, never run at tier cgroup or in another mode.
func LSMPlane(p PlaneSetup, err error) SelectOption {
	return func(o *selectOptions) { o.lsm, o.lsmErr = p, err }
}

// errNoLSMPlane is lsmPlane's answer when the caller handed Select no plane for tier bpflsm at all.
var errNoLSMPlane = errors.New("the decision plane in LSM mode was not handed to the selection (run tego doctor)")

// lsmPlane is nil when Select holds a plane in LSM mode for tier bpflsm, else why it holds none.
func (o selectOptions) lsmPlane() error {
	switch {
	case o.lsmErr != nil:
		return o.lsmErr
	case o.lsm.Mode != ebpfbindings.PlaneLSM:
		return errNoLSMPlane
	}
	return nil
}

// Explain gives Select the reason each tier the probe leaves out is missing, internal/doctor's account of
// the same derivation the probe came from (Report.WhyNot). A refusal carries it as its fix, so the run that
// is refused says what `tego doctor` says about that tier. The import direction is doctor -> enforce, so
// the reasons cross as a function, like the probe crosses as a plain value.
func Explain(why func(backend.Tier) string) SelectOption {
	return func(o *selectOptions) { o.reason = why }
}

// why is the caller's reason tier t is missing, "" when it gave none.
func (o selectOptions) why(t backend.Tier) string {
	if o.reason == nil {
		return ""
	}
	return o.reason(t)
}

// pinnedWhy is why for a pinned tier, with the build's reason first when this binary does not build it: no
// machine can give a run that tier, so that is the reason that decides, and doctor's account listed it after
// every machine fact, last of the prerequisite tiers' reasons (docs/p0/limits-check-doctor-cli.md R32). The
// same sentence is not repeated further on.
func (o selectOptions) pinnedWhy(t backend.Tier) string {
	why := o.why(t)
	if o.reason == nil || Buildable(t) == nil {
		return why
	}
	build := fmt.Sprintf("build: tier %s %s", t, notBuiltWhy(t))
	rest := strings.Trim(strings.ReplaceAll(strings.ReplaceAll(why, "; "+build, ""), build, ""), "; ")
	if rest == "" {
		return build
	}
	return build + "; " + rest
}

// explain adds the caller's reason to a selection failure that has none. A pinned tier is explained as
// itself. "No enforcement tier" is explained by tier landlock's reasons: every tier needs everything tier
// landlock needs, and every ceiling admits landlock, so nothing was selectable only because landlock was
// not. A pin that --tier's single offer left out is refused as the conflict between two requests, naming
// both (TierConflictError), never as that pin missing, since the offer --tier made is what left it out. The
// pin can be missing from the machine as well: the refusal then also carries the pin's own reason, and offers
// no way out that meets the same refusal.
func (o selectOptions) explain(err error) error {
	var tu *backend.TierUnavailableError
	if !errors.As(err, &tu) || tu.Fix != "" {
		return err
	}
	switch {
	case tu.Pinned && o.only != "" && tu.Tier != o.only:
		c := &TierConflictError{Asked: o.only, Pinned: tu.Tier}
		if !o.offered[tu.Tier] {
			c.PinnedMissing, c.PinnedWhy = true, o.pinnedWhy(tu.Tier)
		}
		return c
	case tu.Pinned:
		tu.Fix = o.pinnedWhy(tu.Tier)
	default:
		tu.Fix = o.why(backend.TierLandlock)
	}
	return err
}

// TierConflictError is a run refused because `--tier` asked for one tier and the contract's tier: or the
// machine config's concrete tier pinned another. It is not reported as "pinned but not available", which was
// the sentence this refusal used to print about a tier the machine had. It is errors.Is ErrTierUnavailable, so
// it keeps the refusal's exit status and code.
type TierConflictError struct {
	// Asked is the tier --tier named; Pinned the tier the contract or the machine config pins, as selection
	// read it (a pin above the machine's ceiling is lowered to the ceiling).
	Asked, Pinned backend.Tier
	// PinnedMissing is true when Pinned is not on this machine either (not offered, or not built into this
	// binary), so a run without --tier is refused too. PinnedWhy is then the caller's reason it is missing
	// (Explain), "" when it gave none.
	PinnedMissing bool
	PinnedWhy     string
}

func (e *TierConflictError) Error() string {
	msg := fmt.Sprintf("--tier %s conflicts with tier %s, pinned by the contract or the machine config", e.Asked, e.Pinned)
	if e.PinnedMissing {
		msg += ", and tier " + string(e.Pinned) + " is not available on this machine either"
	}
	return msg
}

// Unwrap returns ErrTierUnavailable so callers use errors.Is.
func (e *TierConflictError) Unwrap() error { return backend.ErrTierUnavailable }

// Fix names the ways out that lead to a run: ask for what the pin says, or change the pin. When the pinned
// tier is missing here, asking for it is refused as well, so only changing the pin is offered, followed by the
// reason the pinned tier is missing, which is what `tego doctor` prints for it (R27).
func (e *TierConflictError) Fix() string {
	if e.PinnedMissing {
		why := e.PinnedWhy
		if why == "" {
			why = "tier " + string(e.Pinned) + " is not available on this machine"
		}
		return fmt.Sprintf("change that pin to %s; %s", e.Asked, why)
	}
	return fmt.Sprintf("run without --tier (or with --tier %s), or change that pin to %s", e.Pinned, e.Asked)
}

// notBuiltWhy is Buildable's refusal of t without its leading "tier t", which the caller has already said.
func notBuiltWhy(t backend.Tier) string {
	var nb *NotBuiltError
	if err := Buildable(t); errors.As(err, &nb) {
		return "is not built into this binary: " + nb.Why
	}
	return "is not built into this binary"
}

// ioUringIgnored is the warning for a contract that declares io_uring: true and runs where io_uring stays refused.
// P0-DESIGN §4.3 admits io_uring only when declared in a root tier, and ADR 0018 (5) only where the kernel decision
// plane decides the run: its socket_create sees io_uring's IORING_OP_SOCKET, which the seccomp filter cannot, and its
// path and file hooks the fs ops a submission makes past the supervisor. So tier cgroup with a plane mode admits it
// (the inherited filter's io_uring_* arms go, landlock Run.IOUring), whose unix names cgroup/connect_unix decides on
// 6.7+ and the plane's step D hooks below (TIER3-PLAN T15); tier cgroup on the fanotify fallback does not, since an io_uring submission bypasses the seccomp
// supervisor and the listener sees no socket. Compile already warns about a table it resolved to landlock
// (CodeIOUring), so this covers the tables it could not: an auto contract compiled for a root tier and run at
// whatever the machine gave it.
//
// Tier bpflsm always runs with its plane (LSMPlane), which decides the run the same way, so it admits io_uring too.
//
// admitted is a plane mode selected for the run's tier (Plane for tier cgroup, LSMPlane for tier bpflsm), whose fixed
// hook set decides every other submission (ioUringDecided; nothing is probed). At tier cgroup the plane must also hold the table's rows
// (holdablePlaneRows, the test Prepare makes, so two fs entries on one inode count): a table it cannot hold runs on
// the fanotify listener (choosePlane), where io_uring stays refused, and
// the warning says why. A tier-bpflsm run the plane cannot hold is refused outright (enforce-plane §6 E13), so it
// needs no warning here.
func ioUringIgnored(rt *agent.RuleTable, file string, tier backend.Tier, admitted bool) (Diagnostic, bool) {
	if rt == nil || rt.Contract == nil || !rt.Contract.IOUring || rt.Tier == backend.TierLandlock {
		return Diagnostic{}, false
	}
	switch {
	case tier == backend.TierBPFLSM && admitted:
		return Diagnostic{}, false
	case tier == backend.TierCgroup && admitted:
		_, err := holdablePlaneRows(rt)
		if err == nil {
			return Diagnostic{}, false
		}
		if fallbackIOUringTestHook() {
			// The run decides on the fanotify listener with no plane rows, where a test build's seam admits io_uring
			// (inheritedRun): say that, and why the plane does not decide the run.
			return Diagnostic{File: file, Code: agent.CodeIOUring, Severity: identityWarning,
				Message: fmt.Sprintf("io_uring: true is admitted at tier %s on the fanotify fallback by this test build's %s, "+
					"since the decision plane cannot hold this contract (%v): "+ioUringFallbackResidual, tier,
					envTestFallbackIOUring, err),
				Fix: "a product build never admits it here; unset " + envTestFallbackIOUring}, true
		}
		return Diagnostic{File: file, Code: agent.CodeIOUring, Severity: identityWarning,
			Message: fmt.Sprintf("io_uring: true has no effect at tier %s here; io_uring stays refused (ENOSYS): the "+
				"decision plane cannot hold this contract (%v), so the run decides through fanotify", tier, err),
			Fix: "narrow the fs, deny_read and exec entries until the plane holds them, or drop io_uring:"}, true
	}
	if tier == backend.TierCgroup && fallbackIOUringTestHook() {
		// A test build's seam (A-0018-5): the run is admitted io_uring with no plane, and its residual is said.
		return Diagnostic{File: file, Code: agent.CodeIOUring, Severity: identityWarning,
			Message: fmt.Sprintf("io_uring: true is admitted at tier %s on the fanotify fallback by this test build's %s: "+
				ioUringFallbackResidual, tier, envTestFallbackIOUring),
			Fix: "a product build never admits it here; unset " + envTestFallbackIOUring}, true
	}
	return Diagnostic{File: file, Code: agent.CodeIOUring, Severity: identityWarning,
		Message: fmt.Sprintf("io_uring: true has no effect at tier %s here; io_uring stays refused (ENOSYS): it is admitted "+
			"where a decision plane mode decides the run (tier cgroup with a mode, tier bpflsm); on the fanotify fallback "+
			ioUringFallbackResidual, tier),
		Fix: "run where doctor selects a plane mode (lsm or fmod_ret) for tier cgroup or tier bpflsm, or drop io_uring:"}, true
}

// ioUringFallbackResidual is what a submission would pass undecided on tier cgroup's fanotify fallback (ADR 0018 (5),
// PR 2): the reason io_uring is not admitted there, and what a test build that admits it leaves open.
const ioUringFallbackResidual = "cgroup/sock_create decides an inet socket made through IORING_OP_SOCKET, but nothing " +
	"decides one of another family, a unix name below 6.7 (no cgroup/connect_unix), or a file operation only the " +
	"seccomp supervisor decides (a deny_write ancestor's rename, a gate)"

// envTestFallbackIOUring is the test seam's variable (iouring_testhook.go's EnvTestFallbackIOUring), named here because
// a product build does not contain that file.
const envTestFallbackIOUring = "TEGO_TEST_FALLBACK_IOURING"

// ioUringDecided is cgroupenforce.IOUringDecided. It probes nothing: it answers true wherever a plane mode is
// selected, because every plane mode loads the same fixed hook set that decides io_uring's other submissions
// (ADR 0018 (5)), so admission is gated only on a plane mode being selected. A variable so this package's tests can
// give both answers without root.
var ioUringDecided = func() bool { return cgroupenforce.IOUringDecided() }

// Observe returns the record-only backend for an explicit --observe run (R17: never selected). It is
// given tier 1's filter to install, because a run whose supervisor is never notified records nothing.
func Observe() Backend { return observeBackend{b: observe.New(observe.Options{Filter: observeFilter})} }

const (
	identityError   = "error"
	identityWarning = "warning"
)

// sortedTiers is the probe's keys in a fixed order, so a run's diagnostics do not depend on Go's
// map iteration order.
func sortedTiers(probe backend.Probe) []backend.Tier {
	out := make([]backend.Tier, 0, len(probe))
	for t := range probe {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if ri, rj := out[i].Rank(), out[j].Rank(); ri != rj {
			return ri < rj
		}
		return out[i] < out[j]
	})
	return out
}

// contractPinned reports whether rt's contract names a concrete tier rather than leaving it to the machine.
func contractPinned(rt *agent.RuleTable) bool {
	if rt == nil || rt.Contract == nil {
		return false
	}
	t := backend.Tier(rt.Contract.Tier)
	return t != "" && t != backend.TierAuto
}

// ceilingAndPin reads the machine ceiling and the effective pin (R17): the contract's tier: when
// concrete, else the machine's concrete tier, else none.
func ceilingAndPin(m *config.Machine, rt *agent.RuleTable) (ceiling, pin backend.Tier) {
	if m != nil && m.Tier.Bounded && !m.Tier.Value.Auto && m.Tier.Value.Tier != "" {
		ceiling = backend.Tier(m.Tier.Value.Tier)
		pin = ceiling
	}
	if rt != nil && rt.Contract != nil {
		if t := backend.Tier(rt.Contract.Tier); t != "" && t != backend.TierAuto {
			pin = t
		}
	}
	return ceiling, pin
}

// construct builds the backend for a selected tier, probing what it needs (R1, R19), with plane the decision plane
// selected for that tier (tier cgroup's mode or its fallback; tier bpflsm's LSM mode, which bpflsm.New requires).
// The Buildable guard repeats Select's filter so that no path to a backend skips it.
func construct(tier backend.Tier, m *config.Machine, plane cgroupenforce.PlaneSetup) (Backend, error) {
	if err := Buildable(tier); err != nil {
		return nil, fmt.Errorf("%w: %w", backend.ErrTierUnavailable, err)
	}
	switch tier {
	case backend.TierLandlock:
		abi, err := landlock.ProbeABI()
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", backend.ErrTierUnavailable, tier, err)
		}
		return landlockBackend{b: landlock.New(landlock.Options{ABI: abi})}, nil
	case backend.TierCgroup, backend.TierBPFLSM:
		// Tier 2 is tier 1 plus kernel maps and a fanotify listener: it installs the same Landlock
		// ruleset and seccomp filter rather than reimplementing them, so the tier-1 backend is threaded
		// in as the inherited state (docs/p0/enforce-cgroup-observe.md §5 R1).
		abi, err := landlock.ProbeABI()
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", backend.ErrTierUnavailable, tier, err)
		}
		inner := landlock.New(landlock.Options{ABI: abi})
		// With a plane mode the run's plane rows ride on the run (cgroupBackend.Prepare compiles them once): the
		// Landlock plan holds every keyed path and adds its neutral rule, and the plane is filled from the
		// descriptors it holds (enforce-plane R16, R17).
		// io_uring is admitted, for a contract that declares it, only where the plane decides the run; the plane's
		// fixed hook set decides what else a submission can do (cgroupenforce.IOUringDecided, unconditional once a
		// plane mode runs, not a kernel probe; ADR 0018 (5)).
		inherit := func(ctx context.Context, rt *agent.RuleTable, run cgroupenforce.Run) (cgroupenforce.Inherited, error) {
			return inner.Prepare(ctx, rt, inheritedRun(run))
		}
		// These are the options selection can fix; the run's event sink is the one that cannot be known
		// here, because it belongs to the run and not to the machine, so Prepare completes them from the
		// RunRef (enforce-cgroup-observe.md §7 — every refusal and gap this tier produces is a ledger row).
		opts := cgroupenforce.Options{Machine: m, Inherit: inherit, Plane: plane}
		if tier == backend.TierBPFLSM {
			// Tier 3 is this backend with the plane required in LSM mode (enforce/bpflsm, enforce-plane R19).
			b, err := bpflsm.New(opts)
			if err != nil {
				return nil, fmt.Errorf("%w: %s: %w", backend.ErrTierUnavailable, tier, err)
			}
			opts.Tier = backend.TierBPFLSM
			return cgroupBackend{b: b, opts: opts}, nil
		}
		return cgroupBackend{b: cgroupenforce.New(opts), opts: opts}, nil
	// Handled after the switch: Buildable already refused every one of them.
	case backend.TierObserve, backend.TierAuto:
	}
	return nil, fmt.Errorf("%w: %s is not built into this binary", backend.ErrTierUnavailable, tier)
}

// unavailable renders a selection failure as the error diagnostic tego run prints before exit 125.
func unavailable(file string, err error) Diagnostic {
	d := Diagnostic{File: file, Code: backend.CodeTierUnavailable, Severity: identityError, Message: err.Error()}
	var tu *backend.TierUnavailableError
	var tc *TierConflictError
	switch {
	case errors.As(err, &tu):
		d.Fix = tu.Fix
	case errors.As(err, &tc):
		d.Fix = tc.Fix()
	}
	return d
}

// inheritedRun is the tier-1 run a tier-2 or tier-3 run composes (the Landlock ruleset and seccomp filter it
// inherits). With plane rows, which cgroupBackend.Prepare compiles only for a mode doctor's probe selected, the plan
// holds every keyed path and adds its neutral rule (enforce-plane R16, R17), and, where the plane's hooks include
// step C's, the filter drops the arm refusing every memfd_create on a kernel without MFD_NOEXEC_SEAL (R27). io_uring
// is admitted with a plane that decides submissions, and on the fanotify fallback only by a test build's seam
// (fallbackIOUringTestHook, A-0018-5).
func inheritedRun(run cgroupenforce.Run) landlock.Run {
	return landlock.Run{Dir: run.Dir,
		Plane: run.PlaneRows, PlaneMaps: run.PlaneRows != nil && ebpfbindings.PlaneDecidesMappings(),
		Drop: run.Drop, DropUID: run.DropUID, DropGID: run.DropGID,
		IOUring: run.PlaneRows != nil && ioUringDecided() || run.PlaneRows == nil && fallbackIOUringTestHook()}
}
