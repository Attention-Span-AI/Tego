// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"context"
	"errors"
	"fmt"
	"io"

	"golang.org/x/net/bpf"

	"github.com/attention-span-ai/tego/internal/platform/startphase"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/observe"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// The tier packages expose concrete types and never import this package (the import direction is
// enforce → tier, docs/p0/enforce-landlock.md §1); these adapters present them as Backend. A tier's
// Handle already carries the Handle and Reporter method sets, so it is returned as is.

// landlockBackend adapts *landlock.Backend.
type landlockBackend struct{ b *landlock.Backend }

var _ Backend = landlockBackend{}

func (a landlockBackend) Tier() backend.Tier        { return a.b.Tier() }
func (a landlockBackend) Capabilities() backend.Set { return a.b.Capabilities() }
func (a landlockBackend) Unwrap() *landlock.Backend { return a.b }
func (a landlockBackend) Prepare(ctx context.Context, rt *agent.RuleTable, run RunRef) (api.Handle, error) {
	defer startphase.Begin(nil, "compose")()
	h, err := a.b.Prepare(ctx, rt, landlock.Run{Dir: run.RunDir,
		Drop: run.Drop, DropUID: run.DropUID, DropGID: run.DropGID})
	if err != nil {
		return nil, err
	}
	return h, nil
}

// observeBackend adapts *observe.Backend.
type observeBackend struct{ b *observe.Backend }

var _ Backend = observeBackend{}

// Tier is backend.TierObserve.
func (a observeBackend) Tier() backend.Tier { return a.b.Tier() }

// Capabilities is the empty observe column.
func (a observeBackend) Capabilities() backend.Set { return a.b.Capabilities() }

// Prepare returns the observe handle: no ruleset, the record filter; the run reference is not needed.
func (a observeBackend) Prepare(ctx context.Context, rt *agent.RuleTable, _ RunRef) (api.Handle, error) {
	h, err := a.b.Prepare(ctx, rt)
	if err != nil {
		return nil, err
	}
	return h, nil
}

// observeFilter is the filter an observe run installs: tier 1's, for this build's architecture. It is
// the ABI>=3 form on purpose. Below ABI 3 tier 1 adds R2's truncation refusals, which stand in for a
// Landlock check the kernel lacks; an observe run applies no Landlock ruleset, so it has nothing for them to
// stand in for, and it carries no memfd, root-tier, signal-scope or process-scope arm either. It is not a
// filter that refuses nothing: the confinement arms every filter carries stay, so an observe run still gets
// ENOSYS for a foreign arch, the x32 bit, io_uring_*, openat2, clone3 and open_by_handle_at (R10), EPERM for
// TIOCSTI and TIOCLINUX, and EPROTONOSUPPORT for an IPPROTO_MPTCP socket (E30). Where the contract decides
// datagrams (frames) it carries R11d's pending-frame arms, as tier 1 does: they only notify, and the supervisor's
// pending-frame decisions, which an observe run records and continues, need them to see what they decide.
func observeFilter(full, frames bool) ([]bpf.RawInstruction, error) {
	insts, err := landlock.BuildFilter(landlock.NativeArch(), full, frames)
	if err != nil {
		return nil, err
	}
	raw, err := bpf.Assemble(insts)
	if err != nil {
		return nil, fmt.Errorf("observe: assembling the record filter: %w", err)
	}
	return raw, nil
}

// cgroupBackend adapts *cgroup.Backend, the tier-2 backend. Its handle also runs the fanotify listener
// for the length of the run; the facade starts it by type-asserting Listener on the handle, which keeps
// the Backend interface the same for every tier.
//
// It keeps the Options Select fixed as well as the backend built from them, because the tier's event
// sink is a per-run value (RunRef.Events) and cgroup.Options is a per-construction one: a run's backend
// is built in Prepare from both halves. The pre-built b answers Tier and Capabilities, which are the
// tier's static row and depend on no option.
type cgroupBackend struct {
	b    *cgroupenforce.Backend
	opts cgroupenforce.Options
	// newRun builds the run-scoped backend; nil means cgroup.New. It is a seam because the sink is the
	// one option whose absence is silent — nothing about the returned Handle reveals it — so this
	// package's own test reads back the Options a run is prepared with instead.
	newRun func(cgroupenforce.Options) *cgroupenforce.Backend
}

var _ Backend = cgroupBackend{}

func (a cgroupBackend) Tier() backend.Tier        { return a.b.Tier() }
func (a cgroupBackend) Capabilities() backend.Set { return a.b.Capabilities() }

// runOptions is what one run's tier-2 backend is built from: the options Select fixed for this machine,
// plus this run's own event sink. Without the sink the listener's refusals and §7 gaps go to an
// unexported counter nothing reads, so the run enforces in the kernel and reports nothing.
func (a cgroupBackend) runOptions(run RunRef) cgroupenforce.Options {
	o := a.opts
	o.Events = run.Events
	return o
}

// planeMounts is the launcher's mountpoints the plane keys a row on below a deny_write target; a variable so a test
// can hand selection and Prepare a mount table of its own, or make it unreadable.
var planeMounts func() ([]string, error)

func planeRowsAt(rt *agent.RuleTable, pointsOf func() ([]string, error)) (*decide.PlaneRows, error) {
	rows, err := decide.CompilePlane(rt)
	if err != nil || len(rt.DenyWrite) == 0 {
		return rows, err
	}
	if pointsOf == nil {
		pointsOf = cgroupenforce.ReadMounts().Points
	}
	points, err := pointsOf()
	if err != nil {
		return nil, err
	}
	return rows.WithMounts(rt, points)
}

// holdablePlaneRows is planeRows the plane can hold now: the rows Prepare hands over, the test ioUringIgnored
// makes of whether a tier cgroup run keeps its plane, and the one Select makes before giving an auto run tier bpflsm
// (planeCannotHold), so selection and Prepare never disagree on a table the plane can hold. Prepare checks it, not only choosePlane, because tier 1 is
// composed from these rows, and a filter built for a plane (io_uring admitted, the memfd arm dropped) cannot be
// rebuilt inside cgroup.Prepare once choosePlane falls back to the listener: rows the plane cannot hold are never handed
// over, so tier 1 keeps both arms (rows that stop holding before choosePlane looks again are
// cgroupenforce.ErrPlaneRowsChanged, and Prepare composes tier 1 again without them). Two fs entries on one inode fail it (cgroupenforce.PlaneHoldable), and so do keys this launcher
// cannot hold a descriptor each for, which would meet EMFILE in the Landlock plan (enforce-plane §2.4 condition 7):
// tier cgroup runs such a table on the listener, tier bpflsm refuses it, as over the maps.
func holdablePlaneRows(rt *agent.RuleTable) (*decide.PlaneRows, error) {
	mounts := cgroupenforce.ReadMounts()
	points := planeMounts
	if points == nil {
		points = mounts.Points
	}
	return holdablePlaneRowsAt(rt, mounts, points)
}

func holdablePlaneRowsAt(rt *agent.RuleTable, mounts *cgroupenforce.MountSnapshot, pointsOf func() ([]string, error)) (*decide.PlaneRows, error) {
	rows, err := planeRowsAt(rt, pointsOf)
	if err != nil {
		return nil, err
	}
	if err := cgroupenforce.PlaneHoldableAt(rows, mounts); err != nil {
		return nil, err
	}
	if err := rows.FitFDs(planeFDCap()); err != nil {
		return nil, err
	}
	return rows, nil
}

func (a cgroupBackend) Prepare(ctx context.Context, rt *agent.RuleTable, run RunRef) (api.Handle, error) {
	opts := a.runOptions(run)
	crun := cgroupRun(run)
	crun.Mounts = cgroupenforce.ReadMounts()
	// ADR 0048 (3) P2: a run whose execs a command rule or the exec gate decides asks for them to be pinned. Prepare
	// pins the slot only when a plane decides the run and the kernel can hold and record a pin (Handle.ExecPins).
	crun.ExecPin = rt.ExecFactsDecided()
	if opts.Plane.Mode != "" && rt != nil && rt.Tier == opts.RunTier() {
		// Compiled once for both halves: the inherited Landlock plan holds and pins the keyed paths, and the plane
		// is filled from the same rows. A table the plane cannot hold is left to cgroup.Prepare, which runs it on
		// the fanotify listener and says why at tier cgroup (choosePlane), and refuses it at tier bpflsm. The mounted
		// roots below a deny_write target are keyed too (enforce-plane R12).
		endCompile := startphase.Begin(opts.Phase, "plane.compile")
		rows, err := holdablePlaneRowsAt(rt, crun.Mounts, crun.Mounts.Points)
		endCompile()
		if err != nil {
			crun.PlaneErr = err
		} else {
			crun.PlaneRows = rows
		}
	}
	h, err := a.prepareRun(ctx, rt, run, crun)
	if err != nil && crun.PlaneRows != nil && errors.Is(err, cgroupenforce.ErrPlaneRowsChanged) {
		// The rows held when holdablePlaneRows checked them and no longer did when choosePlane checked again, a
		// hard link made while tier 1 was composed. That filter was built for a plane (io_uring admitted, the memfd
		// arm dropped) and is closed with the failed Prepare; tier 1 is composed again without the rows, so the run
		// falls back to the listener with both arms, as a table that failed the first check does. Once only: the
		// second attempt hands no rows over, so choosePlane cannot answer it this way again.
		crun.PlaneRows, crun.PlaneErr = nil, err
		h, err = a.prepareRun(ctx, rt, run, crun)
	}
	return h, listenerAliasRemedy(err, rt, crun.Mounts)
}

// listenerAliasRemedy suggests a plane only when it can hold the whole contract.
// A detached part or another holdability failure must never recommend a tier that also refuses.
func listenerAliasRemedy(err error, rt *agent.RuleTable, mounts *cgroupenforce.MountSnapshot) error {
	if !errors.Is(err, cgroupenforce.ErrListenerAlias) {
		return err
	}
	if _, why := holdablePlaneRowsAt(rt, mounts, mounts.Points); why != nil {
		return err
	}
	return fmt.Errorf("%w; this contract can use a working decision-plane mode at tier cgroup or tier bpflsm on a kernel that provides it, which holds whole-tree aliases", err)
}

// prepareRun composes tier 1 for crun and prepares the run's tier-2 backend over it: one attempt of Prepare.
func (a cgroupBackend) prepareRun(ctx context.Context, rt *agent.RuleTable, run RunRef, crun cgroupenforce.Run) (api.Handle, error) {
	// cgroup.New opens nothing — it normalises defaults and stores them — so a backend per run costs a
	// struct, and it is the only place both halves of the options are known.
	newRun := a.newRun
	if newRun == nil {
		newRun = cgroupenforce.New
	}
	opts := a.runOptions(run)
	endCompose := startphase.Begin(opts.Phase, "compose")
	inherited, err := composeFirst(ctx, rt, crun, &opts)
	endCompose()
	if err != nil {
		return nil, err
	}
	h, err := newRun(opts).Prepare(ctx, rt, crun)
	if err != nil {
		if inherited != nil {
			err = errors.Join(err, inherited.Close())
		}
		return nil, err
	}
	if inherited != nil {
		return cgroupHandle{Handle: h, inherited: inherited}, nil
	}
	return h, nil
}

// cgroupRun is the tier-2 backend's view of the run. Resolvers and StageExe are the two fields only tier 2
// reads, and each one it is not handed goes wrong in a way nothing reports: without the resolvers every DNS
// query the supervisor admits and relays is refused with EPERM in the kernel, and without the stage binary a
// launcher that execs anything but its own image as the stage has the tier's helpers exec the wrong file.
func cgroupRun(run RunRef) cgroupenforce.Run {
	return cgroupenforce.Run{
		ID: run.ID, Agent: run.Agent, CgroupID: run.CgroupID,
		CgroupPath: run.CgroupPath, CgroupMount: run.CgroupMount,
		Dir: run.RunDir, Contract: run.Contract,
		Resolvers: run.Resolvers, StageExe: run.StageExe, Log: run.Log,
		Drop: run.Drop, DropUID: run.DropUID, DropGID: run.DropGID,
	}
}

// composeFirst builds the tier-1 ruleset and filter a tier-2 run inherits before tier 2's own Prepare
// runs, and rewrites opts.Inherit to hand that result over as it is. When cgroup.Prepare installed its
// fanotify marks before its Inherit step, composing tier 1, which opens every exec entry to read its
// PT_INTERP (agent.ReadInterp, O_RDONLY), waited on this launcher's own listener, not yet started: a root
// `tego run --tier cgroup` in the KVM guest stalled exactly there. The marks are Arm's now (ADR 0021 (2)),
// after the child stage's exec, so no Prepare step can wait on them; composing first is kept, since it also
// refuses a table before any tier-2 kernel state exists.
//
// A table tier 2 refuses gets nothing composed: cgroup.Prepare's precondition answers it, with ErrTier,
// before any kernel state exists. The returned closer releases the composed state until a Handle takes
// it over; nil means nothing was composed, or nothing composed holds anything to release.
func composeFirst(ctx context.Context, rt *agent.RuleTable, run cgroupenforce.Run, opts *cgroupenforce.Options) (io.Closer, error) {
	if opts.Inherit == nil || rt == nil || rt.Tier != opts.RunTier() {
		return nil, nil
	}
	inh, err := opts.Inherit(ctx, rt, run)
	if err != nil {
		return nil, fmt.Errorf("cgroup: compose the inherited tier-1 state: %w", err)
	}
	opts.Inherit = func(context.Context, *agent.RuleTable, cgroupenforce.Run) (cgroupenforce.Inherited, error) {
		return inh, nil
	}
	if closer, ok := inh.(io.Closer); ok {
		return closer, nil
	}
	return nil, nil
}

// cgroupHandle is a tier-2 handle together with the tier-1 state composed for it, which it now owns:
// cgroup.Handle reads the inherited ruleset and filter but never closes them, so the Landlock ruleset fd
// and the O_PATH fds held for the run outlived it. Every method the facade asserts — RunListener, BPFHash,
// Capabilities — is the tier-2 handle's own; only Close adds the inherited state.
type cgroupHandle struct {
	*cgroupenforce.Handle
	inherited io.Closer
}

// The tier-2 handle is what the runtime's DNS worker hands a TTL refresh to, bare or wrapped with the tier-1
// state it composed, whose method set is promoted from the embedded handle.
var (
	_ NetRefresher            = cgroupHandle{}
	_ ListenerDevicesReporter = cgroupHandle{}
	_ NetRefresher            = (*cgroupenforce.Handle)(nil)
	// and the supervisor reads the kernel's decision on a relayed connect from it (KernelNetReader).
	_ KernelNetReader = cgroupHandle{}
	_ KernelNetReader = (*cgroupenforce.Handle)(nil)
	// and the errno its programs refuse a datagram with, which the supervisor answers in their place (KernelDatagramReader).
	_ KernelDatagramReader = cgroupHandle{}
	_ KernelDatagramReader = (*cgroupenforce.Handle)(nil)
	// and is armed after the child stage's exec (Armer, ADR 0021 (2)).
	_ api.Armer = cgroupHandle{}
	_ api.Armer = (*cgroupenforce.Handle)(nil)
	// and its listener leaves the line of an exec's refused open to the supervisor (SupervisorExecLines).
	_ SupervisorExecLines = cgroupHandle{}
	_ SupervisorExecLines = (*cgroupenforce.Handle)(nil)
	// and names the decision plane that decides it (DecisionPlaneReporter, TIER3-PLAN T9 and T13).
	_ DecisionPlaneReporter = cgroupHandle{}
	_ DecisionPlaneReporter = (*cgroupenforce.Handle)(nil)
	_ PlaneFilterer         = cgroupHandle{}
	_ PlaneFilterer         = (*cgroupenforce.Handle)(nil)
	// and hands the runtime its plane slot's fail-closed counters at run end (PlaneCounterReporter).
	_ PlaneCounterReporter = cgroupHandle{}
	_ PlaneCounterReporter = (*cgroupenforce.Handle)(nil)
	// and says which files its fs rows were written at (PlaneKeyedReporter), which an adoption asks.
	_ PlaneKeyedReporter = cgroupHandle{}
	_ PlaneKeyedReporter = (*cgroupenforce.Handle)(nil)
	// and sums the skip counters of the shared programs the run's rules rely on (SkipCounter, ADR 0148).
	_ SkipCounter = cgroupHandle{}
	_ SkipCounter = (*cgroupenforce.Handle)(nil)
)

// ProgramSkips is one reading of the skip counters of the shared programs a run's rules rely on (SkipCounter); the
// backend declares it, since that package may not import this one.
type ProgramSkips = cgroupenforce.ProgramSkips

// PlaneCount is one counter of a run's plane slot (PlaneCounterReporter): Why is its record.GapPlane* name, Count its
// value. The plane's backend declares it, since that package may not import this one.
type PlaneCount = cgroupenforce.PlaneCount

// PlaneKeyed is one file a run's fs row is written at (PlaneKeyedReporter); the plane's backend declares it.
type PlaneKeyed = cgroupenforce.PlaneKeyed

// DenyReadFrozen is the directories the inherited tier-1 ruleset listed once at launch for its deny_read entries
// (landlock.Handle.DenyReadFrozen): a root tier installs that ruleset as composed (enforce-cgroup-observe §5 R1), so
// run_start names them at every tier that builds one (GAPS A12). nil when the inherited state lists none.
func (h cgroupHandle) DenyReadFrozen() []string {
	if f, ok := h.inherited.(interface{ DenyReadFrozen() []string }); ok {
		return f.DenyReadFrozen()
	}
	return nil
}

// Close releases the tier-2 state, then the tier-1 state it inherited. Both halves are idempotent.
func (h cgroupHandle) Close() error {
	return errors.Join(h.Handle.Close(), h.inherited.Close())
}
