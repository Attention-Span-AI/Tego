// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/net/bpf"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/startphase"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// Inherited is the tier-1 state a tier-2 run still installs: the Landlock ruleset the child applies and the
// seccomp filter it loads with NEW_LISTENER. Tier 2 composes them rather than reimplementing them (§1, §5 R1)
// and rather than importing enforce/landlock, which backends never do — the caller supplies them through
// Options.Inherit, so the dependency points at the composition root instead of sideways between backends.
type Inherited interface {
	// LandlockRuleset returns the ruleset fd to apply in the child stage, or ok=false when there is none.
	LandlockRuleset() (fd int, ok bool)
	// SeccompFilter returns the classic-BPF program to install, or ok=false when there is none.
	SeccompFilter() (prog []bpf.RawInstruction, ok bool)
}

// Options configures New. The zero value is production: real kernel objects, the default bpf filesystem, the
// §6 E16 deadline, and no inherited tier-1 state.
type Options struct {
	// Machine is the effective machine config; record.ringbuf is read from it (§5 R16). Nil uses the
	// built-in defaults.
	Machine *config.Machine
	// BPFFS is the bpf filesystem pins live under; empty means DefaultBPFFS.
	BPFFS string
	// StateDir holds the build lock and the slot table; empty means the verified /run/tego (ADR 0034).
	StateDir string
	// FanotifyDeadline is the per-decision deadline; zero means DefaultFanotifyDeadline.
	FanotifyDeadline time.Duration
	// Events receives the refusal and gap events this backend produces; nil drops them and counts it.
	Events Emitter
	// Inherit supplies the tier-1 ruleset and filter a tier-2 run still installs. Nil means the handle
	// reports none, which leaves file and exec enforcement to fanotify and the kernel maps alone.
	Inherit func(ctx context.Context, rt *agent.RuleTable, run Run) (Inherited, error)
	// Plane is the decision plane's mode doctor selected for tier cgroup (Report.PlaneFor): with a mode, a run's
	// opens, execs and fs mutations are decided by the plane and no fanotify mark is placed (plane.go,
	// docs/p0/enforce-plane.md R18, R22); the zero value is the fanotify fallback.
	Plane PlaneSetup
	// Tier is the tier this backend is: zero or TierCgroup for tier 2; TierBPFLSM for tier 3, which
	// internal/runtime/enforce/bpflsm sets (enforce-plane R19, TIER3-PLAN T7). Tier 3 is this backend with the plane
	// required in LSM mode: Prepare refuses another mode and a table the plane cannot hold, where tier 2 runs such a
	// table on the fanotify listener, since tier 3 has no listener to fall to (§6 E13, I7).
	Tier backend.Tier
	// Phase receives the duration of each step of Prepare and of Arm ("prepare.load", "arm", ...), for the
	// start-latency budget (enforce-plane §10). Nil means startphase.Default, which is nil in a product build.
	Phase startphase.Sink
	// Hash overrides the build identity; empty means the hash of the embedded objects. Tests set it to
	// exercise the pin and lock protocol without loading anything.
	Hash string
	// Now is the clock every event's wall-clock timestamp comes from; nil means time.Now. Kernel ordering
	// never uses it (§6 E20).
	Now func() time.Time

	// newKernel replaces the whole kernel-side half. It is unexported because it exists for this package's
	// own tests, which exercise Prepare's ordering, unwinding and teardown without privilege; production
	// always uses newBPFKernel.
	//
	// It may return a non-nil value together with an error: everything a loader creates is pinned as it is
	// created, so a load that failed part way still owns kernel state, and attachKernel registers that
	// value's undo before it looks at the error (§7, §8 I10).
	newKernel func(ctx context.Context, h *Handle) (kernel, error)
	// carriedSlots replaces the read of the slots the build's pinned run set carries (pinnedRunSetSlots), which
	// New defaults to none whenever newKernel is replaced: a test's kernel pins nothing.
	carriedSlots func(maps string) (map[uint32]bool, error)
	// startTimer replaces the exec of the build's linger timer (Handle.startTimer), so a test sees when a last
	// launcher out would start one.
	startTimer func(hash string) error
	// timerProcess replaces the look at /proc that tells whether a pid is build hash's timer (isTimerProcess), so a
	// test can stand a live timer up without root.
	timerProcess func(pid int, hash string) bool
	// lastOutPause replaces leaveBuild's wait before it asks lastOut again, so a test can release a probe's hold
	// in it.
	lastOutPause func()
	// trimRings replaces the exec of the removal of a slot's rings above the pool (Handle.parkRings).
	trimRings func(hash string) error
	// newListener replaces the fanotify group for the same reason.
	newListener func(h *Handle) (*fanotifyListener, error)
	// planeHeld replaces the inherited state's held-descriptor lookup (Inherited's PlaneHeld) for the tests whose
	// inherited state is none.
	planeHeld heldFD
	// planeWrap wraps the loaded plane a run clears and fills its slot through, so a root test can leave a slot's
	// rows behind as a launcher that died would (TestPlaneStaleRowsOfTheSlotsLastRunAreAbsent).
	planeWrap func(planeKernel) planeKernel
	// selfCgroup names this process's own cgroup, relative to the run's cgroup2 mount, which is where the
	// supervisor's relayed unix connects come from (Attach, §5 R7). Nil reads /proc/self/cgroup; the tests
	// that fake the mount give a path under it.
	selfCgroup func() (string, error)
}

// Backend is the tier-2 backend. It holds no kernel state until Prepare and is safe for concurrent use; a
// Handle owns everything a run creates.
type Backend struct {
	opts Options
}

// New returns the tier-2 backend. It opens nothing.
func New(opts Options) *Backend {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.FanotifyDeadline <= 0 {
		opts.FanotifyDeadline = DefaultFanotifyDeadline
	}
	if opts.BPFFS == "" {
		opts.BPFFS = DefaultBPFFS
	}
	if opts.newKernel != nil && opts.carriedSlots == nil {
		opts.carriedSlots = func(string) (map[uint32]bool, error) { return nil, nil }
	}
	if opts.newKernel != nil && opts.trimRings == nil {
		opts.trimRings = func(string) error { return nil } // a test's kernel pins no outer to trim
	}
	return &Backend{opts: opts}
}

// Tier is backend.TierCgroup, or backend.TierBPFLSM for the backend Options.Tier makes tier 3.
func (b *Backend) Tier() backend.Tier { return b.opts.RunTier() }

// RunTier is the tier these options make a backend: Tier, with the zero value tier 2.
func (o Options) RunTier() backend.Tier {
	if o.Tier == backend.TierBPFLSM {
		return backend.TierBPFLSM
	}
	return backend.TierCgroup
}

// tier3 reports whether these options make tier bpflsm's backend.
func (o Options) tier3() bool { return o.RunTier() == backend.TierBPFLSM }

// Capabilities is the static column of spec/backend/CAPABILITIES.md for this backend's tier. A run's own set can be
// narrower; the Handle reports that one.
func (b *Backend) Capabilities() backend.Set { return backend.Matrix(b.Tier()) }

// RingbufBytes returns the validated ring-buffer size for this machine config. BPF_MAP_TYPE_RINGBUF requires
// a power-of-two multiple of the page size, and Prepare checks it before creating any map so a bad value is
// ErrRingbufSize with its own message rather than an opaque verifier rejection (§5 R16, §6 E28).
func (b *Backend) RingbufBytes() (uint32, error) {
	size := int64(config.Builtin().Record.Ringbuf.Value)
	if b.opts.Machine != nil {
		size = int64(b.opts.Machine.Record.Ringbuf.Value)
	}
	return validateRingbuf(size)
}

// ringBudget is bpf.ring_budget from the machine config, the built-in default without one.
func (b *Backend) ringBudget() uint64 {
	if b.opts.Machine != nil {
		return uint64(b.opts.Machine.BPF.RingBudget.Value)
	}
	return uint64(config.Builtin().BPF.RingBudget.Value)
}

// CaptureRingMin is the smallest record.ringbuf a run that captures with uprobes accepts: two of the largest
// record uprobe_ssl reserves (sizeof(tego_ev_ssl), its data at TEGO_SSL_CHUNK_MAX, plus the ring's 8-byte
// record header), rounded up to a power of two, 128 KiB. The probe reserves a whole class record and has no
// smaller fallback, so a smaller ring could never take a chunk of the largest class (§5 R16).
var CaptureRingMin = captureRingMin(ebpfbindings.SSLEventSize)

func captureRingMin(event int) uint32 {
	need := uint32(2 * (event + 8))
	m := uint32(1)
	for m < need {
		m <<= 1
	}
	return m
}

// validateRingbuf applies the kernel's two requirements plus the bounds a 32-bit max_entries imposes.
func validateRingbuf(size int64) (uint32, error) {
	page := int64(os.Getpagesize())
	switch {
	case size <= 0:
		return 0, fmt.Errorf("%w: %d bytes", ErrRingbufSize, size)
	case size > config.RingbufMax:
		return 0, fmt.Errorf("%w: %d bytes exceeds the map's 32-bit size", ErrRingbufSize, size)
	case size%page != 0:
		return 0, fmt.Errorf("%w: %d bytes is not a multiple of the %d-byte page", ErrRingbufSize, size, page)
	case size&(size-1) != 0:
		return 0, fmt.Errorf("%w: %d bytes is not a power of two", ErrRingbufSize, size)
	default:
		return uint32(size), nil
	}
}

// Prepare builds every piece of kernel state one run needs and returns the Handle that owns it. The order is
// the one §4 specifies, and every step registers its own undo so a failure anywhere leaves nothing behind
// (§8 I10):
//
//  1. validate the table and the ring-buffer size before anything is created;
//  2. resolve the build identity and assert the bpf filesystem is really mounted (§6 E30);
//  3. take the shared build lock and allocate the run's slot (§5 R12, §6 E12, E21);
//  4. compile the rule table into map rows, and fail on a table that cannot fit (§7);
//  5. load and pin the objects, or adopt them from the build's pins when another launcher left them whole,
//     populate the verdict maps, and place the run's rings under the host's ring budget (ADR 0026);
//  6. create the fanotify group, with no mark yet, when a mount holds rules (§5 R8);
//  7. compose the inherited tier-1 ruleset and filter (§1).
//
// The run-set row and the marks are not Prepare's: Arm places them after the child stage's execve (ADR 0021
// (2)). Prepare is not idempotent: a caller retries the whole run, never Prepare alone. On success the caller
// owes the Handle three things: RunListener, started in the run's errgroup; Arm, once the stage has reported
// and before the agent is acked; and Close when the run ends — the marks Arm places are live from then on, and
// openers wait on them until RunListener answers or Close removes them.
func (b *Backend) Prepare(ctx context.Context, rt *agent.RuleTable, run Run) (_ *Handle, err error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("cgroup: prepare cancelled: %w", err)
	}
	if rt == nil {
		return nil, ErrNoTable
	}
	defer startphase.Begin(b.opts.Phase, "prepare")()
	// The table must describe a tier-2 run, because Evaluate and every reader of rt.Tier answer in that
	// tier's semantics. Compile resolves tier: auto to the machine's ceiling, so an auto contract arrives
	// here only because the runtime restamps the table with the tier Select chose (agent.RuleTable.AtTier,
	// agent-contract.md R14); a table naming another tier is a caller that skipped that, refused rather
	// than enforced in the wrong tier's terms.
	if rt.Tier != b.Tier() {
		return nil, fmt.Errorf("%w: table says %q, this backend is tier %s", ErrTier, rt.Tier, b.Tier())
	}
	if b.opts.tier3() {
		// Tier 3 is the plane in LSM mode and nothing else: settled before anything exists, so a refusal leaves
		// no kernel state and no held slot behind (enforce-plane R19, §6 E13).
		if err := tier3Plane(b.opts.Plane, rt, &run); err != nil {
			return nil, err
		}
	}
	// Arm keys the run-set row on the run's cgroup id: a run with none is refused now, before anything exists,
	// rather than at the arming point.
	if run.CgroupID == 0 {
		return nil, fmt.Errorf("%w: run %s has no cgroup id", ErrNotPrepared, run.ID)
	}
	ringbuf, err := b.RingbufBytes()
	if err != nil {
		return nil, err
	}
	// A deny_read entry's submounts are marked from the mount table; one that cannot be read would leave a file
	// on a tmpfs mounted beneath the denied tree readable with no event, so the run is refused (R8, I7). The
	// policy is the fanotify listener's alone, and a tier-3 run never has a listener: the plane decides its opens
	// and execs in the kernel with no fallback (tier3Plane refuses a table it cannot hold), so it builds none, and
	// an unreadable table refuses it only where a deny_write target needs mount rows (enforce-plane R12). A
	// tier-2 run builds the policy even with a plane mode set, since prepare-plane may still fall back to the
	// listener.
	pol := &policy{}
	if !b.opts.tier3() {
		pol = newPolicy(rt, run.CgroupPath)
		if pol.mountErr != nil {
			return nil, pol.mountErr
		}
	}

	h := &Handle{
		opts:       b.opts,
		run:        run,
		ringbuf:    ringbuf,
		ringBudget: b.ringBudget(),
		// A capture ring only for a run whose capture is uprobe: the probes shared by the build's runs emit only
		// into a ring that exists, so a capture: off or forwarder run's TLS plaintext is written nowhere, and
		// record: off places no probe (ADR 0026 (3), capture-derive R4).
		wantCapture: rt.Capture == agent.CaptureUprobe && rt.Record != agent.RecordOff,
		policy:      pol,
		recordMode:  recordModeOf(rt.Record),
	}
	// A capture ring must hold the largest chunk uprobe_ssl reserves, twice, or every chunk of that class is
	// dropped as ring-buffer-drop: refused here, as a configuration error, before anything exists (§5 R16).
	if h.wantCapture && ringbuf < CaptureRingMin {
		return nil, fmt.Errorf("%w: capture: uprobe needs record.ringbuf of at least %d bytes, and it is %d",
			ErrRingbufSize, CaptureRingMin, ringbuf)
	}
	// Every step appends its undo; a failure runs them in reverse. A cleanup that itself fails is joined
	// onto the original error rather than discarded, so a leak is never silent — the first error still
	// reads first, which is what a launcher prints (§4: errors joined, not first-fail).
	defer func() {
		if h.prepared {
			return
		}
		if cleanup := h.unwind(); cleanup != nil {
			err = errors.Join(err, fmt.Errorf("cgroup: cleanup after a failed prepare: %w", cleanup))
		}
	}()

	if h.hash, err = b.buildHash(); err != nil {
		return nil, err
	}
	if h.pins, err = newPinLayout(b.opts.BPFFS, h.hash); err != nil {
		return nil, err
	}
	// The build lock and the slot table live only in the verified /run/tego (ADR 0034); a directory that
	// cannot be trusted refuses the run rather than split them per user, and so do pins under the host's bpf
	// filesystem with a state directory of the caller's own (openState).
	state, err := openState(b.opts.BPFFS, b.opts.StateDir)
	if err != nil {
		return nil, err
	}
	endLockSlot := startphase.Begin(b.opts.Phase, "prepare.lock-slot")
	if h.lock, err = acquireBuildLockIn(state, h.hash); err != nil {
		_ = state.Close()
		return nil, err
	}
	h.undo(func() error { return h.lock.Close() })
	h.rearmExpired()

	if h.slots, err = openSlotTableIn(state, h.hash); err != nil {
		return nil, err
	}
	h.undo(func() error { return h.slots.close() })
	// A slot a run-set row still carries is not handed out (ADR 0026 (6)): read from the build's pins, if it has
	// any yet, before anything of this run is loaded. acquire reads it under the slot table's lock, as
	// purgeDeadSlots does: a launcher that inserted its row and died after an earlier read counts.
	carriedOf := b.opts.carriedSlots
	if carriedOf == nil {
		carriedOf = pinnedRunSetSlots
	}
	if h.slot, h.gen, err = h.slots.acquireGen(func() (map[uint32]bool, error) { return carriedOf(h.pins.Maps) }); err != nil {
		return nil, err
	}
	h.hasSlot = true
	h.undo(h.releaseSlotAndPark)
	endLockSlot()

	endRules := startphase.Begin(b.opts.Phase, "prepare.rules")
	// The plane is chosen first: a run it decides gets no unix row pair for a file its name entries decide alone
	// (BuildRuleMaps, unixPlane).
	if err = h.choosePlane(rt); err != nil {
		return nil, err
	}
	if h.rules, err = BuildRuleMaps(rt, h.slot, run.Resolvers, h.unixPlane()); err != nil {
		return nil, err
	}
	if h.rules.Control, err = BuildNetworkControl(rt, h.slot, h.gen, len(h.rules.Rules)); err != nil {
		return nil, err
	}
	if h.rules.Control != nil {
		h.rules.Rules = append(h.rules.Rules, h.rules.Control.Rules...)
	}
	h.timelineNext = uint32(len(h.rules.Timelines))
	h.table = rt
	endRules()

	endLoad := startphase.Begin(b.opts.Phase, "prepare.load")
	if err := h.attachKernel(ctx); err != nil {
		return nil, err
	}
	endLoad()
	endFan := startphase.Begin(b.opts.Phase, "prepare.fanotify")
	if err := h.startFanotify(); err != nil {
		return nil, err
	}
	endFan()
	endInherit := startphase.Begin(b.opts.Phase, "prepare.inherit")
	if b.opts.Inherit != nil {
		if h.inherited, err = b.opts.Inherit(ctx, rt, run); err != nil {
			return nil, fmt.Errorf("cgroup: compose the inherited tier-1 state: %w", err)
		}
	}
	endInherit()
	endFill := startphase.Begin(b.opts.Phase, "prepare.fill")
	if err := h.fillPlane(rt); err != nil {
		return nil, err
	}
	endFill()
	endFilter := startphase.Begin(b.opts.Phase, "prepare.filter")
	if err := h.preparePlaneFilter(); err != nil {
		return nil, err
	}
	endFilter()
	h.prepared = true
	return h, nil
}

// BuildFix is the one remedy for a binary that cannot run this tier: one without the BPF objects this tier
// loads. internal/runtime/enforce's Buildable, and through it `tego doctor`'s fix line and `tego run`'s
// refusal, give this same string, so one binary never names two remedies for one condition. How the binary is
// linked does not matter to the tier since ADR 0021 (4). The bpf2go output is committed (bpf/README.md), so
// the tagged build needs no clang and no `make gen`; `make gen` only regenerates that output after an edit
// under bpf/.
const BuildFix = "use a tego built with the BPF objects: `make build` or `make build-bpf` " +
	"(go build -tags tegobpf; the objects are committed, so it needs no clang or `make gen`; bpf/README.md)"

// buildHash resolves the build identity: the hash of the embedded objects, or the override a test supplied.
// A binary built without the objects reports ErrProgramLoad naming the fix rather than failing obscurely.
func (b *Backend) buildHash() (string, error) {
	if b.opts.Hash != "" {
		return b.opts.Hash, nil
	}
	hash, err := bpfHash()
	if err != nil {
		return "", fmt.Errorf("%w: %w (%s)", ErrProgramLoad, err, BuildFix)
	}
	return hash, nil
}

// The method set internal/runtime/enforce requires of a Handle, asserted here rather than imported: the
// import direction is enforce → this package, so a signature drift has to fail on this side (§1, REPO-LAYOUT).
var _ interface {
	LandlockRuleset() (fd int, ok bool)
	SeccompFilter() (prog []bpf.RawInstruction, ok bool)
	Attach(cgroupID uint64) error
	Detach() error
	Close() error
	Capabilities() backend.Set
} = (*Handle)(nil)

// undoStep is one registered cleanup.
type undoStep func() error

// Handle is one run's prepared tier-2 state: the pins and links, the slot, the map rows, the fanotify group
// and the inherited tier-1 state. It owns every descriptor it opened, and Close is the only thing that closes
// them. Detach and Close are idempotent and safe after a partial Prepare (§4, §8 I10).
type Handle struct {
	opts Options
	run  Run

	hash    string
	pins    pinLayout
	lock    *buildLock
	slots   *slotTable
	slot    uint32
	hasSlot bool
	// gen is the slot's epoch for this run (slotTable.acquireGen): Run.Gen, the gen every row, record and the slot's
	// plane header carry.
	gen uint32
	// ringbuf is record.ringbuf, the size of the run's record ring (a record: off run's is recordOffRing) and of its
	// capture ring; ringBudget is bpf.ring_budget; wantCapture says the run captures with uprobes and so gets a
	// capture ring, and captureRefused why it did not (placeRings).
	ringbuf        uint32
	ringBudget     uint64
	wantCapture    bool
	captureRefused error

	// netMu orders RefreshNet against Detach: both read and replace rules, and a refresh that finished after
	// Detach removed the rows would write rows nothing removes (§5 R12, §8 I5).
	netMu sync.Mutex
	// credits holds each one-shot approval row from its grant to its revoke (GrantConnect, GrantDatagram, GrantUnix),
	// keyed by the row's own map key.
	credits creditRows
	// table is the compiled table Prepare built rules from; RefreshNet holds a refreshed one against it.
	table *agent.RuleTable
	rules RuleMaps
	// timelineNext never reuses an expiry-chain id while a hook may still read
	// an old verdict row during a DNS refresh.
	timelineNext uint32
	policy       *policy
	// recordMode is the run's record level, written into every run-set row this handle inserts so the
	// high-volume record-only programs can skip their ring-buffer reserve for a run that records nothing.
	recordMode ebpfbindings.RecordMode
	// cgroups are the run-set rows this handle created: its own cgroup plus every descendant it adopted.
	// Teardown removes exactly these and never scans the host-wide map (§4).
	cgroups map[uint64]struct{}
	// rowsLeft records that a row this run wrote could not be deleted. It gates the slot release: an index
	// whose rows survive must not be handed to another run (§5 R12, §8 I5).
	rowsLeft bool

	kern      kernel
	fan       *fanotifyListener
	inherited Inherited

	// armed is set by Arm, the one arming point after the child stage's execve (ADR 0021 (2)).
	armed bool

	// lingering is set when this launcher left the build last with a linger: Close starts the build's timer.
	lingering bool

	// planeMode is the decision plane's mode this run decides in, "" for the fanotify fallback; planeRows its rows
	// and planeWhy, when opts.Plane named a mode this run does not decide in, why (a table the plane cannot hold).
	// plane is the loaded plane (kern.planeOf), nil without one.
	planeMode ebpfbindings.PlaneMode
	planeRows *decide.PlaneRows
	planeWhy  error
	// planeExecs is the plane deciding this run's execs: the contract has an exec: section (DecisionPlane).
	planeExecs bool
	plane      planeKernel
	// handlePins is the run's exec pin state (ADR 0048 (3) P2, execpins.go): set by fillPlane when the run is pinned.
	handlePins
	// planeKeyed are the files the fill wrote this run's fs rows at, once planeFilled (PlaneKeyed).
	planeKeyed  []PlaneKeyed
	planeFilled bool
	// planeFilter is the inherited filter less the notifications the loaded plane decides (preparePlaneFilter), and
	// planeDropped what it leaves out; usePlaneFilter makes SeccompFilter hand it out (UsePlaneFilter).
	planeFilter    []bpf.RawInstruction
	planeDropped   []string
	usePlaneFilter bool

	prepared bool
	detached bool
	closed   bool
	undos    []undoStep
}

// BPFHash names the pin directory holding this build's objects, including the ring buffer the kernel
// record drains (enforce.KernelRecorder). It is stable for one set of compiled programs, which is why
// two launchers on one machine share an attachment.
func (h *Handle) BPFHash() string { return h.hash }

// undo registers a cleanup to run, in reverse order, when Prepare fails or the handle is closed.
func (h *Handle) undo(step undoStep) { h.undos = append(h.undos, step) }

// unwind runs the registered cleanups in reverse and joins their errors, so one failing step never hides the
// rest (§4: errors joined, not first-fail).
func (h *Handle) unwind() error {
	var errs []error
	for i := len(h.undos) - 1; i >= 0; i-- {
		if err := h.undos[i](); err != nil {
			errs = append(errs, err)
		}
	}
	h.undos = nil
	// A failed Prepare that left the build last, with a linger, starts its timer as Close does: the lock went
	// with the undos above.
	if h.lingering {
		h.lingering = false
		if err := h.startTimer(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// releaseSlot frees the run's slot exactly once. Ordering matters: it runs after every row that references
// the slot is gone, which is what keeps an index from being reused while the kernel still holds rows keyed by
// it (§5 R12, §8 I5).
//
// A removal that failed keeps the index allocated instead of freeing it anyway — the fail-closed reading of
// the same invariant, and why the table records a live pid rather than a plain flag: this process keeps the
// slot for as long as it runs, and the launcher that later reclaims it from this dead owner purges whatever
// is still keyed by it before writing its own rows (attachKernel).
func (h *Handle) releaseSlot() error {
	if !h.hasSlot {
		return nil
	}
	if h.rowsLeft {
		return fmt.Errorf("cgroup: run slot %d stays allocated: this run's rows could not be removed, and a "+
			"reused index would inherit them (§5 R12, §8 I5)", h.slot)
	}
	h.hasSlot = false
	return h.slots.release(h.slot)
}

// releaseSlotAndPark is releaseSlot followed, once the slot is free, by parkRings: a slot above the pool has its
// rings removed off the run's path, unless a run holds it again by then. Detach and a failed Prepare's unwind
// both end a slot this way, so rings a Prepare placed above the pool before it failed are trimmed too.
func (h *Handle) releaseSlotAndPark() error {
	released := h.hasSlot
	if err := h.releaseSlot(); err != nil {
		return err
	}
	if !released {
		return nil
	}
	return h.parkRings()
}

// Slot returns the run's dense host-wide run_idx. It is the key every verdict row and every kernel event of
// this run carries.
func (h *Handle) Slot() uint32 { return h.slot }

// Hash returns the build identity that names this run's pin directory and build lock.
func (h *Handle) Hash() string { return h.hash }

// Rules returns the compiled map rows, including the entries no cgroup hook can decide. A caller reports
// those as capabilities this run does not have rather than letting them look enforced. RefreshNet may replace
// the rows while the run goes on, so the read takes the same lock.
func (h *Handle) Rules() RuleMaps {
	h.netMu.Lock()
	defer h.netMu.Unlock()
	return h.rules
}

// LandlockRuleset returns the inherited tier-1 ruleset fd, or ok=false when none was composed.
func (h *Handle) LandlockRuleset() (int, bool) {
	if h.inherited == nil {
		return -1, false
	}
	return h.inherited.LandlockRuleset()
}

// SeccompFilter returns the inherited tier-1 filter, or ok=false when none was composed. Tier 2 installs the
// identical program tier 1 does: the supervisor still sees every connect and datagram send, and answers them
// by reading this tier's reason breadcrumb instead of re-deriving a verdict (§5 R5).
//
// With the decision plane loaded and the runtime's recorder reading the run (UsePlaneFilter), it is that filter less
// the notifications the plane's loaded hooks decide in the kernel (enforce-plane R27, TIER3-PLAN T16).
func (h *Handle) SeccompFilter() ([]bpf.RawInstruction, bool) {
	if h.inherited == nil {
		return nil, false
	}
	if h.usePlaneFilter && len(h.planeFilter) > 0 {
		return h.planeFilter, true
	}
	return h.inherited.SeccompFilter()
}

// Capabilities is this run's capability set: the tier's static column, narrowed by what this run could not
// provide: read and exec denial when it has neither a fanotify listener nor a decision plane. net.unix stays: a unix: entry is decided by
// connect_unix and sendmsg_unix on 6.7+ and by the inherited tier-1 path on every kernel (§5 R7), so no
// kernel leaves one undecided. *Amended:* the row used to be cleared for every run with a unix: entry, while
// the inherited path enforced it.
//
// net.unix_abstract_scope is the inherited ruleset's own answer, not the static column's: no program of this
// tier refuses an abstract name, the Landlock scope the child applies does, and only from ABI 6 on
// (enforce-landlock R7). A handle with no inherited ruleset, or one that does not say, has no scope.
//
// fs.protected_write_targets is the plane's (ADR 0041 D7): a plane mode decides the built-in deny_write targets by
// inode, chmod included, and the fanotify listener leaves them to the supervisor's copied pathnames, best effort.
//
// exec.deny also follows the inherited row when that row withholds it: a contract with exec.anonymous
// drops the tier-1 memfd arm, so any readable binary runs from a memfd, and neither the fanotify listener nor
// the decision plane stops it (the plane's exec row allows anonymous images for such a run, PlaneExecAnonAllow).
// An inherited state that does not say leaves the column as it is.
func (h *Handle) Capabilities() backend.Set {
	set := backend.Matrix(backend.TierCgroup)
	if h.opts.tier3() {
		// Tier 3's run decides through the same mechanisms as a tier-2 run in LSM mode, so its set is that run's,
		// kept within tier 3's column: a row the column promises and no loaded hook decides yet (chmod, step B)
		// is not claimed (enforce-plane R3).
		col := backend.Matrix(backend.TierBPFLSM)
		for c := range set {
			if !col.Has(c) {
				delete(set, c)
			}
		}
	}
	if h.fan == nil && h.plane == nil {
		set[backend.CapReadDeny] = false
		set[backend.CapExecDeny] = false
	}
	set[backend.CapProtectedWriteTargets] = h.planeMode != ""
	// ADR 0043: a file created later at a covered name is refused only where the plane's name check decides the
	// slot, which Prepare's header flag makes so exactly for a plane mode with name rows (a table without name
	// entries compiles none), and only for every declared entry when none was left out by a cap or a collision
	// (D7, RuleTable.NameEntriesWhole); the fallback's listener and supervisor refuse it best effort.
	set[backend.CapReadDenyCreatedLater] = h.planeMode != "" && h.planeRows != nil && len(h.planeRows.NameRows) > 0 &&
		h.table != nil && h.table.NameEntriesWhole()
	// ADR 0048 (9): exec command rules' argv is held by the kernel only in a run whose slot is pinned and whose plane
	// mode passed doctor's exec pin cell.
	claim, _ := h.ExecPinClaim()
	set[backend.CapExecCommandArgv] = claim && h.pinMap != nil
	set[backend.CapGateExecCompletion] = claim && h.pinMap != nil && h.table != nil && h.table.Gate.MayEscalate(gate.Exec)
	set[backend.CapUnixAbstractScope] = false
	if rep, ok := h.inherited.(interface{ Capabilities() backend.Set }); ok {
		inh := rep.Capabilities()
		set[backend.CapUnixAbstractScope] = inh.Has(backend.CapUnixAbstractScope)
		if !inh.Has(backend.CapExecDeny) {
			set[backend.CapExecDeny] = false
		}
	}
	net := h.NetworkGuarantees()
	set[backend.CapTCPDestinationKernel] = net.TCPDestination
	set[backend.CapUDPByDestination] = net.UDPDestination
	set[backend.CapUnixDestinationKernel] = net.UnixDestination
	set[backend.CapSocketFamilies] = net.SocketFamilies
	return set
}

// recordModeOf maps the contract's record level to the byte a run-set row carries.
func recordModeOf(m agent.RecordMode) ebpfbindings.RecordMode {
	switch m {
	case agent.RecordOff:
		return ebpfbindings.RecordOff
	case agent.RecordSummary:
		return ebpfbindings.RecordSummary
	default:
		return ebpfbindings.RecordFull
	}
}
