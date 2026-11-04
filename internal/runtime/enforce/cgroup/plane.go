// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/startphase"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// The decision plane as part of this backend (docs/p0/enforce-plane.md; TIER3-PLAN T6, the join of T2 to T5 and T8).
// When doctor selected a plane mode for tier cgroup (Options.Plane, from doctor's Report.PlaneFor), a run's opens,
// execs, renames, links, unlinks and rmdirs are decided in the kernel by bpf/decide.bpf.c's programs in that mode, on
// the rows its own contract compiles to (decide.CompilePlane), and the fanotify listener is not made: no mark is
// placed, and none of the listener's round trips is paid (R22). What it adds to the tier-2 build:
//
//   - The mode's programs and the plane's own maps, loaded once per build and mode and pinned under
//     /sys/fs/bpf/tego/<hash>-<mode>/{maps,progs,links}, beside the build's own directory, and adopted from there
//     by every later run (R20; the mode is in the name, so two modes never share a row, R18). The maps the plane
//     shares with tier 2 (the run set, the rings, the plane scratch the record's fexit reads) are the build's own,
//     handed to the loader; the host-wide links are pinned like the build's tracing links, so linger keeps them
//     (ADR 0022) and the build's removal takes them.
//   - The answer doctor's probe gave, pinned as <hash>-<mode>/tego_plane_probe (doctor.PinPlaneAnswer, through
//     Options.Plane.PinAnswer), so a run that adopts the build probes nothing (R21).
//   - Each slot's row maps, created once and put in the outers at the slot's run_idx, then kept: a run writes its
//     rows with its own gen, a row of another gen is absent to the walk, and no inner map is created or deleted on
//     a run's path (ADR 0025 (1) as T0 amended it, R6). The fill (T4) writes the fs and exec rows in the kernel from
//     the Landlock plan's held O_PATH descriptors (R16); the unix policy (step D) and the bare-name exec rows (T3's
//     open condition) are written here, from userspace, since their keys are no inode, and then the slot's header
//     (slotHeader), whose flags carry what the contract decides beyond the fs rows (an exec: section and
//     exec.anonymous, a net: section and its icmp) with the run's gen: no policy row is written, and exec-rows key 0
//     is reserved and never written.
//   - The fill's programs, pinned under <hash>-<mode>/fill once and adopted, since their load is most of a fill's
//     cost. Only pinning them takes the build's fill lock (lockFill, from openPlaneFiller); fills and clears take no
//     lock, since each launcher's config and templates are keyed by its tgid and a clear touches only its own slot's
//     rows (enforce-plane §2.6).
//   - The clear (T4's tego_plane_clear) of a slot's rows when its run ends (Detach), when a slot is purged at
//     Prepare (purgeSlot) and by the reaper of a run whose launcher died (PurgeRun), off every run's path.
//
// The run's run-set row names the mode (Run.Plane), so a plane program decides only runs prepared in its own mode:
// a run of the fanotify fallback, or of the other mode, sharing the build's run set is never decided by rows its
// slot does not have (bpf/include/events.h enum tego_run_plane).

// PlaneSetup is the plane mode a backend decides tier cgroup's runs in, from doctor's selection. The zero value is
// the fanotify fallback (ADR 0021).
type PlaneSetup struct {
	// Mode is lsm or fmod_ret, "" for the fanotify fallback.
	Mode ebpfbindings.PlaneMode
	// Build is the object build the probe chose (bpf.ObjectPlaneRdonly or bpf.ObjectPlaneProbe).
	Build ebpfbindings.Object
	// ExecPins is doctor's exec pin cell passed in Mode (ADR 0048 (7)): only then may a pinned run claim that the
	// kernel holds its execs to the decided facts (Handle.ExecPinClaim).
	ExecPins bool
	// PinAnswer pins the answer the build was loaded by into a plane pin directory (doctor.PinPlaneAnswer bound to
	// the choice); nil pins nothing. doctor imports this package's importer, so the call crosses as a function.
	PinAnswer func(dir string) error
}

// planeKernel is the plane's half of the kernel seam: what a Handle asks of a loaded plane. The real one is
// bpfPlane; this package's tests substitute a double.
type planeKernel interface {
	// prepareSlot makes the slot's row maps exist in the outers (created once, then kept) and zeroes its counters.
	prepareSlot(slot uint32) error
	// fill writes one run's rows into its slot's maps with the run's gen and checks them (R16).
	fill(req planeFillRequest) (planeFillReport, error)
	// clearSlot zeroes the slot's header, so every decided hook of a run the slot still names refuses, then deletes
	// every row of the slot, of every gen.
	clearSlot(slot uint32) error
	// counts reads the slot's fail-closed counters (tego_plane_counters), which prepareSlot zeroed.
	counts(slot uint32) (ebpfbindings.PlaneCounts, error)
	// decidesUnix reports whether the plane's step D hooks are loaded: where cgroup/connect_unix is absent (below
	// 6.7), the plane decides a run's unix names in its place (enforce-plane R14).
	decidesUnix() bool
	// hooks is the set of hooks the plane loaded and attached, by bpf.PlaneHook.Name: what it decides on this
	// kernel, which the inherited filter's notifications are left out by (enforce-plane R27, TIER3-PLAN T16).
	hooks() map[string]bool
	// pinsReady reports whether the plane holds the exec pin maps (ADR 0048 (3) P2); slotPins opens a slot's pin map,
	// which a pinned fill made exist.
	pinsReady() bool
	slotPins(slot uint32) (slotPinMap, error)
}

// planeFillRequest is one run's fill.
type planeFillRequest struct {
	Slot, Gen uint32
	Rows      *decide.PlaneRows
	// Held is the Landlock plan's O_PATH descriptor of a keyed path.
	Held           heldFD
	ListenHeld     heldFD
	KeyringAllowed bool
	// Exec is the contract's exec policy: Decides when it has an exec: section, Anonymous for exec.anonymous.
	Exec planeExecPolicy
	// Unix is the slot's policy for the step D hooks (enforce-plane R14), written with the run's gen whether or not
	// they decide, since a slot with no policy of the run's gen refuses every unix name.
	Unix planeUnixPolicy
	// Net is the contract's socket policy (ADR 0018). socket_create reads it from the slot header's flags.
	Net planeNetPolicy
	// Pin is the run's exec pin state (ADR 0048 (3) P2), nil for a run that is not pinned.
	Pin *planePin
}

// planeUnixPolicy is what the slot's unix policy says: Decides when the plane decides the run's unix names (its
// step D hooks are loaded and the contract has a net: section), Relay the launcher's cgroup, whose
// /proc/self/fd/<n> connects the supervisor's relay makes.
type planeUnixPolicy struct {
	Decides bool
	Relay   uint64
}

// planeNetPolicy is what the slot header's net flags say (ADR 0018 (5)): Restricted when the contract has a net:
// section, ICMP when it names an ICMP destination (a port-0 entry). This package may not import enforce/landlock
// (enforce-cgroup-observe I12), so both read agent.RuleTable.NetSocketPolicy: the seccomp filter's socket arm
// (SocketArmFor) and these flags are one predicate for the same table.
type planeNetPolicy struct {
	Restricted, ICMP bool
}

// netPolicyOf is a table's socket policy. The conversion ties planeNetPolicy's fields to agent.SocketPolicy.
func netPolicyOf(rt *agent.RuleTable) planeNetPolicy {
	return planeNetPolicy(rt.NetSocketPolicy())
}

// planeExecPolicy is what the slot header's exec flags say (enforce-plane §2.7).
type planeExecPolicy struct {
	Decides, Anonymous bool
}

// execPolicyOf is the exec policy of a table's contract. A table without its contract decides exec, as the
// Landlock builder fails closed on one (newBuilder).
func execPolicyOf(rt *agent.RuleTable) planeExecPolicy {
	if rt.Contract == nil {
		return planeExecPolicy{Decides: true}
	}
	if rt.ExecUnrestricted() {
		return planeExecPolicy{}
	}
	return planeExecPolicy{Decides: true, Anonymous: rt.ExecAnonymous()}
}

// slotHeader is the slot's header for req (bpf.PlaneSlot, enforce-plane R6): the run's gen, what its contract decides
// beyond the fs rows, and the rows written. unix is whether this plane's step D hooks are loaded (below 6.7); they
// decide the run's unix names only then and with a net: section. A section the contract lacks is a flag left clear,
// never a row left out, so a slot whose rows are gone refuses rather than allows (ADR 0018 (4), SEMANTICS §1).
func slotHeader(req planeFillRequest, unix bool, fsRows, execRows int) ebpfbindings.PlaneSlot {
	h := ebpfbindings.PlaneSlot{Gen: req.Gen, FSRows: uint32(fsRows), ExecRows: uint32(execRows)}
	if req.Exec.Decides {
		h.Flags |= ebpfbindings.PlaneSlotExecDecides
		if req.Exec.Anonymous {
			h.Flags |= ebpfbindings.PlaneSlotExecAnon
		}
	}
	if req.Unix.Decides && unix {
		h.Flags |= ebpfbindings.PlaneSlotUnixDecides
	}
	if req.Net.Restricted {
		h.Flags |= ebpfbindings.PlaneSlotNetDecides
		if req.Net.ICMP {
			h.Flags |= ebpfbindings.PlaneSlotNetICMP
		}
	}
	if req.Rows != nil && req.Rows.ListenPolicy {
		h.Flags |= ebpfbindings.PlaneSlotListenDecides
	}
	if req.Rows != nil && req.Rows.BuiltinTerminals {
		h.Flags |= ebpfbindings.PlaneSlotBuiltinTTY
	}
	if req.KeyringAllowed {
		h.Flags |= ebpfbindings.PlaneSlotKeyringAllowed
	}
	// ADR 0043 D9: a table with name entries has its name rows and config row written before the header
	// (putNameEntries), and the header carries the prefilter's leads and the flag that makes the hooks ask them. A
	// set of leads the header cannot carry leaves the flag clear, which fill refuses (compile never makes one).
	if req.Rows != nil && len(req.Rows.NameRows) > 0 && h.SetLeads(req.Rows.Leads, req.Rows.PrefixLens) {
		h.Flags |= ebpfbindings.PlaneSlotNameDecides
	}
	// ADR 0048 (3) P2: a pinned run's key and pin map are written before the header (putPins), which names the pid
	// namespace the pins' keys number threads in.
	if req.Pin != nil {
		h.Flags |= ebpfbindings.PlaneSlotExecPin
		h.PidnsDev, h.PidnsIno = req.Pin.PidnsDev, req.Pin.PidnsIno
	}
	return h
}

// planeModes are the plane pin directories a build can have, in the order they are removed.
var planeModes = ebpfbindings.PlaneModes

// planeDirName is the name of build hash's pin directory for mode m, beside the build's own.
func planeDirName(hash string, m ebpfbindings.PlaneMode) string { return hash + "-" + string(m) }

// planeDirOf reports whether a name under the tego pin root is a plane directory, and whose.
func planeDirOf(name string) (hash string, m ebpfbindings.PlaneMode, ok bool) {
	for _, m := range planeModes {
		if h, cut := strings.CutSuffix(name, "-"+string(m)); cut && h != "" {
			return h, m, true
		}
	}
	return "", "", false
}

// planeLayout is one build's pin directory for one plane mode.
type planeLayout struct {
	pinLayout
	// Fill holds the fill's pinned programs and maps.
	Fill string
	Mode ebpfbindings.PlaneMode
}

// fill pin names.
const (
	planeFillDir     = "fill"
	planeAnswerName  = "tego_plane_probe" // doctor.PlanePinMap; doctor is not imported here
	planeFillLockTag = "-plane-"
)

// newPlaneLayout is build's plane pin directory for mode m: <base>/<hash>-<mode>.
func newPlaneLayout(build pinLayout, hash string, m ebpfbindings.PlaneMode) planeLayout {
	root := filepath.Join(build.Base, planeDirName(hash, m))
	return planeLayout{
		pinLayout: pinLayout{Base: build.Base, Root: root, Maps: filepath.Join(root, pinMaps),
			Progs: filepath.Join(root, pinProgs), Links: filepath.Join(root, pinLinks)},
		Fill: filepath.Join(root, planeFillDir),
		Mode: m,
	}
}

// create makes the directory and its three subdirectories; the fill's is made when the fill is pinned.
func (l planeLayout) create() error {
	for _, dir := range []string{l.Base, l.Root, l.Maps, l.Progs, l.Links} {
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: create plane pin directory %s: %w", ErrBpffsUnavailable, dir, err)
		}
	}
	return nil
}

// removePlaneDirs removes every plane pin directory of build hash under base: the build's removal takes its planes
// (R20). Its links go first (teardown.unpinLink, their programs recorded in td for the removal's wait), then
// everything else under the directory.
func removePlaneDirs(base, hash string, td *teardown) error {
	var errs []error
	for _, m := range planeModes {
		dir := filepath.Join(base, planeDirName(hash, m))
		errs = append(errs, removePinDir(filepath.Join(dir, pinLinks), td.unpinLink, nil)...)
		if err := os.RemoveAll(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("cgroup: remove plane pins %s: %w", dir, err))
		}
	}
	return errors.Join(errs...)
}

// planeProgram is the program of one hook in one mode.
func planeProgram(h ebpfbindings.PlaneHook, m ebpfbindings.PlaneMode) string { return h.Program(m) }

// bpfPlane is one build's plane in one mode, loaded or adopted.
type bpfPlane struct {
	mode   ebpfbindings.PlaneMode
	layout planeLayout
	hash   string
	// state is the directory the fill lock lives in; not owned.
	state *hoststate.Dir
	// coll holds the mode's programs and the plane's own maps (and clones of the tier-2 maps it was loaded over).
	coll                                 *ebpf.Collection
	rows, execRows, listenRows, counters *ebpf.Map
	// nameRows is the slot-indexed name map (bpf.MapPlaneNameRows, ADR 0043 D9), which userspace fills and clears:
	// its keys are hashes of names, never addresses.
	nameRows *ebpf.Map
	// execPins and pinKeys are the slot-indexed exec pin maps (bpf.MapPlaneExecPins, MapPlanePinKeys; ADR 0048 (3)
	// P2), which userspace fills and clears; pinsInner is the pin map's definition.
	execPins, pinKeys *ebpf.Map
	pinsInner         *ebpf.MapSpec
	// slots is the slot headers' map (bpf.MapPlaneSlots).
	slots *ebpf.Map
	// unixPolicy is the slot-indexed step D policy map; unix is whether the step D hooks were loaded and attached.
	unixPolicy *ebpf.Map
	unix       bool
	// attached is the set of hooks whose program is loaded and attached, by bpf.PlaneHook.Name (hooks).
	attached                          map[string]bool
	rowsInner, execInner, listenInner *ebpf.MapSpec
	nameInner                         *ebpf.MapSpec
	// loadInner restores the full ELF definitions only if an adopted plane needs
	// a new slot. Compact adoption specifications must never create maps.
	loadInner func() error
	links     []sharedLink
	filler    *planeFiller
	// answerErr is why the probe's answer could not be pinned, for the run's log; nil when it was, or was there.
	answerErr error
}

// newBPFPlane loads build hash's plane in setup's mode over the tier-2 kernel k, or adopts it from its pins. It
// returns what it made even with an error: everything it creates is pinned as it is created, and the build's
// removal is what takes it (newBPFKernel's contract).
func newBPFPlane(k *bpfKernel, hash string, setup PlaneSetup, state *hoststate.Dir) (*bpfPlane, error) {
	lay := newPlaneLayout(k.pins, hash, setup.Mode)
	p := &bpfPlane{mode: setup.Mode, layout: lay, hash: hash, state: state}
	if err := lay.create(); err != nil {
		return nil, err
	}
	endSpec := startphase.Begin(k.phase, "plane.spec")
	spec, compact, err := ebpfbindings.LoadAdoption(setup.Build)
	endSpec()
	if err != nil {
		return p, fmt.Errorf("%w: %w", ErrProgramLoad, err)
	}
	endHooks := startphase.Begin(k.phase, "plane.hooks")
	keep := map[string]bool{}
	hookOf := map[string]string{}
	var progs []string
	// Step D's hooks go where cgroup/connect_unix does not: a kernel that loaded it (6.7+) decides unix names there,
	// and a name is never decided twice (enforce-plane R14).
	_, cgroupUnix := k.progs[ebpfbindings.ProgConnectUnix]
	p.unix = !cgroupUnix
	for _, h := range ebpfbindings.PlaneHooks {
		if h.Unix && !p.unix {
			continue
		}
		if h.Optional && !kernelHasFunc(h.Target(setup.Mode)) {
			continue // an optional hook this kernel's BTF lacks: another hook decides its rule here (enforce-plane R3)
		}
		keep[planeProgram(h, setup.Mode)] = true
		hookOf[planeProgram(h, setup.Mode)] = h.Name
		progs = append(progs, planeProgram(h, setup.Mode))
	}
	// The exec-pin program (ADR 0048 (3) P2) is loaded and attached in both modes with the hooks: it returns after one
	// header read for a run whose slot carries no PlaneSlotExecPin, and a mode whose kernel refuses it has no plane.
	keep[ebpfbindings.PlaneExecPinProgram(setup.Mode)] = true
	progs = append(progs, ebpfbindings.PlaneExecPinProgram(setup.Mode))
	for name := range spec.Programs {
		if !keep[name] {
			delete(spec.Programs, name)
		}
	}
	endHooks()
	external := map[string]*ebpf.Map{}
	for name := range spec.Maps {
		if m := k.maps[name]; m != nil && !strings.HasPrefix(name, ".") {
			external[name] = m // a map the build pins by name; a global-variable section is each object's own
		}
	}
	objStart := time.Now()
	verified := map[ebpf.ProgramID]*ebpf.Program{}
	coll, adopted := adoptObjectInWithPrograms(lay.pinLayout, spec, progs, external, verified)
	if !adopted {
		if compact {
			spec, err = ebpfbindings.Load(setup.Build)
			if err != nil {
				return p, fmt.Errorf("%w: %w", ErrProgramLoad, err)
			}
			compact = false
			for name := range spec.Programs {
				if !keep[name] {
					delete(spec.Programs, name)
				}
			}
		}
		// A timed test build attributes the load to the plane's maps and each program (plane.obj.<mode>.maps,
		// plane.prog.<mode>.<prog>.*; enforce-plane §10.1), as newBPFKernel does its objects'.
		trace := ebpfbindings.BeginLoad(k.phase, "plane.obj."+string(setup.Mode)+".maps", "plane.prog."+string(setup.Mode))
		for attempt, attempts := 1, ebpfbindings.PinAttempts(spec); ; attempt++ {
			coll, err = ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
				Maps:            ebpf.MapOptions{PinPath: lay.Maps},
				MapReplacements: external,
				Programs:        ebpfbindings.LoadOptions(),
			})
			if err == nil || !errors.Is(err, os.ErrExist) || attempt >= attempts {
				break
			}
		}
		trace.End(collectionPrograms(coll))
		if err != nil {
			return p, fmt.Errorf("%w: plane %s in %s mode: %w", ErrProgramLoad, setup.Build, setup.Mode, verifierTail(err))
		}
	}
	p.coll = coll
	owns, err := planeOwns(spec, coll, external)
	if err != nil {
		return p, err
	}
	if !adopted {
		for name, prog := range coll.Programs {
			if err := repinPlaneProgram(prog, filepath.Join(lay.Progs, name), owns); err != nil {
				return p, err
			}
		}
	}
	how := ".new"
	if adopted {
		how = ".adopt"
	}
	startphase.Report(k.phase, "plane.objects"+how, time.Since(objStart))
	p.rows, p.execRows, p.counters = coll.Maps[ebpfbindings.MapPlaneRows], coll.Maps[ebpfbindings.MapPlaneExecRows],
		coll.Maps[ebpfbindings.MapPlaneCounters]
	p.listenRows = coll.Maps[ebpfbindings.MapPlaneListenRows]
	p.unixPolicy, p.slots = coll.Maps[ebpfbindings.MapPlaneUnixPolicy], coll.Maps[ebpfbindings.MapPlaneSlots]
	// An object without the name map is never taken for this build's (ADR 0043 D9): the build hash moved with the map,
	// and a plane whose programs read no name map cannot decide a run whose header says it should.
	p.nameRows = coll.Maps[ebpfbindings.MapPlaneNameRows]
	// The same holds for the exec pin maps (ADR 0048 (3) P2): the pin program reads them in every slot it is flagged in.
	p.execPins, p.pinKeys = coll.Maps[ebpfbindings.MapPlaneExecPins], coll.Maps[ebpfbindings.MapPlanePinKeys]
	if p.rows == nil || p.execRows == nil || p.listenRows == nil || p.counters == nil || p.unixPolicy == nil || p.slots == nil ||
		p.nameRows == nil || p.execPins == nil || p.pinKeys == nil {
		return p, fmt.Errorf("%w: the plane's row maps are missing from %s", ErrProgramLoad, setup.Build)
	}
	if compact {
		p.loadInner = func() error {
			full, err := ebpfbindings.Load(setup.Build)
			if err != nil {
				return fmt.Errorf("%w: %w", ErrProgramLoad, err)
			}
			return p.setInnerSpecs(full, setup.Build)
		}
	} else if err := p.setInnerSpecs(spec, setup.Build); err != nil {
		return p, err
	}
	// Which of the recorder's fexit programs this build has attached, before any plane program is: a refusal on a
	// hook with none writes the plane's own sample, so it keeps its one line (enforce-plane §7, R23; T9b).
	recorded := coll.Maps[ebpfbindings.MapPlaneRecorded]
	if recorded == nil {
		return p, fmt.Errorf("%w: the plane's recorder mask is missing from %s", ErrProgramLoad, setup.Build)
	}
	if err := recorded.Put(uint32(0), recordedMask(k.shared)); err != nil {
		return p, fmt.Errorf("%w: write the plane's recorder mask: %w", ErrProgramLoad, err)
	}
	endLinks := startphase.Begin(k.phase, "plane.links")
	for _, name := range progs {
		l, err := attachPlaneLink(coll.Programs[name], name, setup.Mode, filepath.Join(lay.Links, name), owns, verified)
		if err != nil {
			return p, err
		}
		p.links = append(p.links, sharedLink{Link: l, pin: filepath.Join(lay.Links, name)})
		hook, ok := hookOf[name]
		if !ok {
			continue // the exec-pin program, which is no hook
		}
		if p.attached == nil {
			p.attached = map[string]bool{}
		}
		p.attached[hook] = true
	}
	endLinks()
	if setup.PinAnswer != nil {
		if _, err := os.Stat(filepath.Join(lay.Root, planeAnswerName)); errors.Is(err, os.ErrNotExist) {
			if err := setup.PinAnswer(lay.Root); err != nil && !errors.Is(err, os.ErrExist) && !errors.Is(err, unix.EEXIST) {
				p.answerErr = err // a later run probes once more; the plane itself is sound
			}
		}
	}
	fill, ok := ebpfbindings.PlaneFillFor(setup.Build)
	if !ok {
		return p, fmt.Errorf("%w: no fill build goes with %s", ErrProgramLoad, setup.Build)
	}
	endFiller := startphase.Begin(k.phase, "plane.filler")
	p.filler, err = openPlaneFiller(fill, lay.Fill, p.rows, p.execRows, p.lockFill, p.listenRows)
	endFiller()
	if err != nil {
		return p, err
	}
	return p, nil
}

// setInnerSpecs accepts only a full ELF specification, preserving the BTF and
// initialization metadata the kernel needs when creating a new slot's maps.
func (p *bpfPlane) setInnerSpecs(spec *ebpf.CollectionSpec, build ebpfbindings.Object) error {
	rows, execRows := spec.Maps[ebpfbindings.MapPlaneRows], spec.Maps[ebpfbindings.MapPlaneExecRows]
	listen, names := spec.Maps[ebpfbindings.MapPlaneListenRows], spec.Maps[ebpfbindings.MapPlaneNameRows]
	pins := spec.Maps[ebpfbindings.MapPlaneExecPins]
	if rows == nil || execRows == nil || listen == nil || names == nil || pins == nil || rows.InnerMap == nil || execRows.InnerMap == nil ||
		listen.InnerMap == nil || names.InnerMap == nil || pins.InnerMap == nil {
		return fmt.Errorf("%w: the plane's row maps in %s declare no inner map", ErrProgramLoad, build)
	}
	p.rowsInner, p.execInner = rows.InnerMap, execRows.InnerMap
	p.listenInner, p.nameInner, p.pinsInner = listen.InnerMap, names.InnerMap, pins.InnerMap
	p.loadInner = nil
	return nil
}

func (p *bpfPlane) innerSpec(name string) (*ebpf.MapSpec, error) {
	if p.loadInner != nil {
		if err := p.loadInner(); err != nil {
			return nil, err
		}
	}
	if name == ebpfbindings.MapPlaneRows {
		return p.rowsInner, nil
	}
	if name == ebpfbindings.MapPlaneListenRows {
		return p.listenInner, nil
	}
	if name == ebpfbindings.MapPlaneNameRows {
		return p.nameInner, nil
	}
	if name == ebpfbindings.MapPlaneExecPins {
		return p.pinsInner, nil
	}
	return p.execInner, nil
}

// recordedMask is the plane's MapPlaneRecorded value for a build whose host-wide tracing links are shared: the
// recorder fexit programs among them (ebpfbindings.PlaneRecordedMask), each named by its pin.
func recordedMask(shared []sharedLink) uint32 {
	attached := map[string]bool{}
	for _, l := range shared {
		attached[filepath.Base(l.pin)] = true
	}
	return ebpfbindings.PlaneRecordedMask(func(prog string) bool { return attached[prog] })
}

// attachPlaneLink attaches one plane program host-wide in its mode, or adopts the pinned link another launcher of
// the build made, as attachShared does for the tracing links. Two launchers attaching at once each keep one link:
// the second's pin fails, and it adopts the first's and drops its own. A pinned link is adopted only when its
// program reads this plane's maps (owns): one left pinned over maps since re-created (a removal that failed part
// way) runs a program whose run set names no run, which allows everything, so it is unpinned and this launcher's
// program attached in its place (enforce-plane R20).
func attachPlaneLink(prog *ebpf.Program, name string, m ebpfbindings.PlaneMode, pinPath string,
	owns func(*ebpf.Program) string, verified map[ebpf.ProgramID]*ebpf.Program) (link.Link, error) {
	if l, err := link.LoadPinnedLink(pinPath, nil); err == nil {
		why := linkOwned(l, owns, verified)
		if why == "" {
			return l, nil
		}
		_ = l.Close()
		if err := os.Remove(pinPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: unpin plane link %s over foreign maps (%s): %w", ErrProgramLoad, pinPath, why, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: adopt pinned plane link %s: %w", ErrProgramLoad, pinPath, err)
	}
	if prog == nil {
		return nil, fmt.Errorf("%w: plane program %s is not loaded", ErrProgramLoad, name)
	}
	var (
		l   link.Link
		err error
	)
	switch {
	case name == ebpfbindings.PlaneExecPinProgram(m):
		l, err = link.AttachTracing(link.TracingOptions{Program: prog, AttachType: ebpf.AttachTraceRawTp})
	case m == ebpfbindings.PlaneLSM:
		l, err = link.AttachLSM(link.LSMOptions{Program: prog})
	default:
		l, err = link.AttachTracing(link.TracingOptions{Program: prog, AttachType: ebpf.AttachModifyReturn})
	}
	if err != nil {
		return nil, fmt.Errorf("%w: attach %s: %w", ErrProgramLoad, name, err)
	}
	if err := l.Pin(pinPath); err != nil {
		_ = l.Close()
		adopted, loadErr := link.LoadPinnedLink(pinPath, nil)
		if loadErr != nil {
			return nil, fmt.Errorf("%w: pin plane link %s: %w", ErrProgramLoad, pinPath, err)
		}
		if why := linkOwned(adopted, owns, verified); why != "" {
			_ = adopted.Close()
			return nil, fmt.Errorf("%w: the plane link another launcher pinned at %s reads foreign maps (%s)",
				ErrProgramLoad, pinPath, why)
		}
		return adopted, nil
	}
	return l, nil
}

// linkOwned is owns of the program link l runs, or why it cannot be told: a link whose program cannot be read is
// never adopted.
func linkOwned(l link.Link, owns func(*ebpf.Program) string, verified map[ebpf.ProgramID]*ebpf.Program) string {
	info, err := l.Info()
	if err != nil {
		return "link-info"
	}
	// The held collection descriptor prevents reuse of a successfully checked
	// program's ID. A different link program, or one whose descriptor was closed,
	// must still pass the ordinary complete ownership check below.
	if info.Program != 0 {
		if p := verified[info.Program]; p != nil && p.FD() >= 0 {
			return ""
		}
	}
	prog, err := ebpf.NewProgramFromID(info.Program)
	if err != nil {
		return "link-prog"
	}
	defer func() { _ = prog.Close() }()
	return owns(prog)
}

// planeOwns is readsOnly over the plane's maps as coll and external hold them: the maps its spec pins by name, and
// its global-variable sections and kernel-only maps by shape, as adoptObjectIn matches them.
func planeOwns(spec *ebpf.CollectionSpec, coll *ebpf.Collection, external map[string]*ebpf.Map) (func(*ebpf.Program) string, error) {
	ids := map[ebpf.MapID]bool{}
	var sections []*ebpf.MapSpec
	for name, ms := range spec.Maps {
		if ms.Pinning != ebpf.PinByName {
			sections = append(sections, ms)
			continue
		}
		m := coll.Maps[name]
		if m == nil {
			m = external[name]
		}
		if m == nil {
			return nil, fmt.Errorf("%w: the plane's map %s is not loaded", ErrProgramLoad, name)
		}
		info, err := m.Info()
		if err != nil {
			return nil, fmt.Errorf("%w: the plane's map %s: %w", ErrProgramLoad, name, err)
		}
		id, ok := info.ID()
		if !ok {
			return nil, fmt.Errorf("%w: the plane's map %s has no id", ErrProgramLoad, name)
		}
		ids[id] = true
	}
	return func(p *ebpf.Program) string { return readsOnly(p, ids, sections) }, nil
}

// repinPlaneProgram pins prog at path, replacing a program pinned there over other maps (owns), which no launcher
// could adopt: left, it made every later run load the plane again. One pinned over this plane's maps is kept, as
// pinProgram keeps another launcher's.
func repinPlaneProgram(prog *ebpf.Program, path string, owns func(*ebpf.Program) string) error {
	if old, err := ebpf.LoadPinnedProgram(path, nil); err == nil {
		why := owns(old)
		_ = old.Close()
		if why != "" {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("%w: unpin plane program %s over foreign maps (%s): %w", ErrProgramLoad, path, why, err)
			}
		}
	}
	return pinProgram(prog, path)
}

// openPlaneFiller adopts the fill pinned in dir over rows and execRows, or loads fill and pins it there, under the
// build's fill lock, so no two launchers pin at once and a launcher sees the whole fill or none: what a launcher
// that died part way through pinning left is removed and pinned afresh. A fill that cannot be pinned is kept
// unpinned, which is as sound (its maps are this process's own); a reaper then finds none to clear with, and the
// slot's next Prepare clears it. (bpffs refuses a name with a dot, so the pins cannot be made under a temporary
// name and renamed into place.)
func openPlaneFiller(fill ebpfbindings.Object, dir string, rows, execRows *ebpf.Map, lock func() (func(), error), listeners ...*ebpf.Map) (*planeFiller, error) {
	unlock, err := lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if f, ok := adoptPlaneFiller(fill, dir, rows, execRows, listeners...); ok {
		return f, nil
	}
	f, err := newPlaneFiller(fill, rows, execRows, listeners...)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProgramLoad, err)
	}
	if err := os.RemoveAll(dir); err == nil {
		if err := pinPlaneFiller(f, dir); err != nil {
			_ = os.RemoveAll(dir)
		}
	}
	return f, nil
}

// The fill's pins in its directory.
const (
	fillPinProg   = "prog"
	fillPinClear  = "clear"
	fillPinConfig = "config"
	fillPinWants  = "wants"
)

// pinPlaneFiller pins f's programs and maps in dir, which it makes.
func pinPlaneFiller(f *planeFiller, dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	for name, obj := range map[string]interface{ Pin(string) error }{
		fillPinProg: f.prog, fillPinClear: f.clear, fillPinConfig: f.config, fillPinWants: f.wants,
	} {
		if err := obj.Pin(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

// adoptPlaneFiller opens the fill pinned in dir, and reports false, having kept nothing, unless the whole of it is
// there and its programs read the plane's row maps given and the fill's own pinned maps and nothing else.
func adoptPlaneFiller(fill ebpfbindings.Object, dir string, rows, execRows *ebpf.Map, listeners ...*ebpf.Map) (*planeFiller, bool) {
	f := &planeFiller{obj: fill, rows: rows, execRows: execRows}
	var err error
	closeAll := func() {
		for _, c := range []interface{ Close() error }{f.prog, f.clear, f.config, f.wants} {
			if c != nil && !isNilCloser(c) {
				_ = c.Close()
			}
		}
	}
	if f.prog, err = ebpf.LoadPinnedProgram(filepath.Join(dir, fillPinProg), nil); err != nil {
		return nil, false
	}
	if f.clear, err = ebpf.LoadPinnedProgram(filepath.Join(dir, fillPinClear), nil); err != nil {
		closeAll()
		return nil, false
	}
	for _, m := range []struct {
		name string
		dst  **ebpf.Map
	}{{fillPinConfig, &f.config}, {fillPinWants, &f.wants}} {
		if *m.dst, err = ebpf.LoadPinnedMap(filepath.Join(dir, m.name), nil); err != nil {
			closeAll()
			return nil, false
		}
	}
	allowed := map[ebpf.MapID]bool{}
	for _, m := range append([]*ebpf.Map{rows, execRows, f.config, f.wants}, listeners...) {
		info, err := m.Info()
		if err != nil {
			closeAll()
			return nil, false
		}
		id, ok := info.ID()
		if !ok {
			closeAll()
			return nil, false
		}
		allowed[id] = true
	}
	for _, p := range []*ebpf.Program{f.prog, f.clear} {
		info, err := p.Info()
		if err != nil {
			closeAll()
			return nil, false
		}
		used, ok := info.MapIDs()
		if !ok {
			closeAll()
			return nil, false
		}
		for _, id := range used {
			if !allowed[id] && !isDataSectionMap(id) {
				closeAll()
				return nil, false
			}
		}
	}
	return f, true
}

// isNilCloser reports a typed nil behind the interface.
func isNilCloser(c interface{ Close() error }) bool {
	switch v := c.(type) {
	case *ebpf.Program:
		return v == nil
	case *ebpf.Map:
		return v == nil
	}
	return false
}

// isDataSectionMap reports whether the map with this id is a global-variable section (.rodata, .bss): the one a
// pinned program was loaded with, never shared.
func isDataSectionMap(id ebpf.MapID) bool {
	m, err := ebpf.NewMapFromID(id)
	if err != nil {
		return false
	}
	defer func() { _ = m.Close() }()
	info, err := m.Info()
	return err == nil && info.Type == ebpf.Array && strings.HasPrefix(info.Name, ".")
}

// lockFill takes the build's fill lock for this mode, exclusively, for pinning the fill (openPlaneFiller), so no two
// launchers pin at once. Fills and clears take no lock: each launcher's config and templates are keyed by its tgid,
// and a clear touches only its slot's rows (enforce-plane §2.6).
func (p *bpfPlane) lockFill() (func(), error) {
	if p.state == nil {
		return func() {}, nil
	}
	name := "bpf-" + p.hash + planeFillLockTag + string(p.mode) + ".lock"
	f, err := p.state.OpenFile(name, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cgroup: open the plane's fill lock: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("cgroup: lock the plane's fill lock: %w", err)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}

// prepareSlot makes the slot's two row maps exist, creating and inserting each one the slot has not had yet (the
// one RCU grace period an outer insert waits for, paid once per slot and build, never per run), and zeroes the
// slot's counters (§2.2).
func (p *bpfPlane) prepareSlot(slot uint32) error {
	if err := makeSlotMaps(p.rows, p.execRows, p.innerSpec, slot, p.listenRows); err != nil {
		return err
	}
	if err := p.counters.Put(slot, ebpfbindings.PlaneCounts{}); err != nil {
		return fmt.Errorf("cgroup: zero slot %d's plane counters: %w", slot, err)
	}
	return nil
}

// makeSlotMaps makes the slot's fs and exec row maps exist in the outers rows and execRows, creating and inserting
// each one the slot has not had yet from its inner spec.
func makeSlotMaps(rows, execRows *ebpf.Map, innerSpec func(string) (*ebpf.MapSpec, error), slot uint32, listeners ...*ebpf.Map) error {
	type outerSpec struct {
		outer *ebpf.Map
		name  string
	}
	outers := []outerSpec{{rows, ebpfbindings.MapPlaneRows}, {execRows, ebpfbindings.MapPlaneExecRows}}
	if len(listeners) > 0 {
		outers = append(outers, outerSpec{listeners[0], ebpfbindings.MapPlaneListenRows})
	}
	for _, o := range outers {
		if err := makeSlotMap(o.outer, o.name, innerSpec, slot); err != nil {
			return err
		}
	}
	return nil
}

// makeSlotMap makes the slot's map in outer exist, creating and inserting it from its inner spec when the slot has
// none yet.
func makeSlotMap(outer *ebpf.Map, name string, innerSpec func(string) (*ebpf.MapSpec, error), slot uint32) error {
	// Read by a batch lookup, not a lookup of the slot: below 6.7 each ends in synchronize_rcu
	// (ebpfbindings.InnerIDs).
	ids, err := ebpfbindings.InnerIDs(outer)
	if err != nil {
		return fmt.Errorf("cgroup: read slot %d of %s: %w", slot, name, err)
	}
	if _, ok := ids[slot]; ok {
		return nil
	}
	full, err := innerSpec(name)
	if err != nil {
		return fmt.Errorf("cgroup: load slot %d's %s definition: %w", slot, name, err)
	}
	inner, err := ebpf.NewMap(full)
	if err != nil {
		return fmt.Errorf("cgroup: create slot %d's %s map: %w", slot, name, err)
	}
	err = outer.Update(slot, inner, ebpf.UpdateNoExist)
	_ = inner.Close() // the outer holds its own reference
	if err != nil && !errors.Is(err, ebpf.ErrKeyExist) {
		return fmt.Errorf("cgroup: put slot %d's %s map: %w", slot, name, err)
	}
	return nil
}

// counts reads the slot's counters as the plane's programs left them.
func (p *bpfPlane) counts(slot uint32) (ebpfbindings.PlaneCounts, error) {
	var c ebpfbindings.PlaneCounts
	if p.counters == nil {
		return c, fmt.Errorf("cgroup: the %s plane has no counters map", p.mode)
	}
	if err := p.counters.Lookup(slot, &c); err != nil {
		return c, fmt.Errorf("cgroup: read slot %d's plane counters: %w", slot, err)
	}
	return c, nil
}

// innerOf opens the slot's map in outer (ebpfbindings.OpenInner: no synchronize_rcu below 6.7). A slot that holds
// none is ebpf.ErrKeyNotExist, as the outer's lookup said it.
func innerOf(outer *ebpf.Map, slot uint32, name string) (*ebpf.Map, error) {
	inner, ok, err := ebpfbindings.OpenInner(outer, slot)
	if err == nil && !ok {
		err = ebpf.ErrKeyNotExist
	}
	if err != nil {
		return nil, fmt.Errorf("cgroup: open slot %d's %s map: %w", slot, name, err)
	}
	return inner, nil
}

// fill writes a run's rows: the fs and exec rows through the fill (in the kernel, from the held descriptors, checked
// against the plan), then the slot's unix policy and bare-name rows from here (their keys are no inode), each with the
// run's gen, and last the slot's header (slotHeader), before Arm makes any of it decide: a slot whose header is not
// the run's refuses every decided hook, so a fill that stops part way leaves a slot that refuses. A map too full of
// the slot's previous rows to take a userspace row is cleared of them (keeping this gen) and written once more, as
// the fill does for its own.
func (p *bpfPlane) fill(req planeFillRequest) (planeFillReport, error) {
	plan, err := planPlaneFill(req.Rows, req.Slot, req.Gen, req.Held, hostIdentity{})
	if err != nil {
		return planeFillReport{}, err
	}
	if err := planPlaneListenFill(plan, req.Rows, req.ListenHeld, hostIdentity{}); err != nil {
		return planeFillReport{}, err
	}
	if planeFillTestHook != nil {
		fds := make([]int, len(plan.Entries))
		for i, e := range plan.Entries {
			fds[i] = e.FD
		}
		planeFillTestHook(fds)
	}
	rep, err := p.filler.fill(plan, req.Rows, planeFillOptions{})
	if err != nil {
		return rep, err
	}
	if err := p.putUnixPolicy(req); err != nil {
		return rep, err
	}
	keys, vals, err := execKeyRows(req)
	if err != nil {
		return rep, err
	}
	if err := p.putNameRows(req, keys, vals); err != nil {
		return rep, err
	}
	if err := p.putListenNames(req); err != nil {
		return rep, err
	}
	if err := p.putNameEntries(req); err != nil {
		return rep, err
	}
	if err := p.putPins(req); err != nil {
		return rep, err
	}
	hdr := slotHeader(req, p.unix, rep.Rows, rep.ExecRows+len(keys))
	if err := nameHeaderFits(req, &hdr); err != nil {
		return rep, err
	}
	if err := p.slots.Put(req.Slot, &hdr); err != nil {
		return rep, fmt.Errorf("cgroup: write slot %d's %s: %w", req.Slot, ebpfbindings.MapPlaneSlots, err)
	}
	return rep, nil
}

// nameHeaderFits fails a header whose run has name rows and which does not say the name check decides: one that
// cannot carry the run's leads, whose rows would be written and never asked.
func nameHeaderFits(req planeFillRequest, hdr *ebpfbindings.PlaneSlot) error {
	if req.Rows != nil && len(req.Rows.NameRows) > 0 && hdr.Flags&ebpfbindings.PlaneSlotNameDecides == 0 {
		return fmt.Errorf("cgroup: slot %d's header cannot carry the run's %d name leads and %d prefix lengths",
			req.Slot, len(req.Rows.Leads), len(req.Rows.PrefixLens))
	}
	return nil
}

// ErrPlaneNameKey is a name row whose key the slot's name map already holds for this run: two literals compile did
// not see collide (ADR 0043 D9). Prepare fails rather than overwrite a deny row with another row or an exemption.
var ErrPlaneNameKey = errors.New("cgroup: a name row's key is taken in the slot's name map")

// putNameEntries writes the run's name entries (ADR 0043 D9) when its table has any, in D9's order: the slot's name
// map made to exist and cleared of every key (a previous run's rows share it until then, and the clear comes before
// the config row, so its 65 entries need no headroom), then the config row, then each name row with BPF_NOEXIST.
// An error stops Prepare before the header, which alone makes the rows decide (TEGO_SLOT_NAME_DECIDES). A table
// with no name entry writes nothing, and a previous run's rows stay inert: its header's flag is clear and their gen is
// another's.
func (p *bpfPlane) putNameEntries(req planeFillRequest) error {
	rows := req.Rows
	if rows == nil || len(rows.NameRows) == 0 {
		return nil
	}
	if p.nameRows == nil {
		return fmt.Errorf("cgroup: the %s plane has no %s map", p.mode, ebpfbindings.MapPlaneNameRows)
	}
	if err := makeSlotMap(p.nameRows, ebpfbindings.MapPlaneNameRows, p.innerSpec, req.Slot); err != nil {
		return err
	}
	inner, err := innerOf(p.nameRows, req.Slot, ebpfbindings.MapPlaneNameRows)
	if err != nil {
		return err
	}
	defer func() { _ = inner.Close() }()
	return writeNameEntries(inner, req.Slot, req.Gen, rows)
}

// writeNameEntries is D9's write of rows' name entries into slot's inner name map inner, at gen: every key cleared,
// then the config row, then each name row with BPF_NOEXIST. Prepare (putNameEntries) and doctor's known answers
// (ProbeRows.Fill) write through it, before the header that makes the rows decide.
func writeNameEntries(inner *ebpf.Map, slot, gen uint32, rows *decide.PlaneRows) error {
	if err := deleteNameRows(inner, slot); err != nil {
		return err
	}
	cfg, ok := ebpfbindings.NewPlaneNameConfig(gen, rows.NameEntryMasks(), agent.EnvSkipDirs)
	if !ok {
		return fmt.Errorf("cgroup: slot %d's name config row cannot carry %d entries", slot, len(rows.NameEntryMasks()))
	}
	if err := inner.Update(uint64(0), &cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("cgroup: write slot %d's name config row: %w", slot, err)
	}
	for _, r := range rows.NameRows {
		arms := make([]ebpfbindings.PlaneNameArm, len(r.Arms))
		for i, a := range r.Arms {
			arms[i] = ebpfbindings.PlaneNameArm{Scopes: a.Scopes, Depth: a.Depth, RawFrom: a.RawFrom, Rule: a.Rule}
			if a.Exempt {
				arms[i].Flags = ebpfbindings.PlaneNameArmExempt
			}
		}
		v, ok := ebpfbindings.NewPlaneNameRow(r.Name, r.Prefix, gen, arms)
		if !ok {
			return fmt.Errorf("cgroup: the name row %q cannot be written", r.Name)
		}
		if err := inner.Update(r.Key, &v, ebpf.UpdateNoExist); err != nil {
			if errors.Is(err, ebpf.ErrKeyExist) {
				return fmt.Errorf("%w: %q", ErrPlaneNameKey, r.Name)
			}
			return mapFull(ebpfbindings.MapPlaneNameRows, err)
		}
	}
	return nil
}

// deleteNameRows deletes every key of a slot's inner name map: its config row and its name rows, of every gen. The
// map holds at most 65 keys (ADR 0043 D9), so the keys are read first and then deleted one by one; only the slot's
// own Prepare and its clears write the map, never concurrently with each other (enforce-plane §2.6).
func deleteNameRows(inner *ebpf.Map, slot uint32) error {
	var (
		key  uint64
		val  ebpfbindings.PlaneNameRow
		keys []uint64
	)
	it := inner.Iterate()
	for it.Next(&key, &val) {
		keys = append(keys, key)
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("cgroup: read slot %d's %s: %w", slot, ebpfbindings.MapPlaneNameRows, err)
	}
	for _, k := range keys {
		if err := inner.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("cgroup: clear slot %d's %s: %w", slot, ebpfbindings.MapPlaneNameRows, err)
		}
	}
	return nil
}

// clearNameRows deletes the slot's name entries (ADR 0043 D9's clear), which userspace wrote and so clears: the
// kernel's clear (tego_plane_clear) keeps to the inode-keyed maps. A slot that never held a name map has none to
// clear. The inner map itself stays in the outer, as the fs and exec inner maps do: replacing it would cost a
// grace period on every kernel below 6.7 (bpf.InnerIDs).
func (p *bpfPlane) clearNameRows(slot uint32) error {
	if p.nameRows == nil {
		return nil
	}
	inner, ok, err := ebpfbindings.OpenInner(p.nameRows, slot)
	if err != nil {
		return fmt.Errorf("cgroup: open slot %d's %s map: %w", slot, ebpfbindings.MapPlaneNameRows, err)
	}
	if !ok {
		return nil
	}
	defer func() { _ = inner.Close() }()
	return deleteNameRows(inner, slot)
}

// putNameRows writes the bare-name exec rows, keyed by no inode.
func (p *bpfPlane) putNameRows(req planeFillRequest, keys []uint64, vals []ebpfbindings.PlaneExecRow) error {
	if len(keys) == 0 {
		return nil
	}
	exec, err := innerOf(p.execRows, req.Slot, ebpfbindings.MapPlaneExecRows)
	if err != nil {
		return err
	}
	defer func() { _ = exec.Close() }()
	for i := range keys {
		err := exec.Put(keys[i], &vals[i])
		if errors.Is(err, unix.E2BIG) {
			if _, _, cerr := p.filler.clearSlot(req.Slot, req.Gen); cerr != nil {
				return cerr
			}
			err = exec.Put(keys[i], &vals[i])
		}
		if err != nil {
			return mapFull(ebpfbindings.MapPlaneExecRows, err)
		}
	}
	return nil
}

// putUnixPolicy writes the slot's step D policy with the run's gen (enforce-plane R14). It decides only where this
// plane's unix hooks are loaded; the policy is written either way, since a hook that finds none of the run's gen
// refuses.
func (p *bpfPlane) putUnixPolicy(req planeFillRequest) error {
	pol := ebpfbindings.PlaneUnix{Gen: req.Gen}
	if req.Unix.Decides && p.unix {
		pol.Decides, pol.RelayCgroupID = 1, req.Unix.Relay
	}
	if err := p.unixPolicy.Put(req.Slot, &pol); err != nil {
		return fmt.Errorf("cgroup: write slot %d's %s: %w", req.Slot, ebpfbindings.MapPlaneUnixPolicy, err)
	}
	return nil
}

// decidesUnix reports whether this plane's step D hooks were loaded (enforce-plane R14).
func (p *bpfPlane) decidesUnix() bool { return p.unix }

// hooks is the set of hooks this plane attached (planeKernel.hooks).
func (p *bpfPlane) hooks() map[string]bool { return p.attached }

// execKeyRows are the exec rows keyed by no inode: one row per bare-name entry (PlaneRows.Names), keyed by
// bpf.PlaneNameKey, when the contract has an exec: section. Whether exec is decided is the slot header's flag.
func execKeyRows(req planeFillRequest) ([]uint64, []ebpfbindings.PlaneExecRow, error) {
	if !req.Exec.Decides {
		return nil, nil, nil // no exec: section: bprm_check decides nothing, and no name row is read
	}
	var (
		keys []uint64
		vals []ebpfbindings.PlaneExecRow
	)
	for _, n := range req.Rows.Names {
		key, ok := ebpfbindings.PlaneNameKey(n.Name)
		name, length, ok2 := ebpfbindings.PlaneExecName(n.Name)
		if !ok || !ok2 || n.Rule < 0 || n.Rule > int(ebpfbindings.PlaneRuleMax) {
			return nil, nil, fmt.Errorf("plane fill: the exec entry %q (%d) cannot be a name row", n.Name, n.Rule)
		}
		keys = append(keys, key)
		vals = append(vals, ebpfbindings.PlaneExecRow{Gen: req.Gen, RuleIdx: uint16(n.Rule), NameLen: length, Name: name})
	}
	return keys, vals, nil
}

// clearSlot zeroes the slot's header, then deletes every row of the slot, of every gen, in the kernel (T4's clear),
// and last its exec pins and name entries from here (clearPins, clearNameRows). The header goes first: a run-set row that still names the slot is refused by every decided hook from then on
// (norows), never decided by rows half cleared. No lock is taken: a clear touches only its slot's rows (enforce-plane
// §2.6). A slot with no rows map in this mode has no rows, and clearing it is no error: the reaper purges every dead
// slot through every pinned plane of the build, most of whose slots no run of that mode prepared. The fill's own
// clear, whose slot it prepared, still fails on one.
func (p *bpfPlane) clearSlot(slot uint32) error {
	if p.filler == nil {
		return nil
	}
	if p.slots != nil {
		if err := p.slots.Put(slot, &ebpfbindings.PlaneSlot{}); err != nil {
			return fmt.Errorf("cgroup: clear slot %d's %s: %w", slot, ebpfbindings.MapPlaneSlots, err)
		}
	}
	if _, _, err := p.filler.clearSlot(slot, 0); err != nil && !errors.Is(err, errPlaneNoRows) {
		return err
	}
	return errors.Join(p.clearPins(slot), p.clearNameRows(slot))
}

// closeLinks closes this process's descriptors of the plane's host-wide links, so that removing their pins, which
// only the build's last launcher out does, is what detaches them (bpfKernel.unpin).
func (p *bpfPlane) closeLinks() error {
	var errs []error
	for _, l := range p.links {
		if err := l.Close(); err != nil {
			errs = append(errs, fmt.Errorf("cgroup: close plane link: %w", err))
		}
	}
	p.links = nil
	return errors.Join(errs...)
}

// close releases every descriptor; the pins keep the plane attached for the build's other runs.
func (p *bpfPlane) close() error {
	errs := []error{p.closeLinks()}
	if p.filler != nil {
		errs = append(errs, p.filler.Close())
		p.filler = nil
	}
	if p.coll != nil {
		p.coll.Close()
		p.coll = nil
	}
	return errors.Join(errs...)
}

// openPinnedPlanes opens, for a reaper or a sweep, the row maps and the pinned fill of every plane directory build
// hash has under base: what a clear needs, and nothing that attaches. A mode with no pinned fill is skipped: its
// slots' rows are absent to every later run by their gen, and the slot's next Prepare clears them.
func openPinnedPlanes(base, hash string, state *hoststate.Dir) ([]*bpfPlane, error) {
	var (
		out  []*bpfPlane
		errs []error
	)
	for _, m := range planeModes {
		lay := newPlaneLayout(pinLayout{Base: base}, hash, m)
		rows, err := loadPinnedMap(lay.Maps, ebpfbindings.MapPlaneRows)
		if err != nil || rows == nil {
			errs = append(errs, err)
			continue
		}
		execRows, err := loadPinnedMap(lay.Maps, ebpfbindings.MapPlaneExecRows)
		if err != nil || execRows == nil {
			_ = rows.Close()
			errs = append(errs, err)
			continue
		}
		listenRows, err := loadPinnedMap(lay.Maps, ebpfbindings.MapPlaneListenRows)
		if err != nil || listenRows == nil {
			_ = rows.Close()
			_ = execRows.Close()
			errs = append(errs, err)
			continue
		}
		f, ok := adoptPlaneFiller("", lay.Fill, rows, execRows, listenRows)
		if !ok {
			_ = rows.Close()
			_ = execRows.Close()
			_ = listenRows.Close()
			continue
		}
		// The headers' map, to zero a dead slot's header before its rows go; a plane pinned without one (none is
		// loaded so) is cleared of its rows alone. So are the exec pin maps, which a dead slot's key and pins leave.
		slots, err := loadPinnedMap(lay.Maps, ebpfbindings.MapPlaneSlots)
		if err != nil {
			errs = append(errs, err)
		}
		execPins, err := loadPinnedMap(lay.Maps, ebpfbindings.MapPlaneExecPins)
		if err != nil {
			errs = append(errs, err)
		}
		pinKeys, err := loadPinnedMap(lay.Maps, ebpfbindings.MapPlanePinKeys)
		if err != nil {
			errs = append(errs, err)
		}
		// The name map, whose entries userspace clears (clearNameRows). No plane of this build is loaded or adopted
		// without it (ADR 0043 D9); a pin without one holds no name entry to clear.
		names, err := loadPinnedMap(lay.Maps, ebpfbindings.MapPlaneNameRows)
		if err != nil {
			errs = append(errs, err)
		}
		out = append(out, &bpfPlane{mode: m, layout: lay, hash: hash, state: state, rows: rows, execRows: execRows, listenRows: listenRows,
			slots: slots, nameRows: names, filler: f, execPins: execPins, pinKeys: pinKeys})
	}
	return out, errors.Join(errs...)
}

// closePinned releases what openPinnedPlanes opened.
func (p *bpfPlane) closePinned() error {
	errs := []error{p.close()}
	for _, m := range []*ebpf.Map{p.rows, p.execRows, p.listenRows, p.slots, p.execPins, p.pinKeys, p.nameRows} {
		if m != nil {
			errs = append(errs, m.Close())
		}
	}
	return errors.Join(errs...)
}
