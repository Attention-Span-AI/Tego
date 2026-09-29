// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/startphase"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	enforcecg "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
)

// The plane's functional probe (ADR 0024 (3); docs/p0/enforce-plane.md R21). For each mode that its preconditions
// allow it loads the mode's full hook set from the chosen build into doctor's own fds, maps unpinned, and attaches
// every program with doctor's own links. It then starts a child of its own binary (PlaneProbeCommand) inside a
// scratch cgroup, and once the child has exec'd, arms that cgroup in the probe's own tego_run_set as a run whose
// slot has no header and no rows map: the probe row. Every deciding body must refuse under it (a run-set hit whose
// slot holds no header of its gen is the plane's fail-closed NOROWS, R6, R7 and §7), so the child's one syscall per
// hook must read EACCES where the body decides (bpf.PlaneHook.Decides, set on every hook). The same syscalls from doctor itself,
// outside the cgroup and with the row still armed, must pass (R1). BPF run statistics show each program ran. The
// child, its cgroup, the fixtures, the links, the programs and the maps are all gone when the probe returns: it
// pins nothing (I7). A mode whose rows and scope pass then answers the known answers (planeknown.go).

// PlaneProbeCommand is argv[1] of the plane probe's child (`tego __doctor-plane-probe child <dir>`), and of the
// program the child execs for bprm_check (`... noop`). cmd/tego dispatches it before anything else, as it does
// __child: the child's syscalls after arming must be the probe's own and nothing a CLI would add.
const PlaneProbeCommand = "__doctor-plane-probe"

// planeProbeTimeout bounds each wait on the child: its start, its answers and its exit.
const planeProbeTimeout = 10 * time.Second

// planeProbeIdx and planeProbeGen are the probe row's run_idx and gen. The probe's maps are its own, so any slot
// serves; no header (planeProbeGen is never written to one) and no rows map exists at any.
const (
	planeProbeIdx = 0
	planeProbeGen = 1
)

// Probe results of one syscall.
const (
	planePassed  = "passed"
	planeRefused = "refused"
)

// planeChildRole is the child's first argument, "child"; a test sets another to drive the paths where the child
// never becomes ready.
var planeChildRole = "child"

// planeScratchPrefix names the probe's scratch cgroup and fixture directory.
const planeScratchPrefix = ".tego-doctor-plane-"

// probePlane is the plane probe: the environment, the build, and each mode's rows and verdict, with tier cgroup's
// mode selected under pin. keep is true only for a run (ForRun's scope, where the run-probe cache is on): then a
// mode's matched known answers are read from and kept in the known-answers cache; doctor's own scope passes false
// and exercises every cell afresh (limits-check-doctor-cli R27). It never fails: what it cannot establish is an answer (§4).
func probePlane(root bool, uid int, release, pin string, keep bool) (*PlaneState, []HookResult) {
	st := &PlaneState{Pin: pin, Source: planeSourceProbed}
	if !root {
		st.Skipped = true
		return st, nil
	}
	spec, err := loadKernelSpec()
	if err != nil {
		st.BuildWhy = "the kernel's BTF is unavailable: " + err.Error()
		for _, m := range bpfobj.PlaneModes {
			st.Modes = append(st.Modes, PlaneModeResult{Mode: m, Detail: st.BuildWhy,
				Fix: "boot a kernel built with CONFIG_DEBUG_INFO_BTF=y"})
		}
		selectPlane(st)
		return st, nil
	}
	memlockOnce.Do(raiseMemlock)
	st.Env = readPlaneEnv(spec, release)
	build, why, buildFix := choosePlaneBuild(st.Env, carriesPlaneObject)
	st.Build, st.BuildWhy = build, why
	st.BuildHash, _ = bpfobj.Hash()
	lsm, _ := ReadLSMState() // on an error its Source is none, which modePrecondition and probePlaneMode read
	// The known answers' row maps and fill, one set for both modes (each fills its own slot), so the fill build is
	// loaded once per probe, and off the known answers' path: beside the first mode's load and probe row.
	known := &planeKnownRows{cache: newPlaneKnownCache(release, uid, keep), kept: map[bpfobj.PlaneMode]planeKnownKept{}}
	for _, m := range bpfobj.PlaneModes {
		if build == "" {
			break
		}
		start := time.Now()
		if a, pin, ok := known.cache.load(m, build); ok {
			known.kept[m] = planeKnownKept{known: a, execPin: pin, took: time.Since(start)}
		}
	}
	// The row maps and the fill build are made only when a mode has no kept answers to read.
	if build != "" && len(known.kept) < len(bpfobj.PlaneModes) {
		endRows := startphase.Begin(nil, "probe.plane.rows")
		known.rows, known.err = enforcecg.NewProbeRows(build)
		endRows()
		if known.rows != nil {
			known.ready = make(chan struct{})
			go func() {
				defer close(known.ready)
				defer startphase.Begin(nil, "probe.plane.preload")() // beside the modes' loads, not on their path
				known.loadErr = known.rows.Preload(planeKnownSlot(bpfobj.PlaneLSM), planeKnownSlot(bpfobj.PlaneFmodRet))
			}()
			defer func() {
				<-known.ready
				_ = known.rows.Close()
			}()
		}
	}
	// One exec image for every mode's probe, made by the first mode that reaches its syscalls.
	image := &planeImage{fd: -1}
	defer image.close()
	var rows []HookResult
	for _, m := range bpfobj.PlaneModes {
		endMode := startphase.Begin(nil, "probe.plane."+string(m)+".total")
		res, modeRows := probePlaneMode(m, spec, st.Env, lsm, build, why, buildFix, uid, known, image)
		endMode()
		st.Modes = append(st.Modes, res)
		rows = append(rows, modeRows...)
	}
	selectPlane(st)
	return st, rows
}

// carriesPlaneObject reports whether this binary embeds build o.
func carriesPlaneObject(o bpfobj.Object) bool {
	for _, have := range bpfobj.PlaneObjects() {
		if have == o {
			return true
		}
	}
	return false
}

// planeStaticRows is one mode's rows before any load: each hook's target in BTF and its prototype. An optional hook
// whose target this kernel's BTF lacks is an Absent row (enforce-plane R3): the mode is selected without it, since
// another hook decides its rule here, and the row says which.
func planeStaticRows(m bpfobj.PlaneMode, spec *btf.Spec) ([]HookResult, bool) {
	ok := true
	rows := make([]HookResult, 0, len(bpfobj.PlaneHooks))
	for _, h := range bpfobj.PlaneHooks {
		r := HookResult{Hook: planeRowName(h, m), Plane: m, Function: planeTarget(h, m), Decides: h.Decides}
		if h.Optional && !inBTF(spec, r.Function) {
			r.Absent = true
			r.Detail = "not in this kernel (" + planeAbsentWhy[h.Name] + "); the mode runs without it"
			rows = append(rows, r)
			continue
		}
		n, err := checkPrototype(spec, r.Function, planeParamsFor(h, m))
		r.Arity = n
		if err != nil {
			r.Detail = err.Error()
			ok = false
		} else {
			r.BTF = true
		}
		rows = append(rows, r)
	}
	return rows, ok
}

// planeAbsentWhy says, for each optional plane hook, which hook decides its rule on a kernel without it.
var planeAbsentWhy = map[string]string{
	"file_truncate":    "below 6.2 ftruncate(2) and an O_TRUNC open reach path_truncate, which decides them",
	"inode_set_acl":    "below 6.2 setfacl is an xattr write, which inode_setxattr decides",
	"inode_remove_acl": "below 6.2 removing an ACL is an xattr removal, which inode_removexattr decides",
	"key_permission":   "CONFIG_KEYS is disabled, so keyring operations are unavailable",
}

// planeKnownRows is the known answers' row maps and fill (enforce/cgroup ProbeRows), or why there are none, and the
// preload of the fill build and the slots' maps, which ready closes on.
type planeKnownRows struct {
	rows    *enforcecg.ProbeRows
	err     error
	ready   chan struct{}
	loadErr error
	// cache keeps a mode's answers once every cell matched, and kept holds what it had for each mode at the start
	// of the probe (planeknowncache.go): a mode found there is not filled again.
	cache planeKnownCache
	kept  map[bpfobj.PlaneMode]planeKnownKept
}

// planeKnownKept is a mode's kept answers and what reading them took.
type planeKnownKept struct {
	known   []PlaneKnownAnswer
	execPin *PlaneExecPinCell
	took    time.Duration
}

// wait waits for the preload and returns why the known answers cannot be filled, nil when they can.
func (k *planeKnownRows) wait() error {
	if k.rows == nil {
		if k.err == nil {
			return errors.New("no plane build to fill")
		}
		return k.err
	}
	<-k.ready
	return k.loadErr
}

// probePlaneMode is one mode: preconditions, static rows, then the load, attach and syscalls, and the known answers.
func probePlaneMode(m bpfobj.PlaneMode, spec *btf.Spec, env PlaneEnv, lsm LSMState, build bpfobj.Object, buildWhy,
	buildFix string, uid int, known *planeKnownRows, image *planeImage) (PlaneModeResult, []HookResult) {
	rows, protoOK := planeStaticRows(m, spec)
	if detail, fix := modePrecondition(m, env, lsm); detail != "" {
		// An LSM list no mechanism could read rules LSM mode out without saying bpf is inactive; its cause may be
		// transient, so the answer is Faulted and the run-probe cache does not keep it.
		return PlaneModeResult{Mode: m, Detail: detail, Fix: fix,
			Faulted: m == bpfobj.PlaneLSM && lsm.Source == LSMSourceNone}, rows
	}
	if build == "" {
		return PlaneModeResult{Mode: m, Detail: "no build of decide.bpf.c loads here: " + buildWhy, Fix: buildFix}, rows
	}
	if !protoOK {
		var bad []string
		for _, r := range rows {
			if !r.BTF && !r.Absent {
				bad = append(bad, r.Hook+" ("+r.Detail+")")
			}
		}
		return PlaneModeResult{Mode: m, Detail: "prototype check failed: " + strings.Join(bad, "; "),
			Fix: "boot a kernel whose " + string(m) + " hooks match the 6.1 prototypes, or pin bpf.plane to the other " +
				"mode in /etc/tego/config.yaml"}, rows
	}
	run, err := runPlaneProbe(m, spec, build, uid, rows, known, image)
	if err != nil {
		return planeProbeFailed(m, err, rows), rows
	}
	v := planeModeVerdict(m, rows, run.scope, run.known)
	v.ExecPin = run.execPin
	v.KnownTook, v.KnownPhases = run.knownTook.Total, run.knownTook.Phases
	return v, rows
}

// planeProbeFailed is mode m's result when its probe returned err, and fills the rows' empty details with it. The
// error is a fault (PlaneModeResult.Faulted), except a load the kernel refuses the same way every time (loadFault):
// that is a failed mode, and the run-probe cache keeps it for the boot rather than loading both modes again on
// every run.
func planeProbeFailed(m bpfobj.PlaneMode, err error, rows []HookResult) PlaneModeResult {
	for i := range rows {
		if rows[i].Detail == "" {
			rows[i].Detail = err.Error()
		}
	}
	fix := "report this line as a tego bug, or pin bpf.plane to the other mode in /etc/tego/config.yaml"
	if errors.Is(err, errAttachTransient) {
		fix = "re-run once the kernel has memory and trampoline slots to spare; nothing is cached, so the next " +
			"run probes again"
	}
	var le *planeLoadError
	faulted := !errors.As(err, &le) || loadFault(err)
	return PlaneModeResult{Mode: m, Tested: true, Faulted: faulted, Detail: err.Error(), Fix: fix}
}

// planeRig is one mode's loaded set: its programs by hook, the run-set and counters maps, and the links.
type planeRig struct {
	// mode is the mode the rig's programs are loaded in: the probe row names it (Run.Plane), since a program
	// decides only a run prepared in its own mode.
	mode bpfobj.PlaneMode
	// hooks are the hooks loaded, bpf.PlaneHooksFor this kernel: an optional hook it lacks is not; progs is theirs,
	// in the same order.
	hooks    []bpfobj.PlaneHook
	progs    []*ebpf.Program
	runSet   *ebpf.Map
	counters *ebpf.Map
	links    []link.Link
	// execPin is the mode's exec pin program (bpf.PlaneExecPinProgram), loaded with the known answers' maps for the
	// exec pin cell, and execPinWhy why the cell cannot run on this rig ("" when it can).
	execPin    *ebpf.Program
	execPinWhy string
}

// close detaches and unloads everything the rig holds.
func (r *planeRig) close() {
	for _, l := range r.links {
		_ = l.Close()
	}
	for _, p := range append(r.progs, r.execPin) {
		if p != nil {
			_ = p.Close()
		}
	}
	for _, m := range []*ebpf.Map{r.runSet, r.counters} {
		if m != nil {
			_ = m.Close()
		}
	}
}

// noRows reads the probe row's slot's NOROWS count, 0 when it cannot be read.
func (r *planeRig) noRows() uint64 {
	var c bpfobj.PlaneCounts
	if r.counters == nil || r.counters.Lookup(uint32(planeProbeIdx), &c) != nil {
		return 0
	}
	return c.NoRows
}

// loadPlaneRig loads mode m's programs of build o, with only the maps they reference, all unpinned, into
// doctor's own fds (loadOneProgram's lazy loader, for a whole set). With known, the programs read the known
// answers' row and exec pin maps in place of their own, and the mode's exec pin program is loaded too, for the exec
// pin cell (planeexecpin.go).
func loadPlaneRig(m bpfobj.PlaneMode, spec *btf.Spec, o bpfobj.Object, known *enforcecg.ProbeRows) (*planeRig, error) {
	cs, err := bpfobj.Load(o)
	if err != nil {
		return nil, err
	}
	for _, ms := range cs.Maps {
		ms.Pinning = ebpf.PinNone
	}
	hooks := bpfobj.PlaneHooksFor(m, func(fn string) bool { return inBTF(spec, fn) })
	fields := make([]reflect.StructField, 0, len(hooks)+2)
	for i, h := range hooks {
		fields = append(fields, reflect.StructField{Name: "P" + strconv.Itoa(i), Type: reflect.TypeFor[*ebpf.Program](),
			Tag: reflect.StructTag(`ebpf:"` + h.Program(m) + `"`)})
	}
	fields = append(fields, reflect.StructField{Name: "RunSet", Type: reflect.TypeFor[*ebpf.Map](),
		Tag: reflect.StructTag(`ebpf:"` + bpfobj.MapRunSet + `"`)},
		reflect.StructField{Name: "Counters", Type: reflect.TypeFor[*ebpf.Map](),
			Tag: reflect.StructTag(`ebpf:"` + bpfobj.MapPlaneCounters + `"`)})
	pinWhy := "the known answers' maps could not be made"
	if known != nil {
		pinWhy = "build " + string(o) + " has no " + bpfobj.PlaneExecPinProgram(m)
		if cs.Programs[bpfobj.PlaneExecPinProgram(m)] != nil {
			pinWhy = ""
			fields = append(fields, reflect.StructField{Name: "ExecPin", Type: reflect.TypeFor[*ebpf.Program](),
				Tag: reflect.StructTag(`ebpf:"` + bpfobj.PlaneExecPinProgram(m) + `"`)})
		}
	}
	v := reflect.New(reflect.StructOf(fields))
	opts := &ebpf.CollectionOptions{Programs: bpfobj.LoadOptions()} // the zero options outside a timed test build
	opts.Programs.KernelTypes = spec
	if known != nil {
		opts.MapReplacements = map[string]*ebpf.Map{bpfobj.MapPlaneRows: known.Rows, bpfobj.MapPlaneExecRows: known.ExecRows,
			bpfobj.MapPlaneListenRows: known.ListenRows, bpfobj.MapPlaneNameRows: known.NameRows, bpfobj.MapPlaneSlots: known.Slots,
			bpfobj.MapPlaneExecPins: known.ExecPins, bpfobj.MapPlanePinKeys: known.PinKeys}
	}
	// A timed test build attributes the load to its maps and each program (probe.plane.<mode>.maps,
	// probe.plane.prog.<mode>.<prog>.*; enforce-plane §10.1).
	trace := bpfobj.BeginLoad(nil, "probe.plane."+string(m)+".maps", "probe.plane.prog."+string(m))
	if err := cs.LoadAndAssign(v.Interface(), opts); err != nil {
		trace.End(nil)
		return nil, &planeLoadError{msg: fmt.Sprintf("load %s %s: %s", o, m, verifierTail(err)), err: err}
	}
	rig := &planeRig{mode: m, hooks: hooks, execPinWhy: pinWhy}
	loaded := make(map[string]*ebpf.Program, len(hooks))
	for i, h := range hooks {
		p, _ := v.Elem().Field(i).Interface().(*ebpf.Program)
		rig.progs = append(rig.progs, p)
		loaded[h.Program(m)] = p
	}
	trace.End(loaded)
	rig.runSet, _ = v.Elem().Field(len(hooks)).Interface().(*ebpf.Map)
	rig.counters, _ = v.Elem().Field(len(hooks) + 1).Interface().(*ebpf.Map)
	if pinWhy == "" {
		rig.execPin, _ = v.Elem().Field(len(hooks) + 2).Interface().(*ebpf.Program)
	}
	return rig, nil
}

// planeLoadError is a failed load of a mode's programs: its message is the verifier log's tail, and it wraps the
// loader's error so loadFault can read the cause.
type planeLoadError struct {
	msg string
	err error
}

func (e *planeLoadError) Error() string { return e.msg }
func (e *planeLoadError) Unwrap() error { return e.err }

// loadFault reports whether a load error is a probe that could not finish rather than a mode this kernel refuses.
// The verifier's rejection, a kfunc, helper or program type the kernel lacks (ebpf.ErrNotSupported), ENOSYS and
// EOPNOTSUPP are the kernel's same answer every time: a failed mode, kept for the boot. Any of them caused by an
// errno that can pass on its own (memory or memcg pressure, a busy or interrupted call, fds or space running out, a
// charging EPERM, E2BIG, which is not always the verifier's size limit) is a fault, and so is every other error: only
// an error known to repeat may be kept.
func loadFault(err error) bool {
	for _, e := range []unix.Errno{unix.ENOMEM, unix.E2BIG, unix.EBUSY, unix.EAGAIN, unix.EINTR, unix.EMFILE,
		unix.ENFILE, unix.ENOSPC, unix.EPERM} {
		if errors.Is(err, e) {
			return true
		}
	}
	var ve *ebpf.VerifierError
	return !errors.As(err, &ve) && !errors.Is(err, ebpf.ErrNotSupported) && !errors.Is(err, unix.ENOSYS) &&
		!errors.Is(err, unix.EOPNOTSUPP)
}

// progOf is the rig's program index of the hook a row names, -1 for a hook it did not load (an Absent row).
func (r *planeRig) progOf(row HookResult) int {
	for i, h := range r.hooks {
		if planeRowName(h, r.mode) == row.Hook {
			return i
		}
	}
	return -1
}

// errAttachTransient marks an attach that failed for a cause that can pass on its own.
var errAttachTransient = errors.New("a cause that can pass on its own")

// attachFault is the probe's fault for hook's attach error err when its errno can pass on its own (memory or memcg
// pressure, a trampoline whose link slots another tool fills, a busy or interrupted call, a charging EPERM), else
// nil: the row then records a failure the mode fails on, which the run-probe cache keeps for the boot, so only an
// errno known to repeat may be one.
func attachFault(hook string, err error) error {
	for _, e := range []unix.Errno{unix.ENOMEM, unix.E2BIG, unix.EBUSY, unix.EAGAIN, unix.EINTR, unix.EPERM} {
		if errors.Is(err, e) {
			return fmt.Errorf("attach %s: %s (%w)", hook, verifierTail(err), errAttachTransient)
		}
	}
	return nil
}

// planeRun is what one mode's probe found: the probe row's scope evidence and the known answers, with what the
// known answers took.
type planeRun struct {
	scope     planeScope
	known     []PlaneKnownAnswer
	knownTook planeKnownTiming
	execPin   *PlaneExecPinCell
}

// runPlaneProbe loads, attaches and exercises mode m, filling rows, and once every row and the scope passed, runs
// the known answers. An error is a probe that could not run to its end; a row that failed on its own is recorded
// in the row.
func runPlaneProbe(m bpfobj.PlaneMode, spec *btf.Spec, o bpfobj.Object, uid int, rows []HookResult,
	known *planeKnownRows, image *planeImage) (planeRun, error) {
	// A timed test build reports the mode's steps as probe.plane.<mode>.{load,attach,exercise,known,detach}
	// (enforce-plane §10.1's cold attribution); a product build times nothing.
	phase := "probe.plane." + string(m)
	endLoad := startphase.Begin(nil, phase+".load")
	rig, err := loadPlaneRig(m, spec, o, known.rows)
	endLoad()
	if err != nil {
		return planeRun{}, err
	}
	defer func() {
		endDetach := startphase.Begin(nil, phase+".detach")
		rig.close()
		endDetach()
	}()
	endAttach := startphase.Begin(nil, phase+".attach")
	for i := range rows {
		if rows[i].Absent {
			continue
		}
		rows[i].Object = string(o)
		j := rig.progOf(rows[i])
		if j < 0 || rig.progs[j] == nil {
			rows[i].Detail = "load: the loader returned no program"
			continue
		}
		rows[i].Loaded = true
		var l link.Link
		if m == bpfobj.PlaneLSM {
			l, err = link.AttachLSM(link.LSMOptions{Program: rig.progs[j]})
		} else {
			l, err = link.AttachTracing(link.TracingOptions{Program: rig.progs[j], AttachType: ebpf.AttachModifyReturn})
		}
		if err != nil {
			rows[i].Detail = "attach: " + verifierTail(err)
			if f := attachFault(rows[i].Hook, err); f != nil {
				endAttach()
				return planeRun{}, f
			}
			continue
		}
		rig.links = append(rig.links, l)
		rows[i].Attached = true
	}
	if rig.execPin != nil {
		// The exec pin program's attach fails the exec pin cell, never the mode: a run of it is then unpinned.
		l, err := link.AttachTracing(link.TracingOptions{Program: rig.execPin, AttachType: ebpf.AttachTraceRawTp})
		if err != nil {
			rig.execPinWhy = "attach " + bpfobj.PlaneExecPinProgram(m) + ": " + verifierTail(err)
		} else {
			rig.links = append(rig.links, l)
		}
	}
	endAttach()
	for _, r := range rows {
		if !r.Attached && !r.Absent {
			return planeRun{}, nil // the rows say which; the mode fails on them
		}
	}
	endExercise := startphase.Begin(nil, phase+".exercise")
	sc, err := exercisePlane(rig, uid, rows, image)
	endExercise()
	run := planeRun{scope: sc}
	if err != nil {
		return run, err
	}
	for _, r := range rows {
		if !r.OK() {
			return run, nil // the mode fails on its rows; the known answers would add nothing
		}
	}
	if sc.Inside == 0 || sc.Outside != 0 {
		return run, nil
	}
	if kept, ok := known.kept[m]; ok {
		run.known, run.execPin = kept.known, kept.execPin
		run.knownTook = planeKnownTiming{Total: kept.took,
			Phases: []string{fmt.Sprintf("read from an earlier probe of this boot %v", kept.took.Round(10*time.Microsecond))}}
		return run, nil
	}
	endKnown := startphase.Begin(nil, phase+".known")
	run.known, run.knownTook, err = exercisePlaneKnown(rig, known, uid)
	endKnown()
	if err != nil || !knownAllMatch(run.known) {
		known.cache.store(m, o, run.known, nil)
		return run, err
	}
	// The exec pin cell (ADR 0048 (7)) runs once the known answers matched; a cell that could not run to its end is
	// pins off for this probe and is not kept.
	endPin, pinStart := startphase.Begin(nil, phase+".exec_pin"), time.Now()
	cell, perr := exercisePlaneExecPin(rig, known, uid)
	endPin()
	run.knownTook.Phases = append(run.knownTook.Phases, fmt.Sprintf("exec pin cell %v", time.Since(pinStart).Round(100*time.Microsecond)))
	if perr != nil {
		cell = &PlaneExecPinCell{Detail: "the cell could not run: " + perr.Error()}
	}
	run.execPin = cell
	if perr == nil {
		known.cache.store(m, o, run.known, cell)
	}
	return run, nil
}

// exercisePlane runs the probe syscalls against an attached rig: the child's inside the scratch cgroup with the
// probe row armed, doctor's own outside it with the row still armed.
func exercisePlane(rig *planeRig, uid int, rows []HookResult, img *planeImage) (sc planeScope, err error) {
	stats, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		return sc, fmt.Errorf("enable BPF run statistics: %w", err)
	}
	defer func() { _ = stats.Close() }()

	dir, err := makeFixtureDir(planeScratchPrefix)
	if err != nil {
		return sc, fmt.Errorf("fixtures: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	for _, side := range []string{"in", "out"} {
		if err := makePlaneFixtures(filepath.Join(dir, side)); err != nil {
			return sc, fmt.Errorf("fixtures: %w", err)
		}
		closeSockets, err := bindPlaneSockets(filepath.Join(dir, side))
		if err != nil {
			return sc, fmt.Errorf("fixtures: %w", err)
		}
		defer closeSockets()
	}
	cg, err := newPlaneCgroup(uid)
	if err != nil {
		return sc, fmt.Errorf("scratch cgroup: %w", err)
	}
	defer cg.remove()

	// One exec image for both sides and both modes: the child inherits it and doctor's own exec runs it
	// (planeExecImage); probePlane closes it after the last mode.
	image, err := img.get()
	if err != nil {
		return sc, fmt.Errorf("the exec image: %w", err)
	}
	child, err := startPlaneChild(cg, filepath.Join(dir, "in"), image)
	if err != nil {
		return sc, err
	}
	defer child.stop()

	before, rowsBefore := runCounts(rig), rig.noRows()
	key := cg.id
	if err := rig.runSet.Put(key, bpfobj.Run{RunIdx: planeProbeIdx, Tier: 3, Plane: bpfobj.RunPlaneOf(rig.mode), Gen: planeProbeGen}); err != nil {
		return sc, fmt.Errorf("arm the probe row: %w", err)
	}
	defer func() {
		if derr := rig.runSet.Delete(key); derr != nil && err == nil {
			err = fmt.Errorf("disarm the probe row: %w", derr)
		}
	}()
	inside, err := child.run()
	if err != nil {
		return sc, err
	}
	// Join the governed helper before the outside snapshot. Its owned key
	// cleanup also reaches permission hooks, and must not race the outside
	// scope check after the last result has been written to the pipe.
	if err := child.wait(); err != nil {
		return sc, err
	}
	after, rowsInside := runCounts(rig), rig.noRows()
	outDir := filepath.Join(dir, "out")
	outPre := planeMakeEach
	outPre.image = image
	for i, h := range bpfobj.PlaneHooks {
		// Outside first, in hook order for every hook, the absent ones too: the side's fixtures are made for
		// that order (removexattr after setxattr).
		outside := planeOutcome(planeAction(h.Name, outDir, outPre))
		if rows[i].Absent {
			continue
		}
		rows[i].Inside = inside[h.Name]
		if rows[i].Inside == "" {
			rows[i].Inside = "no answer from the probe child"
		}
		if j := rig.progOf(rows[i]); j >= 0 {
			rows[i].Ran = after[j] > before[j]
		}
		rows[i].Outside = outside
	}
	sc = planeScope{Inside: rowsInside - rowsBefore, Outside: rig.noRows() - rowsInside}
	for i := range rows {
		if !rows[i].OK() && rows[i].Detail == "" {
			rows[i].Detail = planeRowFault(rows[i])
		}
	}
	return sc, nil
}

// planeRowFault says what an attached row failed on.
func planeRowFault(r HookResult) string {
	want := planePassed
	if r.Decides {
		want = planeRefused
	}
	switch {
	case !r.Ran:
		return "the program never ran for the probe syscall (not attached where the kernel calls it)"
	case r.Inside != want:
		return fmt.Sprintf("in the scratch cgroup the syscall %s, want %s", r.Inside, want)
	case r.Outside != planePassed:
		return fmt.Sprintf("outside every run the syscall %s, want passed", r.Outside)
	}
	return ""
}

// runCounts reads each program's run count; 0 where statistics cannot be read.
func runCounts(rig *planeRig) []uint64 {
	out := make([]uint64, len(rig.progs))
	for i, p := range rig.progs {
		if p == nil {
			continue
		}
		if s, err := p.Stats(); err == nil {
			out[i] = s.RunCount
		}
	}
	return out
}

// makePlaneFixtures makes one side's fixtures: a file to open, one to rename, one to link, one to unlink, a
// directory to remove, and step B's: files to truncate by path and by descriptor, to chmod, to chown, to set and
// remove an xattr on and to set and remove an ACL on.
func makePlaneFixtures(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	for _, name := range []string{"open", "ren", "lnk", "unl", "trn", "ftr", "chm", "cho", "xat", "acl"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			return err
		}
	}
	return os.Mkdir(filepath.Join(dir, "rmd"), 0o700)
}

// planeImageName is the exec image's memfd name, which the child checks its inherited descriptor by.
const planeImageName = "tego-plane-probe"

// planeImage is the probe's one exec image (planeExecImage), shared by every mode that reaches its syscalls: made
// on the first get, closed by probePlane after the last mode. The image depends on this binary alone, so a second
// copy would buy nothing. A failed make is not kept: the next mode tries again.
type planeImage struct {
	fd int
}

// makePlaneImage is how planeImage makes its image; a test counts the copies through it.
var makePlaneImage = planeExecImage

// get returns the image's descriptor, made on the first call.
func (p *planeImage) get() (int, error) {
	if p.fd >= 0 {
		return p.fd, nil
	}
	fd, err := makePlaneImage()
	if err != nil {
		return -1, err
	}
	p.fd = fd
	return fd, nil
}

// close closes the image, if one was made.
func (p *planeImage) close() {
	if p.fd >= 0 {
		_ = unix.Close(p.fd)
		p.fd = -1
	}
}

// planeExecImage is a memfd holding a copy of this binary, the image the bprm_check probe execs. An exec of a
// named file would open it through file_open first, which a deciding plane refuses in the probe row (no rows map)
// before bprm_check is reached; a memfd is no path, so file_open lets it through (enforce-plane §2.6) and bprm_check
// decides it. doctor makes one per probe (planeImage) before the first mode starts its child; each mode's child
// inherits it as descriptor 3 (planeImageFD), so that nothing is opened once the row is armed, and doctor's own exec
// runs the same image.
func planeExecImage() (int, error) {
	src, err := os.Open("/proc/self/exe")
	if err != nil {
		return -1, err
	}
	defer func() { _ = src.Close() }()
	// MFD_EXEC (6.3+) asks for an executable memfd where vm.memfd_noexec=0 or 1 would seal it otherwise; older
	// kernels refuse the flag. At vm.memfd_noexec=2 every executable memfd is EACCES, which modePrecondition
	// names before any load.
	const mfdExec = 0x10
	fd, err := unix.MemfdCreate(planeImageName, unix.MFD_CLOEXEC|mfdExec)
	if errors.Is(err, unix.EINVAL) {
		fd, err = unix.MemfdCreate(planeImageName, unix.MFD_CLOEXEC)
	}
	if err != nil {
		return -1, err
	}
	dst := os.NewFile(uintptr(fd), planeImageName)
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return -1, err
	}
	nfd, err := unix.Dup(fd)
	_ = dst.Close()
	if err != nil {
		return -1, err
	}
	unix.CloseOnExec(nfd)
	return nfd, nil
}

// bindPlaneSockets binds one side's unix sockets, which step D's probe syscalls address: a listening stream socket,
// "sock", and a datagram socket, "dg", that nothing reads (a probe's one datagram never fills its queue). doctor
// holds both until the returned function closes them.
func bindPlaneSockets(dir string) (func(), error) {
	var fds []int
	closeAll := func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}
	for _, s := range []struct {
		name string
		typ  int
	}{{"sock", unix.SOCK_STREAM}, {"dg", unix.SOCK_DGRAM}} {
		fd, err := unix.Socket(unix.AF_UNIX, s.typ|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			closeAll()
			return nil, err
		}
		fds = append(fds, fd)
		if err := unix.Bind(fd, &unix.SockaddrUnix{Name: filepath.Join(dir, s.name)}); err != nil {
			closeAll()
			return nil, err
		}
		if s.typ == unix.SOCK_STREAM {
			if err := unix.Listen(fd, 4); err != nil {
				closeAll()
				return nil, err
			}
		}
	}
	return closeAll, nil
}

// planePre is what a side of the probe makes before the probe row is armed, each -1 to be made around its syscall:
// bprm_check's exec image (planeExecImage, never -1: both sides exec the one doctor made), the unix stream and datagram sockets step D's syscalls use,
// the file step B's ftruncate(2) truncates, and the memfd step C's syscalls map (planeMapFile). The
// child makes its own before it says ready, so no socket(2) of its runs under the probe row, and each socket's
// cgroup, the one the plane keys a unix decision by, is the scratch cgroup it was made in.
type planePre struct {
	image, stream, dgram, trunc, mapfd int
	bind, listening, key               int
	keyErr                             error
	ptraceTarget, traceme              *planeChild
}

// planeMakeEach makes everything around its syscall: doctor's own side, outside every run, which sets only the image.
var planeMakeEach = planePre{image: -1, stream: -1, dgram: -1, trunc: -1, mapfd: -1, bind: -1, listening: -1, key: -1}

// planeMapFile is a one-page memfd, the file step C's probe syscalls map: an anonymous file, which a run with no
// rows map refuses to map executable (NOROWS) and the host maps freely. It is made sealed against exec where the
// kernel honours MFD_NOEXEC_SEAL, which the mapping does not need (the seal governs the file's execute bits, not a
// PROT_EXEC map), so vm.memfd_noexec=2 does not refuse it.
func planeMapFile() (int, error) {
	const mfdNoexecSeal = 0x8
	fd, err := unix.MemfdCreate("tego-plane-map", unix.MFD_CLOEXEC|mfdNoexecSeal)
	if errors.Is(err, unix.EINVAL) {
		fd, err = unix.MemfdCreate("tego-plane-map", unix.MFD_CLOEXEC)
	}
	if err != nil {
		return -1, err
	}
	if err := unix.Ftruncate(fd, int64(os.Getpagesize())); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// planeMap is step C's probe syscall for hook: mmap_file maps fd PROT_READ|PROT_EXEC; file_mprotect maps it
// PROT_READ, which no step C body decides, and mprotects the mapping to PROT_READ|PROT_EXEC. fd below 0 is made and
// closed around it.
func planeMap(hook string, fd int) error {
	if fd < 0 {
		var err error
		if fd, err = planeMapFile(); err != nil {
			return fmt.Errorf("the mapped file: %w", err)
		}
		defer func() { _ = unix.Close(fd) }()
	}
	prot := unix.PROT_READ | unix.PROT_EXEC
	if hook == "file_mprotect" {
		prot = unix.PROT_READ
	}
	b, err := unix.Mmap(fd, 0, os.Getpagesize(), prot, unix.MAP_PRIVATE)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Munmap(b) }()
	if hook == "file_mprotect" {
		return unix.Mprotect(b, unix.PROT_READ|unix.PROT_EXEC)
	}
	return nil
}

// planeImageFD is the descriptor the probe child inherits doctor's exec image on (startPlaneChild's ExtraFiles).
const planeImageFD = 3

// inheritedPlaneImage is the exec image the child inherited on planeImageFD. It is refused unless that descriptor is
// planeExecImage's memfd, so a child started without one (fd 3 is then whatever the runtime opened) fails rather
// than exec something else. It is marked close-on-exec: the noop gets its own duplicate.
func inheritedPlaneImage() (int, error) {
	target, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(planeImageFD))
	if err != nil {
		return -1, err
	}
	if !strings.HasPrefix(target, "/memfd:"+planeImageName+" ") {
		return -1, fmt.Errorf("descriptor %d is %q, not the probe's exec image", planeImageFD, target)
	}
	unix.CloseOnExec(planeImageFD)
	return planeImageFD, nil
}

// newPlanePre is the child's image, inherited, and its sockets.
func newPlanePre() (planePre, error) {
	pre := planeMakeEach
	var err error
	if pre.image, err = inheritedPlaneImage(); err != nil {
		return pre, fmt.Errorf("the exec image: %w", err)
	}
	if pre.stream, err = unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0); err != nil {
		return pre, fmt.Errorf("a unix stream socket: %w", err)
	}
	if pre.dgram, err = unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); err != nil {
		return pre, fmt.Errorf("a unix datagram socket: %w", err)
	}
	if pre.mapfd, err = planeMapFile(); err != nil {
		return pre, fmt.Errorf("the mapped file: %w", err)
	}
	if err := pre.prepareControls(); err != nil {
		pre.closeControls()
		return pre, err
	}
	return pre, nil
}

// planeSocket is fd, or a new unix socket of typ that the returned function closes.
func planeSocket(fd, typ int) (int, func(), error) {
	if fd >= 0 {
		return fd, func() {}, nil
	}
	fd, err := unix.Socket(unix.AF_UNIX, typ|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return -1, nil, err
	}
	return fd, func() { _ = unix.Close(fd) }, nil
}

// planeACL is a POSIX ACL equivalent to mode 0644 in its xattr form (fs/posix_acl.c posix_acl_from_xattr): version 2,
// then user::rw-, group::r--, other::r--, each tag, perm and an undefined id. setfacl's setxattr of it reaches
// security_inode_set_acl from 6.2, and security_inode_setxattr before.
var planeACL = []byte{
	2, 0, 0, 0,
	0x01, 0, 6, 0, 0xff, 0xff, 0xff, 0xff,
	0x04, 0, 4, 0, 0xff, 0xff, 0xff, 0xff,
	0x20, 0, 4, 0, 0xff, 0xff, 0xff, 0xff,
}

// planeXattrPassed maps what the filesystem answers after the security hook passed an xattr or ACL call to a pass:
// no support for the namespace, or nothing to remove. The hook ran (the row's run count says so) and let it by.
func planeXattrPassed(err error) error {
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.ENODATA) {
		return nil
	}
	return err
}

// planeAction is the one syscall that exercises a hook, on dir's fixtures, made with raw syscalls so that nothing
// else is opened on the way. The exec runs this binary's noop from pre.image, a planeExecImage descriptor; the
// socket hooks connect pre.stream to dir's "sock" and send one datagram on pre.dgram to its "dg"; step C's hooks
// map pre.mapfd (planeMap). What pre holds below 0 is made and closed around the syscall.
func planeAction(hook, dir string, pre planePre) error {
	image := pre.image
	switch hook {
	case "socket_bind", "socket_listen", "ptrace_access_check", "ptrace_traceme", "bpf", "key_permission":
		return planeControlAction(hook, pre)
	case "mmap_file", "file_mprotect":
		return planeMap(hook, pre.mapfd)
	case "socket_connect":
		fd, done, err := planeSocket(pre.stream, unix.SOCK_STREAM)
		if err != nil {
			return err
		}
		defer done()
		return unix.Connect(fd, &unix.SockaddrUnix{Name: filepath.Join(dir, "sock")})
	case "socket_sendmsg":
		fd, done, err := planeSocket(pre.dgram, unix.SOCK_DGRAM)
		if err != nil {
			return err
		}
		defer done()
		return unix.Sendto(fd, []byte{0}, 0, &unix.SockaddrUnix{Name: filepath.Join(dir, "dg")})
	case "file_open":
		fd, err := unix.Open(filepath.Join(dir, "open"), unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err == nil {
			_ = unix.Close(fd)
		}
		return err
	case "bprm_check":
		if image < 0 {
			return errors.New("no exec image")
		}
		// The image goes to the child as descriptor 3 on a duplicate, which the os.File owns and closes.
		dup, err := unix.Dup(image)
		if err != nil {
			return fmt.Errorf("the exec image: %w", err)
		}
		img := os.NewFile(uintptr(dup), planeImageName)
		defer func() { _ = img.Close() }()
		// Through proc.Start, the one process start (ADR 0021 (3)). Every stdio is this process's stderr, so os/exec
		// opens nothing (no /dev/null) on the way to the exec. In the probe row the exec itself is refused, before
		// proc.Start reads the child's identity.
		cmd := proc.Command("/proc/self/fd/3", PlaneProbeCommand, "noop")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr, os.Stderr
		cmd.ExtraFiles = []*os.File{img}
		if _, err := proc.Start(cmd); err != nil {
			return err
		}
		if err := cmd.Wait(); err != nil {
			return fmt.Errorf("the exec'd noop ended: %w", err)
		}
		return nil
	case "path_rename":
		return unix.Rename(filepath.Join(dir, "ren"), filepath.Join(dir, "ren.to"))
	case "path_link":
		return unix.Link(filepath.Join(dir, "lnk"), filepath.Join(dir, "lnk.to"))
	case "path_unlink":
		return unix.Unlink(filepath.Join(dir, "unl"))
	case "path_rmdir":
		return unix.Rmdir(filepath.Join(dir, "rmd"))
	case "path_mknod":
		return unix.Mknod(filepath.Join(dir, "fifo"), unix.S_IFIFO|0o600, 0)
	case "path_mkdir":
		return unix.Mkdir(filepath.Join(dir, "mkd"), 0o700)
	case "path_symlink":
		return unix.Symlink("open", filepath.Join(dir, "sym"))
	case "path_truncate":
		return unix.Truncate(filepath.Join(dir, "trn"), 0)
	case "file_truncate":
		fd := pre.trunc
		if fd < 0 {
			var err error
			if fd, err = unix.Open(filepath.Join(dir, "ftr"), unix.O_WRONLY|unix.O_CLOEXEC, 0); err != nil {
				return fmt.Errorf("the file to truncate: %w", err)
			}
			defer func() { _ = unix.Close(fd) }()
		}
		return unix.Ftruncate(fd, 0)
	case "path_chmod":
		return unix.Chmod(filepath.Join(dir, "chm"), 0o600)
	case "path_chown":
		return unix.Chown(filepath.Join(dir, "cho"), -1, -1)
	case "inode_setxattr":
		return planeXattrPassed(unix.Setxattr(filepath.Join(dir, "xat"), "trusted.tego-probe", []byte("1"), 0))
	case "inode_removexattr":
		return planeXattrPassed(unix.Removexattr(filepath.Join(dir, "xat"), "trusted.tego-probe"))
	case "inode_set_acl":
		return planeXattrPassed(unix.Setxattr(filepath.Join(dir, "acl"), "system.posix_acl_access", planeACL, 0))
	case "inode_remove_acl":
		return planeXattrPassed(unix.Removexattr(filepath.Join(dir, "acl"), "system.posix_acl_access"))
	case "socket_create":
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err == nil {
			_ = unix.Close(fd)
		}
		return err
	}
	return fmt.Errorf("no probe syscall for hook %s", hook)
}

// planeOutcome names a syscall's result: passed, refused (EACCES, the plane's one refusal, R2), or the error.
func planeOutcome(err error) string {
	switch {
	case err == nil:
		return planePassed
	case errors.Is(err, unix.EACCES):
		return planeRefused
	}
	return "failed: " + err.Error()
}

// planeOutcomeFaulted reports whether a row's syscall outcome says the probe could not finish rather than that the
// mode decided wrong: an errno other than EACCES (ENOSPC or EDQUOT on the fixtures directory, EAGAIN or ENOMEM from
// fork, EMFILE) or no answer from the child may be transient or the host's, so the answer is Faulted and not cached
// (PlaneModeResult.Faulted). ENOSYS and EOPNOTSUPP are the kernel's same answer every time: a failed mode.
func planeOutcomeFaulted(s string) bool {
	switch s {
	case "", planePassed, planeRefused:
		return false
	}
	for _, e := range []unix.Errno{unix.ENOSYS, unix.EOPNOTSUPP} {
		if strings.HasSuffix(s, e.Error()) {
			return false
		}
	}
	return true
}

// planeCgroup is the probe's scratch cgroup.
type planeCgroup struct {
	path string
	id   uint64
	fd   int
}

// newPlaneCgroup makes the scratch cgroup under the invoking uid's delegated subtree, as D7's is.
func newPlaneCgroup(uid int) (*planeCgroup, error) {
	fs, err := cgroup.Detect(uid)
	if err != nil {
		return nil, err
	}
	path, err := makeScratchDir(fs.Root(), planeScratchPrefix)
	if err != nil {
		return nil, err
	}
	c := &planeCgroup{path: path, fd: -1}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		c.remove()
		return nil, err
	}
	c.id = st.Ino // cgroup v2's id is the directory's kernfs inode, what bpf_get_current_cgroup_id() reports
	if c.fd, err = unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err != nil {
		c.remove()
		return nil, err
	}
	return c, nil
}

// remove closes and removes the scratch cgroup; its one process is reaped before this runs.
func (c *planeCgroup) remove() {
	if c.fd >= 0 {
		_ = unix.Close(c.fd)
		c.fd = -1
	}
	_ = os.Remove(c.path)
}

// planeChild is the probe's child inside the scratch cgroup.
type planeChild struct {
	cmd    *proc.Cmd
	stdin  io.WriteCloser
	stdout *os.File
	lines  *bufio.Reader
	done   bool
}

// planeStdoutPipe is how startPlaneChildAs makes the child's stdout pipe; a test fails it to count what leaks.
var planeStdoutPipe = os.Pipe

// startPlaneChild starts this binary's PlaneProbeCommand child directly in the scratch cgroup
// (clone3(CLONE_INTO_CGROUP)) and waits until it has exec'd and said ready: the probe row is armed only after
// that, as a run's is armed after the stage's exec (R15).
func startPlaneChild(cg *planeCgroup, dir string, image int) (*planeChild, error) {
	return startPlaneChildAs(cg, planeChildRole, dir, image)
}

// startPlaneChildAs is startPlaneChild with the child's role: "child", the probe row's, which inherits doctor's
// exec image, or "known", the known answers', which execs nothing and is passed image -1.
func startPlaneChildAs(cg *planeCgroup, role, dir string, image int) (*planeChild, error) {
	exe := "/proc/self/exe"
	cmd := proc.Command(exe, PlaneProbeCommand, role, dir)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if cg != nil {
		cmd.SysProcAttr.UseCgroupFD, cmd.SysProcAttr.CgroupFD = true, cg.fd
	}
	cmd.Stderr = os.Stderr
	if image >= 0 {
		// The exec image goes to the child as planeImageFD on a duplicate, closed here once the child has it.
		dup, err := unix.Dup(image)
		if err != nil {
			return nil, fmt.Errorf("the exec image: %w", err)
		}
		img := os.NewFile(uintptr(dup), planeImageName)
		defer func() { _ = img.Close() }()
		cmd.ExtraFiles = []*os.File{img}
	}
	// The stdout pipe comes first: StdinPipe's pair is owned by cmd, which closes it only on Start or Wait, so a
	// failure after it would leave both ends open until a GC finalizer.
	pr, pw, err := planeStdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("the probe child's stdout: %w", err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, fmt.Errorf("the probe child's stdin: %w", err)
	}
	cmd.Stdout = pw
	if _, err := proc.Start(cmd); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		_ = stdin.Close()
		return nil, fmt.Errorf("start the %s probe child: %w", role, err)
	}
	_ = pw.Close()
	c := &planeChild{cmd: cmd, stdin: stdin, stdout: pr, lines: bufio.NewReader(pr)}
	line, err := c.readLine()
	if err != nil || line != "ready" {
		c.stop()
		return nil, fmt.Errorf("the probe child did not start: %q %v", line, err)
	}
	return c, nil
}

// readLine reads one line within planeProbeTimeout.
func (c *planeChild) readLine() (string, error) {
	_ = c.stdout.SetReadDeadline(time.Now().Add(planeProbeTimeout))
	line, err := c.lines.ReadString('\n')
	return strings.TrimSuffix(line, "\n"), err
}

// run tells the child to make its syscalls and reads one answer per hook.
func (c *planeChild) run() (map[string]string, error) {
	if _, err := io.WriteString(c.stdin, "go\n"); err != nil {
		return nil, fmt.Errorf("the probe child: %w", err)
	}
	out := map[string]string{}
	for range bpfobj.PlaneHooks {
		line, err := c.readLine()
		if err != nil {
			return out, fmt.Errorf("the probe child answered %d of %d hooks: %w", len(out), len(bpfobj.PlaneHooks), err)
		}
		name, res, _ := strings.Cut(line, "\t")
		out[name] = res
	}
	return out, nil
}

// wait reaps the child, which exits once it has answered.
func (c *planeChild) wait() error {
	_ = c.stdin.Close()
	errc := make(chan error, 1)
	go func() { errc <- c.cmd.Wait() }()
	select {
	case err := <-errc:
		c.done = true
		_ = c.stdout.Close()
		if err != nil {
			return fmt.Errorf("the probe child: %w", err)
		}
		return nil
	case <-time.After(planeProbeTimeout):
		_ = c.cmd.Process.Kill()
		werr := <-errc
		c.done = true
		_ = c.stdout.Close()
		return fmt.Errorf("the probe child did not exit within %s; its Wait after the kill: %v", planeProbeTimeout, werr)
	}
}

// stop kills and reaps the child if it has not been reaped, so the scratch cgroup can be removed.
func (c *planeChild) stop() {
	if c.done {
		return
	}
	_ = c.cmd.Process.Kill()
	_ = c.stdin.Close()
	_ = c.cmd.Wait()
	_ = c.stdout.Close()
	c.done = true
}

// PlaneProbeMain is the plane probe's child and noop, `tego __doctor-plane-probe child <dir>` and `... noop`. The
// child says ready, waits for go, then makes each hook's one syscall on dir's fixtures and prints
// "<hook>\t<outcome>" per hook, in bpf.PlaneHooks order. It opens nothing but what the syscalls name.
func PlaneProbeMain(args []string) int {
	if len(args) == 1 && args[0] == "noop" {
		return 0
	}
	if len(args) == 2 && args[0] == "known" {
		return planeKnownMain(args[1])
	}
	if len(args) == 2 && args[0] == planePinWriterRole {
		return planePinWriterMain()
	}
	if len(args) == 2 && (args[0] == "ptrace-target" || args[0] == planeTracemeRole) {
		return planePtraceHelper(args[0])
	}
	if len(args) != 2 || args[0] != "child" {
		fmt.Fprintln(os.Stderr, "usage: "+PlaneProbeCommand+" child <dir> | known <dir> | noop")
		return 2
	}
	dir := args[1]
	pre, err := newPlanePre()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer pre.closeControls()
	if pre.trunc, err = unix.Open(filepath.Join(dir, "ftr"), unix.O_WRONLY|unix.O_CLOEXEC, 0); err != nil {
		fmt.Fprintln(os.Stderr, "the file to truncate:", err)
		return 1
	}
	if _, err := os.Stdout.WriteString("ready\n"); err != nil {
		return 1
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil || line != "go\n" {
		return 1
	}
	var b strings.Builder
	for _, h := range bpfobj.PlaneHooks {
		fmt.Fprintf(&b, "%s\t%s\n", h.Name, planeOutcome(planeAction(h.Name, dir, pre)))
	}
	if _, err := os.Stdout.WriteString(b.String()); err != nil {
		return 1
	}
	return 0
}
