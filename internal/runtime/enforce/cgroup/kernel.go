// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/startphase"
	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
)

// kernel is everything a Handle does to the kernel, behind one seam. The real implementation loads the
// embedded objects, pins them and attaches links; the tests substitute a double, which is what lets the
// whole of Prepare's ordering, unwinding and teardown be exercised without privilege.
type kernel interface {
	// trackingFailures reads the durable per-slot membership-failure counter.
	trackingFailures(slot uint32) (uint64, error)
	// populate writes the run's verdict rows into the two network maps and the unix name trie.
	populate(rules RuleMaps) error
	// insertRun adds one cgroup id to the run set under BPF_NOEXIST; an existing row with the same value is left
	// alone, and one with another value, another run's, is refused.
	insertRun(cgroupID uint64, val ebpfbindings.Run) error
	// removeRun deletes a cgroup's run-set row and its reason breadcrumb.
	removeRun(cgroupID uint64) error
	// breadcrumb reads the run's last network decision, tego_reason_map's row under its cgroup id (§5 R5);
	// found is false when there is none.
	breadcrumb(cgroupID uint64) (br ebpfbindings.Breadcrumb, found bool, err error)
	// removeRules deletes the run's verdict rows.
	removeRules(rules RuleMaps) error
	// purgeSlot deletes every verdict row keyed by a run_idx and zeroes its counters, so a slot reclaimed from a
	// launcher that died without tearing down is clean before this run's rows are written (§5 R12, §8 I5, ADR
	// 0026 (4)). The slot's rings are placeRings' to reuse or replace (ADR 0026 (6) as amended).
	purgeSlot(runIdx uint32) error
	// placeRing creates a ring of kind (ebpfbindings.RingRecord, RingCapture) and size bytes and inserts it into its
	// outer at slot, unless its memlock is more than room: then nothing is inserted and placed is false. memlock
	// is what the ring charges, placed or not (ADR 0026 (2)).
	placeRing(kind string, slot, size uint32, room uint64) (memlock uint64, placed bool, err error)
	// slotRings is the size of each ring this build's outers hold at slot, by kind; a kind it has none of is absent.
	slotRings(slot uint32) (map[string]uint32, error)
	// removeRing deletes the slot's ring of kind; a slot with none is not an error.
	removeRing(kind string, slot uint32) error
	// drainRing consumes every committed record of the slot's ring of kind, for the run that reuses it.
	drainRing(kind string, slot uint32) error
	// reclaimRings removes every ring of every build under base at a slot that build's run set does not carry
	// and noOne says no launcher holds, and reports what they charged and how many they were.
	reclaimRings(base string, noOne func(hash string, slot uint32) (bool, error)) (freed uint64, rings int, err error)
	// ringUse is the memlock every live ring of every build under base charges now, and how many rings that is
	// (the host-wide use bpf.ring_budget caps).
	ringUse(base string) (bytes uint64, rings int, err error)
	// attachCgroup attaches the loaded CGROUP_SOCK_ADDR programs (eight, or six below 6.7), cgroup/sock_create and
	// cgroup/setsockopt to a cgroup directory and writes owner into that cgroup's tego_net_owners storage, which is
	// where the deciding programs read their run from.
	attachCgroup(path string, owner ebpfbindings.NetOwner) error
	// detachCgroup closes this run's cgroup links, before any row it wrote is removed (§5 R15).
	detachCgroup() error
	// unpin removes the build's pinned maps, programs and links; only the last launcher out calls it.
	unpin() error
	// runSetLive reports whether the run set holds a row for a cgroup that exists, deleting the rows of vanished
	// ones: a build is never removed under a run it enforces (ADR 0022 (1)).
	runSetLive(mount string) (bool, error)
	// planeOf is the decision plane loaded with the build for this run (Options.Plane), nil when the run has none.
	planeOf() planeKernel
	// close releases every descriptor this value owns.
	close() error
}

// bpfHash is the build identity of the embedded objects.
func bpfHash() (string, error) { return ebpfbindings.Hash() }

// bpfKernel is the real implementation: three collections sharing one set of pinned maps, the host-wide
// tracing links shared by every launcher of this build, and this run's own cgroup links.
type bpfKernel struct {
	pins pinLayout
	// released is the programs of the links unpin removed, which close waits for the kernel to free (teardown).
	released teardown
	// phase receives the load's sub-phase timings (Options.Phase); nil means startphase.Default.
	phase startphase.Sink

	// colls holds one collection per object, in load order, so close releases them in reverse.
	colls []*ebpf.Collection
	// maps are the six shared maps and cgroup_net's own two (tego_net_owners, tego_unix_names), reused from
	// the pins after the first launcher created them.
	maps map[string]*ebpf.Map
	// progs indexes every loaded program by name.
	progs map[string]*ebpf.Program
	// shared holds the host-wide tracing and cgroup-lifecycle links, pinned so launchers share them.
	shared []sharedLink
	// execResultLinks names successfully attached and pinned optional result hooks.
	execResultLinks map[string]bool
	// cgroupLinks holds this run's cgroup attachments, one per loaded CGROUP_SOCK_ADDR program. Each is pinned
	// under runLinks as it attaches (ADR 0020 (1)): a bpf_link is freed on its last close (kernel commit
	// af6eea57437a), so the unpinned links of before went with a SIGKILLed launcher's descriptors and took the
	// run's network policy off an agent tree that was still alive (§6 E38). Pinned, they stay until Detach
	// unpins them, or until the run's reaper or a sweep does once the run's cgroup is removed (PurgeRun).
	cgroupLinks []link.Link
	// netAttached records successful run-specific attachments, including optional
	// Unix hooks. Loaded programs alone do not establish destination coverage.
	netAttached   map[string]bool
	networkFlags  uint32
	bindCleanup   bool
	listenCleanup bool
	// runLinks is <pins.Links>/run-<id>, where the run's cgroup links are pinned; "" pins nothing.
	runLinks string
	// planes is the build's decision plane a run decides in (newBPFPlane), at most one: the Handle clears and fills
	// its slot through planeOf. pinnedPlanes are every mode pinned for the build, opened by a reaper, whose rows of a
	// dead launcher's slot purgeSlot clears (openPinnedPlanes).
	planes       []*bpfPlane
	pinnedPlanes []*bpfPlane
}

// planeOf is the plane a run was prepared with.
func (k *bpfKernel) planeOf() planeKernel {
	if len(k.planes) == 0 {
		return nil
	}
	return k.planes[0]
}

// sharedLink is one host-wide link and the pin that keeps it attached between launchers.
type sharedLink struct {
	link.Link
	pin string
}

// newBPFKernel loads and pins the three objects and attaches the host-wide programs. It is the only place
// that touches bpf(2) during Prepare.
//
// An object another launcher of this build has already loaded whole is adopted from its pins instead of
// loaded again (adoptObject): the programs and maps are the same bytes under the same bpf_hash, and loading
// them again only put this launcher through the verifier, 90–130 ms of Prepare in the KVM guest, for programs
// it then left unused, since the links it adopts run the first launcher's (§9).
//
// A failure after the first byte is pinned returns the half-built value *with* the error, which is the one
// place in this package where both are non-nil. Everything this function creates is pinned as it is created —
// the collection loader pins the LIBBPF_PIN_BY_NAME maps, pinProgram pins each program, attachShared pins
// each link — so a loader that gives up on the second object has already put maps, programs and live
// host-wide attachments into the kernel. Closing the handles does not remove any of them: a pinned link stays
// attached after the fd that made it is gone. Only the caller's undo may decide their fate, because only it
// holds the build lock the last-out question of §5 R14 is asked through, and §7's "abort Prepare, no partial
// pins" and §8 I10's "no leaked pin" are what the answer settles (attachKernel).
//
// The failures *before* that — a cancelled context, no bpf filesystem, a pin directory that cannot be made —
// return a nil value, deliberately: this launcher created nothing.
func newBPFKernel(ctx context.Context, h *Handle) (kernel, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("cgroup: load cancelled: %w", err)
	}
	// trace_proc is loaded as the build this kernel takes (bpf.Load, bpf.KernelReader). Under
	// lockdown=confidentiality a kernel without the rdonly build's functions takes neither, and the probe build's
	// load would fail on the verifier's "cannot use helper": refused here instead, naming the cause, before
	// anything is created.
	if c := ebpfbindings.KernelReader(); ebpfbindings.HasReaders(ebpfbindings.ObjectTraceProc) && !c.Loadable() {
		return nil, fmt.Errorf("%w: %s: lockdown=confidentiality refuses the probe build's bpf_probe_read_kernel "+
			"and %s, which the rdonly build needs", ErrProgramLoad, ebpfbindings.ObjectTraceProc, c.Why)
	}
	if err := checkBPFFS(h.opts.BPFFS); err != nil {
		return nil, err
	}
	if err := h.pins.create(); err != nil {
		return nil, err
	}
	if h.lock != nil {
		reserveBPFDescriptors(h.lock.f)
	}

	k := &bpfKernel{pins: h.pins, phase: h.opts.Phase, maps: map[string]*ebpf.Map{}, progs: map[string]*ebpf.Program{},
		runLinks: h.pins.runLinks(h.run.ID)}
	var sections []*ebpf.MapSpec // the objects' maps not pinned by name, which sharedOwns matches by shape

	for _, obj := range []ebpfbindings.Object{
		ebpfbindings.ObjectCgroupNet, ebpfbindings.ObjectCgroupTrack, ebpfbindings.ObjectTraceProc,
	} {
		objStart := time.Now()
		spec, compact, err := loadKernelSpec(obj, true, h.rules.Control)
		if err != nil {
			return k, fmt.Errorf("%w: %w", ErrProgramLoad, err)
		}
		coll, adopted := k.adoptObject(spec, sharedLinksOf(obj, spec))
		if !adopted {
			// The compact description is only for checking existing kernel
			// objects. Creating objects always uses the complete ELF and BTF.
			if compact {
				spec, _, err = loadKernelSpec(obj, false, h.rules.Control)
				if err != nil {
					return k, fmt.Errorf("%w: %w", ErrProgramLoad, err)
				}
			}
			// cilium/ebpf opens a map that is pinned and creates and pins one that is not; a concurrent first
			// launcher of the build can pin the same name between the two, and this pin then fails with EEXIST.
			// The name is pinned by then, so the next attempt opens it (ebpfbindings.PinAttempts bounds how many
			// it can take). A timed test build attributes the load to the object's maps and to each program
			// (load.obj.<obj>.maps, load.prog.<obj>.<prog>.*; enforce-plane §10.1); a product build's
			// LoadOptions are the zero options and its trace is nil.
			var err error
			trace := ebpfbindings.BeginLoad(h.opts.Phase, "load.obj."+fmt.Sprint(obj)+".maps", "load.prog."+fmt.Sprint(obj))
			for attempt, attempts := 1, ebpfbindings.PinAttempts(spec); ; attempt++ {
				coll, err = ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
					Maps:     ebpf.MapOptions{PinPath: h.pins.Maps},
					Programs: ebpfbindings.LoadOptions(),
				})
				if err == nil || !errors.Is(err, os.ErrExist) || attempt >= attempts {
					break
				}
			}
			trace.End(collectionPrograms(coll))
			if err != nil {
				return k, fmt.Errorf("%w: %s: %w", ErrProgramLoad, obj, verifierTail(err))
			}
		}
		k.colls = append(k.colls, coll)
		for _, ms := range spec.Maps {
			if ms.Pinning != ebpf.PinByName {
				sections = append(sections, ms)
			}
		}
		how := ".new"
		if adopted {
			how = ".adopt"
		}
		startphase.Report(h.opts.Phase, "load.obj."+fmt.Sprint(obj)+how, time.Since(objStart))
		for name, m := range coll.Maps {
			if _, dup := k.maps[name]; !dup {
				k.maps[name] = m
			}
		}
		for name, p := range coll.Programs {
			k.progs[name] = p
			if adopted {
				continue // it is the pinned program
			}
			if err := pinProgram(p, filepath.Join(h.pins.Progs, name)); err != nil {
				return k, err
			}
		}
	}

	endShared := startphase.Begin(h.opts.Phase, "load.shared-links")
	owns := k.sharedOwns(sections)
	for _, name := range append(append([]string{}, ebpfbindings.TrackPrograms...), ebpfbindings.TracePrograms...) {
		if _, optional := ebpfbindings.OptionalTracePrograms[name]; optional && k.progs[name] == nil {
			continue // its function is not in this kernel (dropTraceWhereAbsent)
		}
		if _, optional := ebpfbindings.ExecResultTracepoints[name]; optional && k.progs[name] == nil {
			continue
		}
		if _, listener := ebpfbindings.ListenerTracepoints[name]; listener && k.progs[name] == nil {
			if h.rules.Control != nil && h.rules.Control.Config.Flags&ebpfbindings.NetControlListen != 0 {
				return k, fmt.Errorf("%w: required listener cleanup program %s unavailable", ErrProgramLoad, name)
			}
			continue // no explicit listener policy requested
		}
		l, err := k.attachShared(name, owns)
		if err != nil {
			if errors.Is(err, errExecResultLinkUnavailable) {
				// Optional perf links may be unsupported or denied by this
				// machine's policy. No link means no outcome handoff: the
				// supervisor decides every exec, and the tier is not demoted.
				continue
			}
			return k, err
		}
		k.shared = append(k.shared, sharedLink{Link: l, pin: filepath.Join(k.pins.Links, name)})
		if name == ebpfbindings.ProgBindResult {
			k.bindCleanup = true
		}
		if name == ebpfbindings.ProgListenResult {
			k.listenCleanup = true
		}
		if _, ok := ebpfbindings.ExecResultTracepoints[name]; ok {
			if k.execResultLinks == nil {
				k.execResultLinks = make(map[string]bool)
			}
			k.execResultLinks[name] = true
		}
	}
	endShared()
	// The decision plane in doctor's mode, over the maps just loaded or adopted (plane.go). Its failure fails the
	// run, as a program of the build's own does: doctor's probe passed the mode, so a load that fails here is a
	// fault to report, never a quieter run (enforce-plane I7).
	if h.planeMode != "" {
		var state *hoststate.Dir
		if h.slots != nil {
			state = h.slots.dir
		}
		endPlane := startphase.Begin(h.opts.Phase, "load.plane")
		p, err := newBPFPlane(k, h.hash, PlaneSetup{Mode: h.planeMode, Build: h.opts.Plane.Build,
			PinAnswer: h.opts.Plane.PinAnswer}, state)
		endPlane()
		if p != nil {
			k.planes = append(k.planes, p)
		}
		if err != nil {
			return k, err
		}
		if p.answerErr != nil && h.run.Log != nil {
			h.run.Log.Warn("the plane's probe answer could not be pinned; a later run probes again", "err", p.answerErr)
		}
	}
	return k, nil
}

// collectionPrograms is a load's programs for its attribution (ebpfbindings.LoadTrace), none after a failed load.
func collectionPrograms(coll *ebpf.Collection) map[string]*ebpf.Program {
	if coll == nil {
		return nil
	}
	return coll.Programs
}

// loadKernelSpec selects this run's hooks and checks their context before either
// adopting pinned programs or loading new ones. A layout failure is a hard load
// refusal, never the optional exec attachment fallback.
func loadKernelSpec(obj ebpfbindings.Object, adoption bool, control *NetworkControlMaps) (*ebpf.CollectionSpec, bool, error) {
	var (
		spec    *ebpf.CollectionSpec
		compact bool
		err     error
	)
	if adoption {
		spec, compact, err = ebpfbindings.LoadAdoption(obj)
	} else {
		spec, err = ebpfbindings.Load(obj)
	}
	if err != nil {
		return nil, false, err
	}
	if obj == ebpfbindings.ObjectCgroupNet {
		if err := dropUnixWhereUnsupported(spec, unixConnectSupported); err != nil {
			return nil, false, err
		}
	}
	if obj == ebpfbindings.ObjectTraceProc {
		dropTraceWhereAbsent(spec, kernelHasFunc)
		dropExecResultsWhereAbsent(spec, ebpfbindings.ExecResultTracepointAvailable)
	}
	selectNetworkControlPrograms(spec, control)
	for _, name := range ebpfbindings.TracePrograms {
		if spec.Programs[name] != nil {
			if err := validateSyscallResultContext(name); err != nil {
				return nil, false, err
			}
		}
	}
	return spec, compact, nil
}

var validateSyscallResultContext = ebpfbindings.ValidateSyscallResultContext

// sharedLinksOf names the host-wide links an object's programs run through, which attachShared pins: those of
// its programs the spec still holds, since dropTraceWhereAbsent leaves a program out where its function is not in
// the kernel and nothing attaches it there.
func sharedLinksOf(obj ebpfbindings.Object, spec *ebpf.CollectionSpec) []string {
	var names []string
	switch obj {
	case ebpfbindings.ObjectCgroupTrack:
		names = ebpfbindings.TrackPrograms
	case ebpfbindings.ObjectTraceProc:
		names = ebpfbindings.TracePrograms
	default:
		return nil
	}
	out := make([]string, 0, len(names))
	for _, name := range names {
		if _, optional := ebpfbindings.ExecResultTracepoints[name]; optional {
			// Perf-event links allow multiple attachments of one program. A
			// missing optional link therefore does not prevent safe adoption:
			// attachShared establishes or rejects it before the run is armed.
			// Requiring its pin here would reload the entire trace object on
			// kernels whose perf-event ioctl links cannot be pinned.
			continue
		}
		if _, ok := spec.Programs[name]; ok {
			out = append(out, name)
		}
	}
	return out
}

// kernelHasFunc reports whether the running kernel's BTF has a function of this name. A kernel whose BTF cannot be
// read answers yes, so the load fails naming the function rather than quietly recording less. It is a variable so
// this package's tests can give both answers without a kernel; production never replaces it. It is the answer doctor
// seeded from its run-probe cache when it holds one (ebpfbindings.SeedKernelFuncs), so an adopting run parses no BTF.
var kernelHasFunc = ebpfbindings.KernelHasFunc

// dropTraceWhereAbsent removes from trace_proc's spec each of ebpfbindings.OptionalTracePrograms whose kernel
// function this kernel does not have: security_file_truncate below 6.2 (ADR 0016 (3)). The loader resolves an
// fexit program's target when the program is loaded, so the object would not load whole there; without the
// program, the calls it would record go through security_path_truncate, which that kernel calls instead.
func dropTraceWhereAbsent(spec *ebpf.CollectionSpec, has func(string) bool) {
	for name, fn := range ebpfbindings.OptionalTracePrograms {
		if _, ok := spec.Programs[name]; ok && !has(fn) {
			delete(spec.Programs, name)
		}
	}
}

func dropExecResultsWhereAbsent(spec *ebpf.CollectionSpec, has func(string) bool) {
	for name, event := range ebpfbindings.ExecResultTracepoints {
		if !has(event) {
			delete(spec.Programs, name)
		}
	}
}

func (k *bpfKernel) execOutcomes() bool {
	return k.execResultLinks[ebpfbindings.ProgExecResult] && k.execResultLinks[ebpfbindings.ProgExecatResult]
}

// adoptObject opens an object's programs and maps from this build's pins, and reports false, having opened
// nothing it keeps, unless a launcher of the build has left the whole object there: every map the spec
// declares by name, pinned and compatible with the spec, every program the spec still holds after
// dropUnixWhereUnsupported, of the spec's type and reading no map but those and its own global-variable
// sections, and every host-wide link its programs run through. Anything less is a first launcher, one that is
// still loading, or one that died part way (§6 E32), and the object is loaded as a first launcher loads it.
//
// The global-variable sections (.bss and the like) are not pinned: each load makes its own, and a pinned
// program keeps the one it was loaded with. Nothing here reads or writes them (the objects' globals only anchor
// the BTF types bpf2go generates), so a program's own is matched by shape (ownSection) and not kept open.
//
// The links are required because the trampoline refuses a second attachment of one program (EBUSY): a
// launcher that adopted the programs of another still attaching them would fail where loading its own
// succeeds. The build lock keeps the pins from going while this runs: every launcher holds it shared through
// Prepare, and only a last one out, holding it exclusively, unpins (§5 R14).
func (k *bpfKernel) adoptObject(spec *ebpf.CollectionSpec, links []string) (*ebpf.Collection, bool) {
	return adoptObjectIn(k.pins, spec, links, nil)
}

// adoptObjectIn is adoptObject over any pin directory: a build's own, or a plane mode's (<hash>-<mode>). A map the
// spec pins by name and external holds is not looked for in pins: it is the one the caller hands the object's
// loader too (MapReplacements), a tier-2 map the plane shares, and the pinned programs must read that very map.
// The collection it returns owns what it opened from pins, never an external map.
func adoptObjectIn(pins pinLayout, spec *ebpf.CollectionSpec, links []string, external map[string]*ebpf.Map) (*ebpf.Collection, bool) {
	return adoptObjectInWithPrograms(pins, spec, links, external, nil)
}

// adoptObjectInWithPrograms records the IDs of programs whose map ownership it
// verified, together with the collection descriptors that keep those IDs alive.
// The records belong only to a successful adoption of this collection.
func adoptObjectInWithPrograms(pins pinLayout, spec *ebpf.CollectionSpec, links []string, external map[string]*ebpf.Map,
	verified map[ebpf.ProgramID]*ebpf.Program) (*ebpf.Collection, bool) {
	clear(verified)
	coll := &ebpf.Collection{Programs: map[string]*ebpf.Program{}, Maps: map[string]*ebpf.Map{}}
	fail := func(why string) (*ebpf.Collection, bool) {
		clear(verified)
		coll.Close()
		startphase.Report(nil, "adopt-miss."+why, 0) // timing builds only: why a pinned object was not adopted
		return nil, false
	}
	for _, name := range links {
		if _, err := os.Stat(filepath.Join(pins.Links, name)); err != nil {
			return fail("link")
		}
	}
	ids := map[ebpf.MapID]bool{}
	var sections []*ebpf.MapSpec
	for name, ms := range spec.Maps {
		if ms.Pinning != ebpf.PinByName {
			// Task storage the programs keep for themselves (the plane's tego_plane_path_buf: created for a sample
			// and deleted after it, never read by userspace) needs no handle here, so it is matched by shape like a
			// global-variable section, as is every map bpf.KernelOnlyMaps names. Refused, it made every run load and
			// verify the plane's six programs again, about 100 ms a run (TIER3-PLAN T11, kill test 4's go kind).
			if !strings.HasPrefix(name, ".") && ms.Type != ebpf.TaskStorage && !ebpfbindings.KernelOnlyMaps[name] {
				return fail("own-map") // a map of the object's own that this launcher would need a handle to
			}
			sections = append(sections, ms)
			continue
		}
		m := external[name]
		if m == nil {
			var err error
			if m, err = ebpf.LoadPinnedMap(filepath.Join(pins.Maps, name), nil); err != nil {
				return fail("pinned-map")
			}
			coll.Maps[name] = m
		}
		if ms.Compatible(m) != nil {
			return fail("incompatible-map")
		}
		info, err := m.Info()
		if err != nil {
			return fail("map-info")
		}
		id, ok := info.ID()
		if !ok {
			return fail("map-id")
		}
		ids[id] = true
	}
	for name, ps := range spec.Programs {
		p, err := ebpf.LoadPinnedProgram(filepath.Join(pins.Progs, name), nil)
		if err != nil {
			return fail("pinned-prog")
		}
		coll.Programs[name] = p
		if p.Type() != ps.Type {
			return fail("prog-type")
		}
		if why := readsOnlyWithPrograms(p, ids, sections, verified); why != "" {
			return fail(why)
		}
	}
	return coll, true
}

// readsOnly is "" when program p reads no map but those whose ids are in ids and ones shaped like one of the
// object's global-variable sections, else why not: a program loaded over other maps (a pinned one left from maps
// since re-created) decides over maps nothing fills, and must be neither adopted nor run.
func readsOnly(p *ebpf.Program, ids map[ebpf.MapID]bool, sections []*ebpf.MapSpec) string {
	return readsOnlyWithPrograms(p, ids, sections, nil)
}

// readsOnlyWithPrograms records a program only after every map it references
// passed the same ownership checks readsOnly uses.
func readsOnlyWithPrograms(p *ebpf.Program, ids map[ebpf.MapID]bool, sections []*ebpf.MapSpec,
	verified map[ebpf.ProgramID]*ebpf.Program) string {
	info, err := p.Info()
	if err != nil {
		return "prog-info"
	}
	used, ok := info.MapIDs()
	if !ok {
		return "prog-maps"
	}
	for _, id := range used {
		if !ids[id] && !ownSection(id, sections) {
			return "prog-foreign-map"
		}
	}
	if verified != nil {
		if id, ok := info.ID(); ok && id != 0 {
			verified[id] = p
		}
	}
	return ""
}

// ownSection reports whether the map with this id is shaped like one of the object's global-variable sections:
// the one a pinned program of the object was loaded with, since every map it reads that is not pinned by name
// must be one of those (adoptObject).
func ownSection(id ebpf.MapID, sections []*ebpf.MapSpec) bool {
	m, err := ebpf.NewMapFromID(id)
	if err != nil {
		return false
	}
	defer func() { _ = m.Close() }()
	for _, ms := range sections {
		if m.Type() == ms.Type && m.KeySize() == ms.KeySize && m.ValueSize() == ms.ValueSize &&
			m.MaxEntries() == ms.MaxEntries {
			return true
		}
	}
	return false
}

// unixConnectSupported reports whether this kernel accepts BPF_CGROUP_UNIX_CONNECT (Linux 6.7) as a program's
// expected attach type, by loading the smallest program that has it. It is a variable so this package's tests
// can give both answers without a kernel; production never replaces it.
var unixConnectSupported = func() (bool, error) {
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.CGroupSockAddr,
		AttachType:   ebpf.AttachCgroupUnixConnect,
		License:      "Dual BSD/GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()},
	})
	if err != nil {
		if errors.Is(err, unix.EINVAL) || errors.Is(err, ebpf.ErrNotSupported) {
			return false, nil
		}
		return false, err
	}
	_ = p.Close()
	return true, nil
}

// UnixConnectSupported is unixConnectSupported for the doctor's D7, so its answer for the two unix hooks is
// the one the backend acts on and not a kernel version's guess (a distribution backports).
func UnixConnectSupported() (bool, error) { return unixConnectSupported() }

// dropUnixWhereUnsupported removes connect_unix and sendmsg_unix from cgroup_net's spec on a kernel that
// predates their attach types (§5 R7, §6 E1). The kernel checks a program's expected attach type when the
// program is *loaded*, not when it is attached — bpf_prog_load_check_attach answers EINVAL to
// BPF_CGROUP_UNIX_CONNECT below 6.7 — so loading the object whole failed there, and with it the other six
// programs and all of tier 2, on every kernel from the 6.1 floor to 6.6. One probe answers for both: the unix
// sockaddr attach types arrived together, in one series (6.7, "bpf: Implement cgroup sockaddr hooks for unix
// sockets"). Without the two programs, unix connects and datagrams are decided by the inherited tier-1 path
// alone, which decides them beside the programs on every kernel.
func dropUnixWhereUnsupported(spec *ebpf.CollectionSpec, supported func() (bool, error)) error {
	present := false
	for _, name := range ebpfbindings.UnixPrograms {
		if _, ok := spec.Programs[name]; ok {
			present = true
		}
	}
	if !present {
		return nil
	}
	ok, err := supported()
	if err != nil {
		return fmt.Errorf("%w: probe BPF_CGROUP_UNIX_CONNECT: %w", ErrProgramLoad, err)
	}
	if !ok {
		for _, name := range ebpfbindings.UnixPrograms {
			delete(spec.Programs, name)
		}
	}
	return nil
}

// pinProgram pins a program, treating an existing pin as the concurrent-launcher case it is.
func pinProgram(p *ebpf.Program, path string) error {
	if err := p.Pin(path); err != nil && !errors.Is(err, os.ErrExist) && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("%w: pin program at %s: %w", ErrProgramLoad, path, err)
	}
	return nil
}

// attachShared attaches one host-wide tracing program, or adopts the pinned link another launcher of this
// build already made. Tracepoints and fentry are global hooks, not per-cgroup: one attachment per build
// serves every run, and the in-kernel run-set lookup does all the filtering (§5 R2, §4). How the program is
// attached, as a tracing program or as a syscall tracepoint, is ebpfbindings.AttachTrace's, which the
// integration fixtures that load trace_proc use too, so no second copy of the choice can go stale (§5 R14).
//
// A pinned link is adopted only when its program reads this launcher's maps (owns), as a plane link is
// (attachPlaneLink, enforce-plane R20). A link pinned over maps since re-created (a removal killed or failing
// between the map pins and the link pins) runs a program over a run set that names no run: adopted, it recorded
// nothing for the run, and its exec-result and listener links still set ExecOutcomes, BindOutcomes and
// ListenOutcomes, so the supervisor handed failed execs to a kernel that never reported them. It is unpinned and
// this launcher's own program attached instead; a stale pin that cannot be removed fails the load.
func (k *bpfKernel) attachShared(name string, owns func(*ebpf.Program) string) (link.Link, error) {
	pinPath := filepath.Join(k.pins.Links, name)
	if l, err := link.LoadPinnedLink(pinPath, nil); err == nil {
		why := k.sharedLinkOwned(l, name, owns)
		if why == "" {
			return l, nil
		}
		_ = l.Close()
		if err := os.Remove(pinPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: unpin shared link %s over foreign maps (%s): %w", ErrProgramLoad, pinPath, why, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: adopt pinned link %s: %w", ErrProgramLoad, pinPath, err)
	}

	prog, ok := k.progs[name]
	if !ok {
		return nil, fmt.Errorf("%w: program %s is not in the loaded objects", ErrProgramLoad, name)
	}
	l, err := ebpfbindings.AttachTrace(name, prog)
	if err != nil {
		return nil, sharedAttachFailure(name, err)
	}
	if err := l.Pin(pinPath); err != nil {
		// Another launcher pinned it first; adopt theirs and drop ours so the build keeps one attachment.
		_ = l.Close()
		adopted, loadErr := link.LoadPinnedLink(pinPath, nil)
		if loadErr != nil {
			if _, optional := ebpfbindings.ExecResultTracepoints[name]; optional && errors.Is(err, link.ErrNotSupported) {
				return nil, fmt.Errorf("%w: pin optional link %s: %w", errExecResultLinkUnavailable, name, err)
			}
			return nil, fmt.Errorf("%w: pin link %s: %w", ErrProgramLoad, pinPath, err)
		}
		if why := k.sharedLinkOwned(adopted, name, owns); why != "" {
			_ = adopted.Close()
			return nil, fmt.Errorf("%w: the shared link another launcher pinned at %s reads foreign maps (%s)",
				ErrProgramLoad, pinPath, why)
		}
		return adopted, nil
	}
	return l, nil
}

// sharedLinkOwned is "" when the shared link l runs this launcher's own program for name, or a program that reads
// only this launcher's maps (owns): a concurrent first launcher of the build may have pinned a link of its own
// copy of the program, loaded over the same pinned maps, which is as sound. Else it says why not (linkOwned).
func (k *bpfKernel) sharedLinkOwned(l link.Link, name string, owns func(*ebpf.Program) string) string {
	var verified map[ebpf.ProgramID]*ebpf.Program
	if p := k.progs[name]; p != nil {
		if info, err := p.Info(); err == nil {
			if id, ok := info.ID(); ok && id != 0 {
				verified = map[ebpf.ProgramID]*ebpf.Program{id: p}
			}
		}
	}
	return linkOwned(l, owns, verified)
}

// sharedOwns is readsOnly over the maps this launcher loaded or adopted (every collection's, the build's pinned
// maps among them) and, by shape, the objects' maps not pinned by name: the ownership a pinned shared link's
// program must have to be adopted (attachShared). The map ids are read on the first link that needs them, which
// is none when every pinned link runs this launcher's own programs.
func (k *bpfKernel) sharedOwns(sections []*ebpf.MapSpec) func(*ebpf.Program) string {
	var ids map[ebpf.MapID]bool
	return func(p *ebpf.Program) string {
		if ids == nil {
			ids = map[ebpf.MapID]bool{}
			for _, c := range k.colls {
				for _, m := range c.Maps {
					// A map whose id cannot be read is left out, so a program reading it is refused: fail closed.
					if info, err := m.Info(); err == nil {
						if id, ok := info.ID(); ok {
							ids[id] = true
						}
					}
				}
			}
		}
		return readsOnly(p, ids, sections)
	}
}

var errExecResultLinkUnavailable = errors.New("cgroup: optional exec outcome link unavailable")

// sharedAttachFailure classifies only the actual tracing attachment call.
// Permission failures while adopting or pinning links remain real failures.
func sharedAttachFailure(name string, err error) error {
	if ebpfbindings.ExecResultAttachUnavailable(name, err) {
		return fmt.Errorf("%w: attach %s: %w", errExecResultLinkUnavailable, name, err)
	}
	return fmt.Errorf("%w: attach %s: %w", ErrProgramLoad, name, err)
}

// ownerPrograms are the programs that read tego_net_owners. Attaching the first of them is what makes the
// kernel create the cgroup's storage value, zeroed, and only then can userspace write it.
var ownerPrograms = map[string]bool{
	ebpfbindings.ProgConnect4: true, ebpfbindings.ProgConnect6: true,
	ebpfbindings.ProgSendmsg4: true, ebpfbindings.ProgSendmsg6: true,
	ebpfbindings.ProgConnectUnix: true, ebpfbindings.ProgSendmsgUnix: true,
}

// isUnixProgram reports whether name is one of the two 6.7+ programs the load leaves out on an older kernel.
func isUnixProgram(name string) bool {
	return name == ebpfbindings.ProgConnectUnix || name == ebpfbindings.ProgSendmsgUnix
}

// attachCgroup attaches the loaded CGROUP_SOCK_ADDR programs to the run's cgroup: all eight, or six on a kernel
// below 6.7, where connect_unix and sendmsg_unix were left out of the load (dropUnixWhereUnsupported), and then
// cgroup/sock_create and cgroup/setsockopt (attachSocketPrograms), so ten, or eight below 6.7. Link-based cgroup
// attachment is inherently multi — any number of links may target one cgroup and attach type, and the kernel
// ANDs their return codes — so this never displaces another build's links and never needs an attach flag
// (§5 R1).
//
// The run the deciding programs enforce is written into the cgroup's tego_net_owners storage right after the
// first of them is attached: the kernel creates that value, zeroed, at the attach, and a program that finds it
// zeroed refuses every connect, so the order is fail-closed whatever runs in between. Nothing does at this
// point in a real run — Attach precedes the agent's creation (docs/p0/runtime-launch.md §4.1). The update
// asks for an existing value (BPF_EXIST), so a storage the kernel did not create for this attachment is an
// error, never a new row.
func (k *bpfKernel) attachCgroup(path string, owner ebpfbindings.NetOwner) error {
	if len(k.cgroupLinks) > 0 {
		return nil // already attached; Attach is called once per run
	}
	owners := k.maps[ebpfbindings.MapNetOwners]
	if owners == nil {
		return fmt.Errorf("%w: %s is missing from the loaded objects", ErrProgramLoad, ebpfbindings.MapNetOwners)
	}
	configured := false
	attach := map[string]ebpf.AttachType{
		ebpfbindings.ProgConnect4:    ebpf.AttachCGroupInet4Connect,
		ebpfbindings.ProgConnect6:    ebpf.AttachCGroupInet6Connect,
		ebpfbindings.ProgSendmsg4:    ebpf.AttachCGroupUDP4Sendmsg,
		ebpfbindings.ProgSendmsg6:    ebpf.AttachCGroupUDP6Sendmsg,
		ebpfbindings.ProgBind4:       ebpf.AttachCGroupInet4Bind,
		ebpfbindings.ProgBind6:       ebpf.AttachCGroupInet6Bind,
		ebpfbindings.ProgConnectUnix: ebpf.AttachCgroupUnixConnect,
		ebpfbindings.ProgSendmsgUnix: ebpf.AttachCgroupUnixSendmsg,
	}
	for _, name := range ebpfbindings.CgroupPrograms {
		if owner.Flags&netOwnerUnixOnly != 0 && !isUnixProgram(name) {
			continue
		}
		prog, ok := k.progs[name]
		if !ok {
			if isUnixProgram(name) {
				// Not loaded because this kernel predates its attach type (dropUnixWhereUnsupported).
				continue
			}
			return fmt.Errorf("%w: program %s is not loaded", ErrProgramLoad, name)
		}
		l, err := link.AttachCgroup(link.CgroupOptions{Path: path, Attach: attach[name], Program: prog})
		if err != nil {
			if isUnixProgram(name) && isUnsupported(err) {
				// A kernel that loaded the program but cannot attach it; unix sockets stay with the
				// inherited tier-1 path, which decides them on every kernel anyway (§5 R7, §6 E1).
				continue
			}
			return attachError(name, path, err)
		}
		k.cgroupLinks = append(k.cgroupLinks, l)
		if err := pinRunLink(k.runLinks, l, name); err != nil {
			return err
		}
		if k.netAttached == nil {
			k.netAttached = make(map[string]bool)
		}
		k.netAttached[name] = true
		if ownerPrograms[name] && !configured {
			if err := owners.Update(&owner.CgroupID, &owner, ebpf.UpdateExist); err != nil {
				return fmt.Errorf("%w: configure %s for cgroup %d at %s: %w", ErrProgramLoad,
					ebpfbindings.MapNetOwners, owner.CgroupID, path, err)
			}
			configured = true
		}
	}
	if owner.Flags&netOwnerUnixOnly != 0 {
		return nil
	} // below 6.7 the plane decides unix, otherwise the inherited relay
	if !configured {
		return fmt.Errorf("%w: no program that reads %s was attached to %s", ErrProgramLoad,
			ebpfbindings.MapNetOwners, path)
	}
	if err := k.attachSocketPrograms(path); err != nil {
		return err
	}
	return k.attachNetworkControl(path, owner)
}

// socketAttach is the attach type of each of ObjectCgroupNet's SocketPrograms.
var socketAttach = map[string]ebpf.AttachType{
	ebpfbindings.ProgSockCreate: ebpf.AttachCGroupInetSockCreate,
	ebpfbindings.ProgSetsockopt: ebpf.AttachCGroupSetsockopt,
}

// attachSocketPrograms attaches cgroup/sock_create (§5 R4; ADR 0018 PR 2) and cgroup/setsockopt (ADR 0018 (7)) to
// the run's cgroup, beside the CGROUP_SOCK_ADDR programs, wherever they go: every tier-2 mode and tier 3, the fanotify
// fallback and a plane mode alike (A-0018-1, amending ADR 0018 (5)'s "in the fanotify fallback"). With a plane mode
// the plane's socket_create refuses first, since security_socket_create runs in __sock_create before inet_create, and
// cgroup/sock_create only ANDs the same inet verdict, read from the same NetSocketPolicy; it still holds when a plane
// slot does not. cgroup/setsockopt refuses SOL_TCP's TCP_ULP on any path, io_uring's SOCKET_URING_OP_SETSOCKOPT
// included, which no seccomp filter and no plane hook sees; setsockopt(2)'s is the supervisor's first, through the
// filter's arm. Both are required, never optional: BPF_CGROUP_INET_SOCK_CREATE is 4.10, BPF_CGROUP_SETSOCKOPT 5.3 and
// their bpf_link attach 5.7, all below the floor, so an attach that fails fails the run, an EPERM named as the
// hierarchy conflict it is (attachError; another manager's non-multi program of that attach type above the run blocks
// it alone). Their links are pinned with the run's others (ADR 0020 (1)), so a launcher killed outright leaves them
// deciding.
//
// They read the same tego_net_owners storage as the deciding programs: the cgroup storage's key is the cgroup id
// alone, which the kernel shares between attach types (5.9+), so the value attachCgroup configured after the first
// of them is the one they read. Were either ever given a storage of its own, zeroed, it would refuse every socket or
// option (its unconfigured branch), never admit one.
func (k *bpfKernel) attachSocketPrograms(path string) error {
	for _, name := range ebpfbindings.SocketPrograms {
		prog, ok := k.progs[name]
		if !ok {
			return fmt.Errorf("%w: program %s is not loaded", ErrProgramLoad, name)
		}
		l, err := link.AttachCgroup(link.CgroupOptions{Path: path, Attach: socketAttach[name], Program: prog})
		if err != nil {
			return attachError(name, path, err)
		}
		k.cgroupLinks = append(k.cgroupLinks, l)
		if err := pinRunLink(k.runLinks, l, name); err != nil {
			return err
		}
		if k.netAttached == nil {
			k.netAttached = make(map[string]bool)
		}
		k.netAttached[name] = true
	}
	return nil
}

// attachError names the one cgroup-attach failure an operator cannot diagnose from the errno alone.
//
// kernel/bpf/cgroup.c's __cgroup_bpf_attach refuses with -EPERM when hierarchy_allows_attach() finds an
// ancestor cgroup already holding a program for this attach type that was attached the legacy way with no
// flags — BPF_PROG_ATTACH with neither BPF_F_ALLOW_MULTI nor BPF_F_ALLOW_OVERRIDE, which is bpftool's own
// default — and again when the target cgroup's existing programs carry different flags. A bpf_link is
// internally ALLOW_MULTI, so both checks apply to it: one `bpftool cgroup attach /sys/fs/cgroup connect4 ...`
// blocks every Tego run on that host until it is detached. §5 R1 reasons correctly that Tego's links can
// never displace another manager's; this is the other direction, which R1 does not cover, and systemd
// documents the same coexistence contract from the other side (systemd.io/CGROUP_DELEGATION installs its IP
// filters with BPF_F_ALLOW_MULTI precisely so others can still attach).
//
// EPERM is not proof of a conflict — it is also what a launcher without cap_bpf/cap_net_admin gets — so the
// message names both, conflict first: by this point Prepare has already loaded programs and created tracing
// links, which need privilege of their own, so a capability failure here is the less likely of the two
// (§6 E36).
func attachError(name, path string, err error) error {
	if !errors.Is(err, unix.EPERM) {
		return fmt.Errorf("%w: attach %s to %s: %w", ErrProgramLoad, name, path, err)
	}
	return fmt.Errorf("%w: attach %s to %s: %w; %s", ErrCgroupAttachConflict, name, path, err, AttachConflictHint(path))
}

// AttachConflictHint is the diagnosis of an EPERM from a cgroup attach at path (§6 E36, attachError): a cgroup at
// or above it holds a program for the attach type attached the legacy way without BPF_F_ALLOW_MULTI, or the
// attaching process lacks the capabilities. A run's Attach refusal and doctor's D7 rows (internal/doctor
// cgroupAttachFailure) give these words, so the two cannot describe one host two ways.
func AttachConflictHint(path string) string {
	return fmt.Sprintf("either %s or a cgroup above it already holds a non-overridable program for this attach "+
		"type (`bpftool cgroup tree` names the holder; it has to be detached, or re-attached with "+
		"BPF_F_ALLOW_MULTI), or the attaching process lacks cap_bpf/cap_net_admin", path)
}

// isUnsupported reports whether an attach failed because this kernel lacks the attach type.
func isUnsupported(err error) bool {
	return errors.Is(err, link.ErrNotSupported) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP)
}

// detachCgroup unpins and closes this run's cgroup links. It runs before any of the run's rows is removed, so
// once it returns no hook can write a new breadcrumb and the rows are stable while they are deleted (§5 R15).
// With the pins gone the descriptors hold the last references, and the close is what detaches.
func (k *bpfKernel) detachCgroup() error {
	errs := []error{removeRunLinks(k.runLinks, nil)}
	for _, l := range k.cgroupLinks {
		if err := l.Close(); err != nil {
			errs = append(errs, fmt.Errorf("cgroup: close cgroup link: %w", err))
		}
	}
	k.cgroupLinks = nil
	k.netAttached = nil
	return errors.Join(errs...)
}

// populate writes the run's verdict rows. A map at capacity is ErrMapFull rather than a bare errno, because
// the fix is a smaller contract or a larger map, not a retry (§7).
func (k *bpfKernel) populate(rules RuleMaps) error {
	exact, cidr, names := k.maps[ebpfbindings.MapNetExact], k.maps[ebpfbindings.MapNetCIDR], k.maps[ebpfbindings.MapUnixNames]
	if exact == nil || cidr == nil || names == nil {
		return fmt.Errorf("%w: verdict maps are missing from the loaded objects", ErrProgramLoad)
	}
	if err := k.populateTimelines(rules.Timelines); err != nil {
		return err
	}
	for _, row := range rules.Exact {
		if err := exact.Update(&row.Key, &row.Val, ebpf.UpdateAny); err != nil {
			return mapFull("tego_net_exact", err)
		}
	}
	for _, row := range rules.CIDR {
		if err := cidr.Update(&row.Key, &row.Val, ebpf.UpdateAny); err != nil {
			return mapFull("tego_net_cidr", err)
		}
	}
	for _, row := range rules.Unix {
		if err := names.Update(&row.Key, &row.Val, ebpf.UpdateAny); err != nil {
			return mapFull(ebpfbindings.MapUnixNames, err)
		}
	}
	return k.populateNetworkControl(rules.Control)
}

// purgeSlot deletes every exact, CIDR and unix name row keyed by runIdx and zeroes the slot's counters (ADR 0026
// (4)): a dead launcher's drops would otherwise be counted as this run's. Its rings are placeRings' to reuse,
// drained, or replace (ADR 0026 (6) as amended). All three maps are LIBBPF_PIN_BY_NAME
// (bpf/include/maps.h), so they outlive the launcher that wrote them: one killed with SIGKILL never reaches
// removeRules, and the slot table then hands its run_idx to the next run (slots.go's dead-owner reclaim).
// Without this the new run would inherit the dead one's allow rows — tego_net_match hits on
// (run_idx, family, proto, port, addr) alone and returns TEGO_SOCK_OK — which is exactly the reuse §5 R12
// and §8 I5 forbid, and it fails *open* (§6 E32).
//
// The run set is deliberately left alone. Its rows are keyed by cgroup id, which the kernel does not reuse,
// so no new run can collide with one; deleting a dead run's row would only take the last policy off tasks
// that outlived their launcher, which is E26's fail-open and the worse of the two outcomes.
func (k *bpfKernel) purgeSlot(runIdx uint32) error {
	exact, cidr, names := k.maps[ebpfbindings.MapNetExact], k.maps[ebpfbindings.MapNetCIDR], k.maps[ebpfbindings.MapUnixNames]
	if exact == nil || cidr == nil || names == nil {
		return fmt.Errorf("%w: verdict maps are missing from the loaded objects", ErrProgramLoad)
	}
	errs := []error{
		purgeRowsOfSlot(exact, ebpfbindings.MapNetExact, runIdx,
			func(key *ebpfbindings.NetKey) uint32 { return key.RunIdx }),
		purgeRowsOfSlot(cidr, ebpfbindings.MapNetCIDR, runIdx,
			func(key *ebpfbindings.NetLPMKey) uint32 { return key.RunIdx }),
		purgeRowsOfSlot(names, ebpfbindings.MapUnixNames, runIdx,
			func(key *ebpfbindings.UnixKey) uint32 { return key.RunIdx }),
	}
	if m := k.maps[ebpfbindings.MapNetTimeline]; m != nil {
		errs = append(errs, purgeRowsOfSlot(m, ebpfbindings.MapNetTimeline, runIdx, func(key *ebpfbindings.NetTimelineKey) uint32 { return key.RunIdx }))
	}
	for _, name := range ebpfbindings.SlotCounters {
		if m := k.maps[name]; m != nil {
			errs = append(errs, ebpfbindings.ZeroSlot(m, runIdx))
		}
	}
	// A reaper's: the plane's rows of the slot, of every gen (T4's clear, in the kernel). A dead launcher's rows are
	// absent to the slot's next run by their gen already, and go here rather than holding the slot's maps against
	// its next run's cap. A run's own Prepare clears its slot through its Handle (preparePlaneSlot).
	for _, p := range k.pinnedPlanes {
		errs = append(errs, p.clearSlot(runIdx))
	}
	errs = append(errs, k.purgeNetworkControl(runIdx))
	return errors.Join(errs...)
}

// placeRing creates one ring and inserts it at slot when its memlock fits room (kernel.placeRing).
func (k *bpfKernel) placeRing(kind string, slot, size uint32, room uint64) (uint64, bool, error) {
	outer := k.maps[ebpfbindings.OuterOf(kind)]
	if outer == nil {
		return 0, false, fmt.Errorf("%w: %s is missing from the loaded objects", ErrProgramLoad, ebpfbindings.OuterOf(kind))
	}
	ring, err := ebpfbindings.NewRing(kind, size)
	if err != nil {
		return 0, false, err
	}
	// The outer holds its own reference once the ring is in it; this descriptor goes either way.
	defer func() { _ = ring.Close() }()
	memlock, err := ebpfbindings.Memlock(ring)
	if err != nil {
		return 0, false, err
	}
	if memlock > room {
		return memlock, false, nil
	}
	if err := ebpfbindings.InsertRing(outer, slot, ring); err != nil {
		return memlock, false, err
	}
	return memlock, true, nil
}

// slotRings reads the size of the ring each of this build's outers holds at slot (kernel.slotRings).
func (k *bpfKernel) slotRings(slot uint32) (map[string]uint32, error) {
	out := map[string]uint32{}
	for _, kind := range ringKinds {
		outer := k.maps[ebpfbindings.OuterOf(kind)]
		if outer == nil {
			continue
		}
		ring, ok, err := ebpfbindings.RingOf(outer, slot)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		out[kind] = ring.MaxEntries()
		_ = ring.Close()
	}
	return out, nil
}

// removeRing deletes the slot's ring of kind (kernel.removeRing).
func (k *bpfKernel) removeRing(kind string, slot uint32) error {
	outer := k.maps[ebpfbindings.OuterOf(kind)]
	if outer == nil {
		return nil
	}
	return ebpfbindings.DeleteRing(outer, slot)
}

// drainRing consumes what the slot's ring of kind holds (kernel.drainRing).
func (k *bpfKernel) drainRing(kind string, slot uint32) error {
	outer := k.maps[ebpfbindings.OuterOf(kind)]
	if outer == nil {
		return nil
	}
	ring, ok, err := ebpfbindings.RingOf(outer, slot)
	if err != nil || !ok {
		return err
	}
	defer func() { _ = ring.Close() }()
	_, err = ebpfbindings.DrainRing(ring)
	return err
}

// reclaimRings is reclaimRings over every build's pins under base.
func (k *bpfKernel) reclaimRings(base string, noOne func(string, uint32) (bool, error)) (uint64, int, error) {
	return reclaimRings(base, "", noOne)
}

// ringUse is ringUse over every build's pins under base.
func (k *bpfKernel) ringUse(base string) (uint64, int, error) { return ringUse(base) }

// purgeRowsOfSlot deletes every row of one verdict map whose key names runIdx. It is generic over the two key
// layouts because the walk, the collect-then-delete rule and the error wording are the same for both.
//
// Keys are collected before anything is deleted: deleting during a get_next_key walk is what makes such a
// walk skip entries. Nothing else can be writing rows under this run_idx while it runs — the slot table's
// flock makes the index this process's alone until it exits. Other runs' rows come and go during the walk
// (their Detach, a cgroup_rmdir), which mapKeys steps through.
func purgeRowsOfSlot[K comparable](m *ebpf.Map, name string, runIdx uint32, slotOf func(*K) uint32) error {
	return purgeRowsOfSlotIn(m, m, name, runIdx, slotOf)
}

// keyDeleter is the part of *ebpf.Map purgeRowsOfSlot deletes through.
type keyDeleter interface{ Delete(key any) error }

// purgeRowsOfSlotIn is purgeRowsOfSlot over any map; a test gives one whose walk restarts.
func purgeRowsOfSlotIn[K comparable](w keyWalker, d keyDeleter, name string, runIdx uint32, slotOf func(*K) uint32) error {
	keys, err := mapKeys[K](w)
	if err != nil {
		return fmt.Errorf("cgroup: scan %s for slot %d: %w", name, runIdx, err)
	}
	var errs []error
	for i := range keys {
		if slotOf(&keys[i]) != runIdx {
			continue
		}
		if err := d.Delete(&keys[i]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("cgroup: delete stale %s row of slot %d: %w", name, runIdx, err))
		}
	}
	return errors.Join(errs...)
}

// removeRules deletes the run's verdict rows. A row that is already gone is not an error: teardown must be
// able to run twice (§8 I10).
func (k *bpfKernel) removeRules(rules RuleMaps) error {
	var errs []error
	if m := k.maps[ebpfbindings.MapNetTimeline]; m != nil {
		for _, row := range rules.Timelines {
			if err := m.Delete(&row.Key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = append(errs, err)
			}
		}
	}
	if exact := k.maps[ebpfbindings.MapNetExact]; exact != nil {
		for _, row := range rules.Exact {
			if err := exact.Delete(&row.Key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = append(errs, fmt.Errorf("cgroup: delete exact row: %w", err))
			}
		}
	}
	if cidr := k.maps[ebpfbindings.MapNetCIDR]; cidr != nil {
		for _, row := range rules.CIDR {
			if err := cidr.Delete(&row.Key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = append(errs, fmt.Errorf("cgroup: delete cidr row: %w", err))
			}
		}
	}
	if names := k.maps[ebpfbindings.MapUnixNames]; names != nil {
		for _, row := range rules.Unix {
			if err := names.Delete(&row.Key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				errs = append(errs, fmt.Errorf("cgroup: delete unix name row: %w", err))
			}
		}
	}
	if rules.Control != nil {
		errs = append(errs, k.purgeNetworkControl(rules.Control.RunIdx))
	}
	return errors.Join(errs...)
}

// insertRun adds a cgroup to the run set under BPF_NOEXIST, and on EEXIST re-reads the row, as ADR 0010's
// re-read says. cgroup_track may have materialized the same descendant a moment earlier, and a row with the value
// this would write is this run's. Any other row is another run's: a run cgroup made under another run's subtree
// gets the outer run's row from cgroup_track before its own Attach, and taking EEXIST as success left the inner
// run recorded, and its record mode applied, as the outer run. It is refused. A row that
// is gone by the re-read was removed by cgroup_rmdir, and the insert is tried once more.
func (k *bpfKernel) insertRun(cgroupID uint64, val ebpfbindings.Run) error {
	runSet := k.maps[ebpfbindings.MapRunSet]
	if runSet == nil {
		return fmt.Errorf("%w: the run set is missing from the loaded objects", ErrProgramLoad)
	}
	for range 2 {
		err := runSet.Update(&cgroupID, &val, ebpf.UpdateNoExist)
		switch {
		case err == nil:
			return nil
		case !errors.Is(err, ebpf.ErrKeyExist):
			return mapFull("tego_run_set", err)
		}
		var cur ebpfbindings.Run
		switch err := runSet.Lookup(&cgroupID, &cur); {
		case errors.Is(err, ebpf.ErrKeyNotExist):
			continue
		case err != nil:
			return fmt.Errorf("cgroup: re-read tego_run_set row of cgroup %d: %w", cgroupID, err)
		case cur != val:
			return fmt.Errorf("cgroup: cgroup %d is already in the run set as run slot %d (record mode %d), not as "+
				"this run's slot %d: it is inside another run's cgroup, whose record and rules would be taken as "+
				"this run's", cgroupID, cur.RunIdx, cur.Record, val.RunIdx)
		}
		return nil
	}
	return fmt.Errorf("cgroup: tego_run_set row of cgroup %d was removed twice while it was inserted", cgroupID)
}

// removeRun deletes a cgroup's membership and its breadcrumb.
func (k *bpfKernel) removeRun(cgroupID uint64) error {
	var errs []error
	for _, name := range []string{ebpfbindings.MapRunSet, ebpfbindings.MapReason} {
		m := k.maps[name]
		if m == nil {
			continue
		}
		if err := m.Delete(&cgroupID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, fmt.Errorf("cgroup: delete %s row for cgroup %d: %w", name, cgroupID, err))
		}
	}
	return errors.Join(errs...)
}

// breadcrumb reads one row of this build's tego_reason_map.
func (k *bpfKernel) breadcrumb(cgroupID uint64) (ebpfbindings.Breadcrumb, bool, error) {
	var br ebpfbindings.Breadcrumb
	m := k.maps[ebpfbindings.MapReason]
	if m == nil {
		return br, false, nil
	}
	switch err := m.Lookup(&cgroupID, &br); {
	case errors.Is(err, ebpf.ErrKeyNotExist):
		return br, false, nil
	case err != nil:
		return br, false, fmt.Errorf("cgroup: read the tego_reason_map row of cgroup %d: %w", cgroupID, err)
	}
	return br, true, nil
}

// runSetLive is runSetLive over this build's run set. A kernel whose load failed before the run set reached k.maps
// (newBPFKernel stopped on cgroup_net, the first object) holds no handle to it, but an earlier launcher of the build
// may have pinned one that still names a live orphan: that pin is read instead, so the last launcher out never
// removes the build under it (ADR 0022 (1)). No pin at all is a build whose maps never got that far, which
// enforces no run, as a sweep reads it (sweepBuild); a pin that cannot be read keeps the build.
func (k *bpfKernel) runSetLive(mount string) (bool, error) {
	if m := k.maps[ebpfbindings.MapRunSet]; m != nil {
		return runSetLiveIn(m, mount)
	}
	if k.pins.Maps == "" {
		return false, errors.New("cgroup: the build's run set has no handle and no pin directory")
	}
	switch live, err := pinnedRunSetLiveAt(filepath.Join(k.pins.Maps, ebpfbindings.MapRunSet), mount); {
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	case err != nil:
		return false, err
	default:
		return live, nil
	}
}

// pinnedRunSetLiveAt is what bpfKernel.runSetLive reads a pinned run set with; a variable so a test without
// bpffs can stand in for the pin.
var pinnedRunSetLiveAt = pinnedRunSetLive

// unpin removes every pin of this build. Only the launcher that won the exclusive build lock calls it, so no
// other run can be using what it removes (§5 R14).
//
// Every link is unpinned through k.released (teardown.unpinLink), which records the program it ran, and close,
// once this launcher holds no descriptor of the build, waits until the kernel has freed those programs, which it
// does only once it has released every link over them (perf-cold C3, gate G-H2): the next run's load no longer
// waits in bpf_trampoline_get for a detach this launcher left behind. A shared link's pin is removed before its
// descriptor is closed, so where the pin's release is immediate (6.17) this launcher's close(2) is the last reference
// and frees the link in this process. The free is what costs: each fentry link waits out an RCU Tasks grace period
// in the kernel's ftrace unregistration, serialised under its lock, 110–200 ms a link after the first and 0.47–0.87 s
// a launcher in the KVM guest, and closing them from goroutines at once took longer, 0.66 s. Only the last launcher
// out of a build that does not linger (`bpf.linger: 0`) pays it; with a linger (ADR 0022) the timer's sweep does,
// off any run's path. A removal that fails part way waits for nothing (pinLayout.remove).
func (k *bpfKernel) unpin() error {
	err := k.unpinAll()
	if err != nil {
		k.released.progs = nil
	}
	return err
}

// unpinAll is unpin's removal, its links' programs recorded in k.released.
func (k *bpfKernel) unpinAll() error {
	var errs []error
	// The plane's links go with the build (pins.remove takes its <hash>-<mode> directories): this process's own
	// descriptors are closed first, so the pins' removal is what detaches them.
	for _, p := range k.planes {
		errs = append(errs, p.closeLinks())
	}
	// The planes are removed before any map of the build is unpinned, and a plane that cannot be keeps the build
	// whole: a map unpinned under it is one the next launcher re-creates and the pinned plane never reads (R20).
	if err := removePlaneDirs(k.pins.Base, filepath.Base(k.pins.Root), &k.released); err != nil {
		return errors.Join(append(errs, err)...)
	}
	for _, l := range k.shared {
		if err := k.released.unpinLink(l.pin); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("cgroup: unpin link: %w", err))
		}
		if err := l.Close(); err != nil {
			errs = append(errs, fmt.Errorf("cgroup: close shared link: %w", err))
		}
	}
	k.shared = nil
	// The links this launcher did not attach (a listener link of another's listen contract, a run's left by one
	// whose cgroup is gone) go before any program or map too, and one that cannot keeps them, as pins.remove does:
	// a link left over unpinned maps is one the next launcher would have to refuse (attachShared).
	if err := k.pins.unpinLinks(&k.released); err != nil {
		return errors.Join(append(errs, err)...)
	}
	for _, p := range k.progs {
		if err := p.Unpin(); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("cgroup: unpin program: %w", err))
		}
	}
	for _, m := range k.maps {
		if err := m.Unpin(); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("cgroup: unpin map: %w", err))
		}
	}
	if err := k.pins.removeAll(&k.released); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// close releases every descriptor: this run's cgroup links first, then the shared links, then the
// collections. Closing a shared link does not detach it while its pin exists, which is what lets one
// launcher leave without disturbing another (§5 R14).
func (k *bpfKernel) close() error {
	errs := []error{k.detachCgroup()}
	for _, p := range k.planes {
		errs = append(errs, p.close())
	}
	k.planes = nil
	for _, l := range k.shared {
		if err := l.Close(); err != nil {
			errs = append(errs, fmt.Errorf("cgroup: close shared link: %w", err))
		}
	}
	k.shared = nil
	for i := len(k.colls) - 1; i >= 0; i-- {
		k.colls[i].Close()
	}
	k.colls = nil
	k.maps = map[string]*ebpf.Map{}
	k.progs = map[string]*ebpf.Program{}
	// The build this launcher unpinned is torn down by the kernel once nothing holds it: return when it is (unpin).
	k.released.wait()
	return errors.Join(errs...)
}

// mapFull turns the kernel's capacity errnos into the error the launcher reports, and leaves anything else
// as itself.
func mapFull(name string, err error) error {
	if errors.Is(err, unix.E2BIG) || errors.Is(err, unix.ENOSPC) || errors.Is(err, unix.ENOMEM) {
		return fmt.Errorf("%w: %s: %w", ErrMapFull, name, err)
	}
	return fmt.Errorf("cgroup: update %s: %w", name, err)
}

// verifierTail keeps a verifier rejection's message intact: cilium/ebpf already carries the log's tail on the
// error, and the launcher prints it verbatim after "bpf program load failed:" (§7).
func verifierTail(err error) error {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		return ve
	}
	return err
}
