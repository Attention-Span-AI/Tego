// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/startphase"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// This file is the report `tego run` selects from (R27 "What a run probes"). doctor runs every check of
// R27 and loads every program D6 and D7 name; a run needs only the checks of the tiers its selection can
// pick or has to explain. Every root run used to take the whole of doctor.Run first — 228 bpf(2) calls for
// `--tier landlock -- true` and about 3 s on Ubuntu 24.04's 6.8 in the KVM guest, against a 3-8 ms run — which
// is what failed kill test 4 at tier landlock as root.

// Reach is the highest tier a run's selection can pick or has to explain, so the tiers whose checks the run
// must probe (ForRun): the tier `--tier` names (only), the contract's own tier:, and the machine config's
// concrete tier, each of which a refusal explains by name in doctor's words (enforce.Explain); under tier
// auto, the highest tier at or below the machine's ceiling that this process and this binary could get at
// all. Tier landlock is always among them, since every refusal that names no tier is explained by tier
// landlock's line.
func Reach(m *config.Machine, rt *agent.RuleTable, only backend.Tier) backend.Tier {
	return reach(m, rt, only, config.InitNSRoot(), enforce.Buildable)
}

// reach is Reach with root and the build supplied, so every case can be described without the machine.
//
// Under auto the preconditions read are the two that no probe can change: root (tier cgroup and above need
// CAP_BPF, CAP_NET_ADMIN and CAP_SYS_ADMIN, missingFor) and the build (enforce.Buildable, which Select
// applies to the probe as well). A tier either rules out is one Select would not pick whatever the checks
// said, and it is not explained either, since auto names no tier.
func reach(m *config.Machine, rt *agent.RuleTable, only backend.Tier, root bool, built func(backend.Tier) error) backend.Tier {
	out := backend.TierLandlock
	raise := func(t backend.Tier) {
		if t.AtOrBelow(backend.TierBPFLSM) && t.Rank() > out.Rank() {
			out = t
		}
	}
	var pin backend.Tier
	if rt != nil && rt.Contract != nil {
		if t := backend.Tier(rt.Contract.Tier); t != backend.TierAuto {
			pin = t
		}
	}
	ceil := ceiling(m)
	if only != "" || pin != "" || ceil != "" {
		// A named tier is selected or refused as itself, and a --tier that meets another pin is refused as the
		// conflict, which also explains that pin when it is missing (enforce.TierConflictError): every tier
		// named here is one the refusal may have to explain, whichever the selection settles on.
		raise(only)
		raise(pin)
		raise(ceil)
		return out
	}
	for _, t := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
		if root && built(t) == nil {
			raise(t)
		}
	}
	return out
}

// AutoTiers is the enforcement tiers tier: auto resolves among for this process on this machine, lowest first:
// those this binary constructs (enforce.Buildable), tier cgroup and above only as root in the initial user namespace
// (they need CAP_BPF, CAP_NET_ADMIN and CAP_SYS_ADMIN there, as Reach reads it), and tier bpflsm only with bpf in the
// active LSM list (D6, read unprivileged; an unreadable list is no bpf). No program is loaded: these are the
// preconditions no probe can change. A tegobpf build run by a normal user, on a kernel booted without bpf in lsm=,
// used to compile an auto contract at tier bpflsm and refuse its fs.ask_read for a tier its run could never get.
func AutoTiers() []backend.Tier {
	return autoTiers(config.InitNSRoot(), bpfLSMActive, enforce.Buildable)
}

// bpfLSMActive reports bpf in the active LSM list, false when the list cannot be read.
func bpfLSMActive() bool {
	st, err := ReadLSMState()
	return err == nil && st.BPFActive
}

// autoTiers is AutoTiers with root, the LSM list and the build supplied; bpfLSM is read only when it decides.
func autoTiers(root bool, bpfLSM func() bool, built func(backend.Tier) error) []backend.Tier {
	var out []backend.Tier
	for _, t := range backend.Tiers() {
		if !t.AtOrBelow(backend.TierBPFLSM) || built(t) != nil {
			continue
		}
		if t != backend.TierLandlock && !root {
			continue
		}
		if t == backend.TierBPFLSM && !bpfLSM() {
			continue
		}
		out = append(out, t)
	}
	return out
}

// ForRun is the report `tego run` selects from: doctor.Run's derivation over the checks of tier reach and
// every tier below it (Reach), with the checks no such tier reads left unprobed. Probe and WhyNot agree with
// those of doctor.Run called by the same process for every tier at or below reach, so a run is selected and
// refused exactly as doctor reports it; a tier above reach is reported unavailable, and neither selected nor
// explained.
//
//   - reach landlock: D1, D3, D4 and D5, the whole of tier landlock's list. D2, D6, D7 and D8 are not run, so
//     no BPF program is loaded and no fanotify group made.
//   - reach cgroup: those, and D2, D7's tier-2 rows and D8. D6, tier 3's rows and capture's rows are not run.
//     As root, D7's tier-2 rows and D8 come from the run-probe cache when it holds a valid answer for this
//     boot, kernel, LSM list, lockdown, build and binary, and for this process's own privilege: its effective
//     capabilities, LSM labels, user and mount namespaces, cgroup, cgroup namespace and invoking uid
//     (runcache.go). Concurrent misses coordinate D7/D8 population for at most 30 seconds and revalidate
//     the caller and published answer; a run that waited for an answer that was not kept, and unavailable
//     coordination, use the ordinary probe path (R27 "Concurrent misses"). A fresh
//     answer refreshes it. A process under a seccomp filter never uses it. What the key
//     cannot see is a restriction it does not hold, such as a Landlock domain, and a run under one can be
//     offered tier cgroup and stop at Prepare.
//   - reach bpflsm: those of reach cgroup, cached and adopted alike, and D6's LSM list. Tier bpflsm is the plane in
//     LSM mode over tier cgroup (enforce-plane R19): it reads tier cgroup's checks, bpf in the LSM list and LSM mode's
//     answer, never tier 3's own D7 rows or capture's. D6's counting program is not loaded: LSM mode's probe counts
//     the plane's LSM programs running, which is the same proof, and a cached or pinned answer is one this boot's
//     probe gave. An auto run as root reaches bpflsm, so this is every such run's scope.
//   - anything else: doctor.Run's own probe, every check.
//
// A check a run skips is safe to skip because it reads only into tiers the run can neither select nor
// explain; and what a skipped or cached check would have found wrong still stops the run: the backend loads
// every program and creates its fanotify group at Prepare, whose failure is exit 125 before run_start
// (runtime-launch.md R2), never a run at a lower tier.
func ForRun(ctx context.Context, m *config.Machine, reach backend.Tier) (*Report, error) {
	uid, _ := config.InvokingUID()
	s := scope{uid: uid, root: config.InitNSRoot(), checks: machineChecks, planePin: planePin(m)}
	switch reach {
	case backend.TierLandlock:
		s.reach = reach
	case backend.TierCgroup, backend.TierBPFLSM:
		s.reach, s.cache, s.adopt, s.seed = reach, defaultRunCache(), adoptPinnedPlane, bpfobj.SeedKernelFuncs
	// No other reach narrows the probes.
	case backend.TierObserve, backend.TierAuto:
	}
	st := s.run(ctx)
	if ctx.Err() != nil {
		return nil, fmt.Errorf("doctor: %w", ctx.Err())
	}
	return st.report(m, ""), nil
}

// checks are the nine probes of R27, as fields so a test can describe a machine and count which of them a
// scope runs.
type checks struct {
	kernel   func() (Result, string, Version)
	btf      func() Result
	cgroup   func(uid int) Result
	landlock func() (Result, int)
	seccomp  func() (Result, PtraceState, error)
	lsm      func(root bool) (Result, LSMState)
	programs func(root bool, uid int, kernel Version, tier, capture []hook) (Result, []HookResult)
	// plane is the decision plane's mode probe (planeprobe.go), run inside D7.
	plane    func(root bool, uid int, release, pin string, keep bool) (*PlaneState, []HookResult)
	fanotify func(root bool, kernel Version) (Result, FanotifyState)
	swap     func() Result
	// kernelFuncs answers bpf.KernelFuncNames from the kernel's BTF, nil when it cannot be read: what the run-probe
	// cache keeps beside D2 so a run that reads it parses no BTF (runCacheEntry.KernelFuncs). nil keeps none.
	kernelFuncs func() map[string]bool
	// unixDiag reports whether the kernel answers sock_diag for AF_UNIX, which every tier's implicit admit of a
	// socket under a write entry needs (supervisor R11a). It gates no tier and is no check of R27's nine: doctor's
	// scope asks it for the unix sockets row's note (machineMatrix); a run's supervisor warns on its own. nil asks
	// nothing.
	unixDiag func() bool
}

// machineChecks are the real probes.
var machineChecks = checks{
	kernel:      probeKernelVersion,
	btf:         probeBTF,
	cgroup:      probeCgroup,
	landlock:    probeLandlockABI,
	seccomp:     probeSeccomp,
	lsm:         probeLSM,
	programs:    probeHooks,
	plane:       probePlane,
	fanotify:    probeFanotify,
	swap:        probeSwap,
	kernelFuncs: machineKernelFuncs,
	unixDiag:    supervisor.UnixDiagAvailable,
}

// machineKernelFuncs is bpf.KernelFuncFacts on the kernel's own BTF, through the process's kept parse (D2 has
// parsed it by the time a run records its answer), nil when the BTF cannot be read.
func machineKernelFuncs() map[string]bool {
	spec, err := loadKernelSpec()
	if err != nil {
		return nil
	}
	return bpfobj.KernelFuncFacts(spec)
}

// scope is one run of the probes: every check when reach is "", else the checks of reach and the tiers below it
// (ForRun).
type scope struct {
	reach  backend.Tier
	uid    int
	root   bool
	checks checks
	// cache is where D7's tier-2 rows, the plane's answer and D8 are kept between runs at reach cgroup, nil for
	// none. doctor.Run never has one: doctor always probes afresh.
	cache *runCache
	// planePin is the machine's bpf.plane setting, which selects tier cgroup's plane mode from the probe's answer.
	planePin string
	// adopt reads a pinned plane build's recorded answer (planepin.go), nil for none: a run at reach cgroup
	// that finds its build pinned in the mode it would select probes no plane (R21).
	adopt func(pin string) (*PlaneState, bool)
	// seed hands the kernel's functions a cache entry kept to the process's loaders (bpf.SeedKernelFuncs), nil for
	// none: ForRun's scope only, since what it seeds is process-wide.
	seed func(map[string]bool)
}

// needs reports whether this scope runs checks that tier t reads.
func (s scope) needs(t backend.Tier) bool { return s.reach == "" || t.AtOrBelow(s.reach) }

// run runs the scope's checks in R27's exact order, stopping early when ctx ends. A check the scope does not
// need still has its place in Results, marked not probed, so Results keeps R27's nine entries in order.
func (s scope) run(ctx context.Context) probeState {
	if !s.reach.AtOrBelow(backend.TierBPFLSM) {
		s.reach = "" // not a tier a run selects: doctor's scope
	}
	st := probeState{byID: map[CheckID]Result{}, root: s.root, reach: s.reach}
	add := func(r Result) {
		st.results = append(st.results, r)
		st.byID[r.ID] = r
	}
	skip := func(id CheckID) { add(notProbed(id, s.reach)) }
	// The cache is read and written only by root, in a root-owned directory (runcache.go), and only at reach
	// cgroup and bpflsm: reach landlock runs neither D7 nor D8, and doctor's scope probes afresh.
	cache := s.cache
	if !s.root || (s.reach != backend.TierCgroup && s.reach != backend.TierBPFLSM) {
		cache = nil
	}
	var (
		key   runCacheKey
		keyOK bool
		// entry is read at D1 and rechecked under a concurrent miss lease; hit is entry when its plane
		// answers this run's bpf.plane, which D7 and D8 are then read from.
		entry   *runCacheEntry
		entryID entryID
		hit     *runCacheEntry
		// d7 is D7's Result before the plane's clause, the form the cache keeps: the clause names the mode the
		// machine's bpf.plane selects, which is read afresh on every run.
		d7               Result
		flight           *probeFlight
		coordinationNote string
	)
	// releaseFlight ends this run's hold on its key's flight, if any: once its answer is kept or dropped (D8), or
	// once it knows waiting gained it nothing.
	releaseFlight := func() {
		if flight != nil {
			flight.close()
			flight = nil
		}
	}
	defer releaseFlight()
	// withPlane adds the plane's rows ahead of capture's and its clause to D7's line.
	withPlane := func(r Result, rows []HookResult, plane *PlaneState, planeRows []HookResult) {
		d7 = r
		st.plane = plane
		var tier, capture []HookResult
		for _, h := range rows {
			if h.Capture {
				capture = append(capture, h)
			} else {
				tier = append(tier, h)
			}
		}
		st.hooks = append(append(tier, planeRows...), capture...)
		r.Detail += planeSummary(plane, st.lsm.BPFActive)
		add(r)
	}
	steps := []func(){
		func() {
			r, release, v := s.checks.kernel()
			st.release, st.kernel = release, v
			add(r)
			if cache == nil {
				return
			}
			if key, keyOK = cache.key(st.release, s.uid); keyOK {
				if e, id, ok := cache.loadIdentified(key); ok {
					entry, entryID = &e, id
					if e.KernelFuncs != nil && s.seed != nil {
						s.seed(e.KernelFuncs)
					}
				}
			}
		},
		func() {
			if !s.needs(backend.TierCgroup) {
				skip(CheckBTF)
				return
			}
			// D2 reads the kernel's BTF and this binary's objects alone, both of which the key pins.
			if entry != nil && entry.BTF != nil {
				add(*entry.BTF)
				return
			}
			add(s.checks.btf())
		},
		func() { add(s.checks.cgroup(s.uid)) },
		func() {
			r, abi := s.checks.landlock()
			st.landlockABI = abi
			add(r)
		},
		func() {
			r, pt, err := s.checks.seccomp()
			st.ptrace, st.seccompErr = pt, err
			add(r)
		},
		func() {
			if !s.needs(backend.TierBPFLSM) {
				skip(CheckLSM)
				return
			}
			// A run's scope reads the list and leaves the counting program to LSM mode's answer (ForRun).
			r, state := s.checks.lsm(st.root && s.reach == "")
			st.lsm = state
			add(r)
		},
		func() {
			switch {
			case s.reach == "":
				r, rows := s.checks.programs(st.root, s.uid, st.kernel, hooks, captureHooks)
				plane, planeRows := s.checks.plane(st.root, s.uid, st.release, s.planePin, cache != nil)
				withPlane(r, rows, plane, planeRows)
				return
			case !s.needs(backend.TierCgroup):
				skip(CheckPrograms)
				return
			}
			// A concurrent cold run may publish after our D1 miss. Coordinate
			// only the expensive D7/D8 population, then re-read both authority
			// and answer: holding a lock is never evidence of a capability.
			if cache != nil && keyOK && (entry == nil || entry.Plane == nil || !entry.Plane.answers(s.planePin)) {
				var err error
				flight, err = cache.acquireFlight(ctx, key, runProbeFlightWait)
				if err != nil {
					// A refused cache directory is the cache's own note (cache.refused), not a second one here.
					if !errors.Is(err, errCacheDir) {
						coordinationNote = err.Error()
					}
					if ctx.Err() != nil {
						return
					}
				}
				// Even an unsuccessful wait may span a privilege or machine
				// change. Its fresh probe must not publish under the D1 key.
				current, ok := cache.key(st.release, s.uid)
				if !ok || !reflect.DeepEqual(current, key) {
					releaseFlight()
					entry, cache, keyOK = nil, nil, false
				} else if flight != nil {
					entry = nil
					if e, id, ok := cache.loadIdentified(key); ok {
						entry, entryID = &e, id
						if e.KernelFuncs != nil && s.seed != nil {
							s.seed(e.KernelFuncs)
						}
					}
					// The run this one waited for has ended and kept nothing this run can read: its answer did not
					// vouch, or its plane faulted again. Waiting is only worth an answer the cache keeps, so this run
					// probes without the flight, alongside every other run that waited, rather than making the next
					// one wait out its probe too (v73 review doctor-1, amended 2026-10-05: each waiter used to probe
					// under the flight in turn, N runs started together starting N probe times apart).
					if flight.waited && (entry == nil || entry.Plane == nil || !entry.Plane.answers(s.planePin)) {
						releaseFlight()
					}
				}
			}
			// answerPlane is the plane's answer where the cache holds none: a pinned build's, else a probe. A test
			// build times it as "probe.plane" inside "probe.programs", beside D7's "probe.d7" (enforce-plane §10.1's
			// cold attribution).
			answerPlane := func() (*PlaneState, []HookResult) {
				defer startphase.Begin(nil, "probe.plane")()
				if s.adopt != nil && st.root {
					if plane, ok := s.adopt(s.planePin); ok {
						return plane, nil
					}
				}
				return s.checks.plane(st.root, s.uid, st.release, s.planePin, cache != nil)
			}
			if entry != nil && entry.Plane == nil {
				// An entry whose plane probe faulted kept D7's tier-2 rows and D8's answer alone: the plane is the one
				// thing to answer afresh, and an answer that no longer faults completes the entry, which DiscardCache
				// then follows.
				hit = entry
				st.cached = &cachedAnswer{cache: cache, key: key, id: entryID}
				plane, planeRows := answerPlane()
				if plane != nil && !plane.Skipped && !plane.faulted() {
					if kept := cache.recordWith(key, entry.Programs, entry.Hooks, plane, planeRows, entry.Fanotify,
						entry.FanotifyState, kernelAnswers{btf: entry.BTF, funcs: entry.KernelFuncs}); kept != nil {
						st.cached.id = *kept
					}
				}
				withPlane(entry.Programs, entry.Hooks, plane, planeRows)
				return
			}
			// A cached answer adopted from a pinned build knows the one mode that build was loaded in: a pin naming the
			// other mode is not answered by it, and probes (TIER3-PLAN T6 found a bpf.plane change running every later
			// run on the listener until the cache's boot ended).
			if entry != nil && entry.Plane.answers(s.planePin) {
				hit = entry
				st.cached = &cachedAnswer{cache: cache, key: key, id: entryID}
				plane := *entry.Plane
				plane.Pin, plane.Source = s.planePin, planeSourceRunCache
				selectPlane(&plane)
				withPlane(entry.Programs, entry.Hooks, &plane, entry.PlaneRows)
				return
			}
			endD7 := startphase.Begin(nil, "probe.d7")
			r, rows := s.checks.programs(st.root, s.uid, st.kernel, tierHooks(backend.TierCgroup), nil)
			endD7()
			plane, planeRows := answerPlane()
			withPlane(r, rows, plane, planeRows)
		},
		func() {
			defer releaseFlight() // the answer is kept or dropped by now: D9 needs no coordination
			switch {
			case !s.needs(backend.TierCgroup):
				skip(CheckFanotify)
				return
			case hit != nil:
				st.fanotify = hit.FanotifyState
				add(hit.Fanotify)
				return
			}
			r, state := s.checks.fanotify(st.root, st.kernel)
			st.fanotify = state
			add(r)
			if cache != nil && keyOK {
				var tier, planeRows []HookResult
				for _, h := range st.hooks {
					if h.Plane != "" {
						planeRows = append(planeRows, h)
					} else {
						tier = append(tier, h)
					}
				}
				cache.recordWith(key, d7, tier, st.plane, planeRows, r, state, s.kernelAnswers(st, entry))
			}
		},
		// D9 reads a file or two and gates no tier, so every scope runs it.
		func() { add(s.checks.swap()) },
	}
	// The steps are R27's nine checks in order; each is timed as "probe.<check>" in a test build (startphase), for the
	// start-latency budget's breakdown.
	for i, step := range steps {
		if ctx.Err() != nil {
			return st
		}
		end := startphase.Begin(nil, "probe."+stepNames[i])
		step()
		end()
	}
	if cache != nil {
		st.cacheNote = cache.refused
	}
	if s.reach == "" && s.checks.unixDiag != nil {
		ok := s.checks.unixDiag()
		st.unixDiag = &ok
	}
	// A run that could not coordinate still read and wrote the cache: its reason is a note of its own, never
	// the cache's "unusable" one (amended 2026-10-05, v73 review doctor-3: it was prefixed to the cache note).
	st.coordinationNote = coordinationNote
	return st
}

// stepNames name run's steps for startphase: kernel, btf, cgroup, landlock, seccomp, lsm, programs (with the plane
// and the run cache), fanotify and swap.
var stepNames = [...]string{"kernel", "btf", "cgroup", "landlock", "seccomp", "lsm", "programs", "fanotify", "swap"}

// kernelAnswers is what a fresh answer keeps of the kernel's BTF: D2 as this run has it, and the kernel's functions,
// from the entry it replaces when that holds them, else from the BTF (checks.kernelFuncs).
func (s scope) kernelAnswers(st probeState, prev *runCacheEntry) kernelAnswers {
	var k kernelAnswers
	if r, ok := st.byID[CheckBTF]; ok && passedBTF(r) {
		k.btf = &r
	}
	switch {
	case prev != nil && prev.KernelFuncs != nil:
		k.funcs = prev.KernelFuncs
	case s.checks.kernelFuncs != nil:
		k.funcs = s.checks.kernelFuncs()
	}
	return k
}

// notProbed is the Result of a check a run's scope does not need. It is Skipped, not failed: the check did
// not run, and OK stays false because it established nothing (Result.Skipped).
func notProbed(id CheckID, reach backend.Tier) Result {
	return Result{ID: id, Skipped: true,
		Detail: fmt.Sprintf("not probed by tego run: no tier up to %s, the highest its selection can reach, reads it "+
			"(tego doctor runs it)", reach)}
}
