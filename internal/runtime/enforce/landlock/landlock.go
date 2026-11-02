// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/policy/fsplan"
	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// Sentinel errors, one per failure class (§7, §9); every return wraps one with %w so callers pick
// the exit code with errors.Is.
var (
	// ErrLandlockUnsupported is the ABI probe failing (R1, E1, E2): Select excludes this backend first.
	ErrLandlockUnsupported = errors.New("landlock: unsupported on this kernel")
	// ErrPathVanished is ENOENT/ELOOP/ENOTDIR on a compiled entry (E9, E14): the contract drifted since compile.
	ErrPathVanished = errors.New("landlock: path vanished since compile")
	// ErrFDExhausted wraps EMFILE/ENFILE (E11, E27); the message names how many fds were held.
	ErrFDExhausted = errors.New("landlock: file descriptors exhausted")
	// ErrRulesetBuild wraps a failing landlock_create_ruleset/landlock_add_rule (E21) or a rule the
	// backend cannot build from the table it was given (E5, I5).
	ErrRulesetBuild = errors.New("landlock: ruleset build failed")
	// ErrInterpreterMissing is a script whose #! names an interpreter no exec grant covers (R5, E14).
	ErrInterpreterMissing = errors.New("landlock: script interpreter is not granted")
	// ErrLoaderRefused is an ELF whose PT_INTERP names a loader this tier will not grant: a path the
	// contract governs, or one that is not a regular file (R5, E29). Its own class because the remedy
	// differs from ErrInterpreterMissing's — the binary, not the exec list, chose that path.
	ErrLoaderRefused = errors.New("landlock: ELF loader is refused")
	// ErrNegativeWriteNeedsPlane refuses a table whose contract says fs.assurance: kernel when no plane rows will
	// decide its built-in deny_write targets, exceptions beneath a recursively writable directory that Landlock
	// cannot express and the supervisor refuses only best effort (R5a, ADR 0041 D1 (a)).
	ErrNegativeWriteNeedsPlane = errors.New("landlock: protected write targets require a kernel decision plane")
)

// ctxCheckEvery is how many opened entries pass between ctx.Err() checks (§4: every 256 entries).
const ctxCheckEvery = 256

// Options configures New. The zero value is production: real syscalls, ABI probed on first use.
type Options struct {
	// ABI is the kernel's Landlock ABI as probed by ProbeABI (enforce.Select threads it in, R19).
	// 0 means "probe lazily on the first Capabilities or Prepare call", once per Backend.
	ABI int

	syscalls landlockSyscalls // nil ⇒ the real trio (§4, C2); tests inject a fake
	// sealSupported replaces the MFD_NOEXEC_SEAL probe (MemfdNoexecSealSupported), so a test builds a run of a kernel
	// without the flag on one with it.
	sealSupported func() bool
}

// Run is what Prepare reads of the run it builds for, and nothing else: the import direction (enforce selects
// this package, never the reverse) keeps enforce.RunRef out of here, and enforce adapts the fields tier 1 uses.
type Run struct {
	Dir string // the run directory, an implicit deny node (R8)
	// Plane is the decision plane's rows when the run's tier decides through a plane mode (tier cgroup's lsm or
	// fmod_ret, docs/p0/enforce-plane.md R16, R17), nil otherwise. Prepare then holds an O_PATH descriptor for every
	// path the plane keys (PlaneRows.Keyed), which the plane's fill reads the inodes from (Handle.PlaneHeld), and
	// adds each one's neutral rule (PlaneRows.Neutral), so the run's domain pins every keyed inode and grants
	// nothing it did not grant already (ADR 0025 (3)).
	Plane *decide.PlaneRows
	// PlaneMaps is set when the plane mode that decides this run has step C's hooks loaded and probed
	// (bpf.PlaneDecidesMappings with a mode doctor's probe selected): its bprm_check and mmap_file refuse an anonymous
	// image's exec and its PROT_EXEC mapping race-free, so the filter carries no arm refusing every memfd_create on a
	// kernel without MFD_NOEXEC_SEAL (enforce-plane R27, R11a). The sealing arm stays where the kernel has the flag.
	PlaneMaps bool
	// Drop is set for a root launch whose child drops to DropUID and DropGID (launch.ChildSpec's TargetUID and
	// TargetGID). A write directory Prepare creates for the run (writeEntry) is then made with those
	// credentials, so it is the agent's and not root's: a root-owned 0755 directory would refuse the dropped
	// agent every create in it by DAC while Landlock grants it.
	Drop             bool
	DropUID, DropGID int
	// IOUring is the tier deciding io_uring's submissions in the kernel (a plane mode with its socket_create, and
	// cgroup/connect_unix; enforce.select, ADR 0018 (5)): a contract that declares io_uring: true then gets the
	// filter without its io_uring_* arms (R10). False keeps them, whatever the contract says. The one other setter
	// is a -tags tegotesthooks build's seam on the fanotify fallback (TEGO_TEST_FALLBACK_IOURING, A-0018-5), which
	// exists to prove cgroup/sock_create and which a product build does not contain.
	IOUring bool
}

// Backend is the tier-1 backend: a Landlock ruleset built from held O_PATH fds plus the classic-BPF
// seccomp filter. Safe for concurrent use; it holds no fds itself (a Handle does). enforce wraps it
// as an enforce.Backend.
type Backend struct {
	sc     landlockSyscalls
	seal   func() bool // the MFD_NOEXEC_SEAL probe (Options.sealSupported)
	once   sync.Once
	abi    int
	abiErr error
}

// New is the stateless constructor (§4, C2): no syscalls, safe to call more than once.
func New(opts Options) *Backend {
	b := &Backend{sc: opts.syscalls, seal: opts.sealSupported}
	if b.sc == nil {
		b.sc = realSyscalls{}
	}
	if b.seal == nil {
		b.seal = MemfdNoexecSealSupported
	}
	if opts.ABI > 0 {
		b.once.Do(func() { b.abi = opts.ABI })
	}
	return b
}

// Tier is always backend.TierLandlock.
func (b *Backend) Tier() backend.Tier { return backend.TierLandlock }

// ABI returns the probed Landlock ABI (R1), probing at most once per Backend (R19).
func (b *Backend) ABI() (int, error) {
	b.once.Do(func() { b.abi, b.abiErr = probeABI(b.sc) })
	return b.abi, b.abiErr
}

// Capabilities is the tier-1 row of the capability matrix read against the stored ABI (R19, I10):
// net host deny needs ABI ≥ 4 for its in-kernel backstop, UDP port rules ABI ≥ 10; unix sockets are
// always provided through the seccomp path (RESOLVE_UNIX joins at ABI ≥ 9); the abstract-socket scope needs
// ABI ≥ 6 (R7). An unsupported kernel provides nothing. No new syscall after the first call.
func (b *Backend) Capabilities() backend.Set {
	abi, err := b.ABI()
	if err != nil {
		return backend.Set{}
	}
	return capabilitiesFor(abi)
}

func capabilitiesFor(abi int) backend.Set {
	s := backend.Matrix(backend.TierLandlock)
	provide(s, backend.CapNetHostDeny, abi >= 4)      // R6 backstop; E4 below ABI 4
	provide(s, backend.CapUDPPortInKernel, abi >= 10) // R22
	provide(s, backend.CapUnixSockets, true)          // seccomp connect at every ABI, RESOLVE_UNIX at ≥ 9 (R21)
	// R7: the abstract-socket scope is created with every ruleset from ABI 6 on, whatever the contract; below
	// it nothing refuses an abstract name bound outside the run, which agent-contract R19 says a run records.
	provide(s, backend.CapUnixAbstractScope, abi >= 6)
	return s
}

// provide sets or removes a row: an absent key means "not provided" (backend.Set).
func provide(s backend.Set, c backend.Capability, ok bool) {
	if ok {
		s[c] = true
		return
	}
	delete(s, c)
}

// Prepare builds the run's kernel objects before clone3 (§4): opens every rule path O_PATH|O_CLOEXEC
// and holds the fds, enumerates deny_read siblings (R3/R4), grants exec targets with their loaders
// and interpreters (R5), adds the net (R6/R22) and unix (R21) backstops, creates the ruleset with the
// ABI's handled masks (R2) and assembles the seccomp filter (R9–R16). All-or-nothing: any failure
// closes every fd opened so far (I1). Call exactly once per run.
func (b *Backend) Prepare(ctx context.Context, rt *agent.RuleTable, run Run) (*Handle, error) {
	if rt == nil {
		return nil, fmt.Errorf("%w: nil rule table", ErrRulesetBuild)
	}
	if rt.DenyWriteNeedsPlane() && run.Plane == nil {
		return nil, fmt.Errorf("%w: %s, and the contract sets fs.assurance: kernel; use cgroup/bpflsm with an available decision "+
			"plane, narrow fs.write so it does not cover protected targets, or drop fs.assurance: kernel", ErrNegativeWriteNeedsPlane,
			rt.DenyWrite[0].RuleName())
	}
	abi, err := b.ABI()
	if err != nil {
		return nil, err
	}
	bd := newBuilder(ctx, rt, run, profileFor(abi), b.sc)
	bd.sealProbe = b.seal
	// The plan is held against the launcher's descriptor budget, read before its first open (fdbudget.go): a table
	// that needs more is refused naming the cap, never left to meet EMFILE part way.
	budget, err := readFDBudget()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRulesetBuild, err)
	}
	bd.fds.budget, bd.fds.budgeted = budget, true
	h, err := bd.build()
	if err != nil {
		return nil, errors.Join(err, bd.fds.closeAll())
	}
	return h, nil
}

// builder is the per-Prepare state: the fd owner, the rules derived so far and the counters the ctx
// check and diagnostics need. It lives for one Prepare call on one goroutine.
type builder struct {
	ctx        context.Context
	rt         *agent.RuleTable
	run        Run
	profile    abiProfile
	sc         landlockSyscalls
	sealProbe  func() bool // the MFD_NOEXEC_SEAL probe; nil means MemfdNoexecSealSupported
	fds        *fdSet
	heldNames  map[string]string // actual dentry name when each declared path was first held
	fsPlan     fsplan.Plan
	listenHeld map[string]int           // listener path -> dedicated parent entry; never an alias in fds.paths
	levels     map[string]snapshotLevel // each enumerated ancestor's one listing (noteLevel), for the Snapshot

	governed     []governedPath // write/ask/deny_read entries, resolved once for R5's loader check
	governedOnce bool
	execResolved []string // rt.Exec paths resolved on first use, "" until then (resolvedExec)

	execUnrestricted bool // no exec: section ⇒ EXECUTE joins the read sets (SEMANTICS §1)
	execAnonymous    bool // exec.anonymous: true ⇒ the run opted into anonymous-image exec: no memfd arm, exec.deny off the capability line (SEMANTICS §4)
	netRestricted    bool // net: present ⇒ TCP/UDP handled and gated by port rules (R6)
	// unixRestricted says the run decides unix destinations: a net: section, or the unix-only state of a contract
	// with none (agent.RuleTable.HostSocketsRefused, ADR 0070). RESOLVE_UNIX is handled then, and bind(2) is notified
	// so the supervisor records the run's own sockets (R11c, supervisor R11a).
	unixRestricted bool
	unenforced     []string
	net            []netRule
	opened         int
}

func newBuilder(ctx context.Context, rt *agent.RuleTable, run Run, p abiProfile, sc landlockSyscalls) *builder {
	bd := &builder{ctx: ctx, rt: rt, run: run, profile: p, sc: sc, fds: newFDSet(), heldNames: map[string]string{}}
	// A hand-built table without its Contract fails closed on both dimensions.
	bd.execUnrestricted = rt.ExecUnrestricted()
	bd.execAnonymous = rt.ExecAnonymous()
	bd.netRestricted = rt.Contract == nil || rt.Contract.Net != nil
	bd.unixRestricted = bd.netRestricted || rt.HostSocketsRefused()
	if !bd.unixRestricted {
		// RESOLVE_UNIX sits in the filesystem mask, but it is the pathname-socket half of net: (R21), not
		// a filesystem right: handled with no net: section, it refused the agent's own connect to every
		// pathname socket outside a write entry at ABI ≥ 9, while SEMANTICS §1 says "deny nothing", the
		// supervisor continues that connect and Evaluate answers allow. Unhandled, no unix right is checked
		// at any ABI, and the abstract scope (R7) is the one kernel check stricter than the contract. In the unix-only
		// state (ADR 0070, no net: and no host_sockets: true) it stays handled, as under a net: section: granted under
		// every write entry and on the runtime's own unix: grants (netRules), so the agent's own connect or datagram
		// to a host daemon's socket is refused by the kernel at ABI >= 9, behind the supervisor's relay (R21).
		bd.profile.FS &^= accessResolveUnix
	}
	return bd
}

// build runs the stages in order; each returns the first error so the caller can release the fds.
func (bd *builder) build() (*Handle, error) {
	if err := bd.ctx.Err(); err != nil { // E20: a stop before the first open
		return nil, fmt.Errorf("landlock: prepare cancelled: %w", err)
	}
	for _, stage := range []func() error{bd.fsEntries, bd.denyRead, bd.execGrants, bd.deputyGrant, bd.netRules, bd.implicitRun, bd.planeKeys} {
		if err := stage(); err != nil {
			return nil, err
		}
	}
	// The probed ABI, not a constant: below ABI 3 the kernel cannot deny truncation, so the filter
	// carries the arms that do (R2's ABI-3 row, E31). The memfd_create arm (SEMANTICS §4) is memfdArmFor's.
	// The socket arm (ADR 0018) is the compiled net section's: an allowlist of what the network rules govern
	// under a net: section, nothing without one.
	seal := bd.sealProbe
	if seal == nil {
		seal = MemfdNoexecSealSupported
	}
	memfd := memfdArmFor(bd.rt.Contract, seal, bd.run.PlaneMaps)
	// Below ABI 6 the ruleset has no signal scope, and the filter's signal arm hands the kill family to the
	// supervisor instead (signalScopeTest).
	fopts := filterOpts{full: bd.rt.Record == agent.RecordFull,
		gateRead: bd.rt.Gate.Has(gate.FSRead),
		// Held reads notify every open too (ADR 0069 D2), and so do reason reads (ADR 0077), never part of hasAsk.
		askRead:   bd.rt.HasAskRead() || bd.rt.ReadsHeld() || bd.rt.ReasonReadsNotified(),
		gateWrite: bd.rt.Gate.Has(gate.FSWrite),
		// R11e: every enforcing filter, since a watch reads no file and only the supervisor refuses one (supervisor R36).
		watches: true,
		// R11b: no thread of a run whose net: section or net gate decides destinations may route around them.
		sourceRoute: bd.netRestricted || bd.rt.Gate.Has(gate.Net),
		frames:      bd.rt.DecidesDatagrams(), // R11d: the same predicate the supervisor's pending-frame refusal asks
		abi:         bd.profile.Version, memfd: memfd, socket: SocketArmFor(bd.rt),
		signals:       bd.profile.Version < minSignalScopeABI,
		procScope:     true,                    // no Landlock ABI scopes prlimit or scheduling (procScopeTest)
		heldOpens:     bd.rt.NeedsOpenDeputy(), // no domain of the run's own beneath the deputy's (ADR 0041 D2)
		strictNet:     bd.rt.NetworkAssurance() == agent.NetAssuranceKernel,
		listenControl: bd.rt.Listen != nil || bd.netRestricted, listenersAllowed: len(bd.rt.Listen) > 0,
		unixBinds: bd.unixRestricted, // R11c: the supervisor's record of the run's own unix sockets (supervisor R11a)
		ingress:   bd.rt.Ingress != nil,
		rootTier:  bd.rt.Tier == backend.TierCgroup || bd.rt.Tier == backend.TierBPFLSM,
		ioUring:   bd.run.IOUring && bd.rt.Contract != nil && bd.rt.Contract.IOUring}
	filter, err := assembleFilter(NativeArch(), fopts)
	if err != nil {
		return nil, err
	}
	rulesetFD, err := bd.createRuleset()
	if err != nil {
		return nil, err
	}
	caps := capabilitiesFor(bd.profile.Version)
	provide(caps, backend.CapReadDeny, len(bd.unenforced) == 0) // R4: the run's matrix carries the gap
	// exec.anonymous: true is the contract's opt-out of the memfd arm: with no memfd arm, the agent can copy any
	// binary it can read into a memfd and run it, so exec.allow no longer bounds what runs and the run's
	// capability line says so rather than leaving the opt-out on record only in contract_hash.
	provide(caps, backend.CapExecDeny, !bd.execAnonymous)
	return &Handle{
		sc:         bd.sc,
		rulesetFD:  rulesetFD,
		filter:     filter,
		fds:        bd.fds,
		unenforced: bd.unenforced,
		abi:        bd.profile.Version,
		caps:       caps,
		filterOpts: fopts,
		ask:        hasAsk(bd.rt),
		listenHeld: bd.listenHeld,
		snapshot:   bd.snapshot(),
	}, nil
}

// hasAsk reports whether the table has an fs ask entry, which keeps every notification (planeSkips).
// It is RuleTable.HoldsFSNotifications, which compile's tests read too, so the two cannot differ.
func hasAsk(rt *agent.RuleTable) bool { return rt.HoldsFSNotifications() }

// planeKeys holds every path the decision plane keys, last, once every entry is held and sealed: a keyed path
// another stage holds already is that entry (the E7 dedupe), with the neutral rule's rights unioned onto it; a new
// one is held with them, or for identity alone where the domain grants no read there (enforce-plane R17: Landlock
// then refuses every open of it itself, and the plane's identity check refuses a recycled pointer). A keyed path
// that does not exist keys no row (the plane's fill skips it, as denyRead skips a vanished target, E9).
func (bd *builder) planeKeys() error {
	rows := bd.run.Plane
	if rows == nil {
		return nil
	}
	neutral := make(map[string]accessFS, len(rows.Neutral))
	for _, n := range rows.Neutral {
		neutral[n.Path] = accessFS(n.Access) & readSet
	}
	for _, p := range rows.Keyed {
		if _, err := bd.hold(p, kindPlaneKey, neutral[p]); err != nil && !errors.Is(err, ErrPathVanished) {
			return err
		}
	}
	// A row keyed at the path's own inode (a deny_write target declared through a symlink, enforce-plane R11) is
	// held without following it, for identity alone: no rule is added through it.
	for _, p := range rows.NoFollow {
		if err := bd.tick(); err != nil {
			return err
		}
		fd, st, err := openAt(unix.AT_FDCWD, p, false, bd.fds)
		if errors.Is(err, ErrPathVanished) {
			continue
		}
		if err != nil {
			return err
		}
		bd.fds.add(fd, p, kindPlaneKey, 0, &st)
	}
	if err := bd.planeExecLinks(); err != nil {
		return err
	}
	return bd.planeListenParents()
}

// The iterator's templates are keyed by descriptor number. Give declarations
// sharing a parent distinct descriptors, all borrowed until the fill completes.
// A duplicate of the already held parent preserves the Prepare snapshot rather
// than reopening a mutable pathname.
func (bd *builder) planeListenParents() error {
	bd.listenHeld = make(map[string]int)
	for _, r := range bd.run.Plane.Listen {
		if r.Abstract {
			continue
		}
		if _, duplicate := bd.listenHeld[r.Path]; duplicate {
			return fmt.Errorf("%w: duplicate Unix listener %q", ErrRulesetBuild, r.Path)
		}
		i, ok := bd.fds.paths[r.Parent]
		if !ok {
			return fmt.Errorf("%w: Unix listener parent %q is not held", ErrRulesetBuild, r.Parent)
		}
		if err := bd.fds.owns(i); err != nil {
			return fmt.Errorf("%w: %w", ErrRulesetBuild, err)
		}
		e := bd.fds.open[i]
		if !e.IsDir {
			return fmt.Errorf("%w: Unix listener parent %q is not a directory", ErrRulesetBuild, r.Parent)
		}
		if err := bd.tick(); err != nil {
			return err
		}
		if err := bd.fds.room(r.Parent); err != nil {
			return err
		}
		fd, err := unix.FcntlInt(uintptr(e.FD), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return classifyOpenErr(r.Parent, len(bd.fds.open), err)
		}
		bd.fds.open = append(bd.fds.open, openPath{FD: fd, Path: r.Parent, Kind: kindPlaneKey,
			IsDir: true, id: e.id})
		bd.listenHeld[r.Path] = len(bd.fds.open) - 1
	}
	return nil
}

// planeExecLinks gives each exec row a descriptor held at the link its entry names (enforce-plane R16, §6 E15). The
// fill keys an exec row by the descriptor's own dentry (its inode, its directory and its name), and the E7 dedupe
// holds every name of one inode under the first name that reached it: the hard links of a multi-call binary (uutils'
// ls and cat, busybox's applets) that two entries name would share one descriptor, whose dentry is one of them. An
// exec row whose held descriptor was opened at another path, and does not name this one now (/proc/self/fd), gets a
// descriptor of its own, opened without following (the row's path is resolved already), which must be the inode the
// entry holds; one that is not (the path was replaced since it was held) fails Prepare.
func (bd *builder) planeExecLinks() error {
	for _, e := range bd.run.Plane.Exec {
		i, ok := bd.fds.paths[e.Path]
		if !ok {
			continue // did not exist: no row (the fill skips it)
		}
		held := bd.fds.open[i]
		if held.FD < 0 || held.Path == e.Path {
			continue
		}
		if at, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(held.FD)); err == nil && at == e.Path {
			continue
		}
		if err := bd.tick(); err != nil {
			return err
		}
		fd, st, err := openAt(unix.AT_FDCWD, e.Path, false, bd.fds)
		if err != nil {
			return err
		}
		if (devIno{dev: st.Dev, ino: st.Ino}) != held.id {
			_ = unix.Close(fd)
			return fmt.Errorf("%w: exec entry %q is dev %d:%d ino %d now, not the inode held for it through %q: the path was replaced while Prepare held it",
				ErrRulesetBuild, e.Path, unix.Major(st.Dev), unix.Minor(st.Dev), st.Ino, held.Path)
		}
		bd.fds.link(fd, e.Path, &st)
	}
	return nil
}

// memfdArmFor is the memfd_create arm a run gets (SEMANTICS §4, R11a). A contract with no exec: section denies
// no exec (SEMANTICS §1) and one that set exec.anonymous: true opted into anonymous-image exec: both get
// no arm, and so does a Contract-less hand-built table (tests only; production always carries one), which
// the supervisor alone keeps exec-restricted. Every other run restricts exec and gets a closing arm:
// MemfdSealed where the kernel honours MFD_NOEXEC_SEAL, and MemfdRefused on a kernel without it, where no
// flag separates an executable memfd from a data one and refusing the creation outright is the only
// race-free closure. sealSupported is the probe, a parameter so both kernels' answers are testable on one
// box. planeMaps is Run.PlaneMaps: where a plane mode with step C decides the run, its bprm_check and mmap_file
// close the anonymous image race-free in the kernel, so a kernel without the flag gets no arm rather than the
// refusing one (enforce-plane R27); the sealing arm stays as defense in depth.
func memfdArmFor(c *agent.Contract, sealSupported func() bool, planeMaps bool) MemfdArm {
	if c == nil || c.ExecUnrestricted() || c.ExecAnonymous() {
		return MemfdOpen
	}
	if sealSupported() {
		return MemfdSealed
	}
	if planeMaps {
		return MemfdOpen
	}
	return MemfdRefused
}

// hold opens one path (following symlinks) and takes ownership; it is the single entry point every
// stage uses, so the ctx check and the fd count are uniform (§4, E20, E22).
func (bd *builder) hold(path string, kind entryKind, access accessFS) (int, error) {
	if err := bd.tick(); err != nil {
		return -1, err
	}
	// A later stage applies rights to the object held earlier, rather than opening
	// the same mutable name again. Preserve add's sealed-node union rule.
	if idx, ok := bd.fds.paths[path]; ok {
		if err := bd.fds.owns(idx); err != nil {
			return -1, err
		}
		e := &bd.fds.open[idx]
		if !e.Kind.sealed() || kind == kindPlaneKey {
			var st unix.Stat_t
			if err := unix.Fstat(e.FD, &st); err != nil {
				return -1, err
			}
			e.Access |= bd.fitAccess(access, &st)
		}
		return idx, nil
	}
	fd, st, name, err := openNamed(path, bd.fds, nil)
	if err != nil {
		return -1, err
	}
	return bd.keep(fd, &st, path, name, kind, access), nil
}

// openNamed opens path (following symlinks) against s's budget, nil for an open the plan does not keep, and reads
// the name the opened object has from the descriptor itself: the name a held path is known by (heldNames). The name
// is captured before identity dedupe closes a second alias's descriptor: the surviving fd may have been opened
// through a different hardlink or mount.
//
// want, when not nil, is asked with that name whether the plan keeps the descriptor. One it does not keep, like one
// whose name cannot be read or whose want fails, is closed here, the one close of an open the plan never took
// (ADR 0023 A9), and answered as -1 with the name and want's error.
func openNamed(path string, s *fdSet, want func(name string) (bool, error)) (int, unix.Stat_t, string, error) {
	fd, st, err := openAt(unix.AT_FDCWD, path, true, s)
	if err != nil {
		return -1, st, "", err
	}
	keep := true
	name, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	switch {
	case err != nil || !filepath.IsAbs(name) || strings.HasSuffix(name, " (deleted)"):
		err = fmt.Errorf("%w: cannot establish held path %q (%q): %v", ErrRulesetBuild, path, name, err)
	case want != nil:
		keep, err = want(name)
	}
	if err != nil || !keep {
		_ = unix.Close(fd)
		return -1, st, name, err
	}
	return fd, st, name, nil
}

// keep takes ownership of fd, opened at path on an object named name, as hold's entry of kind with access.
func (bd *builder) keep(fd int, st *unix.Stat_t, path, name string, kind entryKind, access accessFS) int {
	if bd.heldNames == nil {
		bd.heldNames = map[string]string{}
	}
	bd.heldNames[path] = name
	return bd.fds.add(fd, path, kind, bd.fitAccess(access, st), st)
}

// holdGrant is hold for a declared grant that is built after denyRead: R5's exec grants and R21's
// RESOLVE_UNIX backstop (ABI ≥ 9 only; below it unixEntry holds nothing). add never unions onto a
// sealed entry (I11), and such a grant lost quietly would surface only as an EACCES at execve or
// connect, behind a compile --test row that says allow. A declared grant whose inode is a deny node,
// by its own name or another (a hardlink, a bind mount), therefore fails the build naming both (E32,
// §7). The two arms fail for different reasons, and the message says which. An exec grant carries
// READ_FILE, so granting it would read what deny_read denies. RESOLVE_UNIX carries no read right. The
// seal refuses it anyway, because the seal is kept by kind, not by right. So the backstop would be
// dropped and Landlock would refuse the connect that net.allow declares. A grant at a path *beneath* a
// target is a different inode and is unaffected: the contract named that file itself.
func (bd *builder) holdGrant(path string, kind entryKind, access accessFS) error {
	idx, err := bd.hold(path, kind, access)
	if err != nil {
		return err
	}
	e := bd.fds.open[idx]
	if !e.Kind.sealed() {
		return nil
	}
	why := "tier 1 cannot grant it without granting what deny_read denies (exec needs READ_FILE)"
	if kind == kindUnixSocket {
		why = "RESOLVE_UNIX would not read it, but no right unions onto a sealed entry, so the ABI ≥ 9 backstop would be dropped and Landlock would refuse the connect net.allow declares"
	}
	return fmt.Errorf("%w: %s %q is the same inode as the %s entry %q, whose rights stay sealed: %s",
		ErrRulesetBuild, kindName(kind), path, kindName(e.Kind), e.Path, why)
}

// tick checks ctx.Err() every ctxCheckEvery entries (individual openat calls are not cancellable).
func (bd *builder) tick() error {
	bd.opened++
	if bd.opened%ctxCheckEvery == 0 {
		if err := bd.ctx.Err(); err != nil {
			return fmt.Errorf("landlock: prepare cancelled after %d entries: %w", bd.opened, err)
		}
	}
	return nil
}

// fitAccess masks the requested rights against the ABI (R2) and, for a non-directory, against the
// rights valid on a file (R3: a directory right on a file is EINVAL).
func (bd *builder) fitAccess(a accessFS, st *unix.Stat_t) accessFS {
	a = bd.profile.mask(a)
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		a &= fileRights
	}
	return a
}

// readSet is the tier read set a sibling directory gets (R3); EXECUTE joins only while the contract
// leaves exec unrestricted, because EXECUTE on a directory grants every binary beneath it and would
// otherwise defeat exec.allow (CAPABILITIES.md "deny exec by inode").
func (bd *builder) readSet() accessFS {
	if bd.execUnrestricted {
		return readSet | accessExecute
	}
	return readSet
}

// ancestorAccess is what an enumerated ancestor gets: listing and stat, never contents (R3). Not to
// be confused with ancestorSet in enumerate.go, which computes *which* directories are ancestors;
// this only says what rights the ones enumerate finds receive.
func (bd *builder) ancestorAccess() accessFS {
	if bd.execUnrestricted {
		return accessReadDir | accessExecute
	}
	return accessReadDir
}
