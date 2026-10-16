// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Adoption (ADR 0055; ADR 0054's stage 2): an agent that was already running when
// Tego met it, started from any terminal or IDE, is governed from the kernel. A running process cannot be given a
// seccomp filter, Landlock or another environment, so this is root's and the kernel's alone: Adopt moves the agent's
// own process tree, and nothing else, into a fresh cgroup of a run (adopt-<run id>.scope), prepares tier 2 for it,
// arms it, and from then on the trace programs, which are host-wide and filter on the run set by the current task's
// cgroup, record its execs, opens and connects into the run's ledger. A boundary contract adds the decision plane's
// rules where it decides them for every task in the cgroup (fs reads and writes, execs); nothing else of a contract
// can be added to a running process, and the caller refuses it beforehand.
//
// It is a normal run: the same ledger (run_start, the record, run_end), the same lock, the same live index, so
// `tego status|events|drift <run>` read it. It differs from `tego run` in what it never does: it starts no agent,
// waits on no child, and never kills: the agent is the operator's own process. When the agent's tree ends the run ends
// (reason exit); when the adopter is asked to stop (SIGINT, SIGTERM) or the run is asked to release (a release request:
// `tego adopt --release`, `tego stop <run>`, which end this adoption alone, whatever else its adopter holds) it
// releases the agent, its whole tree moved back to the cgroup it came from, and the run ends (reason stopped); when
// the adopter dies, its reaper (`tego __adopt-reap`) releases it and ends the run (reason orphaned). Nothing is left
// attached in any of them.
//
// What it cannot see is said in the ledger, never left silent: everything the agent did before the attach (gap
// adoption-pre-attach, its processes' exec ids carrying their start times), a descendant it did not move (gap
// adoption-not-moved), the sockets the agent held when adopted (gap adoption-open-sockets), and, for a boundary, the
// files it held open or mapped across a rule, whose reads and writes nothing records or decides (gap what=enforce
// adoption-open-descriptors).

// AdoptionBy is the `by` of the exec line an adoption writes for each process it moved: the process was already
// running, its exec was not seen, and from this line on its actions are the run's.
const AdoptionBy = "adoption"

// Gap reasons an adoption records (record.GapPayload.Why).
const (
	// GapAdoptionPreAttach: what each adopted process did before the run's attach (its start time is in its exec id,
	// the attach is this line's time) is not in the record. Count is the processes adopted, Binary the agent's.
	GapAdoptionPreAttach = "adoption-pre-attach"
	// GapAdoptionNotMoved: processes of the agent's tree that were not moved (in another cgroup, exited, or a pid
	// that named another process by the time of the move): nothing of theirs is recorded.
	GapAdoptionNotMoved = "adoption-not-moved"
	// GapAdoptionOpenSockets: sockets the adopted processes held when adopted. Their connections predate the record,
	// and a socket keeps the cgroup it was made in, so no network rule of the run would govern it.
	GapAdoptionOpenSockets = "adoption-open-sockets"
	// GapAdoptionOpenFiles (what=enforce): files a boundary adoption's processes held across a rule, decided by the
	// plane's own rows (adoption.heldRules): open, or mapped at all, where the plane refuses a read (any deny_read
	// entry, a name entry included); open for writing, or mapped shared and writable or may-write, where it refuses a
	// write (outside every write entry, or a deny_write target beneath one). Reads and writes through a descriptor, and
	// loads and stores through a mapping, are not decided.
	GapAdoptionOpenFiles = "adoption-open-descriptors"
	// GapAdoptionUnread (what=enforce for a boundary, record otherwise): moved processes whose descriptors or mappings
	// could not all be read (more than 4096 of either, or a listing that failed, a thread's table included, or a
	// descriptor /proc cannot name or whose flags it cannot give, or an io_uring instance whose registered files cannot
	// be listed; for a boundary also a file no name of tego's namespace names, and a process
	// in another mount namespace: heldFiles.unread): what they held past that is in neither count above.
	GapAdoptionUnread = "adoption-descriptors-unread"
	// GapAdoptionLeft: processes a release could not move out of the run's cgroup; they stay there, released.
	GapAdoptionLeft = "adoption-left-in-scope"
	// GapAdoptionNoFilter (what=enforce, a boundary adoption's, once after run_start): what only tier 1's seccomp
	// filter refuses is not held on a process that was already running, whatever the contract says: System V IPC
	// (refused unless the contract sets ipc: true), the socket families outside the network rules (AF_VSOCK, AF_PACKET,
	// AF_TIPC, SCTP and the rest of the family allowlist), io_uring, openat2, open_by_handle_at, clone3, the
	// terminal-input ioctls, and the namespace arm: new mount and user namespaces and setns, which tier 1 refuses so
	// that its rules hold on one mount tree. The plane has no mount or namespace hook, and its walk follows the
	// process's own mount tree, so an agent that can mount (root, or one that can make a user namespace) can put a
	// file where the contract's paths do not reach it (a directory outside every write entry bound beneath one is
	// written; an overlay whose lower layer is a deny_read directory is read: TestPlaneRunWalksTheMountTreeAsItStands):
	// the file rules hold on the mount topology as it stands. The
	// plane holds the keyring, the file rules on that topology and exec.allow's programs; nothing else.
	GapAdoptionNoFilter = "adoption-no-syscall-filter"
)

// AdoptSpec is the process an adoption takes over.
type AdoptSpec struct {
	// Root is the agent's process, identified (adopt.Identify) and checked (adopt.Check) by the caller.
	Root adopt.Process
	// Recheck applies the caller's rules again (adopt.Check, and its owner filter) to Root as read again right before
	// the move, under the host-wide move lock: a process that exec'd, changed its user or namespaces, or was taken by
	// another adoption since it was identified is refused then, and nothing moves. Required.
	Recheck func(adopt.Process) error
	// Extra are identities of the agent's descendants the caller followed by fork events, so that one reparented away
	// from the root (its parent exited) still moves. No caller passes any yet (neither tego adopt nor the guard): such
	// a process is not moved and not counted (ADR 0055, "The scope guard").
	Extra []adopt.Identity
	// Env is the /proc and cgroup filesystem the move reads and writes; the zero value is the system's.
	Env adopt.Env
	// Boundary says the table is the operator's boundary contract, held by the decision plane, rather than the
	// record-only table of an adoption with none.
	Boundary bool
	// Keyed are the files a boundary's rows must be written at, at the identities the caller checked them at: the
	// agent owner's own ~/.tego, which R6a's deny attaches to (ADR 0055 Decision 5). The agent runs unconfined until
	// the arm, and Prepare keys a row at whatever its path names then (a path gone keys nothing), so after Prepare,
	// before the attach, each must be one of the files the plane's fs rows were written at
	// (enforce.PlaneKeyedReporter) with that device and inode, or the adoption fails, named (ErrAdoptUnkeyed). A row
	// keys an inode, so from the fill on a rename of the file moves the deny with it, and
	// the path could name another file or none at the arm: after the arm, from which the plane refuses the agent a
	// rename or removal of it, the path must still lead to that device and inode too (checkKeyedPaths).
	Keyed []AdoptKeyed
	// Started is told once the tree has moved and the run records it; nil tells no one.
	Started func(AdoptStarted)
	// ExitStatus, asked once the adopted tree has ended, is the root process's exit status as something that saw
	// it end reported it (the proc connector); ok false when nothing did. Tego is not the agent's parent and cannot
	// wait for it.
	ExitStatus func() (code, signal int, ok bool)
}

// AdoptStarted is what an adoption reports once it records.
type AdoptStarted struct {
	RunID, Dir string
	// Scope is the adoption's cgroup (absolute); From the cgroup the agent was found in (relative to the mount).
	Scope, From string
	Moved       []adopt.Process
	Skipped     []adopt.Skip
	// Window is from the root's identification to the attach: the least of what the record misses.
	Window time.Duration
	// DecisionPlane is the plane's mode a boundary adoption decides in, "" for a record-only one.
	DecisionPlane string
}

// AdoptCgroups is what an adoption needs of the cgroup manager: a run's, and a scope under its own name.
type AdoptCgroups interface {
	cgroup.Manager
	CreateScope(agent, runID, scope string) (cgroup.Cgroup, error)
}

// NoAdoptReaper as AdoptDeps.ReaperExe starts no reaper: a test binary is never tego.
const NoAdoptReaper = "-"

// AdoptDeps are the injected components of one adoption.
type AdoptDeps struct {
	Config  *config.Machine
	Enforce enforce.Backend
	// ObserveFactory builds the kernel recorder once the handle names its build, as Deps.ObserveFactory.
	ObserveFactory func(bpfHash string) (source.Source, error)
	Build          Build
	ContractYAML   []byte
	AnchorPath     string
	Logger         *slog.Logger
	Clock          Clock
	Rand           io.Reader
	MachineID      []byte
	// Cgroups makes and removes the adoption's scope; nil is cgroup.Detect's.
	Cgroups AdoptCgroups
	// StateDir holds the adoption records; "" is AdoptStateDir.
	StateDir string
	// ReaperExe is the binary the reaper runs; "" is /proc/self/exe, NoAdoptReaper none.
	ReaperExe string
	// Identified is when the caller identified Root, for AdoptStarted.Window; zero is when Adopt began.
	Identified time.Time
	// ContractSource is the boundary contract's file, as Deps.ContractSource; nil with no boundary.
	ContractSource *record.ContractSource
}

// ErrAdoptDeps is an incomplete or inconsistent AdoptSpec or AdoptDeps: a caller bug, before anything exists.
var ErrAdoptDeps = errors.New("runtime: invalid adoption")

// ErrAdoptLeftInScope is a failure before run_start whose release left processes of the agent in the adoption's
// scope: neither the cgroup they came from nor any above it took them. The scope and the record stay, the record
// marked released, so `tego adopt --release --pid` (or the reaper) can move them out later.
var ErrAdoptLeftInScope = errors.New("runtime: processes of the agent stay in the adoption's cgroup, released")

// ErrAdoptNoPlane is a boundary adoption whose tier decides its contract with no decision plane: without one, nothing
// holds a write rule on a process that was not started under Landlock.
var ErrAdoptNoPlane = errors.New("runtime: no decision plane decides this contract for an adopted process")

// ErrAdoptUnkeyed is a boundary adoption whose plane holds no row at a file its caller requires one at (AdoptSpec.Keyed):
// the file was removed or replaced between the caller's check and Prepare, and its deny would hold nothing; or whose
// path, once armed, no longer leads to the file the row keys (removed or replaced between Prepare and the arm), so the
// records written there next would be under no row.
var ErrAdoptUnkeyed = errors.New("runtime: the decision plane keys no row at a file the boundary requires")

// AdoptKeyed is a file a boundary adoption requires the plane to key a row at (AdoptSpec.Keyed): Path as the table
// names it (resolved), Name the path the owner's runs reach it by (~/.tego as spelled; "" is Path), ID the device and
// inode the caller found it at, What what it is, for the refusal.
type AdoptKeyed struct {
	Path string
	Name string
	ID   adopt.FileID
	What string
}

// adoption is one Adopt. It rides on a runner for the ledger, the lock, the queue and the pipeline, whose methods it
// shares with `tego run`; everything about a child, a supervisor, a budget and a kill is its own or absent.
type adoption struct {
	r     *runner
	spec  AdoptSpec
	deps  AdoptDeps
	env   adopt.Env
	store *adoptStore
	lock  *os.File
	rec   adoptRecord
	cgm   AdoptCgroups
	moved adopt.MoveResult
	// identified is when the root was identified, armed when the run's row went in.
	identified, armed time.Time
	planeMode         string
	// release is set once the adoption has released its tree, with what it did; releasedBy is who asked for it
	// through a release request (ReleaseAdoption), "" when the adopter was asked to stop.
	release    *adopt.ReleaseResult
	releasedBy string
	// reason is ReasonExit once the agent's tree has ended by itself; an error that ended the run is the runner's
	// terminal reason (runner.fail), and a release with neither is reason stopped. left says the run's cgroup emptied
	// while the agent still ran: its processes were moved out by someone other than tego (root, by hand).
	reason identity.EndReason
	left   bool
}

// Adopt adopts spec.Root into a run of rt and blocks until the run ends: the agent's tree ended, or the adopter was
// asked to stop (ctx) or the run to release (a release request, ReleaseAdoption), in which case it releases the agent
// first. A non-nil error is returned only for a failure before run_start, after which nothing of the run is left and
// what moved went back; when a process of it could not go back (no cgroup took it), the error also matches
// ErrAdoptLeftInScope and says where it stays, with the adoption's record kept, marked released, for a later release.
// Everything after run_start is Result.Reason and a run_end line.
func Adopt(ctx context.Context, rt *agent.RuleTable, spec AdoptSpec, deps AdoptDeps) (Result, error) {
	a, err := newAdoption(rt, spec, deps)
	if err != nil {
		return Result{ExitCode: identity.ExitLauncher, Reason: record.RunEndError}, err
	}
	return a.run(ctx)
}

func newAdoption(rt *agent.RuleTable, spec AdoptSpec, deps AdoptDeps) (*adoption, error) {
	switch {
	case rt == nil || rt.Contract == nil:
		return nil, fmt.Errorf("%w: no rule table", ErrAdoptDeps)
	case deps.Config == nil:
		return nil, fmt.Errorf("%w: no machine config", ErrAdoptDeps)
	case deps.Enforce == nil || deps.Enforce.Tier() != backend.TierCgroup:
		return nil, fmt.Errorf("%w: an adoption runs at tier cgroup", ErrAdoptDeps)
	case spec.Root.PID <= 1 || spec.Root.Start == 0 || spec.Root.Cgroup == "":
		return nil, fmt.Errorf("%w: the process to adopt is not identified", ErrAdoptDeps)
	case spec.Recheck == nil:
		return nil, fmt.Errorf("%w: no rules to recheck the process with before the move", ErrAdoptDeps)
	}
	if err := refuseAdjustable(rt, true); err != nil {
		return nil, err
	}
	agentID, err := identity.ParseAgentID(rt.Contract.Name)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrAdoptDeps, err)
	}
	log := deps.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if deps.Clock == nil {
		deps.Clock = systemClock{}
	}
	grace := deps.Config.StopGrace.Value
	if grace <= 0 {
		grace = config.DefaultStopGrace
	}
	env := spec.Env
	if env.Proc == nil {
		env.Proc = adopt.NewFS("")
	}
	if env.FS == nil {
		env.FS = adopt.Cgroups{}
	}
	if env.Live == nil {
		env.Live = adopt.Pidfds{}
	}
	r := &runner{
		rt: rt.AtTier(deps.Enforce.Tier()), log: log, agentID: agentID, stopGrace: grace,
		started: make(chan struct{}),
		deps: Deps{Config: deps.Config, Enforce: deps.Enforce, ObserveFactory: deps.ObserveFactory, Build: deps.Build,
			ContractYAML: deps.ContractYAML, AnchorPath: deps.AnchorPath, Logger: log, Clock: deps.Clock, Rand: deps.Rand,
			MachineID: deps.MachineID, ContractSource: deps.ContractSource},
	}
	if r.deps.Rand == nil {
		r.deps.Rand = rand.Reader
	}
	identified := deps.Identified
	if identified.IsZero() {
		identified = time.Now()
	}
	return &adoption{r: r, spec: spec, deps: deps, env: env, identified: identified}, nil
}

// run is prepare (everything before run_start, contain first), run_start and the adoption's own lines, the wait,
// and the shutdown.
func (a *adoption) run(ctx context.Context) (Result, error) {
	r := a.r
	group, gctx := newGroup(ctx)
	r.group = group
	if err := a.prepare(gctx); err != nil {
		return Result{RunID: string(r.id), ExitCode: identity.ExitLauncher, Reason: record.RunEndError}, a.unwind(ctx, err)
	}
	if err := a.writeRunStart(); err != nil {
		return Result{RunID: string(r.id), ExitCode: identity.ExitLauncher, Reason: record.RunEndError}, a.unwind(ctx, err)
	}
	close(r.started) // the pipeline writes from here on: run_start is on disk
	a.emitAdoptionLines()
	if a.spec.Started != nil {
		a.spec.Started(a.startedInfo())
	}
	a.await(gctx)
	return a.shutdown(ctx), nil
}

// prepare is the adoption's steps before run_start, each recorded on the adoption so unwind releases exactly what was
// taken: the run directory and its lock, the lock on the process, the scope, the record root's tools act on, the
// reaper, the move (contain first: from here on every process the agent forks is born in the scope), then tier 2's
// Prepare, Attach and Arm (recording starts at the arm), and the pipeline and the kernel recorder.
func (a *adoption) prepare(ctx context.Context) error {
	r := a.r
	if err := r.mintRun(); err != nil {
		return err
	}
	if err := r.openLedger(); err != nil {
		return err
	}
	store, err := openAdoptStore(a.deps.StateDir)
	if err != nil {
		return err
	}
	a.store = store
	if a.lock, err = store.claim(a.spec.Root.Identity); err != nil {
		return err
	}
	if err := a.createScope(); err != nil {
		return err
	}
	if a.env.Mount == "" {
		mount, _ := splitCgroupPath(r.cg.Path)
		if mount == "" {
			mount = identity.SystemCgroupRoot
		}
		a.env.Mount = mount
	}
	mount := a.env.Mount
	self := adopt.Identity{PID: os.Getpid(), Start: r.launcherStart / proc.NanosPerTick}
	a.rec = adoptRecord{Run: string(r.id), Agent: string(r.agentID), Dir: r.dir, Anchor: r.anchorFile(), Mount: mount,
		Scope: r.cg.Path, ScopeID: r.cg.ID, From: a.spec.Root.Cgroup, Root: a.spec.Root.Identity, Adopter: self}
	if err := store.write(a.rec); err != nil {
		return err
	}
	if err := a.startReaper(); err != nil {
		return err
	}
	if err := a.move(ctx); err != nil {
		return err
	}
	if err := a.prepareEnforcement(ctx); err != nil {
		return err
	}
	return a.startWorkers(ctx)
}

// move rechecks the root and moves its tree, under the host-wide move lock (adoptStore.lockMoves): the root is read
// again, and refused unless it is the process identified (its start time) and the caller's rules still admit it;
// then adopt.Move, which rechecks each member's start time and cgroup before its own write.
func (a *adoption) move(ctx context.Context) error {
	lock, err := a.store.lockMoves(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	pid := a.spec.Root.PID
	t, err := adopt.Identify(a.env.Proc, pid)
	switch {
	case err != nil:
		return fmt.Errorf("runtime: adopt pid %d: %w", pid, err)
	case t.Start != a.spec.Root.Start:
		return fmt.Errorf("runtime: adopt pid %d: %w", pid, adopt.ErrIdentityChanged)
	}
	if err := a.spec.Recheck(t); err != nil {
		return fmt.Errorf("runtime: adopt pid %d, rechecked before the move: %w", pid, err)
	}
	moved, err := adopt.Move(a.env, a.r.cg.Path, a.spec.Root, a.spec.Extra)
	a.moved = moved
	if err != nil {
		return fmt.Errorf("runtime: adopt pid %d: %w", pid, err)
	}
	return nil
}

// createScope makes tego.slice/tego-<agent>.slice/adopt-<run id>.scope under the cgroup2 mount root.
func (a *adoption) createScope() error {
	r := a.r
	cgm := a.deps.Cgroups
	if cgm == nil {
		fs, err := cgroup.Detect(0)
		if err != nil {
			return fmt.Errorf("runtime: cgroup: %w", err)
		}
		cgm = fs
	}
	cg, err := cgm.CreateScope(string(r.agentID), string(r.id), adopt.ScopeName(string(r.id)))
	if err != nil {
		return fmt.Errorf("runtime: create the adoption's cgroup: %w", err)
	}
	a.cgm, r.cgm, r.cg = cgm, cgm, cg
	return nil
}

// prepareEnforcement prepares tier 2 for the scope and arms it. A boundary adoption is refused here, before the arm,
// when no plane mode decides it: the fanotify fallback cannot refuse a write, and no Landlock domain holds one on a
// process tego did not start; the listener's marks would be placed only by Arm, so nothing is marked.
func (a *adoption) prepareEnforcement(ctx context.Context) error {
	r := a.r
	mount, rel := splitCgroupPath(r.cg.Path)
	ref := enforce.RunRef{
		ID: string(r.id), Agent: string(r.agentID), CgroupID: r.cg.ID, RunDir: r.dir,
		Contract: filepath.Join(r.dir, ledger.ContractFile), CgroupMount: mount, CgroupPath: rel,
		Events: r.runQueue().Lane(LaneListener), Log: r.log,
	}
	if a.spec.Boundary {
		// A write directory the composed tier-1 plan creates is the agent's to write: made as its owner.
		ref.Drop, ref.DropUID, ref.DropGID = true, a.spec.Root.UID[1], a.spec.Root.GID[1]
	}
	h, err := r.deps.Enforce.Prepare(ctx, r.rt, ref)
	if err != nil {
		return fmt.Errorf("runtime: prepare %s: %w", r.deps.Enforce.Tier(), err)
	}
	r.handle = h
	if l, ok := h.(api.Listener); ok {
		r.group.Go("enforce-listener", func() error { return l.RunListener(ctx) })
	}
	r.deps.Build.BPFHash = ""
	if kr, ok := h.(enforce.KernelRecorder); ok {
		r.deps.Build.BPFHash = kr.BPFHash()
	}
	if dp, ok := h.(enforce.DecisionPlaneReporter); ok {
		a.planeMode, _ = dp.DecisionPlane()
	}
	if a.spec.Boundary && a.planeMode == "" {
		return fmt.Errorf("%w: the plane runs in no mode here or cannot hold this contract (tego doctor says which); "+
			"adopt with no --boundary to record it", ErrAdoptNoPlane)
	}
	if err := a.checkKeyed(h); err != nil {
		return err
	}
	if t, ok := h.(reaped); ok {
		target := t.ReapTarget()
		a.rec.Target = &target
		if err := a.store.write(a.rec); err != nil {
			return err
		}
	}
	if err := h.Attach(r.cg.ID); err != nil {
		return fmt.Errorf("runtime: attach %s: %w", r.deps.Enforce.Tier(), err)
	}
	if armer, ok := h.(api.Armer); ok {
		if err := armer.Arm(); err != nil {
			return fmt.Errorf("runtime: arm %s: %w", r.deps.Enforce.Tier(), err)
		}
	}
	a.armed = time.Now()
	return a.checkKeyedPaths()
}

// checkKeyed is AdoptSpec.Keyed's check, after Prepare and before the attach: each required file is one the plane's fs
// rows were written at, with the device and inode the caller found it at. A handle that cannot say which files its
// rows key fails it: the deny cannot be shown to hold.
func (a *adoption) checkKeyed(h api.Handle) error {
	if len(a.spec.Keyed) == 0 {
		return nil
	}
	var keyed []enforce.PlaneKeyed
	ok := false
	if kr, is := h.(enforce.PlaneKeyedReporter); is {
		keyed, ok = kr.PlaneKeyed()
	}
	for _, want := range a.spec.Keyed {
		if !ok {
			return fmt.Errorf("%w: %s (%s): the tier cannot say which files its rows key", ErrAdoptUnkeyed, want.What, want.Path)
		}
		i := slices.IndexFunc(keyed, func(k enforce.PlaneKeyed) bool { return k.Path == want.Path })
		if i < 0 {
			return fmt.Errorf("%w: %s, %s, is gone since the boundary was compiled, so its deny holds nothing; adopt again",
				ErrAdoptUnkeyed, want.What, want.Path)
		}
		k := keyed[i]
		if got := (adopt.FileID{Dev: unix.Mkdev(unix.Major(k.Dev), unix.Minor(k.Dev)), Ino: k.Ino}); got != (adopt.FileID{
			Dev: unix.Mkdev(unix.Major(want.ID.Dev), unix.Minor(want.ID.Dev)), Ino: want.ID.Ino}) {
			return fmt.Errorf("%w: %s, %s, was replaced since the boundary was compiled (the row is at %d:%d, the table "+
				"was compiled against %d:%d), so its deny would hold another file; adopt again", ErrAdoptUnkeyed, want.What,
				want.Path, k.Dev, k.Ino, want.ID.Dev, want.ID.Ino)
		}
	}
	return nil
}

// checkKeyedPaths is AdoptSpec.Keyed's second check, after the arm: each required file's name (AdoptKeyed.Name) is
// still, itself and not through a link at it, the directory its row keys, at that device and inode. checkKeyed holds
// the row to the directory the table was compiled against, but the agent runs unconfined until the arm, so between
// the fill and the arm it can rename that directory away, with or without a new one at its name: the row follows the
// old inode, and the owner's next run would write its records into a directory no row keys. It can also put a link
// to the keyed directory at the name: followed,
// the name leads to the row's inode, but the link is under no row, and under a write entry over the home the plane
// lets the agent unlink it and make a directory there once armed, so a name that is no directory itself fails the
// check. From the arm on the plane refuses the agent a rename,
// removal or replacement of the keyed directory, so what this check sees holds for the rest of the adoption.
func (a *adoption) checkKeyedPaths() error {
	for _, want := range a.spec.Keyed {
		name := want.Name
		if name == "" {
			name = want.Path
		}
		var st unix.Stat_t
		if err := unix.Lstat(name, &st); err != nil {
			return fmt.Errorf("%w: %s, %s, was removed after the plane keyed it and before the arm (%v), so its deny "+
				"holds a directory no longer at that path; adopt again", ErrAdoptUnkeyed, want.What, name, err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR {
			return fmt.Errorf("%w: %s, %s, is no directory itself once armed (a link or a file is at the name), so the "+
				"agent could put a directory no row keys there; make it a directory and adopt again", ErrAdoptUnkeyed,
				want.What, name)
		}
		dev := uint64(st.Dev) //nolint:unconvert // Dev is uint64 on amd64 and arm64, not everywhere
		got := adopt.FileID{Dev: unix.Mkdev(unix.Major(dev), unix.Minor(dev)), Ino: st.Ino}
		if got != (adopt.FileID{Dev: unix.Mkdev(unix.Major(want.ID.Dev), unix.Minor(want.ID.Dev)), Ino: want.ID.Ino}) {
			return fmt.Errorf("%w: %s, %s, was replaced after the plane keyed it and before the arm (the path leads to "+
				"%d:%d, the row is at %d:%d), so its deny holds a directory no longer at that path; adopt again",
				ErrAdoptUnkeyed, want.What, name, got.Dev, got.Ino, want.ID.Dev, want.ID.Ino)
		}
	}
	return nil
}

// startWorkers starts the pipeline and the tier's kernel recorder, which reads the run's ring from its row: the
// arm has inserted it. The recorder is told it is the only producer of exec lines (no supervisor exists) and names
// the plane's mode; a recorder that fails to start is a gap, as at `tego run`, and the run goes on.
func (a *adoption) startWorkers(ctx context.Context) error {
	r := a.r
	q := r.runQueue()
	r.pipe = newPipeline(q, ledger.Sink(r.writer.Append), r.writer.RedactStage, r.writer.SplitBlobsStage,
		runStamp{PID: os.Getpid(), TID: syscall.Gettid(), Cgroup: r.cg.ID}, nil, nil, r.log)
	r.pipe.onLedgerFail = a.ledgerFailed
	r.runPipeline(ctx)
	kr, ok := r.handle.(enforce.KernelRecorder)
	if !ok {
		return nil
	}
	var src source.Source
	var err error
	if r.deps.ObserveFactory != nil {
		src, err = r.deps.ObserveFactory(kr.BPFHash())
	}
	if err != nil || src == nil {
		if err != nil {
			r.log.Warn("adopt: kernel record unavailable", "err", err)
		}
		r.deps.CaptureGaps = append(r.deps.CaptureGaps, source.Gap{What: record.GapRecord, Why: GapKernelRecordUnavailable, Count: 1})
		return nil
	}
	if n, ok := src.(interface{ SetSupervisorExecs(bool) }); ok {
		n.SetSupervisorExecs(false)
	}
	if n, ok := src.(DecisionPlaneNamer); ok {
		n.SetDecisionPlane(a.planeMode)
	}
	if t, ok := src.(TrackingFailureReporter); ok {
		t.SetTrackingFailure(func(err error) { r.trackingFailed.Store(true) })
	}
	if err := src.Start(ctx, r.ref(), q.Lane(LaneKernel)); err != nil {
		return fmt.Errorf("runtime: start source %s: %w", src.Name(), err)
	}
	r.kernelRecord = src
	r.sources = append(r.sources, src)
	return nil
}

// ledgerFailed is the pipeline's report that the ledger refused a line: the record can no longer say what the agent
// does, so the adoption ends, releasing the agent rather than killing it.
func (a *adoption) ledgerFailed(err error) {
	a.r.log.Error("adopt: the ledger refused a line; releasing the agent", "err", err)
	a.r.fail(identity.ReasonError, "ledger: "+err.Error())
	a.r.group.Cancel()
}

// startedInfo is what Started is told.
func (a *adoption) startedInfo() AdoptStarted {
	return AdoptStarted{RunID: string(a.r.id), Dir: a.r.dir, Scope: a.r.cg.Path, From: a.spec.Root.Cgroup,
		Moved: a.moved.Moved, Skipped: a.moved.Skipped, Window: a.armed.Sub(a.identified), DecisionPlane: a.planeMode}
}

// releasePoll is how often an adoption looks for a release request (ReleaseAdoption).
var releasePoll = 200 * time.Millisecond

// await waits for the run's end. The scope empties when the agent's tree has ended, or when root moved every process
// of it out by hand while the agent runs on (a.left). A release request for this run (`tego adopt --release`,
// `tego stop`: ReleaseAdoption), or ctx's end (the adopter asked to stop, a worker failed), releases the agent.
func (a *adoption) await(ctx context.Context) {
	r := a.r
	wctx, release := context.WithCancel(ctx)
	defer release()
	requested := make(chan string, 1)
	watching := make(chan struct{})
	go func() {
		defer close(watching)
		a.watchRelease(wctx, requested, release)
	}()
	err := r.cgm.WaitEmpty(wctx, r.cg)
	release()
	<-watching
	if err == nil {
		if a.rootRunsOn() {
			a.left = true
		} else {
			a.reason = identity.ReasonExit
		}
		return
	}
	select {
	case a.releasedBy = <-requested:
	default:
	}
	switch gerr := r.group.Err(); {
	case gerr != nil && !errors.Is(gerr, context.Canceled):
		r.fail(identity.ReasonError, gerr.Error())
	case a.releasedBy == "" && ctx.Err() == nil:
		r.fail(identity.ReasonError, "watch the run's cgroup: "+err.Error())
	}
	a.releaseTree()
}

// watchRelease looks for a release request every releasePoll until ctx ends; one found is sent on requested, and
// release ends the wait.
func (a *adoption) watchRelease(ctx context.Context, requested chan<- string, release context.CancelFunc) {
	t := time.NewTicker(releasePoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if by, ok := a.store.releaseRequested(string(a.r.id)); ok {
			requested <- by
			release()
			return
		}
	}
}

// rootRunsOn reports whether the adopted process is still alive, the same process (its start time), once the run's
// cgroup is empty: then it was moved out, not ended.
func (a *adoption) rootRunsOn() bool {
	t, err := adopt.Identify(a.env.Proc, a.spec.Root.PID)
	return err == nil && t.Start == a.spec.Root.Start
}

// releaseTree moves the adopted tree back where it came from (adopt.Release): the scope frozen while its processes
// leave, thawed after.
func (a *adoption) releaseTree() {
	if a.release != nil || a.r.cg.Path == "" {
		return
	}
	res := adopt.Release(a.env, a.r.cg.Path, adopt.ReleaseTargets(a.env.Mount, a.spec.Root.Cgroup))
	a.release = &res
	n := 0
	for _, pids := range res.To {
		n += len(pids)
	}
	a.r.log.Info("adopt: released the agent", "processes", n, "left", len(res.Left))
}

// releaseSummary says where a release sent the tree, for run_end's detail.
func (a *adoption) releaseSummary() string {
	if a.release == nil {
		return ""
	}
	var parts []string
	for to, pids := range a.release.To {
		parts = append(parts, fmt.Sprintf("%d process(es) to %s", len(pids), strings.TrimPrefix(to, a.env.Mount)))
	}
	if len(a.release.Left) > 0 {
		parts = append(parts, fmt.Sprintf("%d left in %s, released", len(a.release.Left), a.r.cg.Path))
	}
	if len(parts) == 0 {
		return "the tree had ended"
	}
	return strings.Join(parts, "; ")
}

// end is the run's reason, detail and exit code, decided once the tree has ended or been released.
func (a *adoption) end() (record.RunEndPayload, int) {
	r := a.r
	r.termMu.Lock()
	decided, detail := r.terminal, r.detail
	r.termMu.Unlock()
	end := record.RunEndPayload{}
	code := identity.ExitOK
	switch {
	case decided != "":
		end.Reason, end.Detail, code = string(decided), detail, identity.ExitError
		if s := a.releaseSummary(); s != "" {
			end.Detail += "; released: " + s
		}
	case a.reason == identity.ReasonExit:
		end.Reason = record.RunEndExit
		if a.spec.ExitStatus != nil {
			if c, sig, ok := a.spec.ExitStatus(); ok {
				end.ExitCode, end.Signal = c, sig
				end.Detail = "the adopted agent's tree ended; its status was read from the kernel's process events"
				break
			}
		}
		end.Detail = "the adopted agent's tree ended; tego is not its parent, so its exit status is unknown"
	case a.left:
		end.Reason = record.RunEndStopped
		end.Detail = "every process of the adopted tree left the run's cgroup without tego (moved by root) while the " +
			"agent ran on; nothing of it is recorded from then on"
	default:
		end.Reason = record.RunEndStopped
		by := ""
		if a.releasedBy != "" {
			by = " at the request of " + a.releasedBy
		}
		end.Detail = "released" + by + ", never killed: " + a.releaseSummary() + "; the agent runs on outside tego, unrecorded"
	}
	end.Detail = record.CutDetail(end.Detail) // run_end must stay a line the ledger takes
	return end, code
}

// shutdown is `tego run`'s §4.1 step 13 for an adoption: workers stopped while the queue is read, the recorder's
// final drain, the source and plane gaps, run_end, then the kernel state, the scope, the record and the locks. The
// tree is released (or gone) before any of it, so nothing here can strand the agent.
func (a *adoption) shutdown(ctx context.Context) Result {
	r := a.r
	a.releaseTree()
	r.group.Cancel()
	r.stopPipeline()
	stopped := r.pumpWhileStopping()
	r.stopSources()
	if err := r.group.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		r.fail(identity.ReasonError, err.Error())
	}
	if w, ok := r.handle.(api.ListenerWaiter); ok {
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), killTimeout)
		_ = w.WaitListener(wctx)
		cancel()
	}
	r.runQueue().stopWaiting()
	stopped()
	if r.pipe != nil {
		r.pipe.drain()
		r.emitSourceGaps()
		r.emitPlaneGaps()
		if r.trackingFailed.Load() {
			r.emitGapNow(source.Gap{What: record.GapRecord, Why: GapCgroupTrackingFailed, Count: 1})
		}
		if a.release != nil && len(a.release.Left) > 0 {
			r.emitGapNow(source.Gap{What: record.GapRecord, Why: GapAdoptionLeft, Count: int64(len(a.release.Left))})
		}
	}
	end, code := a.end()
	end.Resources = r.runResources()
	var recordErr error
	if r.writer != nil {
		if err := r.writer.Close(end); err != nil {
			r.log.Error("adopt: close ledger", "err", err)
			recordErr = err
		}
	}
	a.releaseKernelState(ctx, true)
	if recordErr != nil {
		code = identity.ExitError
	}
	return Result{RunID: string(r.id), ExitCode: code, Reason: end.Reason, RecordErr: recordErr}
}

// releaseKernelState detaches and closes the tier, removes the scope (when it is empty), the record, the process's
// lock, the root launch record and the live index entry. ended says run_end is on disk.
func (a *adoption) releaseKernelState(ctx context.Context, ended bool) {
	r := a.r
	if r.handle != nil {
		if err := r.handle.Detach(); err != nil {
			r.log.Warn("adopt: detach", "err", err)
		}
		if err := r.handle.Close(); err != nil {
			r.log.Warn("adopt: close handle", "err", err)
		}
	}
	removed := false
	left := a.release != nil && len(a.release.Left) > 0
	if r.cgm != nil && r.cg.Path != "" {
		if left {
			_ = r.cg.Close() // processes stay in it, released: the scope stays until they are gone (docs/OPERATIONS.md)
		} else {
			tctx, cancel := teardownCtx(ctx)
			if err := r.cgm.Remove(tctx, r.cg); err != nil {
				r.log.Warn("adopt: remove the adoption's cgroup", "path", r.cg.Path, "err", err)
			} else {
				removed = true
			}
			cancel()
		}
	}
	if a.store != nil {
		switch {
		case left:
			// Processes stay in the kept scope: the record stays too, marked released, so `tego adopt --release --pid`
			// and the reaper can move them out later (releaseOrphan) without asking this adoption, which is over. A
			// release request it answered goes: ReleaseAdoption reads the released record as the answer.
			rec := a.rec
			rec.Released, rec.Left, rec.Unstarted = true, len(a.release.Left), !ended
			if err := a.store.write(rec); err != nil {
				r.log.Warn("adopt: mark the record released; processes stay in the scope", "err", err)
			}
			a.store.clearRequest(string(r.id))
		case removed || ended:
			a.store.remove(string(r.id))
		}
		a.store.unclaim(a.lock, a.spec.Root.Identity)
		a.lock = nil
	}
	if r.rootMarked {
		removeRootMark(string(r.id))
		r.rootMarked = false
	}
	if ended {
		r.clearLive()
	}
}

// unwind is a failure before run_start, cause: whatever moved goes back, the tier and the scope go, and the run
// directory is removed as a run that never started is (case 2). A process no cgroup takes back stays in the scope,
// released, and the scope stays with the record (marked released and unstarted, releaseKernelState); the error
// returned says so (ErrAdoptLeftInScope), so no caller reports a tree that went back.
func (a *adoption) unwind(ctx context.Context, cause error) error {
	r := a.r
	if len(a.moved.Moved) > 0 {
		a.releaseTree()
	}
	if r.group != nil {
		r.group.Cancel()
	}
	r.stopPipeline()
	r.stopSources()
	if r.queue != nil {
		r.queue.stopWaiting()
	}
	if r.group != nil {
		_ = r.group.Wait()
	}
	a.releaseKernelState(ctx, false)
	left := a.release != nil && len(a.release.Left) > 0
	if a.store != nil && r.id != "" && !left {
		a.store.remove(string(r.id))
	}
	r.abandonRun(true)
	if left {
		return fmt.Errorf("%w; %w: %d process(es) stay in %s (neither the cgroup they came from nor any above it takes "+
			"them); `tego adopt --release --pid <pid>` moves them out once one does", cause, ErrAdoptLeftInScope,
			len(a.release.Left), r.cg.Path)
	}
	return cause
}

// emitAdoptionLines writes, right after run_start, what the adoption did: one exec line per process it moved (by
// adoption, its exec id carrying its start time, its parent's when that moved too), the pre-attach gap, the processes
// of the tree it did not move, and the descriptors they held open.
func (a *adoption) emitAdoptionLines() {
	r := a.r
	ids := map[int]string{}
	for _, p := range a.moved.Moved {
		ids[p.PID] = execIDOf(r.id, p)
	}
	sink := r.runQueue().Lane(LaneDefault)
	for _, p := range a.moved.Moved {
		ev := &record.Event{Kind: record.KindExec, Source: record.SourceKernel, PID: p.PID, TID: p.PID, Cgroup: r.cg.ID,
			Rule: UnmatchedRule, Verdict: record.VerdictObserved, Authority: record.AuthorityRule}
		argv := p.Argv
		if len(argv) == 0 {
			argv = []string{p.Exe}
		}
		if err := ev.SetPayload(record.ExecPayload{Path: p.Exe, Argv: argv, ExecID: ids[p.PID], ParentExecID: ids[p.PPID],
			By: AdoptionBy}); err == nil {
			sink.Emit(ev)
		}
	}
	r.emitGap(source.Gap{What: record.GapRecord, Why: GapAdoptionPreAttach, Binary: a.spec.Root.Exe, Count: int64(len(a.moved.Moved))})
	if a.spec.Boundary {
		r.emitGap(source.Gap{What: record.GapEnforce, Why: GapAdoptionNoFilter, Count: 1})
	}
	if n := len(a.moved.Skipped) + len(a.moved.Misplaced) + a.moved.Left; n > 0 {
		r.emitGap(source.Gap{What: record.GapRecord, Why: GapAdoptionNotMoved, Binary: a.spec.Root.Exe, Count: int64(n)})
	}
	for _, g := range r.deps.CaptureGaps {
		r.emitGap(g)
	}
	held := a.openDescriptors()
	if held.sockets > 0 {
		r.emitGap(source.Gap{What: record.GapRecord, Why: GapAdoptionOpenSockets, Count: int64(held.sockets)})
	}
	if held.files > 0 {
		r.emitGap(source.Gap{What: record.GapEnforce, Why: GapAdoptionOpenFiles, Count: int64(held.files)})
	}
	if held.unread > 0 {
		what := record.GapRecord
		if a.spec.Boundary {
			what = record.GapEnforce
		}
		r.emitGap(source.Gap{What: what, Why: GapAdoptionUnread, Count: int64(held.unread)})
	}
}

// execIDOf is a moved process's exec id: the one the kernel recorder gives it from /proc, its pid and start time.
func execIDOf(run identity.RunID, p adopt.Process) string {
	return string(proc.ExecID(run, p.PID, p.Start*proc.NanosPerTick))
}

// heldFiles is what openDescriptors found the moved processes holding.
type heldFiles struct {
	// sockets are the sockets held; files, for a boundary, the files held across a rule (heldRules).
	sockets, files int
	// unread counts the moved processes whose descriptors or mappings could not all be read: a listing past its cap
	// (adopt.ErrTruncated), or one that failed for a process still alive (a thread's table included), one holding a
	// descriptor /proc cannot name or whose flags it cannot give (adopt.FD.Unread), one holding an io_uring instance with a
	// table of registered files (adopt.FD.RegisteredFiles), and, for a boundary, a process in a mount namespace other
	// than tego's (or one whose namespace could not be read), whose files /proc names by paths of tego's namespace
	// that need not be the files the plane's rows name by them, one holding a file whose name is no path of it in
	// tego's namespace (adopt.FD.Unnamed, adopt.Mapping.Unnamed: held through a detached clone or a lazily unmounted
	// mount, whose root the name stops at), and one mapping an io_uring instance it holds no descriptor of. What they
	// hold is not in the two counts.
	unread int
}

// openDescriptors counts, over the moved processes, the sockets they held when adopted and, for a boundary, the files
// held across a rule (heldRules): by a descriptor, or by a mapping (a mapping outlives the descriptor it was made
// from, and loads and stores through it pass no LSM hook), read through any mapping and written through a shared one
// that is writable or may be made so. A file on one of the kernel-internal superblocks tego found on this kernel
// (adopt.FD.NoPath, adopt.Mapping.NoPath: a memfd, a System V segment, the AIO ring, hugetlb or shared anonymous
// memory) is no path a rule names, and the plane decides no open of it (bpf/decide.bpf.c tego_no_path), so it is
// never across a rule: its device says so, never the name /proc gives it nor which mount shows it. Every other file is
// a path the plane decides, whichever mount reaches it, and the rows are asked about it by its name, by every other
// path of tego's namespace that reaches it through another mount of its filesystem (adopt.FD.Aliases), as the
// plane's walk meets each directory above it, and by the path of each fs row keyed at its inode (adopt.FD.ID), as the
// plane decides a keyed inode under every name it has (a hard link), or keyed at a directory its name passes through,
// beneath that row's path (a deny_read directory renamed since the fill): of the files /proc lists, the count can be
// high (a write grant one alias is outside), never low. A file whose name is no path of it in tego's namespace (held
// through a detached clone or a lazily unmounted mount: the name stops at that mount's root; or a pseudo file of an
// internal superblock tego did not probe, a dma-buf: adopt.FD.Unnamed), a descriptor /proc cannot name at all (a
// path past PATH_MAX: adopt.FD.Unread), a listing it could not read whole (every thread's table is read), a process
// in another mount namespace, and an io_uring instance whose registered files cannot be listed, are counted in unread,
// never asked by a name that is not theirs nor taken as all. What /proc lists of no process is not seen at all: a
// descriptor in flight in a unix socket's queue (SCM_RIGHTS sent and not yet received), a ring registered with itself
// and neither held nor mapped (IORING_SETUP_NO_MMAP), a file another kernel object holds (ADR 0055 Decision 3).
func (a *adoption) openDescriptors() heldFiles {
	var out heldFiles
	maps, _ := a.env.Proc.(adopt.MapsReader)
	var held func(string, bool) bool
	dirs := &keyedDirs{}
	if a.spec.Boundary {
		held, dirs.keyed = a.heldRules()
	}
	own, err := a.env.Proc.Namespace(os.Getpid(), "mnt")
	if err != nil {
		own = 0
	}
	for _, p := range a.moved.Moved {
		incomplete := false
		fds, err := a.env.Proc.FDs(p.PID)
		if err != nil && !errors.Is(err, adopt.ErrGone) {
			incomplete = true // ErrTruncated returns what it read; any other failure returns nothing
		}
		// What /proc names of a file is its path as tego's namespace sees it; for a process in another mount
		// namespace that need not be the file the rows name by it, so its files are not counted by name: it is
		// counted unread (a socket is no path, and counts wherever).
		foreign := a.spec.Boundary && (own == 0 || p.MntNS == 0 || p.MntNS != own)
		rings := map[adopt.FileID]bool{} // the io_uring instances it holds a descriptor of
		for _, fd := range fds {
			switch {
			case fd.Unread:
				// /proc cannot say what it holds (a path past PATH_MAX) or how it was opened: a file across a rule, or a
				// socket, for all tego can tell.
				incomplete = true
			case fd.Socket():
				out.sockets++
			case fd.Ring:
				if fd.ID != (adopt.FileID{}) {
					rings[fd.ID] = true
				}
				// A registered file, a socket included, is read and written through the ring with no descriptor or
				// mapping /proc lists: what the process holds is not all read.
				incomplete = incomplete || fd.RegisteredFiles
			case foreign || !fd.File() || !a.spec.Boundary || fd.NoPath:
			case fd.Unnamed:
				incomplete = true // its name is no path of tego's namespace: no rule can be asked about it
			case heldFile(held, dirs, strings.TrimSuffix(fd.Target, " (deleted)"), fd.Aliases, idsOf(fd.ID), fd.Writes()):
				out.files++
			}
		}
		if foreign {
			out.unread++
			continue
		}
		if a.spec.Boundary {
			if maps == nil {
				incomplete = true
			} else {
				ms, err := maps.Maps(p.PID)
				if err != nil && !errors.Is(err, adopt.ErrGone) {
					incomplete = true
				}
				for _, m := range ms {
					switch {
					case m.Ring:
						// A ring mapped with no descriptor of it left (registered with itself, IORING_REGISTER_RING_FDS,
						// and closed) is still in use, and its registered files cannot be read.
						if len(m.IDs) != 1 || !rings[m.IDs[0]] {
							incomplete = true
						}
					case m.NoPath:
					case m.Unnamed:
						incomplete = true
					case heldFile(held, dirs, m.Path, m.Aliases, m.IDs, m.SharedWritable):
						out.files++
					}
				}
			}
		}
		if incomplete {
			out.unread++
		}
	}
	return out
}

// heldByAny is held asked of a file by its name and by each other path that reaches it (adopt.FD.Aliases): across a
// rule when the boundary would refuse the open by any of them, as the plane's walk meets every directory they name.
func heldByAny(held func(string, bool) bool, path string, aliases []string, writes bool) bool {
	if held(path, writes) {
		return true
	}
	for _, a := range aliases {
		if held(a, writes) {
			return true
		}
	}
	return false
}

// heldFile is heldByAny, and held asked by the path of each fs row the plane keyed at one of the file's inodes (ids;
// dirs.keyed, heldRules): the plane looks the object's own inode up first (bpf/decide.bpf.c tego_walk_step), so a
// keyed file's row decides it under every name it has, a hard link no rule names included. The walk then looks each
// directory above it up by its inode too, so for each directory the
// name passes through that a row is keyed at (dirs.at: a deny_read directory renamed after the fill, while the agent
// ran unconfined until the arm), held is also asked by the file's path beneath that row's path.
func heldFile(held func(string, bool) bool, dirs *keyedDirs, path string, aliases []string, ids []adopt.FileID,
	writes bool) bool {
	if heldByAny(held, path, aliases, writes) {
		return true
	}
	for _, id := range ids {
		for _, k := range dirs.keyed[id] {
			if held(k, writes) {
				return true
			}
		}
	}
	name := filepath.Clean(path)
	for child, dir := name, filepath.Dir(name); dir != child; child, dir = dir, filepath.Dir(dir) {
		ks := dirs.at(dir)
		if len(ks) == 0 {
			continue
		}
		rel, err := filepath.Rel(dir, name)
		if err != nil {
			continue
		}
		for _, k := range ks {
			if held(filepath.Join(k, rel), writes) {
				return true
			}
		}
	}
	return false
}

// keyedDirs is the inodes the plane's fs rows are keyed at (keyed, heldRules), and the rows keyed at each directory
// a held file's name passes through, by an lstat of that directory in tego's namespace, read once per count.
type keyedDirs struct {
	keyed map[adopt.FileID][]string
	seen  map[string][]string
}

// at is the paths of the rows keyed at the directory dir names now: none when no row is keyed, or dir is no
// directory tego can lstat.
func (d *keyedDirs) at(dir string) []string {
	if len(d.keyed) == 0 {
		return nil
	}
	if v, ok := d.seen[dir]; ok {
		return v
	}
	var v []string
	var st unix.Stat_t
	if unix.Lstat(dir, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR {
		dev := uint64(st.Dev) //nolint:unconvert // Dev is uint64 on amd64 and arm64, not everywhere
		v = d.keyed[adopt.FileID{Dev: unix.Mkdev(unix.Major(dev), unix.Minor(dev)), Ino: st.Ino}]
	}
	if d.seen == nil {
		d.seen = map[string][]string{}
	}
	d.seen[dir] = v
	return v
}

// idsOf is a descriptor's file as heldFile's list: none when its inode could not be read.
func idsOf(id adopt.FileID) []adopt.FileID {
	if id == (adopt.FileID{}) {
		return nil
	}
	return []adopt.FileID{id}
}

// heldRules gives the test of a file held open or mapped (for writing when writes): whether the boundary would refuse
// to open it so now. It asks the plane's own rows (decide.CompilePlane of the run's table, what the run's programs hold),
// never a second model of them: a read under any deny_read entry (declared, built-in, or a name entry such as the
// built-in .env list), a write outside every write entry or on a deny_write target beneath one (a repository's hooks
// and config, shell startup files), and a path the walk cannot resolve. A writable descriptor reads too, so it is
// asked both questions. The device files a launched run's agent holds the same way and writes with no decision either
// (the terminal, /dev/null and its kind: heldWriteExempt) are not across a rule for a write; every other file under
// /dev is (/dev/shm is storage). A table the rows cannot be compiled for (which no armed plane holds) counts every held
// file, fail-closed. It also gives the paths of the fs rows the plane keyed at each inode (keyedFiles): a row decides
// every name of its inode, so a file held under a name no rule names (a hard link of ~/.netrc in the workspace, or the
// keyed file renamed since the fill, or a file of a keyed directory renamed since) is asked about by the keyed path
// too (heldFile).
func (a *adoption) heldRules() (func(path string, writes bool) bool, map[adopt.FileID][]string) {
	rt := a.r.rt
	rows, err := decide.CompilePlane(rt)
	if err != nil {
		a.r.log.Warn("adopt: the plane's rows for the open-descriptor count", "err", err)
		return func(string, bool) bool { return true }, nil
	}
	refused := func(path string, q decide.PlaneQuestion) bool {
		return !rows.DecideObject(decide.Canonical(rt, filepath.Clean(path)), q, false).Allow
	}
	return func(path string, writes bool) bool {
		if refused(path, decide.PlaneRead) {
			return true
		}
		return writes && !heldWriteExempt(path) && refused(path, decide.PlaneModify)
	}, a.keyedFiles(rows)
}

// keyedFiles maps each inode a run's fs row is keyed at to the rows' paths: what the plane's fill wrote the rows at
// (enforce.PlaneKeyedReporter), or, from a handle that cannot say (no plane filled them: a test's), each row's path as
// an lstat finds it now. A path that cannot be stat'ed keys nothing.
func (a *adoption) keyedFiles(rows *decide.PlaneRows) map[adopt.FileID][]string {
	out := map[adopt.FileID][]string{}
	add := func(path string, dev, ino uint64) {
		id := adopt.FileID{Dev: unix.Mkdev(unix.Major(dev), unix.Minor(dev)), Ino: ino}
		if !slices.Contains(out[id], path) {
			out[id] = append(out[id], path)
		}
	}
	if kr, ok := a.r.handle.(enforce.PlaneKeyedReporter); ok {
		if keyed, ok := kr.PlaneKeyed(); ok {
			for _, k := range keyed {
				add(k.Path, k.Dev, k.Ino)
			}
			return out
		}
	}
	for _, r := range rows.FS {
		var st unix.Stat_t
		if unix.Lstat(r.Path, &st) == nil {
			add(r.Path, uint64(st.Dev), st.Ino) //nolint:unconvert // Dev is uint64 on amd64 and arm64, not everywhere
		}
	}
	return out
}

// heldWriteExempt are the device files a process holds for writing that carry no file's contents: the terminal and
// the byte sinks and sources. A launched run's agent inherits its terminal the same way, written with no decision.
func heldWriteExempt(path string) bool {
	switch path {
	case "/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty", "/dev/ptmx", "/dev/console":
		return true
	}
	return strings.HasPrefix(path, "/dev/pts/")
}
