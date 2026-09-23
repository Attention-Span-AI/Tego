// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"context"
	"log/slog"
	"net/netip"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Emitter is the run's event sink — the same bounded, non-blocking queue every other producer of the
// run writes to (P0-DESIGN §6; internal/runtime's *Queue satisfies it). It is declared here rather
// than imported so this package never depends on internal/runtime, which would be a cycle.
type Emitter interface {
	// Emit takes an event without blocking; a sink that cannot take it drops and counts it.
	Emit(*record.Event)
}

// RunRef identifies the run a backend prepares for.
type RunRef struct {
	ID       string
	Agent    string
	CgroupID uint64
	RunDir   string
	Contract string // path of the compiled contract copy
	// CgroupPath is the run scope's path relative to the cgroup2 mount and CgroupMount that mount point.
	// Tier 2 needs both to place its programs; tier 1 ignores them.
	CgroupPath  string
	CgroupMount string
	// Events is where a tier's own producers put what they refused and what they could not see. It is
	// per run and not per process because those events are rows of this run's ledger: tier 2's fanotify
	// listener refuses a read or an exec and every one of docs/p0/enforce-cgroup-observe.md §7's gaps —
	// fanotify-timeout, -overflow, -path-unresolved, -malformed-record, -response-failed — carries the
	// run id, and §5 R17 fixes the `rule` each row spells. A backend handed no sink still refuses in the
	// kernel and records nothing, which is the one combination the design rules out.
	//
	// Nil is correct only for a tier that produces no events of its own: tier 1's supervisor is its own
	// producer and writes to the queue directly. When set it must already be usable — a live sink, not a
	// nil pointer inside a non-nil interface — because tier 2's listener answers opens, and so may call
	// Emit, from the moment Prepare returns.
	Events Emitter
	// Resolvers are the endpoints the supervisor's port-53 exception covers for this run (supervisor R14):
	// the one list the runtime also hands the supervisor's resolver set, read once, so the two can never
	// name different servers. Tier 2 writes a port-53 row for each, because it decides every connect the
	// supervisor relays (docs/p0/enforce-cgroup-observe.md §5 R5); empty means no exception (supervisor E32).
	// Tier 1 ignores it: its supervisor is the only thing deciding.
	Resolvers []netip.AddrPort
	// StageExe is the binary the launcher execs as the child stage; empty means /proc/self/exe, which is
	// what `tego run` execs. The launcher creates the stage inside the run's cgroup at every tier
	// (clone3(CLONE_INTO_CGROUP), runtime-launch step 6); tier 2 execs it again for its detached helpers. The
	// stage's exec of it comes before the tier arms (Armer, ADR 0021 (2)), so no tier decides or records it.
	StageExe string
	// Log is the run's own log (tego's, never the ledger); nil discards. Tier 2's fanotify listener writes
	// what it swallows there (docs/p0/enforce-cgroup-observe.md §6 E10).
	Log *slog.Logger
	// Drop is set for a root launch, whose child drops to DropUID and DropGID (launch.ChildSpec's TargetUID and
	// TargetGID). Tier 1 creates a missing write directory with those credentials (landlock.Run.Drop), and tier
	// 2 passes them on to the tier-1 state it inherits.
	Drop             bool
	DropUID, DropGID int
}

// Backend is one enforcement tier (docs/p0/enforce-landlock.md §4, P0-DESIGN §2.6).
type Backend interface {
	Tier() backend.Tier
	Capabilities() backend.Set
	// Prepare resolves rule paths (holding O_PATH fds for the run) and builds the tier's rulesets or maps.
	Prepare(ctx context.Context, rt *agent.RuleTable, run RunRef) (api.Handle, error)
}

// KernelRecorder is the optional interface a Handle implements when its tier writes a kernel ring
// buffer for the record to drain. A Handle without it means the tier produces no record of its own:
// tier 1 has none, because the seccomp supervisor is its only producer and it writes events directly.
//
// It exists as a type assertion rather than a Handle method because the ring buffer is named by a
// build hash the handle computes at Prepare time, and internal/runtime cannot construct the recorder
// itself: internal/runtime/observe imports internal/runtime (for ActivityStamper, DecisionPlaneNamer,
// PathHookNamer, KernelReading, Queue and the Gap* names), so the arrow only points one way. The runtime reads the hash here and hands it to a factory its caller supplied.
type KernelRecorder interface {
	// BPFHash names the pin directory under bpffs holding this build's shared ring buffer.
	BPFHash() string
}

// NetRefresher is the optional Handle extension a tier implements when its kernel rows hold a host entry's
// addresses: tier 2's connect4/6 decides every connect the supervisor relays, so its rows have to follow the
// addresses the supervisor's resolver set re-resolves on TTL (docs/p0/enforce-cgroup-observe.md §6 E7). rt is
// the run's table with refreshed addresses and expiry deadlines; policy entries and permissions remain
// unchanged. An unchanged address still needs renewal when its deadline changes. Callers type-assert.
type NetRefresher interface {
	RefreshNet(rt *agent.RuleTable) error
}

// NetworkReporter reports actual attached destination mechanisms and the
// inherited client filter. A missing reporter provides no kernel assurance.
type NetworkReporter interface {
	NetworkGuarantees() backend.NetworkGuarantees
}

// KernelNetReader is the optional Handle extension a tier implements when a kernel program of its own decides
// the connects the supervisor relays on the agent's socket: tier 2's connect4/6, whose refusal fails the relay
// with EPERM. KernelNet reads that decision back for the ledger line (docs/p0/enforce-cgroup-observe.md §5 R5,
// §6 E5; supervisor.Options.KernelNet). Callers type-assert.
type KernelNetReader interface {
	KernelNet(ap netip.AddrPort, proto string, notified time.Time) (v record.Verdict, rule string, reason record.Reason)
}

// KernelDatagramReader is the optional Handle extension a tier implements when a kernel program of its own decides
// addressed datagrams by destination on the kernel's own copy of the address: tier 2's cgroup/sendmsg4, sendmsg6 and
// sendmsg_unix, and the decision plane's socket_sendmsg below 6.7. KernelDatagrams is the errno such a program refuses
// a unix and a UDP datagram with, 0 for a family none decides; the supervisor refuses with it a datagram the program
// would refuse, so the datagram's one line is that refusal (supervisor.Options.KernelDatagrams, supervisor.md R13b,
// docs/p0/enforce-cgroup-observe.md §5 R7). Callers type-assert.
type KernelDatagramReader interface {
	KernelDatagrams() (unixErrno, udpErrno syscall.Errno)
}

// SupervisorExecLines is the optional Handle extension a tier implements when a mechanism of its own refuses
// an exec's open of its image after the supervisor continued the exec: tier 2's fanotify listener, whose refusal
// the supervisor records on the exec's own line (supervisor R7a, R16b). The runtime hands it
// supervisor.Loop.ExecLine once the loop exists, and the listener writes no line for such an open. Callers
// type-assert.
type SupervisorExecLines interface {
	SetSupervisorExecLines(fn func(tid int, dev, ino uint64) bool)
}

// ExecPinClaimer is the optional Handle extension a tier implements when its decision plane can hold a run's execs to
// the facts that were decided (ADR 0048 (3) P2, (7)): ExecPinClaim reports whether it does for this run, and why not
// when it does not. A Handle without it never does. The runtime reads it for run_start's capability line and
// best_effort, and refuses an exec.assurance: kernel run without the claim.
type ExecPinClaimer interface {
	ExecPinClaim() (bool, string)
}

// DecisionPlaneReporter is the optional Handle extension a tier implements when the kernel decision plane decides
// the run's fs actions and execs (ADR 0024; tier bpflsm, and tier cgroup where a plane mode is selected; T6/T7).
// DecisionPlane returns the plane's mode (record.DecisionPlaneLSM or record.DecisionPlaneFmodRet), "" for none, and
// whether its bprm_check decides this run's execs (the contract has an exec: section). The runtime names the mode
// on the plane's ledger lines and, when the plane decides execs, leaves each continued exec's one line to the
// kernel (supervisor Options.KernelExecs, observe SetSupervisorExecs(false); supervisor R7a, TIER3-PLAN T9).
// Callers type-assert.
type DecisionPlaneReporter interface {
	DecisionPlane() (mode string, execs bool)
}

// ExecOutcomeReporter reports complete kernel coverage for failed execve and
// execveat attempts, in addition to successful sched_process_exec records.
// Without it the supervisor keeps exec policy decisions and refusal records.
type ExecOutcomeReporter interface {
	ExecOutcomes() bool
}

// PlaneCounterReporter is the optional Handle extension a tier implements when its decision plane keeps per-slot
// fail-closed counters (tego_plane_counters, enforce-plane §2.2 and §2.8). The runtime calls PlaneCounters once at
// run end, after the run's cgroup has emptied and before the ledger closes, and writes one gap what=enforce line per
// non-zero count (record.GapPlane*), naming the mode DecisionPlane reports. It returns every counter of the slot,
// zeros included, and an error when the slot could not be read, which the runtime records as
// record.GapPlaneCountersUnread. A run with no plane mode is never asked. Callers type-assert.
type PlaneCounterReporter interface {
	PlaneCounters() ([]PlaneCount, error)
}

// PlaneKeyedReporter is the optional Handle extension a tier implements when its decision plane keys fs rows on
// inodes: after Prepare, the files the run's fs rows were written at (each row's canonical path, and the device and
// inode the fill wrote it at), ok false when no plane row was filled. A row decides every name of its inode, so an
// adoption asks it whether its deny of the agent owner's records holds the directory its table was compiled against,
// and which keyed file a file the agent held is under a name no rule names (ADR 0055 Decisions 3 and 5). Callers
// type-assert.
type PlaneKeyedReporter interface {
	PlaneKeyed() ([]PlaneKeyed, bool)
}

// TrackingFailureCounter exposes durable loss of descendant enforcement membership. The runtime checks it
// before releasing the child, polls it independently of recording, and checks it again before run_end.
// An unreadable counter is an enforcement failure, never a known zero.
type TrackingFailureCounter interface {
	TrackingFailures() (uint64, error)
}

// PlaneFilterer is the optional Handle extension a tier implements when its decision plane decides in the kernel
// what the inherited seccomp filter notifies (enforce-plane R22, R27; TIER3-PLAN T16). The runtime calls
// UsePlaneFilter before the child stage takes SeccompFilter, and only when the run's kernel recorder writes and names
// by path the line of each action no longer notified (runtime.PathHookNamer); SeccompFilter then leaves those
// notifications out. It returns what is left out (the filter's syscall names, "open-write" and "truncate" for the
// open family's write arm and truncate(2)), empty when nothing is. Callers type-assert.
type PlaneFilterer interface {
	UsePlaneFilter() (dropped []string)
}

// Reporter is the optional Handle extension a backend implements when a run's capability set can
// differ from the tier's static row: the landlock handle clears fs.deny_read when an entry was left
// unenforced under a writable parent (docs/p0/enforce-landlock.md R4). Callers type-assert.
type Reporter interface {
	// Capabilities is the per-run capability set attached to run_start.
	Capabilities() backend.Set
}
