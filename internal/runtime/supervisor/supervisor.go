// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/execpin"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/internal/runtime/deputy"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Sentinel errors, one per failure class (docs/p0/supervisor.md §9).
var (
	// ErrAlreadyRunning is a second Run on the same Loop.
	ErrAlreadyRunning = errors.New("supervisor: loop is already running")
	// ErrPolicy is an unusable Policy handed to New.
	ErrPolicy = errors.New("supervisor: invalid policy")
	// ErrListener is a notify fd that failed in a way the loop cannot continue through.
	ErrListener = errors.New("supervisor: notify listener failed")
	// errProcStat is a /proc/<pid>/stat this package could not parse.
	errProcStat = errors.New("supervisor: malformed /proc/<pid>/stat")
)

// SoftCeiling is the per-notification anomaly threshold (P0-DESIGN §2.7, R22). It is soft: a notification
// over it is counted and, at debug level, logged; nothing is aborted. The typical fast path (read, record,
// CONTINUE) is an order of magnitude below it (P0-DESIGN §9).
const SoftCeiling = 200 * time.Microsecond

// DefaultWorkers is the bounded worker pool size (P0-DESIGN §2.7): a blocked worker blocks one target
// thread, never the run.
const DefaultWorkers = 4

// maxStandby bounds the standby workers the pool may add while its own are parked on a relayed syscall
// (R21). Each standby costs one goroutine, and the parked relay it stands in for holds one duplicate
// descriptor open, so an agent running thousands of threads each inside an allowed connect must not be
// able to grow either without limit. Past this many the pool degrades to exactly what it did before:
// the parked worker keeps its slot, and the next notifying thread waits inside its own trapped syscall.
// An unsourced P0 engineering default, like R3's byte budgets.
//
// It bounds only the relays a handler is still waiting on. A relay whose handler has returned — the
// target abandoned the syscall (E35), or the run was cancelled — keeps its goroutine and its duplicate
// until the kernel returns, and is bounded by relayCeiling instead.
const maxStandby = 64

// DefaultMaxArgv is the byte budget for one execve's argv strings; exceeding it truncates and sets
// argv_truncated on the exec event (R3, R16).
const DefaultMaxArgv = 128 << 10

// pollTimeoutMS bounds one poll so a worker notices a cancelled context even if the wake fd write is lost.
const pollTimeoutMS = 200

// Sink receives the events the supervisor records. A response is always already sent by the time Emit is
// called (R23, I5). Emit may wait for room up to a bound of its own, never longer — the runtime's supervisor
// lane waits 250 ms, then drops and counts — since the worker calling it takes no new notification meanwhile.
type Sink interface {
	Emit(ev *record.Event)
}

// NetMatch is the compiled net.allow entry that admitted a destination. It is an alias of dns.Match, so a
// *dns.Set satisfies Resolver with no adapter.
type NetMatch = dns.Match

// Resolver matches an address against the run's compiled net rules with their live IP sets and names the
// machine's DNS resolvers. internal/platform/dns implements it and refreshes host entries on TTL, keeping
// the previous addresses when a lookup fails (R8, R8a, R27).
type Resolver interface {
	// Match returns the entry that admits dst on proto ("tcp", "udp" or "raw"), or nil when none does.
	Match(dst netip.AddrPort, proto string) *NetMatch
	// ResolverAddrs returns the /etc/resolv.conf endpoints allowed on UDP and TCP 53 (R14); empty means
	// the exception matches nothing (E32).
	ResolverAddrs() []netip.AddrPort
}

// Policy is what the loop needs from the compiled contract and the machine (docs/p0/supervisor.md §2).
// A Policy is immutable once handed to New, which compiles it into the loop's one decision table (I9).
// Nothing swaps that table: what changes during a run lives behind it — the resolver's addresses in the
// runtime's dns.Set, refreshed by its own TTL loop, and the models[] guard's, refreshed by Run (R27).
type Policy struct {
	// Rules is the compiled contract; its Net entries decide connects and its FS entries give the
	// advisory verdict on recorded write-opens, deletes, renames, mkdirs and symlinks.
	Rules *agent.RuleTable
	// Resolver matches inet destinations and names the DNS resolvers; required.
	Resolver Resolver
	// RunID and Agent identify the run on every event.
	RunID, Agent string
	// Record overrides Rules.Record when set; off suppresses the advisory fs events but never a refusal.
	Record agent.RecordMode
	// MaxArgvSize bounds one execve's argv bytes; <= 0 means DefaultMaxArgv.
	MaxArgvSize int
	// Observe makes the loop record-only for an explicit --observe run (R30): every refusal it would have
	// answered is answered CONTINUE instead, and every action event is recorded verdict observed with no
	// reason. Rules still names the entry each action matches, so the record says what the contract would
	// have done without the run having done it.
	Observe bool
	// Cgroup is the run's cgroup, its path relative to the cgroup2 mount as /proc/<pid>/cgroup spells it:
	// below Landlock ABI 6 a signal is continued only to a process in it or beneath it (signal.go). Empty
	// refuses every signal the filter hands this loop.
	Cgroup string
}

// Validate reports whether the policy carries everything a decision needs.
func (p *Policy) Validate() error {
	switch {
	case p == nil:
		return fmt.Errorf("%w: nil policy", ErrPolicy)
	case p.Rules == nil:
		return fmt.Errorf("%w: no rule table", ErrPolicy)
	case p.Resolver == nil:
		return fmt.Errorf("%w: no resolver", ErrPolicy)
	case p.RunID == "":
		return fmt.Errorf("%w: no run id", ErrPolicy)
	case !record.IsAgentID(p.Agent):
		return fmt.Errorf("%w: agent %q is not an agent id", ErrPolicy, p.Agent)
	}
	return nil
}

// Revoke withdraws one kernel approval credit once the relay it admitted has returned, whatever came of it. untaken
// reports that the credit was still in the run's map: the run's hook never took it, so a relay the kernel answered
// with success did not pass connect4/6, sendmsg4/6 or connect_unix as the operation the credit names (askDatagram).
// Calls after the first return the first's result. It is cgroup's Revoke.
type Revoke = func() (untaken bool, err error)

// Options configures a Loop; every field has a spec-mandated default.
type Options struct {
	Ask         func(context.Context, ask.Request) (ask.Decision, error)
	AskResolver Resolver
	// GrantConnect is mandatory in root tiers for a governed socket's ask.
	// It grants only the exact duplicate/cookie/destination for one connect.
	//
	// Each grant takes its row of the run's kernel approval maps from the grant to its revoke: another grant of the
	// same row waits for that revoke, at most a second and never past done (the run's end), and is refused
	// otherwise. The row is the map's own key, so the granter, which builds it, serializes it (cgroup creditRows).
	// A revoke reports whether the credit was still in the map, which the run's hook never took (Revoke).
	GrantConnect func(done <-chan struct{}, fd int, dst netip.AddrPort, proto string) (Revoke, error)
	// GrantUnix is mandatory in root tiers for an approved abstract unix name (askUnix): it lets the run's kernel
	// programs admit one connect of the socket with that SO_COOKIE (read from the duplicate, which askUnix checks
	// is AF_UNIX) to exactly that name, and its revoke withdraws it. A pathname needs none: the relay names the
	// inode it resolved, which those programs admit from the relay alone.
	GrantUnix func(done <-chan struct{}, cookie uint64, name []byte) (Revoke, error)
	// GrantDatagram is mandatory in root tiers for an approved UDP datagram (askDatagram, R13d): it lets the run's
	// sendmsg4/6 admit one addressed datagram of the UDP socket with that SO_COOKIE and SO_DOMAIN (read from the
	// duplicate) to exactly that destination, and its revoke withdraws it.
	GrantDatagram func(done <-chan struct{}, cookie uint64, domain int, dst netip.AddrPort) (Revoke, error)
	// FirstWrite reserves a first-write relay (ask.hold first_write) for a held TCP connect to the destination, on the
	// socket the int names: the connect is made into it, and the person is asked once the agent writes. Its last
	// argument names the live block refusing the destination now, "" when none (liveInetAsked): the relay withdraws a
	// pending request when one lands and refuses an approval it outranks (ask.RelayPool.Reserve).
	FirstWrite func(context.Context, ask.Request, netip.AddrPort, bool, int, func() string) (netip.AddrPort, func(), error)
	// Workers is the notification pool size; <= 0 means DefaultWorkers (R21).
	Workers int
	// Budget is the soft per-notification ceiling; <= 0 means SoftCeiling (R22).
	Budget time.Duration
	// Log is the run's own log; nil discards. Handler lines carry the syscall number and timings, never
	// a path or an argv: agent data belongs in the redacted ledger (§9).
	Log *slog.Logger
	// kernel is the syscall seam; nil means the real one. Tests set it.
	kernel kernel
	// mayRun says whether a thread may still be about to run a notified mutation (the walk cache's pending
	// ones); nil means mutationMayRun, /proc's answer. Tests set it.
	mayRun func(tid int, nr int32) bool
	// lookup resolves a guarded models[] host name (modelGuard); nil means net.DefaultResolver. Tests set
	// it.
	lookup agent.Resolver
	// modelRefresh is how often Run refreshes the guard; <= 0 means modelRefreshEvery. Tests shorten it.
	modelRefresh time.Duration
	// Activity, when set, is told of every notification this loop answers: the agent's activity, which a
	// record: off run does not carry to the budget watcher in events (docs/p0/limits-check-doctor-cli.md R4).
	// It must not block.
	Activity func()
	// Late, when set, is told of a notification finished more than the soft ceiling (Budget) after its receipt, with
	// the CLOCK_MONOTONIC reading of its finish. Every line carries its notification's receipt as mono_ns (R23a), so
	// a syscall this loop relayed for long (a blocking connect, a unix relay) wrote a line stamped at its start, and
	// its completion is the agent's activity to the budget watcher's stall check only through this
	// (docs/p0/limits-check-doctor-cli.md R4). Only a slow notification calls it, from the time
	// finish already reads. It must not block.
	Late func(monoNS uint64)
	// KernelConnects, when set, reports whether the run's kernel recorder writes the line of an IP
	// connect(2) the agent's own task makes (enforce-cgroup-observe §5 R1, security_socket_connect): true
	// only while a recorder is reading this run's ring under a record mode other than off. A connect this
	// loop answers CONTINUE is then the kernel's to record, and this loop writes no line for it (R7), so
	// the ledger holds one line per connect. It is asked after the answer is sent, and it may wait until
	// the recorder has decided whether it reads; it must return once the run is cancelled. Nil means no
	// recorder: every continued connect gets this loop's line, as at tier 1.
	KernelConnects func() bool
	// KernelFS, when set, reports whether the run's kernel recorder writes the line of a filesystem action the
	// kernel's hooks see (enforce-cgroup-observe §5 R9: an open, create, unlink, rmdir, mkdir, rename, link,
	// symlink or truncate), with the verdict the LSM chain returned: true while a recorder reads this run's ring,
	// under every record mode (the recorder keeps refusals under off). Such an action this loop answers CONTINUE
	// is then the kernel's to record, and this loop writes no line for it (R7a), handing the recorder its own
	// naming instead (ContinuedFS). It is asked before the answer is sent, and it may wait until the recorder
	// has decided whether it reads; it must return once the run is cancelled. Nil means no recorder.
	KernelFS func() bool
	// KernelExecs, when set, reports whether the run's kernel writes the line of an exec this loop continues: the
	// kernel decision plane decides execs in bprm_check (ADR 0024) and a recorder reads this run's ring, so the
	// exec's one line is the plane's refusal sample or the recorder's sched_process_exec record named by the
	// plane's rule (R7a, TIER3-PLAN T9). This loop then writes no line for an exec it allows and continues; its own
	// refusals, the PATH-search answers it gives itself and the MCP server line stay its own. It is asked after the
	// answer is sent and must return once the run is cancelled. Nil means the plane decides no exec here.
	KernelExecs func() bool
	// KernelExecHandoff delegates every exec decision and outcome to a ready
	// kernel plane and recorder. The notification remains solely to capture
	// bounded metadata before CONTINUE. Nil or false retains supervisor decisions,
	// as an exec gate, command rules, a live exec block or fence entry and a running
	// MCP relay (MCPRelayed) each do; the recorder still writes what such an exec continues.
	KernelExecHandoff func() bool
	// ExecPinner, when set, writes the pin of every exec this loop continues into the run's decision plane, and an
	// exec whose pin cannot be written is refused (ADR 0048 (3) P2, rule exec.pin). ExecPinKey is the run's MAC key,
	// which the pins' MACs are under; it is never written to the ledger or a log. Nil means the run is not pinned.
	ExecPinner ExecPinner
	ExecPinKey execpin.Key
	// KernelBindHandoff delegates Unix bind decisions and terminal outcomes
	// only while copied-name listener hooks and the result recorder are ready.
	KernelBindHandoff func() bool
	// KernelListenHandoff delegates Unix listen to the actual bound-socket
	// listener plane and terminal result recorder. Nil retains the fallback.
	KernelListenHandoff func() bool
	// PlaneFS says the run's seccomp filter no longer notifies some fs mutations, which the kernel decision plane
	// decides and the recorder records (enforce-plane R27, TIER3-PLAN T16). The walk cache then stays off: it is
	// invalidated by the notified mutations of the run's own tasks, and a rename or unlink it is no longer told of
	// would leave a kept directory's symlinks stale for the notifications still coming (walkcache.go).
	PlaneFS bool
	// PlaneAttrs reports that a kernel decision plane mode decides this run (ADR 0024 step B, TIER3-PLAN T13): its
	// attribute hooks refuse a chmod beneath a deny_write target in the kernel, with its own line. This loop then
	// refuses such a chmod it is notified of (record: full) itself, by R15c's predicate, rather than record it as
	// allowed ahead of the kernel's refusal: one line per action, and the same verdict (enforce-plane R12, I8).
	PlaneAttrs bool
	// OwnState is tego's own state the launcher knows beyond the compiled table's (RuleTable.OwnState): the
	// run's runtime directories' parent, $XDG_RUNTIME_DIR/tego, by each of its spellings. No alternate a person
	// names for a held open is delivered from at or beneath one (alternateRefusal, ADR 0057 D2).
	OwnState []string
	// RuntimeDir is the run's own runtime directory (its reason file, its CODEX_HOME), which lies inside OwnState's
	// runtime parent and which the run is given to read: a held read beneath it is not refused as tego's own state
	// (heldReadFloors, ADR 0069 D3 (d)). "" when the run has none.
	RuntimeDir string
	// MCPRelayed is the MCP relay's gate (ADR 0126 §4): asked of an allowed exec that starts a declared MCP server,
	// it reports whether the start is the relay's (the caller's parent is a shim the relay admitted for that server);
	// a start it does not vouch for is refused, rule mcp[<name>].relay. Nil turns the gate off: every path unchanged.
	MCPRelayed func(server string, callerPID int) bool
	// DenyReadSnapshot reports whether the run's Landlock ruleset refuses a read open of a resolved path the contract
	// allows, because the path lies beneath a deny_read target's ancestor through a name that ancestor's one listing
	// at launch did not grant (enforce-landlock R3, E10): a directory or file made there after the run started.
	// This loop refuses such an open itself and records it refused under deny-read-snapshot, and explains the same
	// EACCES of a held open (snapshotRead). Nil when the run's ruleset enumerated nothing, or the tier keeps no
	// snapshot.
	DenyReadSnapshot func(path string) bool
	// Deputy is the run's open deputy (ADR 0041 D2), which the child stage started in the run's own domain and cgroup:
	// with it, under gate.completion: held every open of a gate kind whose rules can score to allow or above, and in a
	// run that holds its reads (ADR 0069) every read-capable open, is held and completed in the run's kernel context
	// (heldOpen), never continued. Nil keeps those opens on copied facts, best effort and disclosed. The caller keeps
	// ownership and closes it after Run returns.
	Deputy *deputy.Client
	// openDeputy replaces Deputy in tests.
	openDeputy openDeputy
	// KernelNet, when set, reads the run's tier-2 network decision for a connect this loop relayed on the
	// agent's socket that failed EPERM: the run's connect4/6 decides the relayed connect too, and a refusal
	// of its own is the kernel's, not this loop's (enforce-cgroup-observe §5 R5). proto is the socket's, "tcp"
	// or "udp", and notified is when the notification arrived. It answers VerdictRefused with the kernel's rule and reason, VerdictAllow when
	// the kernel allowed this destination (the EPERM came from elsewhere), or "" when nothing fresh names it
	// (§6 E5). Nil means no kernel decides this run's connects: tiers 1 and observe.
	KernelNet func(ap netip.AddrPort, proto string, notified time.Time) (v record.Verdict, rule string, reason record.Reason)
	// LiveBlocks, when set, is the run's live blocks now (internal/liveblock, MinorLiveBlock): read at each decision
	// that could continue, relay or ask an exec, a connect or send, or an fs action, it refuses what a block names on
	// top of the contract (liveblock.go). Live blocks only tighten: a refusal this loop already makes stands as it is.
	// It must not block (an atomic load); nil, or a nil Set, blocks nothing.
	LiveBlocks func() *liveblock.Set
	// KernelDatagrams names the addressed datagrams a kernel program of the run decides by destination, on the
	// kernel's own copy of the address, and the errno its refusal fails one with (R13b; enforce-cgroup-observe §5
	// R7, enforce-plane §2.11). A datagram that program would refuse is refused here, with that errno, rather than
	// continued with a best-effort line the kernel's refusal then contradicts: the refusal is this loop's own
	// answer and the datagram's one line (ADR 0016). The zero value is no kernel program: tier 1, and every family
	// a tier-2 run has no program attached for.
	KernelDatagrams KernelDatagrams
}

// KernelDatagrams is Options.KernelDatagrams: per family, the errno the run's own kernel program refuses an
// addressed datagram with, or 0 where none decides that family.
type KernelDatagrams struct {
	// Unix is cgroup/sendmsg_unix's EPERM (6.7+), or the decision plane's socket_sendmsg's EACCES below 6.7.
	Unix unix.Errno
	// UDP is cgroup/sendmsg4 and sendmsg6's EPERM.
	UDP unix.Errno
}

// Metrics are the counters carried into run_end.supervisor (R24).
type Metrics struct {
	// Notifications counts every notification received, abandoned and recovered ones included.
	Notifications int64
	// HeldMS is the summed time notifications were held, in milliseconds, from a monotonic clock (E14).
	HeldMS int64
	// Anomalies counts notifications held longer than the soft ceiling (R22).
	Anomalies int64
	// Orphaned counts syscalls this loop performed for the target whose notification was withdrawn before
	// the answer reached it (E35). Below 5.19, or where the listener was installed without
	// WAIT_KILLABLE_RECV, a non-fatal signal withdraws it and the kernel restarts the syscall, so each is a
	// side effect about to happen twice; with the flag only a fatal signal does, so each means the target
	// was killed and nothing restarts. It does not count the one restart the flag leaves on a kernel
	// without cce436aa, a non-fatal signal landing as the answer is sent: NOTIF_SEND succeeds there, and
	// nothing this loop sees is withdrawn (relayOrphaned). Under record: summary or full each one counted
	// also gets its own net line with result_unknown; under record: off emitNet writes no allowed net line
	// at all, so this total, carried into run_end, is the only trace of them.
	Orphaned int64
	// Starved counts the relays that could not be backfilled because maxStandby was reached (R21): each
	// left one worker parked on a relay with no standby receiving in its place, so the loop answered the
	// run's other notifications with one worker fewer until that relay returned.
	Starved int64
	// OrderLost counts the notifications whose lines gave up waiting, after orderWait, for the previous
	// notification of their thread to finish writing (R23a): each line may precede the one before it in the
	// thread's syscall order. It is zero in a run that kept every thread's order.
	OrderLost int64
	// ExecRules counts what the exec command rules refused (ADR 0048 (8)); nil for a run without command rules.
	ExecRules *record.ExecRules
	// ExecMissing counts the execs whose pathname named nothing, which the loop answered with the walk's ENOENT or
	// ENOTDIR and wrote no line for (R16b (0)): a PATH search's misses, mostly. It is their only trace in the record.
	ExecMissing int64
}

// metrics are the live counters behind Metrics; held time accumulates in microseconds so that a run of
// sub-millisecond notifications is not rounded away to zero.
type metrics struct {
	notifications atomic.Int64
	heldUS        atomic.Int64
	anomalies     atomic.Int64
	// orphaned counts notifications the target abandoned while a syscall this loop had already performed
	// on its behalf was still running (E35): each one is a side effect the agent never saw the result of
	// and, below 5.19 or without WAIT_KILLABLE_RECV, where the kernel restarts the abandoned syscall, a
	// side effect about to happen twice (Metrics.Orphaned).
	orphaned atomic.Int64
	// starved counts the times a parked relay could not be backfilled because maxStandby was reached.
	starved atomic.Int64
	// relayLimited counts the allowed connects and Fast-Open sends refused because relayCeiling relays
	// were already outstanding.
	relayLimited atomic.Int64
	// cmdRefused, cmdAmbiguous and cmdAsked count the execs the exec command rules refused, those refused on an
	// ambiguous match, and those the reserved exec.ask list refused (ADR 0048 (8)). An observe run refuses nothing,
	// so it counts nothing (F3): the lines are stamped observed and carry the rule for a learn or drift pass.
	cmdRefused, cmdAmbiguous, cmdAsked atomic.Int64
	// pinRefused counts the execs of a pinned run refused for their pin (ADR 0048 (8), rule exec.pin with
	// pin_unavailable): run_end's exec_rules.pin_refused, beside the plane's own pin refusals the recorder counts.
	pinRefused atomic.Int64
	// execMissing counts the execs whose pathname named nothing (the walk met ENOENT or ENOTDIR), answered with that
	// errno and written as no line (missedExec).
	execMissing atomic.Int64
}

// Loop drains one seccomp user-notification fd for the lifetime of a run (docs/p0/supervisor.md §4).
// The zero value is unusable; call New. One Loop owns one listener: two Loops never share a fd, and no
// state is package-global, so concurrent runs cannot observe each other (E15).
type Loop struct {
	ask              func(context.Context, ask.Request) (ask.Decision, error)
	askResolver      Resolver
	grantConnect     func(done <-chan struct{}, fd int, dst netip.AddrPort, proto string) (Revoke, error)
	grantUnix        func(done <-chan struct{}, cookie uint64, name []byte) (Revoke, error)
	grantDatagram    func(done <-chan struct{}, cookie uint64, domain int, dst netip.AddrPort) (Revoke, error)
	firstWrite       func(context.Context, ask.Request, netip.AddrPort, bool, int, func() string) (netip.AddrPort, func(), error)
	askScopes        map[string]askScope
	k                kernel
	sink             Sink
	workers          int
	budget           time.Duration
	log              *slog.Logger
	dispatch         dispatchTable
	table            atomic.Pointer[compiled]
	listenerBindings listenerBindings
	metrics          metrics
	running          atomic.Bool
	// fdWarnAt is when descriptor exhaustion was last logged at Warn (UnixNano), which fdExhausted rate-limits.
	fdWarnAt atomic.Int64

	// armed closes once Run owns the listener and its workers are about to wait on it. A caller that
	// execs the target before the loop is waiting would leave the target blocked in the kernel with
	// nobody to answer it, so the launcher blocks on this instead of guessing with a sleep.
	armed     chan struct{}
	armedOnce sync.Once
	// armedOK separates the two reasons Armed can close. Only the arm point sets it; the deferred
	// disarm on a failed start does not, so a caller can tell a loop that is running from one that
	// returned before it ever owned the listener.
	armedOK atomic.Bool

	// readers pools the per-notification read sessions with their page-sized scan buffers.
	readers sync.Pool

	// spawn starts one more worker on Run's own context and wait group; it is how a worker about to park
	// on a relayed syscall backfills the pool (R21). Nil outside Run — a handler driven directly by a
	// test has no pool to backfill — and written once, before the first worker exists.
	spawn func()
	// standby counts the backfill workers currently alive: incremented when a parked relay is covered,
	// decremented when the worker it covered retires.
	standby atomic.Int64
	// relays counts the relay goroutines still alive, each holding one duplicate of a target socket:
	// incremented before one starts, decremented once it has closed its duplicate. Unlike standby it
	// keeps counting a relay whose handler has already returned, which is what relayCeiling bounds.
	relays atomic.Int64

	// dgramApproved holds the UDP destinations a person approved, each for the one socket it was approved on
	// (askDatagram, R13d); dgramMu guards it.
	dgramMu       sync.Mutex
	dgramApproved map[dgramApproval]struct{}

	// recvMu serializes poll+recv so that exactly one worker is ever inside NOTIF_RECV: the ioctl blocks
	// uninterruptibly by a fd close, so the loop only calls it once poll says a notification is pending.
	recvMu sync.Mutex
	// wakeR/wakeW is the self-pipe cancellation travels on; owned and closed by Run.
	wakeR, wakeW int

	// topology remembers which binaries this run already has a landlock-topology gap line for
	// (refuseTopology), so a sandbox retrying its mount does not repeat the gap; every refusal still
	// gets its own refused line.
	topology topologySeen
	// keyringSeen remembers which (binary, keyring syscall) pairs this run already has a keyring gap line
	// for (answerKeyring), so an allowed Kerberos library's stream of keyctl calls leaves one line per
	// binary and syscall rather than one per call.
	keyringSeen topologySeen
	// ipcSeen is keyringSeen for System V IPC (answerSysVIPC): one gap line per (binary, syscall).
	ipcSeen topologySeen
	// frameSeen is keyringSeen for an observe run's pending-frame refusals that name no destination (refuseOp): one
	// gap line per (binary, syscall and rule). Every seen set is keyed by gapOwner: a process stands for a binary
	// that cannot be read.
	frameSeen topologySeen
	// activity is Options.Activity, told of every answered notification; nil when not asked for.
	activity func()
	// late is Options.Late, told of a notification finished past the soft ceiling; nil when not asked for.
	late func(monoNS uint64)
	// kernelConnects is Options.KernelConnects; nil when the run has no kernel recorder (kernelRecords).
	kernelConnects func() bool
	// kernelFS is Options.KernelFS; nil when the run has no kernel recorder.
	kernelFS func() bool
	// kernelExecs is Options.KernelExecs; nil when no plane decides this run's execs.
	kernelExecs       func() bool
	kernelExecHandoff func() bool
	execHanded        execHandover
	// pinner and pinKey are Options.ExecPinner and ExecPinKey; pinner is nil in a run that is not pinned.
	pinner              ExecPinner
	pinKey              execpin.Key
	kernelBindHandoff   func() bool
	bindHanded          bindHandover
	kernelListenHandoff func() bool
	listenHanded        bindHandover
	// runSockets is R11a's set: the sockets processes of the run bound to a pathname (unixorigin.go).
	runSockets runSockets
	// planeAttrs is Options.PlaneAttrs.
	planeAttrs bool
	// ownState is Options.OwnState.
	ownState []string
	// runtimeDirs is the invoking user's runtime directory, which R19's list of daemon sockets names as %U, and the
	// supervisor's XDG_RUNTIME_DIR where that differs and the run was not started through sudo (hostRuntimeDirs).
	runtimeDirs []string
	// runtimeDir is Options.RuntimeDir, cleaned.
	runtimeDir string
	// snapshotRefuses is Options.DenyReadSnapshot.
	snapshotRefuses func(path string) bool
	// mcpRelayed is Options.MCPRelayed.
	mcpRelayed func(server string, callerPID int) bool
	// deputy is Options.Deputy, or a test's fake: the run's open deputy, which completes held opens (heldOpen). Nil
	// for a run with none, whose escalating open cells stay best effort (ADR 0041 D1, D7).
	deputy openDeputy
	// handed holds the naming of the fs actions this loop left to the kernel recorder's line (ContinuedFS).
	handed handover
	// walks keeps the directories whose paths land on their spelling (walkcache.go), and mayRun says whether a
	// thread with a pending mutation may still run it (mutationMayRun; tests replace it).
	walks  walkCache
	mayRun func(tid int, nr int32) bool
	// mono stamps a handed-over action (handOver): monotonicNS; tests replace it.
	mono func() uint64
	// order keeps one thread's lines in the order of its syscalls (order.go, R23a).
	order orderBook
	// execLines holds the execs whose image's open the fanotify listener refuses and whose line this loop
	// writes (ExecLine).
	execLines execLines
	// kernelNet is Options.KernelNet; nil when no kernel program decides the run's connects.
	kernelNet func(ap netip.AddrPort, proto string, notified time.Time) (record.Verdict, string, record.Reason)
	// kernelDgrams is Options.KernelDatagrams.
	kernelDgrams KernelDatagrams
	// tgids caches each notifying thread's process, so a line's pid is the process and its tid the thread
	// (tgidOf).
	tgids tgidCache
	// groups is the last /proc scan of the host's process groups, which a group signal below Landlock ABI
	// 6 is decided on (groupMembers).
	groups groupCache

	// started is when New built the loop, before the agent ran: an exec image changed after it under a
	// write entry was written during the run (droppedImage).
	started time.Time

	// guard is the table's models[] guard with its live addresses (modelGuard); nil when the table guards
	// nothing. Run refreshes it every modelRefresh. lookup is what it resolves with.
	guard        atomic.Pointer[modelGuard]
	lookup       agent.Resolver
	modelRefresh time.Duration
}

// compiled is the immutable per-policy decision table: the policy plus the derived nearest-wins filesystem
// rules (fsResolved, fsBoth) and unix socket rules. It is built once, in New, and only ever read afterwards (I9).
type compiled struct {
	pol *Policy
	// live is Options.LiveBlocks: the run's live blocks, which change while the table does not (blocks).
	live func() *liveblock.Set
	unix []unixRule
	// planeKeyed is the files a decision plane keys at their own inodes, by identity (planeKeyedAt).
	planeKeyed planeKeyedIndex
	// unixAsk is net.ask's unix: scopes (askUnix): approval candidates, never admitted without a person's answer.
	unixAsk []unixRule
	// unixAskPaths says unixAsk holds a pathname scope: only then is a pathname connect's name walked to the place it
	// reaches before the write entry around its spelling admits it (unixScopeOf, R11c).
	unixAskPaths bool
	argvMax      int
	record       agent.RecordMode
	// pathSearch maps every path the run's own PATH search must try before a granted binary onto the
	// rule name of the grant it is searching for (R28); nil when the table has no basename entry.
	pathSearch map[string]string
	// execUnrestricted is SEMANTICS §1's "no exec:" — deny nothing — read off the contract exactly as
	// the Landlock builder reads it (execUnrestricted) and as decide.Evaluate does, so the three never
	// answer one exec differently; a table with no Contract fails closed, as the builder does.
	execUnrestricted bool
	// execAnonymous is the contract's `exec.anonymous: true` (SEMANTICS §4): the run opted into
	// anonymous-image exec, so tiers 1/2 install no memfd_create arm and this loop allows an anonymous
	// image rather than refusing it — still recording it fileless. Read off the contract like
	// execUnrestricted; a table with no Contract does not opt in.
	execAnonymous bool
	// keyringAllowed is the contract's `keyring: true` (SEMANTICS §1): the kernel keyring syscalls
	// are continued and recorded as gap lines instead of refused. Read off the contract like
	// execUnrestricted; a table with no Contract refuses them.
	keyringAllowed bool
	// ipcAllowed is the contract's `ipc: true` (SEMANTICS §1, R34): System V IPC is continued
	// and recorded as gap lines instead of refused. A table with no Contract refuses it.
	ipcAllowed bool
	// netOpen is SEMANTICS §1's "no net:" — deny nothing — from agent.RuleTable.NetUnrestricted, the
	// predicate Evaluate answers compile --test with. Under it this loop performs no connect and no send:
	// each is answered CONTINUE, and the kernel runs it as the agent, under the agent's credentials and
	// its own Landlock domain (decide, handleConnect) — except a send whose address is AF_UNSPEC, which is
	// refused as under a net: section (refusesUndecidable), and an IP socket's syscall when the table guards
	// a models[] endpoint (guard, decideGuarded).
	netOpen bool
	// hostSockets is ADR 0070's unix-only state, agent.RuleTable.HostSocketsRefused, the predicate Evaluate answers
	// compile --test with: no net: section and no host_sockets: true. netOpen still holds for every IP destination,
	// but a unix one reaches only a socket a process of the run bound, or one of tego's own endpoints, and every
	// other one is refused host-sockets (decideHostSocket). No connect is continued then: each is relayed on the
	// duplicate, so neither a sibling's rewrite of the address nor a descriptor swapped in after the duplicate
	// reaches a host socket (R7b), and an address or socket this loop could not read is refused (passesUnresolved).
	hostSockets bool
	// datagrams is agent.RuleTable.DecidesDatagrams, read once: the run decides where a datagram goes beyond best
	// effort, so no socket of it may come to hold a pending frame (R13, frame.go), and its filter carries the arms
	// that notify what could start one (enforce-landlock R11d).
	datagrams bool
	// mcp maps a declared MCP server's resolved command[0] onto the servers that run it, for the mcp
	// event an exec of one produces (mcpServerOf).
	mcp map[string][]mcpServer
	// mcpIDs maps the file each such command[0] named when the loop first saw it (resolveExecEntries) onto the servers
	// that run it, at its symlink-resolved path: an exec whose image is that file, by any spelling, starts them.
	mcpIDs map[fileID][]mcpFile
	// cmds are the exec command rules (ADR 0048), nil when the table has none that can decide an exec: then no
	// exec reads argv for them and the fast handover stays available.
	cmds *agent.ExecCommands
	// codexHome is the run's own CODEX_HOME grant (agent.CodexHomeGrant), each spelling followed by itself with a
	// trailing slash, in a deny-list run with command rules only: an image there, or a loader's program there, is
	// refused codex-home-exec (inCodexHome). Nil otherwise: a restricted run refuses such an exec unmatched already,
	// and a run with no exec: section denies nothing (SEMANTICS §1).
	codexHome []string
	// hookState is the run's hook-state grant (agent.HarnessStateGrant, agent-contract.md R27) as codexHome is: an image
	// there, or a loader's program there, is refused harness-state-exec in a deny-list run with command rules.
	hookState []string
	// fsResolved is fs with each entry at its symlink-resolved path (agent.FSRule.Resolved), ordered the
	// same way: the table a relayed unix connect's resolved socket is matched against (decideResolved).
	// fs keeps the declared paths.
	fsResolved *decide.AdvisoryList
	// linkedFS holds the rule names of the fs entries declared through a symlink (agent.FSRule.Resolved differs from
	// Path): a landed path these name by their declared spelling is decided again where they are bound (decideFS).
	linkedFS map[string]bool
	// fsBoth is every entry under both spellings, resolved and declared, ordered the same way: what the
	// advisory verdicts on the paths a target passed compare with (fsVerdict). A relative path is joined to
	// the task's /proc/<pid>/cwd, which the kernel spells canonically, while a program may spell an absolute
	// one through the symlink the contract was written through; matched against the declared paths alone, a
	// write Landlock allowed under a project reached through a symlink was recorded refused, and a read it
	// refused allow (R15b).
	fsBoth *decide.AdvisoryList
	// askRead is the table's fs.ask_read entries (agent.RuleTable.AskReadRules): a read-open one of them decides is
	// held for a person (askReadOpen). Empty for every other table.
	askRead []agent.FSRule
	// heldReads is the held-read floor of a table whose run holds its reads at its tier (agent.RuleTable.ReadsHeld,
	// ADR 0069): every read-capable open is completed by the open deputy and refused on the object it reached
	// (heldReadFloors). nil for every other table.
	heldReads *decide.HeldReadIndex
	// reasonReads is a table whose filter notifies every read open for the reason channel alone (agent.RuleTable.
	// ReasonReadsNotified, ADR 0077): an allowed read is answered quietly (quietRead), and a refused one keeps its line
	// (readMechanism).
	reasonReads bool
	// fsIx is the table's index: REFER's rule, the tier-2 listener's open decision and the exec grant asked
	// by path component, not by a walk of every entry (the .env scan can plant 50,000). nil for a table
	// built without one, which is asked by scan.
	fsIx *decide.FSIndex
	// guard is set when forwarder capture protects a models[] endpoint (agent.RuleTable.GuardedModels),
	// with or without net: entries. IP operations are decided and relayed on the duplicate; named model
	// ports require explicit allowances for unrelated destinations (decideGuarded, R7). nil otherwise.
	guard *modelGuard
	// execIDs maps the file each declared exec entry names onto the entries naming it, each at its
	// symlink-resolved path under its rule name, and execDirs holds each directory entry at its resolved
	// path: what an exec's image is matched against when its spelling matches no entry (decideExec). Both
	// are the entries as the loop first saw them, before the agent ran, which is when the Landlock builder
	// bound its EXECUTE rules to the same files. An image matches a file entry on its inode and its
	// resolved path both: the inode alone admits every hard link of a granted binary (execGranted).
	execIDs  map[fileID][]execFile
	execDirs []execDir
	// execPinned holds the file entries (by Path) that have an execIDs identity: for those, an exec whose
	// walk landed here is matched on where it landed, never on its lexically cleaned spelling (execGranted).
	execPinned map[string]bool
	// execHeld maps each inode an exec entry named when the loop first saw it, which is the inode the Landlock
	// builder bound the entry's grant to, onto the rights that grant gives it (EXECUTE and READ_FILE, READ_DIR for a
	// directory): the rule moves with the inode when the agent renames it inside a write entry, and stays with a dead
	// one when it removes it, so the no-gain rule asks it by identity (execGrants).
	execHeld decide.HeldExecGrants
	// statID is the kernel's StatID, for execGranted's check that a directory entry's name still holds the inode its
	// grant is bound to.
	statID func(string) (fileID, error)
}

// mcpServer is one declared mcp[] entry as an exec is matched against it: its name and the arguments
// its command declares after command[0].
type mcpServer struct {
	name string
	args []string
}

// mcpFile is a declared MCP server's command[0] by identity: the servers it runs, and its symlink-resolved path.
type mcpFile struct {
	path    string
	servers []mcpServer
}

// The fs tables (fs, fsResolved, fsBoth) are the decision core's advisory tables (decide.AdvisoryTables): each
// entry reduced to what an advisory verdict needs, ordered longest path first so the first match is the nearest
// ancestor (SEMANTICS §2).

// nearestIn is decide.NearestIn.
func nearestIn(rules *decide.AdvisoryList, p string) *decide.AdvisoryRule {
	return decide.NearestIn(rules, p)
}

// linkGains is decide.LinkGainsBy on the table's index: a hard link's no-gain rule, the file rights at the new name's
// directory against the file's own, asked across directories only (hook_path_link), with the exec grants' rights from
// exec (nil: by the table, decide.ExecGrantAt).
func (c *compiled) linkGains(src, dst string, exec decide.ExecGrants) bool {
	if c.fsIx != nil {
		return c.fsIx.LinkGainsBy(src, dst, exec)
	}
	return decide.LinkGainsBy(c.pol.Rules, src, dst, exec)
}

// renameGained is decide.RenameGainedBy on the table's index: the rights a rename of the object at src to the name dst
// gains, none within one directory (hook_path_rename), with the exec grants' rights from exec.
func (c *compiled) renameGained(src, dst string, exec decide.ExecGrants) agent.AccessSet {
	if c.fsIx != nil {
		return c.fsIx.RenameGainedBy(src, dst, exec)
	}
	return decide.RenameGainedBy(c.pol.Rules, src, dst, exec)
}

// listenerOpenRefused is decide.ListenerOpenRefused on the table's index.
func (c *compiled) listenerOpenRefused(path string) (agent.FSRule, bool) {
	if c.fsIx != nil {
		return c.fsIx.ListenerOpenRefused(path)
	}
	return decide.ListenerOpenRefused(c.pol.Rules, path)
}

// denyReadMoveTarget is agent.RuleTable.DenyReadMoveTarget on the table's index: asked for every link and
// rename at tier 2, it must not scan the 50,000 entries the .env scan can plant (R15d).
func (c *compiled) denyReadMoveTarget(p string, ancestors bool) (agent.FSRule, bool) {
	if c.fsIx != nil {
		return c.fsIx.DenyReadMoveTarget(p, ancestors)
	}
	return c.pol.Rules.DenyReadMoveTarget(p, ancestors)
}

// denyWriteTarget is agent.RuleTable.DenyWriteTarget on the table's index: asked for each end of every notified
// modification while the deny_write set is not empty, it must not scan every target (R15c).
func (c *compiled) denyWriteTarget(p string, ancestors bool) (agent.FSRule, bool) {
	if c.fsIx != nil {
		return c.fsIx.DenyWriteTarget(p, ancestors)
	}
	return c.pol.Rules.DenyWriteTarget(p, ancestors)
}

// denyWriteName is agent.RuleTable.DenyWriteNameTarget on the table's index: the question of a modification that makes
// the name p (makesName, a link's new name).
func (c *compiled) denyWriteName(p string) (agent.FSRule, bool) {
	if c.fsIx != nil {
		return c.fsIx.DenyWriteNameTarget(p)
	}
	return c.pol.Rules.DenyWriteNameTarget(p)
}

// denyWriteOpen is the deny_write question of a write-open of p with flags: an exclusive create makes the name.
func (c *compiled) denyWriteOpen(p string, flags int) (agent.FSRule, bool) {
	if makesName(record.FSOpen, flags) {
		return c.denyWriteName(p)
	}
	return c.denyWriteTarget(p, false)
}

// hasDenyReadMove reports whether denyReadMoveTarget can match anything.
func (c *compiled) hasDenyReadMove() bool {
	if c.fsIx != nil {
		return c.fsIx.HasDenyReadMove()
	}
	return decide.HasDenyReadMove(c.pol.Rules)
}

// unixRule is one unix: net.allow entry: a cleaned absolute pathname, or the raw bytes of an abstract name
// (never NUL-scanned, E5).
type unixRule struct {
	path     string
	abstract []byte
	name     string
	raw      string
	// resolved is path's place, taken once when the loop is built (resolveUnixDeclared), before the agent runs: the
	// place a relayed connect must reach (decideResolved), and for a net.ask unix: scope the place a connect's name
	// must reach to be asked (unixScopeOf). Resolving it again at decision time would let an agent that can write where
	// a declared path points repoint it.
	resolved string
}

// New takes the notify fd from the child stage (launch.Child.WaitNotifyFD): listener must own an installed
// SECCOMP_FILTER_FLAG_NEW_LISTENER descriptor, and the Loop owns it from the call on, on every path (ADR 0023
// C7): Run closes it once, as its shutdown step, and New closes it itself when it returns an error. The caller
// keeps no reference to it. Two Loops must never share one listener: both would race NOTIF_RECV. A nil listener
// is ErrListener.
func New(listener *sys.FD, pol *Policy, sink Sink, opts Options) (_ *Loop, err error) {
	if listener == nil {
		return nil, fmt.Errorf("%w: none", ErrListener)
	}
	defer func() {
		if err != nil {
			_ = listener.Close()
		}
	}()
	if err := pol.Validate(); err != nil {
		return nil, err
	}
	if sink == nil {
		return nil, fmt.Errorf("%w: nil sink", ErrPolicy)
	}
	l := &Loop{
		ask: opts.Ask, askResolver: opts.AskResolver, grantConnect: opts.GrantConnect, grantUnix: opts.GrantUnix, grantDatagram: opts.GrantDatagram,
		firstWrite: opts.FirstWrite, k: opts.kernel, sink: sink,
		workers: opts.Workers, budget: opts.Budget, log: opts.Log,
		dispatch: buildDispatch(), wakeR: -1, wakeW: -1,
	}
	l.armed = make(chan struct{})
	if l.k == nil {
		l.k = sysKernel{ln: listener}
	}
	if l.workers <= 0 {
		l.workers = DefaultWorkers
	}
	if l.budget <= 0 {
		l.budget = SoftCeiling
	}
	if l.log == nil {
		l.log = slog.New(slog.DiscardHandler)
	}
	// SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP (Linux 6.6) has the notifying task hand its CPU to the worker it
	// wakes instead of going through a full wake-up, about 12 µs to 3 µs a round trip upstream. It changes
	// scheduling only, never what is decided or answered, so an older kernel's EINVAL costs the speed-up
	// and nothing else (internal/platform/sys.SeccompNotifSetFlags explains why the errno cannot tell an
	// old kernel from an unknown flag).
	if err := l.k.SetSyncWakeUp(); err != nil {
		l.log.Debug("supervisor: SECCOMP_USER_NOTIF_FD_SYNC_WAKE_UP not set", "err", err)
	}
	l.mayRun = mutationMayRun
	l.mono = monotonicNS
	l.order.monoBase, l.order.wallBase = anchorMono(monotonicNS)
	if opts.mayRun != nil {
		l.mayRun = opts.mayRun
	}
	l.started = time.Now()
	l.lookup = opts.lookup
	l.activity = opts.Activity
	l.late = opts.Late
	l.kernelConnects = opts.KernelConnects
	l.kernelFS = opts.KernelFS
	l.kernelExecs = opts.KernelExecs
	l.kernelExecHandoff = opts.KernelExecHandoff
	if !pol.Observe {
		// An observe run enforces nothing (R30): no pin holds an exec it continues.
		l.pinner, l.pinKey = opts.ExecPinner, opts.ExecPinKey
	}
	l.kernelBindHandoff = opts.KernelBindHandoff
	l.kernelListenHandoff = opts.KernelListenHandoff
	if opts.PlaneFS {
		l.walks.off = true
	}
	l.planeAttrs = opts.PlaneAttrs
	l.snapshotRefuses = opts.DenyReadSnapshot
	l.mcpRelayed = opts.MCPRelayed
	l.ownState = slices.Clone(opts.OwnState)
	l.runtimeDirs = hostRuntimeDirs()
	if opts.RuntimeDir != "" {
		l.runtimeDir = cleanPath(opts.RuntimeDir)
	}
	switch {
	case opts.openDeputy != nil:
		l.deputy = opts.openDeputy
	case opts.Deputy != nil:
		l.deputy = opts.Deputy
	}
	l.kernelNet = opts.KernelNet
	l.kernelDgrams = opts.KernelDatagrams
	l.modelRefresh = opts.modelRefresh
	if l.modelRefresh <= 0 {
		l.modelRefresh = modelRefreshEvery
	}
	c := l.guarded(l.resolveExecEntries(l.resolveUnixEntries(compile(pol))))
	c.live = opts.LiveBlocks
	l.table.Store(c)
	l.warnNoUnixDiag(l.table.Load())
	if err := l.pinAskScopes(pol.Rules); err != nil {
		return nil, fmt.Errorf("%w: pin ask scope: %v", ErrPolicy, err)
	}
	return l, nil
}

// guarded attaches the loop's models[] guard to the compiled table, resolved before the table is published
// (newModelGuard); nil when the table guards nothing. Run refreshes it.
func (l *Loop) guarded(c *compiled) *compiled {
	g := newModelGuard(c.pol.Rules.GuardedModels(), dns.Options{Lookup: l.lookup})
	l.guard.Store(g)
	c.guard = g
	return c
}

// resolveUnixEntries fills each pathname unix entry's and unix: ask scope's resolved path. It runs once, in New, before the
// agent runs, and the table is never rebuilt: resolving an entry again later would follow a symlink the agent
// may have planted where a declared path lies under its own write entry.
func (l *Loop) resolveUnixEntries(c *compiled) *compiled {
	for _, rules := range [][]unixRule{c.unix, c.unixAsk} {
		for i := range rules {
			if u := &rules[i]; u.path != "" {
				u.resolved, _ = resolveUnixDeclared(l.k, u.path)
			}
		}
	}
	for i := range c.unixAsk {
		if c.unixAsk[i].path != "" {
			c.unixAskPaths = true
		}
	}
	return c
}

// compile derives the immutable decision table from a policy.
func compile(pol *Policy) *compiled {
	c := &compiled{
		pol: pol, argvMax: pol.MaxArgvSize, record: pol.Record,
		pathSearch: pathSearchSet(pol.Rules),
	}
	if c.argvMax <= 0 {
		c.argvMax = DefaultMaxArgv
	}
	if c.record == "" {
		c.record = pol.Rules.Record
	}
	if ct := pol.Rules.Contract; ct != nil {
		c.execUnrestricted = ct.ExecUnrestricted()
		c.execAnonymous = ct.ExecAnonymous()
		if pol.Rules.ExecCommands.HasRules() {
			c.cmds = pol.Rules.ExecCommands
		}
		if c.cmds != nil && ct.Exec.DenyList() {
			c.codexHome = codexHomeSpellings(pol.Rules)
			c.hookState = runtimeGrantSpellings(pol.Rules, agent.HarnessStateGrant)
		}
		c.keyringAllowed = ct.Keyring
		c.ipcAllowed = ct.IPC
		c.mcp = mcpServers(pol.Rules)
	}
	c.netOpen = pol.Rules.NetUnrestricted()
	c.hostSockets = pol.Rules.HostSocketsRefused()
	c.datagrams = pol.Rules.DecidesDatagrams()
	t := decide.NewAdvisoryTablesFor(pol.Rules)
	c.fsResolved, c.fsBoth, c.fsIx = t.Resolved, t.Both, t.FS
	for _, r := range pol.Rules.FS {
		if r.Resolved != "" && decide.TrimDir(r.Resolved) != decide.TrimDir(r.Path) {
			if c.linkedFS == nil {
				c.linkedFS = map[string]bool{}
			}
			c.linkedFS[r.RuleName()] = true
		}
	}
	c.askRead = pol.Rules.AskReadRules()
	if pol.Rules.ReadsHeld() {
		c.heldReads = decide.NewHeldReadIndex(pol.Rules)
	}
	c.reasonReads = pol.Rules.ReasonReadsNotified()
	c.unix = unixRules(pol.Rules.Net)
	c.unixAsk = unixRules(pol.Rules.NetAsk)
	return c
}

// unixRules is the unix: entries of rules, each with its cleaned path, resolved later by resolveUnixEntries.
func unixRules(rules []agent.NetRule) []unixRule {
	var out []unixRule
	for _, r := range rules {
		if r.Proto != agent.ProtoUnix {
			continue
		}
		u := unixRule{name: r.RuleName(), raw: r.Raw}
		if r.Abstract {
			u.abstract = []byte(r.UnixPath)
		} else {
			u.path = cleanPath(r.UnixPath)
			u.resolved = u.path // until resolveUnixEntries replaces it
		}
		out = append(out, u)
	}
	return out
}

// trimDir is decide.TrimDir: a declared entry's path without its trailing slash, "/" kept.
func trimDir(p string) string { return decide.TrimDir(p) }

// Metrics returns a lock-free snapshot, safe concurrently with Run. The run's run_end reads it once after
// Run has returned, when every worker has finished and the counters are complete (I7, E25).
func (l *Loop) Metrics() Metrics {
	m := Metrics{
		Notifications: l.metrics.notifications.Load(),
		HeldMS:        l.metrics.heldUS.Load() / 1000,
		Anomalies:     l.metrics.anomalies.Load(),
		Orphaned:      l.metrics.orphaned.Load(),
		Starved:       l.metrics.starved.Load(),
		ExecMissing:   l.metrics.execMissing.Load(),
		OrderLost:     l.order.lost.Load(),
	}
	if c := l.table.Load(); c != nil && (c.cmds != nil || l.pinner != nil) {
		m.ExecRules = &record.ExecRules{Refused: l.metrics.cmdRefused.Load(), Ambiguous: l.metrics.cmdAmbiguous.Load(),
			Asked: l.metrics.cmdAsked.Load(), PinRefused: l.metrics.pinRefused.Load()}
	}
	return m
}

// Armed is closed once Run owns the listener and its workers are about to wait on it. A launcher that
// execs the target before then would leave it blocked in the kernel with nobody to answer it, so the
// launcher waits on this. It is closed exactly once per Loop, and a Run that fails to start closes it too,
// so a caller blocked on it is never stranded.
func (l *Loop) Armed() <-chan struct{} { return l.armed }

// Started reports whether the loop actually armed, as opposed to returning before it could.
//
// Armed closing does not answer that on its own. Run disarms on every return path, including an
// immediate failure, so that a caller waiting on Armed is never stranded — and that means both
// outcomes look identical to a caller watching only the channel. A caller that selects on Armed and
// on Run's error has both ready at once when the start failed, and Go picks among ready cases at
// random, so the failure is missed about half the time unless it asks this.
func (l *Loop) Started() bool { return l.armedOK.Load() }

// arm marks the loop as running and releases Armed. Only the point where every worker is on its way
// into poll(2) calls it.
func (l *Loop) arm() { l.armedOK.Store(true); l.disarm() }

// disarm closes Armed exactly once.
func (l *Loop) disarm() { l.armedOnce.Do(func() { close(l.armed) }) }

// Run drains the listener until ctx is cancelled or the listener fails, then closes the notify fd and
// returns. It answers every notification exactly once (or not at all, when the target died first, R19) and
// starts and joins every worker itself, standbys included. The one goroutine it does not join is a relay
// still inside a connect or Fast-Open send on a duplicate: that syscall has no deadline by design (§4),
// which is the whole reason it is not on a worker, so Run's return is bounded by the run's cancellation
// rather than by the network. Such a goroutine answers nothing (relayCancelled, I3) and closes its own
// duplicate when the kernel finally returns.
//
// Cancellation travels on an internal self-pipe, not on the fd: SECCOMP_IOCTL_NOTIF_RECV sleeps on a
// semaphore that neither a close nor a signal (the ioctl restarts on EINTR) reliably interrupts, so each
// worker polls the listener and the wake fd and calls RECV only once a notification is pending. A
// cancelled ctx therefore returns within one poll slice, and the fd is closed after the last worker has
// left the ioctl — never underneath it (E24, corrected: see the package notes).
//
// It returns nil on a clean shutdown, including the listener hanging up when the run's last task exits,
// and a wrapped error for a listener failure the loop cannot continue through, a listener closed under a
// live run included (receive). A second call returns
// ErrAlreadyRunning.
func (l *Loop) Run(ctx context.Context) error {
	defer l.disarm() // a failed start must not strand a caller waiting on Armed
	if !l.running.CompareAndSwap(false, true) {
		return ErrAlreadyRunning
	}
	defer l.listenerBindings.clear()
	defer l.closeAskScopes()
	if err := l.openWake(); err != nil {
		// The listener is this call's to close either way: a caller that cannot start the loop has no
		// other owner for it, and a second Run is refused.
		if cerr := l.k.CloseListener(); cerr != nil {
			l.log.Warn("supervisor: closing the listener after a failed start", "err", cerr)
		}
		return err
	}
	defer l.closeWake()
	stop := make(chan struct{})
	var watcher sync.WaitGroup
	watcher.Add(1)
	go func() {
		defer watcher.Done()
		select {
		case <-ctx.Done():
			l.wake()
		case <-stop:
		}
	}()

	var (
		workers sync.WaitGroup
		failed  sync.Once
		err     error
	)
	wctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// start is also how a parked relay backfills the pool (R21, backfill), so it is published on the
	// Loop before the first worker exists: a worker can only reach it once it is running, which is
	// ordered after this write by the go statement below.
	start := func() {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if werr := l.worker(wctx); werr != nil {
				failed.Do(func() { err = werr })
				cancel()
				l.wake()
			}
		}()
	}
	l.spawn = start
	for i := 0; i < l.workers; i++ {
		start()
	}
	// The models[] guard's names re-resolve on TTL for as long as the loop decides (modelGuard). Joined
	// below like the workers, so nothing of this Loop outlives Run but a relay still in its syscall.
	var refresher sync.WaitGroup
	refresher.Add(1)
	go func() {
		defer refresher.Done()
		t := time.NewTicker(l.modelRefresh)
		defer t.Stop()
		for {
			select {
			case <-wctx.Done():
				return
			case <-t.C:
				if g := l.guard.Load(); g != nil {
					g.refresh(wctx)
				}
			}
		}
	}()
	// Every worker exists and is on its way into poll(2) on the listener: the loop is armed, and a
	// launcher blocked on Armed may let the child's execve proceed.
	l.arm()
	workers.Wait()
	cancel()
	refresher.Wait()
	close(stop)
	watcher.Wait()
	if cerr := l.k.CloseListener(); cerr != nil && err == nil {
		err = fmt.Errorf("%w: %w", ErrListener, cerr)
	}
	return err
}

// openWake creates the self-pipe cancellation travels on.
func (l *Loop) openWake() error {
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return fmt.Errorf("%w: wake pipe: %w", ErrListener, err)
	}
	l.wakeR, l.wakeW = p[0], p[1]
	return nil
}

// wake makes every worker's poll return. The pipe is level-triggered and never drained, so one byte stops
// the whole pool and a lost write (EAGAIN on a full pipe) means the pipe is already readable anyway.
func (l *Loop) wake() {
	if l.wakeW >= 0 {
		_, _ = unix.Write(l.wakeW, []byte{1})
	}
}

// closeWake releases the self-pipe after every worker has returned.
func (l *Loop) closeWake() {
	for _, fd := range [...]*int{&l.wakeR, &l.wakeW} {
		if *fd >= 0 {
			_ = unix.Close(*fd)
			*fd = -1
		}
	}
}

// worker runs one synchronous receive -> dispatch -> respond loop (R21). It returns nil on shutdown and an
// error for a listener failure: one the loop cannot continue through, which Run returns.
func (l *Loop) worker(ctx context.Context) error {
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, done, err := l.receive(ctx)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if n == nil {
			continue
		}
		l.metrics.notifications.Add(1)
		l.handle(n)
		if n.replaced {
			// A standby took this worker's place in the pool while it waited on a relayed connect or
			// Fast-Open send (R21): receive capacity was restored then, so this goroutine retires now
			// rather than leaving the pool one worker over its size for the rest of the run.
			l.standby.Add(-1)
			return nil
		}
	}
}

// backfill keeps the pool's receive capacity intact while this worker waits on a relayed syscall.
//
// R21 sizes the pool for handlers that are microseconds long and E17 reads pool exhaustion as
// npm-install-shaped latency. R9's connect-on-duplicate is neither: the duplicate shares the target's
// open file description, so a blocking socket gives a blocking connect(2), and against a route that
// blackholes SYNs that is the kernel's whole retry schedule (~127 s at the default tcp_syn_retries=6)
// with the worker parked inside it. Four of those — one connection pool dialling one declared host that
// a firewall has started dropping — park every worker of the default pool, and then nothing is received
// at all: every openat, execve, mkdir and rename of every thread of the run stays trapped in the kernel
// until one frees up. The agent is not slowed down, it is stopped.
//
// So a worker about to park hands its place to a standby and retires when it returns (the worker loop,
// via notif.replaced). Receive capacity stays at Workers however many relays are outstanding; maxStandby
// bounds the relays a handler is still parked on, and relayCeiling every relay goroutine, including the
// ones whose handler has already returned. It reports whether a standby was started.
func (l *Loop) backfill(n *notif) bool {
	if l.spawn == nil || n.replaced {
		return false
	}
	if l.standby.Add(1) > maxStandby {
		l.standby.Add(-1)
		// relay asks again on every poll tick, and a later tick may find a slot; the relay is counted and
		// logged once, since starved counts the relays maxStandby could not cover, not the ticks.
		if !n.starved {
			n.starved = true
			l.metrics.starved.Add(1)
			l.log.Warn("supervisor: relay backfill at its ceiling, the pool is running short",
				"standby", maxStandby)
		}
		return false
	}
	// Set before the standby exists, so the retire decision cannot be lost if this worker's handler
	// returns the moment the standby starts.
	n.replaced = true
	l.spawn()
	return true
}

// relayCeiling is how many relay goroutines may be alive at once (E28). Every one a handler is still
// waiting on runs on a worker or a standby, so Workers+maxStandby is exactly what the pool can have
// parked, and while every relay is waited on the ceiling is never reached. What reaches it is relays
// nobody waits on any more: the target abandoned the syscall (E35) and, below 5.19 or without
// WAIT_KILLABLE_RECV, the kernel restarts it into a fresh notification and a fresh relay, while the first
// one holds its duplicate for as long as the syscall takes — the whole SYN retry schedule against a
// blackholed route. Signalled on a loop, that grows goroutines and descriptors with the signal rate, not
// with anything the pool bounds. With the flag only a fatal signal abandons a received notification, so
// the relays past the pool are those of targets already killed, each still bounded by its syscall. The
// restart the flag leaves on a kernel without cce436aa (relayOrphaned) follows an answered relay, whose
// goroutine has already returned, so it adds nothing here.
func (l *Loop) relayCeiling() int64 { return int64(l.workers) + maxStandby }

// receive waits for and takes one notification. Exactly one worker is inside poll+RECV at a time, so RECV
// is only ever called with a notification already pending and never parks the pool. done reports a
// shutdown (cancelled context, wake, or a listener that hung up).
//
// Nothing closes the listener while a worker can reach it — shutdown travels on the wake pipe and Run
// closes the fd after the last worker has left — so an fd that poll reports not open (POLLNVAL) or that
// poll or RECV fails EBADF, EINVAL or ECANCELED on is a listener lost under a live run, not a shutdown,
// unless the context has already ended (every wake follows a cancel of ctx). Returned as ErrListener, it
// makes Run fail and the runtime end the run, rather than Run returning nil while the agent runs on
// with every notified syscall failing ENOSYS and nothing recording why (§7).
func (l *Loop) receive(ctx context.Context) (n *notif, done bool, err error) {
	l.recvMu.Lock()
	defer l.recvMu.Unlock()
	if ctx.Err() != nil {
		return nil, true, nil
	}
	state, err := l.k.Wait(l.wakeR, pollTimeoutMS)
	if err != nil {
		if ctx.Err() != nil {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("%w: %w", ErrListener, err)
	}
	switch state {
	case waitWake, waitHup:
		return nil, true, nil
	case waitInvalid:
		if ctx.Err() != nil {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("%w: listener fd not open (POLLNVAL)", ErrListener)
	case waitTimeout:
		return nil, false, nil
	}
	var raw sysNotif
	if err := l.k.Recv(&raw); err != nil {
		switch {
		case errors.Is(err, unix.ENOENT):
			// The notifying thread died between poll and RECV: nothing to answer (R19, E1).
			return nil, false, nil
		case ctx.Err() != nil:
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("%w: %w", ErrListener, err)
	}
	n = newNotif(&raw)
	l.admit(n)
	// The worker context reaches the handler here rather than through every handlerFunc signature: only
	// the relayed connect/send needs it, and only to stop waiting on a syscall the run no longer needs.
	n.done = ctx.Done()
	return n, false, nil
}
