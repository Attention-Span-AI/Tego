// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"

	"sync"
	"sync/atomic"

	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/internal/platform/startphase"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/source"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/deputy"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/dnsbroker"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/internal/runtime/limits"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"

	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/harness"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ErrDeps is an incomplete or inconsistent Deps: a caller bug, always before run_start (R2).
var ErrDeps = errors.New("runtime: invalid dependencies")

// ErrPrivilegedTarget is a root launcher with no unprivileged account to drop the agent to.
// no_new_privs is set by default (ADR 0033), but it does not drop an existing root identity. A run
// that cannot name a real target uid is refused before the child is created. See privilegedTarget.
var ErrPrivilegedTarget = errors.New("runtime: root launcher with no unprivileged uid to drop the agent to")

// Clock abstracts wall and monotonic time for tests.
type Clock interface {
	Now() time.Time
	MonoNS() uint64
}

// Deps are the injected components of one run (P0-DESIGN §2.4). Nil optional members disable that source.
type Deps struct {
	Config  *config.Machine
	Cgroups cgroup.Manager
	Enforce enforce.Backend
	// Sink replaces the pipeline's terminal, which is otherwise the run's own ledger writer;
	// tests use it to read what the stages produced. run_start and run_end are written by the
	// ledger either way, because they are the run's record and not events a producer raised.
	Sink    source.Sink
	Clock   Clock         // nil = system clock
	Observe source.Source // tier 2 eBPF recorder, optional; a caller that has one already built
	Capture []source.Source
	// Extra are sources that are neither the tier's recorder nor model capture: the MCP relay (ADR 0126 §4). They
	// start and stop with the others and their loopback listeners are admitted (allSources), but they never satisfy
	// the contract's capture: (captureSources).
	Extra []source.Source
	// ObserveFactory builds the tier's kernel recorder once the enforcement handle exists, which is
	// the earliest moment its ring buffer can be named: the pin directory is keyed by a build hash
	// Prepare computes. A source the caller builds before Run, the way a forwarder is built, cannot
	// work here, because there is nothing to read until the tier has attached.
	//
	// It is a factory rather than a constructed source because internal/runtime cannot build one
	// itself: internal/runtime/observe imports internal/runtime (for ActivityStamper,
	// DecisionPlaneNamer, PathHookNamer, KernelReading, Queue and the Gap* names; the Source contract
	// is internal/runtime/source), so the dependency arrow only points one way and the caller closes
	// over observe.New instead.
	//
	// Nil means this build starts no kernel recorder, and so does a tier whose Handle is not an
	// enforce.KernelRecorder. Either way the run says so with a gap rather than a silence.
	ObserveFactory func(bpfHash string) (source.Source, error)
	// CaptureGaps are the shortfalls the caller's own capture selection already implies —
	// capture.Select's second return, a mechanism this binary does not carry or could not build.
	// They are written to the ledger right after run_start, because a capture shortfall is always a
	// gap event and never a silence (docs/p0/capture-derive.md §8 I4).
	CaptureGaps []source.Gap

	// Build is what run_start records about this binary; internal/cli fills it from its own
	// version banner so pkg/spec and the runtime never read link-time variables of the CLI.
	Build Build
	// Stdio are the agent's standard streams; a nil member becomes /dev/null.
	Stdio Stdio
	// Launcher starts the child stage; nil means a fresh launch.Launcher over /proc/self/exe.
	Launcher *launch.Launcher
	// ContractYAML is the compiled contract's bytes, copied into the run directory at Open (§3).
	ContractYAML []byte
	// AnchorPath is the chain.log the run appends its head to at Close: the invoking user's
	// ~/.tego/chain.log (beside the ledger root for an account with no home), which the CLI resolves
	// with AnchorPath and opens once with ledger.ProbeAnchor before calling Run. "" is the ledger's
	// default beside the ledger root (ledger.DefaultAnchorPath), which only tests rely on.
	AnchorPath string
	// OwnStateRestored is what the caller's RestoreOwnState restored before the run (the CLI calls it before it reads
	// the machine config and again before it compiles), which the run records right after run_start, one gap
	// why=own-state-mode-restored each; nil for none.
	OwnStateRestored []ModeRestored
	// UserState is the user's own state of tego's the caller gave back before it read the machine config: OwnState's
	// Home and Log, ~/.tego with the per-user config layer and tego.log in it. The run gives it back again at its end,
	// beside its own (restoreRunState), so a mode its agent took is not left for the processes after it, which skip a
	// layer they cannot read (`tego gc` refuses one). The zero value names none; its other fields are not read.
	UserState OwnState
	// ParentRun is the run this one says it is nested in (tego run: the enclosing run's TEGO_RUN_ID, else
	// TEGO_PARENT_RUN), and the child's TEGO_PARENT_RUN; "" is itself a value the child receives. A value that is not
	// a run id is ErrDeps; a valid one is recorded as run_start.parent_run, the launcher environment's claim (ADR 0073).
	ParentRun string
	// Labels are the caller's labels for the run, recorded as run_start.labels (ADR 0073); nil or empty for none.
	// Labels identity.ValidLabels refuses are ErrDeps.
	Labels map[string]string
	// Role is what the run is for, recorded as run_start.role (ADR 0073): identity.RoleAgent, the zero value, for the
	// agent's own run. A role identity.Role.Valid does not know is ErrDeps.
	Role identity.Role
	// Started is called once per run, after run_start is durable and the gaps that follow it are queued, and before
	// the agent is released (runtime-launch.md §4.1 step 9a, ADR 0073): the one point where the run id and its
	// directory exist and the agent has not run. The agent waits for it to return. An error ends the run before the
	// agent execs: run_end reason error with a detail naming the hook, exit 125. A panic is not recovered (R14). nil
	// calls nothing.
	Started func(StartedRun) error
	// AskPending, when set, is told of each request the run holds for a person, once `tego ask` lists it, and never of
	// one a standing answer decides (ADR 0122). It runs on the goroutine that holds the agent's operation, so it must
	// return at once: the CLI's desktop notice queues the request and drops it when one is already queued.
	AskPending func(AskPending)
	// Environ is the environment env.pass/deny/set are resolved against; nil means os.Environ().
	Environ []string
	// Cwd is the agent's working directory; "" means the launcher's own.
	Cwd string
	// ContractSource is the contract file the launching user named, by path or by registry name, which run_start
	// records (agent-contract.md R26); nil for a contract tego generated.
	ContractSource *record.ContractSource
	// RunStartExtras are the reserved run_start blocks (record minors 32 to 34). Run copies them,
	// checks the copy at record.Minor (record.RunStartPayload.ValidateFields) and writes it into run_start as given; a
	// block Minor does not reach, or a malformed one, is ErrDeps before the run exists. The zero value adds nothing,
	// and run_start is then byte for byte what it is without the field.
	RunStartExtras RunStartExtras
	// Rand is the randomness NewRunID consumes; nil means crypto/rand.
	Rand io.Reader
	// MachineID is the content of /etc/machine-id, hashed into the run id's host component; nil
	// means read it here, and an unreadable file degrades to the hostname (never a hard failure).
	MachineID []byte
	// Logger receives operational detail; nil discards it. The ledger is never written through it.
	Logger *slog.Logger
	// Signals is the channel the launcher's signal rules consume; nil means launch.Notify().
	Signals <-chan os.Signal
	// StdinIsTTY overrides the terminal test on stdin (§6: a terminal already delivered SIGINT to
	// the whole process group, so the launcher does not re-send it).
	StdinIsTTY *bool

	// Prices is the machine's price table, loaded once by the caller: the check happens at `run`
	// startup so the one warning a missing or refused table produces is printed where the user can
	// see it (limits-check-doctor-cli.md §7), which a run's own logger cannot do. A nil table
	// prices nothing, so only the cost ceiling (R2) is disabled; tokens, wall, stall and repeats
	// still hold.
	Prices *limits.PriceTable
	// Warn prints one warning line where the user sees it (the CLI's stderr, before the agent runs), for a
	// condition the run also records (a gap, or run_start's best_effort), under its own diagnostic code (WarnSwapUncapped,
	// WarnHeldUnavailable, WarnHeldLabel); nil prints nothing.
	Warn func(code, what string)
	// PriceGap is the `why` of the gap this run records because no price table loaded (or the one that
	// loaded lists no model): limits.GapNoPriceTable or limits.GapVersionMismatch (E15, R32). It is empty
	// when a table did load, even one that prices no model (refuseUncountedBudget refuses a cost_usd budget under
	// that table itself, limits.PriceTable.PricesAnyModel). A missing table fails only a run whose contract declares
	// cost_usd (refuseUncountedBudget, R32); any other run goes on with cost not estimated, and the gap is how the
	// ledger says the cost column of this run is not comparable with another's.
	PriceGap string
	// Harness is the provisioner for a harness (agent-contract.md R27, ADR 0062), nil for one this build cannot
	// provision; a nil Harness provisions nothing for any harness. internal/cli connects internal/adapters here.
	Harness func(harness.Name) Provisioner
}

// AskPending is what Deps.AskPending is told of one held request: the run, the ask id `tego approve` takes and the
// operation tego named. The target and the rule are left out on purpose: the agent chooses its target, and a notice
// shown outside the run must not carry text the agent wrote (ADR 0122).
type AskPending struct {
	Run   identity.RunID
	AskID string
	Op    string
}

// StartedRun is what Deps.Started is told about the run it is called for.
type StartedRun struct {
	// ID is the run's id.
	ID identity.RunID
	// Dir is the run's directory, whose events.jsonl holds run_start.
	Dir string
}

// Build is the binary's identity as run_start records it (spec/record/v1 run_start).
type Build struct {
	Version string
	Commit  string
	// BPFHash is the build's own bpf_hash, "" for a build without the objects. run_start does not
	// record it as given: prepareEnforcement replaces it with the prepared tier's own hash, the pin
	// directory the run's programs really live in, and with "" at a tier that loads no BPF programs
	// (record-ledger.md §2.2: "empty in tier 1").
	BPFHash string
	Kernel  string
	Parsers map[string]string
}

// Stdio are the agent's standard streams.
type Stdio struct {
	In, Out, Err *os.File
}

// Result is the outcome of a run.
type Result struct {
	RunID    string
	ExitCode int
	Reason   string // exit | signal | stopped | oom | pids | limit | exec-failed | error
	// RecordErr is the ledger's Close error, nil when run_end, the fsyncs and the chain anchor all landed.
	// It is not the agent's outcome, and the caller reports it apart: a run whose record is incomplete, or
	// is complete but unanchored (ledger.ErrAnchorWrite), is never reported as a plain exit
	// (record-ledger.md §7).
	RecordErr error
}

// QueueCapacity is the events channel's depth (P0-DESIGN §2.4): producers never block the agent, a
// full queue drops and counts instead.
const QueueCapacity = 4096

// limitPollInterval is how often the cgroup watcher diffs memory.events and pids.events against its
// baseline. cgroup.events wakes on the populated transition only, so oom_kill and pids max — the two
// counters R10/R11 turn into a terminal reason — are polled (docs/p0/runtime-launch.md §11 notes the
// same split).
const limitPollInterval = 200 * time.Millisecond

// maxLimitReadFailures is how many consecutive unreadable polls of memory.events/pids.events the
// watcher tolerates before it gives up on them for the rest of the run.
const maxLimitReadFailures = 5

// killTimeout bounds the reap after an escalation: cgroup.kill delivers SIGKILL asynchronously (R10).
const killTimeout = 10 * time.Second

// Run executes cmd under the compiled contract with the given dependencies and blocks until the run
// ends (docs/p0/runtime-launch.md §4, P0-DESIGN §4.1).
//
// Pre: rt is compiled against deps.Config, which passed its trust checks, and deps.Enforce is the
// tier internal/cli already selected — tier selection and machine-config failures are the CLI's own
// exit 125 [tier-unavailable]/[config-untrusted] before Run is ever called (§5 R2, invariant 10).
//
// Post: exactly one run_end is the last line of the run's ledger on every return path but an
// unrecovered panic (R14). A non-nil error is returned only for a failure before run_start, and
// always means exit 125: everything after run_start folds into Result.Reason and run_end (R2), and
// every resource this call acquired is released in the order of R8 whatever else went wrong (R18).
func Run(ctx context.Context, rt *agent.RuleTable, cmd []string, deps Deps) (Result, error) {
	r, err := newRunner(rt, cmd, deps)
	if err != nil {
		return Result{ExitCode: identity.ExitLauncher, Reason: record.RunEndError}, err
	}
	return r.run(ctx)
}

// runner holds one run's state. Every field is owned by this call: nothing is global (§9).
type runner struct {
	dnsBroker        *dnsbroker.Broker
	dnsBrokerStarted bool
	dnsDirectory     *dnsDirectory
	reapHandoff      *os.File // the DNS reaper's target handoff (startDNSReaper), until startReaper writes or closes it
	askBroker        *ask.Broker
	askRelays        *ask.RelayPool
	askCtx           context.Context
	askOwner         uint32 // the uid ask.sock serves beside root: the invoking user's (askPeerAuthorize)
	rt               *agent.RuleTable
	cmd              []string
	deps             Deps
	log              *slog.Logger

	id      identity.RunID
	agentID identity.AgentID
	dir     string

	writer *ledger.Writer
	// listed says the run is in the ledger root's live index (openLedger), for clearLive.
	listed bool
	// kernelRecord is the tier's own recorder, built in prepareEnforcement once the handle has named
	// its ring buffer; nil when the tier writes none or the caller supplied no factory.
	kernelRecord source.Source
	// kernelDecided closes once startWorkers has started the run's sources, or failed to: from then on
	// kernelReads says whether the kernel recorder reads this run's ring (kernelConnects). kernelReads is
	// written before the close and read only after it.
	kernelDecided chan struct{}
	kernelReads   bool
	// trackingOnce joins the recorder's prompt notification with the independent durable counter check.
	trackingOnce   sync.Once
	trackingFailed atomic.Bool
	// planeFS is set when the tier's filter leaves fs mutations its decision plane decides unnotified
	// (enforce.PlaneFilterer, TIER3-PLAN T16): the supervisor then keeps no walk cache (supervisor Options.PlaneFS).
	planeFS bool
	// steps derives the run's model turns and attributes actions to them; nil when nothing captures. Only the
	// attribute stage uses it in the run; the tests read the run's own instance through it.
	steps *derive.Steps
	// hookQueues call the capture sources' process hooks off the recorder's drain goroutine (hookQueue).
	hookQueues []*hookQueue
	// stopWait overrides sourceStopWait; tests shorten it.
	stopWait time.Duration
	// stuckStops are the Stops of sources shutdown gave up on (stopSource): each is closed when its Stop
	// returns, and releaseKernelState releases the handle only after all of them (R8).
	stuckStops []<-chan struct{}
	cgm        cgroup.Manager
	cg         cgroup.Cgroup
	handle     api.Handle
	launcher   *launch.Launcher
	child      *launch.Child
	// deputy is the run's open deputy (ADR 0041 D2), when the contract chose gate.completion: held and the stage
	// started it; nil otherwise, and then its held-open cells stay best effort (run_start best_effort).
	deputy *deputy.Client
	// deputyStart is the deputy's start time as /proc read it right after its hello, while it was this process's
	// unreaped child (0 when that read failed): with its pid, what names it to the kernel recorder (SetSkipProcess).
	deputyStart uint64
	signals     *launch.SignalHandler
	signalCh    <-chan os.Signal
	unnotify    func()
	// reasonFile is the run's readable copy of last-refusal.json (createRuntimeDir), "" when there is none.
	reasonFile string
	// harness is what provisionHarness made for the run's harness (harness.go).
	harness harnessState

	queue *Queue
	pipe  *pipeline
	// pipeStop ends the pipeline goroutine. It is shutdown's and unwind's to call, never a sibling worker's
	// failure: the pipeline keeps reading the queue while awaitExit kills and reaps the tree.
	pipeStop context.CancelFunc
	sup      *supervisor.Loop
	budget   *limits.Watcher
	// activity is the run directory's activity sidecar the watcher publishes to (newBudget), nil when it could
	// not be made; closed once the workers have stopped (closeActivity).
	activity *ledger.Activity
	group    *group
	started  chan struct{}
	sources  []source.Source

	// pipeDone is closed when the pipeline goroutine returns; shutdown pumps the queue after it while the
	// sources stop (pumpWhileStopping).
	pipeDone chan struct{}
	// killWait bounds awaitEmpty's wait for a killed tree; zero is killTimeout, production's.
	killWait time.Duration

	// dnsSet is the net.allow address set and resolver list the supervisor decides connects against;
	// nil for a tier with no seccomp filter.
	dnsSet *dns.Set
	// resolvers is this run's one resolver list, read once by runResolvers: the supervisor's port-53
	// exception and tier 2's port-53 rows are both built from it, so they cannot name different servers.
	resolvers     []netip.AddrPort
	resolversRead bool
	// dnsOptions and dnsTick configure the resolver set and its worker; the zero values are production's
	// (the system resolver, dnsRefreshTick). They are fields so a test can drive a TTL refresh through
	// startNotifyLoop itself, which is where the worker that hands the tier its refreshes is started.
	dnsOptions dns.Options
	dnsTick    time.Duration
	// hostAddrs is the snapshot of this host's own addresses refreshDenied reads, for the table Prepare is
	// given and for the set's refreshes (hostSnapshot); nil until the run first needs it, when production's,
	// net.InterfaceAddrs and the local routing table taken again once hostAddrsMaxAge old, is made. A field so
	// a test can give the host addresses of its own.
	hostAddrs *hostAddrs
	// rowsNet is the net section the tier was prepared with (rowsTable), from which refreshDNS starts.
	rowsNet []agent.NetRule
	// landlockAuditGap is the why of the gap emitLandlockAuditGap writes after run_start, as landlockFlags
	// chose it: empty when the run did not opt into the kernel's audit, or opted in and found it on.
	landlockAuditGap string
	// swapUncapped are the active swap areas createCgroup found the run's memory cap cannot keep the agent out
	// of (cgroup.UncappedSwap); emitLimitsGap records them.
	swapUncapped []string
	// limitBase is memory.events oom_kill and pids.events max as createCgroup read them, before any
	// process existed in the cgroup; ok is false when they could not be read then.
	limitBase struct {
		oom, pids uint64
		ok        bool
	}

	anchored   atomic.Bool
	runtimeDir string
	// runtimeLock is the flocked lock file in runtimeDir, held for the run's life so the next launch's sweep leaves the
	// directory alone (makeRunRuntimeDir); nil when there is no directory.
	runtimeLock *os.File
	// codexHome is the run's own CODEX_HOME under runtimeDir, "" when none was written (codexhome.go).
	codexHome string
	// codexHomeID is the device and inode of the directory writeCodexHome made, which grantCodexHome requires the
	// path still to name before it grants it.
	codexHomeID   fileID
	launcherStart uint64
	// rootMarked is a root launcher's record that it launched this run (rootmark.go), removed with the scope.
	rootMarked bool
	stopGrace  time.Duration
	// notifyFD owns the seccomp listener taken from the child stage (launch.Child.WaitNotifyFD) until
	// startNotifyLoop moves it into supervisor.New, which leaves it nil (ADR 0023 C7); nil for a tier without
	// a filter. Only a run that never reached New closes it here (releaseKernelState).
	notifyFD *sys.FD

	// terminal state, written by the wait phase and read when run_end is built.
	wait launch.WaitResult
	// terminal is a reason this package decided itself rather than read off the agent's wait
	// status: oom and pids from the cgroup watcher (R10, R11), limit from the budget watcher
	// (limits-check-doctor-cli.md §4 trip), error when the agent never got to run at all. Three
	// workers can decide one, so termMu guards it and the first decision stands: the reason that
	// stopped the run is the one that got there first, and a later one is the consequence.
	termMu   sync.Mutex
	terminal identity.EndReason
	detail   string
	// quiesced is set once no process of the run can spend any more: the run's cgroup is empty (awaitEmpty),
	// or tego's own teardown has begun (the kill awaitExit or awaitEmpty sends when ctx ends, or shutdown).
	// A report of spend capture could not count that arrives after it no longer decides the run's end
	// (captureUnmetered): what reaches capture then is tego's own shutdown aborting a request, or the loss of
	// one a process that has exited made. The main process's exit alone does not set it: a descendant that
	// outlives it (`sh -c 'agent & exit 0'`) can still spend, and its spend must still be counted.
	quiesced atomic.Bool
	// pause is the run's pause as the launcher applied it (livepause.go, record.MinorLiveControl).
	pause pauseState
}

// fail records reason with detail as the run's end unless one was already decided, and reports whether
// this call decided it. detail is set under the same lock, since the decider can be any worker.
func (r *runner) fail(reason identity.EndReason, detail string) bool {
	r.termMu.Lock()
	defer r.termMu.Unlock()
	if r.terminal != "" {
		return false
	}
	r.terminal = reason
	if detail != "" {
		// An empty detail keeps one noteDetail already recorded (setTerminal's case).
		r.detail = detail
	}
	return true
}

// endRun is how a failure that must stop the run ends it: it records reason and detail as fail does, logs
// logMsg when this call decided the end, and kills the run's tree, warning killMsg if the kill fails. The
// kill happens even when another worker decided the end first, as a tree that outlives its verdict is the
// worse outcome.
func (r *runner) endRun(reason identity.EndReason, detail, logMsg, killMsg string, attrs ...any) {
	if r.fail(reason, detail) {
		r.log.Error(logMsg, attrs...)
	}
	if r.cgm != nil && r.cg.Path != "" {
		if kerr := r.cgm.Kill(r.cg); kerr != nil {
			r.log.Warn(killMsg, "err", kerr)
		}
	}
}

// noteDetail adds detail to the run's end when nothing has said why it ended yet. The caller is a worker that
// did not decide the reason, so it takes termMu like every writer of detail and never replaces the detail of
// a reason another worker already decided.
func (r *runner) noteDetail(detail string) {
	r.termMu.Lock()
	defer r.termMu.Unlock()
	if r.detail == "" {
		r.detail = detail
	}
}

// ledgerFailed is the pipeline's report that the ledger refused a line (a full disk, a quota, EIO). The
// record can no longer say what the agent does, so the run ends here: reason error, the cause in detail, and
// the tree killed, as record-ledger.md §7 says. The events already queued are drained and the run_end is
// written if the file takes it; if it does not, Close's error reaches the caller (Result.RecordErr).
func (r *runner) ledgerFailed(err error) {
	r.endRun(identity.ReasonError, "ledger: "+err.Error(), "run: the ledger refused a line; ending the run",
		"run: kill after a ledger failure", "err", err)
}

// captureLost ends a run with a token or cost budget once the queue has dropped some of its model traffic,
// even after the capture lane's wait: the budget could no longer see what the run spent. A run with no such
// budget keeps running with the loss counted in its channel-full gap.
func (r *runner) captureLost(n int64) {
	lim := r.rt.Limits
	if !lim.Bounded(agent.BudgetTokens) && !lim.Bounded(agent.BudgetCostUSD) {
		return
	}
	if r.quiesced.Load() {
		// As captureUnmetered: a drop counted once no process can spend more changes neither the end reason
		// nor the exit code (ADR 0037).
		r.log.Warn("run: model traffic dropped after the run quiesced", "exchanges", n)
		r.emitGap(source.Gap{What: record.GapCapture, Why: GapUnmeteredAfterExit, Count: n})
		return
	}
	r.endRun(identity.ReasonError, fmt.Sprintf("capture: %d model exchanges were dropped before the budget saw them; a token or cost budget cannot be enforced", n),
		"run: model traffic dropped under a budget; ending the run", "run: kill after lost model traffic", "dropped", n)
}

// setTerminal records the run's terminal reason unless one was already decided, and reports
// whether this call is the one that decided it.
func (r *runner) setTerminal(reason identity.EndReason) bool { return r.fail(reason, "") }

// newRunner validates the caller's arguments; every failure here is a caller bug before any
// resource exists.
func newRunner(rt *agent.RuleTable, cmd []string, deps Deps) (*runner, error) {
	switch {
	case rt == nil:
		return nil, fmt.Errorf("%w: no rule table", ErrDeps)
	case len(cmd) == 0 || cmd[0] == "":
		return nil, fmt.Errorf("%w: no command", ErrDeps)
	case deps.Config == nil:
		return nil, fmt.Errorf("%w: no machine config", ErrDeps)
	case deps.Enforce == nil:
		return nil, fmt.Errorf("%w: no enforcement backend", ErrDeps)
	case rt.Contract == nil:
		return nil, fmt.Errorf("%w: the rule table carries no contract", ErrDeps)
	}
	if err := validIdentity(deps); err != nil {
		return nil, err
	}
	if err := refuseAdjustable(rt, false); err != nil {
		return nil, err
	}
	// The run keeps its own copy, so the blocks it checked are the ones run_start carries.
	deps.RunStartExtras = deps.RunStartExtras.clone()
	if err := deps.RunStartExtras.check(); err != nil {
		return nil, err
	}
	if rt.Contract.Net != nil && len(rt.Contract.Net.HTTP) != 0 &&
		(rt.HTTP == nil || rt.Capture != agent.CaptureForwarder || deps.Enforce.Tier() == backend.TierObserve) {
		return nil, fmt.Errorf("%w: net.http requires compiled forwarder policy and an enforcing tier", ErrDeps)
	}
	if rt.Contract.Net != nil && rt.Contract.Net.Proxy != nil &&
		(rt.Proxy == nil || rt.Capture != agent.CaptureForwarder || deps.Enforce.Tier() == backend.TierObserve) {
		return nil, fmt.Errorf("%w: net.proxy requires compiled forwarder policy and an enforcing tier", ErrDeps)
	}
	if err := rt.Proxy.ValidateLimits(rt.Limits); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDeps, err)
	}
	log := deps.Logger
	if err := validateNetworkRequest(rt, deps); err != nil {
		return nil, err
	}
	if err := validateAskRequest(rt, deps); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if deps.Clock == nil {
		deps.Clock = systemClock{}
	}
	if deps.Rand == nil {
		deps.Rand = rand.Reader
	}
	agentID, err := identity.ParseAgentID(rt.Contract.Name)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrDeps, err)
	}
	grace := deps.Config.StopGrace.Value
	if grace <= 0 {
		// A machine config that lost its stop_grace would otherwise leave the run with no signal
		// handling at all (the handler refuses a non-positive grace), which is worse than the
		// documented default (R9: stop_grace comes from the machine, never hardcoded — this is the
		// same default the built-in layer carries, used only when the value is missing entirely).
		grace = config.DefaultStopGrace
	}
	return &runner{
		rt: admitLoopback(rt.AtTier(deps.Enforce.Tier()), allSources(deps)), cmd: cmd, deps: deps, log: log, agentID: agentID,
		stopGrace: grace,
		started:   make(chan struct{}),
	}, nil
}

// run is the §4.1 sequence: prepare (everything before the first ledger line), run_start, ack, wait,
// shutdown. Only prepare can fail the whole call; after run_start every outcome is a run_end.
func (r *runner) run(ctx context.Context) (Result, error) {
	group, gctx := newGroup(ctx)
	r.group = group
	if err := r.prepare(gctx); err != nil {
		r.unwind(ctx)
		// A worker that failed before run_start cancelled gctx, and the prepare step that noticed returned the bare
		// cancellation; the worker's own error is the cause the operator needs (runtime-launch.md §7).
		if gerr := r.group.Err(); gerr != nil && !errors.Is(err, gerr) {
			err = fmt.Errorf("%w (worker failed: %v)", err, gerr)
		}
		return Result{RunID: string(r.id), ExitCode: identity.ExitLauncher, Reason: record.RunEndError}, err
	}
	endRunStart := startphase.Begin(nil, "run_start")
	err := r.writeRunStart()
	endRunStart()
	if err != nil {
		r.unwind(ctx)
		return Result{RunID: string(r.id), ExitCode: identity.ExitLauncher, Reason: record.RunEndError}, err
	}
	// The budget's origin is seeded while the pipeline is still waiting on r.started, so the
	// watcher's accumulator has exactly one writer at that moment.
	r.startBudgetClock()
	close(r.started) // the pipeline may write now: run_start is on disk (ledger.Append's precondition)
	r.emitPostStartGaps()
	term := saveTerminal(r.deps.Stdio) // before the agent can touch the terminal it shares with the person (G1)
	r.wireInputActivity(term)          // its baseline is read here, before the agent can read the terminal (G7)
	if r.releaseAgent(ctx, r.child) {
		r.startWatchers(gctx)
		r.startStopFollower(gctx, term) // the agent's own stops reach the shell through tego (G2)
		r.awaitExit(gctx)
		r.repairTerminal(term)
	}
	return r.shutdown(ctx), nil
}

// agentGate is what releaseAgent needs of the child stage (*launch.Child): Ack releases it into the agent's execve,
// and Kill ends and reaps it before it gets there.
type agentGate interface {
	Ack() error
	Kill(ctx context.Context) error
}

// releaseAgent is §4.1 steps 9a and 10, after run_start and its gaps: the Started hook, then the group check, then the
// child's Ack, each only when the one before it passed, and it reports whether the agent was released. The hook runs
// while the run id exists and the agent has not run. A worker that died while the sources started or run_start was
// written has cancelled the group and, for the enforce listener, taken its marks down: the agent is not released into
// that (§7). Any of the three failing means the agent never execs: the child is killed and reaped here and the run
// closes reason=error with a detail naming the step, which is exit 125, since no error is returned once run_start
// exists (R2) and the agent's own exit code cannot stand in for a run that never reached execve.
func (r *runner) releaseAgent(ctx context.Context, child agentGate) bool {
	var err error
	detail := ""
	if err = r.notifyStarted(); err != nil {
		detail = err.Error()
	} else if gerr := r.group.Err(); gerr != nil {
		err = fmt.Errorf("worker failed before the agent was released: %w", gerr)
		detail = "ack: " + err.Error()
	} else if err = child.Ack(); err != nil {
		detail = "ack: " + err.Error()
	}
	if err == nil {
		return true
	}
	r.log.Error("run: ack", "err", err)
	r.fail(identity.ReasonError, detail)
	kctx, kcancel := teardownCtx(ctx)
	kerr := child.Kill(kctx)
	kcancel()
	if kerr != nil {
		r.log.Warn("run: kill after failed ack", "err", kerr)
	}
	return false
}

// postStartGaps are the gaps a run writes right after run_start, in this order (§4.1 step 10): each a shortfall the
// run already knows of before the agent does anything, so each precedes every line the agent causes. A gap a package
// adds adds its row here; the Started hook runs after the last.
var postStartGaps = []func(*runner){
	(*runner).emitOwnStateGap,
	(*runner).emitCaptureGaps,
	(*runner).emitPriceGap,
	(*runner).emitBudgetUnmeteredGaps,
	(*runner).emitWatchedReadGap,
	(*runner).emitCodexUnroutedGap,
	(*runner).emitReasonUnavailableGap,
	(*runner).emitLandlockAuditGap,
	(*runner).emitLimitsGap,
}

// emitPostStartGaps queues every gap of postStartGaps, in order.
func (r *runner) emitPostStartGaps() {
	for _, emit := range postStartGaps {
		emit(r)
	}
}

// notifyStarted calls Deps.Started once (§4.1 step 9a). Its error is the run's: the agent is never released into a
// run whose caller failed to take note of it (ADR 0073 D4). A panic is not recovered (R14): it ends the launcher
// before the Ack, so the child stage never execs the agent (ADR 0020), and the sweep closes the run.
func (r *runner) notifyStarted() error {
	if r.deps.Started == nil {
		return nil
	}
	if herr := r.deps.Started(StartedRun{ID: r.id, Dir: r.dir}); herr != nil {
		return fmt.Errorf("started hook: %w", herr)
	}
	return nil
}

// validIdentity is newRunner's check of the run identity Deps carry (ADR 0073 D2): a parent run that is not a run id,
// labels identity.ValidLabels refuses and a role this version does not know are caller errors, refused before
// any resource exists.
func validIdentity(deps Deps) error {
	if deps.ParentRun != "" && !identity.RunID(deps.ParentRun).Valid() {
		return fmt.Errorf("%w: the parent run %q (the launcher environment's %s, else %s) is not a run id", ErrDeps,
			deps.ParentRun, identity.EnvRunID, identity.EnvParentRun)
	}
	if err := identity.ValidLabels(deps.Labels); err != nil {
		return fmt.Errorf("%w: %w", ErrDeps, err)
	}
	if !deps.Role.Valid() {
		return fmt.Errorf("%w: unknown role %q", ErrDeps, deps.Role)
	}
	return nil
}

// prepare is steps 1-8 of §4.1. Every resource it takes is recorded on the runner so unwind can
// release exactly what was acquired, in reverse order, however early the failure came (case 26).
func (r *runner) prepare(ctx context.Context) error {
	if err := r.mintRun(); err != nil {
		return err
	}
	// The subscription is taken before any child exists, so a stop that arrives while the run is
	// still starting is queued in the channel rather than lost to the default disposition: the
	// handler reads it as soon as step 11 starts it. Losing it would leave `tego stop` waiting on
	// a launcher that never learned it should stop.
	r.subscribeSignals()
	if err := r.openLedger(); err != nil {
		return err
	}
	if err := r.createCgroup(); err != nil {
		return err
	}
	if err := r.setupDNSBroker(); err != nil {
		return err
	}
	// The owned DNS endpoint is never without its reaper, even while Prepare runs.
	if err := r.startDNSReaper(); err != nil {
		return err
	}
	// Before Prepare: the run's CODEX_HOME is a write grant the backend must build its ruleset or maps with, and
	// Landlock pins a path that exists (capture-derive.md R19b, agent-contract.md R10a).
	if err := r.createRuntimeDir(); err != nil {
		return err
	}
	if err := r.tellRuntimeDir(); err != nil {
		return err
	}
	if err := r.provisionHarness(); err != nil {
		return err
	}
	if err := r.prepareEnforcement(ctx); err != nil {
		return err
	}
	// The reaper comes after Prepare, whose pins it purges, and before the child stage, so no process of the run
	// ever exists without one (ADR 0020 (2)).
	if err := r.startReaper(); err != nil {
		return err
	}
	if err := r.startChild(ctx); err != nil {
		return err
	}
	return r.startWorkers(ctx)
}

// systemClock is the Clock a run uses when none is injected.
type systemClock struct{}

// Now returns the wall clock.
func (systemClock) Now() time.Time { return time.Now() }

// MonoNS reads CLOCK_MONOTONIC in nanoseconds.
func (systemClock) MonoNS() uint64 { return ledger.SystemClock{}.Mono() }
