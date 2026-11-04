// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Name is the source name a Recorder reports to the run facade.
const Name = "observe"

// DefaultFlushInterval is R13's aggregation window: open read counts reach the ledger at least this
// often while a process is still running, so a crash loses at most this much counting.
// It is agent.ReadAggregationWindow, the window compile's stall-reads-unseen warning names.
const DefaultFlushInterval = agent.ReadAggregationWindow

// DefaultReadInterval is the longest the drain waits between two reads of the ring. trace_proc submits its
// opens, file operations and connects without waking the reader (BPF_RB_NO_WAKEUP), so these reads are what
// fetch them; an exec, an exit, an open of a libssl and a ring an eighth full still wake it at once
// (enforce-cgroup-observe §9). A wakeup is paid by the process that submits the sample, and a reader that kept
// up with a slow producer was woken once a sample; this bounds how long such a sample waits instead, and costs
// an idle run this many wakeups of the drain a second, not one a sample.
const DefaultReadInterval = 50 * time.Millisecond

// DefaultStopDrain bounds how long Stop's final drain records samples (finalDrain). Past it, what is left of
// this run's on the ring is counted into a ringbuf-undrained gap rather than recorded, which bounds the
// final drain by the ring's size instead of by the work its samples cause (a hook's attach is budgeted at
// 50 ms, capture-derive.md §4).
const DefaultStopDrain = 2 * time.Second

// PinDir is where tier 2 pins the maps this recorder reads, one directory per bpf_hash
// (docs/p0/enforce-cgroup-observe.md §3).
const PinDir = "/sys/fs/bpf/tego"

// EventsMapName and LostMapName are the pinned names of the record's ring outer, which holds each run's own ring
// at its slot, and of the per-run lost counter inside a build's pin directory (ADR 0026 (1), (4)). They are the maps' ELF names and nothing else: every map in
// bpf/include/maps.h is LIBBPF_PIN_BY_NAME and the tier-2 loader pins it at <PinPath>/<name>
// (enforce/cgroup's MapOptions.PinPath), so a second spelling here is a recorder that opens a path no
// loader ever creates. That is how every tier-2 run came to record kernel-record-unavailable while
// the ring buffer was being written.
const (
	EventsMapName = bpf.MapEvents
	LostMapName   = bpf.MapLost
)

// Gap reasons this recorder reports (record.GapPayload.Why).
const (
	// GapRingbufFull is the kernel's own lost-event counter: bpf_ringbuf_reserve failed, so a
	// producer dropped a sample rather than blocking (I7).
	GapRingbufFull = "ringbuf-full"
	// GapMalformedRecord is a sample this build could not decode.
	GapMalformedRecord = "malformed-record"
	// GapPathTruncated is E4: bpf_d_path filled the fixed path buffer with no room for a NUL.
	GapPathTruncated = "path-truncated"
	// GapArgvTruncated is E25: an exec whose argv did not fit the fixed buffer.
	GapArgvTruncated = "argv-truncated"
	// GapDirUnresolved is R9's miss: an unlink/rename/mkdir whose parent (dev, ino) names no
	// declared entry, recorded with the raw identifier instead of a path.
	GapDirUnresolved = "dir-unresolved"
	// GapExecUnresolved is an exec of a relative name whose working directory could not be read as the one the
	// exec looked it up in (Recorder.resolveExec): recorded with the name as passed, unmatched and observed.
	GapExecUnresolved = "exec-unresolved"
	// GapExecMetadataMissing is an exec outcome with no matching before-CONTINUE attempt metadata.
	GapExecMetadataMissing = "exec-metadata-missing"
	// GapBindMetadataMissing is a terminal listener result missing the matched
	// supervisor attempt or the kernel permission hook's marker.
	GapBindMetadataMissing = "bind-metadata-missing"
	// GapExecArgvMismatch means actual mapped arguments differed from the blocked notification's metadata.
	GapExecArgvMismatch = "exec-argv-mismatch"
	// GapExecFragmentOverflow is a refusal/open fragment discarded before its terminal exec outcome.
	GapExecFragmentOverflow = "exec-fragment-overflow"
	// GapDirUnindexed counts the declared fs entries left out of the directory index because stat does not
	// name them by their super block's device, as on btrfs and on an overlayfs of one filesystem: an unlink,
	// rename or mkdir beneath them is recorded unresolved (dir-unresolved), whatever entry covers it. Recorded
	// once, when the recorder starts reading (R9).
	GapDirUnindexed = "dir-unindexed"
	// GapAggregateOverflow is a read-aggregation flush forced by the table's cap.
	GapAggregateOverflow = "aggregate-overflow"
	// GapRingbufUndrained is a sample of this run that was on the ring when Stop began and that Stop's
	// final drain counted but did not record, because its budget (Options.StopDrain) had run out. The run
	// writes the same why, with no count, when its cgroup still held processes as the drain began, so one
	// spelling serves both (runtime.GapRingbufUndrained).
	GapRingbufUndrained = runtime.GapRingbufUndrained
	// GapReadFailed is a drain that ended on a read error before the run did: nothing the run did after it is
	// recorded. The error went to a log line at shutdown and the ledger said nothing.
	GapReadFailed = "kernel-record-failed"
	// GapCgroupTrackingFailed means a descendant has no required run-set membership row.
	GapCgroupTrackingFailed = runtime.GapCgroupTrackingFailed
)

// TruncatedPath is what an fs event's path field carries when the kernel's buffer overflowed (E4).
const TruncatedPath = "<truncated>"

// ErrAlreadyStarted is Start called twice on one Recorder; it is not idempotent (§4).
var ErrAlreadyStarted = errors.New("observe: recorder already started")

// ErrStopped is Start or hook registration after Stop released the recorder's resources.
var ErrStopped = errors.New("observe: recorder stopped")

// ErrNoReader is New without a ring-buffer reader and without a pin to open one from.
var ErrNoReader = errors.New("observe: no ring buffer reader")

// RingReader is the ring buffer a Recorder drains. *ringbuf.Reader satisfies it; a test supplies a
// reader over synthetic samples so the whole decode, cache, rule-stamping and aggregation path runs
// with no kernel at all.
type RingReader interface {
	// ReadInto blocks for the next sample and puts it in rec, reusing rec.RawSample's array when it is
	// large enough, or returns os.ErrDeadlineExceeded at the deadline and ringbuf.ErrClosed once Close has
	// been called. The drain reads every sample into one Record, which spares it the allocation per
	// sample that Read makes; the price is that a sample's bytes last only until the next read.
	ReadInto(rec *ringbuf.Record) error
	// SetDeadline bounds the next read so the drain goroutine wakes to flush aggregates without a
	// second goroutine touching the tables.
	SetDeadline(t time.Time)
	// Close unblocks a pending read and releases the reader.
	Close() error
}

// flushReader is a RingReader that Stop can wake without closing it and that says how much it still holds.
// *ringbuf.Reader is one. Flush makes a pending read return what the ring holds and then ringbuf.ErrFlushed,
// which is how the drain goroutine is told to stop without the ring being closed under the samples Stop's
// final drain still has to read; AvailableBytes is the ring's producer position less its consumer position,
// which bounds that drain (Recorder.finalDrain).
type flushReader interface {
	Flush() error
	AvailableBytes() int
}

// ringRecordBytes is how far one sample of n bytes moves the ring's consumer position: the kernel's 8-byte
// record header, then the data padded to 8 bytes (kernel/bpf/ringbuf.c, BPF_RINGBUF_HDR_SZ).
func ringRecordBytes(n int) int { return 8 + (n+7)&^7 }

// LostCounter reads the kernel's cumulative count of samples that never reached the ring buffer.
type LostCounter interface {
	// Lost returns the cumulative count across every CPU.
	Lost() (uint64, error)
}

// Options configure a Recorder. Rules is the only required field when Reader is supplied; a nil
// Reader is the run's own ring, opened at Start from BPFHash's pin directory by the run's slot.
type Options struct {
	// Rules is the compiled contract the recorder stamps events against.
	Rules *agent.RuleTable
	// Reader drains the ring buffer. Nil means "open the run's own ring from the build BPFHash names".
	Reader RingReader
	// Lost reads the kernel's lost-sample counter. Nil disables ringbuf-full gap accounting.
	Lost LostCounter
	// BPFHash names the pin directory under PinRoot when Reader is nil.
	BPFHash string
	// PinRoot overrides PinDir, the bpffs directory holding one pin directory per build. Tests and
	// a host that mounts bpffs elsewhere set it; production leaves it empty.
	PinRoot string
	// Proc reads the process cache's /proc. Nil means the system's.
	Proc *proc.FS
	// FlushInterval overrides DefaultFlushInterval.
	FlushInterval time.Duration
	// ReadInterval overrides DefaultReadInterval.
	ReadInterval time.Duration
	// StopDrain overrides DefaultStopDrain.
	StopDrain time.Duration
	// CacheSize overrides DefaultProcCacheSize; AggregateLimit overrides DefaultAggregateLimit.
	CacheSize      int
	AggregateLimit int
	// Now supplies wall-clock timestamps; nil means time.Now. mono_ns always comes from the
	// kernel's own bpf_ktime_get_ns() value, never from here (E20).
	Now func() time.Time
	// OnError is called once with the fatal error that ended the drain goroutine, when it ends it. The run's
	// ledger learns of it from the recorder's own gap (GapReadFailed) and the run goes on; this is where the
	// error itself goes, the CLI's own log. Nil leaves the error to Stop.
	OnError func(error)
	// OnTrackingFailure stops a run whose descendants cannot be tracked. Unlike a recording failure,
	// missing membership also removes enforcement. Called once, including under record: off.
	OnTrackingFailure func(error)
	// RunSet is the build's run membership map: Start reads the slot of the run's own cgroup row, which names
	// the run's ring, and from then on a sample is this run's when its header's run_idx is that slot. Nil with
	// a Reader means the ring holds this run's samples alone, which is what a test's synthetic ring holds. A
	// recorder opened from BPFHash always opens the pinned map.
	RunSet RunSet
	// Logger receives the detail a gap reason cannot carry: why the record could not be scoped or its ring
	// opened. Nil discards it.
	Logger *slog.Logger
	// Stamps reads the build's per-slot activity stamps (tego_activity), which LastActivity reads at the run's slot.
	// Nil means the pinned map of a recorder opened from BPFHash, opened at Start, and no stamps with a Reader.
	Stamps ActivityStamps
	// Activity is told the mono_ns of each of the run's samples the recorder keeps no line for, which under
	// record: off is every one: the budget watcher's stall check, which reads activity from the lines the
	// pipeline carries, would otherwise see an agent busy at tier 2 as idle and kill it for stalling
	// (docs/p0/limits-check-doctor-cli.md R4). Nil tells no one. SetActivity sets it on a recorder a factory built.
	Activity func(monoNS uint64)
	// ContinuedNet names an IP connect or datagram the run's supervisor continued, the way the supervisor's own
	// line would have named it: its rule, declared host and verdict, ok false when the supervisor continues no
	// such destination (a contract with a net: section, or one guarding a models[] endpoint). It is
	// supervisor.Loop.ContinuedNet, the one lookup behind that line: the supervisor writes none for a continued
	// connect this recorder reads (docs/p0/supervisor.md R7), so this recorder's line is the connect's only one
	// and must name it as the supervisor would, the resolver exception, the resolved-address check and the
	// entries the runtime adds (the capture listener) included (§5 R5). Nil, or ok false, names the sample
	// against Rules (matchNet). SetContinuedNet sets it on a recorder a factory built.
	ContinuedNet func(ap netip.AddrPort, proto string) (rule, host string, v record.Verdict, ok bool)
	// ContinuedFS names a filesystem action the run's supervisor continued and left to this recorder's line
	// (docs/p0/supervisor.md R7a), for a record whose directory the index cannot name (an unindexed parent, a
	// rename's or a link's other end): the thread, the operation (record.FS*, an O_CREAT create an open), each
	// end's final component and the record's own stamp (MonoNS) in; the supervisor's spellings, rule, verdict and
	// reason out, ok false when it handed over no such action as the thread's last before the stamp (a thread
	// makes one syscall at a time, so however far this recorder has fallen behind, the stamp says which action a
	// record is of). It is supervisor.Loop.ContinuedFS. The chain's return stays the verdict; the
	// supervisor's verdict is the model that explains a refusal (ChainFS). Nil names such a record by its raw
	// identifiers, observed. SetContinuedFS sets it on a recorder a factory built.
	ContinuedFS     func(tid int, op, name, name2 string, at uint64) (path, path2, rule string, v record.Verdict, reason record.Reason, ok bool)
	ContinuedFSInfo func(tid int, op, name, name2 string, at uint64) (supervisor.FSNaming, bool)
	// ContinuedExec consumes the immutable naming captured before this exec was continued. The original TID,
	// process birth and kernel timestamp distinguish nonleader execs, reused tasks and delayed records.
	ContinuedExec func(originalTID, pid int, startBootNS, eventMonoNS uint64) (supervisor.ExecNaming, bool)
	// ExecResults says the attached producers include both failed exec syscall results and successful execs.
	// It is set before Start; without it image-open and bprm refusals keep their previous recording behavior.
	ExecResults     bool
	ContinuedBind   func(tid, pid int, startBootNS, eventMonoNS uint64) (supervisor.BindNaming, bool)
	BindResults     bool
	ContinuedListen func(tid, pid int, startBootNS, eventMonoNS uint64) (supervisor.ListenNaming, bool)
	ListenResults   bool
	// SupervisorExecs says the run's supervisor writes the line of every exec (docs/p0/supervisor.md R7a,
	// R16b): it decides each one on the image it resolves and names it by the grant, where this recorder's
	// sched_process_exec record carries no verdict of a mechanism and names the spelling. The recorder then writes
	// no exec line, and keeps its process cache and hooks. SetSupervisorExecs sets it.
	SupervisorExecs bool
	// DecisionPlane is the mode the run's kernel decision plane runs in (record.DecisionPlaneLSM or
	// record.DecisionPlaneFmodRet), which a line whose verdict the plane gave names in decision_plane; "" when the
	// run has no plane (TIER3-PLAN T9). SetDecisionPlane sets it.
	DecisionPlane string
	// ExecPins says the run's handle pinned its plane slot (ADR 0048 (3) P2): each exec's line waits for the plane's
	// held or kill sample of it (exec_pin.go). ExecPinKill is the pidfd backstop for a kill the kernel could not send.
	// SetExecPins sets both.
	ExecPins    bool
	ExecPinKill func(pid int, startBootNS uint64) error
	// namespaceCheck refuses a launcher whose pids or clocks are not the kernel's (hostNamespaces, the
	// default); a test replaces it.
	namespaceCheck func() error
	// mountinfo is the mount table the directory index compares devices with (newRuleIndexAt); "" is
	// this process's. A test replaces it.
	mountinfo string
	// ringFault, when set, is what openRing answers for the run's slot in place of opening its ring: how a test has a
	// recorder that found the run's row fail to open its ring, which a caller-supplied Reader never does. Nil opens it.
	ringFault func(slot uint32) error
}

// Recorder is the kernel record: it drains the run's own ring buffer, enriches each sample from the
// process cache, stamps the rule and verdict the contract implies, aggregates ordinary reads and
// emits record.Event values (docs/p0/enforce-cgroup-observe.md §2.4, §5 R8-R13).
//
// It satisfies source.Source. The spec sketches Start(ctx, identity.Run); the merged
// internal/runtime owns the producer contract (Source/Sink/RunRef), so that is the shape here.
type Recorder struct {
	// skip is the open deputy, whose records are dropped (SetSkipProcess); nil for none.
	skip            atomic.Pointer[skipProcess]
	trackingFailure sync.Once

	opts     Options
	rules    *ruleIndex
	reader   RingReader
	closer   sync.Once
	stopOnce sync.Once

	// Published under mu by Start, then owned by the drain goroutine until it returns and by
	// whichever Stop caller joins that goroutine after it.
	procs *procCache
	agg   *aggTable
	run   source.RunRef
	sink  source.Sink
	lost  uint64 // last value read from the kernel counter, drain-goroutine-owned

	// silent is `record: off` (E23): drain and maintain the cache, emit nothing. full is `record: full`, under
	// which no read is aggregated (SEMANTICS §7).
	silent bool
	full   bool
	ownTTY [2]uint64 // inherited terminal file identity for builtin.other_tty attribution
	// exits drops the second record of one process's exit (exitSeen); drain-goroutine-owned.
	exits exitSeen
	// owned holds the run's ring Start opened and Stop must close; empty when the caller supplied its own
	// reader. The lost counter (lostMap) is closed apart from it and last, because Stop reads it once more
	// after the ring is closed.
	owned []io.Closer
	// hooks are fed every process's exec, open and exit from the drain goroutine (feedHooks). They are
	// added before Start and never after, so the drain reads the slice without a lock.
	hooks []source.ProcessHook
	// runSet names the run's slot (Options.RunSet); runSetOwned is the pinned map New opened for it, closed by
	// Stop. rings and lostMap are the build's pinned ring outer and per-run lost counter New opened for a
	// recorder of BPFHash, from which Start opens the run's own ring and counter by its slot; closed by Stop.
	runSet      RunSet
	runSetOwned io.Closer
	rings       *ebpf.Map
	lostMap     *ebpf.Map
	// scoped, slot and gen are Start's reading of this run's row, fixed before the drain goroutine exists: from
	// then on a sample is this run's only when it carries slot and gen. The generation is what keeps a record
	// the slot's previous run left in its ring, which this run reuses, out of this run's (ADR 0026 (6) as
	// amended). inert is a recorder whose Start read nothing and recorded kernel-record-unavailable; set under
	// mu before done is closed.
	scoped bool
	slot   uint32
	gen    uint32
	inert  bool

	// stampMu guards stamps, stampSlot and stampOn, which LastActivity reads from the budget watcher's goroutine:
	// Start sets them once the run's slot is known, and Stop clears them before it closes stampsOwned, the pinned
	// map Start opened for a recorder of BPFHash.
	stampMu     sync.RWMutex
	stamps      ActivityStamps
	stampsOwned io.Closer
	stampSlot   uint32
	stampOn     bool

	// plane is the run's plane rows, compiled by planeRows on the first plane line; planeCompiled says it was
	// tried. Drain-goroutine-owned.
	plane         *decide.PlaneRows
	planeCompiled bool
	// execFragments holds image opens and refusals until the same attempt's terminal syscall outcome.
	// The single drain goroutine owns it, including Stop's final drain after that goroutine has joined.
	execFragments execFragments
	execOutcomes  execOutcomesSeen
	bindOutcomes  bindOutcomesSeen
	// pins is the fold of a pinned run's exec records with the plane's held and kill samples (exec_pin.go), owned
	// like execFragments.
	pins execPinFold

	// halt tells the drain goroutine to return at its next sample or wake-up without closing the ring, so
	// Stop's final drain can still read what the goroutine left (haltDrain, finalDrain).
	halt atomic.Bool

	// mu publishes started and both completion channels together, and guards stopped, err and gaps.
	// startDone joins initialization before Stop touches a reader or map Start may still publish;
	// done then joins the drain before Stop owns its tables.
	mu        sync.Mutex
	started   bool
	stopped   bool
	startDone chan struct{}
	done      chan struct{}
	err       error
	gaps      map[string]int64
}

var _ source.Source = (*Recorder)(nil)

// The recorder is the run's runtime.ActivityStamper: the watcher pulls the kernel's activity stamp through it.
var _ runtime.ActivityStamper = (*Recorder)(nil)

// The recorder is a runtime.DecisionPlaneNamer: the runner names the plane's mode on it, or a plane refusal's line
// carries no decision_plane.
var _ runtime.DecisionPlaneNamer = (*Recorder)(nil)

// New builds a Recorder. It opens no kernel object when Options.Reader is set, which is how the
// unit tests drive the whole pipeline; otherwise it opens the named build's pinned run set, ring outer and lost
// counter, from which Start opens the run's own ring by its slot.
func New(opts Options) (*Recorder, error) {
	r := &Recorder{opts: opts, rules: newRuleIndexAt(opts.Rules, cmp.Or(opts.mountinfo, selfMountinfo)),
		gaps: map[string]int64{}, ownTTY: inheritedTTYIdentity()}
	if opts.Rules != nil {
		r.silent = opts.Rules.Record == agent.RecordOff
		r.full = opts.Rules.Record == agent.RecordFull
	}
	if opts.FlushInterval <= 0 {
		r.opts.FlushInterval = DefaultFlushInterval
	}
	if opts.ReadInterval <= 0 {
		r.opts.ReadInterval = DefaultReadInterval
	}
	if opts.StopDrain <= 0 {
		r.opts.StopDrain = DefaultStopDrain
	}
	if opts.Now == nil {
		r.opts.Now = time.Now
	}
	if opts.namespaceCheck == nil {
		r.opts.namespaceCheck = hostNamespaces
	}
	switch {
	case opts.Reader != nil:
		r.reader = opts.Reader
		r.runSet = opts.RunSet
	case opts.BPFHash != "":
		rings, lost, err := openPinned(opts.PinRoot, opts.BPFHash)
		if err != nil {
			return nil, err
		}
		// The run set is required like the lost counter: it is what names the run's slot, and so its ring.
		rs, err := openRunSet(opts.PinRoot, opts.BPFHash)
		if err != nil {
			_ = rings.Close()
			_ = lost.Close()
			return nil, err
		}
		r.rings, r.lostMap = rings, lost
		r.runSet, r.runSetOwned = rs, rs
	default:
		return nil, fmt.Errorf("%w: neither Reader nor BPFHash was set", ErrNoReader)
	}
	r.baselineLost()
	return r, nil
}

// baselineLost reads the lost counter once, as the value this run's drops are counted from. A run's own
// counter is zeroed at Prepare (ADR 0026 (4)), so this is 0 unless a test's counter says otherwise. A counter
// that cannot be read now is diffed from zero: more drops than this run's, never fewer.
func (r *Recorder) baselineLost() {
	if r.opts.Lost == nil {
		return
	}
	if n, err := r.opts.Lost.Lost(); err == nil {
		r.lost = n
	} else {
		r.logWarn("observe: the lost counter has no baseline; ringbuf-full counts from zero", "err", err)
	}
}

// openRing opens this run's own ring and lost counter from the build's pinned outer by the run's slot, for a
// recorder New opened from BPFHash (ADR 0026 (1), (5)): the ring is this run's alone, so this recorder is its
// only reader by construction. A run with no ring at its slot has nothing to read, which Start reports.
func (r *Recorder) openRing(slot uint32) error {
	if r.opts.ringFault != nil {
		return r.opts.ringFault(slot)
	}
	if r.rings == nil {
		return nil // a caller-supplied Reader
	}
	ring, ok, err := bpf.RingOf(r.rings, slot)
	if err != nil {
		return fmt.Errorf("observe: %w", err)
	}
	if !ok {
		return fmt.Errorf("observe: the build holds no ring at this run's slot %d", slot)
	}
	reader, err := ringbuf.NewReader(ring)
	if err != nil {
		_ = ring.Close()
		return fmt.Errorf("observe: read the ring of slot %d: %w", slot, err)
	}
	r.reader, r.owned = reader, []io.Closer{ring}
	if r.opts.Lost == nil {
		r.opts.Lost = &slotLost{m: r.lostMap, slot: slot}
		r.baselineLost()
	}
	return nil
}

// Name is the source name in the run's diagnostics.
func (r *Recorder) Name() string { return Name }

var _ source.ProcessStream = (*Recorder)(nil)

// AddProcessHook feeds a hook the process lifecycle this recorder drains: every exec, every open and every
// exit the kernel record sees in the run's cgroups (source.ProcessStream). It is how the uprobe source
// learns which processes to attach to (docs/p0/capture-derive.md §4, R4, R8), and it must be called before
// Start: the drain goroutine reads the hooks without a lock, so a hook added later is refused.
func (r *Recorder) AddProcessHook(h source.ProcessHook) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return ErrStopped
	}
	if r.started {
		return fmt.Errorf("%w: a process hook is added before Start", ErrAlreadyStarted)
	}
	if h != nil {
		r.hooks = append(r.hooks, h)
	}
	return nil
}

// Start begins draining in one goroutine and returns immediately (source.Source's contract). The
// goroutine stops on ctx cancellation or Stop, whichever comes first; a read error other than a
// clean close is fatal and reaches the caller through OnError and Stop.
func (r *Recorder) Start(ctx context.Context, run source.RunRef, sink source.Sink) error {
	if sink == nil {
		return fmt.Errorf("observe: start %s: nil sink", run.ID)
	}
	// Publish both completion channels with started: Stop first joins resource initialization, then
	// wakes and joins the drain. It must not close a reader while openRing can still replace it.
	procs := newProcCache(r.opts.Proc, identity.RunID(run.ID), r.opts.CacheSize)
	agg := newAggTable(r.opts.AggregateLimit)
	done := make(chan struct{})
	startDone := make(chan struct{})

	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return fmt.Errorf("%w: run %s", ErrStopped, run.ID)
	}
	if r.started {
		r.mu.Unlock()
		return fmt.Errorf("%w: run %s", ErrAlreadyStarted, run.ID)
	}
	r.started = true
	r.run, r.sink, r.procs, r.agg, r.done, r.startDone = run, sink, procs, agg, done, startDone
	r.mu.Unlock()
	defer close(startDone)

	// Scoped before the first read: the run's slot names its ring (ADR 0026 (1)). A recorder that cannot name
	// this run's slot, or finds no ring at it, reads no record. That is the kernel record not running for this
	// run, which the run reports as a gap and survives, as it does a factory that failed. The activity stamp needs
	// the slot alone, so it is read once the slot is known, ring or none: the BPF programs stamp a run with no ring
	// as they do one with a ring, and a busy record: off run whose ring could not be opened is not ended as stalled.
	err := r.scope(run.CgroupID)
	if err == nil {
		r.openStamps()
		err = r.openRing(r.slot)
	}
	if err != nil {
		r.gap(runtime.GapKernelRecordUnavailable, 1)
		r.logWarn("observe: kernel record unavailable for this run", "err", err)
		r.mu.Lock()
		r.inert = true
		r.mu.Unlock()
		r.closeReader()
		close(done)
		return nil
	}

	if n := len(r.rules.unindexed); n > 0 {
		r.gap(GapDirUnindexed, int64(n))
		r.logWarn("observe: unlink, rename and mkdir beneath these entries are recorded unresolved: stat does not "+
			"name them by their super block's device, which the kernel's records carry (btrfs, overlayfs)",
			"entries", r.rules.unindexed)
	}

	// Cancellation ends the goroutine but not the record: the run cancels its workers before it knows its
	// processes are gone, so the samples still to come are read by Stop's final drain, which the run calls
	// once its cgroup is empty, or once a killed tree has had killTimeout to empty (runtime awaitEmpty,
	// docs/p0/runtime-launch.md §4.1 steps 12-13).
	stop := context.AfterFunc(ctx, r.haltDrain)
	go func() {
		// The local, not r.done: the field is Stop's to read under the lock, and the goroutine
		// closing what Start handed it needs no further synchronisation.
		defer close(done)
		defer stop()
		err := r.drain(ctx)
		r.mu.Lock()
		r.err = err
		r.mu.Unlock()
		if err == nil {
			return
		}
		// The run survives its record, as it does a factory that failed, and its ledger says what is missing
		// from there on.
		r.gap(GapReadFailed, 1)
		if r.opts.OnError != nil {
			r.opts.OnError(err)
		}
	}()
	return nil
}

// Reading reports whether the recorder reads this run's ring: it started, found the run's row
// (Start's scope), and its drain has not failed. The supervisor writes no line of its own for a connect the
// ring records while this holds (runtime.KernelReading, supervisor.md R7).
func (r *Recorder) Reading() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started || r.stopped || r.inert || r.err != nil {
		return false
	}
	select {
	case <-r.startDone:
		return true
	default:
		return false // startup has not yet selected and opened this run's ring
	}
}

// Stop halts the drain goroutine, drains what is still on the ring (finalDrain), flushes every open
// aggregate as a final fs event, closes the reader and returns the drain's fatal error if it had one. It
// is safe to call twice, concurrently, and after a Start that never ran: the final drain and flush happen
// exactly once, so two callers can never touch the aggregation table at the same time.
func (r *Recorder) Stop() error {
	r.mu.Lock()
	r.stopped = true
	started, startDone, done := r.started, r.startDone, r.done
	r.mu.Unlock()
	if started {
		<-startDone
	}
	r.haltDrain()
	if started {
		<-done
	}
	// The drain goroutine has returned, so the tables and the reader belong to whichever caller flushes
	// them. The lost counter is read once more here: a run that ends inside its flush window would
	// otherwise drop the samples the kernel reported lost since the last poll. That read needs the
	// counter still open, which is why closeReader leaves it alone and it is closed only after.
	r.stopOnce.Do(func() {
		r.mu.Lock()
		inert := r.inert
		r.mu.Unlock()
		// An inert recorder read nothing, and kernel-record-unavailable already covers this run's whole
		// record.
		if started && !inert {
			r.finalDrain()
			r.settleAllPins()
			r.pollLost()
			r.emitAggregates(r.agg.flushAll())
		}
		r.logProcCache()
		r.closeReader()
		r.closeStamps()
		for _, m := range []*ebpf.Map{r.rings, r.lostMap} {
			if m != nil {
				_ = m.Close()
			}
		}
		if r.runSetOwned != nil {
			_ = r.runSetOwned.Close()
		}
	})
	if !started {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// Gaps reports what the recorder could not cover, one entry per distinct reason with its count
// (P0-DESIGN §6). Call it after Stop.
func (r *Recorder) Gaps() []source.Gap {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]source.Gap, 0, len(r.gaps))
	for why, n := range r.gaps {
		out = append(out, source.Gap{What: record.GapRecord, Why: why, Count: n})
	}
	sortGaps(out)
	return out
}

// haltDrain tells the drain goroutine to return, and wakes it if it is waiting on an empty ring. A reader that
// cannot be woken without closing it (a test's) is closed, which ends the goroutine the same way and leaves
// finalDrain only what that reader still hands out once closed.
func (r *Recorder) haltDrain() {
	r.halt.Store(true)
	if f, ok := r.reader.(flushReader); ok && f.Flush() == nil {
		return
	}
	r.closeReader()
}

// finalDrain reads what the ring holds when Stop runs, after the drain goroutine has returned: edge case #28's
// one final ring-buffer drain, which the recorder owes the exits that end a run, the actions just before
// them, and the hooks those feed. The run calls Stop once its cgroup is empty (docs/p0/runtime-launch.md
// §4.1 steps 12-13), so every sample of this run is on the ring by then and lies within the bytes the ring
// holds at this moment. On a cancelled run the tree is killed and given killTimeout to empty first; one that
// outlasts it is the run's own gap why=ringbuf-undrained with no count (runtime awaitEmpty). The drain reads
// that many bytes and no further, because a ring the run's escaped or orphaned processes keep writing (the run's
// ring is its own, but its row outlives a cgroup that did not empty) need never be empty. Reads do not wait: the deadline is now, so the reader hands out what the
// ring holds and then os.ErrDeadlineExceeded. Samples are handled for StopDrain and past it only counted,
// this run's into gap why=ringbuf-undrained, so the drain is bounded by the ring's size and not by the work
// its samples cause. What handling emits goes to the run's queue, which the run keeps writing to the ledger
// while its sources stop; the queue is still bounded, so a drain that outruns the ledger by more than its
// depth is counted there as channel-full. A reader that cannot say how much it holds (a test's) is read
// until it reports empty or closed.
func (r *Recorder) finalDrain() {
	left := -1
	if f, ok := r.reader.(flushReader); ok {
		left = f.AvailableBytes()
	}
	r.reader.SetDeadline(time.Now())
	handleBy := time.Now().Add(r.opts.StopDrain)
	var (
		rec    Record
		sample ringbuf.Record // reused by every read; see drain for what that asks of handle
	)
	for left != 0 {
		if err := r.reader.ReadInto(&sample); err != nil {
			return // empty, closed or unreadable: nothing more can be read from it
		}
		if left > 0 {
			left = max(left-ringRecordBytes(len(sample.RawSample)), 0)
		}
		if derr := DecodeInto(&rec, sample.RawSample); derr != nil {
			r.gap(GapMalformedRecord, 1)
			continue
		}
		if time.Now().After(handleBy) {
			if r.mine(&rec) {
				r.gap(GapRingbufUndrained, 1)
			}
			continue
		}
		r.handle(&rec)
	}
}

// closeReader closes the ring buffer exactly once, unblocking a pending read, and releases every
// kernel object New opened for it but the lost counter, which Stop still reads. A pinned map survives in the kernel through its pin; what is
// released here is this process's fd (§9 "every fd opened here is closed by the function that
// opened it, or by a Handle whose Close closes it").
func (r *Recorder) closeReader() {
	r.closer.Do(func() {
		if r.reader != nil {
			_ = r.reader.Close()
		}
		for _, c := range r.owned {
			_ = c.Close()
		}
	})
}

// drain is the single owner of the process cache and the aggregation table. It batches: it keeps
// reading while the ring still holds samples, and does the between-batch work — the kernel's
// lost-sample counter, the aggregation flush — only once the window has elapsed.
//
// The "ring ran dry" signal alone must never flush: with a slow producer every single read reports
// an empty ring, so flushing there would give every read its own event and defeat R13's aggregation
// entirely. It only decides when to re-arm the read deadline, which is what wakes an idle drain in
// time for the next flush.
//
// Every sample is read into the one sample Record, whose bytes the next read overwrites. Nothing handle
// does may keep them: DecodeInto copies every field of a record out of the sample and decodes nothing past an
// SSL chunk's header, and handle records nothing of an SSL chunk, whose capture belongs to capture/uprobe.
func (r *Recorder) drain(ctx context.Context) error {
	var (
		rec    Record
		sample ringbuf.Record
	)
	now := r.opts.Now()
	next := now.Add(r.opts.FlushInterval)
	r.reader.SetDeadline(r.readBy(now, next))
	for {
		err := r.reader.ReadInto(&sample)
		switch {
		case err == nil:
		case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, ringbuf.ErrFlushed):
			if r.halt.Load() {
				return nil // Stop or cancellation: finalDrain reads the rest
			}
			next = r.betweenBatches(next)
			continue
		case errors.Is(err, ringbuf.ErrClosed), errors.Is(err, os.ErrClosed):
			return nil // a reader haltDrain had to close: a clean end
		default:
			if ctx.Err() != nil || r.halt.Load() {
				return nil
			}
			return fmt.Errorf("observe: read ring buffer: %w", err)
		}
		if derr := DecodeInto(&rec, sample.RawSample); derr != nil {
			r.gap(GapMalformedRecord, 1)
		} else {
			r.handle(&rec)
		}
		// Checked after every sample and not only when the ring runs dry: another run's producers can keep
		// the ring from ever being empty, and the goroutine must still return promptly (source.Source).
		if r.halt.Load() {
			return nil
		}
		// The window is also checked while the ring still holds samples: another run's producers can keep it
		// from ever running dry, and the flush and the lost poll waited for that, so a live process's counts
		// and the kernel's drops reached the ledger only at its exit or at Stop (R13).
		if sample.Remaining == 0 || !r.opts.Now().Before(next) {
			next = r.betweenBatches(next)
		}
	}
}

// betweenBatches does the per-window work when the window has elapsed and re-arms the read deadline
// either way. It returns the next flush time.
func (r *Recorder) betweenBatches(next time.Time) time.Time {
	now := r.opts.Now()
	if !now.Before(next) {
		r.pollLost()
		r.emitAggregates(r.agg.flushAll())
		next = now.Add(r.opts.FlushInterval)
	}
	r.reader.SetDeadline(r.readBy(now, next))
	return next
}

// readBy is the deadline of the next read: the next flush, or ReadInterval from now if that comes first. A
// sample submitted without a wakeup is read at that deadline, since a read that reaches it still hands out
// what the ring holds before it reports the deadline (*ringbuf.Reader.ReadInto).
func (r *Recorder) readBy(now, next time.Time) time.Time {
	if by := now.Add(r.opts.ReadInterval); by.Before(next) {
		return by
	}
	return next
}

// pollLost diffs the kernel's cumulative lost-sample counter and records the increment.
func (r *Recorder) pollLost() {
	if r.opts.Lost == nil {
		return
	}
	n, err := r.opts.Lost.Lost()
	if err != nil || n <= r.lost {
		return
	}
	delta := n - r.lost
	r.lost = n
	r.gap(GapRingbufFull, int64(delta))
}

// handle dispatches one decoded sample. Under `record: off` allowed actions keep no ledger line;
// membership failures still stop the run. Process lifecycle and capture hooks remain active, and
// the ring is drained so lost-counter accounting keeps working (E23).
//
// A sample stamped with another slot is neither recorded nor fed to a hook. The run's ring is its own, created
// fresh at its Prepare and written only by programs that looked it up by this run's slot, so none should be;
// the check stands so a sample that is not this run's could never enter its ledger.
func (r *Recorder) handle(rec *Record) {
	if !r.mine(rec) {
		return
	}
	// The run's open deputy opens for the supervisor, which writes each held open's one line (supervisor.md R7a, ADR
	// 0041 D5), the decision plane's refusal of the open included, which it attributes with the tier's model as this
	// recorder would (decide.ChainFS): the deputy's own records would be a second line for the same action. Only the
	// deputy's: a later process given its pid is recorded as any other (skipProcess.drops).
	if r.skip.Load().drops(rec) {
		return
	}
	// Older producers can expose an internal restart at sys_exit. Ignore it
	// before touching terminal deduplication, joined naming or image evidence.
	if rec.Kind == KindExecResult && rec.ExecResult.restarting() {
		return
	}
	if rec.Kind == KindExit && !r.exits.first(rec.PID, rec.Exit.ExecStartNS) {
		return
	}
	if r.opts.ExecResults && (rec.Kind == KindExec || rec.Kind == KindExecResult) && !r.execOutcomes.first(rec) {
		return
	}
	if rec.Kind == KindExec && r.execPathRead() {
		r.resolveExec(rec)
	}
	r.record(rec)
	r.feedHooks(rec)
}

// execPathRead reports whether anything reads an exec record's path: the exec's line, which the recorder writes
// unless the supervisor writes every exec's (SupervisorExecs) or record: off writes none, or a hook. Otherwise
// resolveExec's /proc readlink and stat would be spent on the drain goroutine for a path nobody reads.
func (r *Recorder) execPathRead() bool {
	return len(r.hooks) > 0 || !r.opts.SupervisorExecs && !r.silent
}

// resolveExec makes an exec record's path absolute. bprm->filename is the name the process passed to execve, and
// a relative one ("./git", "venv/bin/pip") names a file under its working directory: matched as it stood, "./git"
// was the bare name git, and a ./git beside the agent was recorded exec[/usr/bin/git] allow (§2.4).
// The name is joined to /proc/<pid>/cwd, taken only while that directory is the one the kernel saw at the exec,
// whose (dev, inode) the record carries: a process that has since changed directory could otherwise have its
// exec named by another file. One that has exited has no cwd to read, and its parent's is taken on the same
// condition (the exec's line was lost to that race under load: ADR 0017's exec cells). A name that cannot be
// resolved stays
// as it was and sets Exec.Unresolved, and the exec is recorded unmatched and observed.
//
// A name holding a ".." component, relative or absolute, is not resolved either. The kernel walks it physically,
// following a symlink before the ".." leaves it, and a join or clean does it lexically: with link -> /usr/local/bin,
// "link/../tool" ran /usr/local/tool and was recorded as <cwd>/tool under that path's entry.
func (r *Recorder) resolveExec(rec *Record) {
	name := rec.Exec.Path
	if rec.Exec.PathTruncated || name == "" {
		return
	}
	if hasDotDot(name) {
		rec.Exec.Unresolved = true
		return
	}
	if filepath.IsAbs(name) {
		return
	}
	// A process that has exited since (a quick tool, run and gone before its record is read) has no cwd left; its
	// parent's, when it is the same directory, names it as well.
	for _, pid := range [2]int{int(rec.PID), int(rec.PPID)} {
		if cwd, ok := r.execCwd(pid, rec); ok {
			rec.Exec.Path = filepath.Join(cwd, name)
			return
		}
	}
	rec.Exec.Unresolved = true
}

// execCwd is pid's working directory when it is the one an exec record says the kernel saw: the same dev and inode.
func (r *Recorder) execCwd(pid int, rec *Record) (string, bool) {
	if pid <= 0 {
		return "", false
	}
	cwd, err := r.procs.fs.Cwd(pid)
	var st unix.Stat_t
	if err != nil || !filepath.IsAbs(cwd) || unix.Stat(cwd, &st) != nil ||
		uint64(st.Dev) != rec.Exec.CwdDev || st.Ino != rec.Exec.CwdIno {
		return "", false
	}
	return cwd, true
}

// hasDotDot reports whether a path has a ".." component.
func hasDotDot(name string) bool {
	for _, c := range strings.Split(name, "/") {
		if c == ".." {
			return true
		}
	}
	return false
}

// exitSeen remembers the exits handled last, so a thread group's exit is handled once: trace_proc reports the
// exit of a thread group's last thread, and two threads that end at one instant can both find the group's live
// count at 0 and both report it (E23). The copy arrives right behind the first, so a short
// window of recent exits holds it. Owned by whichever goroutine drains, like the process cache.
type exitSeen struct {
	keys [64]exitKey
	next int
}

// exitKey is one process: its pid and its start time, which a reused pid does not share.
type exitKey struct {
	pid   uint32
	start uint64
}

// first reports whether this is the first exit of the process seen among the recent ones, and remembers it.
func (s *exitSeen) first(pid uint32, start uint64) bool {
	k := exitKey{pid: pid, start: start}
	for _, v := range s.keys {
		if v == k {
			return false
		}
	}
	s.keys[s.next] = k
	s.next = (s.next + 1) % len(s.keys)
	return true
}

// mine reports whether a decoded sample is this run's (see handle).
func (r *Recorder) mine(rec *Record) bool {
	return !r.scoped || rec.RunIdx == r.slot && rec.Gen == r.gen
}

// scope reads this run's slot from its own cgroup's run-set row. With no run set there is nothing to scope
// against and every sample is taken as this run's (Options.RunSet).
//
// Another run of the build, and a dead launcher's leftover, no longer need refusing here (ADR 0026 (5)): each
// run reads its own ring, and the slot table hands out no slot a run-set row still carries (ADR 0026 (6)), so
// no other cgroup's processes write into this run's ring.
func (r *Recorder) scope(cgroupID uint64) error {
	if r.runSet == nil {
		return nil
	}
	if err := r.opts.namespaceCheck(); err != nil {
		return err
	}
	if cgroupID == 0 {
		return errors.New("observe: the run names no cgroup, so no run-set row can name its slot")
	}
	slot, gen, ok, err := r.runSet.Slot(cgroupID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("observe: cgroup %d has no row in the build's run set", cgroupID)
	}
	r.scoped, r.slot, r.gen = true, slot, gen
	return nil
}

// logWarn writes to the run's own log, never to the ledger.
func (r *Recorder) logWarn(msg string, args ...any) {
	if r.opts.Logger == nil {
		return
	}
	r.opts.Logger.Warn(msg, append([]any{"run", r.run.ID}, args...)...)
}

// logProcCache writes the process cache's accounting to the run's own log at debug level once the drain
// goroutine has stopped: how often a sample's pid had to be read from /proc, had already exited, or named a
// process other than the cached one (pid reuse, §6 E14). None of these loses a line, so none is a gap; they are
// what to read when attribution degrades to ExecIDUnknown.
func (r *Recorder) logProcCache() {
	if r.opts.Logger == nil || r.procs == nil {
		return
	}
	c := r.procs
	r.opts.Logger.Debug("recorder process cache", "run", r.run.ID, "rebuilds", c.rebuilds, "gone", c.gone,
		"reused", c.reused, "cached", c.len())
}

// SetActivity sets Options.Activity. It is called before Start, from the goroutine that starts the recorder.
func (r *Recorder) SetActivity(fn func(monoNS uint64)) { r.opts.Activity = fn }

// ActivityStamps reads one slot of the build's tego_activity: the bpf_ktime_get_ns (CLOCK_MONOTONIC) of the newest
// action the BPF programs stamped for the run at that slot, 0 for none (limits-check-doctor-cli.md R4).
type ActivityStamps interface {
	Stamp(slot uint32) (uint64, error)
}

// pinnedStamps is a build's pinned tego_activity.
type pinnedStamps struct{ m *ebpf.Map }

// Stamp reads the slot's stamp.
func (p pinnedStamps) Stamp(slot uint32) (uint64, error) { return bpf.ActivityAt(p.m, slot) }

// Close releases the map's descriptor; the pin keeps the map.
func (p pinnedStamps) Close() error { return p.m.Close() }

// openStamps makes the run's activity stamp readable once Start has found the run's slot, before and whether or not
// it opens the run's ring, since the stamp needs the slot alone: the caller's Options.Stamps, or the build's pinned
// tego_activity for a recorder opened from BPFHash. A map that cannot be opened leaves LastActivity answering 0,
// logged: the stall check then sees what it saw before the stamp existed, which can end a busy run under
// record: off as stalled but never keeps an idle one alive (GAPS C35).
func (r *Recorder) openStamps() {
	stamps := r.opts.Stamps
	var owned io.Closer
	if stamps == nil && r.opts.BPFHash != "" && r.rings != nil {
		path := pinnedMapPath(r.opts.PinRoot, r.opts.BPFHash, bpf.MapActivity)
		m, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{ReadOnly: true})
		if err != nil {
			r.logWarn("observe: the activity stamps cannot be read; the stall check counts only lines and samples",
				"path", path, "err", err)
			return
		}
		p := pinnedStamps{m: m}
		stamps, owned = p, p
	}
	if stamps == nil {
		return
	}
	r.stampMu.Lock()
	r.stamps, r.stampsOwned, r.stampSlot, r.stampOn = stamps, owned, r.slot, true
	r.stampMu.Unlock()
}

// closeStamps ends LastActivity's reads and closes the map openStamps opened, once no read can be using it.
func (r *Recorder) closeStamps() {
	r.stampMu.Lock()
	owned := r.stampsOwned
	r.stamps, r.stampsOwned, r.stampOn = nil, nil, false
	r.stampMu.Unlock()
	if owned != nil {
		_ = owned.Close()
	}
}

// LastActivity is the run's activity stamp (runtime.ActivityStamper): the CLOCK_MONOTONIC reading the BPF programs
// last wrote at the run's slot of tego_activity for an action no line or sample carries (trace_proc's allowed
// actions under record: off, the TLS probes' calls in every mode; limits R4). It answers 0, no activity, before Start
// has found the run's slot, for a recorder that found no row for the run, after Stop, and on a read that fails; a
// recorder that found the slot but could not open the run's ring still answers the stamp. The watcher pulls it once a
// tick, and a value below the run's start is ignored there, which is what keeps a stamp the slot's previous run left
// from counting.
func (r *Recorder) LastActivity() uint64 {
	r.stampMu.RLock()
	defer r.stampMu.RUnlock()
	if !r.stampOn {
		return 0
	}
	v, err := r.stamps.Stamp(r.stampSlot)
	if err != nil {
		return 0
	}
	return v
}

// SetTrackingFailure installs the run's fatal membership-failure handler before Start.
func (r *Recorder) SetTrackingFailure(fn func(error)) { r.opts.OnTrackingFailure = fn }

// SetContinuedNet sets Options.ContinuedNet. It is called before Start, from the goroutine that starts the
// recorder.
func (r *Recorder) SetContinuedNet(fn func(ap netip.AddrPort, proto string) (rule, host string, v record.Verdict, ok bool)) {
	r.opts.ContinuedNet = fn
}

// SetContinuedFS sets Options.ContinuedFS. It is called before Start, from the goroutine that starts the
// recorder.
func (r *Recorder) SetContinuedFS(fn func(tid int, op, name, name2 string, at uint64) (path, path2, rule string, v record.Verdict, reason record.Reason, ok bool)) {
	r.opts.ContinuedFS = fn
}

// SetContinuedFSInfo supplies optional copied decision metadata without changing
// the kernel's final object, chain verdict or one-action ownership.
func (r *Recorder) SetContinuedFSInfo(fn func(int, string, string, string, uint64) (supervisor.FSNaming, bool)) {
	r.opts.ContinuedFSInfo = fn
}

func (r *Recorder) fsGateInfo(rec *Record, op string) supervisor.GateFields {
	if r.opts.ContinuedFSInfo == nil || rec.FS.PathTruncated || rec.FS.Path2Truncated {
		return supervisor.GateFields{}
	}
	name := rec.FS.Path
	if op == record.FSOpen {
		name = filepath.Base(name)
	}
	name2 := ""
	if rec.Kind == KindRename || rec.Kind == KindLink {
		name2 = rec.FS.Path2
	}
	n, ok := r.opts.ContinuedFSInfo(int(rec.TID), op, name, name2, rec.MonoNS)
	if !ok {
		return supervisor.GateFields{}
	}
	return n.GateFields
}
func (r *Recorder) fsGatePayload(rec *Record, p record.FSPayload) any {
	return struct {
		record.FSPayload
		supervisor.GateFields
	}{p, r.fsGateInfo(rec, p.Op)}
}

// SetContinuedExec installs the attempt lookup before Start.
func (r *Recorder) SetContinuedExec(fn func(originalTID, pid int, startBootNS, eventMonoNS uint64) (supervisor.ExecNaming, bool)) {
	r.opts.ContinuedExec = fn
}

// SetExecResults declares the attached terminal-result coverage before Start.
func (r *Recorder) SetExecResults(on bool) { r.opts.ExecResults = on }

// ExecHandoverReady declares the configured recording seam; Reading separately reports live initialization.
func (r *Recorder) ExecHandoverReady() bool { return r.opts.ExecResults && r.opts.ContinuedExec != nil }

// SetContinuedBind and SetBindResults configure terminal ownership before Start.
func (r *Recorder) SetContinuedBind(fn func(tid, pid int, startBootNS, eventMonoNS uint64) (supervisor.BindNaming, bool)) {
	r.opts.ContinuedBind = fn
}
func (r *Recorder) SetBindResults(on bool)  { r.opts.BindResults = on }
func (r *Recorder) BindHandoverReady() bool { return r.opts.BindResults && r.opts.ContinuedBind != nil }

func (r *Recorder) SetContinuedListen(fn func(tid, pid int, startBootNS, eventMonoNS uint64) (supervisor.ListenNaming, bool)) {
	r.opts.ContinuedListen = fn
}
func (r *Recorder) SetListenResults(on bool) { r.opts.ListenResults = on }
func (r *Recorder) ListenHandoverReady() bool {
	return r.opts.ListenResults && r.opts.ContinuedListen != nil
}

// SetSupervisorExecs sets Options.SupervisorExecs. It is called before Start, from the goroutine that starts the
// recorder.
func (r *Recorder) SetSupervisorExecs(on bool) { r.opts.SupervisorExecs = on }

// SetSkipProcess names the run's open deputy (ADR 0041 D2) by its pid and its start time in CLOCK_BOOTTIME
// nanoseconds as /proc reads it (0 when it could not be read), whose records this recorder drops: every open it makes
// is one the supervisor completes and writes the line of (supervisor.md R7a), a refusal the decision plane made of it
// included. A pid of 0 names none. Safe to call while the recorder reads.
func (r *Recorder) SetSkipProcess(pid uint32, startNS uint64) {
	if pid == 0 {
		r.skip.Store(nil)
		return
	}
	r.skip.Store(&skipProcess{pid: pid, startNS: startNS})
}

// skipProcess is the process whose records the recorder drops: the run's open deputy.
type skipProcess struct {
	pid uint32
	// startNS is the deputy's start as /proc reads it, rounded down to a USER_HZ tick; 0 when unknown.
	startNS uint64
}

// drops reports whether rec is the deputy's. The pid alone names whichever process holds it now: the agent can end
// the deputy, and a later process of the run given its pid must keep its records. So the record's
// start must be the deputy's (proc.SameProcess, §6 E14); a record that carries no start (a socket or cgroup record,
// which the deputy's filter never lets it make) is kept. With no start known the pid alone decides, which holds only
// because the launcher leaves the deputy's zombie unreaped until the run ends (launch.Child.KeepUnreaped), so no
// other process is given that pid meanwhile. A launcher in a time namespace with a boottime offset reads a start that
// never matches (proc.Stat.StartBootNS): the deputy's records are then recorded beside the supervisor's lines, a
// second line for a held open and never a lost one.
func (s *skipProcess) drops(rec *Record) bool {
	if s == nil || rec.PID != s.pid {
		return false
	}
	if s.startNS == 0 {
		return true
	}
	return rec.StartNS != 0 && proc.SameProcess(rec.StartNS, s.startNS)
}

// NamesPathHooks reports that this recorder names every path-hook record (unlink, rmdir, mkdir, mknod, symlink,
// link, rename, truncate, an O_CREAT create) by its full path on its own wherever a plane mode decides the run
// (runtime.PathHookNamer): the trace object walks each parent directory of such a run's records in the kernel
// (tego_dir_walk, keyed by the run-set row's plane byte, which Prepare writes), and handleFSOp joins the walked
// path with the final component, with no supervisor naming. A walk that cannot prove its path falls back to the
// directory index, and past it to a marked dev:ino/name, never to a wrong path (enforce-plane §2.15). The walk
// needs bpf_loop, which every plane mode needs too (ADR 0024 (1)).
func (r *Recorder) NamesPathHooks() bool { return true }

// SetDecisionPlane sets Options.DecisionPlane. It is called before Start, from the goroutine that starts the
// recorder.
func (r *Recorder) SetDecisionPlane(mode string) { r.opts.DecisionPlane = mode }

// record is handle's ledger half.
func (r *Recorder) record(rec *Record) {
	if rec.Kind == KindCgroupMkdir && rec.Cgroup.Err != 0 {
		r.gap(GapCgroupTrackingFailed, 1)
		err := fmt.Errorf("observe: track descendant cgroup %d under %d: errno %d", rec.Cgroup.ChildCgroupID, rec.Cgroup.ParentCgroupID, rec.Cgroup.Err)
		r.logWarn("descendant cgroup tracking failed", "err", err)
		r.trackingFailure.Do(func() {
			if r.opts.OnTrackingFailure != nil {
				r.opts.OnTrackingFailure(err)
			}
		})
		return
	}
	switch {
	case rec.Kind == KindPlaneExecHeld || rec.Kind == KindPlaneExecKill:
		if r.opts.ExecPins {
			r.handleExecPin(rec)
		} else if rec.Kind == KindPlaneExecKill {
			r.pins.killed.Add(1)
			r.emitKill(nil, rec) // no pin was asked for, yet the plane killed: its line, never nothing
		}
		return
	case r.opts.ExecPins && rec.Kind != KindExec:
		// A later record of a process settles what still waits of its last exec (exec_pin.go); an exec record does
		// so itself (holdExec).
		r.settlePinsOf(rec.PID, rec.StartNS)
	}
	if r.opts.ExecResults && !r.opts.SupervisorExecs {
		switch {
		case rec.Kind == KindOpen && rec.FS.ExecOpen, rec.Kind == KindPlaneExec:
			r.rememberExecFragment(rec)
			if rec.Kind == KindOpen && rec.FS.RetOK && rec.FS.Ret >= 0 && !r.silent {
				r.handleOpen(rec) // successful image reads retain independent full/watch/aggregate coverage
			}
			return
		case rec.Kind == KindExecResult:
			r.handleExecResult(rec)
			return
		}
	}
	if rec.Kind == KindExec && r.opts.SupervisorExecs {
		r.procs.observeExec(int(rec.PID), rec)
		return
	}
	if rec.Kind == KindExecResult {
		return // only the configured terminal-result owner above records this event
	}
	if rec.Kind == KindBindResult {
		if r.opts.BindResults {
			r.handleBindResult(rec)
		}
		return
	}
	if rec.Kind == KindListenResult {
		if r.opts.ListenResults {
			r.handleBindResult(rec)
		}
		return
	}
	if r.silent {
		if r.opts.Activity != nil {
			r.opts.Activity(rec.MonoNS)
		}
		switch {
		case rec.Kind == KindExec && r.opts.ExecPins:
			// A pinned exec's line waits for the plane's sample: a kill makes it a refusal, which record: off keeps.
			r.handleExec(rec)
		case rec.Kind == KindExec:
			if r.opts.ExecResults {
				r.joinExec(rec, int(rec.Exec.OldTID))
				r.execFragments.discard(rec, int(rec.Exec.OldTID))
			}
			r.procs.observeExec(int(rec.PID), rec)
		}
		if rec.Kind == KindExit {
			r.procs.evictExited(int(rec.PID), rec.Exit.ExecStartNS)
		}
		switch rec.Kind {
		case KindPlaneExec:
			r.handlePlaneExec(rec) // a refusal, which record: off keeps (ADR 0016 (3))
		case KindPlaneAttr:
			r.handlePlaneAttr(rec)
		case KindPlaneSocket:
			r.handlePlaneSocket(rec)
		case KindPlaneControl:
			r.handlePlaneControl(rec)
		case KindPlaneMap:
			r.handlePlaneMap(rec)
		case KindPlaneFS:
			r.handlePlaneFS(rec)
		case KindSockCreate:
			r.handleSockCreate(rec) // cgroup/sock_create's refusal (enforce-cgroup-observe R5)
		case KindSockopt:
			r.handleSockopt(rec) // cgroup/setsockopt's refusal (ADR 0018 (7))
		}
		// The one thing record: off records is a refusal (ADR 0016 (3)): the kernel sends an fs record under off
		// only when the chain refused, and emitAction keeps only a refused line of it.
		if rec.FS.RetOK && rec.FS.Ret != 0 {
			switch {
			case rec.Kind == KindOpen:
				r.handleOpen(rec)
			case rec.Kind.IsFSOp():
				r.handleFSOp(rec)
			}
		}
		return
	}
	switch rec.Kind {
	case KindExec:
		r.handleExec(rec)
	case KindExit:
		r.handleExit(rec)
	case KindOpen:
		r.handleOpen(rec)
	case KindUnlink, KindRename, KindMkdir, KindMknod, KindRmdir, KindLink, KindSymlink, KindTruncate:
		r.handleFSOp(rec)
	case KindConnect, KindSendmsg:
		r.handleNet(rec)
	case KindPlaneExec:
		r.handlePlaneExec(rec)
	case KindPlaneAttr:
		r.handlePlaneAttr(rec)
	case KindPlaneSocket:
		r.handlePlaneSocket(rec)
	case KindPlaneControl:
		r.handlePlaneControl(rec)
	case KindPlaneMap:
		r.handlePlaneMap(rec)
	case KindPlaneFS:
		r.handlePlaneFS(rec)
	case KindSockCreate:
		r.handleSockCreate(rec)
	case KindSockopt:
		r.handleSockopt(rec)
	case KindBind, KindCgroupMkdir, KindCgroupRmdir, KindSSLChunk:
		// R6: bind is a placeholder with no rule to stamp. The cgroup tracepoints materialize the
		// run set in-kernel and the SSL chunks belong to capture/uprobe; none of the four
		// is a ledger action here.
	}
}

// feedHooks hands one sample's process lifecycle to every hook, after the sample's own event is emitted so a
// hook's work (an attach is budgeted at 50 ms, capture-derive.md §4) never delays the record of the action
// that caused it. It runs under record: off too: the kernel still emits exec and exit then, and what a
// hook does with them is not recording (E23). An open whose path the kernel truncated names no file a hook
// could act on, and is not passed on; an exec is, with no path, because the process is still one to attach.
func (r *Recorder) feedHooks(rec *Record) {
	if len(r.hooks) == 0 {
		return
	}
	pid := int(rec.PID)
	switch rec.Kind {
	case KindExec:
		path := rec.Exec.Path
		if rec.Exec.PathTruncated {
			path = ""
		}
		for _, h := range r.hooks {
			h.OnExec(pid, rec.CgroupID, path)
		}
	case KindOpen:
		if rec.FS.PathTruncated || rec.FS.Path == "" {
			return
		}
		for _, h := range r.hooks {
			h.OnOpen(pid, rec.CgroupID, rec.FS.Path)
		}
	case KindExit:
		for _, h := range r.hooks {
			h.OnExit(pid)
		}
	}
}

// handleExec records one execve and refreshes the process cache from the kernel's own view.
func (r *Recorder) handleExec(rec *Record) {
	pid := int(rec.PID)
	entry := r.procs.observeExec(pid, rec)
	naming, joined := r.joinExec(rec, int(rec.Exec.OldTID))
	if joined && naming.SupervisorOwned {
		r.execFragments.discard(rec, int(rec.Exec.OldTID))
		return
	}
	displayPath := rec.Exec.Path
	joinedPath := joined && rec.Exec.Path == naming.RawPath && !filepath.IsAbs(rec.Exec.Path) && !hasDotDot(rec.Exec.Path) &&
		filepath.IsAbs(naming.Path) && naming.CwdDev != 0 && naming.CwdDev == rec.Exec.CwdDev &&
		naming.CwdIno != 0 && naming.CwdIno == rec.Exec.CwdIno
	if joinedPath {
		// The attempt's joined spelling uses the same cwd the kernel used. It names the invocation only;
		// the plane's kernel rule below remains the policy attribution.
		displayPath = naming.Path
	}
	if rec.Exec.ArgvTruncated {
		r.gap(GapArgvTruncated, 1)
	}
	// A name the kernel could not read at all (bprm->filename unreadable: no path, reason PATH_UNRESOLVED on a
	// record nothing refused) is no more the exec's name than a truncated one, and is recorded as one: matched
	// as the path "" it was an exec with an empty name and no gap.
	unreadable := rec.Exec.Path == "" || (rec.Verdict != KernelRefused && rec.Reason == ReasonPathUnresolved)
	if rec.Exec.PathTruncated || unreadable {
		r.gap(GapPathTruncated, 1)
	}
	// A truncated path is a prefix of the one the process exec'd, and a prefix can name an entry the file is not
	// (Evaluate cleans "/usr/bin/git////..." into /usr/bin/git), so it is matched against nothing (E4).
	path := rec.Exec.Path
	m := execMatch{Rule: RuleUnmatched, Verdict: record.VerdictObserved}
	switch {
	case rec.Exec.PathTruncated || unreadable:
		path = TruncatedPath
	case rec.Exec.Unresolved:
		// A relative name whose directory is unknown, or a name with a ".." component, names no file the recorder
		// can vouch for (resolveExec, §2.4).
		if !joinedPath {
			r.gap(GapExecUnresolved, 1)
		}
	default:
		m = r.rules.matchExec(path)
	}
	verdict, reason := r.verdict(rec, func() (record.Verdict, record.Reason) { return m.Verdict, m.Reason })
	payload := execOutcomePayload{ExecPayload: record.ExecPayload{
		Path:         path,
		Argv:         rec.Exec.Argv,
		ExecID:       entry.ExecID,
		ParentExecID: r.procs.parentExecID(int(rec.PPID), rec.Exec.ParentStartNS),
	}}
	if joined {
		payload.applyNaming(naming)
		if joinedPath && !rec.Exec.PathTruncated && !unreadable {
			payload.Path = displayPath
		}
	}
	r.successArgv(&payload, rec, naming, joined)
	rule := m.Rule
	if named := rec.Exec.Plane; named != bpf.PlaneNamedNone && rec.Verdict != KernelRefused {
		// The plane's bprm_check allowed this exec: the verdict is the plane's, and the rule the entry it matched
		// by (an exec.allow directory's by its fs row), whatever the spelling matches (TIER3-PLAN T9).
		idx := uint32(rec.RuleIdx)
		if named == bpf.PlaneNamedFSRow {
			idx |= bpf.PlaneRuleFSRow
		}
		rule, verdict, reason = r.planeExecRule(idx), record.VerdictAllow, ""
		payload.Mechanism, payload.DecisionPlane = record.MechanismPlane, r.opts.DecisionPlane
	}
	if !r.opts.ExecPins && joined && naming.RuntimeRule != "" && verdict != record.VerdictRefused &&
		!rec.Exec.ArgvTruncated && !naming.ArgvTruncated && slices.Equal(rec.Exec.Argv, naming.Argv) {
		// A process-bound allowance is not an ambient command pattern. Name its authority only after the
		// kernel confirms the successful vector; pinned runs wait for their held sample in settleExec.
		rule, verdict, reason = naming.RuntimeRule, record.VerdictAllow, ""
	}
	ev := r.event(rec, record.KindExec, rule, verdict, reason)
	mcp := r.execMCP(rec, naming, joined)
	if r.opts.ExecResults {
		r.execFragments.discard(rec, int(rec.Exec.OldTID))
	}
	if r.opts.ExecPins {
		// The plane checks this exec against its pin in the same tracepoint: the line waits for that answer.
		r.holdExec(rec, &pinExec{ev: ev, p: payload, naming: naming, joined: joined, seq: rec.Exec.PinSeq, mcp: mcp})
		return
	}
	r.setPayload(ev, payload)
	r.emit(ev)
	if mcp != nil {
		r.emit(mcp)
	}
}

// handleExit flushes the exiting process's aggregates with their final counts (R13) and evicts it
// from the cache, which bounds memory even under record: off (E23).
//
// The process is the one the exit's start time names, not whatever the cache holds for the pid: that was a
// check this function never made, so a later process of the pid whose record arrived first lost its entry and
// its counts, and the exiting one's stayed open (§6 E14). A record with no start time
// takes the cache's entry.
func (r *Recorder) handleExit(rec *Record) {
	pid, start := int(rec.PID), rec.Exit.ExecStartNS
	var id string
	if start != 0 {
		id = r.procs.execID(pid, start)
	} else if e, ok := r.procs.peek(pid); ok {
		id = e.ExecID
	}
	if id != "" {
		r.emitAggregates(r.agg.flushExec(id))
	}
	r.procs.evictExited(pid, start)
}

// handleOpen records one file open. Reads that are neither watched nor denied are aggregated per
// (exec id, rule) instead of recorded individually (R13); everything else is its own event.
//
// A read whose path the kernel truncated (E4) is everything else: the file it opened is unknown and may be a
// deny_read file the kernel refused, so it is matched against nothing and recorded on its own, observed. Counted
// into an aggregate it became a line that said allow (E4).
func (r *Recorder) handleOpen(rec *Record) {
	entry, _ := r.procs.lookup(int(rec.PID), rec.StartNS)
	path := rec.FS.Path
	m := fsMatch{Rule: RuleUnmatched}
	if rec.FS.PathTruncated {
		r.gap(GapPathTruncated, 1)
		path = TruncatedPath
	} else {
		m = r.rules.matchFS(path)
	}
	write := isWrite(rec.FS.Flags)
	if !write && !rec.FS.PathTruncated {
		m = r.rules.absentRead(path, m)
	}
	if r.listenerRefused(rec, path) {
		// The fanotify listener refused this open after the Landlock ruleset let it through, and wrote its line,
		// the mechanism's own answer (§5 R8, supervisor R7a, ADR 0016 (4)): a second one here would count one
		// refusal twice.
		return
	}
	// A read under an unenforced deny_read entry is the fanotify listener's to answer (the core routes it there),
	// and the listener's answer is in the chain's return only up to 6.12, where security_file_open returned
	// fsnotify_open_perm's: its line keeps the tier model's verdict on every kernel (ADR 0016 (4)). Only on the
	// fallback: where a plane mode decides the run there is no listener, the plane is in the chain and stamps each
	// refusal, and an open the chain let through happened.
	listener := !write && m.DenyRead && m.Read.Unenforced && r.opts.DecisionPlane == ""
	builtinTTY := r.builtinTTYRefusal(rec, path)
	fv := r.fsVerdict(rec, path, !listener, func() (record.Verdict, record.Reason) {
		if builtinTTY {
			if write {
				return record.VerdictRefused, record.ReasonWriteOutsideContract
			}
			return record.VerdictRefused, record.ReasonReadDenied
		}
		if write && m.Entry == nil && rec.FS.RetOK {
			// A write-open outside every entry: the Landlock ruleset the run inherits grants no write there, so
			// the chain's refusal is that ruleset's, unmatched, as compile --test answers it. Asked with no chain
			// return, the model still attributes nothing (InferFS).
			return record.VerdictRefused, decide.OpReason(record.FSOpen)
		}
		v, reason := r.rules.inferFS(record.FSOpen, write, m)
		if v == record.VerdictRefused && listener && r.rules.unmarkedRead(rec.FS.Dev) {
			// Only the fanotify listener refuses a read under this entry, and it marked no mount of this
			// device at Prepare: one the host mounted beneath the entry since (E24). The read was made, so
			// the line claims no refusal.
			return record.VerdictObserved, ""
		}
		return v, reason
	})
	verdict, reason := fv.verdict, fv.reason
	if !write && !m.Watched && !m.DenyRead && !rec.FS.PathTruncated && verdict != record.VerdictRefused && fv.by == "" {
		if r.full || r.fsGateInfo(rec, record.FSOpen).Score != nil {
			// SEMANTICS §7: record: full disables aggregation. The read is its own event, with the file it
			// opened and the verdict its aggregate would have carried; it was counted into one at tier 2 while
			// tier 1 recorded it individually (R13).
			ev := r.event(rec, record.KindFS, m.Rule, record.VerdictAllow, "")
			r.setPayload(ev, r.fsGatePayload(rec, fv.payload(record.FSPayload{Op: record.FSOpen, Path: path, Flags: int(rec.FS.Flags),
				Created: rec.FS.Created})))
			r.emitAction(ev)
			return
		}
		rulePath := path
		if m.Entry != nil {
			rulePath = m.Entry.Path
		}
		full := r.agg.add(aggKey{ExecID: entry.ExecID, Rule: m.Rule}, aggEntry{
			LastNS: rec.MonoNS, Path: rulePath, PID: int(rec.PID), TID: int(rec.TID), Cgroup: rec.CgroupID,
		})
		if full {
			r.gap(GapAggregateOverflow, 1)
			r.emitAggregates(r.agg.flushAll())
		}
		return
	}
	rule := fv.ruleOr(m.Rule)
	if builtinTTY && verdict == record.VerdictRefused {
		rule = agent.BuiltinOtherTTY
	}
	if write && verdict == record.VerdictAllow && !rec.FS.PathTruncated {
		rule = r.grantName(record.FSOpen, path, rule)
	}
	ev := r.event(rec, record.KindFS, rule, verdict, reason)
	r.setPayload(ev, r.fsGatePayload(rec, fv.payload(record.FSPayload{Op: record.FSOpen, Path: path, Flags: int(rec.FS.Flags),
		Created: rec.FS.Created})))
	r.emitAction(ev)
}

// listenerRefused reports whether the fanotify listener refused this open after the Landlock ruleset let it
// through, by the listener's own rule (decide.ListenerOpenRefused, on the canonical path the listener reads
// back too), on a device the listener marked (E24). Landlock decides first, and a refusal of its own never
// reaches the listener: the chain's EACCES says so, and a record that carries no return asks the Landlock model
// (decide.Evaluate's landlock column). Only at tier 2 on the fanotify fallback, where the listener is: where a plane
// mode decides the run (Options.DecisionPlane) no listener decides an open, and the plane, which exempts by the
// parent's inode where the model exempts by path (ADR 0043 D3), may allow one the listener's rule would refuse.
// On the fallback the return is the LSM chain's, which carries the listener's EPERM only up to 6.12 and 0 from
// 6.13 (fsnotify_open_perm left security_file_open), so a 0 there is the listener's refusal still, the listener
// deciding by this same rule on this same path; Landlock's EACCES is Landlock's.
func (r *Recorder) listenerRefused(rec *Record, path string) bool {
	rt := r.rules.rt
	if rt == nil || rt.Tier != backend.TierCgroup || r.opts.DecisionPlane != "" || rec.FS.PathTruncated ||
		rec.Verdict == KernelRefused {
		return false
	}
	if !r.rules.listenerOpenRefused(path) || r.rules.unmarkedRead(rec.FS.Dev) {
		return false
	}
	if rec.FS.RetOK {
		return rec.FS.Ret != -int32(unix.EACCES)
	}
	kind := agent.ActionFSRead
	if isWrite(rec.FS.Flags) {
		kind = agent.ActionFSWrite
	}
	return decide.LandlockRuleset(rt, agent.Action{Kind: kind, Path: path}).Verdict == agent.VerdictAllow
}

// grantName is the rule an allowed modification of path is named by: the entry whose grant the Landlock ruleset
// allowed it under (decide.GrantName), as compile --test names it, not a deny_read or watch entry nearer to the
// path, which decided nothing (supervisor R15). fallback when no entry grants it.
func (r *Recorder) grantName(op, path, fallback string) string {
	if name, ok := r.rules.grantName(op, path); ok {
		return name
	}
	return fallback
}

// handleFSOp records one file operation: unlink, rename, mkdir, mknod, rmdir, link, symlink or truncate. R9/R10:
// these hooks never call bpf_d_path, so the sample carries the parent directory's (dev, ino) and the final
// component and the path is rebuilt here from the rule table's own directory index. A miss is recorded with the
// raw dev:ino/name identifier and no rule rather than a guessed verdict. Where a plane mode decides the run, the
// sample also carries each parent directory's path, walked in the kernel (FSBody.Dir): the plane's filter leaves
// such an action unnotified (enforce-plane §2.13, §2.15), so the line names it by its full path on its own, as an
// open's line does, and no supervisor naming is asked for.
//
// The verdict is the chain's return the sample carries (fsVerdict); the tier model below only explains a refusal,
// or decides a sample that carries no return. An rmdir is recorded as the unlink the supervisor calls it, and a
// mknod — a mknod(2), or an O_CREAT open whose create the chain refused and which opened nothing — as the open
// with O_CREAT the supervisor's creat line is.
func (r *Recorder) handleFSOp(rec *Record) {
	op := fsOp(rec.Kind)
	path, m, resolved := r.resolveFSOpPath(rec.FS.Dev, rec.FS.Ino, rec.FS.Path, rec.FS.PathTruncated, true,
		rec.FS.Dir, rec.FS.DirWalk)
	payload := record.FSPayload{Op: op, Path: path}
	if rec.Kind == KindMknod {
		payload.Flags = unix.O_CREAT
	}
	// A rename and a link name a second directory entry, resolved against the directory index exactly as the
	// first is — never against the first one's directory, which would name a file that does not exist. A
	// symlink's second name is its target, which names nothing the contract decides for this action.
	twoEnds := rec.Kind == KindRename || rec.Kind == KindLink
	var m2 fsMatch
	var resolved2 bool
	switch {
	case twoEnds && (rec.FS.Path2 != "" || rec.FS.Path2Truncated):
		payload.Path2, m2, resolved2 = r.resolveFSOpPath(rec.FS.Dev2, rec.FS.Ino2, rec.FS.Path2, rec.FS.Path2Truncated,
			rec.FS.Ino2 != 0, rec.FS.Dir2, rec.FS.Dir2Walk)
	case rec.Kind == KindSymlink:
		payload.Path2 = rec.FS.Path2
		if rec.FS.Path2Truncated {
			payload.Path2 = TruncatedPath
		}
	}
	// A record the index cannot name at every end is named by the supervisor, which continued the syscall and
	// left its line to this one (ContinuedFS): its spellings and rule, and its verdict as the model that explains
	// the chain's refusal.
	var sup *continued
	if (!resolved || (twoEnds && !resolved2)) && !rec.FS.PathTruncated && !rec.FS.Path2Truncated {
		sup = r.continuedFS(rec, op, twoEnds)
	}
	if sup != nil {
		payload.Path, resolved = sup.path, true
		if twoEnds {
			payload.Path2, resolved2 = sup.path2, true
		}
	}
	r.dirUnresolvedGap(resolved && (!twoEnds || resolved2 || rec.FS.Path2Truncated), rec.FS.PathTruncated)
	rule := m.Rule
	// infer is the tier model for one resolved end. An end outside every entry is one only the kernel's walked
	// path names (the index holds entries' directories only): the Landlock ruleset the run inherits grants no write
	// there, so the chain's refusal is that ruleset's, unmatched, as compile --test answers it and as handleOpen
	// answers a write-open outside every entry.
	infer := func(m fsMatch) (record.Verdict, record.Reason) {
		if m.Entry == nil {
			return record.VerdictRefused, decide.OpReason(op)
		}
		return r.rules.inferFS(op, true, m)
	}
	fv := r.fsVerdict(rec, path, true, func() (record.Verdict, record.Reason) {
		rule = m.Rule
		if sup != nil {
			rule = sup.rule
			return sup.verdict, sup.reason
		}
		if !resolved {
			return record.VerdictObserved, ""
		}
		if twoEnds {
			// Landlock decides a rename or a link at the new name's directory too: it must grant the write. The
			// verdict was the source's alone, so a rename out of a write entry, which Landlock refuses at the
			// destination, was recorded allow (R9). A second end the index cannot name leaves the outcome
			// unknown, and one the contract refuses is the refusal.
			if !resolved2 {
				return record.VerdictObserved, ""
			}
			if rec.Kind == KindRename {
				// The Landlock ruleset under every tier asks REFER of both directories, which a file-level write
				// entry's own directory and a symlink entry's outside every write directory lack, and refuses a move
				// into a place where the object gains a right the ruleset grants there alone (an exec.allow
				// directory's EXECUTE): a chain refusal it explains is the ruleset's, named as tier 1's line and
				// compile --test's every column name it, by the directory that lacks the right or by the source
				// (decide.LandlockRenameRefusal). At tier 3 the plane's hooks decide the objects
				// only, so an end's own entry allowed what the floor refused.
				if name, refused := r.rules.landlockRenameRefusal(path, payload.Path2); refused {
					rule = name
					return record.VerdictRefused, decide.OpReason(op)
				}
			}
			if v, _ := infer(m2); v == record.VerdictRefused {
				rule = m2.Rule
				return record.VerdictRefused, decide.OpReason(op)
			}
			if rec.Kind == KindLink {
				// The source is not modified, but the Landlock ruleset under every tier asks MAKE_REG and REFER of both
				// directories and refuses a file right gained (hook_path_link): a chain refusal it explains (a
				// file-level write entry linked elsewhere, a link into an exec.allow directory) is the ruleset's, named
				// as tier 1's line and compile --test name it (decide.LandlockLinkRefusal).
				if name, refused := r.rules.landlockLinkRefusal(path, payload.Path2); refused {
					rule = name
					return record.VerdictRefused, decide.OpReason(op)
				}
				return record.VerdictAllow, ""
			}
		}
		if op == record.FSUnlink {
			// The Landlock floor asks an unlink's or an rmdir's REMOVE_* of its directory, under every tier: tier 3's
			// hooks decide on the object and allowed a file-level write entry's own unlink the floor refuses. A chain
			// refusal it explains is the floor's, named by the directory as compile --test names it
			// (decide.LandlockDeleteRefusal).
			if name, refused := r.rules.landlockDeleteRefusal(path); refused {
				rule = name
				return record.VerdictRefused, decide.OpReason(op)
			}
		}
		return infer(m)
	})
	switch {
	case fv.plane:
		rule = fv.rule
	case sup != nil:
		rule = sup.rule
	case fv.verdict == record.VerdictAllow && resolved:
		rule = r.grantName(op, path, rule)
	}
	ev := r.event(rec, record.KindFS, rule, fv.verdict, fv.reason)
	r.setPayload(ev, r.fsGatePayload(rec, fv.payload(payload)))
	r.emitAction(ev)
}

// continued is the supervisor's naming of one action (ContinuedFS).
type continued struct {
	path, path2, rule string
	verdict           record.Verdict
	reason            record.Reason
}

// continuedFS asks the supervisor how it named the action of rec, keyed by the thread, the operation and each
// end's final component; nil when it has none.
func (r *Recorder) continuedFS(rec *Record, op string, twoEnds bool) *continued {
	if r.opts.ContinuedFS == nil || rec.FS.Path == "" {
		return nil
	}
	name2 := ""
	if twoEnds {
		name2 = rec.FS.Path2
	}
	p, p2, rule, v, reason, ok := r.opts.ContinuedFS(int(rec.TID), op, rec.FS.Path, name2, rec.MonoNS)
	if !ok {
		return nil
	}
	return &continued{path: p, path2: p2, rule: rule, verdict: v, reason: reason}
}

// fsLine is what fsVerdict decided for one fs line: the verdict and reason, where they came from, and, for a
// refusal no Tego mechanism explains, the errno and who.
type fsLine struct {
	verdict record.Verdict
	reason  record.Reason
	from    string // record.FSVerdictChain or record.FSVerdictModel
	errno   int
	by      string // record.FSByOther, or ""
	// plane is set on a refusal the kernel decision plane made (planeFS): its rule replaces the model's, and the
	// line names the mechanism, the plane's mode and its own cause.
	plane       bool
	rule        string
	planeReason string
	mode        string
}

// payload adds the line's verdict source and, for a refusal by another mechanism, its errno to an fs payload,
// and a plane refusal's mechanism, mode and cause.
func (l fsLine) payload(p record.FSPayload) record.FSPayload {
	p.VerdictFrom, p.Errno, p.By = l.from, l.errno, l.by
	if l.plane {
		p.Mechanism, p.DecisionPlane, p.PlaneReason = record.MechanismPlane, l.mode, l.planeReason
	}
	return p
}

// ruleOr is the plane's rule on a plane refusal, else rule.
func (l fsLine) ruleOr(rule string) string {
	if l.plane {
		return l.rule
	}
	return rule
}

// fsVerdict decides one fs line (ADR 0016 (1), (3)). A sample that carries the LSM chain's return, which the
// fexit programs read after the security_ function ran, has that return as its verdict (decide.ChainFS): 0 is
// allow, a refusal the tier model explains is refused with the model's reason, and any other refusal is observed
// with its errno and by: other. model is the tier model (InferFS), asked only to explain a refusal. A sample
// without a return — a kernel whose record does not carry it, or chain false for an action another mechanism
// answers outside the chain — keeps the model's verdict, and the line says which one produced it. An enforcing
// program's own refusal in the header wins over both, as it always has (verdict).
func (r *Recorder) fsVerdict(rec *Record, path string, chain bool, model func() (record.Verdict, record.Reason)) fsLine {
	if rec.Verdict == KernelRefused && (rec.Kind == KindOpen || rec.Kind.IsFSOp()) {
		// On an fs record only the decision plane's refusal is on the header, stamped by the fexit that read it
		// for this very call (trace_proc tego_plane_stamp): the plane refused, and the chain returned its
		// -EACCES.
		pl, ok := r.planeFS(rec, fsOp(rec.Kind), path)
		if !ok {
			r.gap(GapMalformedRecord, 1)
		}
		return fsLine{verdict: record.VerdictRefused, reason: pl.reason, from: record.FSVerdictChain, plane: true,
			rule: pl.rule, planeReason: pl.planeReason, mode: r.opts.DecisionPlane}
	}
	if rec.Verdict == KernelRefused || !chain || !rec.FS.RetOK {
		v, reason := r.verdict(rec, model)
		return fsLine{verdict: v, reason: reason, from: record.FSVerdictModel}
	}
	v, reason, other := decide.ChainFS(rec.FS.Ret, model)
	l := fsLine{verdict: v, reason: reason, from: record.FSVerdictChain}
	if other {
		l.errno, l.by = int(-rec.FS.Ret), record.FSByOther
	}
	return l
}

// emitAction emits an action line; under record: off, only a refusal (ADR 0016 (3), record()).
func (r *Recorder) emitAction(ev *record.Event) {
	if r.silent && ev.Verdict != record.VerdictRefused {
		return
	}
	r.emit(ev)
}

// dirUnresolvedGap counts R9's directory-index miss for one fs action: a name the index could not resolve. A
// truncated name is never looked up and has its own path-truncated gap, so it is not also a dir-unresolved miss.
func (r *Recorder) dirUnresolvedGap(resolved, truncated bool) {
	if !resolved && !truncated {
		r.gap(GapDirUnresolved, 1)
	}
}

// resolveFSOpPath turns one side of an fs-operation sample into a path: an absolute string the
// kernel resolved (only security_file_open may produce one), the parent directory's path the kernel walked for a
// run a plane mode decides (dirWalk bpf.DirOK) joined with the final component, or the directory index's answer
// for a (dev, ino) plus final component. A walk that could not prove its path (bpf.DirLong, DirRaced,
// DirUnreachable) is never used: the index names the side when it holds the directory, and a miss is the raw
// dev:ino/name identifier with no rule, as before.
func (r *Recorder) resolveFSOpPath(dev, ino uint64, name string, truncated, haveDir bool, dir string,
	dirWalk bpf.DirState) (string, fsMatch, bool) {
	if truncated {
		r.gap(GapPathTruncated, 1)
		return TruncatedPath, fsMatch{Rule: RuleUnmatched}, false
	}
	if dirWalk == bpf.DirOK && name != "" && name[0] != '/' {
		path := dir + "/" + name
		return path, r.rules.matchFS(path), true
	}
	if len(name) > 0 && name[0] == '/' {
		m := r.rules.matchFS(name)
		return name, m, m.Entry != nil
	}
	if !haveDir {
		return name, fsMatch{Rule: RuleUnmatched}, false
	}
	return r.rules.matchDir(dev, ino, name)
}

// handleNet records one connect or unconnected datagram. The address bytes are the kernel's, so a
// family this build does not know is recorded as an unmatched action rather than dropped.
//
// A destination the run's supervisor continued is named by the supervisor's own lookup (ContinuedNet): its
// line is the one this sample replaces (docs/p0/supervisor.md R7), and this package's matcher knows neither
// the resolver exception nor the resolved-address check, so a DNS query the supervisor names net.resolver
// was recorded unmatched (§5 R5). Anything else is named against the contract's entries.
func (r *Recorder) handleNet(rec *Record) {
	addr, ok := addrFrom(rec.Net.Family, rec.Net.Addr)
	proto := protoName(rec.Net.Proto)
	rule, host, inferred, named := RuleUnmatched, "", record.VerdictObserved, false
	if ok && r.opts.ContinuedNet != nil {
		rule, host, inferred, named = r.opts.ContinuedNet(netip.AddrPortFrom(addr, rec.Net.Port), proto)
	}
	if !named {
		rule, host, inferred = RuleUnmatched, "", record.VerdictObserved
		if ok {
			var matched *agent.NetRule
			if rule, matched = r.rules.matchNet(addr, rec.Net.Port, proto); matched != nil {
				host, inferred = matched.Host, record.VerdictAllow
				if matched.Verdict == agent.VerdictRefused {
					inferred = record.VerdictRefused
				}
			}
		}
	}
	verdict, reason := r.verdict(rec, func() (record.Verdict, record.Reason) {
		if inferred == record.VerdictRefused {
			return record.VerdictRefused, record.ReasonNetNotAllowed
		}
		return inferred, ""
	})
	// netip's spelling, as the supervisor's line has it: an IPv6 address in brackets.
	dst := netip.AddrPortFrom(addr, rec.Net.Port).String()
	if !ok {
		dst = fmt.Sprintf("family%d:%d", rec.Net.Family, rec.Net.Port)
	}
	ev := r.event(rec, record.KindNet, rule, verdict, reason)
	r.setPayload(ev, record.NetPayload{Proto: proto, Dst: dst, Host: host})
	r.emit(ev)
}

// verdict resolves the verdict and reason of one sample. An explicit kernel refusal always wins:
// the program that refused is the one decision-maker, so record and enforcement cannot disagree
// (§5 R5). Everything else is inferred from the contract, because every ring-buffer producer in
// tier 2 is record-only (R5, R8, R9) and leaves the header's verdict at its zero value — treating
// that zero as an enforced "allow" would silently overrule the contract on every sample.
func (r *Recorder) verdict(rec *Record, infer func() (record.Verdict, record.Reason)) (record.Verdict, record.Reason) {
	if rec.Verdict != KernelRefused {
		return infer()
	}
	reason, ok := ReasonFor(rec.Reason)
	if !ok && rec.Reason != ReasonNone {
		r.gap(GapMalformedRecord, 1)
	}
	if reason == "" {
		reason = record.ReasonPathUnresolved
	}
	return record.VerdictRefused, reason
}

// event builds the common fields of one action event. Seq, id and prev belong to the ledger writer;
// mono_ns is the kernel's own bpf_ktime_get_ns() value, never a userspace clock (E20).
func (r *Recorder) event(rec *Record, kind record.Kind, rule string, verdict record.Verdict, reason record.Reason) *record.Event {
	return &record.Event{
		V:      record.Version,
		TS:     r.opts.Now(),
		MonoNS: rec.MonoNS,
		Run:    r.run.ID,
		Agent:  r.run.Agent,
		PID:    int(rec.PID),
		TID:    int(rec.TID),
		Cgroup: rec.CgroupID,
		Kind:   kind,
		Source: record.SourceKernel,
		Rule:   rule,
		// Every action event needs a valid authority (spec/record/v1 validateAction); the contract's
		// rule table is the authority here even when no entry matched.
		Authority: record.AuthorityRule,
		Verdict:   verdict,
		Reason:    reason,
		Attr:      record.Unattributed(),
	}
}

// setPayload attaches a payload, turning the impossible marshal failure into a decode gap rather
// than dropping the event silently.
func (r *Recorder) setPayload(ev *record.Event, payload any) {
	if err := ev.SetPayload(payload); err != nil {
		r.gap(GapMalformedRecord, 1)
	}
}

// emitAggregates turns each flushed bucket into one fs event with its count (R13).
func (r *Recorder) emitAggregates(flushed []aggregate) {
	for _, a := range flushed {
		ev := &record.Event{
			V:         record.Version,
			TS:        r.opts.Now(),
			MonoNS:    a.LastNS,
			Run:       r.run.ID,
			Agent:     r.run.Agent,
			PID:       a.PID,
			TID:       a.TID,
			Cgroup:    a.Cgroup,
			Kind:      record.KindFS,
			Source:    record.SourceKernel,
			Rule:      a.Rule,
			Authority: record.AuthorityRule,
			Verdict:   record.VerdictAllow,
			Attr:      record.Unattributed(),
		}
		r.setPayload(ev, record.FSPayload{Op: record.FSOpen, Path: a.Path, Count: int(a.Count)})
		r.emit(ev)
	}
}

// emit hands one event to the sink. The sink never blocks (runtime.Queue drops and counts), so this
// is the last step of the drain loop and never a back-pressure point (I7).
func (r *Recorder) emit(ev *record.Event) {
	if r.sink == nil {
		return
	}
	r.sink.Emit(ev)
}

// gap counts one uncovered thing for the run's gap report.
func (r *Recorder) gap(why string, n int64) {
	r.mu.Lock()
	r.gaps[why] += n
	r.mu.Unlock()
}

// isWrite reports whether an open's flags asked for write access. It mirrors the seccomp filter's
// own 0x243 test (O_WRONLY|O_RDWR|O_CREAT|O_TRUNC, docs/p0/enforce-landlock.md R15) so both tiers
// classify one open the same way.
func isWrite(flags uint32) bool {
	const mask = unix.O_WRONLY | unix.O_RDWR | unix.O_CREAT | unix.O_TRUNC
	return flags&mask != 0
}

// fsOp names the record.FS* operation of an fs-operation sample.
func fsOp(k Kind) string {
	switch k {
	case KindUnlink, KindRmdir:
		return record.FSUnlink
	case KindRename:
		return record.FSRename
	case KindMkdir:
		return record.FSMkdir
	case KindLink:
		return record.FSLink
	case KindSymlink:
		return record.FSSymlink
	case KindTruncate:
		return record.FSTruncate
	default:
		return record.FSOpen
	}
}

// protoName maps an IP protocol number to the record vocabulary; anything else is "raw", the
// record-only class of R4's stated P0 gap.
func protoName(p uint8) string {
	switch p {
	case unix.IPPROTO_TCP:
		return agent.ProtoTCP
	case unix.IPPROTO_UDP:
		return agent.ProtoUDP
	default:
		return protoRaw
	}
}

// addrFrom reads the address bytes of a net sample. The sample lays them out the way the verdict maps key
// them (AF_INET in the first four bytes, AF_INET6 all sixteen), so it is bpf.AddrFrom, the inverse of the
// key builder, rather than a second decoder that could drift from it. A v4-mapped address is unmapped, so a
// dual-stack socket's connect matches the IPv4 entry the contract declared. An unknown family yields
// ok=false and is recorded without an address.
func addrFrom(family uint8, b [16]byte) (netip.Addr, bool) {
	a, err := bpf.AddrFrom(family, b)
	if err != nil {
		return netip.Addr{}, false
	}
	return unmapped(a), true
}

// pinnedMapPath is where a build pins one of its maps: <root>/<bpf_hash>/maps/<name>, root defaulting
// to PinDir (docs/p0/enforce-cgroup-observe.md §3's "Pins" row).
func pinnedMapPath(root, bpfHash, name string) string {
	if root == "" {
		root = PinDir
	}
	return filepath.Join(root, bpfHash, "maps", name)
}

// openPinned opens a build's pinned ring outer and per-run lost counter, which the recorder opens the run's own
// ring and counter from at Start (openRing).
//
// The lost counter is required, not optional. Every tier-2 object declares tego_lost beside tego_events, so a
// build with the one pinned and not the other is not a build this recorder understands, and draining its ring
// without the counter would turn every kernel-side drop into a silence where §8 I7 requires a ringbuf-full gap.
// Refusing here leaves the run to record kernel-record-unavailable instead, which says the same thing about the
// whole record.
func openPinned(root, bpfHash string) (rings, lost *ebpf.Map, err error) {
	eventsPath := pinnedMapPath(root, bpfHash, EventsMapName)
	rings, err = ebpf.LoadPinnedMap(eventsPath, &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return nil, nil, fmt.Errorf("observe: open pinned ring outer %s: %w", eventsPath, err)
	}
	lostPath := pinnedMapPath(root, bpfHash, LostMapName)
	lost, err = ebpf.LoadPinnedMap(lostPath, &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		_ = rings.Close()
		return nil, nil, fmt.Errorf("observe: open pinned lost counter %s: %w", lostPath, err)
	}
	return rings, lost, nil
}

// slotLost reads one run's lost counter, its slot of the build's per-run array (§3's "Lost counter" row).
type slotLost struct {
	m    *ebpf.Map
	slot uint32
}

// Lost reads the run's count.
func (p *slotLost) Lost() (uint64, error) {
	n, err := bpf.SlotCount(p.m, p.slot)
	if err != nil {
		return 0, fmt.Errorf("observe: read lost counter: %w", err)
	}
	return n, nil
}

// sortGaps orders a gap report by reason so a run's gap lines are stable.
func sortGaps(g []source.Gap) {
	sort.Slice(g, func(i, j int) bool { return g[i].Why < g[j].Why })
}

// The inode of the initial pid namespace (PROC_PID_INIT_INO, include/linux/proc_ns.h), which every kernel
// gives it.
const procPidInitIno = 0xEFFFFFFC

// hostNamespaces is Options.namespaceCheck's default: it refuses a launcher whose pids or monotonic clock are
// not the kernel's own. The ring's samples carry the initial pid namespace's pids (bpf_get_current_pid_tgid)
// and bpf_ktime_get_ns() readings, and this process compares them with the pids and the CLOCK_MONOTONIC it
// sees: from a pid namespace of its own every pid named the wrong process (a child of 7 was recorded as 157),
// and in a time namespace with an offset every kernel clock reading the record carries (mono_ns, the start times
// the process cache matches /proc against) is on another clock than this process's. Refused, the recorder reads
// nothing and the run records the gap.
func hostNamespaces() error {
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &st); err == nil && st.Ino != procPidInitIno {
		return errors.New("observe: the launcher is in a pid namespace of its own, and the kernel record's pids are the initial namespace's")
	}
	if b, err := os.ReadFile("/proc/self/timens_offsets"); err == nil && timensOffset(b) {
		return errors.New("observe: the launcher's time namespace offsets its clocks from the kernel's, whose readings the ring carries")
	}
	return nil
}

// timensOffset reports whether a /proc/<pid>/timens_offsets table ("monotonic <secs> <nanosecs>" and
// "boottime ...") offsets either clock.
func timensOffset(b []byte) bool {
	for line := range strings.SplitSeq(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && (f[1] != "0" || f[2] != "0") {
			return true
		}
	}
	return false
}
