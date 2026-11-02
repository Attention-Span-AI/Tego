// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/runtime/capture/httpstream"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Name is the source name this component reports to the run facade.
const Name = "uprobe"

// Gap reasons this source reports (record.GapPayload.Why, the closed set of R37).
const (
	// GapNoOpenSSL is R4 finding nothing to read, and — because the closed why set has no value for
	// it — a /proc/<pid>/maps the kernel refused us, a library whose process exited before it could be
	// read (OnOpen), and an attach the verifier or the host rejected (edge case #31, §7's "Uprobe attach
	// fails" row). The detail goes to the run's own log.
	GapNoOpenSSL = "no-openssl"
	// GapStaticTLSNoSymbols is a process whose every readable candidate exports none of R1-R3's symbols:
	// Bun's BoringSSL, a rustls binary, a stripped interpreter copy (edge case #5) — and, since only E71's
	// signature scan could tell them apart, a process with no TLS stack at all (R4, R37).
	GapStaticTLSNoSymbols = "static-tls-no-symbols"
	// GapRingBufferDrop is a chunk lost between the probe and userspace: the kernel's own lost-sample
	// counter, a chunk that never reached the ring buffer because it was full and the traced process was
	// never blocked for it (I1, I7); and a chunk of this run still on the ring when Stop's final drain ran
	// out of its budget (Options.StopDrain), counted rather than reassembled (edge case #28).
	GapRingBufferDrop = "ring-buffer-drop"
	// GapSizeCap is a record this build could not decode and the scratch-map eviction of R5.
	GapSizeCap = "size-cap"
	// GapMechanismUnavailable is R37's value for a mechanism that never ran: here, a source whose capture
	// object could not be loaded or whose ring buffer could not be opened when the run started (the run has no
	// capture ring when the host's bpf.ring_budget had no room for it, ADR 0026 (2)), and one no kernel record
	// was there to drive. Its binary is the mechanism's own name, as capture.Select writes it for a factory that
	// failed, and it carries no count: the source lost no event it had.
	GapMechanismUnavailable = "mechanism-unavailable"
)

// errRecordOff is why a record: off run's uprobe source does not capture (Start): with no stall budget it places
// no probe either.
var errRecordOff = errors.New("record: off keeps no model traffic, so no probe is placed")

// errRecordOffActivity is errRecordOff for a record: off run whose stall_after is bounded: the source places the
// probes so that the run's TLS calls stamp its activity, and captures nothing (activityOnly).
var errRecordOffActivity = errors.New("record: off keeps no model traffic: the probes only stamp the stall check's activity")

// DefaultAttachBudget is §4's budget for discovery and attach together, per exec. Past it the attach is
// abandoned for that exec and left to the tree's next one (edge case #1).
const DefaultAttachBudget = 50 * time.Millisecond

var (
	// ErrAlreadyStarted is Start called twice on one Uprobe; it is not idempotent.
	ErrAlreadyStarted = errors.New("uprobe: already started")
	// ErrNoReader is New with neither a ring-buffer reader nor a build to open one from.
	ErrNoReader = errors.New("uprobe: no ring buffer reader")
	// ErrAttachFailed wraps every attach failure. It is never returned fatally: a binary that cannot
	// be hooked is a gap and the run continues (§4).
	ErrAttachFailed = errors.New("uprobe: attach failed")
	// errStopped is an exec that reached the attach cache only after Stop's sweep. The reference it
	// took has already been given back (see own), and the run is over, so it is neither a capture nor
	// a gap.
	errStopped = errors.New("uprobe: source stopped")
	// errOpenCap is a library opened by name past MaxOpenAttach distinct attaches in the run.
	errOpenCap = errors.New("uprobe: too many distinct libraries opened by name")
)

// MaxOpenAttach bounds how many distinct libssl files one source attaches because a process opened them
// (OnOpen), beyond the host's own (MaxPreattach) and an exec's mappings (MaxScan). Each is six probes, link
// fds in the launcher and pin and lock files, held while the process lives, and the file is one the agent may
// write and name as it likes. A library past the bound is a gap why=size-cap naming it, and is not attached.
const MaxOpenAttach = 64

// owners numbers every Uprobe, so the attach cache can tell one source's reference on a process from
// another's that carries the same pid (see refKey).
var owners atomic.Uint64

// RingReader is the capture ring buffer this source drains. *ringbuf.Reader satisfies it; a test supplies
// a reader over synthetic chunk records so the whole decode, reassembly and event path runs with no kernel.
type RingReader interface {
	// ReadInto blocks for the next sample and puts it in rec, reusing rec.RawSample's array when it is
	// large enough, returns os.ErrDeadlineExceeded at the deadline and ringbuf.ErrClosed once Close has
	// been called. The drain reads every chunk into one Record, which spares it the allocation per chunk
	// that Read makes; the price is that a chunk's bytes last only until the next read.
	ReadInto(rec *ringbuf.Record) error
	// SetDeadline bounds the next read so the drain wakes to poll the lost counter.
	SetDeadline(t time.Time)
	// Close unblocks a pending read and releases the reader.
	Close() error
}

// flushReader is a RingReader that Stop can wake without closing it and that says how much it still holds;
// *ringbuf.Reader is one. See Uprobe.finalDrain.
type flushReader interface {
	Flush() error
	AvailableBytes() int
}

// ringRecordBytes is how far one sample of n bytes moves the ring's consumer position: the kernel's 8-byte
// record header, then the data padded to 8 bytes (kernel/bpf/ringbuf.c, BPF_RINGBUF_HDR_SZ).
func ringRecordBytes(n int) int { return 8 + (n+7)&^7 }

// LostCounter reads the kernel's cumulative count of chunks that never reached the ring buffer.
type LostCounter interface {
	// Lost returns the cumulative count across every CPU.
	Lost() (uint64, error)
}

// BlobStore is the content-addressed body store; internal/ledger's BlobRepository satisfies it. Bodies go
// through it rather than through a payload field so the bytes on disk are exactly the decoded bytes, with
// no JSON string in between to mangle anything that is not UTF-8 (I10).
type BlobStore interface {
	PutStream(r io.Reader) (sha string, size int64, err error)
}

// Options configure an Uprobe. One of Reader, BPFHash and Kernel is required; everything else has a working
// default.
type Options struct {
	// Rules is the compiled contract: models[] name the endpoints an ssl_request is attributed to,
	// and Record off or summary decides whether bodies are stored at all.
	Rules *agent.RuleTable
	// Reader drains the capture ring buffer. Nil means "open the run's own capture ring from the build BPFHash
	// names", at Start, by the run's slot.
	Reader RingReader
	// Lost reads the kernel's lost-sample counter. Nil disables ring-buffer-drop accounting.
	Lost LostCounter
	// BPFHash names the pin directory under PinRoot when Reader is nil; PinRoot overrides the
	// default bpffs location. New opens that build's pinned capture ring outer, and Start the run's own ring.
	BPFHash string
	PinRoot string
	// Kernel is the production shape: the source follows the tier's kernel record. The build is named
	// later, by FollowKernel, and Start — not New — loads the capture object under that build's pins,
	// attaches through it when Attacher is nil, and opens the run's own capture ring, which the tier-2
	// backend placed at the run's slot at Prepare (ADR 0026 (3)). The capture sources are built before the
	// run, and nothing of the build is pinned until the tier-2 backend has prepared it.
	Kernel bool
	// Attacher places the uprobes. Nil means the cilium/ebpf one over the loaded capture object,
	// which needs privilege; tests supply their own.
	Attacher Attacher
	// StateDir is the directory the library locks of shared probes live in (ADR 0026 (7), shared.go). Empty
	// means the verified /run/tego when PinRoot is the default too, and no sharing otherwise: a test's own
	// pin root places this run's own probes, as before, unless it names a state directory as well.
	StateDir string
	// Detach removes a library's probes once the last run holding them has left; nil queues it for
	// StartDetaches, which runs this tego as DetachCommand to wait out ProbeGrace and unpin them
	// (spawnDetach). A test passes one to see it.
	Detach func(detachJob)
	// Preattach lists the libraries Start attaches before the run's first process exists (see
	// preattach). Nil means the host's libssl files (systemLibraries) in Kernel mode and none otherwise; a
	// function that returns nothing turns it off, and so does Rules' record: off, whatever the list.
	Preattach func() []string
	// PreattachBudget overrides DefaultPreattachBudget.
	PreattachBudget time.Duration
	// Cache is the host-wide attach cache. Nil means one private to this source, which is what a
	// single-run launcher wants; a host-wide daemon passes a shared one (§11).
	Cache *cache
	// Blobs stores decoded bodies. Nil means bodies are sized and hashed into nothing: the events
	// still carry their size, which is what `record: summary` wants anyway.
	Blobs BlobStore
	// Deriver reads each captured pair: the ssl_response's model, usage and parser_version, and the
	// decision events after it (see emitResponse). Nil records every exchange underived.
	Deriver Deriver
	// OpenBlobs builds the body store for a run when Blobs is nil, from the run directory Start is
	// given: the store is per run (record-ledger R11), and the run directory does not exist when the
	// capture sources are built.
	OpenBlobs func(run source.RunRef) BlobStore
	// Proc reads /proc. Nil means the system's.
	Proc *proc.FS
	// Assembler reassembles the chunks. Nil means one private to this source, which is the only production
	// use: Stop closes it for good (CloseAll), so it is never shared with another source.
	Assembler *httpstream.Assembler
	// AttachBudget overrides DefaultAttachBudget; MaxScan overrides DefaultMaxScan.
	AttachBudget time.Duration
	MaxScan      int
	// PollInterval is how often an idle drain wakes to poll the lost counter.
	PollInterval time.Duration
	// StopDrain overrides DefaultStopDrain.
	StopDrain time.Duration
	// Now supplies wall-clock stamps; nil means time.Now. mono_ns always comes from the kernel's own
	// bpf_ktime_get_ns() value on the record, never from here.
	Now func() time.Time
	// Logger receives the detail a closed gap reason cannot carry (edge case #31). Nil discards it.
	Logger *slog.Logger
	// OnError is called once with the error that ended the drain goroutine, so the run's errgroup can
	// cancel. Nil leaves it to Stop.
	OnError func(error)
	// RunSet is the build's run membership map (see RunSet). Start reads this run's slot from it, which names
	// the run's capture ring; from then on a chunk is this run's when it carries that slot. Nil with a Reader
	// means the ring holds this run's chunks alone, which is what a test's synthetic ring holds, and the cgroup
	// set filters instead; a source that opens pins opens the pinned map.
	RunSet RunSet
}

// DefaultPollInterval is how often an idle drain wakes to read the kernel's lost counter.
const DefaultPollInterval = 2 * time.Second

// DefaultStopDrain bounds how long Stop's final drain reassembles chunks (finalDrain). Past it, what is left
// of this run's on the ring is counted into ring-buffer-drop rather than reassembled, which bounds the
// drain by the ring's size instead of by the work its chunks cause (bodies stored, responses derived).
const DefaultStopDrain = 2 * time.Second

// Uprobe is the OpenSSL capture source: it attaches probes per binary as processes exec, drains the
// plaintext chunks they produce, reassembles HTTP/1.1 from them and emits ssl_request/ssl_response events.
//
// It satisfies source.Source. §2 of the spec calls the gap accessor Coverage(); the merged
// internal/runtime owns the producer contract and calls it Gaps(), so that is the shape here.
type Uprobe struct {
	opts  Options
	cache *cache
	disc  *discoverer
	asm   *httpstream.Assembler
	// owner is this source's half of every refKey it puts in the attach cache.
	owner uint64

	reader RingReader
	// owned are the run's ring Start opened; rings and lostMap are the build's pinned capture ring outer and
	// per-run lost counter New or Start opened, which the run's ring and counter are read from by its slot.
	// lostMap is closed apart and last, because Stop reads the counter once more after the ring is closed.
	owned    []io.Closer
	rings    *ebpf.Map
	lostMap  *ebpf.Map
	closer   sync.Once
	stopOnce sync.Once
	// halt tells the drain goroutine to return at its next chunk or wake-up without closing the ring, so
	// Stop's final drain can still read what the goroutine left (haltDrain, finalDrain).
	halt atomic.Bool
	// kernel holds what Start loaded in Kernel mode — the capture collection and the attacher over it —
	// for Stop to release once every link this source took has been given back.
	kernel []io.Closer

	mu      sync.Mutex
	started bool
	// openAttached counts the distinct libraries attached for an open, against MaxOpenAttach.
	openAttached int
	// ready is set once Start has what a hook's attach needs (the attacher openKernel makes) and has decided
	// to capture; the recorder can call a hook before and during Start (live).
	ready bool
	// startDone closes once Start has published its reader and owned resources, including failure paths.
	// Stop joins it before waking the drain or consuming any resource's closer.
	startDone chan struct{}
	done      chan struct{}
	err       error
	gaps      map[gapKey]*source.Gap
	cgroups   map[uint64]struct{}
	run       source.RunRef
	sink      source.Sink
	lost      uint64
	// asmFolded is the reassembler's cumulative count per reason that is already inside gaps, so a
	// repeated fold adds only the growth. See collectAssemblerGaps.
	asmFolded map[string]int64
	// pids are the processes whose reference in the attach cache this source holds and has not yet
	// given back. See releaseOwned for why it is not the cache's whole contents.
	pids map[int]struct{}
	// stopped is set when Stop begins. From then on a reference an exec still in flight takes is given
	// back by own rather than recorded in pids, which nothing would ever sweep again (I9).
	stopped bool
	// bpfHash is the build FollowKernel named, for a Kernel-mode Start to load and open.
	bpfHash string
	// runSet names the run's slot (Options.RunSet); runSetOwned is the pinned map this source opened for it,
	// closed with the rest of the kernel side at Stop. scoped, slot and gen are Start's reading of this run's
	// row, under mu: once scoped, a chunk is this run's only when it carries slot and gen, the generation that
	// keeps a chunk the slot's previous run left in the ring this run reuses out (ADR 0026 (6) as amended).
	runSet      RunSet
	runSetOwned io.Closer
	scoped      bool
	slot        uint32
	gen         uint32
	// syncErr is Stop's failure to make this run's bodies durable (syncBlobs), returned with the drain's.
	syncErr error
	// inert is a source that never got its kernel side: Start recorded mechanism-unavailable and every
	// exec, open and exit is ignored, because nothing could be attached and one gap already says so.
	inert bool
	// cause is why an inert source is not running, for the runtime's refusal of a budgeted run
	// (UnavailableCause); "" while it runs.
	cause string
	// activityOnly is an inert source that places probes all the same: a record: off run whose stall_after is
	// bounded (stampsActivity), whose TLS calls the shared probes stamp into its slot of tego_activity for the stall
	// check (limits R4, A-REC-3). It reads no ring and reports no coverage: its only gap is the mechanism's own.
	activityOnly bool
	// uncaptured is each live process's standing verdict from its last exec: the gap it will leave if
	// nothing of it is ever captured. It is held rather than recorded because an exec is not the last
	// chance: a dynamically loaded libssl (CPython's _ssl, a dlopen) is not mapped when the exec is seen,
	// and the open that loads it attaches the process later (OnOpen). Recording at exec would put a
	// static-tls-no-symbols line in the ledger for a process whose every exchange was captured. A verdict
	// becomes a gap when its process execs again, exits, or the source stops, and it is settled through
	// cov, so derive.Classify names its reason.
	uncaptured map[int]pendingGap
	// cov is this run's per-process gap ledger (derive.Coverage): every settled verdict, by binary and
	// reason. gaps holds everything else this source reports.
	cov *derive.Coverage

	// Owned by the drain goroutine between Start and its return.
	pending map[httpstream.ConnKey]map[int]*openRequest
	// connHosts is the Host of each connection's last request (noteHost), for the loss accounting of a
	// connection capture loses (loseConn).
	connHosts map[httpstream.ConnKey]string
	// ptrs is the thread each process's SSL* last did its I/O on (edge case #11, followPtr).
	ptrs map[ptrKey]ptrState
}

// ptrKey names one SSL* of one process.
type ptrKey struct {
	pid uint32
	ssl uint64
}

// ptrState is the thread an SSL*'s I/O was last seen on, and whether its connection was given up.
type ptrState struct {
	tid  uint32
	dead bool
}

// maxTrackedPtrs bounds ptrs. Past it the followed pointers are forgotten and the next chunk of one starts
// a connection that is passed over until a request begins on it; pointers given up stay dead. Only when
// dead ones alone fill the table is it cleared whole.
const maxTrackedPtrs = 2 * httpstream.DefaultMaxConns

// pendingGap is one process's held gap: see Uprobe.uncaptured. proc is what discovery read, from which
// derive.Classify names the reason and whose Binary the gap names. image is the executable the verdict was
// reached for, which is how a second exec record of one image is told from a new image.
type pendingGap struct {
	proc          derive.Process
	detail, image string
}

// gapKey groups gaps by reason and binary, which is how a gap event names them (R37).
type gapKey struct {
	Why    string
	Binary string
}

// openRequest is what a response needs from the request it answers. Msg is the request as derive reads it,
// kept only when the source has a Deriver.
type openRequest struct {
	// Pair links the request's line with its response's in the pipeline (Event.Pair).
	Pair   uint64
	Method string
	Path   string
	Host   string
	// BadTarget says the request target was neither origin-form, "*" nor an http(s) URL (derive.SplitTarget):
	// what it reached is unknown, so a successful answer to it, or its loss, is reported unmetered.
	BadTarget bool
	// Tunnel is a CONNECT, whose target names the host the tunnel reaches: its answer opens a tunnel and is no
	// model call (ADR 0035).
	Tunnel bool
	// MaxTokens is the request's max_tokens where derive cannot read it (httpstream.Message.MaxTokens,
	// holdBody), 0 when unknown.
	MaxTokens int
	StartNS   uint64
	Msg       *derive.Message
	// held is what Msg's body holds of the reassembler's budget until the response arrives (holdBody).
	held int64
	// ReadAs is the parser_version of a request derive read as it was captured (deriveRequest), which its
	// response carries; Msg is then nil, since nothing more is derived of the exchange.
	ReadAs string
}

// Deriver turns one captured exchange into the facts an ssl_response carries and the decisions that follow
// it. *derive.Dispatcher is the implementation, the one the forwarder is given; nil records without deriving.
type Deriver interface {
	Handle(req, resp *derive.Message, meta derive.Meta) (derive.Result, error)
}

// requestDeriver is a Deriver that also reads what a request says alone as it is captured
// (derive.Dispatcher.HandleRequest): a declared HTTP MCP server's tool calls (capture-derive R41).
type requestDeriver interface {
	HandleRequest(req *derive.Message, meta derive.Meta) (derive.Result, bool)
}

// requestReader is a Deriver that also reads what a request says alone (derive.Dispatcher.ReadRequest): whether it
// is a model host's side traffic, and the tool results a model turn reports, which the request line carries for
// the attribute stage (capture-derive R40, R42).
type requestReader interface {
	ReadRequest(req *derive.Message, meta derive.Meta) derive.RequestReading
}

var _ source.Source = (*Uprobe)(nil)

// New builds an Uprobe. It opens no kernel object when Options.Reader is set, which is how the unit tests
// drive the whole path; otherwise it opens the pinned capture ring buffer of the named build.
func New(opts Options) (*Uprobe, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = DefaultPollInterval
	}
	if opts.StopDrain <= 0 {
		opts.StopDrain = DefaultStopDrain
	}
	if opts.AttachBudget <= 0 {
		opts.AttachBudget = DefaultAttachBudget
	}
	if opts.PreattachBudget <= 0 {
		opts.PreattachBudget = DefaultPreattachBudget
	}
	if opts.Proc == nil {
		opts.Proc = proc.New()
	}
	u := &Uprobe{
		opts:       opts,
		cache:      opts.Cache,
		disc:       &discoverer{fs: opts.Proc, maxScan: opts.MaxScan},
		asm:        opts.Assembler,
		owner:      owners.Add(1),
		gaps:       map[gapKey]*source.Gap{},
		cgroups:    map[uint64]struct{}{},
		asmFolded:  map[string]int64{},
		pids:       map[int]struct{}{},
		uncaptured: map[int]pendingGap{},
		cov:        derive.NewCoverage(),
		runSet:     opts.RunSet,
	}
	if u.cache == nil {
		u.cache = newCache()
	}
	if u.asm == nil {
		// A connection the reassembler keeps after passing a response over leaves no error for handle
		// to log, only a count, so what it passed over and why is logged as it happens.
		u.asm = httpstream.NewAssembler(httpstream.Options{BodyScanner: maxTokensScanner, OnGap: func(g httpstream.Gap) {
			u.log("uprobe: gap %s: %s", g.Why, g.Detail)
		}})
	}
	switch {
	case opts.Reader != nil:
		u.reader = opts.Reader
	case opts.BPFHash != "":
		rings, lost, err := openPinned(opts.PinRoot, opts.BPFHash)
		if err != nil {
			return nil, err
		}
		if u.runSet == nil {
			rs, err := openRunSet(opts.PinRoot, opts.BPFHash)
			if err != nil {
				_ = rings.Close()
				_ = lost.Close()
				return nil, err
			}
			u.runSet, u.runSetOwned = rs, rs
		}
		u.rings, u.lostMap = rings, lost
	case opts.Kernel:
		// Start opens the kernel side, once FollowKernel has named the build.
	default:
		return nil, fmt.Errorf("%w: none of Reader, BPFHash and Kernel was set", ErrNoReader)
	}
	return u, nil
}

// FollowKernel names the build whose pins a Kernel-mode source loads its capture object under and drains.
// The run calls it once, before Start, with the hash its enforcement handle pinned the build under, and
// only when that tier's kernel record is running to drive OnExec, OnOpen and OnExit
// (source.KernelFollower). A source it is never called for has no process to attach to, and Start says so
// with a gap instead of draining a ring nothing writes.
func (u *Uprobe) FollowKernel(bpfHash string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.bpfHash = bpfHash
}

// openKernel is Start's half of Kernel mode: read this run's slot (scope), open the run's own capture ring and
// lost counter by it, load the capture object under the followed build's pins, and make the attacher that places
// probes through it (unless the caller supplied one). Everything it opened is closed again on failure, so a
// source that could not open is holding nothing. The ring comes before the load: a run the host's ring budget
// left without one loads and places no probe at all. An activity-only source (ring false) opens no ring: the
// probes it places stamp its activity and write it nothing.
func (u *Uprobe) openKernel(hash string, cgroupID uint64, ring bool) error {
	if hash == "" {
		return errors.New("uprobe: no kernel record to follow: the tier's recorder is not running or reads nothing for this run, so no exec would ever reach OnExec")
	}
	if u.runSet == nil {
		rs, err := openRunSet(u.opts.PinRoot, hash)
		if err != nil {
			return err
		}
		u.runSet, u.runSetOwned = rs, rs
	}
	if err := u.scope(cgroupID); err != nil {
		return err
	}
	if ring {
		if u.rings == nil {
			rings, lost, err := openPinned(u.opts.PinRoot, hash)
			if err != nil {
				return err
			}
			u.rings, u.lostMap = rings, lost
		}
		if err := u.openRing(); err != nil {
			return err
		}
	}
	coll, err := LoadCollection(u.opts.PinRoot, hash)
	if err != nil {
		u.closeReader()
		return err
	}
	var att *EBPFAttacher
	if u.opts.Attacher == nil {
		att = NewAttacher(coll)
		u.opts.Attacher = att
	}
	u.kernel = []io.Closer{closerFunc(func() error { coll.Close(); return nil })}
	if att != nil {
		u.kernel = append([]io.Closer{att}, u.kernel...)
		if u.shares() {
			detach := u.opts.Detach
			if detach == nil {
				detach = queueDetach
			}
			u.opts.Attacher = &sharedAttacher{EBPFAttacher: att, root: buildDir(u.opts.PinRoot, hash),
				state: u.opts.StateDir, hash: hash, detach: detach, logf: u.log}
			// A library whose removal never ran (its detacher killed, with its launcher's cgroup or otherwise)
			// is removed now rather than left attached host-wide until a gc.
			if n, err := SweepLibraries(u.opts.PinRoot, u.opts.StateDir, time.Now()); n > 0 || err != nil {
				u.log("uprobe: removed %d libraries' overdue probes (%v)", n, err)
			}
		}
	}
	return nil
}

// openRing opens this run's own capture ring and lost counter from the build's pinned outer by the run's slot
// (ADR 0026 (1), (3), (5)): the ring is this run's alone, so this source is its only reader by construction. A
// run with no capture ring at its slot is a run the tier-2 backend gave none: its capture is not uprobe, or the
// host's bpf.ring_budget had no room for it (cgroup.Handle.CaptureRefused).
func (u *Uprobe) openRing() error {
	if u.rings == nil {
		return nil // a caller-supplied Reader
	}
	u.mu.Lock()
	slot := u.slot
	u.mu.Unlock()
	ring, ok, err := bpf.RingOf(u.rings, slot)
	if err != nil {
		return fmt.Errorf("uprobe: %w", err)
	}
	if !ok {
		return fmt.Errorf("uprobe: this run has no capture ring at its slot %d: the host's bpf.ring_budget had no "+
			"room for it (`tego doctor` shows the rings in use; raise bpf.ring_budget in /etc/tego/config.yaml or "+
			"wait for other runs to end)", slot)
	}
	reader, err := ringbuf.NewReader(ring)
	if err != nil {
		_ = ring.Close()
		return fmt.Errorf("uprobe: read the capture ring of slot %d: %w", slot, err)
	}
	u.reader, u.owned = reader, []io.Closer{ring}
	if u.opts.Lost == nil {
		u.opts.Lost = &slotLost{m: u.lostMap, slot: slot}
	}
	return nil
}

// shares reports whether this source places its probes shared per library across the build's runs (ADR 0026
// (7)): in production, and in a test that names a state directory for the library locks.
func (u *Uprobe) shares() bool { return u.opts.PinRoot == "" || u.opts.StateDir != "" }

// closerFunc adapts a function to io.Closer.
type closerFunc func() error

// Close calls the function.
func (f closerFunc) Close() error { return f() }

// Name is the source name in the run's diagnostics.
func (u *Uprobe) Name() string { return Name }

// UnavailableCause is why Start left this source inert, "" when it runs (source.UnavailableCause): the
// runtime names it when it refuses a run whose budget this source was to meter.
func (u *Uprobe) UnavailableCause() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.cause
}

// Start begins draining in one goroutine and returns once the probes are on the host's libssl
// (preattach), a few attaches that must be done before the agent runs. That work is what source.Source's
// "return promptly" allows here: it is bounded by PreattachBudget and by ctx, checked before each library,
// and what the bound leaves unattached is attached when a process opens it. The drain itself never holds
// Start up. The goroutine stops on ctx cancellation or Stop, whichever comes first.
func (u *Uprobe) Start(ctx context.Context, run source.RunRef, sink source.Sink) error {
	if sink == nil {
		return fmt.Errorf("uprobe: start %s: nil sink", run.ID)
	}
	u.mu.Lock()
	if u.stopped {
		u.mu.Unlock()
		return fmt.Errorf("%w: run %s", errStopped, run.ID)
	}
	if u.started {
		u.mu.Unlock()
		return fmt.Errorf("%w: run %s", ErrAlreadyStarted, run.ID)
	}
	u.started = true
	u.run, u.sink = run, sink
	if run.CgroupID != 0 {
		u.cgroups[run.CgroupID] = struct{}{}
	}
	hash := u.bpfHash
	done := make(chan struct{})
	startDone := make(chan struct{})
	u.startDone = startDone
	u.done = done
	u.mu.Unlock()
	defer close(startDone)

	if u.opts.Blobs == nil && u.opts.OpenBlobs != nil && run.Dir != "" {
		u.opts.Blobs = u.opts.OpenBlobs(run)
	}
	u.pending = map[httpstream.ConnKey]map[int]*openRequest{}
	u.connHosts = map[httpstream.ConnKey]string{}
	u.ptrs = map[ptrKey]ptrState{}

	var unavailable error
	activity := false
	switch {
	case u.capturesNothing() && u.stampsActivity():
		// record: off with a stall budget: the source captures nothing, as below, but places the probes the build's
		// runs share, so that the run's TLS calls stamp its activity (limits R4, A-REC-3). It reads no ring: one a
		// test handed it is closed. A kernel side that cannot be opened leaves it the record: off source with no
		// probe it would otherwise be.
		u.closeReader()
		u.reader = nil
		activity = true
		if u.opts.Attacher == nil {
			if err := u.openKernel(hash, run.CgroupID, false); err != nil {
				u.warn("uprobe: no probes for this record: off run's stall check, so a model response it streams is no activity: %v", err)
				activity = false
			}
		}
		unavailable = errRecordOff
		if activity {
			unavailable = errRecordOffActivity
		}
	case u.capturesNothing():
		// record: off keeps nothing the capture programs could read, so no probe is placed (live) and the
		// source captures nothing. That is said as this mechanism not running, the one statement run_start
		// reads (runtime.mechanismUnavailable): it claimed capture: uprobe and capture.model_traffic for a run
		// whose model traffic no line records, and whose token, cost and repeats budgets saw none of it (R4).
		// No per-process coverage is reported: there is no capture to measure it against.
		unavailable = errRecordOff
	case u.opts.Kernel && u.reader == nil:
		// Kernel mode. A capture object the kernel will not load, or a run with no capture ring to read, is
		// this mechanism not running for this run: one gap naming it, never a failed run (§4, R37).
		unavailable = u.openKernel(hash, run.CgroupID, true)
	case u.runSet != nil:
		// A source New opened from BPFHash, or a caller's Reader with a run set: the run's slot names its ring.
		if unavailable = u.scope(run.CgroupID); unavailable == nil {
			unavailable = u.openRing()
		}
		if unavailable != nil {
			u.closeReader()
		}
	}
	if unavailable != nil {
		u.mu.Lock()
		u.inert = true
		u.cause = unavailable.Error()
		u.activityOnly = activity
		u.gaps[gapKey{Why: GapMechanismUnavailable, Binary: Name}] = &source.Gap{
			What: record.GapCapture, Why: GapMechanismUnavailable, Binary: Name,
		}
		u.mu.Unlock()
		u.warn("uprobe: capture unavailable for this run: %v", unavailable)
		if activity {
			// Before Start returns, as for a capture run: CPython's _ssl dlopens the host libssl, and the kernel
			// record carries no opens under record: off, so a probe placed only at an open would never be (A-REC-4).
			u.preattach(ctx)
			u.mu.Lock()
			u.ready = true
			u.mu.Unlock()
		}
		close(done)
		return nil
	}
	// The lost counter is cumulative since the build's pins were made, so this run's drops are what it grows
	// by from here, before any probe of this run is placed.
	u.baselineLost()
	// Before Start returns, which is before the run's ack lets the agent exec: see preattach.
	u.preattach(ctx)
	u.mu.Lock()
	u.ready = true
	u.mu.Unlock()

	// Cancellation ends the goroutine but not the capture: the chunks still on the ring are read by Stop's
	// final drain, once the run's processes are gone (Recorder.Start in internal/runtime/observe says why).
	stop := context.AfterFunc(ctx, u.haltDrain)
	go func() {
		defer close(done)
		defer stop()
		err := u.drain()
		u.mu.Lock()
		u.err = err
		u.mu.Unlock()
		if err != nil && u.opts.OnError != nil {
			u.opts.OnError(err)
		}
	}()
	return nil
}

// Stop halts the drain goroutine, drains what is still on the ring (finalDrain), flushes every connection
// still open as a gap rather than a silent half-message (edge case #28), detaches every binary no run still
// wants (I9) and returns the drain's error if it had one. It is safe to call twice and after a Start that
// never ran.
func (u *Uprobe) Stop() error {
	u.mu.Lock()
	u.stopped = true
	started, startDone, done := u.started, u.startDone, u.done
	u.mu.Unlock()
	if started {
		<-startDone
	}
	u.mu.Lock()
	ready := u.ready
	u.mu.Unlock()
	u.haltDrain()
	if started {
		<-done
	}
	u.stopOnce.Do(func() {
		// The drain goroutine has returned, so the reader, the pending requests and the assembler's
		// leftovers belong to this caller.
		if ready {
			u.finalDrain()
		}
		u.closeReader()
		if started {
			u.pollLost()
			u.emitMessages(u.asm.CloseAll())
			// No response is coming for what is still pending; its bodies go back to the budget, which
			// the source owns (Options.Assembler is a test seam), and a request that may have been model
			// spend is reported unmetered (closePending).
			for key := range u.pending {
				u.closePending(key, "a request's response was never seen before the capture source stopped")
			}
		}
		// No body is stored after this point, and the run writes run_end only once every source has
		// stopped, so this is where this source's bodies meet the ledger's barrier (syncBlobs).
		u.syncBlobs()
		u.collectAssemblerGaps()
		for _, c := range u.releaseOwned() {
			_ = c.Close()
		}
		u.flushUncaptured()
		// The final pollLost above needed the counter open; closeReader left it for here.
		for _, m := range []*ebpf.Map{u.rings, u.lostMap} {
			if m != nil {
				_ = m.Close()
			}
		}
		// Every link this source placed is closed or belongs to another run's reference now, so the
		// collection and the attacher can go: a live link holds its own reference on the program.
		for _, c := range u.kernel {
			_ = c.Close()
		}
		if u.runSetOwned != nil {
			_ = u.runSetOwned.Close()
		}
	})
	u.mu.Lock()
	defer u.mu.Unlock()
	return errors.Join(u.err, u.syncErr)
}

// syncBlobs makes the bodies this source stored durable before the run can end. It is record-ledger R6's one
// barrier, blobs before events, met for a store the ledger writer does not own: the source writes bodies
// through its own handle on the run's blob directory (Options.OpenBlobs), and the writer's Close syncs only
// the blobs it stored itself before it syncs events.jsonl. Unsynced, a crash inside that Close would leave a
// ledger that verifies and reads as ended whose ssl_request and ssl_response lines name bodies that were
// only ever in the page cache, with no gap to say they are gone. A store with no Sync (a test's, or the
// hash-only store of record: summary) has nothing to make durable.
func (u *Uprobe) syncBlobs() {
	s, ok := u.opts.Blobs.(interface{ Sync() error })
	if !ok {
		return
	}
	if err := s.Sync(); err != nil {
		u.mu.Lock()
		u.syncErr = fmt.Errorf("uprobe: fsync captured bodies: %w", err)
		u.mu.Unlock()
		u.warn("uprobe: captured bodies are not durable: %v", err)
	}
}

// scope reads this run's slot from its own cgroup's run-set row, which names the run's capture ring. Another run
// of the build no longer refuses it (ADR 0026 (5)): each run reads its own ring, the probes shared by the build's
// runs emit each call once, into the ring of the run the calling process belongs to (ADR 0026 (7)), and the slot
// table hands out no slot a run-set row still carries, so no dead launcher's processes write into this run's ring
// (ADR 0026 (6)).
func (u *Uprobe) scope(cgroupID uint64) error {
	if cgroupID == 0 {
		return errors.New("uprobe: the run names no cgroup, so no run-set row names its slot")
	}
	slot, gen, ok, err := u.runSet.Slot(cgroupID)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("uprobe: cgroup %d has no row in the build's run set", cgroupID)
	}
	u.mu.Lock()
	u.scoped, u.slot, u.gen = true, slot, gen
	u.mu.Unlock()
	return nil
}

// Gaps reports what this source could not cover, one entry per reason and binary (R37, §2's Coverage). A
// gap names the binary whenever there is one to name, which is what makes "every missing pair explained"
// actionable rather than a bare count.
func (u *Uprobe) Gaps() []source.Gap {
	u.collectAssemblerGaps()
	settled := u.cov.Gaps()
	u.mu.Lock()
	defer u.mu.Unlock()
	merged := make(map[gapKey]*source.Gap, len(u.gaps)+len(settled)+len(u.uncaptured))
	add := func(why, binary string, count int64) {
		k := gapKey{Why: why, Binary: binary}
		cur, ok := merged[k]
		if !ok {
			cur = &source.Gap{What: record.GapCapture, Why: why, Binary: binary}
			merged[k] = cur
		}
		cur.Count += count
	}
	for _, g := range u.gaps {
		add(g.Why, g.Binary, g.Count)
	}
	for _, g := range settled {
		add(g.Why, g.Binary, g.Count)
	}
	// A held verdict is reported as the gap it will become, so a Gaps call while processes still run
	// reads the same as one after they exit; it only disappears if its process is captured after all.
	for _, p := range u.uncaptured {
		if why, gap := derive.Classify(p.proc); gap {
			add(why, p.proc.Binary, 1)
		}
	}
	out := make([]source.Gap, 0, len(merged))
	for _, g := range merged {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Why != out[j].Why {
			return out[i].Why < out[j].Why
		}
		return out[i].Binary < out[j].Binary
	})
	return out
}

// Adopt tells an unscoped source (no RunSet) that a cgroup belongs to this run, so chunks stamped with it are
// reassembled. A scoped source filters on the run's slot instead, which the kernel stamps on every chunk of
// every cgroup of the run and which no other run's chunk carries (mine). Nothing the kernel record feeds the
// source adopts a cgroup: a hook sample names whatever cgroup the process was in, and an adoption from one
// that was not this run's would put another run's plaintext into this run's ledger.
func (u *Uprobe) Adopt(cgroupID uint64) {
	if cgroupID == 0 {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.cgroups[cgroupID] = struct{}{}
}

// OnExec attaches this process's TLS library, driven by observe's exec stream (source.ProcessHook). It is
// the whole of R4-R8's userspace half and never fails a run: a process it cannot capture is one gap naming
// the binary and why.
//
// That gap is held, not recorded, until the process execs again, exits or the source stops (see
// Uprobe.uncaptured): at the exec the dynamic loader has not run yet, so a libssl the process links, or
// loads later with dlopen, is not in its maps, and OnOpen may still attach it.
//
// The hook runs after the fact, on the recorder's drain, and a short-lived process can be gone by then, its
// /proc entry with it. Its maps then say nothing, so R4 reads nothing, and the verdict is no-openssl; the
// binary it names is path, the file the process exec'd as the kernel's exec record carries it, because
// /proc/<pid>/exe went with the process. While the process lives, /proc/<pid>/exe names the image: it is
// the file itself, where path can be relative, a script its interpreter runs, or /proc/self/exe.
//
// The work is bounded by AttachBudget: past it the attach is abandoned for this exec and retried on the
// tree's next one, because a launcher blocked parsing a huge binary is a launcher not recording anything
// (§4, edge case #1).
func (u *Uprobe) OnExec(pid int, cgroupID uint64, path string) {
	// After Stop there is no run left to capture for; own still covers an exec that passes this check
	// and reaches the cache only after the sweep. Before Start there is no attacher yet (openKernel makes
	// it), and an attach tried then would record a failure the host-wide cache keeps for the binary (§7).
	if !u.live() {
		return
	}
	image, err := u.opts.Proc.Exe(pid)
	if err != nil || image == "" {
		image = execName(path)
	}
	u.newImage(pid, image)
	deadline := u.opts.Now().Add(u.opts.AttachBudget)
	cands, err := u.disc.candidates(pid)
	if err != nil {
		u.hold(pid, pendingGap{proc: derive.Process{PID: pid, Binary: image}, image: image,
			detail: fmt.Sprintf("pid %d: %v", pid, err)})
		return
	}
	// The first error that is not "this file has no OpenSSL in it" is the informative one: a later
	// candidate reporting no symbols must not mask an attach the verifier or the host refused.
	var hardErr error
	for _, c := range cands {
		if u.opts.Now().After(deadline) {
			u.gap(GapSizeCap, c.Name, 1,
				fmt.Sprintf("pid %d: attach budget of %s spent before %s was read", pid, u.opts.AttachBudget, c.Name))
			return
		}
		ok, err := u.attachCandidate(pid, c)
		if ok || errors.Is(err, errStopped) {
			return
		}
		if err != nil && hardErr == nil && !softErr(err) {
			hardErr = err
		}
	}
	// Candidates existed and none of them exported anything hookable: the first of them, which is what R4
	// reports the process against, was read and has no R1-R3 symbol. derive.Classify calls that
	// static-tls-no-symbols: the Bun/BoringSSL and rustls case and, indistinguishably without E71, a process
	// with no TLS at all (R37).
	held := pendingGap{proc: derive.Process{PID: pid, Binary: cands[0].Name, Library: cands[0].Name}, image: image,
		detail: fmt.Sprintf("pid %d: no OpenSSL symbols in %d candidates", pid, len(cands))}
	if hardErr != nil {
		// A read or attach that failed for any other reason is not distinguishable from "no OpenSSL here"
		// in the closed why set (§7, edge case #31): it is discovery that read nothing usable, and the
		// detail carries the truth.
		held.proc = derive.Process{PID: pid, Binary: image}
		held.detail = fmt.Sprintf("pid %d: %v", pid, hardErr)
	}
	u.hold(pid, held)
}

// execName is an exec record's path as the name of the file the process ran, or "" when it names none: a
// path relative to a working directory nobody recorded, or a /proc or /dev/fd alias that resolved to a file
// only inside the process that exec'd it.
func execName(path string) string {
	if !filepath.IsAbs(path) || strings.HasPrefix(path, "/proc/") || strings.HasPrefix(path, "/dev/fd/") {
		return ""
	}
	return path
}

// OnOpen is fed every open the kernel record sees a process of the run make (source.ProcessHook), and
// attaches a libssl at the moment it is opened. It is R4's discovery for the library an exec cannot see: a
// dynamically linked client's libssl is mapped by the loader after the exec returns, and CPython's is
// dlopen'd by `import ssl`. A uprobe belongs to the file, not to a mapping, so a probe placed on the file
// before the process maps it fires once it does. For the host's own libssl, which Start pre-attached, the
// open only takes this process's reference; a library it did not (a private copy, a container's) is
// attached here, after the open, which is late for a call the process makes before the attach is done.
//
// Only a path named like a libssl (R4's libssl\.so(\.\d+)*) is considered; everything else returns at once,
// because the recorder calls this for every open, through the hook queue's own goroutine. The path is the one the process
// opened, resolved through its own /proc/<pid>/root (R39).
func (u *Uprobe) OnOpen(pid int, cgroupID uint64, path string) {
	base := filepath.Base(path)
	if !strings.HasPrefix(base, "libssl.so") || !libsslName.MatchString(base) || !filepath.IsAbs(path) {
		return
	}
	if !u.live() {
		return
	}
	ok, err := u.attachCandidate(pid, candidate{Path: u.disc.rootPath(pid, path), Name: path, Open: true})
	switch {
	case errors.Is(err, errOpenCap):
		u.gap(GapSizeCap, path, 1, fmt.Sprintf("pid %d: %s not attached: %d libraries opened by name are attached already",
			pid, path, MaxOpenAttach))
	case ok:
		u.mu.Lock()
		delete(u.uncaptured, pid)
		u.mu.Unlock()
	case errors.Is(err, errStopped):
	case err != nil:
		// static-tls-no-symbols says the library was read and exports none of R1-R3 (R37). A library that
		// could not be read at all says nothing about its symbols: the recorder hands an open on after the
		// fact, and a process that has exited by then takes its /proc/<pid>/root, and so every path of
		// the file, with it. Reading that as "no symbols" would tell the reader that the host's own
		// OpenSSL exports none. It is no-openssl, R4 having nothing it could read, and the process's own
		// image stays the binary the gap names.
		p, detail := derive.Process{PID: pid, Binary: path}, fmt.Sprintf("pid %d: %v", pid, err)
		gone := u.exited(pid)
		switch {
		case gone:
			detail = fmt.Sprintf("pid %d exited before %s could be read: %v", pid, path, err)
		case errors.Is(err, ErrNoSymbols) || errors.Is(err, ErrNotELF):
			// Read, and none of R1-R3 in it: static-tls-no-symbols by derive.Classify.
			p.Library = path
		}
		u.mu.Lock()
		prev, held := u.uncaptured[pid]
		if held {
			if gone && prev.proc.Binary != "" {
				p.Binary = prev.proc.Binary
			}
			// Still uncaptured, and this library is the better explanation than the exec's.
			u.uncaptured[pid] = pendingGap{proc: p, image: prev.image, detail: detail}
		}
		u.mu.Unlock()
		if !held {
			// The process is captured through another library already; this one is its own gap.
			u.settleProcess(p, detail)
		}
	}
}

// live reports whether a hook call can be acted on: Start has opened the kernel side and decided to capture
// (ready, and not inert), and Stop has not swept. The run starts the kernel record before this source (runtime.recorderFirst), so the
// recorder's drain can call a hook before Start; what it can see then is the launcher's own child stage,
// because the agent is released only after every source has started (runtime-launch.md §4.1 step 8), and the
// stage's exec is already held back from this source (runtime.stageFilter).
//
// A run under record: off is never live (capturesNothing) unless it is activity-only (stampsActivity). The
// recorder still hands its execs on, since the kernel emits exec and exit whatever the mode, and a libssl mapped at
// exec or an OpenSSL linked into the executable would otherwise be probed there: every process on the host that
// calls into that file would pay the traps for the whole run, and the capture programs keep nothing of the run's
// calls (R4). An activity-only run pays that on purpose: its stall check reads the stamp the probes write.
func (u *Uprobe) live() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.ready && !u.stopped && (u.activityOnly || !u.inert && !u.capturesNothing())
}

// capturesNothing reports a run under record: off, for which the capture programs record nothing
// (tego_recording): no ring, no chunk, no coverage. No probe is placed for it either, not by pre-attach, not at an
// exec, not at an open (R4), unless it is activity-only (stampsActivity).
func (u *Uprobe) capturesNothing() bool {
	return u.opts.Rules != nil && u.opts.Rules.Record == agent.RecordOff
}

// stampsActivity reports a record: off run whose probes are placed for its stall check alone (A-REC-3, D3): its
// stall_after is bounded, so the backend's row says TEGO_RUN_ACTIVITY and the shared probes stamp its TLS calls
// into its slot of tego_activity, and the source follows the tier's kernel record (Kernel), whose exec stream
// drives OnExec. Without a stall budget nothing reads the stamp, and record: off keeps its zero probes.
func (u *Uprobe) stampsActivity() bool {
	return u.opts.Kernel && u.opts.Rules != nil && u.opts.Rules.Limits.Bounded(agent.BudgetStallAfter)
}

// reporting reports whether this source reports coverage and gaps: every source but an activity-only one, which
// keeps no capture to measure a process against, so what it could not attach is logged and never a gap.
func (u *Uprobe) reporting() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return !u.activityOnly
}

// exited reports whether a process's /proc entry is gone, which is how an attach that failed on a path
// under it is told from one that failed on the library itself.
func (u *Uprobe) exited(pid int) bool {
	_, err := os.Stat(u.disc.procPath(pid, ""))
	return errors.Is(err, os.ErrNotExist)
}

// newImage settles what a process's previous image left uncaptured, now that an exec has replaced it. A
// second exec record of the same image — the recorder can see one execve more than once — supersedes
// the held verdict instead, so one process is never counted twice.
func (u *Uprobe) newImage(pid int, image string) {
	u.mu.Lock()
	prev, ok := u.uncaptured[pid]
	delete(u.uncaptured, pid)
	u.mu.Unlock()
	if ok && prev.image != image {
		u.settleProcess(prev.proc, prev.detail)
	}
}

// hold records a process's standing verdict (see Uprobe.uncaptured). An activity-only source keeps no capture to
// measure the process against, so it only logs the verdict.
func (u *Uprobe) hold(pid int, g pendingGap) {
	if !u.reporting() {
		u.log("uprobe: activity-only, no gap: %s", g.detail)
		return
	}
	u.mu.Lock()
	u.uncaptured[pid] = g
	u.mu.Unlock()
}

// settle turns a process's held verdict into the gap it stands for.
func (u *Uprobe) settle(pid int) {
	u.mu.Lock()
	prev, ok := u.uncaptured[pid]
	delete(u.uncaptured, pid)
	u.mu.Unlock()
	if ok {
		u.settleProcess(prev.proc, prev.detail)
	}
}

// settleProcess counts one process verdict in the run's coverage, which classifies it (derive.Classify).
func (u *Uprobe) settleProcess(p derive.Process, detail string) {
	if !u.reporting() {
		return
	}
	why, gap := u.cov.Settle(p)
	if gap && detail != "" {
		u.log("uprobe: gap %s %s: %s", why, p.Binary, detail)
	}
}

// flushUncaptured settles every held verdict: the run is over, so a process nothing captured by now is
// never captured.
func (u *Uprobe) flushUncaptured() {
	u.mu.Lock()
	pids := make([]int, 0, len(u.uncaptured))
	for pid := range u.uncaptured {
		pids = append(pids, pid)
	}
	u.mu.Unlock()
	for _, pid := range pids {
		u.settle(pid)
	}
}

// softErr reports whether an error means "there is nothing to attach to here" rather than "attaching
// failed". A file that is not an ELF, exports no OpenSSL symbols, or has gone away between the maps read
// and the open is the ordinary case for most of a process's mappings; only the rest is worth reporting as
// the cause of a gap.
func softErr(err error) bool {
	// A failed attach is never "nothing to attach to here": the candidate exported R1-R3's symbols
	// and this package computed their offsets before it ever asked. R37 reserves
	// static-tls-no-symbols for a candidate that exports none of them, and §7's failure-modes table
	// files every attach() error under no-openssl instead. The test has to be ErrAttachFailed rather
	// than the errno, because an attach can fail with ENOENT when the file that is missing is not the
	// candidate at all — tracefs's uprobe_events on a kernel without CONFIG_UPROBE_EVENTS, see vanished
	// — and the line below would otherwise swallow that into the Bun/rustls verdict.
	if errors.Is(err, ErrAttachFailed) {
		return false
	}
	return errors.Is(err, ErrNoSymbols) || errors.Is(err, ErrNotELF) || errors.Is(err, os.ErrNotExist)
}

// vanished reports whether an attach failed because the path it named stopped existing between discovery
// and the attach, rather than because this binary or this host refused the probe. §7 spends its one
// attempt per binary on the second kind only, so confusing the two costs either a permanent gap on a
// hookable libssl or the retry storm the rule exists to prevent.
//
// The errno alone cannot separate them, because both arrive as ENOENT. On the uprobe PMU, which every kernel
// on the 5.14 floor built with CONFIG_UPROBE_EVENTS has, perf_event_open's ENOENT is the kernel's own lookup
// of the path (kern_path in create_local_trace_uprobe), and a write to tracefs's uprobe_events looks the
// path up the same way: that is the vanished case. The host produces the same errno for causes no later
// process escapes. A kernel built without CONFIG_UPROBE_EVENTS has neither the PMU nor uprobe_events, so
// cilium/ebpf's fallback open of that tracefs file fails with ENOENT for every probe; and cilium/ebpf reads
// the PMU's format/retprobe for every uretprobe and hands back that read's ENOENT unchanged, so a sysfs that
// shows the PMU without that file refuses every read pair. Those are exactly what the failure record is for.
// So the errno only opens the question and the filesystem answers it: what vanishes is the path, every
// candidate path is spelled through one process's own /proc entry (R39), and while that process lives a
// refusal the host owns leaves the path in place. A host refusal that coincides with the process exiting is
// taken for a vanished path and costs the next process one more attempt, which is one attempt and not a
// storm.
func vanished(path string, err error) bool {
	// procfs answers ESRCH rather than ENOENT for some reads once the task is gone.
	if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ESRCH) {
		return false
	}
	_, statErr := os.Stat(path)
	return statErr != nil
}

// attachCandidate reads one candidate ELF and attaches to it, or explains why it could not. The bool says
// whether this process is now captured.
func (u *Uprobe) attachCandidate(pid int, c candidate) (bool, error) {
	// Every cache below is keyed on identity, build id included (R7), so the build id has to be read
	// before any of them is consulted: a (device, inode) pair alone cannot tell a live entry from one
	// left by a file that has since gone, and this cache outlives runs. A candidate whose ELF header
	// will not read stops here and is not recorded as a failure — §7's one attempt per binary exists to
	// stop attach retry storms and to skip a repeated symbol-table parse, and a file that is not an ELF
	// reaches neither; an entry no lookup can reach would only grow the map.
	//
	// The path is resolved once, here: the identity, the parse and every probe go through the descriptor's
	// link, so a path the process swaps in between cannot aim the probes at a file that was not parsed.
	pin, err := pinCandidate(c.Path)
	if err != nil {
		return false, err
	}
	defer func() { _ = pin.Close() }()
	id, err := candidateIdentity(pin.path)
	if err != nil {
		return false, pin.rename(err, c.Path)
	}
	for {
		if a, refs, ok := u.cache.ref(id, u.key(pid)); ok {
			if !u.own(pid) {
				return false, errStopped
			}
			// refs is read under the cache's lock by ref itself: RefCount here would be len(a.refs)
			// read outside it while a concurrent OnExec's addRefLocked writes the map.
			u.log("uprobe: %s already attached (refcount %d)", a.Name, refs)
			u.oneSided(a, c.Name)
			return true, nil
		}
		if err, ok := u.cache.failure(id); ok {
			return false, err // one attempt per binary, never a retry storm (§7)
		}
		// I8: two processes exec'd together that map one libssl must not both attach it. Whoever
		// claims the binary attaches it; everyone else waits for that attempt and then reads its
		// outcome from the cache like any later process, which is a reference or a recorded failure —
		// or neither, when the attempt found its path gone, and then the next claim tries again with
		// its own process's path.
		wait := u.cache.claim(id)
		if wait == nil {
			break
		}
		<-wait
	}
	defer u.cache.unclaim(id)
	bin := u.cache.lookupOffsets(id)
	if bin == nil {
		// Pre-attach only ever offers native libraries (systemLibraries); an exec's candidates and a library
		// opened by name can be anything the process maps, a 32-bit libssl under a multilib prefix among them.
		if err := pin.rename(checkNativeELF(pin.path), c.Path); err != nil {
			if errors.Is(err, ErrNotELF) {
				u.cache.fail(id, err)
			}
			return false, err
		}
		bin, err = readBinary(pin.path)
		if err != nil {
			err = pin.rename(err, c.Path)
			if errors.Is(err, ErrNoSymbols) || errors.Is(err, ErrNotELF) {
				u.cache.fail(id, err)
			}
			return false, err
		}
		u.cache.putOffsets(id, bin)
	}
	if c.Open {
		u.mu.Lock()
		if u.openAttached >= MaxOpenAttach {
			u.mu.Unlock()
			return false, errOpenCap
		}
		u.openAttached++
		u.mu.Unlock()
	}
	a, err := u.attach(id, c, pin.path, bin, pid)
	if err != nil {
		if c.Open {
			u.mu.Lock()
			u.openAttached--
			u.mu.Unlock()
		}
		err = pin.rename(err, c.Path)
		// §7's "one attempt per (dev,ino), no retry storm" is about what the binary and the host
		// refuse — a verifier rejection, a permission denial — which no later process will refuse
		// any differently. A path that went away under us is a property of the process that mapped
		// it, so caching it would answer every later process with a gap naming a libssl that is
		// perfectly hookable through its own /proc entry.
		if !vanished(c.Path, err) {
			u.cache.fail(id, err)
		}
		return false, err
	}
	if !u.own(pid) {
		return false, errStopped
	}
	u.log("uprobe: attached %s (build id %q, writes %v, reads %v)", a.Name, a.BuildID, a.WriteSyms, a.ReadSyms)
	u.oneSided(a, c.Name)
	return true, nil
}

// oneSided reports a binary attached with only one direction of R1-R3: requests without their responses, or
// the reverse, is a shortfall of I4 and never silent. It is a no-openssl gap naming the binary and the missing
// half. A missing read half also reports unmetered, since a response whose usage capture can never read
// reaches no budget.
func (u *Uprobe) oneSided(a *attachedBinary, name string) {
	var missing string
	switch {
	case len(a.WriteSyms) == 0:
		missing = "write"
	case len(a.ReadSyms) == 0:
		missing = "read"
	default:
		return
	}
	u.gap(GapNoOpenSSL, name, 1, fmt.Sprintf("%s exports no %s symbol in .dynsym or .symtab: captured in one direction only", name, missing))
	if missing == "read" {
		u.reportUnmetered(1, name+": no read hook, responses are never captured")
	}
}

// key is this source's reference on a process in the attach cache.
func (u *Uprobe) key(pid int) refKey { return refKey{owner: u.owner, pid: pid} }

// own records that this source holds the attach cache's reference for a process, so Stop can give back
// exactly the references it took and no others. It reports false when Stop's sweep has already run.
//
// The reference is taken in the cache first and recorded here second, and Stop's sweep reads pids
// independently of the cache, so an exec still being handled at teardown can add its reference after the
// only sweep that will ever run. Recorded then, it would hold its binary's links open past the run with
// nothing left to release them, which is the leak I9 bounds. The sweep sets stopped in the same critical
// section in which it takes its snapshot of pids, so every own either lands in that snapshot or sees
// stopped here and gives the reference back itself.
func (u *Uprobe) own(pid int) bool {
	u.mu.Lock()
	if !u.stopped {
		u.pids[pid] = struct{}{}
		u.mu.Unlock()
		return true
	}
	u.mu.Unlock()
	for _, l := range u.cache.release(u.key(pid)) {
		_ = l.Close()
	}
	u.log("uprobe: pid %d attached after Stop; reference given back", pid)
	return false
}

// releaseOwned drops this source's reference to every process it still holds one for and returns the links
// of every binary that thereby reached refcount zero, for the caller to close outside the lock.
//
// It is the sweep Stop runs, and it sweeps this source's processes rather than the cache: the cache is
// host-wide and outlives a single run (ARCHITECTURE §9 "resource lifetimes"), so an entry may carry
// another concurrent run's references too, and R8 keeps its links alive while that run's contribution to
// RefCount stands (edge case #26). Closing the lot would leave that run executing with its probes gone and
// no gap to say so, which is the silent absence I4 forbids. Sweeping this source's own pids still meets
// I9 from the other side: a process whose exit event never arrived gave its reference back here.
//
// It also closes this source to new references (see own), so it is the last sweep and runs once.
func (u *Uprobe) releaseOwned() []io.Closer {
	u.mu.Lock()
	u.stopped = true
	pids := make([]int, 0, len(u.pids))
	for pid := range u.pids {
		pids = append(pids, pid)
	}
	u.pids = map[int]struct{}{}
	u.mu.Unlock()
	var out []io.Closer
	for _, pid := range pids {
		out = append(out, u.cache.release(u.key(pid))...)
	}
	return out
}

// attach places every probe R1-R3 asks for on one binary and records it in the cache. A partial attach is
// rolled back whole: half a binary's probes would double-count nothing but would report a connection's
// requests without its responses, which is worse than a clean gap.
//
// The kernel resolves the path at attach time, once per probe, so the probes are placed through at, the
// link of the descriptor attachCandidate holds on this process's own spelling of the file (R39, c.Path),
// never through c.Path again and never through the cached binary's: the link names the inode that was
// identified and parsed whatever c.Path names by now. bin is keyed by (dev,ino) and may have been parsed
// for a process that has since exited, taking its /proc entry and every path under it with it; what the
// cache contributes across processes is the offsets and the build id, which are properties of the file
// itself (R7).
func (u *Uprobe) attach(id identity, c candidate, at string, bin *binary, pid int) (*attachedBinary, error) {
	att := u.opts.Attacher
	if att == nil {
		return nil, fmt.Errorf("%w: %s: no attacher", ErrAttachFailed, c.Name)
	}
	a := &attachedBinary{
		ID: id, Path: c.Path, Name: c.Name, BuildID: bin.BuildID,
		WriteSyms: bin.WriteSymbols(), ReadSyms: bin.ReadSymbols(),
	}
	if ba, ok := att.(binaryAttacher); ok {
		links, err := ba.AttachBinary(at, id, probesFor(bin))
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %w", ErrAttachFailed, c.Name, err)
		}
		a.links = links
		kept, discard := u.cache.put(a, u.key(pid))
		for _, l := range discard {
			_ = l.Close()
		}
		return kept, nil
	}
	for _, p := range probesFor(bin) {
		link, err := att.Attach(at, p)
		if err != nil {
			for _, l := range a.links {
				_ = l.Close()
			}
			return nil, fmt.Errorf("%w: %s: %s: %w", ErrAttachFailed, c.Name, p, err)
		}
		a.links = append(a.links, link)
	}
	kept, discard := u.cache.put(a, u.key(pid))
	for _, l := range discard {
		_ = l.Close() // another goroutine attached the same binary first (I8)
	}
	return kept, nil
}

// probesFor turns a binary's symbol choice into the probes to place, in the order attach places them: an
// entry and a return probe per read symbol, then one uprobe per write symbol (R1-R3).
//
// Every read probe comes before any write probe. attach places them one at a time, and a process already
// running the library (one attached at its open or exec, R4) makes calls between two of them; a uretprobe
// fires only for a call entered after it was placed. With the writes first, a blocking client's request
// written in that window was captured while the SSL_read it then entered for the response was not, so the
// response never came, and httpstream paired every later response on the connection with the request before
// its own (I3), with nothing but one gap at Close to say so. With the reads first, a request is captured only
// once every read probe is in place, so the read that follows it is captured too, and what a late attach
// splits is a response whose request it missed, or a request whose head it missed, which httpstream passes
// over and counts for that exchange (R18). Not every such request: a tail that looks like the start of a
// request line fails the connection closed under one count, however many exchanges were left on it. A whole
// line of a token and a space, or one that runs past httpstream's 8 KiB start-line cap, fails as it is
// parsed; a known method whose line has not ended fails when its response comes before the next request (R4
// names the shapes).
// A read entered before the read probes and still waiting when a request is written after the write probes
// is missed too, but only a thread other than the writer's can be waiting so, and capture keys a connection
// by thread: that thread's responses are another connection's, each passed over as one with no request, and
// never paired with the writer's requests (R4, edge case #11).
//
// SSL_free goes on first of all (R3a): a connection whose I/O is captured then has its end captured
// too, so a new SSL* at the same address is never read as the old connection going on. Placed first, it
// also sees the end of connections whose I/O the late attach missed, which is a close of nothing.
func probesFor(bin *binary) []Probe {
	var out []Probe
	if bin.Has(SymFree) {
		out = append(out, Probe{Program: bpf.ProgSSLFree, Symbol: SymFree, Offset: bin.Offsets[SymFree]})
	}
	for _, sym := range bin.ReadSymbols() {
		prog := bpf.ProgSSLReadEx
		if sym == SymRead {
			prog = bpf.ProgSSLRead
		}
		out = append(out, Probe{Program: prog, Symbol: sym, Offset: bin.Offsets[sym]})
		out = append(out, Probe{Program: bpf.ProgSSLReadReturn, Symbol: sym, Offset: bin.Offsets[sym], Return: true})
	}
	for _, sym := range bin.WriteSymbols() {
		prog := bpf.ProgSSLWriteEx
		if sym == SymWrite {
			prog = bpf.ProgSSLWrite
		}
		out = append(out, Probe{Program: prog, Symbol: sym, Offset: bin.Offsets[sym]})
	}
	return out
}

// OnExit drops this source's reference on a process and closes the links of every binary no reference
// is left on (R8). A binary another run's process still holds stays attached (edge case #26), and so does
// one another run holds under the same pid: the pid may be a reused one this source never attached, and
// only this source's own reference is its to give back.
//
// It also settles the process's held verdict: an exit is the last moment it could have been captured.
func (u *Uprobe) OnExit(pid int) {
	u.mu.Lock()
	delete(u.pids, pid)
	u.mu.Unlock()
	u.settle(pid)
	for _, l := range u.cache.release(u.key(pid)) {
		_ = l.Close()
	}
}

// haltDrain tells the drain goroutine to return, and wakes it if it is waiting on an empty ring. A reader that
// cannot be woken without closing it (a test's) is closed, which ends the goroutine the same way and leaves
// finalDrain only what that reader still hands out once closed.
func (u *Uprobe) haltDrain() {
	u.halt.Store(true)
	if f, ok := u.reader.(flushReader); ok && f.Flush() == nil {
		return
	}
	u.closeReader()
}

// finalDrain is edge case #28's one final ring-buffer drain, run by Stop once the drain goroutine has returned:
// the last response of a run, and its last requests, are on the ring when the run ends. The run calls Stop
// once its processes are gone (on a cancelled run, once the killed tree has emptied or had killTimeout to:
// runtime awaitEmpty), so every chunk of this run lies within the bytes the ring holds at this moment, and the
// drain reads that many and no further: the ring is every run's of the build, and another run's probes can
// keep it from ever being empty. Reads do not wait (the deadline is now). Chunks are reassembled for StopDrain
// and past it only counted, this run's into ring-buffer-drop, so the drain is bounded by the ring's size. The
// events reassembly emits go to the run's queue, which the run keeps writing while its sources stop, and a
// drain that outruns the ledger by more than the queue's depth is counted there as channel-full. A reader that
// cannot say how much it holds (a test's) is read until it reports empty or closed.
func (u *Uprobe) finalDrain() {
	if u.reader == nil {
		return
	}
	left := -1
	if f, ok := u.reader.(flushReader); ok {
		left = f.AvailableBytes()
	}
	u.reader.SetDeadline(time.Now())
	handleBy := time.Now().Add(u.opts.StopDrain)
	var sample ringbuf.Record // reused by every read; see drain for what that asks of handle
	for left != 0 {
		if err := u.reader.ReadInto(&sample); err != nil {
			return // empty, closed or unreadable: nothing more can be read from it
		}
		if left > 0 {
			left = max(left-ringRecordBytes(len(sample.RawSample)), 0)
		}
		if time.Now().After(handleBy) {
			if chunk, err := bpf.DecodeSSLChunk(sample.RawSample); err == nil && u.mine(chunk.Hdr) {
				u.gap(GapRingBufferDrop, "", 1, "")
			}
			continue
		}
		u.handle(sample.RawSample)
	}
}

// closeReader closes the ring buffer exactly once and releases the ring's kernel objects; the lost counter
// stays open for Stop's last read.
func (u *Uprobe) closeReader() {
	u.closer.Do(func() {
		if u.reader != nil {
			_ = u.reader.Close()
		}
		for _, c := range u.owned {
			_ = c.Close()
		}
	})
}

// drain is the single owner of the pending-request table and the event path. It keeps reading while the ring
// holds samples and polls the kernel's lost counter between batches.
//
// Every chunk is read into the one sample Record, whose bytes the next read overwrites, and the plaintext
// bpf.DecodeSSLChunk returns aliases them. handle's only use of it is httpstream's Feed, which appends it to
// the connection's own buffer before returning, so nothing keeps a chunk's bytes past its read.
func (u *Uprobe) drain() error {
	var sample ringbuf.Record
	next := u.opts.Now().Add(u.opts.PollInterval)
	u.reader.SetDeadline(next)
	for {
		err := u.reader.ReadInto(&sample)
		switch {
		case err == nil:
		case errors.Is(err, os.ErrDeadlineExceeded), errors.Is(err, ringbuf.ErrFlushed):
			if u.halt.Load() {
				return nil // Stop or cancellation: finalDrain reads the rest
			}
			u.pollLost()
			next = u.opts.Now().Add(u.opts.PollInterval)
			u.reader.SetDeadline(next)
			continue
		case errors.Is(err, ringbuf.ErrClosed), errors.Is(err, os.ErrClosed):
			return nil // a reader haltDrain had to close: a clean end
		default:
			if u.halt.Load() {
				return nil
			}
			return fmt.Errorf("uprobe: ring buffer: %w", err)
		}
		u.handle(sample.RawSample)
		// Checked after every chunk: another run's probes can keep the ring from ever being empty, and the
		// goroutine must still return promptly (source.Source).
		if u.halt.Load() {
			return nil
		}
	}
}

// handle turns one ring-buffer record into reassembled messages and the events they imply.
func (u *Uprobe) handle(raw []byte) {
	if bpf.PeekKind(raw) == bpf.KindSSLClose {
		u.handleClose(raw)
		return
	}
	chunk, err := bpf.DecodeSSLChunk(raw)
	if err != nil {
		u.gap(GapSizeCap, "", 1, fmt.Sprintf("undecodable chunk record: %v", err))
		return
	}
	if !u.mine(chunk.Hdr) {
		return // another run's process on the same host-wide ring (R9's userspace half)
	}
	key := httpstream.ConnKey{
		Src:      record.SourceSSL,
		CgroupID: chunk.Hdr.CgroupID,
		PidTgid:  uint64(chunk.Hdr.PID)<<32 | uint64(chunk.Hdr.TID),
		SSLPtr:   chunk.SSLPtr,
	}
	dir := httpstream.DirRequest
	if chunk.Direction == bpf.SSLRead {
		dir = httpstream.DirResponse
	}
	if !u.followPtr(key, chunk.Hdr.PID, chunk.Hdr.TID, chunk.SSLPtr, chunk.Seq, dir == httpstream.DirRequest) {
		return
	}
	// Every hole but an unreadable chunk's, whose Skipped says how far to step, is a read the kernel did not
	// read; a hole value this reader does not know is one too, which fails closed.
	if chunk.Hole != bpf.SSLHoleNone && chunk.Hole != bpf.SSLHoleUnreadable {
		u.unreadRead(key, chunk)
		return
	}
	// The kernel numbers every chunk of a connection before its reserve (bpf/uprobe_ssl.bpf.c), so a chunk
	// the ring never took is a hole httpstream finds at the next one. This source numbered chunks itself on
	// arrival, which could not show a hole: a response lost to a full ring paired every later response on the
	// connection with the request before its own (I2).
	//
	// A 1 is a count that starts afresh: SSL_free on this thread removed the pointer's row, so this is a new
	// connection even if its close record never arrived, or the LRU evicted the row of a live one. Either way
	// what the key held is over: it is closed as a close record would close it, and the chunk starts a new
	// connection, where a connection going on mid-message is passed over and counted, never paired (R3a).
	// The count wraps to 1 only after 2^32 chunks of one connection.
	if chunk.Seq == 1 {
		u.emitMessages(u.asm.Close(key))
		u.closePending(key, "a request's response was never seen before its connection ended")
	}
	msgs, err := u.asm.Feed(key, dir, httpstream.Chunk{
		Data:      chunk.Data,
		Seq:       chunk.Seq,
		Truncated: chunk.Truncated,
		Skipped:   chunk.Skipped,
		TS:        u.opts.Now(),
		MonoNS:    chunk.Hdr.TSMonoNS,
	})
	u.emitMessages(msgs)
	if err != nil {
		if errors.Is(err, httpstream.ErrRefusedAgain) {
			// The full table turned this key away before: its loss was reported then, and a chunk is not
			// an exchange, so this one adds neither a count nor a line.
			return
		}
		u.log("uprobe: connection %s gapped: %v", key, err)
		if errors.Is(err, httpstream.ErrClosed) {
			// A closed assembler is Stop's, which accounts for what is still pending.
			u.dropPending(key)
			return
		}
		if errors.Is(err, httpstream.ErrHTTP2) {
			// h2 is R17's stated gap, never read at all. OpenSSL clients (curl among them) negotiate it with
			// model hosts, so an h2 connection whose peer is a model host, or one capture never learned — a
			// preface on a fresh connection names none — is model spend no budget can count: reported
			// unmetered as a lost connection is (ADR 0035). A connection capture learned is to
			// another host, an h2c upgrade's, stays exempt.
			u.loseConn(key, "an HTTP/2 connection, which capture does not read")
			return
		}
		// A sequence hole or a framing error: the connection's waiting requests lost their responses,
		// and a run with a token or cost budget can no longer count what they spent (limits-check-doctor-cli.md R1 (f)).
		u.loseConn(key, "a connection's exchanges were lost to a capture hole or a framing error")
	}
}

// unreadRead is a read the kernel numbered and emitted as a hole without reading it: one whose entry probe was
// further from its return than bpf.SSLMaxCallNS allows (SSLHoleStale, edge case #3), whose buffer it did not
// trust, one whose scratch row the LRU evicted before its return (SSLHoleEvicted, R5), whose buffer it no
// longer knew, or an SSL_read_ex whose *readbytes it could not read (SSLHoleNoLength, edge case #13). Either way the call moved bytes on the connection. Before, the kernel dropped such a read with
// no number and no record, and on a keep-alive connection the next response paired with this one's request.
//
// It is the gap #3 and R5 promise, why=size-cap, and that gap is the exchange's whole account: what the key
// held is given up (Abandon, so closing it adds no malformed count for the request left waiting), every request
// still waiting has lost its response, and the key is closed, so the connection's next chunk starts a new one,
// where a message joined midway is passed over and counted, never paired (R3a). The hole's length is not
// stepped over the way an unreadable chunk's is: a stale row may be another process's, and so may the
// SSL_read_ex length it pointed to, and an evicted row's or an unreadable *readbytes' length is unknown.
func (u *Uprobe) unreadRead(key httpstream.ConnKey, chunk bpf.SSLChunk) {
	why := fmt.Sprintf("returned more than %s after the entry probe its scratch row came from",
		time.Duration(bpf.SSLMaxCallNS))
	switch chunk.Hole {
	case bpf.SSLHoleStale:
	case bpf.SSLHoleEvicted:
		why = "lost its scratch row to the map's LRU before it returned"
	case bpf.SSLHoleNoLength:
		why = "returned 1 from SSL_read_ex with a *readbytes the return probe could not read"
	default:
		why = fmt.Sprintf("carried hole kind %d, which this reader does not know", chunk.Hole)
	}
	u.gap(GapSizeCap, "", 1, fmt.Sprintf("a read (%d bytes known) on SSL* %#x of pid %d %s; its bytes are not "+
		"recorded and its connection starts afresh", chunk.Skipped, chunk.SSLPtr, chunk.Hdr.PID, why))
	u.asm.Abandon(key)
	u.emitMessages(u.asm.Close(key))
	u.closePending(key, "a request's response was lost to a read the probes could not read (edge case #3, R5)")
}

// followPtr keeps each SSL*'s I/O on one thread, and reports whether a chunk of it is to be reassembled
// (edge case #11). Chunks are keyed by thread (the kernel's sequence is per thread and pointer, R5), so an SSL*
// whose I/O moves to another thread becomes a second key. Between exchanges that loses nothing — a pool
// handing a connection to another thread — and the old thread's connection, idle, is closed as a new
// connection's first chunk closes it. Inside one, the two keys each see part of an exchange, and the one that
// sees a request and the next exchange's response pairs them: a mispairing. That is failed closed: both keys
// are given up with one gap why=malformed, the loss is reported, and the pointer's chunks are passed over
// until its SSL_free, or a count that starts afresh (Seq 1) on the thread it was last followed on, which a
// lost close record leaves as the only sign of the address's next connection.
func (u *Uprobe) followPtr(key httpstream.ConnKey, pid, tid uint32, ssl uint64, seq uint32, request bool) bool {
	pk := ptrKey{pid: pid, ssl: ssl}
	st, seen := u.ptrs[pk]
	switch {
	case !seen:
		if len(u.ptrs) >= maxTrackedPtrs {
			// Only followed pointers are forgotten: a given-up one stays dead, or its chunks would reach
			// an abandoned connection that drops them uncounted.
			for k, v := range u.ptrs {
				if !v.dead {
					delete(u.ptrs, k)
				}
			}
			if len(u.ptrs) >= maxTrackedPtrs {
				clear(u.ptrs)
			}
		}
		u.ptrs[pk] = ptrState{tid: tid}
		return true
	case st.dead:
		if seq == 1 && tid == st.tid {
			// A count that starts afresh on the thread the pointer was last followed on: SSL_free removed the
			// kernel's row although its close record never reached us (a full ring), and glibc gave the
			// address to a new connection. What the dead pointer held is over, as handle's Seq==1 path
			// closes a live one.
			u.ptrs[pk] = ptrState{tid: tid}
			return true
		}
		if request {
			// Each request passed over is an exchange lost, counted rather than left to the one gap the
			// split raised.
			u.gap(httpstream.GapMalformed, "", 1, fmt.Sprintf("a request on SSL* %#x of pid %d, whose connection "+
				"is not followed until it is freed, was passed over", ssl, pid))
		}
		return false
	case st.tid == tid:
		return true
	}
	old := key
	old.PidTgid = uint64(pid)<<32 | uint64(st.tid)
	if len(u.pending[old]) == 0 && u.asm.Idle(old) && u.asm.Idle(key) {
		u.emitMessages(u.asm.Close(old))
		u.dropPending(old)
		u.ptrs[pk] = ptrState{tid: tid}
		return true
	}
	u.asm.Abandon(old)
	u.asm.Abandon(key)
	u.gap(httpstream.GapMalformed, "", 1, fmt.Sprintf("SSL* %#x of pid %d did the I/O of one exchange on threads %d "+
		"and %d; its connection is not followed until it is freed", ssl, pid, st.tid, tid))
	u.loseConns("an SSL*'s I/O split across two threads", old, key)
	u.ptrs[pk] = ptrState{tid: st.tid, dead: true}
	return false
}

// handleClose ends the connections an SSL_free record names (R3a). The record names a process and a
// pointer, and every connection of that process on the pointer is over, whichever thread did its I/O: a live
// SSL* names one object in its process. Each is closed as Stop closes a connection (edge case #28), so a
// close-delimited response ends here as a whole message, a body short of its length is emitted truncated with
// its gap, and the pointer's next connection, which glibc may give the same address, starts afresh instead of
// feeding its bytes into the old one's framing.
func (u *Uprobe) handleClose(raw []byte) {
	rec, err := bpf.DecodeSSLClose(raw)
	if err != nil {
		u.gap(GapSizeCap, "", 1, fmt.Sprintf("undecodable close record: %v", err))
		return
	}
	if !u.mine(rec.Hdr) {
		return
	}
	pid := uint64(rec.Hdr.PID)
	keys, msgs := u.asm.CloseWhere(func(k httpstream.ConnKey) bool {
		return k.Src == record.SourceSSL && k.SSLPtr == rec.SSLPtr && k.PidTgid>>32 == pid
	})
	u.emitMessages(msgs)
	for _, k := range keys {
		u.closePending(k, "a request's response was never seen before its connection closed")
	}
	// The pointer is freed, so its next connection, on whichever thread, starts afresh (followPtr).
	delete(u.ptrs, ptrKey{pid: rec.Hdr.PID, ssl: rec.SSLPtr})
}

// closePending ends what a connection that closed, started afresh or outlived the source still held: requests
// whose responses capture never saw (limits-check-doctor-cli.md R1 (e)). Those whose host may have been a
// model's (meteredHost) are reported unmetered, which ends a run with a token or cost budget, since their
// spend reached no budget. A connection with none waiting ended cleanly, and nothing is reported for it,
// unlike one capture lost (loseConn).
func (u *Uprobe) closePending(key httpstream.ConnKey, why string) {
	var n int64
	for _, r := range u.pending[key] {
		n += u.unanswered(r)
	}
	u.dropPending(key)
	u.reportUnmetered(n, why)
}

// mine reports whether a chunk belongs to this run. A scoped source compares the slot the kernel stamped on
// the chunk from the process's run-set row, which every cgroup of the run shares and no other run's does.
// An unscoped one falls back to the cgroup set, and one whose run's cgroup id is unknown — a test —
// accepts everything the kernel already filtered.
func (u *Uprobe) mine(h bpf.Header) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.scoped {
		return h.RunIdx == u.slot && h.Gen == u.gen
	}
	if len(u.cgroups) == 0 {
		return true
	}
	_, ok := u.cgroups[h.CgroupID]
	return ok
}

// baselineLost reads the lost counter once, at Start, as the value this run's drops are counted from. The
// counter is the build's and cumulative since its pins were made: earlier runs of the build, and, before the
// counter was split from the kernel record's, that ring too, left their drops in it, and diffing from zero
// made them this run's ring-buffer-drop (a run that lost nothing reported 500). A counter that cannot be read
// here leaves the baseline at zero, which can overstate the gap but never hides one of this run's drops (I4).
func (u *Uprobe) baselineLost() {
	if u.opts.Lost == nil {
		return
	}
	total, err := u.opts.Lost.Lost()
	if err != nil {
		u.warn("uprobe: lost counter unreadable at start, so drops before this run may be counted as its own: %v", err)
		return
	}
	u.mu.Lock()
	u.lost = total
	u.mu.Unlock()
}

// pollLost diffs the kernel's cumulative lost counter into a ring-buffer-drop gap (I7), from the value
// baselineLost read at Start.
func (u *Uprobe) pollLost() {
	if u.opts.Lost == nil {
		return
	}
	total, err := u.opts.Lost.Lost()
	if err != nil {
		u.log("uprobe: lost counter unreadable: %v", err)
		return
	}
	u.mu.Lock()
	delta := int64(total - u.lost)
	if total >= u.lost {
		u.lost = total
	}
	u.mu.Unlock()
	if delta > 0 {
		u.gap(GapRingBufferDrop, "", delta, "")
	}
}

// collectAssemblerGaps folds the reassembler's own counts into this source's, so one Gaps call reports
// both what could not be attached and what could not be parsed.
//
// What is folded in is the growth since the last fold, because the two counts meet on one key. The
// assembler counts cumulatively, and this source counts its own occurrences under reasons it shares with
// it: R37 files an undecodable ring record and the assembler's R11/R13 bounds alike under size-cap, and
// neither names a binary, so both land on gapKey{size-cap, ""}. Overwriting with the larger of the two
// would report whichever producer counted more and silently drop the other's occurrences, and adding the
// whole cumulative figure would double it on the next Gaps call — a gap event that understates what it
// explains is the half of I4 that R37's counts carry.
func (u *Uprobe) collectAssemblerGaps() {
	for _, g := range u.asm.Gaps() {
		u.mu.Lock()
		if delta := g.Count - u.asmFolded[g.Why]; delta > 0 {
			k := gapKey{Why: g.Why}
			cur, ok := u.gaps[k]
			if !ok {
				cur = &source.Gap{What: record.GapCapture, Why: g.Why}
				u.gaps[k] = cur
			}
			cur.Count += delta
			u.asmFolded[g.Why] = g.Count
		}
		u.mu.Unlock()
	}
}

// gap records one shortfall, adding to the count of an identical reason and binary. An activity-only source keeps no
// capture to measure a shortfall against, so it only logs one.
func (u *Uprobe) gap(why, binary string, count int64, detail string) {
	if !u.reporting() {
		u.log("uprobe: activity-only, no gap %s %s: %s", why, binary, detail)
		return
	}
	u.mu.Lock()
	k := gapKey{Why: why, Binary: binary}
	if _, ok := u.gaps[k]; !ok && binary != "" && len(u.gaps) >= derive.MaxCoverageKeys {
		// The binary is a name the agent chose (a path it opened, a mapping it made), so past the cap the
		// count goes into the reason's one binary-less entry, as derive.Coverage does (R37).
		k.Binary, binary = "", ""
	}
	cur, ok := u.gaps[k]
	if !ok {
		cur = &source.Gap{What: record.GapCapture, Why: why, Binary: binary}
		u.gaps[k] = cur
	}
	cur.Count += count
	u.mu.Unlock()
	if detail != "" {
		u.log("uprobe: gap %s %s: %s", why, binary, detail)
	}
}

// warn writes the one line an operator needs even at the default log level: why this mechanism is not
// running for the run, which the ledger's mechanism-unavailable gap cannot say (§7).
func (u *Uprobe) warn(format string, args ...any) {
	if u.opts.Logger == nil {
		return
	}
	u.mu.Lock()
	runID := u.run.ID
	u.mu.Unlock()
	u.opts.Logger.Warn(fmt.Sprintf(format, args...), "run", runID)
}

// maxTokensScanner is the reassembler's BodyScanner: a request body kept only as a prefix has its max_tokens read
// off every byte by derive's own reading, so a cut stream can still be bounded (R10).
func maxTokensScanner() httpstream.BodyScanner { return &anthropic.MaxTokensScanner{} }

// log writes operator detail to this run's own log, never to the ledger (§9 "Logging").
func (u *Uprobe) log(format string, args ...any) {
	if u.opts.Logger == nil {
		return
	}
	u.mu.Lock()
	runID := u.run.ID
	u.mu.Unlock()
	u.opts.Logger.Debug(fmt.Sprintf(format, args...), "run", runID)
}
