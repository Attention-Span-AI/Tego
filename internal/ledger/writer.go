// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/reason"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// File names inside a run directory (§3).
const (
	EventsFile      = "events.jsonl"
	LockFile        = "lock"
	BlobsDir        = "blobs"
	ContractFile    = "contract.yaml"
	LastRefusalFile = reason.FileName // the reason file (pkg/spec/reason)
	// ChainLogFile is the chain anchor's file name: the invoking user's ~/.tego/chain.log in the product,
	// next to the ledger root by default (DefaultAnchorPath).
	ChainLogFile = "chain.log"
	// StopRequestFile is the stop marker `tego stop` (and the dashboard's Stop) places before signalling the
	// launcher, so the launcher records run_end reason=stopped, not reason=signal (docs/p0/runtime-launch.md §3,
	// R9). internal/runtime names it as StopRequestFile too; it lives here so tego-control can place it without
	// linking the engine.
	StopRequestFile = "stop.request"
)

// Sink is the pipeline's terminal type: internal/runtime composes stages in front of a Writer's Append.
type Sink func(e *record.Event) error

// Stage wraps a Sink with one transform; RedactStage and SplitBlobsStage have this shape.
type Stage func(next Sink) Sink

// Option configures Open.
type Option func(*options)

type options struct {
	anchor   ChainAnchor
	clock    Clock
	contract []byte
	log      *slog.Logger
	fresh    bool
	existing bool
	noCreate bool
}

// WithAnchor replaces the default chain anchor, <ledger_root>/../chain.log (DefaultAnchorPath).
func WithAnchor(a ChainAnchor) Option { return func(o *options) { o.anchor = a } }

// WithClock replaces SystemClock.
func WithClock(c Clock) Option { return func(o *options) { o.clock = c } }

// WithContract supplies the compiled contract bytes copied to contract.yaml at Open, best-effort (§3).
func WithContract(yaml []byte) Option { return func(o *options) { o.contract = yaml } }

// WithLogger routes operational detail (best-effort failures) to the product's own log; discarded by default.
func WithLogger(l *slog.Logger) Option { return func(o *options) { o.log = l } }

// WithFreshRunDir makes Open accept only the run directory MakeRunDir just made: one this process owns
// that holds nothing yet. The launcher makes its run directory and opens it in two steps, and in between
// a user who owns the ledger root could rename in a directory of their own under the run's name, holding
// links root would then create and write through; with this option Open refuses that directory (os.ErrExist)
// instead of writing into it, and what it holds from then on is the directory it checked (openRunDir).
func WithFreshRunDir() Option { return func(o *options) { o.fresh = true } }

// WithExistingRunDir makes Open resume a run directory that must already exist: a missing one is os.ErrNotExist
// and is not created (nor is a missing ledger root). Only a fresh run makes its directory (MakeRunDir); a
// resume that recreated a directory gc had just removed would write a ledger with no run_start and anchor it.
func WithExistingRunDir() Option { return func(o *options) { o.existing = true } }

// WithExistingFiles makes Open create nothing in the run directory: a missing lock, events.jsonl or blobs/ is
// os.ErrNotExist. It is for a process that only ends a run a live Writer made: a reaper, a launched run's or an
// adoption's, which wakes as its launcher or adopter exits and so may meet a run directory already being removed,
// and a release of an adoption from its record. A file made there leaves `tego gc`'s or a test's RemoveAll with a
// directory that is not empty, and the empty ledger it makes reads as a run never started.
func WithExistingFiles() Option { return func(o *options) { o.noCreate = true } }

// Writer is the single writer of one run directory for the run's lifetime (§3). It owns the events and lock
// file descriptors, closed only by Close; it is safe for concurrent Append calls within one process, though the
// product drains one channel into it from one goroutine (§9).
type Writer struct {
	dir string
	// dirFD is the run directory, held from Open to Close: every file the Writer makes or opens in it is
	// named relative to this descriptor (openRunDir), so a ledger root renamed or replaced while the run
	// is live does not move where the Writer writes; a path-based store beside it (NewBlobRepository, a
	// uprobe source's) is not covered (record-ledger.md §3, residual).
	// It is strict (ADR 0023): Close fsyncs it, and closeDirs reports its close.
	dirFD *sys.FD
	// handTo is who Close hands the run directory to, the ledger root's owner when this process is root
	// and the ledger root is another uid's (handOK).
	handTo owner
	handOK bool
	ref    record.RunRef
	events *os.File
	out    io.Writer // events, or a test double that fails on demand
	lock   *os.File
	blobs  *blobStore
	anchor ChainAnchor
	clock  Clock
	log    *slog.Logger
	pid    int
	tid    int

	mu      sync.Mutex
	seq     uint64
	prevID  string
	headID  string
	started bool
	// minor is the run's revision, its run_start's record_minor: every line is encoded at it (MarshalLineAt), so a
	// field malformed or below its revision is refused, never written.
	minor  int
	closed bool
	torn   error // sticky: a partial line on disk that could not be cut back (E6)
	// orphanGap says this Writer wrote the orphaned run's gap (Close), so a Close retried after a refused run_end
	// does not write a second one.
	orphanGap bool
	// size is how many bytes of events.jsonl are whole lines. A write that leaves part of a line on disk
	// is cut back to it, so the next line starts on a line boundary and the Writer goes on (E6).
	size int64
	// truncate cuts events.jsonl to a length; it is the file's Truncate, a field so a test can make it fail.
	truncate func(int64) error
	// mirrorFD is a directory the run's own processes can read, where last-refusal.json is written as well,
	// or nil (MirrorLastRefusal). The ledger root is read-denied to the agent (agent-contract.md R6a), so a
	// harness inside the run reads its refusal there (spec/reason/REASON-CHANNEL.md §2).
	mirrorFD *sys.FD
	mirror   string
	// refusal holds the last refused line waiting to become last-refusal.json, written off Append's path
	// (lastRefusal).
	refusal lastRefusal
}

// newOptions is the setup Open and OpenAt share: the run reference check, the options with their defaults, and
// the default anchor beside dir. One place, so the launcher path and the reaper path cannot default differently.
func newOptions(dir string, run record.RunRef, opts []Option) (options, error) {
	if !IsRunID(run.ID) || !record.IsAgentID(run.Agent) {
		return options{}, fmt.Errorf("%w: id %q agent %q", ErrBadRunRef, run.ID, run.Agent)
	}
	o := options{clock: SystemClock{}, log: slog.New(slog.DiscardHandler)}
	for _, opt := range opts {
		opt(&o)
	}
	if o.anchor == nil {
		o.anchor = NewFileChainAnchor(DefaultAnchorPath(dir))
	}
	return o, nil
}

// Open creates or resumes the run directory dir for run and takes its lock (§4).
//
// A fresh directory yields a Writer with seq 0 and no line written. A directory left by a dead process is
// resumed: seq and prev continue from the last complete line, a torn tail is discarded and a gap event records
// it (see resume). A directory whose ledger already ends in run_end is refused with ErrRunEnded; one whose lock
// another live process holds with ErrRunLocked. Nothing is retried and nothing blocks.
func Open(dir string, run record.RunRef, opts ...Option) (*Writer, error) {
	o, err := newOptions(dir, run, opts)
	if err != nil {
		return nil, err
	}
	d, handTo, handOK, err := openRunDir(dir, o.existing)
	if err != nil {
		return nil, fmt.Errorf("ledger: create run dir: %w", err)
	}
	return openWriter(dir, d, handTo, handOK, run, o)
}

// OpenAt is Open for the run directory the caller lends as at (an O_PATH descriptor will do), which stays the
// caller's: the Writer works on a descriptor of its own reopened from it under one lease, and dir, which names
// the directory in messages and for the default anchor, is never resolved. It is how a privileged process that
// was handed the run's directory (the reaper, ADR 0020 (3)) writes the ledger without re-resolving a path a
// same-uid process could have swapped since. The hand-over owner is that of the directory the run directory is
// in now, read through "..". A lender that lends nothing is sys.ErrClosed.
func OpenAt(at sys.Lender, dir string, run record.RunRef, opts ...Option) (*Writer, error) {
	o, err := newOptions(dir, run, opts)
	if err != nil {
		return nil, err
	}
	if at == nil {
		return nil, fmt.Errorf("ledger: reopen run dir %s: %w", dir, sys.ErrClosed)
	}
	d, err := reopenDir(at)
	if err != nil {
		return nil, fmt.Errorf("ledger: reopen run dir %s: %w", dir, err)
	}
	p, err := d.Openat("..", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("ledger: open the parent of run dir %s: %w", dir, err)
	}
	handTo, handOK, err := ownerOf(p, filepath.Dir(dir))
	_ = p.Close()
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	return openWriter(dir, d, handTo, handOK, run, o)
}

// reopenDir is a descriptor of the caller's own on the directory at lends, reopened under one lease.
func reopenDir(at sys.Lender) (*sys.FD, error) {
	var d *sys.FD
	err := at.Borrow(func(n int) error {
		var err error
		d, err = sys.Strict(sys.Own(unix.Openat(n, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)))
		return err
	})
	return d, err
}

// openWriter is Open and OpenAt past the run directory's descriptor, which it owns from here.
func openWriter(dir string, d *sys.FD, handTo owner, handOK bool, run record.RunRef, o options) (*Writer, error) {
	var err error
	w := &Writer{
		dir: dir, dirFD: d, handTo: handTo, handOK: handOK, ref: run, anchor: o.anchor, clock: o.clock,
		log: o.log, pid: os.Getpid(), tid: unix.Gettid(),
	}
	if o.fresh {
		if err := checkFresh(d, dir); err != nil {
			w.closeDirs()
			return nil, err
		}
	}
	if w.lock, err = takeLock(d, dir, o.fresh, !o.noCreate); err != nil {
		w.closeDirs()
		return nil, err
	}
	if err := w.openFiles(!o.noCreate); err != nil {
		w.release()
		w.closeDirs()
		return nil, err
	}
	if err := w.resume(); err != nil {
		w.release()
		w.closeDirs()
		return nil, err
	}
	w.copyContract(o.contract)
	return w, nil
}

// checkFresh is WithFreshRunDir's test of the run directory open at d: this process's own, and empty.
func checkFresh(d *sys.FD, dir string) error {
	var st unix.Stat_t
	if err := d.Fstat(&st); err != nil {
		return &os.PathError{Op: "fstat", Path: dir, Err: err}
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("ledger: run directory %s is uid %d's, not the one this process made: %w", dir, st.Uid, os.ErrExist)
	}
	names, err := readDirNames(d, dir)
	if err != nil {
		return err
	}
	if len(names) != 0 {
		return fmt.Errorf("ledger: run directory %s already holds %v, not the one this process made: %w", dir, names, os.ErrExist)
	}
	return nil
}

// takeLock opens the lock file in the run directory open at at and takes flock(LOCK_EX|LOCK_NB);
// EWOULDBLOCK is ErrRunLocked (§7 row 1). The kernel releases the lock when the holding process dies, which
// is what makes it a liveness signal.
//
// For a fresh run directory, EWOULDBLOCK is retried for up to freshLockWait. The run is this process's and
// has no holder, so the only other flock is a probe's: a reader's lockFree takes LOCK_SH|LOCK_NB and stop's
// liveness check (runtime.ProbeLock) LOCK_EX|LOCK_NB, each for an instant, and either conflicts with this
// LOCK_EX request; one that landed between the lock file's creation and this flock
// refused a brand-new run with ErrRunLocked.
func takeLock(at *sys.FD, dir string, fresh, create bool) (*os.File, error) {
	f, _, err := openFileAt(at, dir, LockFile, unix.O_RDWR, create)
	if err != nil {
		return nil, fmt.Errorf("ledger: open lock: %w", err)
	}
	lockOpened(f.Name())
	deadline := time.Now().Add(freshLockWait)
	for {
		err = sys.Flock(f, unix.LOCK_EX|unix.LOCK_NB)
		if !fresh || !errors.Is(err, unix.EWOULDBLOCK) || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w: %s", ErrRunLocked, f.Name())
		}
		return nil, fmt.Errorf("ledger: flock %s: %w", f.Name(), err)
	}
	return f, nil
}

// freshLockWait is how long a fresh run's lock waits out a probe's momentary hold (takeLock).
const freshLockWait = 50 * time.Millisecond

// lockOpened runs between the lock file's open and its flock; a test takes a probe's hold there.
var lockOpened = func(string) {}

// openFiles opens events.jsonl O_WRONLY|O_CREAT|O_APPEND 0600 (I1: the only writing open of that path in the
// package and it always carries O_APPEND) and creates blobs/, both in the run directory's descriptor. With create
// false neither is made (WithExistingFiles).
func (w *Writer) openFiles(create bool) error {
	f, _, err := openFileAt(w.dirFD, w.dir, EventsFile, unix.O_WRONLY|unix.O_APPEND, create)
	if err != nil {
		return fmt.Errorf("ledger: open events: %w", err)
	}
	w.events, w.out, w.truncate = f, f, f.Truncate
	blobs := filepath.Join(w.dir, BlobsDir)
	if create {
		if _, err := makeDir(w.dirFD, w.dir, BlobsDir, blobs); err != nil {
			return fmt.Errorf("ledger: create blobs dir: %w", err)
		}
	}
	bd, err := w.dirFD.Openat(BlobsDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("ledger: open blobs dir: %w", openError(w.dirFD, BlobsDir, blobs, err))
	}
	w.blobs = &blobStore{dir: blobs, fd: bd, added: new(atomic.Int64)}
	if n := w.blobs.sweepTemp(); n > 0 {
		w.log.Info("ledger: discarded partial blobs from a dead writer", "run", w.ref.ID, "count", n)
	}
	if n := sweepRunTemps(w.dirFD, w.dir); n > 0 {
		w.log.Info("ledger: discarded partial files from a dead writer", "run", w.ref.ID, "count", n)
	}
	return nil
}

// sweepRunTemps removes the temp files writeFileAt leaves in a run directory when its writer dies between
// creating one and renaming it: ".contract.yaml.<n>" and ".last-refusal.json.<n>". Nothing else removed them.
// It runs from Open, under the run's lock, like blobStore.sweepTemp.
func sweepRunTemps(at *sys.FD, dir string) int {
	names, err := readDirNames(at, dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, name := range names {
		if !strings.HasPrefix(name, "."+ContractFile+".") && !strings.HasPrefix(name, "."+LastRefusalFile+".") {
			continue
		}
		if unlinkAt(at, name) == nil {
			n++
		}
	}
	return n
}

// resume continues an existing ledger. It walks the complete lines to recover seq, prev and whether run_start
// and run_end were written, then discards an unterminated tail that does not decode and terminates one that
// does. Under the exclusive lock
// the torn bytes were never a line any reader could see, so truncating them changes no id and no anchor; the
// resumed chain then records the loss as a gap event (what=record). A ledger that already ended is refused.
func (w *Writer) resume() error {
	st, err := w.events.Stat()
	if err != nil {
		return fmt.Errorf("ledger: stat events: %w", err)
	}
	w.size = st.Size()
	if st.Size() == 0 {
		return nil
	}
	// events is O_WRONLY, so scanning needs a descriptor of its own, and it must be of the same file.
	rf, _, err := openFileAt(w.dirFD, w.dir, EventsFile, unix.O_RDONLY, false)
	if err != nil {
		return fmt.Errorf("ledger: resume: %w", err)
	}
	defer func() { _ = rf.Close() }()
	if rst, err := rf.Stat(); err != nil || !os.SameFile(rst, st) {
		return fmt.Errorf("ledger: resume: %s changed while it was being opened", rf.Name())
	}
	var chain record.Chain
	var tornBytes int64
	ended, unterminated := false, false
	for l, err := range scanLines(rf) {
		if err != nil {
			return fmt.Errorf("ledger: resume: %w", err)
		}
		if !l.terminated {
			if !wholeLine(l.data) {
				tornBytes = int64(len(l.data))
				break
			}
			unterminated = true
		}
		if ended {
			return ErrRunEnded // a line after run_end: the run is closed, and this file is not the Writer's
		}
		e, err := chain.Add(l.data)
		if err != nil {
			return fmt.Errorf("ledger: resume: %w", err)
		}
		// A digest-valid prefix may still belong to another run or violate
		// the event/whole-run invariants Verify checks. Refuse it before
		// restoring a terminator, cutting a torn tail or publishing an anchor.
		if e.Kind == record.KindRunStart {
			if w.minor, err = e.RunStartMinor(); err != nil {
				return fmt.Errorf("ledger: resume: %w: line %d: %w", ErrUnverified, e.Seq, err)
			}
		}
		if err := e.ValidateAt(w.minor); err != nil {
			return fmt.Errorf("ledger: resume: %w: line %d: %w", ErrUnverified, e.Seq, err)
		}
		if e.Run != w.ref.ID {
			return fmt.Errorf("ledger: resume: %w: %w: line %d is run %q, resuming %q", ErrUnverified,
				ErrRunMismatch, e.Seq, e.Run, w.ref.ID)
		}
		if (e.Seq == 0) != (e.Kind == record.KindRunStart) {
			return fmt.Errorf("ledger: resume: %w: line %d is %s: run_start is the first line and only the first",
				ErrUnverified, e.Seq, e.Kind)
		}
		switch e.Kind {
		case record.KindRunStart:
			w.started = true
		case record.KindRefused:
			// The reason file's refusals counts the run's refused lines, not this Writer's: it only grows across a
			// resume, and the ring, empty here, lists the ones after (the rest Since reports as not listed).
			w.refusal.count++
		}
		ended = e.Kind == record.KindRunEnd
	}
	if ended {
		return ErrRunEnded
	}
	w.seq, w.prevID = chain.Len(), chain.Head()
	// The dead writer's lines name blobs this store never saw written, and Put's Has short-circuit will not
	// queue them either: Close makes all of them durable (one syncfs), so no reference the resumed ledger
	// anchors is durable before the blob it names (R6).
	w.blobs.overflow = true
	if tornBytes == 0 {
		// The tail decoded, so it is a whole line that lost only its terminator: a crash during write(2) can
		// take the last byte as readily as any other. An id covers the line's bytes as the reader takes them,
		// without the newline, so writing the newline back restores the file's line boundary and changes no id
		// and no content. Skipping it would leave the next Append starting at the end of the file and running
		// its JSON onto the unterminated line, putting two events on one physical line that decodes as
		// neither, which no truncation can later undo (E8).
		if unterminated {
			if _, err := w.events.Write([]byte{'\n'}); err != nil {
				return fmt.Errorf("ledger: terminate resumed line: %w", err)
			}
			w.size++
		}
		return nil
	}
	if err := w.events.Truncate(st.Size() - tornBytes); err != nil {
		return fmt.Errorf("ledger: discard torn tail: %w", err)
	}
	w.size = st.Size() - tornBytes
	if !w.started {
		return nil // the torn line was run_start itself: a fresh run
	}
	gap := record.Event{Kind: record.KindGap, Source: record.SourceSupervisor, PID: w.pid, TID: w.tid}
	if err := gap.SetPayload(record.GapPayload{What: record.GapRecord, Why: "torn-tail", Count: 1}); err != nil {
		return err
	}
	return w.append(&gap)
}

// copyContract writes contract.yaml, best-effort and never fatal (§3): a failure is logged, not returned.
func (w *Writer) copyContract(yaml []byte) {
	if yaml == nil {
		return
	}
	if err := writeFileAt(w.dirFD, w.dir, ContractFile, yaml, true); err != nil {
		w.log.Warn("ledger: contract copy not written", "run", w.ref.ID, "err", err)
	}
}

// Ref returns the run the Writer is bound to.
func (w *Writer) Ref() record.RunRef { return w.ref }

// Dir returns the run directory.
func (w *Writer) Dir() string { return w.dir }

// Seq returns the seq the next Append will assign.
func (w *Writer) Seq() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.seq
}

// Size returns how many bytes of events.jsonl are whole lines.
func (w *Writer) Size() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.size
}

// LedgerBytes returns what the run's record.max_run_bytes ceiling is compared against
// (limits.WithLedgerCeiling): events.jsonl's whole lines and the bytes this run added to blobs/, a store beside the
// Writer's included (BlobBytes). A Writer that resumes a run counts only what it adds; no ceiling applies to one.
func (w *Writer) LedgerBytes() int64 { return w.Size() + w.blobs.added.Load() }

// BlobBytes is the counter LedgerBytes reads, for a store beside this Writer's (NewCountedBlobRepository).
func (w *Writer) BlobBytes() *atomic.Int64 { return w.blobs.added }

// Head returns the id of the last line written; after Close it is the run_end id anchored in chain.log.
func (w *Writer) Head() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.prevID
}

// WriteRunStart appends the run_start line, which must be the first line of every run. Source is supervisor;
// pid and tid are the launcher's.
func (w *Writer) WriteRunStart(start record.RunStartPayload) error {
	return w.WriteRunStartIn(start, 0)
}

// WriteRunStartIn is WriteRunStart for a run whose cgroup scope exists: its id goes in run_start's cgroup
// field, where a sweep reads which scope is the run's (internal/runtime killOrphan; runtime-launch.md R20). 0
// is a run with no scope of its own.
func (w *Writer) WriteRunStartIn(start record.RunStartPayload, cgroup uint64) error {
	e := record.Event{Kind: record.KindRunStart, Source: record.SourceSupervisor, PID: w.pid, TID: w.tid, Cgroup: cgroup}
	if err := e.SetPayload(start); err != nil {
		return err
	}
	// R10 applies to run_start as to every event: an argv over 4 KiB is stored as a blob (command_blob), not
	// left to make a line every reader takes whole.
	if err := w.splitBlobs(&e); err != nil {
		return err
	}
	return w.Append(&e)
}

// Append writes e as the next line (§4). The caller sets Kind, Source, PID, TID, Cgroup, the action fields and
// Payload, and may set MonoNS to the moment it captured the event; Run, Agent, TS, Seq, Prev and ID are
// overwritten unconditionally, MonoNS only when it is zero, and all are left on *e afterwards.
// Append trusts Payload as already redacted and blob-split (I2). It never fsyncs (R6) and issues one write(2)
// (R4, I5). run_start must come first and only once; run_end is written by Close only.
func (w *Writer) Append(e *record.Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.appendNext(e)
}

// AppendBatch appends prepared events without another writer interleaving them.
// Each line keeps its own hash and write. On failure an already written prefix
// remains; the caller must end the run as for any failed Append.
func (w *Writer) AppendBatch(events ...*record.Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, e := range events {
		if err := w.appendNext(e); err != nil {
			return err
		}
	}
	return nil
}

// appendNext checks sequencing under the writer mutex.
func (w *Writer) appendNext(e *record.Event) error {
	if w.closed {
		return ErrClosed
	}
	if w.torn != nil {
		return fmt.Errorf("%w: %w", ErrTorn, w.torn)
	}
	switch {
	case e.Kind == record.KindRunEnd:
		return fmt.Errorf("%w: run_end is written by Close", record.ErrInvalidEvent)
	case !w.started && e.Kind != record.KindRunStart, w.started && e.Kind == record.KindRunStart:
		return fmt.Errorf("%w: seq %d is %s", ErrNotStarted, w.seq, e.Kind)
	}
	return w.append(e)
}

// append stamps, encodes and writes one line; w.mu must be held.
func (w *Writer) append(e *record.Event) error {
	line, minor, err := w.encode(e)
	if err != nil {
		return err
	}
	return w.writeLine(e, line, minor)
}

// encode stamps e as the next line and encodes it at the run's revision, minor, writing nothing: the line, ending in
// "\n", is writeLine's to write. w.mu must be held.
func (w *Writer) encode(e *record.Event) (line []byte, minor int, err error) {
	e.V = record.Version
	e.Run, e.Agent = w.ref.ID, w.ref.Agent
	e.TS = w.clock.Now().UTC()
	// mono_ns is the CLOCK_MONOTONIC reading at capture (§2), so a producer's own reading stands: the
	// kernel recorder's is bpf_ktime_get_ns() at the hook (enforce-cgroup-observe.md E20), the
	// forwarder's is when the request began. Stamping every line here would record how long the event
	// waited in the queue rather than when the agent acted. Zero is E20's "unknown", and only that is
	// filled in with the append time.
	if e.MonoNS == 0 {
		e.MonoNS = w.clock.Mono()
	}
	e.Seq, e.Prev, e.ID = w.seq, w.prevID, ""
	minor = w.minor
	if e.Kind == record.KindRunStart {
		if minor, err = e.RunStartMinor(); err != nil {
			return nil, 0, fmt.Errorf("ledger: append seq %d: %w", e.Seq, err)
		}
	}
	if line, err = e.MarshalLineAt(minor); err != nil {
		return nil, 0, fmt.Errorf("ledger: append seq %d: %w", e.Seq, err)
	}
	if len(line) >= MaxLineBytes {
		// Every reader refuses a line past MaxLineBytes as corruption, so writing one would end the run's
		// record at that line for every reader after it. R10 keeps real lines far below the bound.
		return nil, 0, fmt.Errorf("ledger: append seq %d: %w: line of %d bytes, the bound is %d", e.Seq,
			record.ErrInvalidEvent, len(line), MaxLineBytes)
	}
	return append(line, '\n'), minor, nil
}

// writeLine writes line, e as encode encoded it, as the next line, and advances the chain; w.mu must be held.
func (w *Writer) writeLine(e *record.Event, line []byte, minor int) error {
	// R4: the whole line in one Write; os.File retries a short write(2) on the unwritten suffix and reports
	// io.ErrShortWrite only when the kernel accepted fewer bytes with no error (E5).
	n, err := w.out.Write(line)
	if err != nil {
		if errors.Is(err, io.ErrShortWrite) {
			err = fmt.Errorf("%w: %d of %d bytes", ErrShortWrite, n, len(line))
		}
		if n > 0 {
			// Bytes of this line reached the file. Cut them back to the last whole line: the Writer holds the
			// run's lock and events.jsonl is O_APPEND, so everything past w.size is this line's. The line is
			// lost, and reported; the next one starts on a line boundary, so one full-disk moment no longer
			// ends the run's record for good. Only a file that cannot be cut is torn for the rest of the run.
			if terr := w.cutTornLine(); terr != nil {
				w.torn = errors.Join(err, terr)
			}
		}
		return fmt.Errorf("ledger: write seq %d: %w", e.Seq, err)
	}
	w.size += int64(len(line))
	w.seq++
	w.prevID = e.ID
	if e.Kind == record.KindRunStart {
		w.started, w.minor = true, minor
	}
	if e.Kind == record.KindRefused {
		w.refusal.post(w, e)
	}
	return nil
}

// cutTornLine truncates events.jsonl back to its last whole line (w.size); w.mu must be held.
func (w *Writer) cutTornLine() error {
	if err := w.truncate(w.size); err != nil {
		return fmt.Errorf("ledger: cut a partial line: %w", err)
	}
	return nil
}

// refusalWindow is how often last-refusal.json is rewritten at most. A refused line posts itself as the
// latest and returns; the file is written off Append's path, at once when the last write is older than the
// window, else when the window ends, with whichever refusal is latest by then. Written per line, a refusal
// flood (the agent chooses the refusal rate) cost a create, write and rename per line, twice with the
// mirror, on the pipeline goroutine under w.mu: Append went from 22 µs to 100 µs on tmpfs and 400 µs on
// ext4, and the ledger's throughput fell 3.7x.
const refusalWindow = 10 * time.Millisecond

// lastRefusal is last-refusal.json's latest-wins writer (record-ledger.md §3), in the reason file's v1 shape
// (pkg/spec/reason, ADR 0061). What its readers (a harness polling TEGO_REASON after the refusal it saw) may rely
// on: the file is always one whole file (temp file and rename); its seq and refusal count only grow from one write
// to the next, so a newer refusal is never followed by an older one; it lists only refused lines events.jsonl already
// holds (post runs after the line's write); it trails the ledger by refusalWindow plus the timer's and the box's delay
// while the Writer is open; and Close and Abandon write the latest before they return. A crash loses at most the last
// window; the ledger line is authoritative.
//
// Of the two copies, the mirror (the run-readable one a harness's hook reads, MirrorLastRefusal) is written first,
// under a lock of its own, and the run directory's copy, which no process of the run reads, after it: a refusal reaches
// the hook as soon as the window allows and never waits behind a rename on a slow disk. A crash between the two
// writes leaves the mirror one write ahead of the run directory's copy, never the other way, and both list only lines
// the ledger holds (record-ledger.md §3).
//
// The newest reason.RingSize refused lines are kept in a ring, filled by post() under mu with no file I/O and no
// decoding (a payload's cost to decode is the agent's to choose): post() copies the payload, into the slot's own
// buffer, reused from one refusal to the next, when it fits, so the steady state allocates nothing. The write that
// next lists a refusal decodes it, once, and keeps its fields cut (reason.Refusal.Cut) for the writes after.
type lastRefusal struct {
	mu      sync.Mutex // guards ring, next, n, count, waiting, dirty, armed, last and done
	ring    [reason.RingSize]refusalSlot
	next    int       // the slot the next refusal takes
	n       int       // slots that hold a refusal
	count   uint64    // the run's refused lines, those a resumed ledger held and those posted since: the file's refusals
	waiting int       // bytes of the ring's long payloads (refusalSlot.long), at most maxWaitingBytes
	dirty   bool      // a refusal was posted since the file was last written
	armed   bool      // a flush is scheduled
	last    time.Time // when the file was last written
	done    bool      // Close or Abandon has flushed; nothing is written after
	// dirFile is the newest file the mirror got and the run directory's copy has not, nil when there is none; under
	// mu. A write of the run directory's copy takes it, so that copy is never older than the one it replaces.
	dirFile []byte
	// mirrorMu serializes the writes from their copy of the ring to the mirror's write, the decoding included, and
	// keeps the mirror's descriptor open under them. fileMu serializes the writes of the run directory's copy and
	// keeps the run directory's descriptor open under them; a write takes it only after it let go of mirrorMu, so a
	// rename in the run directory on a slow disk never holds up the mirror. Close, Abandon and MirrorLastRefusal take
	// the lock of a descriptor before they close it.
	mirrorMu sync.Mutex
	fileMu   sync.Mutex
	dirDone  bool // the final write of the run directory's copy is done; under fileMu
	writes   int  // run directory copies written, under fileMu; for tests
	decoded  int  // payloads decoded, under mirrorMu; for tests
}

// refusalSlot is one refused line of the ring: what the reason file takes from it. Until a write decodes it, its
// payload is in payload, the slot's own buffer, when it is at most maxSlotPayload bytes, and else in long, a copy of
// its own; the write that decodes it puts it, cut (reason.Refusal.Cut, which keeps each cut field's length), in
// cut, and releases long.
type refusalSlot struct {
	nth     uint64 // the refusal's number in count: which refusal a write decoded, when it settles it
	seq     uint64
	ts      time.Time
	pid     int
	reason  record.Reason
	rule    string
	payload []byte
	long    []byte
	cut     *reason.Refusal
}

// maxSlotPayload is the longest refused payload a ring slot copies into its own buffer: a path within PATH_MAX made
// of control bytes, each escaped as six, is about 24 KiB, so every path fits. The slots' buffers hold at most
// reason.RingSize times this much (1 MiB), and their cut fields as much again.
const maxSlotPayload = 32 << 10

// maxWaitingBytes bounds the long payloads the ring holds whole until a write decodes them (a target is a string the
// agent chose, up to the ledger's line bound). One always fits, since a payload is shorter than its line; when the
// next would pass the bound, the oldest refusals leave the ring, so recent stays contiguous and the count exact, and
// the reader is told how many are not listed. While a write decodes, the bytes it holds are counted no longer, so
// the ring and that write hold at most twice this much.
const maxWaitingBytes = MaxLineBytes

// post makes e the latest refusal, in the ring's next slot, and schedules the file's write; w.mu is held, e's
// seq, ts and pid are the line's (append), and nothing here touches a file or decodes the payload.
func (r *lastRefusal) post(w *Writer, e *record.Event) {
	var long []byte
	if len(e.Payload) > maxSlotPayload {
		long = append([]byte(nil), e.Payload...) // a copy of its own, as every refusal had before the ring
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.done {
		return
	}
	for r.waiting+len(long) > maxWaitingBytes && r.n > 0 {
		r.release(&r.ring[(r.next-r.n+reason.RingSize)%reason.RingSize])
		r.n--
	}
	s := &r.ring[r.next]
	r.release(s)
	r.count++
	s.nth, s.seq, s.ts, s.pid, s.reason, s.rule, s.cut, s.long = r.count, e.Seq, e.TS, e.PID, e.Reason, e.Rule, nil, long
	r.waiting += len(long)
	s.payload = s.payload[:0]
	if long == nil {
		if cap(s.payload) < len(e.Payload) {
			s.payload = make([]byte, 0, min(maxSlotPayload, max(len(e.Payload), 2*cap(s.payload))))
		}
		s.payload = append(s.payload, e.Payload...)
	}
	r.next = (r.next + 1) % reason.RingSize
	r.n = min(r.n+1, reason.RingSize)
	r.dirty = true
	if r.armed {
		return
	}
	r.armed = true
	time.AfterFunc(max(0, refusalWindow-time.Since(r.last)), func() { w.flushRefusal(false) })
}

// release lets go of s's long payload, which s no longer needs: r.mu is held.
func (r *lastRefusal) release(s *refusalSlot) {
	r.waiting -= len(s.long)
	s.long = nil
}

// snapshot is the ring's refusals, oldest first. The payloads of those no write has decoded yet are copied out of
// the slots' buffers (into one buffer); a long one is shared, since nothing writes to it after post. r.mu is held.
func (r *lastRefusal) snapshot() []refusalSlot {
	out := make([]refusalSlot, r.n)
	size := 0
	for i := range out {
		out[i] = r.ring[(r.next-r.n+i+reason.RingSize)%reason.RingSize]
		if out[i].cut == nil {
			size += len(out[i].payload)
		}
	}
	buf := make([]byte, 0, size)
	for i := range out {
		if out[i].cut != nil {
			out[i].payload = nil
			continue
		}
		at := len(buf)
		buf = append(buf, out[i].payload...)
		out[i].payload = buf[at:len(buf):len(buf)]
	}
	return out
}

// settle keeps what a write decoded in the slots that still hold those refusals, so each refusal is decoded once,
// and releases their long payloads: r.mu is held.
func (r *lastRefusal) settle(recent []refusalSlot) {
	for i := range recent {
		for j := range r.ring {
			if s := &r.ring[j]; s.nth == recent[i].nth && s.cut == nil && recent[i].cut != nil {
				s.cut = recent[i].cut
				r.release(s)
			}
		}
	}
}

// flushRefusal writes the file, if a refusal came since it was last written: the mirror first, under mirrorMu, then
// the run directory's copy, under fileMu, with the newest file the mirror got (dirFile). final is Close's and
// Abandon's: it writes what is pending and stops every later write, and it returns only after every earlier write
// has finished with both descriptors, so no scheduled flush reaches a descriptor after it is closed. The ring is
// copied under the refusal lock, which mirrorMu's order makes later than the copy any earlier write took: the seq and
// count a write carries only grow, in both copies.
func (w *Writer) flushRefusal(final bool) {
	r := &w.refusal
	r.mirrorMu.Lock()
	r.mu.Lock()
	if r.done {
		r.mu.Unlock()
		r.mirrorMu.Unlock()
		return
	}
	var recent []refusalSlot
	count, dirty := r.count, r.dirty
	if dirty {
		recent = r.snapshot()
		r.last = time.Now()
	}
	r.dirty, r.armed, r.done = false, false, final
	r.mu.Unlock()
	if dirty {
		b := w.encodeLastRefusal(count, recent)
		w.writeMirror(b)
		r.mu.Lock()
		r.settle(recent)
		if b != nil {
			r.dirFile = b
		}
		r.mu.Unlock()
	}
	r.mirrorMu.Unlock()
	// The run directory's copy: the newest file the mirror got, unless a write that came here first took it. A
	// final flush with nothing new still waits here for the write before it, and marks the copy done.
	r.fileMu.Lock()
	defer r.fileMu.Unlock()
	if r.dirDone {
		return
	}
	r.dirDone = final
	r.mu.Lock()
	b := r.dirFile
	r.dirFile = nil
	r.mu.Unlock()
	if b == nil {
		return
	}
	if err := writeFileAt(w.dirFD, w.dir, LastRefusalFile, b, false); err != nil {
		w.log.Warn("ledger: last-refusal not written", "run", w.ref.ID, "err", err)
	}
	r.writes++
}

// writeMirror writes b, the reason file, into the mirror when there is one; w.refusal.mirrorMu is held.
func (w *Writer) writeMirror(b []byte) {
	if b == nil || w.mirrorFD == nil {
		return
	}
	if err := writeFileAt(w.mirrorFD, w.mirror, LastRefusalFile, b, false); err != nil {
		w.log.Warn("ledger: last-refusal mirror not written", "run", w.ref.ID, "dir", w.mirror, "err", err)
	}
}

// encodeLastRefusal is last-refusal.json, one of the two files in the run directory that are overwritten (§3; the
// other is the activity sidecar), as the reason file of count refusals with recent the newest; the mirror gets the
// same bytes. It is nil, and logged, when it cannot be encoded. Each refusal no write has decoded yet is decoded here,
// off Append's path, and its fields, cut, are left in its cut. The ring is taken newest first, and once the refusals
// taken pass the file even at their smallest (reason.MinEntryBytes) the older ones are left out: Encode would list
// none of them, so the file is the same and an agent's flood of long targets costs a few decodes a write, not one per
// slot. Advisory, best-effort: the ledger line is authoritative. w.refusal.mirrorMu is held.
func (w *Writer) encodeLastRefusal(count uint64, recent []refusalSlot) []byte {
	first, size := len(recent), 0
	for first > 0 && size <= reason.MaxFileBytes {
		first--
		s := &recent[first]
		if s.cut == nil {
			b := s.payload
			if s.long != nil {
				b = s.long
			}
			var p record.RefusedPayload
			if err := json.Unmarshal(b, &p); err != nil {
				w.log.Warn("ledger: last-refusal payload", "run", w.ref.ID, "seq", s.seq, "err", err)
			}
			p.Reason, p.Rule = s.reason, s.rule // the line's own, as the file has always said
			// Encode's own first cut, which keeps each cut field's length: the file is the one Encode makes of p.
			c := reason.Refusal{Seq: s.seq, TS: s.ts, PID: s.pid, Payload: p}.Cut()
			s.cut = &c
			w.refusal.decoded++
		}
		size += reason.MinEntryBytes(s.cut.Payload)
	}
	rs := make([]reason.Refusal, 0, len(recent)-first)
	for _, s := range recent[first:] {
		rs = append(rs, *s.cut)
	}
	b, err := reason.Encode(w.ref.ID, count, rs)
	if err != nil {
		w.log.Warn("ledger: last-refusal not written", "run", w.ref.ID, "err", err)
		return nil
	}
	return b
}

// MirrorLastRefusal makes every later last-refusal.json be written into dir as well, a directory the run's
// own processes can read (the run's runtime directory): the ledger root is read-denied to the agent
// (agent-contract.md R6a), and a harness inside the run reads the reason of its last refusal from the mirror
// (spec/reason/REASON-CHANNEL.md §2). dir is opened O_NOFOLLOW and must be a directory owned by this
// process's uid, which the launcher made; the Writer holds it until Close.
func (w *Writer) MirrorLastRefusal(dir string) error {
	d, err := sys.Own(unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0))
	if err != nil {
		return &os.PathError{Op: "open", Path: dir, Err: err}
	}
	var st unix.Stat_t
	if err := d.Fstat(&st); err != nil {
		_ = d.Close()
		return &os.PathError{Op: "fstat", Path: dir, Err: err}
	}
	if int(st.Uid) != os.Geteuid() {
		_ = d.Close()
		return &os.PathError{Op: "open", Path: dir, Err: fmt.Errorf("owned by uid %d, not this process's", st.Uid)}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		_ = d.Close()
		return ErrClosed
	}
	w.refusal.mirrorMu.Lock() // a scheduled write may be using the old descriptor
	defer w.refusal.mirrorMu.Unlock()
	_ = w.mirrorFD.Close()
	w.mirrorFD, w.mirror = d, dir
	return nil
}

// Blob stores b content-addressed under blobs/ and returns its sha256 (R11, R14); identical content is stored
// once. ErrClosed after Close (E26).
func (w *Writer) Blob(b []byte) (string, error) {
	if w.isClosed() {
		return "", ErrClosed
	}
	return w.blobs.Put(b)
}

// BlobFrom is the streaming form of Blob for bodies that must not be held in memory (E11); it returns the sha256
// and the number of bytes read.
func (w *Writer) BlobFrom(r io.Reader) (string, int64, error) {
	if w.isClosed() {
		return "", 0, ErrClosed
	}
	return w.blobs.PutStream(r)
}

func (w *Writer) isClosed() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.closed
}

// Close ends the run (§4): it appends run_end with end as payload (its id becomes the head, R13), fsyncs
// events.jsonl and the blobs written since Open, or all of them for a resumed run (the run's one fsync, R6), anchors "<run> <head>" in
// chain.log, then releases the lock and every descriptor, on every error path. An anchor failure after a
// successful fsync is returned as ErrAnchorWrite, distinct from a data error (E29). A second Close returns
// ErrAlreadyClosed and writes nothing. After a torn write (ErrTorn) no run_end is appended, so the run reads
// as lost and gc's sweep ends it.
//
// An orphaned run gets gap what=record why=launcher-lost just before its run_end (orphanedGap): every sweep and reaper
// ends a run here, so they all say its record may stop short.
//
// run_end is encoded first, at the run's revision, before anything is closed. One the Writer refuses (an
// ErrInvalidEvent: an unknown reason, or a stopped_by malformed, on a run_end not stopped, or below the run's
// record minor) is returned with the Writer still open, holding its lock and every descriptor, and nothing
// written but an orphaned run's gap, which the next Close does not repeat, so the caller can Close again with a run_end it can write (without the field) and the run keeps its
// run_end, its fsync and its anchor; refused after closing, the run had none and no later Close could add it.
//
// Last, a root process hands the run directory to the owner of the ledger root holding it (handOverDir,
// record-ledger.md §3), through the descriptor it held for the whole run: only now, with the writer done,
// can the user own the directory without being able to plant a link under a name the writer is about to
// create. A failure there is logged, not returned: the run is complete and durable, and only who may read
// it is left undone.
func (w *Writer) Close(end record.RunEndPayload) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrAlreadyClosed
	}
	var (
		e      *record.Event
		line   []byte
		minor  int
		gapErr error
	)
	if end.Reason == record.RunEndOrphaned {
		gapErr = w.orphanedGap()
	}
	if w.torn == nil && gapErr == nil {
		e = &record.Event{Kind: record.KindRunEnd, Source: record.SourceSupervisor, PID: w.pid, TID: w.tid}
		if err := e.SetPayload(end); err != nil {
			return err
		}
		var err error
		if line, minor, err = w.encode(e); err != nil {
			return err // refused: the Writer stays open for a Close it can write
		}
	}
	w.closed = true
	w.flushRefusal(true) // the latest last-refusal.json, before the run directory is synced and handed over
	err := gapErr
	if err == nil {
		err = w.finish(e, line, minor)
	}
	w.release()
	if w.handOK {
		if herr := handOverDir(w.dirFD, w.dir, w.handTo); herr != nil {
			w.log.Warn("ledger: hand run directory to its ledger root's owner", "run", w.ref.ID, "err", herr)
		}
	}
	w.closeDirs()
	return err
}

// orphanedGap writes gap what=record why=launcher-lost, the line that says an orphaned run's record may stop short of
// what the run did; w.mu must be held. Whoever ends such a run did not write its lines: Append never fsyncs and the
// launcher's queue is in its memory (R6), so a kernel crash or a power cut can take whole trailing lines, and a killed
// launcher can take queued ones. What survives ends on a line boundary as a rule, resume cannot tell it from a run that
// lost nothing, and the chain and the anchor written next verify whatever is there, so without this line the record
// reads as complete. A run with no run_start has no line it may lack and gets no gap; line 0 is run_start's (Verify).
//
// A gap that cannot be written ends Close with no run_end, so the run stays lost and the next sweep tries again: a
// run_end alone is the claim this line is here to take back.
func (w *Writer) orphanedGap() error {
	if w.torn != nil || !w.started || w.orphanGap {
		return nil
	}
	gap := record.Event{Kind: record.KindGap, Source: record.SourceSupervisor, PID: w.pid, TID: w.tid}
	if err := gap.SetPayload(record.GapPayload{What: record.GapRecord, Why: record.GapLauncherLost}); err != nil {
		return err
	}
	if err := w.append(&gap); err != nil {
		return err
	}
	w.orphanGap = true
	return nil
}

// Abandon releases the lock and every descriptor without writing a byte: no run_end, no fsync, no anchor, no
// hand-over. It is the launcher's close for a run that failed before run_start (runtime's unwind), which
// removes the run directory next. Close appended run_end there as the ledger's line 0, so a launcher that died
// before the removal, or a removal that failed, left a directory that reads as ended with no run_start, where
// the empty ledger it should have left reads as a run that never started. A Writer already closed or
// abandoned returns ErrAlreadyClosed.
func (w *Writer) Abandon() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return ErrAlreadyClosed
	}
	w.closed = true
	w.flushRefusal(true) // a refusal still pending (none, before run_start) is written, and no later one
	w.release()
	w.closeDirs()
	return nil
}

// OpenDirPath opens the run directory the Writer holds, O_PATH, through the Writer's own descriptor, never by
// name: a descriptor the caller owns and may hand to another process (the run's reaper, ADR 0020 (2)), which
// then names the directory this Writer writes whatever has been renamed since.
func (w *Writer) OpenDirPath() (*os.File, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil, ErrClosed
	}
	d, err := w.dirFD.Openat(".", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("ledger: open run dir %s O_PATH: %w", w.dir, err)
	}
	f, err := d.Release(w.dir)
	if err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("ledger: open run dir %s O_PATH: %w", w.dir, err)
	}
	return f, nil
}

// WriteLockInfo replaces the lock file's content with b (the launcher's "<pid> <start_boot_ns>" line,
// runtime-launch.md R22), through the descriptor that holds the run's flock: the lock file is written where
// the lock is, never reopened by name. Writing does not disturb the flock, which lives on the open file
// description.
func (w *Writer) WriteLockInfo(b []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.lock == nil {
		return ErrClosed
	}
	if err := w.lock.Truncate(0); err != nil {
		return fmt.Errorf("ledger: write lock info: %w", err)
	}
	if _, err := w.lock.WriteAt(b, 0); err != nil {
		return fmt.Errorf("ledger: write lock info: %w", err)
	}
	return nil
}

// finish writes run_end, e as Close encoded it into line at the run's revision minor, syncs and anchors; w.mu must
// be held.
func (w *Writer) finish(e *record.Event, line []byte, minor int) error {
	if w.torn != nil {
		return fmt.Errorf("ledger: close: %w: %w", ErrTorn, w.torn)
	}
	if err := w.writeLine(e, line, minor); err != nil {
		return err
	}
	w.headID = e.ID
	// R6's one durability barrier, blobs before events. A line that carries blob:"<sha>" is a pointer into
	// blobs/, and no blob is fsynced before this point (store renames onto the content address without one),
	// so syncing events.jsonl first would make every reference of the run durable while the bytes they name
	// are still only page cache: a crash inside Close would leave a ledger that verifies and reads as ended
	// while its captured bodies are gone, with no gap event recording the loss. The reverse direction is safe
	// — a durable blob no line references is an orphan gc removes with the run directory.
	// Both are attempted even when the first fails, so a blob that was removed under us cannot cost
	// events.jsonl its fsync; the first error is what Close reports.
	berr := w.blobs.Sync()
	if berr != nil {
		berr = fmt.Errorf("ledger: fsync blobs: %w", berr)
	}
	if serr := w.events.Sync(); serr != nil {
		return errors.Join(berr, fmt.Errorf("ledger: fsync events: %w", serr))
	}
	// The directory entries too: the run directory holds events.jsonl, contract.yaml and blobs/, and the
	// ledger root holds the run directory. A file's fsync persists a new entry on ext4, XFS and btrfs in
	// practice, and POSIX does not promise it (R6). A failure joins berr, a
	// durability error reported after the anchor like a blob's; a filesystem that cannot fsync a directory
	// (EINVAL) is not one.
	if derr := syncDirs(w.dirFD); derr != nil {
		berr = errors.Join(berr, fmt.Errorf("ledger: fsync run directory: %w", derr))
	}
	// The anchor vouches for the chain, which is now durable whatever a blob's fsync said: withholding it
	// would turn one blob's EIO into a run that reads as unanchored (ErrAnchorMissing) forever.
	if err := w.anchor.Append(w.ref.ID, w.headID); err != nil {
		return errors.Join(berr, fmt.Errorf("%w: %w", ErrAnchorWrite, err))
	}
	return berr
}

// fsyncDir is the fsync a directory gets; a variable so a test can see which directories Close syncs.
var fsyncDir = func(d *sys.FD) error { return d.Fsync() }

// syncDirs fsyncs the run directory open at d and its parent, the ledger root it is in now. The parent's
// descriptor is strict: fsync first, then a close whose error is reported.
func syncDirs(d *sys.FD) error {
	ignore := func(err error) error {
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EROFS) {
			return nil
		}
		return err
	}
	err := ignore(fsyncDir(d))
	p, perr := sys.Strict(d.Openat("..", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if perr != nil {
		return errors.Join(err, perr)
	}
	return errors.Join(err, ignore(fsyncDir(p)), p.Close())
}

// release closes the events file and the lock (flock(LOCK_UN) then close). Errors here are logged: the data
// is already durable or already reported.
func (w *Writer) release() {
	if w.events != nil {
		if err := w.events.Close(); err != nil {
			w.log.Warn("ledger: close events", "run", w.ref.ID, "err", err)
		}
		w.events = nil
	}
	if w.lock != nil {
		if err := sys.Flock(w.lock, unix.LOCK_UN); err != nil {
			w.log.Warn("ledger: unlock", "run", w.ref.ID, "err", err)
		}
		if err := w.lock.Close(); err != nil {
			w.log.Warn("ledger: close lock", "run", w.ref.ID, "err", err)
		}
		w.lock = nil
	}
}

// closeDirs closes the run, blobs and mirror directory descriptors, after everything that names a file
// through them is done. A use after this is sys.ErrClosed, never a number the process has reused.
func (w *Writer) closeDirs() {
	if w.blobs != nil {
		w.blobs.close()
	}
	if err := w.dirFD.Close(); err != nil {
		w.log.Warn("ledger: close run directory", "run", w.ref.ID, "err", err)
	}
	_ = w.mirrorFD.Close()
}

// writeFileAt writes b to name in the directory open at at, 0600, through a temp file created O_EXCL and
// renamed onto name, so a reader never sees a partial file and whatever already sits at name — a link
// included — is replaced rather than written through. durable fsyncs the temp file before the rename, so a
// crash cannot leave name empty: contract.yaml's copy is what drift and the sweep of an early-killed run
// read. last-refusal.json is a hint to the agent rewritten after refusals (lastRefusal), and is not durable. A temp file
// a crash leaves behind is removed by the next Open (sweepRunTemps).
func writeFileAt(at *sys.FD, dir, name string, b []byte, durable bool) error {
	tmp, tname, err := createTempAt(at, dir, "."+name+".")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		_ = unlinkAt(at, tname)
		return err
	}
	if durable {
		if err := tmp.Sync(); err != nil {
			_ = tmp.Close()
			_ = unlinkAt(at, tname)
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		_ = unlinkAt(at, tname)
		return err
	}
	if err := at.Borrow(func(n int) error { return unix.Renameat(n, tname, n, name) }); err != nil {
		_ = unlinkAt(at, tname)
		return &os.LinkError{Op: "rename", Old: filepath.Join(dir, tname), New: filepath.Join(dir, name), Err: err}
	}
	return nil
}
