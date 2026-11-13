// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"math"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"github.com/attention-span-ai/tego/pkg/spec/record/chaincheck"
)

// Reader reads one run directory without taking its lock; any number may open a run concurrently with its
// live Writer (§3). It owns one file descriptor, released by Close, and a second, its run directory, when it
// was opened under a ledger root a GC or SweepLive pass holds (openReaderIn).
type Reader struct {
	dir string
	f   *os.File
	// at is the run directory a reader opened under a held root resolves the lock through, instead of dir,
	// which then only names the run in errors and reports; nil for a reader over a path.
	at    *sys.FD
	blobs BlobRepository
	// skipNewer is SkipNewerVersions; newer is the most newer-version lines one pass has skipped.
	skipNewer bool
	newer     int
	scanSize  int // the read buffer of a line scan; 0 is scanLines' default
	// binder is the Binder Bind attached, which the next pass of Lines takes and feeds.
	binder *Binder
}

// SkipNewerVersions makes Iter and Entries pass over a line whose record version is newer than this binary
// reads (record.ErrNewerVersion) instead of stopping at it as corrupt, and count it (SkippedNewer). The views
// (events, drift, measure, status) ask for it and warn once with the count (limits-check-doctor-cli.md §6
// case 20); v 0, a missing or non-integer v and a malformed line still stop iteration as ErrCorruptLedger.
// Verify is unaffected: it checks such a line's link in the chain (record.Chain.AddNewer).
func (r *Reader) SkipNewerVersions() { r.skipNewer = true }

// SkippedNewer is how many newer-version lines a pass over the ledger skipped: the largest count any one pass
// of Iter or Entries has reached, so a caller that reads the ledger twice does not count a line twice.
func (r *Reader) SkippedNewer() int { return r.newer }

// Entry is one complete line as stored and its decoded event.
type Entry struct {
	Line  []byte
	Event *record.Event
}

// OpenReader opens dir/events.jsonl read-only. os.ErrNotExist when the ledger is absent; a directory without
// run_start yet reads fine and yields nothing (E14).
func OpenReader(dir string) (*Reader, error) {
	f, err := openRegular(filepath.Join(dir, EventsFile))
	if err != nil {
		return nil, fmt.Errorf("ledger: open events: %w", err)
	}
	return &Reader{dir: dir, f: f, blobs: NewBlobRepository(dir)}, nil
}

// OpenReaderAt is OpenReader for the run directory dir lends, which stays the caller's: the Reader reads under a
// descriptor of its own reopened from it, and path, which names the directory in errors, is never resolved. Like
// openReaderIn it reads no blobs. internal/runtime reads a swept run's run_start through it (WithSweepHook).
func OpenReaderAt(dir sys.Lender, path string) (*Reader, error) {
	if dir == nil {
		return nil, fmt.Errorf("ledger: open events: %s: %w", path, sys.ErrClosed)
	}
	d, err := reopenDir(dir)
	if err != nil {
		return nil, fmt.Errorf("ledger: open events: %w", &os.PathError{Op: "open", Path: path, Err: err})
	}
	return openReaderIn(d, path)
}

// openReaderIn is OpenReader for the run directory open at d, which the Reader then owns (Close closes it); dir
// is what its errors and reports name. Its lock probes are made under d too. It reads no blobs: nothing a GC
// pass asks of a run reads one, and a blob path would resolve outside the directory the pass holds.
func openReaderIn(d *sys.FD, dir string) (*Reader, error) {
	f, err := openRegularAt(d, EventsFile, filepath.Join(dir, EventsFile))
	if err != nil {
		_ = d.Close()
		return nil, fmt.Errorf("ledger: open events: %w", err)
	}
	return &Reader{dir: dir, f: f, at: d, blobs: &blobStore{dir: filepath.Join(dir, BlobsDir), closed: true}}, nil
}

// Close releases the descriptor, and the run directory's when the Reader holds one.
func (r *Reader) Close() error {
	err := r.f.Close()
	if r.at != nil {
		err = errors.Join(err, r.at.Close())
	}
	return err
}

// lockFree probes the run's lock (lockFree), under the run directory the Reader holds when it holds one.
func (r *Reader) lockFree() (bool, error) {
	if r.at != nil {
		return lockFreeAt(r.at, filepath.Join(r.dir, LockFile))
	}
	return lockFree(filepath.Join(r.dir, LockFile))
}

// openRegular opens path read-only for a reader: O_NONBLOCK so a FIFO planted under the name cannot hold the
// open (every `tego run` reads the retained runs' state before it starts, and gc and status do too),
// O_NOFOLLOW so a link is refused, and anything but a regular file is refused after the open. The Writer's
// own opens already hold to this.
func openRegular(path string) (*os.File, error) {
	fd, err := sys.Own(unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0))
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return regularFile(fd, path)
}

// openRegularAt is openRegular for name under the directory open at at (a Writer's own); path is what an
// error names.
func openRegularAt(at *sys.FD, name, path string) (*os.File, error) {
	fd, err := at.Openat(name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return regularFile(fd, path)
}

// regularFile hands fd to an *os.File named path when it is open on a regular file, and closes it otherwise.
func regularFile(fd *sys.FD, path string) (*os.File, error) {
	defer func() { _ = fd.Close() }() // a no-op once Release has handed the number on
	var st unix.Stat_t
	if err := fd.Fstat(&st); err != nil {
		return nil, &os.PathError{Op: "fstat", Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, &os.PathError{Op: "open", Path: path, Err: errNotRegular}
	}
	f, err := fd.Release(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return f, nil
}

// errNotRegular is openRegular's refusal of a FIFO, a device, a socket or a directory.
var errNotRegular = errors.New("not a regular file")

// Dir returns the run directory.
func (r *Reader) Dir() string { return r.dir }

// Blob opens a blob of this run for reading (E16: not re-verified).
func (r *Reader) Blob(sha string) (io.ReadCloser, error) { return r.blobs.Get(sha) }

// rawLine is one line of a file as scanned: data without the "\n", and whether that "\n" was present.
type rawLine struct {
	data       []byte
	terminated bool
}

// MaxLineBytes bounds one line of events.jsonl as a reader takes it (chaincheck.MaxLineBytes, CHAIN.md §2): a
// longer line is a corrupt ledger.
const MaxLineBytes = chaincheck.MaxLineBytes

// scanLines yields every line of f from byte 0 (chaincheck.ScanLines, the framing the chain check reads), as this
// package's rawLine. The final line is yielded with terminated=false when it lacks "\n"; the caller applies the
// torn-line rule. Read errors, and a line past MaxLineBytes, are yielded once and end the sequence.
func scanLines(f io.ReaderAt) iter.Seq2[rawLine, error] { return scanLinesSized(f, 64<<10) }

// scanLinesSized is scanLines with a read buffer of size bytes; a caller that wants a line or two asks for a
// small one (a line longer than the buffer is still read whole).
func scanLinesSized(f io.ReaderAt, size int) iter.Seq2[rawLine, error] {
	return func(yield func(rawLine, error) bool) {
		for l, err := range chaincheck.ScanLinesSized(f, size) {
			if !yield(rawLine{data: l.Data, terminated: l.Terminated}, err) {
				return
			}
		}
	}
}

func (r *Reader) scan() iter.Seq2[rawLine, error] {
	if r.scanSize > 0 {
		return scanLinesSized(r.f, r.scanSize)
	}
	return scanLines(r.f)
}

// errLineTooLong is readLine's refusal of a line past MaxLineBytes.
var errLineTooLong = chaincheck.ErrLineTooLong

// readLine is bufio.Reader.ReadBytes('\n') that gives up past MaxLineBytes instead of growing without bound
// (chaincheck.ReadLine).
func readLine(br *bufio.Reader) ([]byte, error) { return chaincheck.ReadLine(br) }

// Lines yields the stored bytes of every complete line, without the terminator, in order: what `tego events
// --json` prints verbatim. Once the first top-level JSON value lexically closes, the entire final chunk is
// yielded, including any suffix. Only a chunk with no closed value is torn and ends iteration cleanly (§4, E6, E8),
// unless the line before it is run_end. A torn tail is what a writer that died mid-write(2) leaves, and a writer
// that wrote run_end is not that writer, so bytes after it are
// ErrCorruptLedger naming their offset, as Verify reports them: a tail of NUL bytes after run_end was read as
// a clean end by events, drift and measure while `events --verify` refused it, and a `garbage\n` line in the
// same place already failed all four. Each call rescans from byte 0; there is no follow mode.
func (r *Reader) Lines() iter.Seq2[[]byte, error] {
	return func(yield func([]byte, error) bool) {
		bind := r.takeBinder() // nil unless Bind asked for this pass
		var prev []byte        // the last complete line, decoded only when a torn tail follows it
		offset, n := int64(0), 0
		for l, err := range r.scan() {
			if err != nil {
				bind.fail(err)
				yield(nil, err)
				return
			}
			n++
			if !l.terminated {
				if !wholeLine(l.data) {
					bind.tornTail(l.data)
					if afterRunEnd(prev) {
						yield(nil, fmt.Errorf("%w %d: %d bytes at byte offset %d after run_end are not a record",
							ErrCorruptLedger, n, len(l.data), offset))
						return
					}
					bind.end()
					return // torn tail: not a line
				}
			}
			bind.line(l)
			if !yield(l.data, nil) {
				return
			}
			prev = l.data
			offset += int64(len(l.data)) + 1
		}
		bind.end()
	}
}

// Size is the length of the events file now: an offset LinesFrom can later read on from.
func (r *Reader) Size() (int64, error) {
	st, err := r.f.Stat()
	if err != nil {
		return 0, fmt.Errorf("ledger: stat events: %w", err)
	}
	return st.Size(), nil
}

// LinesFrom is Lines for the lines that begin at byte off or later, for a caller waiting for a line appended after it
// took Size (`tego lift` waiting for its launcher's answer), so a weeks-long run's ledger is not read from byte 0 on
// every poll. A line that off cuts is skipped, and so is a torn tail; there is no chain check and no run_end rule, so
// a caller decodes each line and trusts none for more than finding it. off 0 or less is Lines.
func (r *Reader) LinesFrom(off int64) iter.Seq2[[]byte, error] {
	if off <= 0 {
		return r.Lines()
	}
	return func(yield func([]byte, error) bool) {
		// Start one byte early: if that byte is the "\n" ending the line before off, the first line read is empty and
		// off begins a line; otherwise the first line read is the rest of the line off cuts. Either way it is dropped.
		br := bufio.NewReaderSize(io.NewSectionReader(r.f, off-1, math.MaxInt64), 64<<10)
		for first := true; ; first = false {
			data, err := readLine(br)
			if errors.Is(err, errLineTooLong) {
				yield(nil, fmt.Errorf("%w: a line after byte offset %d is longer than %d bytes", ErrCorruptLedger, off, MaxLineBytes))
				return
			}
			if err != nil && !errors.Is(err, io.EOF) {
				yield(nil, fmt.Errorf("ledger: read events: %w", err))
				return
			}
			if len(data) == 0 || data[len(data)-1] != '\n' {
				return // the end, or a torn tail
			}
			if first {
				continue
			}
			if !yield(data[:len(data)-1], nil) {
				return
			}
		}
	}
}

// wholeLine reports whether a top-level JSON value has lexically closed in the final chunk (E8).
// The entire chunk remains a record line, including any suffix; validation belongs to the caller
// (chaincheck.WholeLine).
func wholeLine(data []byte) bool { return chaincheck.WholeLine(data) }

// afterRunEnd reports whether line is a run_end record.
func afterRunEnd(line []byte) bool {
	if line == nil {
		return false
	}
	kind, ok := lineKind(line)
	return ok && kind == record.KindRunEnd
}

// lineKind reads the kind of a line: Decode's for a line of this version, the link's for a newer binary's
// (record.LinkOf), the same reading Verify counts a newer run_end by. ok is false for a line that is neither.
func lineKind(line []byte) (kind record.Kind, ok bool) {
	e, err := record.Decode(line)
	if err == nil {
		return e.Kind, true
	}
	if !errors.Is(err, record.ErrNewerVersion) {
		return "", false
	}
	l, lerr := record.LinkOf(line)
	if lerr != nil {
		return "", false
	}
	return record.Kind(l.Kind), true
}

// Iter yields every complete line decoded, in order. A line that fails to decode anywhere but the torn tail
// yields ErrCorruptLedger (wrapping the decode error, ErrUnsupportedVersion included) and stops, except a
// newer-version line once SkipNewerVersions is set, which is skipped and counted; iteration applies Decode
// only, so a validation-level oddity in an old line never hides the rest of the run.
func (r *Reader) Iter() iter.Seq2[*record.Event, error] {
	return func(yield func(*record.Event, error) bool) {
		for en, err := range r.Entries() {
			if !yield(en.Event, err) || err != nil {
				return
			}
		}
	}
}

// Entries is Iter with each event's stored line beside it, for a caller that writes the bytes the chain
// hashed (events --json, I8).
func (r *Reader) Entries() iter.Seq2[Entry, error] {
	return func(yield func(Entry, error) bool) {
		n := 0 // lines read, so the line in hand is n, counted from 1 as an editor and `events --json` count them
		skipped := 0
		defer func() { r.newer = max(r.newer, skipped) }()
		offset := int64(0)
		for line, err := range r.Lines() {
			if err != nil {
				yield(Entry{}, err)
				return
			}
			n++
			e, err := record.Decode(line)
			if err != nil && r.skipNewer && errors.Is(err, record.ErrNewerVersion) {
				skipped++
				offset += int64(len(line)) + 1
				continue
			}
			if err != nil {
				yield(Entry{}, fmt.Errorf("%w %d: at byte offset %d: %w", ErrCorruptLedger, n, offset, err))
				return
			}
			offset += int64(len(line)) + 1
			if !yield(Entry{Line: line, Event: e}, nil) {
				return
			}
		}
	}
}

// VerifyReport is what Verify found (chaincheck.Report). Its Run is the name the path that reached the
// directory gives it (RunDirPath): the last component of the path made absolute ("." being the working directory
// as $PWD names it) when that is a run id, even a link to another run's directory; else, for a link such as
// ~/latest, the first run id its link chain names; else the id the ledger's first line names.
type VerifyReport = chaincheck.Report

// Verify walks the run's chain (I3, I4, R2) and validates every event (record.Validate). With a non-nil
// anchor it also checks the ledger against chain.log. ctx is checked per line so a large ledger can be
// interrupted. The first failure is returned with the line number; every failure that is about the
// ledger's content, rather than about reading it, wraps ErrUnverified.
//
// The anchor is consulted whenever it has a line for the run, not only when the ledger ends in run_end.
// chain.log is written once, at Close, with the run_end line's id, so an anchored head the ledger does not
// end with is a ledger that lost lines after it was closed — a truncation that removes run_end and the
// events before it leaves a chain that is internally intact and reads as lost, and only the anchor can
// tell it from a launcher that died. An ended run with no anchor line is ErrAnchorMissing (E29); a run
// that has not ended has none yet and is not an error.
//
// Every line must belong to the run being verified (ErrRunMismatch), and the anchor is looked up under
// that run, never under an id the ledger supplies: when the directory is named by a run id, that id. A
// ledger another anchored run wrote is a complete, correctly anchored chain in its own right, so copying
// it over this run's events.jsonl would otherwise verify — against the other run's anchor line — and
// this run's own anchor line would never be read. The run's id is the name the path gives the directory
// (RunDirPath), never the name a link in its last component resolves to: runs/<A> replaced by a link to
// runs/<B> is A's record gone, and taking B's name verified B's anchored ledger as if it were A's. The path
// is made absolute first, and one whose last component is still no run id is followed through its links:
// `cd <run> && tego events . --verify` named no run by its last component, ".", and fell back to the id
// the swapped ledger claimed.
func (r *Reader) Verify(ctx context.Context, anchor ChainAnchor) (VerifyReport, error) {
	return r.verify(ctx, anchor, false, true)
}

// verify is Verify; rescanned is set on the one rescan a mismatch against a run still being written earns, and
// validate holds each line to its schema. The check is chaincheck.Walk's: this method frames the file, reads the
// anchor and waits for a launcher inside Close, the parts that touch the host.
func (r *Reader) verify(ctx context.Context, anchor ChainAnchor, rescanned, validate bool) (VerifyReport, error) {
	w := chaincheck.NewWalk(runDirName(r.dir), validate)
	for l, err := range chaincheck.ScanLines(r.f) {
		if err == nil {
			if cerr := ctx.Err(); cerr != nil {
				return w.Report(), fmt.Errorf("ledger: verify: %w", cerr)
			}
		}
		stop, err := w.Step(l, err)
		if err != nil {
			return w.Report(), err
		}
		if stop {
			break
		}
	}
	if err := w.Finish(); err != nil {
		return w.Report(), err
	}
	if anchor == nil {
		return w.Report(), nil
	}
	run, err := w.AnchorRun()
	if err != nil {
		return w.Report(), err
	}
	head, ok, err := anchor.Head(run)
	next, err := w.Anchor(chaincheck.AnchorHead{Head: head, OK: ok, Err: err}, rescanned)
	switch {
	case err != nil:
		return w.Report(), err
	case next == chaincheck.AnchorRescan:
		return r.verify(ctx, anchor, true, validate)
	case next == chaincheck.AnchorAwait:
		// A held lock on an ended run is a launcher still inside Close: it appends run_end, fsyncs, and anchors
		// last, lock held throughout. That run is not missing its anchor yet.
		// awaitAnchor's ErrRunClosing, a cancelled context or a read error is returned as it is (AnchorAfterWait
		// makes only a malformed chain.log a finding).
		head, ok, err = r.awaitAnchor(ctx, anchor, run)
		err = w.AnchorAfterWait(chaincheck.AnchorHead{Head: head, OK: ok, Err: err})
		return w.Report(), err
	}
	return w.Report(), nil
}

// closeWait bounds how long Verify waits for a launcher still inside Close to write the anchor line.
var closeWait = 2 * time.Second

// awaitAnchor re-reads run's anchor line while the run's lock is held, up to closeWait. A lock still held
// when the wait ends is ErrRunClosing, not a finding; a free lock gets one last read, since the launcher
// may have anchored between the read and the probe.
func (r *Reader) awaitAnchor(ctx context.Context, anchor ChainAnchor, run string) (string, bool, error) {
	deadline := time.Now().Add(closeWait)
	for {
		free, err := r.lockFree()
		if err != nil {
			return "", false, err
		}
		head, ok, err := anchor.Head(run)
		if err != nil || ok || free {
			return head, ok, err
		}
		if !time.Now().Before(deadline) {
			return "", false, fmt.Errorf("%w: %s", ErrRunClosing, run)
		}
		select {
		case <-ctx.Done():
			return "", false, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// VerifyRunDir is Verify over the run directory dir, reaching the one case a Reader cannot: a ledger that
// is gone. When events.jsonl does not exist and dir is named by a run id the anchor holds a line for, that
// is a finding (ErrUnverified, ErrLedgerMissing) — chain.log says the run was recorded and closed, so a
// deleted ledger, or a deleted run directory, is the record's loss, not a run that never existed. Without
// an anchor line the not-exist error is returned as it is: nothing vouches that the run was ever recorded.
func VerifyRunDir(ctx context.Context, dir string, anchor ChainAnchor) (VerifyReport, error) {
	return verifyRunDir(ctx, dir, anchor, true)
}

func verifyRunDir(ctx context.Context, dir string, anchor ChainAnchor, validate bool) (VerifyReport, error) {
	r, err := OpenReader(dir)
	if err == nil {
		defer func() { _ = r.Close() }()
		return r.verify(ctx, anchor, false, validate)
	}
	run := runDirName(dir)
	missing := errors.Is(err, os.ErrNotExist)
	// A ledger swapped for a link, a FIFO or a directory is refused by OpenReader on purpose: with an anchor line
	// for the run that is the record's substitution, a finding, not an environment failure (E26).
	swapped := errors.Is(err, unix.ELOOP) || errors.Is(err, errNotRegular)
	if !(missing || swapped) || anchor == nil || !IsRunID(run) {
		return VerifyReport{}, err
	}
	head, ok, aerr := anchor.Head(run)
	return chaincheck.MissingLedger(run, filepath.Join(dir, EventsFile), chaincheck.AnchorHead{Head: head, OK: ok, Err: aerr},
		true, swapped, err)
}

// maxRunDirLinks bounds the links RunDirPath follows looking for a run id, as the kernel bounds the links
// one path may cross (MAXSYMLINKS).
const maxRunDirLinks = 40

// RunDirPath is the path that names the run directory dir, whose last component is the run R29 verifies
// (record-ledger.md §4): dir made absolute and lexically cleaned, as OpenReader joins it, and returned as
// it is whenever that last component is a run id. A relative dir is taken from the working directory as
// os.Getwd names it — $PWD when $PWD is that directory, so after a shell's cd through a link, "." ends in
// the link's name. The link a run id names is never resolved: a run directory replaced by a link to
// another run's leaves the named run's record gone, and resolving the link would verify the other run's
// anchored ledger in its place. A last component that is no run id (a link such as ~/latest) is followed
// one link at a time, and the first name in the chain that is a run id is the run; a relative link
// target is read from the directory holding the link, as the kernel reads it. A chain that reaches no run
// id gives the directory's resolved path: a copy under another name keeps that name, and for it alone
// Verify falls back to the id on the ledger's first line.
func RunDirPath(dir string) string {
	p, err := filepath.Abs(dir)
	if err != nil {
		p = filepath.Clean(dir)
	}
	start := p
	for range maxRunDirLinks {
		if IsRunID(filepath.Base(p)) {
			return p
		}
		target, err := os.Readlink(p)
		if err != nil {
			break
		}
		if !filepath.IsAbs(target) {
			parent := filepath.Dir(p)
			if real, err := filepath.EvalSymlinks(parent); err == nil {
				parent = real
			}
			target = filepath.Join(parent, target)
		}
		p = filepath.Clean(target)
	}
	if real, err := filepath.EvalSymlinks(start); err == nil {
		return real
	}
	return p
}

// runDirName is the name of the run directory dir (RunDirPath).
func runDirName(dir string) string { return filepath.Base(RunDirPath(dir)) }

// RunState is what a run directory says about its run, derived from the file and the lock alone (I7).
type RunState string

// Run states (§2.3). StateEmpty is the fourth, for a directory with no complete run_start: nothing to sweep,
// eligible for retention like any other.
const (
	StateRunning RunState = "running" // run_start present, no run_end, lock held
	StateEnded   RunState = "ended"   // run_end present
	StateLost    RunState = "lost"    // lines present, no run_end, lock free (never written by a reader)
	StateEmpty   RunState = "empty"   // no complete line at all
)

// State reports the run's state without blocking: run_end on the last complete line is ended; else a held lock
// is running; else complete lines mean lost and none mean empty. A missing lock file counts as free (E27).
//
// Only the tail of events.jsonl is read, never the whole file: §4's definition needs two facts — whether a
// complete line exists and what the last one is — and gc asks for them once per run directory on every
// `tego run` (sweepBeforeRun), where a full decode of every retained ledger would be paid before the agent is
// even launched. One consequence is deliberate: damage before the last complete line no longer makes State an
// error, because a run's state is what run_end and the lock say (I7) and reporting chain damage is Verify's
// job, not the state probe's. A last complete line that does not decode is still ErrCorruptLedger — the state
// itself cannot be read then.
func (r *Reader) State() (RunState, error) {
	// The lock is probed before the tail is read: a Writer appends run_end and only then releases the lock, so a
	// lock seen free means the tail read below is final. The other order could read a tail with no run_end, then
	// find the lock free because Close ran in between, and call a cleanly ended run lost.
	free, err := r.lockFree()
	if err != nil {
		return "", err
	}
	return r.stateWithLockFree(free)
}

// stateWithLockFree reads the ledger after the caller established the lock's state. GC passes true while it
// owns the removal lock: probing that lock again would mistake GC itself for a live Writer.
func (r *Reader) stateWithLockFree(free bool) (RunState, error) {
	st, err := r.f.Stat()
	if err != nil {
		return "", fmt.Errorf("ledger: stat events: %w", err)
	}
	line, present, err := lastLine(r.f, st.Size())
	if err != nil {
		return "", err
	}
	if present {
		kind, ok := lineKind(line)
		if !ok {
			_, derr := record.Decode(line)
			if derr == nil {
				derr = errors.New("chain fields do not read")
			}
			return "", fmt.Errorf("%w: last line: %w", ErrCorruptLedger, derr)
		}
		if kind == record.KindRunEnd {
			return StateEnded, nil
		}
	}
	switch {
	case !free:
		return StateRunning, nil
	case present:
		return StateLost, nil
	}
	return StateEmpty, nil
}

// tailWindow is how much of the end of events.jsonl lastLine reads first. A run_end line is well under 1 KiB, so
// one small window finds it for almost every run, and lastLine widens (doubling) for the lines that are longer.
const tailWindow = 4 << 10

// maxTailWindow is the widest tail lastLine reads: a line of MaxLineBytes-1 bytes (the longest Append accepts),
// its own "\n", and the "\n" that ends the line before it. A torn tail after that line widens the bound by its
// own length (lastLine).
const maxTailWindow = MaxLineBytes + 1

// lastLine returns the bytes of the last complete line of an events.jsonl of size bytes, reading only the end
// of the file. "Complete" is Lines' rule (§4, E6, E8): every terminated line, plus the entire unterminated final
// chunk once its first top-level JSON value lexically closes, including any suffix. A chunk with no closed value
// is torn and was never a line. present is false when the file holds no complete line at all. The window doubles
// until it holds a line boundary or covers the whole file, so a line longer than tailWindow is found rather than missed.
func lastLine(f io.ReaderAt, size int64) (line []byte, present bool, err error) {
	if size <= 0 {
		return nil, false, nil
	}
	var prev int64                // the window the last pass read
	limit := int64(maxTailWindow) // the widest window: a torn tail widens it by its own length
	for window := int64(tailWindow); ; window *= 2 {
		if window > size {
			window = size
		}
		if window > limit {
			if prev >= limit {
				// No line boundary within a line's bound of the end: the last line is longer than any the Writer
				// makes, and widening further would read the whole file into memory (E16).
				return nil, false, fmt.Errorf("%w: last line longer than %d bytes", ErrCorruptLedger, MaxLineBytes)
			}
			window = limit // the last widening stops at the bound rather than doubling past it
		}
		prev = window
		off := size - window
		buf := make([]byte, window)
		// Positional read: a concurrent Writer only appends, so bytes before size never change (E19).
		n, err := f.ReadAt(buf, off)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, false, fmt.Errorf("ledger: read events tail: %w", err)
		}
		buf = buf[:n]
		if len(buf) == 0 {
			return nil, false, nil // the file shrank under us; a later call re-stats
		}
		whole := off == 0 // the window covers the file, so a missing "\n" means the file holds none
		var cut []byte    // the complete-line region, the last line's terminator already removed
		if buf[len(buf)-1] == '\n' {
			cut = buf[:len(buf)-1]
		} else {
			i := bytes.LastIndexByte(buf, '\n')
			if i < 0 && !whole {
				continue // no line boundary in the window: widen
			}
			if wholeLine(buf[i+1:]) {
				return buf[i+1:], true, nil // unterminated but whole: still a line (E8)
			}
			if i < 0 {
				return nil, false, nil // the whole file is one torn line: no complete line
			}
			cut = buf[:i]
			// The torn tail was never a line and the last line lies before it: room for both.
			limit = int64(len(buf)-i-1) + maxTailWindow
		}
		if j := bytes.LastIndexByte(cut, '\n'); j >= 0 {
			return cut[j+1:], true, nil
		}
		if whole {
			return cut, true, nil
		}
	}
}

// Lost reports whether the run is StateLost: it started, never ended, and nobody holds its lock. Views never
// show it as done.
func (r *Reader) Lost() (bool, error) {
	s, err := r.State()
	return s == StateLost, err
}

// LockHeld reports whether a live Writer holds the run's lock, by the one probe every reader shares (status,
// the sweeps, State): the lock is opened as openRegular opens it (a FIFO or a link planted under the name
// cannot hang or redirect the probe), then flock(LOCK_SH|LOCK_NB) on a private descriptor, released at once.
// A run directory with no lock file counts as free (E27).
func LockHeld(dir string) (bool, error) {
	free, err := lockFree(filepath.Join(dir, LockFile))
	return !free, err
}

// OpenRegular is the hardened open of a run's file for reading: O_NONBLOCK, O_NOFOLLOW, regular files only. It
// is exported for the lock file's one other reader, runtime.ProbeLock, which must read the lock line and probe
// with its own flock mode on the same descriptor.
func OpenRegular(path string) (*os.File, error) { return openRegular(path) }

// OpenRegularAt is OpenRegular for name under the run directory dir lends, which stays the caller's; path is what
// an error names. runtime's lock probe and launcher check use it for the run directory a sweep hook was lent
// (WithSweepHook).
func OpenRegularAt(dir sys.Lender, name, path string) (*os.File, error) {
	if dir == nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: sys.ErrClosed}
	}
	var fd *sys.FD
	err := dir.Borrow(func(n int) error {
		var err error
		fd, err = sys.Own(unix.Openat(n, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0))
		return err
	})
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return regularFile(fd, path)
}

// lockFree probes the lock with flock(LOCK_SH|LOCK_NB) on a private descriptor and releases it at once; it
// never blocks. A live Writer's LOCK_EX makes it EWOULDBLOCK.
func lockFree(path string) (bool, error) {
	f, err := openRegular(path)
	return probeLock(f, err)
}

// lockFreeAt is lockFree for the lock file of the run directory open at d; path is what an error names.
func lockFreeAt(d *sys.FD, path string) (bool, error) {
	f, err := openRegularAt(d, LockFile, path)
	return probeLock(f, err)
}

// probeLock is lockFree's probe of the lock file f, whose open answered err.
func probeLock(f *os.File, err error) (bool, error) {
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, fmt.Errorf("ledger: open lock: %w", err)
	}
	defer func() { _ = f.Close() }()
	if err := sys.Flock(f, unix.LOCK_SH|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return false, nil
		}
		return false, fmt.Errorf("ledger: probe lock: %w", err)
	}
	return true, sys.Flock(f, unix.LOCK_UN)
}
