// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/check/askpair"
	"github.com/attention-span-ai/tego/internal/check/mirror"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A run's events file is append-only, so the read model decodes each line once: a runState keeps what it decoded,
// the run's summary built from it, and the byte offset it reached, and a later request reads only the lines appended
// since. A page refresh then costs the new lines, not the whole ledger. A file whose device or inode changed, that got
// shorter, or that changed without growing (rewritten in place) is read again from the start. Only complete lines are
// taken; a line still being written waits for its newline. An unchanged file (same device, inode, size, mtime and
// ctime as the last look) is not even opened.

// fileID is what says an events file is still the one a runState read: its identity, size, mtime and ctime. The
// ctime is there because the mtime alone is the writer's to set: a line rewritten in place at the same length, its
// mtime put back with utimes (`touch -r`), kept the size and mtime, so the read model served the old lines and the
// chain verdict cache (chainKey, keyed on this) kept "Chain verified" for its ten minutes while the line page showed
// the edited bytes (r10 BR-2). Every change to the inode moves its ctime, and no system call sets it back. The chain
// anchor's view stamps chain.log by it too (anchorview.go).
type fileID struct {
	dev, ino uint64
	size     int64
	mtime    int64
	ctime    int64
}

func idOf(fi os.FileInfo) fileID {
	id := fileID{size: fi.Size(), mtime: fi.ModTime().UnixNano()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		id.dev, id.ino = uint64(st.Dev), st.Ino //nolint:unconvert // Dev's type differs between platforms
		id.ctime = st.Ctim.Nano()
	}
	if coarseStamps != nil {
		id = coarseStamps(id)
	}
	return id
}

// coarseStamps, set by tests alone, stands in for a kernel whose clock ticks too slowly to tell two writes apart (before
// 6.13: the Debian 13 guest's 6.12 gives two writes within one tick the same mtime and ctime).
var coarseStamps func(fileID) fileID

// racySlack is how long after a file's last change its stamps are not believed to tell the next change: a coarse
// clock gives a write the time of the last tick (10 ms at HZ=100; a filesystem with 1 s or 2 s stamps, ext3 or FAT,
// longer), so a rewrite at the same size within the slack of what was read keeps size, mtime and ctime. Git's racily
// clean entries, and the chain anchor's view (anchorview.go), meet the same hole.
const racySlack = 2 * time.Second

// racyStamp reports whether a file with stamps id, looked at at now, may still change without showing in them: its
// mtime or ctime lies within racySlack of now (or after it: a clock that is not this machine's).
func racyStamp(id fileID, now time.Time) bool {
	n := now.UnixNano()
	return n-id.mtime < int64(racySlack) || n-id.ctime < int64(racySlack)
}

// rewritten reports whether now, a later look at the events file a runState read as was (its complete lines ending
// at off), is no longer that file with lines appended: another file (device or inode), shorter than what was read, or
// changed without growing (another mtime or ctime at the same size or less: bytes rewritten in place). Its lines are
// then read again from the start; only an append leaves the lines read before as they were.
func rewritten(now, was fileID, off int64) bool {
	return now.dev != was.dev || now.ino != was.ino || now.size < off || now != was && now.size <= was.size
}

// sameFile reports whether now is the file st read, as far as its stamps can tell: not when st looked at it too soon
// after its last change for them to tell (racy).
func (st *runState) sameFile(now fileID) bool { return now == st.file && !st.racy }

// tailSum is the digest of the last tailStamp bytes of f's first off bytes (all of them when fewer): what a racy file
// is held to at its next look, since an events file is only ever appended to and a rewrite shows in its end first.
func tailSum(f *os.File, off int64) ([sha256.Size]byte, bool) {
	n := min(off, tailStamp)
	buf := make([]byte, n)
	if m, err := f.ReadAt(buf, off-n); (err != nil && !errors.Is(err, io.EOF)) || int64(m) != n {
		return [sha256.Size]byte{}, false
	}
	return sha256.Sum256(buf), true
}

// runState is one run's incremental read: the summary being built (b, whose Events grow), the asks still open, and
// the published, immutable Run (pub) requests share. Every field is guarded by the Store's mutex, except while reading
// is set: then the request that set it owns the builder fields (everything Store.read touches) without the mutex, and
// no one else reads or writes them until it closes reading under the mutex (store.go, bring). pub, once set, is never
// changed, only replaced, and only under the mutex.
type runState struct {
	store *Store
	// reading is non-nil while a request reads this run outside the Store's mutex; it is closed when the read is
	// published, so a request needing the run waits on it instead of reading it at the same time.
	reading chan struct{}
	id      string
	path    string
	file    fileID // as of the last look
	// racy says file was looked at within racySlack of its last change, so an unchanged stamp does not show that the
	// bytes are: the next look reads the run again from the start, whatever the stamps say, until one that finds the
	// file settled. An append (a larger size) still reads only the new lines.
	racy      bool
	tail      [sha256.Size]byte // of the last bytes read, kept while racy (tailSum)
	tailOK    bool
	windowOff int64 // oldest retained line, also after eviction
	off       int64 // the end of the last complete line read
	b         Run
	// asks are the run's asks (internal/check/askpair, the one pairing of an ask with its answer), the open ones in the
	// order their ids were first seen; held is the newest line with verdict ask, which an ask line that names nothing
	// of its own is about.
	asks      *askpair.Book[Ask]
	held      askpair.Held
	lastID    string // the newest line's id (its hash), for the chain verdict cache
	rereadErr *rereadRefusal
	refused   map[int64][sha256.Size]byte
	pub       *Run
	// A scoped view shares the immutable record version while its live source is unreadable.
	liveView, liveSource *Run
	live                 bool
	// resident is set while b.Events holds the run's lines; bytes is their estimated size; used is the LRU stamp.
	resident bool
	bytes    int64
	used     uint64
	// pairs is the mirror pairing's window over the last lines (markMirror).
	pairs mirror.Pairs
	// prog is the run's program index (program.go), built on first use and continued as the run grows; nil again
	// when the lines are evicted. It is reached without the Store's mutex, so it is an atomic pointer.
	prog atomic.Pointer[progEntry]
}

func newRunState(id, path string) *runState {
	st := &runState{id: id, path: path}
	st.reset()
	return st
}

func (st *runState) reset() {
	st.off, st.asks, st.held, st.lastID, st.bytes, st.pairs = 0, askpair.NewBook[Ask](maxWindowLines, maxPendingBytes), askpair.Held{}, "", 0, mirror.Pairs{}
	st.windowOff = 0
	st.refused = map[int64][sha256.Size]byte{}
	st.b = Run{ID: st.id, Kinds: map[string]int{}}
	st.resident = true
}

// eventBytes estimates one decoded line and its derived views. Charge every string, including envelope fields
// absent from Raw: the intern table deliberately does not share long values. Counting shared values again is safe.
func eventBytes(e *Event) int64 {
	// Reserve room for the memo's folds, text, process/ask indexes and signal
	// state as well as the decoded strings. This is an estimate, not an RSS cap.
	n := len(e.Run) + len(e.Agent) + len(e.Kind) + len(e.Source) + len(e.Rule) + len(e.Verdict) + len(e.Authority) + len(e.Reason)
	n += len(e.Op) + len(e.Target) + len(e.Proto) + len(e.Host) + len(e.AskID) + len(e.Raw)
	for _, word := range e.argv {
		n += len(word) + 16
	}
	n += len(e.askOp) + len(e.askTarget) + len(e.askName) + len(e.askName2) + len(e.to) + len(e.path) + len(e.blob)
	return 4096 + 8*int64(n)
}

// take adds one decoded line to the summary: whether it mirrors a refused action, whether its paths name secrets
// (markSecret), the counts, the run's start and end, and the asks still open.
func (st *runState) take(ev Event) {
	st.markMirror(&ev)
	st.pairAsk(&ev)
	markSecret(&ev)
	// Trim while decoding, before an append can allocate an unbounded slice.
	st.trim(eventBytes(&ev))
	startError := st.b.StartError
	st.b.add(ev)
	if startError != "" {
		st.b.refuseStart(errors.New(startError))
	}
	st.b.LastSeq = ev.Seq
	if len(st.b.Events) > 0 {
		st.windowOff = st.b.Events[0].off
	}
	if st.resident {
		st.bytes += eventBytes(&ev)
	}
	if ev.Verdict == string(record.VerdictAsk) {
		st.held.Note(ev.Op, ev.Target, ev.Rule)
	}
}

// pairAsk takes an ask or answer line through the run's askpair.Book: it keeps the open asks, and marks a repeated ask
// and an unpaired answer on the line (askRepeat, answerUnpaired) and shows each as a refused line of the run, in
// askpair's words, so no reader takes either as a question or an answer.
func (st *runState) pairAsk(ev *Event) {
	ev.askRepeat, ev.answerUnpaired, ev.Malformed = false, false, ""
	switch ev.Kind {
	case string(record.KindAsk):
		a := Ask{OwnerOnly: st.b.LocalApprovalAuthority != nil, Run: st.id, Agent: ev.Agent, AskID: ev.AskID, Hold: ev.Op, TS: ev.TS, Seq: ev.Seq,
			Op: ev.askOp, Target: ev.askTarget, Rule: ev.Rule}
		st.held.Fill(&a.Op, &a.Target, &a.Rule)
		switch st.asks.Ask(ev.AskID, a, askBytes(a)) {
		case askpair.Repeated:
			ev.askRepeat, ev.Malformed = true, askpair.RepeatedWords
			st.refuseLine(ev.off, fmt.Errorf("%s (ask %s, line %d)", askpair.RepeatedWords, ev.AskID, ev.Seq), string(record.KindAsk))
		case askpair.Refused:
			st.b.PendingCut = true
		case askpair.Opened:
		}
	case string(record.KindAnswer):
		if _, r := st.asks.Answer(ev.AskID); r == askpair.Unpaired {
			ev.answerUnpaired, ev.Malformed = true, askpair.UnpairedWords
			st.refuseLine(ev.off, fmt.Errorf("%s (ask %s, line %d)", askpair.UnpairedWords, ev.AskID, ev.Seq), string(record.KindAnswer))
		}
	}
}

const maxPendingBytes int64 = 8 << 20

// Pending asks outlive the event window, so charge all their strings independently of eventBytes.
func askBytes(a Ask) int64 {
	return 256 + 8*int64(len(a.Run)+len(a.Agent)+len(a.AskID)+len(a.Hold)+len(a.Op)+len(a.Target)+len(a.Rule))
}

// pending is the asks with no answer, in first-seen order; none once the run ended.
func (st *runState) pending() []Ask {
	if st.b.Ended {
		return nil
	}
	var out []Ask
	st.asks.Each(func(_ string, a Ask) bool {
		out = append(out, a)
		return true
	})
	return out
}

// publish makes the immutable Run requests see from the summary built so far. Its Events share the builder's
// backing array up to its length, capped, so a later append never writes where a published Run can see.
func (st *runState) publish(rev uint64) {
	p := st.b
	p.LineErrors = slices.Clone(st.b.LineErrors)
	if st.resident {
		p.Events = st.b.Events[:len(st.b.Events):len(st.b.Events)]
	} else {
		p.Events = nil
	}
	p.Kinds = make(map[string]int, len(st.b.Kinds))
	for k, v := range st.b.Kinds {
		p.Kinds[k] = v
	}
	p.routes = st.b.routes.clone()
	p.Pending = st.pending()
	p.Live = st.live && !p.Ended
	// The launcher's mark that it puts file blocks in force in the run's plane (liveblock.PlaneName): made before the
	// first live-block line a block's state is confirmed by, so a publication that holds that line sees it.
	p.planeMarked = st.path != "" && liveblock.TakesPlane(filepath.Dir(st.path))

	p.Rev, p.st, p.memo = rev, st, &runMemo{}
	p.lastID, p.file = st.lastID, st.file
	st.pub = &p
	st.liveView, st.liveSource = nil, nil
}

// read brings st up to date with its events file: nothing when the file is unchanged since the last look (seen is
// its Lstat), the appended lines when it grew, every line when it was replaced, got shorter or was rewritten in place
// (rewritten). It reports whether the summary changed.
func (s *Store) read(st *runState, seen os.FileInfo) (bool, error) {
	if seen != nil && st.pub != nil && st.b.ReadError == "" && st.sameFile(idOf(seen)) {
		return false, nil // unchanged; an evicted run stays evicted until a page asks for its lines
	}
	f, err := os.OpenFile(st.path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // read-only, no lock
	if err != nil {
		return false, ledger.WithModeAdvice(filepath.Dir(st.path), err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return false, err
	}
	if !fi.Mode().IsRegular() {
		return false, errors.New("events file is not a regular file")
	}
	now := idOf(fi)
	changed := false
	// A racy file whose stamps are unchanged is held to its tail: the same bytes there are no change (nothing moves, no
	// new version is published), others mean a rewrite within the clock's tick, read again from the start.
	staleStamps := st.pub != nil && st.b.ReadError == "" && st.racy && now == st.file
	if staleStamps {
		if sum, ok := tailSum(f, st.off); ok && st.tailOK && sum == st.tail {
			st.racy = racyStamp(now, time.Now())
			return false, nil
		}
	}
	if st.pub == nil || staleStamps || rewritten(now, st.file, st.off) || st.rereadErr != nil && now != st.file {
		st.reset()
		changed = true
	}
	st.file, st.racy = now, racyStamp(now, time.Now())
	if st.racy {
		defer func() { st.tail, st.tailOK = tailSum(f, st.off) }()
	}
	if !st.resident {
		if err := st.loadWindow(); err != nil {
			var refusal *rereadRefusal
			if !errors.As(err, &refusal) {
				err = &rereadRefusal{cause: err, off: st.windowOff}
			}
			return changed, err
		}
	}
	if now.size <= st.off {
		return changed, nil
	}
	if _, err := f.Seek(st.off, io.SeekStart); err != nil {
		return changed, err
	}
	br := bufio.NewReaderSize(io.LimitReader(f, now.size-st.off), 64<<10)
	for {
		line, size, err := boundedLine(br)
		if errors.Is(err, io.EOF) {
			break // no newline yet: the line is still being written, so it is left for a later read
		}
		if err != nil {
			return true, err
		}
		at := st.off
		st.off += size
		changed = true
		var ev Event
		var id string
		decodeErr := fmt.Errorf("line longer than %d bytes", maxLineBytes)
		if line != nil {
			ev, id, decodeErr = decodeLine(line[:len(line)-1])
		}
		if decodeErr != nil {
			digest, err := refusedLineHash(f, at, size, line)
			if err != nil {
				return true, err
			}
			st.refused[at] = digest
			st.refuseLine(at, decodeErr, ev.Kind)
			continue
		}
		ev.off = at
		if ev.blob != "" {
			// Once per line as it is taken, never per published version: a later append starts after this line.
			resolveBlob(filepath.Dir(st.path), &ev)
		}
		s.internEvent(&ev)
		st.lastID = id
		st.take(ev)
	}
	return changed, nil
}

// boundedLine consumes one complete line with a fixed allocation ceiling. Oversized
// lines return nil and their size; a torn tail is retried from its original offset.
func boundedLine(br *bufio.Reader) ([]byte, int64, error) {
	var line []byte
	var size int64
	oversized := false
	for {
		part, err := br.ReadSlice('\n')
		size += int64(len(part))
		if size > maxLineBytes {
			oversized = true
			line = nil
		}
		if !oversized {
			line = append(line, part...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return line, size, err
	}
}

// Windows bound both raw events and the derived indexes built from them. Eviction
// also applies to live runs. Full-history counts live in Run, not in this window.
const maxWindowLines = 32768
const maxWindowBytes int64 = 128 << 20

func (st *runState) trim(incoming int64) {
	limit := max(1, min(MaxLines, maxWindowLines))
	evs := st.b.Events
	if len(evs) == 0 || len(evs) < limit && st.bytes+incoming <= maxWindowBytes {
		return
	}
	// Drop at least half, amortizing copies while keeping published slices immutable.
	n := 0
	for n < len(evs) && (n < len(evs)/2 || len(evs)-n >= limit || st.bytes+incoming > maxWindowBytes) {
		st.bytes -= eventBytes(&evs[n])
		n++
	}
	st.b.Events = slices.Clone(evs[n:])
	st.b.Cut = true
	if len(st.b.Events) > 0 {
		st.windowOff = st.b.Events[0].off
	} else {
		st.windowOff = st.off
	}
}

// loadWindow rehydrates only the retained byte interval; summary counters never
// replay, and requests for evicted live runs cannot reallocate their whole history.
func (st *runState) loadWindow() error {
	f, err := os.OpenFile(st.path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return errors.New("events file is not a regular file")
	}
	if rewritten(idOf(fi), st.file, st.off) {
		return ErrLineMoved
	}
	tmp := newRunState(st.id, st.path)
	tmp.b.RecordMinor, tmp.b.LocalApprovalAuthority = st.b.RecordMinor, st.b.LocalApprovalAuthority
	br := bufio.NewReaderSize(io.NewSectionReader(f, st.windowOff, st.off-st.windowOff), 64<<10)
	at := st.windowOff
	for {
		line, size, err := boundedLine(br)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		var ev Event
		decodeErr := fmt.Errorf("line longer than %d bytes", maxLineBytes)
		if line != nil {
			ev, _, decodeErr = decodeLine(line[:len(line)-1])
		}
		if decodeErr != nil {
			// Revalidate before skipping; position and reason alone cannot
			// establish that this is the same previously counted damage.
			digest, err := refusedLineHash(f, at, size, line)
			if err != nil {
				return err
			}
			if retained, ok := st.refused[at]; !ok || retained != digest {
				return &rereadRefusal{cause: decodeErr, off: at, start: ev.Kind == "" || ev.Kind == string(record.KindRunStart)}
			}
		} else {
			ev.off = at
			if ev.blob != "" {
				resolveBlob(filepath.Dir(st.path), &ev)
			}
			tmp.take(ev)
		}
		at += size
	}
	st.b.Events, st.bytes, st.pairs = tmp.b.Events, tmp.bytes, tmp.pairs
	st.resident = true
	return nil
}

// decodeLine is decode, also returning the line's id.
func decodeLine(body []byte) (Event, string, error) {
	e, err := record.Decode(body)
	if err != nil {
		// Malformed envelopes (including duplicate kind keys) cannot supply
		// a trustworthy classification. A second decoder must not choose its
		// last repaired/partial kind and preserve earlier baseline claims.
		if errors.Is(err, record.ErrMalformedLine) {
			return Event{}, "", err
		}
		var head map[string]json.RawMessage
		if classifyErr := json.Unmarshal(body, &head); classifyErr != nil {
			return Event{}, "", err
		}
		var kind string
		if classifyErr := json.Unmarshal(head["kind"], &kind); classifyErr != nil {
			return Event{}, "", err
		}
		return Event{Kind: kind}, "", err
	}
	return fromRecord(e), e.ID, nil
}

// maxIntern bounds the intern table; past it, strings are kept as decoded.
const maxIntern = 1 << 16

// internEvent shares the strings many lines repeat (run, agent, kind, rule, verdict ...) so a big run keeps one
// copy of each instead of one per line. Runs are read in parallel, so the table is taken once per line.
func (s *Store) internEvent(e *Event) {
	s.internMu.Lock()
	defer s.internMu.Unlock()
	for _, p := range []*string{&e.Run, &e.Agent, &e.Kind, &e.Source, &e.Rule, &e.Verdict, &e.Authority, &e.Reason,
		&e.Op, &e.Proto} {
		if *p == "" {
			continue
		}
		if v, ok := s.intern[*p]; ok {
			*p = v
		} else if len(s.intern) < maxIntern && len(*p) <= 256 {
			s.intern[*p] = *p
		}
	}
}

// replay builds a Run from lines already decoded, as a fresh read of a file holding only evs would; when cut, the
// file's last line (last) still gives an ended run its run_end. It serves the line bound (MaxLines).
func replay(id string, evs []Event, cut bool, last *Event) *Run {
	st := newRunState(id, "")
	for _, ev := range evs {
		st.take(ev)
	}
	st.b.Cut = cut
	if cut && last != nil && last.Kind == string(record.KindRunEnd) {
		st.b.end(*last)
	}
	st.publish(0)
	st.pub.st = nil
	return st.pub
}

// rereadRefusal crosses the cache worker boundary without losing the decoder's
// reason or treating an invalid retained window as the earlier valid snapshot.
type rereadRefusal struct {
	cause error
	off   int64
	start bool
}

func (e *rereadRefusal) Error() string {
	return fmt.Sprintf("line at byte offset %d: %v", e.off, e.cause)
}
func (e *rereadRefusal) Unwrap() error { return e.cause }

// refuseReread is shared by both retained-window publication paths. The Store's
// mutex is held; repeated reads of the same refusal do not add another bad line, and a failure to read the file adds none.
func (st *runState) refuseReread(err error) bool {
	var refusal *rereadRefusal
	decoded := errors.As(err, &refusal)
	if !decoded {
		refusal = &rereadRefusal{cause: err, off: st.windowOff}
	}
	changed := st.rereadErr == nil || st.rereadErr.Error() != refusal.Error() || st.rereadErr.start != refusal.start
	if changed && decoded {
		// A line the decoder refused is a bad line; a failure to read the file is not (ReadError holds it).
		st.b.Bad++
	}
	st.rereadErr = refusal
	st.b.ReadError = refusal.Error()
	st.b.Cut = true
	if refusal.start {
		st.b.refuseStart(refusal)
	}
	return changed
}

// A failed classification cannot exclude run_start; withdraw prior baseline claims.
func (st *runState) refuseLine(off int64, err error, kind string) {
	refusal := &rereadRefusal{cause: err, off: off}
	st.b.Bad++
	st.b.LineErrors = append(st.b.LineErrors, LineRefusal{Offset: off, Reason: refusal.Error()})
	if kind == "" || kind == string(record.KindRunStart) {
		st.b.refuseStart(refusal)
	}
}

// Hash the complete refused frame, including oversized lines, with bounded memory.
func refusedLineHash(f io.ReaderAt, off, size int64, line []byte) ([sha256.Size]byte, error) {
	if line != nil {
		return sha256.Sum256(line), nil
	}
	h := sha256.New()
	n, err := io.Copy(h, io.NewSectionReader(f, off, size))
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	if n != size {
		return [sha256.Size]byte{}, io.ErrUnexpectedEOF
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}
