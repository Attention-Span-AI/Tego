// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"syscall"

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
	return id
}

// rewritten reports whether now, a later look at the events file a runState read as was (its complete lines ending
// at off), is no longer that file with lines appended: another file (device or inode), shorter than what was read, or
// changed without growing (another mtime or ctime at the same size or less: bytes rewritten in place). Its lines are
// then read again from the start; only an append leaves the lines read before as they were.
func rewritten(now, was fileID, off int64) bool {
	return now.dev != was.dev || now.ino != was.ino || now.size < off || now != was && now.size <= was.size
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
	reading   chan struct{}
	id        string
	path      string
	file      fileID // as of the last look
	windowOff int64  // oldest retained line, also after eviction
	off       int64  // the end of the last complete line read
	b         Run
	asks      map[string]Ask
	askBytes  int64
	// askOrder is the ask ids in the order they were first seen; lastAsk is the newest line with verdict ask.
	askOrder []string
	lastAsk  *Event
	lastID   string // the newest line's id (its hash), for the chain verdict cache
	pub      *Run
	live     bool
	// resident is set while b.Events holds the run's lines; bytes is their estimated size; used is the LRU stamp.
	resident bool
	bytes    int64
	used     uint64
	// paired is the indices in b.Events of the refused actions a mirror took, among the last lines only (markMirror).
	paired []int
}

func newRunState(id, path string) *runState {
	st := &runState{id: id, path: path}
	st.reset()
	return st
}

func (st *runState) reset() {
	st.off, st.asks, st.askOrder, st.lastAsk, st.lastID, st.bytes, st.paired = 0, map[string]Ask{}, nil, nil, "", 0, nil
	st.windowOff, st.askBytes = 0, 0
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
	n += len(e.askOp) + len(e.askTarget) + len(e.askName) + len(e.askName2) + len(e.to) + len(e.path) + len(e.blob)
	return 4096 + 8*int64(n)
}

// take adds one decoded line to the summary: whether it mirrors a refused action, whether its paths name secrets
// (markSecret), the counts, the run's start and end, and the asks still open.
func (st *runState) take(ev Event) {
	st.markMirror(&ev)
	markSecret(&ev)
	// Trim while decoding, before an append can allocate an unbounded slice.
	st.trim(eventBytes(&ev))
	st.b.add(ev)
	st.b.LastSeq = ev.Seq
	if len(st.b.Events) > 0 {
		st.windowOff = st.b.Events[0].off
	}
	if st.resident {
		st.bytes += eventBytes(&ev)
	}
	switch ev.Kind {
	case string(record.KindAsk):
		a := Ask{Run: st.id, Agent: ev.Agent, AskID: ev.AskID, Hold: ev.Op, TS: ev.TS, Seq: ev.Seq}
		switch {
		case ev.askTarget != "":
			// The ask line names its own operation, target and rule (the supervisor writes them on every ask);
			// a line before it with verdict ask may belong to another ask.
			a.Op, a.Target, a.Rule = ev.askOp, ev.askTarget, ev.Rule
		case st.lastAsk != nil:
			a.Op, a.Target, a.Rule = st.lastAsk.Op, st.lastAsk.Target, st.lastAsk.Rule
		}
		previous, seen := st.asks[ev.AskID]
		bytes := askBytes(a)
		oldBytes := int64(0)
		if seen {
			oldBytes = askBytes(previous)
		}
		if (!seen && len(st.asks) >= maxWindowLines) || st.askBytes-oldBytes+bytes > maxPendingBytes {
			st.b.PendingCut = true
		} else {
			if !seen {
				st.askOrder = append(st.askOrder, ev.AskID)
			}
			st.asks[ev.AskID] = a
			st.askBytes += bytes - oldBytes
		}
	case string(record.KindAnswer):
		if a, ok := st.asks[ev.AskID]; ok {
			st.askBytes -= askBytes(a)
		}
		delete(st.asks, ev.AskID)
		st.askOrder = slices.DeleteFunc(st.askOrder, func(id string) bool { return id == ev.AskID })
	}
	if ev.Verdict == string(record.VerdictAsk) {
		e := ev
		st.lastAsk = &e
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
	for _, id := range st.askOrder {
		if a, ok := st.asks[id]; ok {
			out = append(out, a)
		}
	}
	return out
}

// publish makes the immutable Run requests see from the summary built so far. Its Events share the builder's
// backing array up to its length, capped, so a later append never writes where a published Run can see.
func (st *runState) publish(rev uint64) {
	p := st.b
	if st.resident {
		p.Events = st.b.Events[:len(st.b.Events):len(st.b.Events)]
	} else {
		p.Events = nil
	}
	p.Kinds = make(map[string]int, len(st.b.Kinds))
	for k, v := range st.b.Kinds {
		p.Kinds[k] = v
	}
	p.Pending = st.pending()
	p.Live = st.live && !p.Ended

	p.Rev, p.st, p.memo = rev, st, &runMemo{}
	p.lastID, p.file = st.lastID, st.file
	st.pub = &p
}

// read brings st up to date with its events file: nothing when the file is unchanged since the last look (seen is
// its Lstat), the appended lines when it grew, every line when it was replaced, got shorter or was rewritten in place
// (rewritten). It reports whether the summary changed.
func (s *Store) read(st *runState, seen os.FileInfo) (bool, error) {
	if seen != nil && st.pub != nil && idOf(seen) == st.file {
		return false, nil // unchanged; an evicted run stays evicted until a page asks for its lines
	}
	f, err := os.OpenFile(st.path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // read-only, no lock
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return false, err
	}
	if !fi.Mode().IsRegular() {
		return false, os.ErrNotExist
	}
	now := idOf(fi)
	changed := false
	if st.pub == nil || rewritten(now, st.file, st.off) {
		st.reset()
		changed = true
	}
	st.file = now
	if !st.resident {
		if err := st.loadWindow(); err != nil {
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
		if line == nil {
			st.b.Bad++
			continue
		}
		body := line[:len(line)-1]
		if len(body) == 0 {
			continue
		}
		if len(body) > maxLineBytes {
			st.b.Bad++
			continue
		}
		ev, id, ok := decodeLine(body)
		if !ok {
			st.b.Bad++
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
	st.paired = slices.DeleteFunc(st.paired, func(i int) bool { return i < n })
	for i := range st.paired {
		st.paired[i] -= n
	}
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
	if rewritten(idOf(fi), st.file, st.off) {
		return ErrLineMoved
	}
	tmp := newRunState(st.id, st.path)
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
		if line != nil {
			if ev, _, ok := decodeLine(line[:len(line)-1]); ok {
				ev.off = at
				if ev.blob != "" {
					resolveBlob(filepath.Dir(st.path), &ev)
				}
				tmp.take(ev)
			}
		}
		at += size
	}
	st.b.Events, st.bytes, st.paired = tmp.b.Events, tmp.bytes, tmp.paired
	st.resident = true
	return nil
}

// decodeLine is decode, also returning the line's id.
func decodeLine(body []byte) (Event, string, bool) {
	e, err := record.Decode(body)
	if err != nil {
		return Event{}, "", false
	}
	return fromRecord(e), e.ID, true
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
