// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
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
// the edited bytes (r10 BR-2). Every change to the inode moves its ctime, and no system call sets it back.
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
	reading chan struct{}
	id      string
	path    string
	file    fileID // as of the last look
	off     int64  // the end of the last complete line read
	b       Run
	asks    map[string]Ask
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
	st.b = Run{ID: st.id, Kinds: map[string]int{}}
	st.resident = true
}

// eventBytes estimates what one decoded line keeps in memory: the struct, its payload text and the strings the
// intern table does not share.
func eventBytes(e *Event) int64 {
	return 256 + int64(len(e.Raw)+len(e.Target)+len(e.AskID)+len(e.askOp)+len(e.askTarget))
}

// take adds one decoded line to the summary: whether it mirrors a refused action, whether its paths name secrets
// (markSecret), the counts, the run's start and end, and the asks still open.
func (st *runState) take(ev Event) {
	st.markMirror(&ev)
	markSecret(&ev)
	st.b.add(ev)
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
		if _, seen := st.asks[ev.AskID]; !seen {
			st.askOrder = append(st.askOrder, ev.AskID)
		}
		st.asks[ev.AskID] = a
	case string(record.KindAnswer):
		delete(st.asks, ev.AskID)
	}
	if ev.Verdict == string(record.VerdictAsk) {
		e := ev
		st.lastAsk = &e
	}
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
	if n := len(st.b.Events); n > 0 {
		p.LastSeq = st.b.Events[n-1].Seq
	}
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
	f, err := os.OpenFile(st.path, os.O_RDONLY|syscall.O_NOFOLLOW, 0) // read-only, no lock
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return false, err
	}
	now := idOf(fi)
	changed := false
	if st.pub == nil || rewritten(now, st.file, st.off) || !st.resident {
		st.reset()
		changed = true
	}
	st.file = now
	if now.size <= st.off {
		return changed, nil
	}
	if _, err := f.Seek(st.off, io.SeekStart); err != nil {
		return changed, err
	}
	br := bufio.NewReaderSize(f, 256<<10)
	for {
		line, err := br.ReadBytes('\n')
		if errors.Is(err, io.EOF) {
			break // no newline yet: the line is still being written, so it is left for a later read
		}
		if err != nil {
			return true, err
		}
		at := st.off
		st.off += int64(len(line))
		changed = true
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
		} else if len(s.intern) < maxIntern {
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
