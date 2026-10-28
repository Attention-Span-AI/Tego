// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bytes"
	"container/heap"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
)

// Export: every line a Logs search matches, one at a time, with its exact bytes read back from its events file, for
// the dashboard's JSONL and CSV downloads.

// Order is the order Each gives lines in.
type Order int

// The orders: Logs' own (newest first, by time, then run, then seq), and that order reversed, as a log reads.
const (
	NewestFirst Order = iota
	OldestFirst
)

// ErrLineMoved is raw's error when the events file no longer holds the line where the read model saw it (the file
// was replaced since).
var ErrLineMoved = errors.New("the events file changed: the line is no longer where it was read")

// WholeRun reports the run f selects when it selects exactly one run and narrows it by nothing else (no kind,
// verdict, text, time, process or any other query field), so its lines are all of that run's lines.
func (f *Filter) WholeRun() (string, bool) {
	if !f.plain() {
		return "", false
	}
	run := f.Run
	for _, r := range f.Runs {
		if run != "" && r != run {
			return "", false
		}
		run = r
	}
	if run == "" || slices.Contains(f.Not.Runs, run) {
		return "", false
	}
	return run, true
}

// Each calls fn with every line f matches, unfolded (the lines Page.Matched counts, so a refused action's mirror is
// left out unless f lists refused lines by kind), in order, until fn returns false. raw reads the line's exact bytes
// from its events file, without the newline; they are valid until fn returns. f's Before and PageSize are ignored.
//
// With f.Ledger and one whole run (WholeRun), Each gives every line of that run in file order (reversed for
// NewestFirst), mirrors included: the download is then the run's events file and its chain checks.
func (s *Snapshot) Each(f Filter, order Order, fn func(e *Event, raw func() ([]byte, error)) bool) {
	if f.Ledger {
		if id, ok := f.WholeRun(); ok {
			s.eachLine(id, order, fn)
			return
		}
	}
	m := newMatcher(&f)
	h := &lineHeap{order: order}
	for _, r := range s.Runs {
		evs := r.AllEvents()
		if len(evs) == 0 {
			continue
		}
		rm, ok := m.forRun(r)
		if !ok {
			continue
		}
		nf := r.newestFirst()
		var idx []int32
		for k := range evs {
			i := int32(len(evs) - 1 - k) //nolint:gosec // a run holds far fewer than 2^31 lines (MaxLines)
			if nf != nil {
				i = nf[k]
			}
			if ok, _ := rm.match(i, &evs[i]); ok {
				idx = append(idx, i)
			}
		}
		if len(idx) == 0 {
			continue
		}
		if order == OldestFirst {
			for a, b := 0, len(idx)-1; a < b; a, b = a+1, b-1 {
				idx[a], idx[b] = idx[b], idx[a]
			}
		}
		h.parts = append(h.parts, &linePart{run: r.ID, evs: evs, idx: idx})
	}
	heap.Init(h)
	rd := newLineReader(s.Root)
	defer rd.close()
	for h.Len() > 0 {
		p := h.parts[0]
		e := &p.evs[p.idx[p.pos]]
		raw := func() ([]byte, error) { return rd.read(p.run, e.off, e.Seq) }
		if !fn(e, raw) {
			return
		}
		p.pos++
		if p.pos == len(p.idx) {
			heap.Pop(h)
		} else {
			heap.Fix(h, 0)
		}
	}
}

// eachLine is Each over every line of run id in file order, reversed for NewestFirst.
func (s *Snapshot) eachLine(id string, order Order, fn func(e *Event, raw func() ([]byte, error)) bool) {
	r := s.Find(id)
	if r == nil {
		return
	}
	evs := r.AllEvents()
	rd := newLineReader(s.Root)
	defer rd.close()
	for k := range evs {
		i := k
		if order == NewestFirst {
			i = len(evs) - 1 - k
		}
		e := &evs[i]
		if !fn(e, func() ([]byte, error) { return rd.read(r.ID, e.off, e.Seq) }) {
			return
		}
	}
}

// linePart is one run's matched lines, in order, and how far Each has given them.
type linePart struct {
	run string
	evs []Event
	idx []int32
	pos int
}

// lineHeap merges the runs' parts: its top is the part whose next line comes first in order.
type lineHeap struct {
	parts []*linePart
	order Order
}

func (h *lineHeap) Len() int { return len(h.parts) }
func (h *lineHeap) Less(i, j int) bool {
	a, b := &h.parts[i].evs[h.parts[i].idx[h.parts[i].pos]], &h.parts[j].evs[h.parts[j].idx[h.parts[j].pos]]
	if h.order == OldestFirst {
		return less(b, a)
	}
	return less(a, b)
}
func (h *lineHeap) Swap(i, j int) { h.parts[i], h.parts[j] = h.parts[j], h.parts[i] }
func (h *lineHeap) Push(x any)    { h.parts = append(h.parts, x.(*linePart)) }
func (h *lineHeap) Pop() any {
	p := h.parts[len(h.parts)-1]
	h.parts = h.parts[:len(h.parts)-1]
	return p
}

// lineReader reads lines back by offset, keeping a few events files open with a window of each, so lines read in
// order cost one read per window rather than one per line.
type lineReader struct {
	root  string
	files map[string]*windowFile
	order []string // open files, oldest use first
}

type windowFile struct {
	f   *os.File
	buf []byte
	at  int64 // where buf starts in the file
	err error
}

const (
	maxOpenExports = 32
	exportWindow   = 256 << 10
)

func newLineReader(root string) *lineReader {
	return &lineReader{root: root, files: map[string]*windowFile{}}
}

func (lr *lineReader) close() {
	for _, w := range lr.files {
		if w.f != nil {
			_ = w.f.Close() // read-only: nothing to flush
		}
	}
}

func (lr *lineReader) file(run string) *windowFile {
	if w, ok := lr.files[run]; ok {
		return w
	}
	if len(lr.order) >= maxOpenExports {
		old := lr.order[0]
		lr.order = lr.order[1:]
		if w := lr.files[old]; w != nil && w.f != nil {
			_ = w.f.Close() // read-only: nothing to flush
		}
		delete(lr.files, old)
	}
	w := &windowFile{}
	if !validRunID(run) {
		w.err = os.ErrNotExist
	} else {
		w.f, w.err = os.OpenFile(filepath.Join(lr.root, run, "events.jsonl"), os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	}
	lr.files[run] = w
	lr.order = append(lr.order, run)
	return w
}

// read is the line of run that starts at off, which must be line seq.
func (lr *lineReader) read(run string, off int64, seq uint64) ([]byte, error) {
	w := lr.file(run)
	if w.err != nil {
		return nil, w.err
	}
	line, ok := w.window(off)
	if !ok {
		size := exportWindow
		for {
			if cap(w.buf) < size {
				w.buf = make([]byte, size)
			}
			n, err := w.f.ReadAt(w.buf[:size], off)
			w.buf, w.at = w.buf[:n], off
			if line, ok = w.window(off); ok {
				break
			}
			if err != nil || n < size {
				if err == nil || errors.Is(err, io.EOF) {
					err = ErrLineMoved
				}
				return nil, err
			}
			if size >= maxLineBytes+1 {
				return nil, fmt.Errorf("line at %d: longer than %d bytes", off, maxLineBytes)
			}
			size = min(size*4, maxLineBytes+1)
		}
	}
	if !isSeq(line, seq) {
		return nil, ErrLineMoved
	}
	return line, nil
}

// window is the line at off when the window holds all of it.
func (w *windowFile) window(off int64) ([]byte, bool) {
	if off < w.at || off >= w.at+int64(len(w.buf)) {
		return nil, false
	}
	rest := w.buf[off-w.at:]
	k := bytes.IndexByte(rest, '\n')
	if k < 0 {
		return nil, false
	}
	return rest[:k], true
}

// isSeq reports whether line's envelope (its first "seq" member, which the writer puts before the payload) is seq.
func isSeq(line []byte, seq uint64) bool {
	k := bytes.Index(line, []byte(`"seq":`))
	if k < 0 {
		return false
	}
	rest := line[k+len(`"seq":`):]
	n := 0
	for n < len(rest) && rest[n] >= '0' && rest[n] <= '9' {
		n++
	}
	v, err := strconv.ParseUint(string(rest[:n]), 10, 64)
	return err == nil && v == seq
}
