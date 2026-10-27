// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The Follower (record-ledger.md §4 Follow) is the one tail of a live run in the lowest
// layer: `tego events --follow` reads it, and any other reader of a run's ledger is to use it rather than keep a follower
// of its own. A Reader rescans from byte 0 on every pass; the Follower reads each byte once, from where it
// stopped, and checks the chain as it goes.

// Cursor names a line a Follower delivered: the byte offset where it starts in events.jsonl, its seq and its id.
// A Follower started from it delivers the lines after it, and first checks that the line is still there; the
// zero Cursor starts at the first line.
type Cursor struct {
	Offset int64  `json:"offset"`
	Seq    uint64 `json:"seq"`
	ID     string `json:"id"`
}

// ErrCursorMismatch is a cursor that names no line this ledger holds: its offset is past the end or inside a
// line, or the line there does not carry its seq and id. The ledger is not the one the cursor was taken from,
// or it changed; a Follower never resumes from such a cursor, because the lines it skipped are unchecked.
var ErrCursorMismatch = errors.New("ledger: the cursor names no line this ledger holds [cursor-mismatch]")

// ErrRunLost ends a Follower whose run will write no more: no writer holds the lock and the ledger does not end
// in run_end (StateLost, or a run directory whose launcher died before run_start). The next `tego run`, `tego
// stop` or `tego gc` ends such a run as orphaned; a follower started after that reads it to its run_end.
var ErrRunLost = errors.New("ledger: no writer holds the run's lock and its ledger ends without run_end")

// FollowEntry is a line a Follower delivered and the cursor that resumes after it. Entry.Line is the
// Follower's own buffer: it is valid until the loop asks for the next line, so a caller that keeps it copies
// it. Entry.Event is the line decoded and the caller's to keep.
type FollowEntry struct {
	Entry
	Cursor Cursor
}

// followBuf is the size the Follower's one read buffer starts at and returns to; a longer line grows it, up
// to MaxLineBytes, and it shrinks back once that line is delivered. 512 followed runs hold 16 MiB at rest.
const followBuf = 32 << 10

// followCtxEvery is how many lines the Follower delivers between checks of its context while it catches up.
const followCtxEvery = 1024

// Follower follows one run's events.jsonl as its Writer appends to it. It opens the ledger as a Reader does,
// read-only and without the lock, so any number may follow a live run. Its memory is one read buffer of at
// most MaxLineBytes and the chain's head: it keeps no line once the caller has moved past it.
type Follower struct {
	dir       string
	f         *os.File
	wake      *waker
	from      Cursor
	skipNewer bool
	newer     int
	idle      func() error
	used      bool
	maxBuf    int // the largest the buffer has been, for the tests that cap it
	bufLen    int // the buffer's size after the last read, for the test that sees it shrink
}

// Follow opens the run directory dir to follow from the line after from (the zero Cursor: from the first
// line). os.ErrNotExist when the ledger is absent. A cursor is checked when the lines are read (Lines), not
// here.
func Follow(dir string, from Cursor) (*Follower, error) {
	events := filepath.Join(dir, EventsFile)
	f, err := openRegular(events)
	if err != nil {
		return nil, fmt.Errorf("ledger: open events: %w", err)
	}
	w := newWaker()
	// The Writer appends with write(2), which raises IN_MODIFY; Close releases the lock by closing the
	// descriptor it opened O_RDWR, which raises IN_CLOSE_WRITE. A lock file not made yet is the backstop's.
	_ = w.watch(events, unix.IN_MODIFY)
	_ = w.watch(filepath.Join(dir, LockFile), unix.IN_CLOSE_WRITE)
	return &Follower{dir: dir, f: f, wake: w, from: from}, nil
}

// Dir is the run directory being followed.
func (fl *Follower) Dir() string { return fl.dir }

// Wake reports how the Follower learns of new lines: WakeInotify, or WakePoll (every second) when inotify could
// not be had, with the reason.
func (fl *Follower) Wake() (string, error) { return fl.wake.mode, fl.wake.why }

// SkipNewerVersions makes Lines pass over a line a newer record version wrote, once its link in the chain is
// checked, and count it (SkippedNewer), as Reader.SkipNewerVersions does for the views; without it such a line
// ends the follow as ErrCorruptLedger, as it ends Reader.Entries.
func (fl *Follower) SkipNewerVersions() { fl.skipNewer = true }

// SkippedNewer is how many newer-version lines Lines has passed over.
func (fl *Follower) SkippedNewer() int { return fl.newer }

// OnIdle sets fn to run each time the Follower has delivered every line there is and is about to wait for
// more: a renderer flushes what it buffered there. An error from fn ends Lines with that error.
func (fl *Follower) OnIdle(fn func() error) { fl.idle = fn }

// Close releases the ledger's descriptor and the inotify instance.
func (fl *Follower) Close() error { return errors.Join(fl.f.Close(), fl.wake.close()) }

// Lines yields each complete line appended after the cursor, once, in order, waiting for the Writer between
// them; a Follower is read once. Every line is checked as it arrives (runCheck): its id against its bytes, seq
// and prev against the line before, the run's id, run_start first. A line that breaks the chain ends the
// sequence with ErrCorruptLedger naming the line and its byte offset, and nothing after it is delivered.
//
// An unterminated last line is held while a writer holds the lock: write(2) of one line can be seen half done.
// Once the lock is free it is a line if it reads as one (wholeLine, E8) and a torn tail otherwise (E6). The
// sequence ends cleanly after run_end once the lock is free (the launcher anchors after run_end, lock held),
// with ErrCorruptLedger when bytes follow run_end, with ErrRunLost when the lock is free and there is no
// run_end, and with ctx's error when ctx ends. The lock is probed before the read that finds the end of the
// file, as Reader.State probes it, so a lock seen free means that read was final.
func (fl *Follower) Lines(ctx context.Context) iter.Seq2[FollowEntry, error] {
	return func(yield func(FollowEntry, error) bool) {
		if fl.used {
			yield(FollowEntry{}, errors.New("ledger: a Follower's lines are read once"))
			return
		}
		fl.used = true
		s := &follow{fl: fl, buf: make([]byte, followBuf)}
		fl.maxBuf = max(fl.maxBuf, len(s.buf))
		lock := filepath.Join(fl.dir, LockFile)
		atEnd, err := s.resume(ctx, lock)
		if err != nil {
			yield(FollowEntry{}, err)
			return
		}
		if atEnd {
			// The cursor named the unterminated last line of a ledger no writer holds: nothing follows it.
			if _, _, err := s.finish(); err != nil {
				yield(FollowEntry{}, err)
			}
			return
		}
		read := 0
		for {
			for {
				data, ok := s.next()
				if !ok {
					break
				}
				en, deliver, err := s.take(data, true)
				if err != nil {
					yield(FollowEntry{}, err)
					return
				}
				if deliver && !yield(en, nil) {
					return
				}
				if read++; read%followCtxEvery == 0 && ctx.Err() != nil {
					yield(FollowEntry{}, ctx.Err())
					return
				}
			}
			more, err := s.fill()
			if err != nil {
				yield(FollowEntry{}, err)
				return
			}
			if more {
				continue
			}
			beforeLockProbe()
			free, err := lockFree(lock)
			if err != nil {
				yield(FollowEntry{}, err)
				return
			}
			if more, err = s.fill(); err != nil {
				yield(FollowEntry{}, err)
				return
			}
			if more {
				continue
			}
			if free {
				en, deliver, err := s.finish()
				if deliver && !yield(en, nil) {
					return
				}
				if err != nil {
					yield(FollowEntry{}, err)
				}
				return
			}
			if fl.idle != nil {
				if err := fl.idle(); err != nil {
					yield(FollowEntry{}, err)
					return
				}
			}
			if err := fl.wake.wait(ctx); err != nil {
				yield(FollowEntry{}, err)
				return
			}
		}
	}
}

// beforeLockProbe runs between the read that found the end of the file and the lock probe, in Lines and in
// resume; a test writes there and releases the lock.
var beforeLockProbe = func() {}

// follow is one pass of Lines: the buffer, the byte offset of its first byte, and the check.
type follow struct {
	fl  *Follower
	buf []byte
	// buf[start:end] is read and not yet delivered; buf[start:scan] is known to hold no "\n".
	start, scan, end int
	pos              int64 // the offset in events.jsonl of buf[start]
	n                int   // lines read, so the line in hand is n, counted from 1
	check            runCheck
}

// next returns the next terminated line in the buffer, without its "\n"; false when the buffer holds none.
func (s *follow) next() ([]byte, bool) {
	i := bytes.IndexByte(s.buf[s.scan:s.end], '\n')
	if i < 0 {
		s.scan = s.end
		return nil, false
	}
	data := s.buf[s.start : s.scan+i]
	s.start = s.scan + i + 1
	s.scan = s.start
	return data, true
}

// fill reads the file from s.pos, the offset of the first byte not yet delivered, into the buffer, and reports
// whether it holds more than before: a "\n", or bytes past those it held. The bytes not yet delivered are read
// again on every fill, never kept across one: only the bytes before s.pos are fixed (E19), since a Writer
// that resumes a lost run truncates its torn tail and appends after it (Writer.resume), and a held torn tail
// joined to what replaced it would read as a break in a ledger that has none. The buffer doubles, up to
// MaxLineBytes, when it is all one partial line, and goes back to followBuf once what it holds fits there;
// a buffer of MaxLineBytes that holds no "\n" while the file holds more is a line past the bound,
// ErrCorruptLedger, as scanLines reports it.
func (s *follow) fill() (bool, error) {
	held := s.end - s.start
	switch {
	case held == len(s.buf) && len(s.buf) < MaxLineBytes:
		s.buf = make([]byte, min(2*len(s.buf), MaxLineBytes))
		s.fl.maxBuf = max(s.fl.maxBuf, len(s.buf))
	case held < followBuf && len(s.buf) > followBuf:
		s.buf = make([]byte, followBuf) // the long line is delivered: give its room back
	}
	n, err := s.fl.f.ReadAt(s.buf, s.pos)
	s.start, s.scan, s.end = 0, 0, n
	s.fl.bufLen = len(s.buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("ledger: read events: %w", err)
	}
	nl := bytes.IndexByte(s.buf[:n], '\n') >= 0
	if !nl {
		s.scan = n
		if n == len(s.buf) && n >= MaxLineBytes {
			var one [1]byte
			if m, _ := s.fl.f.ReadAt(one[:], s.pos+int64(n)); m > 0 {
				return false, fmt.Errorf("%w %d: longer than %d bytes", ErrCorruptLedger, s.n+1, MaxLineBytes)
			}
			// The line may yet be whole: finish or a later fill judges it.
		}
	}
	return nl || n > held, nil
}

// take checks data, the line at s.pos, as the run's next line and returns its entry; deliver is false for a
// newer-version line skipped by SkipNewerVersions.
func (s *follow) take(data []byte, terminated bool) (FollowEntry, bool, error) {
	s.n++
	off := s.pos
	if terminated {
		s.pos += int64(len(data)) + 1
	} else {
		s.pos += int64(len(data))
	}
	if s.check.ended {
		return FollowEntry{}, false, fmt.Errorf("%w %d: at byte offset %d: a line follows run_end", ErrCorruptLedger,
			s.n, off)
	}
	e, newer, err := s.check.add(data)
	if err != nil {
		return FollowEntry{}, false, fmt.Errorf("%w %d: at byte offset %d: %w", ErrCorruptLedger, s.n, off, err)
	}
	if newer {
		if s.fl.skipNewer {
			s.fl.newer++
			return FollowEntry{}, false, nil
		}
		_, derr := record.Decode(data)
		return FollowEntry{}, false, fmt.Errorf("%w %d: at byte offset %d: %w", ErrCorruptLedger, s.n, off, derr)
	}
	return FollowEntry{
		Entry:  Entry{Line: data, Event: e},
		Cursor: Cursor{Offset: off, Seq: e.Seq, ID: s.check.chain.Head()},
	}, true, nil
}

// finish ends the pass once the lock is free and the file holds nothing more: an unterminated tail is a line
// when it reads as one, and torn otherwise.
func (s *follow) finish() (FollowEntry, bool, error) {
	var (
		en      FollowEntry
		deliver bool
	)
	if tail := s.buf[s.start:s.end]; len(tail) > 0 {
		if !wholeLine(tail) {
			if s.check.ended {
				return en, false, fmt.Errorf("%w %d: %d bytes at byte offset %d after run_end are not a record",
					ErrCorruptLedger, s.n+1, len(tail), s.pos)
			}
			return en, false, fmt.Errorf("%w: %s (a torn last line of %d bytes at byte offset %d)", ErrRunLost,
				s.fl.dir, len(tail), s.pos)
		}
		s.start = s.end
		var err error
		if en, deliver, err = s.take(tail, false); err != nil {
			return en, false, err
		}
	}
	if !s.check.ended {
		return en, deliver, fmt.Errorf("%w: %s", ErrRunLost, s.fl.dir)
	}
	return en, deliver, nil
}

// resume places the pass at the Follower's cursor: the first line for the zero Cursor; otherwise the line the
// cursor names must start at its offset and carry its seq and id, and the chain resumes after it. The line is
// terminated, or it is the whole unterminated last line of a ledger no writer holds, which finish delivers
// (E8) and which a cursor names as well; atEnd then says nothing can follow it. A partial line at the cursor
// while a writer holds the lock is waited for.
func (s *follow) resume(ctx context.Context, lock string) (atEnd bool, err error) {
	if want := runDirName(s.fl.dir); IsRunID(want) {
		s.check.run = want // every line must carry the run directory's id, as Verify holds it
	}
	from := s.fl.from
	if from == (Cursor{}) {
		return false, nil
	}
	mismatch := func(why string) error {
		return fmt.Errorf("%w: %s: the line at byte offset %d %s", ErrCursorMismatch, s.fl.dir, from.Offset, why)
	}
	if from.Offset < 0 || !record.IsID(from.ID) {
		return false, mismatch("is not a cursor (offset or id malformed)")
	}
	if from.Offset > 0 {
		var one [1]byte
		if n, _ := s.fl.f.ReadAt(one[:], from.Offset-1); n != 1 || one[0] != '\n' {
			return false, mismatch("does not start a line")
		}
	}
	s.pos = from.Offset
	data, ok := s.next()
	for !ok {
		more, err := s.fill()
		if err != nil {
			return false, err
		}
		if data, ok = s.next(); ok || more {
			continue
		}
		// The file ends inside the cursor's line or at its offset. The lock is probed before the last read,
		// as Lines probes it.
		beforeLockProbe()
		free, err := lockFree(lock)
		if err != nil {
			return false, err
		}
		if more, err = s.fill(); err != nil {
			return false, err
		}
		if data, ok = s.next(); ok || more {
			continue
		}
		tail := s.buf[s.start:s.end]
		switch {
		case free && len(tail) > 0 && wholeLine(tail):
			data, ok, atEnd = tail, true, true
			s.start = s.end
		case !free && len(tail) > 0:
			if err := s.fl.wake.wait(ctx); err != nil {
				return false, err
			}
		default:
			return false, mismatch("is not a complete line")
		}
	}
	link, err := lineLink(data)
	if err != nil {
		return false, mismatch(fmt.Sprintf("does not read (%v)", err))
	}
	if link.ID != from.ID || link.Seq != from.Seq {
		return false, mismatch(fmt.Sprintf("is seq %d id %s, the cursor says seq %d id %s", link.Seq, link.ID,
			from.Seq, from.ID))
	}
	if s.check.run == "" {
		s.check.run = link.Run
	}
	if link.Run != s.check.run {
		return false, fmt.Errorf("%w %d: at byte offset %d: %w: line is run %q, following %q", ErrCorruptLedger,
			from.Seq+1, from.Offset, ErrRunMismatch, link.Run, s.check.run)
	}
	s.check.chain = record.ChainAfter(from.Seq, from.ID)
	s.check.started = true
	s.check.ended = record.Kind(link.Kind) == record.KindRunEnd
	s.n = int(from.Seq) + 1
	s.pos += int64(len(data))
	if !atEnd {
		s.pos++ // its "\n"
	}
	return atEnd, nil
}

// lineLink reads a line's chain fields with its id checked against its bytes: the line's own for this
// version, record.LinkOf for a newer one.
func lineLink(data []byte) (record.Link, error) {
	id, err := record.VerifyLine(data)
	if err != nil {
		if _, derr := record.Decode(data); errors.Is(derr, record.ErrNewerVersion) {
			return record.LinkOf(data)
		}
		return record.Link{}, err
	}
	e, err := record.Decode(data)
	if err != nil {
		return record.Link{}, err
	}
	return record.Link{V: e.V, Seq: e.Seq, ID: id, Prev: e.Prev, Run: e.Run, Kind: string(e.Kind)}, nil
}
