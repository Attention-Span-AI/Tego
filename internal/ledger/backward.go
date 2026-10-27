// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"iter"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// backBlock is how much of events.jsonl Backward reads per step back from the end: a few dozen lines, so a caller
// that wants the newest one reads about one block, whatever the ledger's length.
const backBlock = 16 << 10

// Backward yields the ledger's complete lines from the last to the first, each with its decoded event, reading the
// file from its end: a caller that stops at the newest line it wants reads only the lines after it, not the ledger
// (tego events --last). The lines are Lines' and the decoding is Entries': every terminated line, and an
// unterminated last line only when it decodes; a torn tail is passed over, unless the line before it is run_end,
// which is ErrCorruptLedger naming the tail's offset; a line that does not decode is ErrCorruptLedger naming its line
// number and offset, except a newer version's line once SkipNewerVersions is set, which is skipped and counted. A
// line longer than MaxLineBytes is ErrCorruptLedger. The line number in an error is counted from byte 0 when the
// error is reported, the one time Backward reads the file before the line.
//
// What it does not read it does not check: damage before the line a caller stops at is not reported, as State does
// not report it (§4); a full pass (Iter, Entries) or Verify does. The file is read up to its size when the call
// starts, by positional reads: a live Writer only appends after it (E19), so the bytes read never change, and a
// line it is writing then is a torn tail.
func (r *Reader) Backward() iter.Seq2[Entry, error] {
	return func(yield func(Entry, error) bool) {
		skipped := 0
		defer func() { r.newer = max(r.newer, skipped) }()
		st, err := r.f.Stat()
		if err != nil {
			yield(Entry{}, fmt.Errorf("ledger: stat events: %w", err))
			return
		}
		block := backBlock
		if r.scanSize > 0 {
			block = r.scanSize
		}
		b := &backScanner{f: r.f, end: st.Size(), block: block}
		torn := false
		var tornOff, tornLen int64
		for first := true; ; first = false {
			l, ok, err := b.prev()
			if err != nil {
				yield(Entry{}, r.lineError(err))
				return
			}
			if !ok {
				return
			}
			if first && !l.terminated && !wholeLine(l.data) {
				torn, tornOff, tornLen = true, l.off, int64(len(l.data))
				continue // a torn tail: never a line (E6)
			}
			if torn {
				torn = false
				if afterRunEnd(l.data) {
					n, nerr := lineNumberAt(r.f, tornOff)
					if nerr != nil {
						yield(Entry{}, nerr)
						return
					}
					yield(Entry{}, fmt.Errorf("%w %d: %d bytes at byte offset %d after run_end are not a record",
						ErrCorruptLedger, n, tornLen, tornOff))
					return
				}
			}
			e, err := record.Decode(l.data)
			if err != nil && r.skipNewer && errors.Is(err, record.ErrNewerVersion) {
				skipped++
				continue
			}
			if err != nil {
				n, nerr := lineNumberAt(r.f, l.off)
				if nerr != nil {
					yield(Entry{}, nerr)
					return
				}
				yield(Entry{}, fmt.Errorf("%w %d: at byte offset %d: %w", ErrCorruptLedger, n, l.off, err))
				return
			}
			if !yield(Entry{Line: l.data, Event: e}, nil) {
				return
			}
		}
	}
}

// lineError is a backScanner error as Lines words it: a line past MaxLineBytes names its line number.
func (r *Reader) lineError(err error) error {
	var long *lineTooLongError
	if !errors.As(err, &long) {
		return err
	}
	n, nerr := lineNumberAt(r.f, long.off)
	if nerr != nil {
		return nerr
	}
	return fmt.Errorf("%w %d: longer than %d bytes", ErrCorruptLedger, n, MaxLineBytes)
}

// backLine is one line as backScanner found it: its bytes without the "\n", the offset they start at, and whether
// a "\n" ended them.
type backLine struct {
	data       []byte
	off        int64
	terminated bool
}

// lineTooLongError is a line past MaxLineBytes, starting at or before off.
type lineTooLongError struct{ off int64 }

func (e *lineTooLongError) Error() string {
	return fmt.Sprintf("ledger: line at byte offset %d too long", e.off)
}

// backScanner splits the first end bytes of a file into lines from the last to the first. buf holds the file's
// bytes [lo, end); prev takes the line that ends at end and moves end to its start.
type backScanner struct {
	f       io.ReaderAt
	end     int64
	lo      int64
	buf     []byte
	block   int
	started bool
	done    bool
}

// prev returns the line before the ones already returned; ok is false at the start of the file.
func (b *backScanner) prev() (backLine, bool, error) {
	if b.done {
		return backLine{}, false, nil
	}
	terminated := true
	if !b.started {
		b.started = true
		b.lo = b.end
		if b.end == 0 {
			b.done = true
			return backLine{}, false, nil
		}
		if err := b.grow(b.block); err != nil {
			return backLine{}, false, err
		}
		if b.buf[len(b.buf)-1] == '\n' {
			b.end-- // the last line's "\n"; nothing follows it
			b.buf = b.buf[:len(b.buf)-1]
		} else {
			terminated = false
		}
	}
	// The longest line Lines takes: MaxLineBytes with its "\n", or MaxLineBytes for the unterminated last one.
	limit := int64(MaxLineBytes - 1)
	if !terminated {
		limit = MaxLineBytes
	}
	for want := b.block; ; want = min(2*want, MaxLineBytes) {
		if i := bytes.LastIndexByte(b.buf, '\n'); i >= 0 {
			start := b.lo + int64(i) + 1
			if b.end-start > limit {
				return backLine{}, false, &lineTooLongError{off: start}
			}
			l := backLine{data: bytes.Clone(b.buf[i+1:]), off: start, terminated: terminated}
			b.buf, b.end = b.buf[:i], start-1 // drop the line and the "\n" before it, which ends the next one
			return l, true, nil
		}
		if b.end-b.lo > limit {
			return backLine{}, false, &lineTooLongError{off: b.lo}
		}
		if b.lo == 0 {
			l := backLine{data: bytes.Clone(b.buf), off: 0, terminated: terminated}
			b.buf, b.done = nil, true
			return l, true, nil
		}
		if err := b.grow(want); err != nil { // a line longer than the buffer: read further back, more each time
			return backLine{}, false, err
		}
	}
}

// grow reads up to size bytes before lo into buf.
func (b *backScanner) grow(size int) error {
	n := min(int64(size), b.lo)
	chunk := make([]byte, n, n+int64(len(b.buf)))
	got, err := b.f.ReadAt(chunk, b.lo-n)
	if int64(got) < n {
		if err == nil || errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF // the file shrank: a ledger never does
		}
		return fmt.Errorf("ledger: read events: %w", err)
	}
	b.buf = append(chunk, b.buf...)
	b.lo -= n
	return nil
}

// lineNumberAt is the number, counted from 1, of the line that starts at byte off: one more than the "\n" bytes
// before it.
func lineNumberAt(f io.ReaderAt, off int64) (int, error) {
	n := 1
	buf := make([]byte, 64<<10)
	for pos := int64(0); pos < off; {
		want := min(int64(len(buf)), off-pos)
		got, err := f.ReadAt(buf[:want], pos)
		n += bytes.Count(buf[:got], []byte{'\n'})
		pos += int64(got)
		if int64(got) < want {
			if err == nil || errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return 0, fmt.Errorf("ledger: read events: %w", err)
		}
	}
	return n, nil
}
