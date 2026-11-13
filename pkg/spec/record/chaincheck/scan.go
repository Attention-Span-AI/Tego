// SPDX-License-Identifier: Apache-2.0

package chaincheck

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"math"
)

// MaxLineBytes bounds one line of events.jsonl or chain.log as a reader takes it, its "\n" included (CHAIN.md §2).
// The Writer never writes a line past a few hundred KiB (R10 splits every field over 4 KiB into a blob), and the
// files are bytes a tamperer can write (E16): read whole, a line the size of the file cost that much heap. A longer
// line is a corrupt ledger.
const MaxLineBytes = 2 << 20

// Line is one line of a file as framed: Data without its "\n", and whether that "\n" was present. Only the last
// line of a file can lack it.
type Line struct {
	Data       []byte
	Terminated bool
}

// ScanLines yields every line of f from byte 0 using positional reads, so concurrent iterations over one
// descriptor never interfere. The final line is yielded with Terminated false when it lacks "\n"; the caller
// applies the torn-line rule (WholeLine). Read errors, and a line past MaxLineBytes (ErrCorruptLedger, ErrLineTooLong),
// are yielded once and end the sequence.
func ScanLines(f io.ReaderAt) iter.Seq2[Line, error] { return ScanLinesSized(f, 64<<10) }

// ScanLinesSized is ScanLines with a read buffer of size bytes; a caller that wants a line or two asks for a small
// one (a line longer than the buffer is still read whole).
func ScanLinesSized(f io.ReaderAt, size int) iter.Seq2[Line, error] {
	return func(yield func(Line, error) bool) {
		br := bufio.NewReaderSize(io.NewSectionReader(f, 0, math.MaxInt64), size)
		for n := 1; ; n++ {
			data, err := ReadLine(br)
			if errors.Is(err, ErrLineTooLong) {
				yield(Line{}, coded(ErrLineTooLong,
					fmt.Errorf("%w %d: longer than %d bytes", ErrCorruptLedger, n, MaxLineBytes)))
				return
			}
			if err != nil && !errors.Is(err, io.EOF) {
				yield(Line{}, fmt.Errorf("ledger: read events: %w", err))
				return
			}
			if len(data) == 0 {
				return
			}
			terminated := data[len(data)-1] == '\n'
			if terminated {
				data = data[:len(data)-1]
			}
			if !yield(Line{Data: data, Terminated: terminated}, nil) || !terminated {
				return
			}
		}
	}
}

// ReadLine is bufio.Reader.ReadBytes('\n') that gives up past MaxLineBytes (ErrLineTooLong) instead of growing
// without bound.
func ReadLine(br *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(line)+len(chunk) > MaxLineBytes {
			return nil, ErrLineTooLong
		}
		line = append(line, chunk...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return line, err
	}
}

// WholeLine recognizes a closed JSON container independently of its grammar, depth or record fields.
// Full validation belongs to the checker: none of its refusals may hide a closed final record as a torn tail.
// Once a value closes, its entire chunk is a line, including any suffix the checker must refuse.
// JSON scalars are whole once their grammar reads a value; they fail the record's object requirement.
func WholeLine(data []byte) bool {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return false
	}
	if data[0] != '{' && data[0] != '[' {
		var value json.RawMessage
		return json.NewDecoder(bytes.NewReader(data)).Decode(&value) == nil
	}
	stack := make([]byte, 0, 32)
	quoted, escaped := false, false
	for _, c := range data {
		if quoted {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				quoted = false
			}
			continue
		}
		switch c {
		case '"':
			quoted = true
		case '{', '[':
			stack = append(stack, c)
		case '}', ']':
			if len(stack) == 0 {
				return false
			}
			open := stack[len(stack)-1]
			if (c == '}' && open != '{') || (c == ']' && open != '[') {
				return false
			}
			stack = stack[:len(stack)-1]
			if len(stack) == 0 {
				return true
			}
		}
	}
	return false
}
