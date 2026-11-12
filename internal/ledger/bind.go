// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
)

// Bound is what one pass over a run's events.jsonl read, bound to its bytes: the receipt's binding block
// (`tego receipt --json`), so a copy of the receipt names the exact record its numbers came from.
type Bound struct {
	// Run, Lines, Head and Ended are Verify's (with no anchor) over the same lines: the run every line names, how many
	// complete lines chained, the last one's id, and whether it is a run_end.
	Run   string
	Lines uint64
	Head  string
	Ended bool
	// Bytes and SHA256 are the size and sha256 of every byte the pass read: each complete line as stored with its
	// "\n" when it has one, then a torn tail. For a record at rest that is the whole file, what sha256sum prints.
	Bytes  int64
	SHA256 string
	// TornBytes is the size of an unterminated last line that is not a whole line (E6), the last of Bytes.
	TornBytes int
	// Newer is how many lines a newer record version wrote: linked into the chain and counted in Lines.
	Newer int
	// Err is why nothing is bound: a line that breaks the chain or fails validation, a line after run_end, a read
	// that failed, or a pass that stopped before the end of the record. With Err set every other field is zero but Run.
	Err error
}

// Binder binds one pass of Lines (and so of Entries and Iter, which read through it) to the bytes it read. It
// checks each line with the check Verify makes (runCheck, validation on), as the line is scanned and before any
// view decodes or skips it: a view that skips newer-version lines (SkipNewerVersions) still has them bound, and a
// receipt computed in the same pass binds exactly the lines its numbers came from, even for a run still growing.
type Binder struct {
	check runCheck
	sum   hash.Hash
	bytes int64
	torn  int
	newer int
	err   error
	done  bool
}

// errPassStopped is a Binder whose pass ended before the end of the record.
var errPassStopped = errors.New("the pass stopped before the end of the record")

// Bind returns a Binder that the next pass of Lines over r feeds, and only that pass: a later pass does not change
// what it bound. The run every line must name is the run directory's name when that is a run id, as Verify takes it.
func (r *Reader) Bind() *Binder {
	b := &Binder{check: runCheck{validate: true}, sum: sha256.New()}
	if want := runDirName(r.dir); IsRunID(want) {
		b.check.run = want
	}
	r.binder = b
	return b
}

// takeBinder hands the Binder Bind attached to the pass starting now, and detaches it.
func (r *Reader) takeBinder() *Binder {
	b := r.binder
	r.binder = nil
	return b
}

// line binds one scanned line: its bytes, and, until the chain breaks, its place in the chain.
func (b *Binder) line(l rawLine) {
	if b == nil {
		return
	}
	b.write(l.data, l.terminated)
	if b.err != nil {
		return
	}
	if b.check.ended {
		b.err = fmt.Errorf("line %d follows run_end", b.check.chain.Len())
		return
	}
	_, newer, err := b.check.add(l.data)
	if err != nil {
		b.err = err
		return
	}
	if newer {
		b.newer++
	}
}

// tornTail binds an unterminated tail that is no line: its bytes are hashed and counted, and after run_end it is
// bytes somebody else put there, as Verify reports them.
func (b *Binder) tornTail(data []byte) {
	if b == nil {
		return
	}
	b.write(data, false)
	b.torn = len(data)
	if b.err == nil && b.check.ended {
		b.err = fmt.Errorf("%d bytes after run_end", len(data))
	}
}

// fail binds nothing: the pass met an error it yields to its reader.
func (b *Binder) fail(err error) {
	if b != nil && b.err == nil {
		b.err = err
	}
}

// end marks the pass as having read the record to its end.
func (b *Binder) end() {
	if b != nil {
		b.done = true
	}
}

func (b *Binder) write(data []byte, terminated bool) {
	b.sum.Write(data) // a hash.Hash's Write never fails
	b.bytes += int64(len(data))
	if terminated {
		b.sum.Write([]byte{'\n'})
		b.bytes++
	}
}

// Bound is what the pass bound. A pass that did not reach the end of the record, or a record whose chain breaks,
// binds no head (Bound.Err).
func (b *Binder) Bound() Bound {
	switch {
	case b.err != nil:
		return Bound{Run: b.check.run, Err: b.err}
	case !b.done:
		return Bound{Run: b.check.run, Err: errPassStopped}
	}
	return Bound{
		Run: b.check.run, Lines: b.check.chain.Len(), Head: b.check.chain.Head(), Ended: b.check.ended,
		Bytes: b.bytes, SHA256: hex.EncodeToString(b.sum.Sum(nil)), TornBytes: b.torn, Newer: b.newer,
	}
}
