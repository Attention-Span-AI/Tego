// SPDX-License-Identifier: Apache-2.0

package record

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
)

// Chain verifies one run's lines in order: every id matches its bytes (R2), seq is gapless from 0 (I4) and
// prev names the previous id, "" for the first line (I3). It is pure: the ledger's verifier and the fixture
// tests both feed it lines. The zero value is ready to use.
type Chain struct {
	next uint64
	head string
}

// ChainAfter is the chain that has verified every line up to and including line seq, whose id is id: the next
// line must carry seq+1 and prev id. It is how a reader resumes from a line it checked earlier (the ledger
// follower's cursor) without hashing the lines before it again; the caller vouches for that earlier check, and
// confirms the line at its resume point still carries seq and id before it trusts them.
func ChainAfter(seq uint64, id string) Chain { return Chain{next: seq + 1, head: id} }

// Add verifies line as the next link and returns its decoded event. On error the chain is unchanged, so the
// caller can report the line number (Len) at which verification failed.
func (c *Chain) Add(line []byte) (*Event, error) {
	id, err := VerifyLine(line)
	if err != nil {
		// A newer version's line has another prefix: say so (ErrNewerVersion), so the caller can take it to
		// AddNewer rather than report it malformed.
		if _, derr := Decode(line); errors.Is(derr, ErrNewerVersion) {
			return nil, fmt.Errorf("line %d: %w", c.next, derr)
		}
		return nil, fmt.Errorf("line %d: %w", c.next, err)
	}
	e, err := Decode(line)
	if err != nil {
		return nil, fmt.Errorf("line %d: %w", c.next, err)
	}
	if e.Seq != c.next {
		return nil, fmt.Errorf("line %d: %w: seq %d, want %d", c.next, ErrCorruptChain, e.Seq, c.next)
	}
	if e.Prev != c.head {
		return nil, fmt.Errorf("line %d: %w: prev %q, want %q", c.next, ErrCorruptChain, e.Prev, c.head)
	}
	c.next++
	c.head = id
	return e, nil
}

// Len is the number of verified lines, which is also the seq the next line must carry.
func (c *Chain) Len() uint64 { return c.next }

// Head is the id of the last verified line; "" before the first.
func (c *Chain) Head() string { return c.head }

// Link is what the chain reads of a line a newer record version wrote: the fields the chain covers, which keep
// their names and positions across versions (v, seq and id the first three keys, prev a string), and the run
// and kind when they read as strings.
type Link struct {
	V         int
	Seq       uint64
	ID, Prev  string
	Run, Kind string
}

// AddNewer verifies a line whose v is newer than this reader's (ErrNewerVersion from Decode) as the next link:
// the chain covers the line's bytes, not its schema, so the id must still be the digest of the line with the
// id zeroed (R2), seq gapless and prev the previous id. The rest of the line is not read. A line that is not
// of a newer version, or whose chain fields do not read, is an error, and the chain is unchanged.
func (c *Chain) AddNewer(line []byte) (Link, error) {
	l, err := readLink(line, c.next)
	if err != nil {
		return Link{}, err
	}
	if l.Seq != c.next {
		return Link{}, fmt.Errorf("line %d: %w: seq %d, want %d", c.next, ErrCorruptChain, l.Seq, c.next)
	}
	if l.Prev != c.head {
		return Link{}, fmt.Errorf("line %d: %w: prev %q, want %q", c.next, ErrCorruptChain, l.Prev, c.head)
	}
	c.next++
	c.head = l.ID
	return l, nil
}

// LinkOf reads a newer version's line as AddNewer does, its id checked against its bytes, but takes it out of
// any chain: seq and prev are returned, not compared. It is for a caller that holds one line, such as the
// last line of a ledger, and needs its kind.
func LinkOf(line []byte) (Link, error) { return readLink(line, 0) }

// readLink reads the link fields of a newer version's line; n is the line number an error names.
func readLink(line []byte, n uint64) (Link, error) {
	line = bytes.TrimSuffix(line, []byte{'\n'})
	fields, err := objectFields(line)
	if err != nil {
		return Link{}, fmt.Errorf("line %d: %w: %w", n, ErrMalformedLine, err)
	}
	var l Link
	get := func(key string) ([]byte, bool) {
		i := slices.IndexFunc(fields, func(f field) bool { return f.key == key })
		if i < 0 {
			return nil, false
		}
		return fields[i].val, true
	}
	vtok, ok := get("v")
	if ok {
		l.V, err = parseInt(vtok)
	}
	if !ok || err != nil || l.V <= Version {
		return Link{}, fmt.Errorf("line %d: %w: v=%s is not a newer version", n, ErrUnsupportedVersion, vtok)
	}
	prefix := []byte(`{"v":` + string(vtok) + `,"seq":`)
	if !bytes.HasPrefix(line, prefix) {
		return Link{}, fmt.Errorf("line %d: %w: v and seq are not the first keys", n, ErrMalformedLine)
	}
	if l.ID, err = verifyDigest(line, len(prefix)); err != nil {
		return Link{}, fmt.Errorf("line %d: %w", n, err)
	}
	stok, _ := get("seq")
	if l.Seq, err = parseUint(stok); err != nil {
		return Link{}, fmt.Errorf("line %d: %w: seq %s", n, ErrMalformedLine, stok)
	}
	ptok, ok := get("prev")
	if !ok {
		return Link{}, fmt.Errorf("line %d: %w: no prev", n, ErrMalformedLine)
	}
	if l.Prev, err = unquote(ptok); err != nil {
		return Link{}, fmt.Errorf("line %d: %w: prev: %w", n, ErrMalformedLine, err)
	}
	if tok, ok := get("run"); ok {
		l.Run, _ = unquote(tok)
	}
	if tok, ok := get("kind"); ok {
		l.Kind, _ = unquote(tok)
	}
	return l, nil
}
