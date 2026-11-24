// SPDX-License-Identifier: Apache-2.0

package askpair

import (
	"cmp"
	"crypto/sha256"
	"slices"
)

// Words are what every reader says of a malformed ask, so one record reads the same in each. Each reader shows them in
// its own place (the receipt's coverage notes, `tego status`'s ledger anomalies, the dashboard's refused lines).
const (
	// RepeatedWords is said of an ask line whose ask id was already asked.
	RepeatedWords = "an ask was recorded twice"
	// UnpairedWords is said of an answer line that pairs with no ask: it came before its ask, names an id never asked,
	// or answers an ask that already has its answer.
	UnpairedWords = "an answer has no ask before it"
)

// Result is what Book.Ask made of an ask line.
type Result int

const (
	// Opened: the first ask line of its id; the question is open until its answer.
	Opened Result = iota
	// Repeated: the id was asked before (the question is open or answered). The line is malformed and changes nothing.
	Repeated
	// Refused: the book's bound is passed; nothing changed. A later answer for the id is Dropped, not unpaired.
	Refused
)

// Answered is what Book.Answer made of an answer line.
type Answered int

const (
	// Paired: the answer closes its open ask.
	Paired Answered = iota
	// Dropped: the answer is to an ask the bound refused (Refused); it is no malformed line and holds no ask.
	Dropped
	// Unpaired: the answer pairs with no ask: it came before its ask, names an id never asked, or answers an ask that
	// was answered already. It never counts as an answer, and it is malformed.
	Unpaired
)

type digest [16]byte

func digestOf(id string) digest {
	s := sha256.Sum256([]byte(id))
	return digest(s[:16])
}

// Book is a run's asks by ask id, the one rule that pairs an ask line with its answer line. The first ask line of an id
// opens the question; each later ask line of the id is Repeated (malformed) and changes nothing, and the answer pairs with
// the first. An answer line pairs only with an open ask, and closes it; any other answer is Unpaired (malformed) and is
// never counted as answered. An ask that never gets an answer stays open: unanswered. T is what the reader keeps of an
// open ask; Each lists the open asks in the order their ids were first asked. A Book remembers every id it has seen
// (16 bytes of its hash each, so a long run's history stays small), and its bounds apply to the open asks only.
// The zero value is not ready: use NewBook.
type Book[T any] struct {
	open     map[string]slot[T]
	closed   map[digest]struct{} // ids answered
	dropped  map[digest]struct{} // ids refused by the bound
	next     uint64              // the first-asked rank the next new id takes
	bytes    int64
	maxIDs   int
	maxBytes int64
	repeated int
	unpaired int
}

type slot[T any] struct {
	v     T
	bytes int64
	rank  uint64 // when the id was first asked, among the ids
}

// NewBook is an empty Book that holds at most maxIDs open asks and maxBytes of the weight the reader gives them (Ask's
// bytes); a zero bound is no bound.
func NewBook[T any](maxIDs int, maxBytes int64) *Book[T] {
	return &Book[T]{open: map[string]slot[T]{}, closed: map[digest]struct{}{}, dropped: map[digest]struct{}{}, maxIDs: maxIDs, maxBytes: maxBytes}
}

// Ask takes an ask line naming id, which the reader keeps as v and which weighs bytes.
func (b *Book[T]) Ask(id string, v T, bytes int64) Result {
	d := digestOf(id)
	if _, ok := b.open[id]; ok {
		b.repeated++
		return Repeated
	}
	if _, ok := b.closed[d]; ok {
		b.repeated++
		return Repeated
	}
	if _, ok := b.dropped[d]; ok {
		b.repeated++
		return Repeated
	}
	if (b.maxIDs > 0 && len(b.open) >= b.maxIDs) || (b.maxBytes > 0 && b.bytes+bytes > b.maxBytes) {
		b.dropped[d] = struct{}{}
		return Refused
	}
	b.open[id] = slot[T]{v, bytes, b.next}
	b.next++
	b.bytes += bytes
	return Opened
}

// Answer takes an answer line naming id. For Paired it returns what the reader kept of the ask, which is now closed.
func (b *Book[T]) Answer(id string) (T, Answered) {
	var zero T
	d := digestOf(id)
	if s, ok := b.open[id]; ok {
		delete(b.open, id)
		b.bytes -= s.bytes
		b.closed[d] = struct{}{}
		return s.v, Paired
	}
	if _, ok := b.dropped[d]; ok {
		delete(b.dropped, d)
		b.closed[d] = struct{}{}
		return zero, Dropped
	}
	b.unpaired++
	return zero, Unpaired
}

// Repeated is how many ask lines repeated an id already asked.
func (b *Book[T]) Repeated() int { return b.repeated }

// Unpaired is how many answer lines paired with no ask.
func (b *Book[T]) Unpaired() int { return b.unpaired }

// Get is the open ask id.
func (b *Book[T]) Get(id string) (T, bool) {
	s, ok := b.open[id]
	return s.v, ok
}

// Len is how many asks are open.
func (b *Book[T]) Len() int { return len(b.open) }

// Bytes is the weight of the open asks.
func (b *Book[T]) Bytes() int64 { return b.bytes }

// Each calls f with each open ask in the order its id was first asked, until f returns false.
func (b *Book[T]) Each(f func(id string, v T) bool) {
	ids := make([]string, 0, len(b.open))
	for id := range b.open {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, c string) int { return cmp.Compare(b.open[a].rank, b.open[c].rank) })
	for _, id := range ids {
		if !f(id, b.open[id].v) {
			return
		}
	}
}

// Held is the last action line with verdict ask: what an ask line that names nothing of its own asks about. This is the
// one fallback of an ask line's operation, target and rule, taken by every reader.
type Held struct {
	Op, Target, Rule string
	set              bool
}

// Note records the action line with verdict ask the reader has just taken.
func (h *Held) Note(op, target, rule string) { h.Op, h.Target, h.Rule, h.set = op, target, rule, true }

// Fill fills each of op, target and rule that an ask line left empty from the held line, when there is one.
func (h *Held) Fill(op, target, rule *string) {
	if !h.set {
		return
	}
	if *op == "" {
		*op = h.Op
	}
	if *target == "" {
		*target = h.Target
	}
	if *rule == "" {
		*rule = h.Rule
	}
}
