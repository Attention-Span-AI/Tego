// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"errors"
	"fmt"
	"sort"
	"sync"
)

// Defaults for the bounds of §11 "Exact numeric caps": this package's own, no normative document sets
// them, and M2 confirms them against real traffic.
const (
	// DefaultMaxHeaderBytes is R13's header block cap, Envoy's default.
	DefaultMaxHeaderBytes = 64 << 10
	// DefaultMaxHeaderLines is R13's line cap.
	DefaultMaxHeaderLines = 128
	// DefaultMaxPipeline: requests queued on one connection awaiting their responses.
	DefaultMaxPipeline = 8
	// DefaultMaxConns bounds the live connection table of one run, so a process opening connections
	// faster than it closes them cannot grow the assembler without bound.
	DefaultMaxConns = 4096
	// DefaultMaxBody bounds one message body held in launcher memory.
	//
	// R14 asks for no total cap, because bodies are meant to stream to the blob writer as they decode.
	// This package assembles a whole body in memory instead (the streaming handoff is not wired: uprobe
	// blobs the finished Message.Body), so "no cap" here is "no bound on the launcher's address space",
	// and the bytes are chosen by whatever server the traced agent talks to. A compressed body makes that
	// asymmetric: a few hundred KiB of gzip expands without limit. The launcher is the process holding the
	// ledger writer and the seccomp supervisor, so an OOM there ends enforcement and the audit trail
	// together and leaves no gap behind to explain it, which is exactly what I4 forbids.
	//
	// 64 MiB is the smallest power of two that keeps the "32 MB body handled" acceptance whole with
	// headroom; past it the body is cut and the message marked Truncated, a recorded loss rather than a
	// silent one. Lifting it again is what implementing R14's streaming blob writer buys.
	DefaultMaxBody = 64 << 20
)

// Options bound one Assembler. The zero value is the defaults above, which is what every caller but a
// test wants.
//
// docs/p0/capture-derive.md §4 sketches NewAssembler(maxHeader, maxChunk int); the two ints are not enough
// for the five bounds R11, R13 and R14 actually name, so they are a struct here and the body window is not
// a cap at all (R14: bodies stream, only chunks are capped, and only in the kernel).
type Options struct {
	// MaxHeaderBytes and MaxHeaderLines are R13; zero means the defaults.
	MaxHeaderBytes int
	MaxHeaderLines int
	// MaxPipeline is R11's queue depth; zero means DefaultMaxPipeline.
	MaxPipeline int
	// MaxBody bounds one decoded body; zero means DefaultMaxBody. A body that reaches it is cut and its
	// message marked Truncated — this package's own bound under R14's implementation condition, not a
	// peer's framing error, so it costs no gap. NewAssembler never leaves it unset: every conn is built
	// from these Options, and an unbounded body is unbounded launcher memory.
	MaxBody int64
	// MaxConns bounds the connection table; zero means DefaultMaxConns.
	MaxConns int
	// MaxBytes bounds every body in flight on every connection together, counted by the capacity of the
	// arrays that hold them; zero means DefaultMaxBytes, and a value below three MaxBody-sized arrays is
	// raised to that (NewBudget). A body the budget cuts is marked Truncated and counted as a gap
	// why=size-cap (R14). The caller shares it through Budget for the bodies it keeps itself.
	MaxBytes int64
	// BodyScanner, when set, makes the scanner a request body is fed to once it stops being kept whole
	// (Message.MaxTokens): a body kept only as a prefix does not parse, and the value a cut stream is bounded by
	// is read off every byte instead (R10). This package knows no provider, so the capture wiring
	// supplies it (the uprobe source: anthropic.MaxTokensScanner). Nil reads nothing, and MaxTokens stays 0.
	BodyScanner func() BodyScanner
	// OnGap is called as each gap happens, for a caller that emits a gap event per occurrence rather
	// than one per reason at run_end. Nil records the gap in Gaps only.
	OnGap func(Gap)
}

// Assembler reassembles every connection of one run. One Assembler is private to one capture source (the uprobe
// source's; the forwarder does not use one), and is closed for good by that source's Stop (CloseAll). Feed
// and Close are safe from that source's drain and Stop at the same time.
type Assembler struct {
	opts Options

	// budget bounds every body the assembler holds, and whatever its caller reserves from it (Budget).
	budget *Budget
	// allow is the allowance of the call in progress, shared by every connection it touches (feedAllowance).
	allow feedAllowance

	mu    sync.Mutex
	conns map[ConnKey]*conn
	gaps  map[string]*Gap
	// refused holds the keys the full table turned away, so a stream of chunks on one refused key is one
	// gap, not one per chunk. Bounded by maxRefused; a Close naming a key, or a slot freeing, drops it.
	refused map[ConnKey]struct{}
	closed  bool
	// tick orders connections by last use. A counter, not a clock: this package has no clock of its
	// own (§4, "no internal timeouts") and only needs to know which connection was touched least
	// recently, never how long ago.
	tick uint64
	// retireHint is false once evictLocked's scan found nothing retirable, and true again when a connection
	// may have become so (a feed that leaves one between messages, a gap, an abandon). While it is false a
	// full table is not scanned again: every chunk of a refused key would otherwise cost O(MaxConns) under
	// mu, and an agent holding MaxConns half-sent requests could stall the drain with them.
	retireHint bool
	// scans counts evictLocked's full-table scans, for the test that holds them to one per change.
	scans int
}

// maxRefused bounds the set of keys the full table turned away.
const maxRefused = 4096

// NewAssembler builds an Assembler with the given bounds; the zero Options is the documented defaults.
func NewAssembler(opts Options) *Assembler {
	if opts.MaxHeaderBytes <= 0 {
		opts.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
	if opts.MaxHeaderLines <= 0 {
		opts.MaxHeaderLines = DefaultMaxHeaderLines
	}
	if opts.MaxPipeline <= 0 {
		opts.MaxPipeline = DefaultMaxPipeline
	}
	if opts.MaxConns <= 0 {
		opts.MaxConns = DefaultMaxConns
	}
	if opts.MaxBody <= 0 {
		opts.MaxBody = DefaultMaxBody
	}
	a := &Assembler{opts: opts, budget: NewBudget(opts.MaxBytes, opts.MaxBody), conns: map[ConnKey]*conn{},
		gaps: map[string]*Gap{}, refused: map[ConnKey]struct{}{}, retireHint: true}
	a.allow.budget = a.budget
	return a
}

// beginCallLocked opens the allowance of one call into the assembler and returns what ends it, for the
// call to defer: the decoded bytes of every message the call hands back are bounded together, and their
// reservations go back when it returns (feedAllowance, R15).
func (a *Assembler) beginCallLocked() func() {
	a.allow.begin(a.opts.MaxBody)
	return a.allow.end
}

// Budget is the byte budget every body this assembler holds is reserved from. A caller that keeps a
// Message's body past the Feed that returned it reserves it from here too, so one bound covers both
// (R14).
func (a *Assembler) Budget() *Budget { return a.budget }

// Feed hands one direction of one connection its next run of plaintext and returns every message the bytes
// completed — more than one under pipelining, none while a message is still arriving.
//
// It never panics on any input (fuzzed by FuzzFeed). A framing failure returns an ErrMalformed-wrapped
// error and gaps that connection alone; every other connection keeps its state, because state is per
// ConnKey (R18). A response that answers no request the connection saw, and the tail of a request whose
// head it never saw, return no error: the exchange is passed over as one counted gap and the connection
// goes on (conn.pair, conn.skip, conn.skipRequest). Feed on a connection that already gapped is a no-op
// with no error, which is what lets a caller keep draining a ring buffer without filtering.
func (a *Assembler) Feed(key ConnKey, dir Direction, ch Chunk) ([]*Message, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	defer a.beginCallLocked()()
	if a.closed {
		return nil, fmt.Errorf("%w: assembler closed", ErrClosed)
	}
	c, err := a.connLocked(key)
	if err != nil {
		return nil, err
	}
	if c == nil || c.dead {
		return nil, nil
	}
	msgs, err := c.feed(dir, ch)
	if !a.retireHint && c.retirable() {
		a.retireHint = true
	}
	// R11 puts the overflow gap on the request that was refused and lets the connection continue, so it
	// is recorded here rather than raised as an error: an error would abandon the connection. An exchange
	// passed over for want of its request's start is the same kind of loss, one exchange on a live
	// connection.
	a.drainOverflowLocked(c)
	a.drainUnpairedLocked(c)
	a.drainStarvedLocked(c)
	a.drainDecodeFailedLocked(c)
	if err != nil {
		a.gapForLocked(c, err)
		return msgs, err
	}
	return msgs, nil
}

// drainOverflowLocked records the requests R11's pipeline depth refused since the last feed, one gap
// why=size-cap carrying how many, and leaves the connection alive.
func (a *Assembler) drainOverflowLocked(c *conn) {
	if c.overflow == 0 {
		return
	}
	n := int64(c.overflow)
	c.overflow = 0
	err := fmt.Errorf("%w: %d requests past a pipeline depth of %d", ErrSizeCap, n, a.opts.MaxPipeline)
	a.recordLocked(Gap{Why: GapSizeCap, Count: n, Detail: fmt.Sprintf("%s: %v", c.key, err)})
}

// drainUnpairedLocked records the exchanges the connection passed over since the last drain because capture
// never saw their request whole (conn.pair, conn.skip, conn.skipRequest): one gap why=malformed carrying one
// count per exchange, with the connection left alive. R18 files it under malformed, the reason this package
// has always given a response with no request and a request line that does not parse; what changed is that
// it now costs that exchange alone.
func (a *Assembler) drainUnpairedLocked(c *conn) {
	if c.unpaired == 0 {
		return
	}
	n := int64(c.unpaired)
	c.unpaired = 0
	a.recordLocked(Gap{Why: GapMalformed, Count: n,
		Detail: fmt.Sprintf("%s: %d exchanges passed over, capture having missed the start of their request", c.key, n)})
}

// drainStarvedLocked records the bodies the budget cut since the last drain, one gap why=size-cap each, with
// the connection left alive: the loss is this message's, and its framing is still followed (R14).
func (a *Assembler) drainStarvedLocked(c *conn) {
	if c.starved == 0 {
		return
	}
	n := int64(c.starved)
	c.starved = 0
	a.recordLocked(Gap{Why: GapSizeCap, Count: n,
		Detail: fmt.Sprintf("%s: %d bodies cut short, the run's capture budget of %d bytes being in use", c.key, n,
			a.budget.Limit())})
}

// drainDecodeFailedLocked records the bodies whose content coding failed to decode since the last feed, one
// gap why=malformed each, and leaves the connection alive: the body was framed whole, so only its decoded
// form is lost (R15).
func (a *Assembler) drainDecodeFailedLocked(c *conn) {
	if c.decodeFailed == 0 {
		return
	}
	n := int64(c.decodeFailed)
	err := c.decodeErr
	c.decodeFailed, c.decodeErr = 0, nil
	a.recordLocked(Gap{Why: GapMalformed, Count: n, Detail: fmt.Sprintf("%s: %d bodies failed to decode: %v", c.key, n, err)})
}

// Close flushes a connection: a body still arriving is emitted as far as it got and marked Truncated, a
// half-read header block is a gap and nothing else, and an idle connection produces neither (edge case
// #28). It is idempotent — a second Close returns nothing.
func (a *Assembler) Close(key ConnKey) []*Message {
	a.mu.Lock()
	defer a.mu.Unlock()
	defer a.beginCallLocked()()
	return a.closeLocked(key)
}

// CloseWhere closes every connection whose key match accepts, in a stable order, as Close closes each, and
// returns the keys it closed with the messages they flushed. It is how a producer that learns a connection
// ended by something other than its key says so: the uprobe source's SSL_free record names a process and a
// pointer, and the connections of that process on it are keyed by whichever threads did their I/O
// (R3a). A connection that already gapped is closed too, so its key starts afresh.
func (a *Assembler) CloseWhere(match func(ConnKey) bool) ([]ConnKey, []*Message) {
	a.mu.Lock()
	defer a.mu.Unlock()
	defer a.beginCallLocked()()
	var keys []ConnKey
	for k := range a.conns {
		if match(k) {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	var out []*Message
	for _, k := range keys {
		out = append(out, a.closeLocked(k)...)
	}
	return keys, out
}

// CloseAll flushes every live connection, in a stable order, and marks the assembler closed: the final
// drain of Stop (edge case #28). Later Feed calls return ErrClosed.
func (a *Assembler) CloseAll() []*Message {
	a.mu.Lock()
	defer a.mu.Unlock()
	defer a.beginCallLocked()()
	keys := make([]ConnKey, 0, len(a.conns))
	for k := range a.conns {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	var out []*Message
	for _, k := range keys {
		out = append(out, a.closeLocked(k)...)
	}
	a.closed = true
	return out
}

// closeLocked is Close with the lock already held.
func (a *Assembler) closeLocked(key ConnKey) []*Message {
	delete(a.refused, key)
	c := a.conns[key]
	if c == nil {
		return nil
	}
	delete(a.conns, key)
	if c.dead {
		return nil
	}
	msgs, errs := c.close()
	a.drainUnpairedLocked(c) // a response Close completes can be one passed over
	a.drainStarvedLocked(c)
	a.drainDecodeFailedLocked(c)
	for _, err := range errs {
		a.gapForLocked(c, err)
	}
	return msgs
}

// Idle reports whether a key holds nothing a later chunk could still complete: no connection at all, or one
// that has gapped, or one whose halves both sit between messages with no request waiting for its response.
// The uprobe source asks it when an SSL* moves to another thread, to tell a handoff between exchanges, which
// loses nothing, from I/O of one exchange split across threads, which would mispair (edge case #11).
func (a *Assembler) Idle(key ConnKey) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.conns[key]
	return !ok || c.retirable()
}

// Abandon gaps a connection on its caller's word, as a framing failure would: whatever it held is dropped, it
// hands nothing over, and later chunks on its key are ignored until it is closed. No gap is recorded here:
// the caller knows why the connection cannot be followed and records that (edge case #11). It reports whether
// the key had a live connection.
func (a *Assembler) Abandon(key ConnKey) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.conns[key]
	if !ok || c.dead {
		return false
	}
	c.dead = true
	a.retireHint = true
	c.release()
	return true
}

// Conns is how many connections the assembler is tracking, for the caller's own diagnostics.
func (a *Assembler) Conns() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.conns)
}

// Gaps reports one entry per reason with its count, sorted by reason. A caller turns each into a
// record gap event with what=capture (R37).
func (a *Assembler) Gaps() []Gap {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]Gap, 0, len(a.gaps))
	for _, g := range a.gaps {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Why < out[j].Why })
	return out
}

// connLocked returns the connection for a key, retiring a finished one to make room when the table is full.
// Only when nothing can be retired is a new key one gap why=size-cap and no connection at all, so the table
// can never grow without bound and a run that merely opens many connections never stops being captured.
func (a *Assembler) connLocked(key ConnKey) (*conn, error) {
	if c, ok := a.conns[key]; ok {
		a.touchLocked(c)
		return c, nil
	}
	if len(a.conns) >= a.opts.MaxConns {
		a.evictLocked()
	}
	if len(a.conns) >= a.opts.MaxConns {
		err := fmt.Errorf("%w: %d connections tracked", ErrSizeCap, len(a.conns))
		if _, again := a.refused[key]; again {
			return nil, fmt.Errorf("%w: %w", ErrRefusedAgain, err)
		}
		if len(a.refused) >= maxRefused {
			clear(a.refused)
		}
		a.refused[key] = struct{}{}
		a.recordLocked(Gap{Why: GapSizeCap, Detail: fmt.Sprintf("%s: %v", key, err), Count: 1})
		return nil, err
	}
	c := newConn(key, &a.opts, a.budget, &a.allow)
	delete(a.refused, key)
	a.conns[key] = c
	a.touchLocked(c)
	return c, nil
}

// touchLocked marks a connection as the most recently used.
func (a *Assembler) touchLocked(c *conn) {
	a.tick++
	c.lastUse = a.tick
}

// evictLocked retires one finished connection so a new one can be tracked.
//
// Nothing in this package can know a connection is over: the uprobe source sees SSL_write/SSL_read and no
// SSL_free, so Close(key) is never called for it and entries only ever accumulate. Without this, a run that
// opens more than MaxConns connections — one short-lived TLS client per tool call is enough — would refuse
// every connection after the MaxConns-th for the rest of the run and quietly stop producing the
// ssl_request/ssl_response pairs limits and derive are fed from. Losing one finished connection's ordinal
// counters is a far smaller loss than that, and it is the trade every flow table makes.
//
// Only a retirable connection is a candidate (conn.retirable), so nothing in flight is ever dropped; a
// connection already gapped goes first, then the one idle longest. A retired connection whose key returns
// starts again at message index 0 and with no Seq continuity across the boundary — the one fidelity cost,
// and it lands on connections that have finished rather than on the traffic being captured now.
//
// The scan is O(table) and runs when a new key arrives at a full table and a connection may have become
// retirable since the last scan found none (retireHint). A refused key returns on every chunk, so without
// the hint each of its chunks would scan a table of connections that are all mid-message.
func (a *Assembler) evictLocked() {
	if !a.retireHint {
		return
	}
	a.scans++
	var (
		victim ConnKey
		worst  *conn
	)
	for k, c := range a.conns {
		if !c.retirable() {
			continue
		}
		if worst == nil || betterVictim(c, worst) {
			victim, worst = k, c
		}
	}
	if worst == nil {
		a.retireHint = false
		return
	}
	// retirable() means both halves are between messages with nothing buffered and no request is
	// waiting, so close() here produces neither a message nor a gap: nothing is lost by retiring it.
	a.closeLocked(victim)
}

// betterVictim reports whether c should be retired ahead of cur: a connection that already gapped holds
// nothing but the memo that says to ignore its key, so it always outranks a live idle one; between two of
// the same kind the one idle longest goes.
func betterVictim(c, cur *conn) bool {
	if c.dead != cur.dead {
		return c.dead
	}
	return c.lastUse < cur.lastUse
}

// gapForLocked turns one reassembly error into the gap reason R37 assigns it and abandons the connection.
// The connection's buffers go with it: an abandoned connection is never parsed or flushed again, so
// holding its half-decoded body until Stop would pin memory nothing can ever read.
func (a *Assembler) gapForLocked(c *conn, err error) {
	c.dead = true
	a.retireHint = true
	c.release()
	a.recordLocked(Gap{Why: whyFor(err), Detail: fmt.Sprintf("%s: %v", c.key, err), Count: 1})
}

// recordLocked accumulates a gap by reason and notifies OnGap.
func (a *Assembler) recordLocked(g Gap) {
	cur, ok := a.gaps[g.Why]
	if !ok {
		cur = &Gap{Why: g.Why, Detail: g.Detail}
		a.gaps[g.Why] = cur
	}
	cur.Count += g.Count
	if a.opts.OnGap != nil {
		a.opts.OnGap(g)
	}
}

// whyFor maps a reassembly error onto the closed gap reason set of R37.
func whyFor(err error) string {
	switch {
	case errors.Is(err, ErrHTTP2):
		return GapH2
	case errors.Is(err, ErrSizeCap):
		return GapSizeCap
	default:
		return GapMalformed
	}
}
