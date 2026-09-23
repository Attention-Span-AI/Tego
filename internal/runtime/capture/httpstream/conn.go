// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"bytes"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"
)

// hstate is where one half of a connection stands (R10). A half is Idle before a message, reads its start
// line and header block, then its body under whichever framing the headers declared.
type hstate int

const (
	hsStart   hstate = iota // waiting for a request or status line
	hsHeaders               // inside the header block
	hsBody                  // Content-Length or close-delimited body
	hsChunked               // chunked body
)

// pendingReq is one request awaiting its response: everything the response half needs before it can decide
// its own framing (a response to HEAD carries no body, whatever its headers say).
type pendingReq struct {
	Index  int
	Method string
	// owedAfter is how many requests R11 refused while this one was the newest queued. RFC 9112 §9.3 puts
	// their responses on the wire right after this one's, and they have no entry of their own, so they are
	// counted here, in the place the refused requests took (conn.owed).
	owedAfter int
	// headless is a request capture saw only the tail of (conn.skipRequest): its head was written before
	// the probes were placed (docs/p0/capture-derive.md R4). The entry holds that request's place, so its
	// response is passed over rather than handed to the next request; the exchange was counted when its
	// tail was passed over, so the response costs no second count.
	headless bool
}

// half is one direction's parser. Its buffer holds only what no complete element has consumed yet, so a
// keep-alive connection carrying a thousand messages never grows.
type half struct {
	dir Direction

	state hstate
	// buf is what no complete element has consumed yet. During one feed it may be the caller's Chunk.Data
	// itself (bufAliased), which costs no copy; what is left of it when the feed ends is copied into an
	// array of the half's own, reserved from the assembler's Budget (keepRest, R13).
	buf []byte
	msg *Message
	// bufHeld is the capacity of buf's own array reserved from the Budget, what it has past headAllowance; 0
	// when buf is nil, aliased or within the allowance.
	bufHeld int64
	// bufAliased is buf being the Chunk.Data of the feed in progress, not an array of the half's own.
	bufAliased bool
	// noLF is how many leading bytes of buf are known to hold no '\n', valid while buf still starts at
	// noLFAt: a line arriving a byte at a time is searched from there, each byte once (R13).
	noLF   int
	noLFAt *byte

	hdrBytes   int
	hdrLines   int
	lastHeader string

	framing  bodyFraming
	bodyLeft int64
	chunk    chunkedReader
	// body is the body in flight. Its whole array is reserved from the assembler's Budget (R14),
	// so it is grown by hand (growBody) rather than by bytes.Buffer, whose growth this package could not
	// count before it happened.
	body []byte
	// wire counts every body byte this half consumed for the message in flight, kept or not, so
	// Message.WireBytes is the wire's length when the body was cut or capped.
	wire int64

	count     int  // messages completed on this half
	truncated bool // a chunk the kernel cut belongs to the message in flight (R6)
	// capped is the body in flight having reached Options.MaxBody, which is a different loss from
	// truncated: the kernel delivered the bytes and this package chose not to keep them.
	capped bool
	// cut is the body in flight no longer being kept, although its framing is still followed: the budget
	// had no room for its next bytes (R14), or capture lost some of them (conn.hole, R6).
	// Bytes kept after the cut would follow the ones before it with the loss closed up, a body the wire
	// never carried, so the kept body stays a prefix.
	cut bool
	// sizeCut is the body in flight cut by the budget, the one cause of cut Message.SizeCut reports.
	sizeCut bool
	// skipping is the half passing over the rest of a message whose start line capture never saw
	// (conn.skip, conn.skipRequest). It ends at the next start line.
	skipping bool
	// waited is the request half holding bytes that may yet be a request line, while those bytes may
	// also be the tail of a request capture missed the head of (requestStart). The line they complete is
	// then held to a stricter shape, because the bytes before it may belong to that tail.
	waited bool
	// noRequest is the response in flight answering no request capture saw. It is settled at the first byte
	// of the response the half holds (decided), before its status line is whole: nothing was queued, owed or
	// arriving on the request half then (unanswered). It is passed over when it completes, whatever has been
	// queued since, including between two pieces of its status line. A request's SSL_write is captured on
	// entry to the call (bpf/uprobe_ssl.bpf.c, tego_ssl_write), before the server can have read it, so a
	// request capture saw only after a response's first byte is not what that response answers, and pairing
	// the two would hand every later response to the request before its own (I3).
	noRequest bool
	// decided is noRequest having been settled for the response in flight. It holds until that response
	// completes. A 1xx clears it, because the final response is decided afresh: a request tail passed over
	// after the interim one takes the unseen request's place (skipRequest), and the final response must pop
	// it. skip clears it too, because the bytes it passed over began no message.
	decided bool

	// lastTS and lastNS are when the most recent chunk of this half arrived: a message's End.
	lastTS time.Time
	lastNS uint64
	// A start line can span chunks. Hold its first byte's clocks until it is whole,
	// rather than stamp the message with the chunk that completed the line.
	startTS time.Time
	startNS uint64
	started bool

	// mt reads the request in flight's max_tokens off every body byte once its body stops being kept whole
	// (writeBody, R10); nil until then. newMT makes it (Options.BodyScanner). mtWanted is the
	// body being text (no content coding) and a scanner being configured, and mtLost is bytes of the body lost
	// to capture, after which it reads none.
	mt       BodyScanner
	newMT    func() BodyScanner
	mtWanted bool
	mtLost   bool
}

// conn is one connection's whole state: both halves and the FIFO that pairs them (R10, R15 of §6).
type conn struct {
	key    ConnKey
	opts   *Options
	halves [2]half

	pending []pendingReq
	// owed is how many responses due on the wire before pending[0]'s answer requests R11 refused. Each
	// was counted as a size-cap gap when its request was refused, so its response is passed over rather
	// than paired: pairing it with pending[0] would hand every later response to a request it did not
	// answer. It is refilled from the owedAfter of each entry a response pops.
	owed int
	// overflow counts requests refused by the pairing FIFO at R11's depth that the assembler has not
	// yet turned into a gap; it is drained after every feed, so the gap R11 puts "on that request" is
	// recorded as the request is refused and cannot be lost if the connection dies before Close.
	overflow int
	// unpaired counts exchanges passed over because capture never saw their request whole: a response
	// with no request (pair, skip) or a request with no head (skipRequest). Not yet turned into a gap;
	// drained like overflow, one gap count per lost exchange.
	unpaired int
	// starved counts bodies the budget cut short since the last drain: one gap why=size-cap each, drained
	// like overflow (assembler.go's drainStarvedLocked).
	starved int
	// decodeFailed counts bodies whose content coding failed to decode since the last drain (decodeErr is
	// the last error): one gap why=malformed each, connection left alive (assembler.go's drainDecodeFailedLocked).
	decodeFailed int
	decodeErr    error
	// budget is the assembler's, shared by every connection of the run (R14).
	budget *Budget
	// allow is the assembler's allowance for the call in progress (feedAllowance): what the bodies this
	// call completes may decode to, and the reservations they hold until it returns (R15).
	allow *feedAllowance
	// lastSeq is the Seq of the connection's last numbered chunk, in either direction (Chunk.Seq).
	lastSeq uint32
	dead    bool
	closed  bool
	// tunnel is a connection a 2xx answered CONNECT on: its later bytes are the tunnel's, never parsed
	// (becomeTunnel, ADR 0035).
	tunnel bool
	// lastUse is the assembler's own tick at the last Feed on this connection, so eviction can retire
	// the connection idle longest rather than an arbitrary one (assembler.go's evictLocked).
	lastUse uint64
}

// newConn starts a connection in the Idle state on both halves.
func newConn(key ConnKey, opts *Options, budget *Budget, allow *feedAllowance) *conn {
	c := &conn{key: key, opts: opts, budget: budget, allow: allow}
	c.halves[DirRequest].dir = DirRequest
	c.halves[DirResponse].dir = DirResponse
	return c
}

// half returns the parser for one direction; an out-of-range Direction is treated as the request half
// rather than indexing out of bounds, because the value crosses a package boundary.
func (c *conn) half(dir Direction) *half {
	if dir == DirResponse {
		return &c.halves[DirResponse]
	}
	return &c.halves[DirRequest]
}

// feed appends a chunk to one half and runs the state machine over everything buffered.
func (c *conn) feed(dir Direction, ch Chunk) ([]*Message, error) {
	if c.closed {
		return nil, fmt.Errorf("%w: %s", ErrClosed, c.key)
	}
	if c.tunnel {
		return nil, nil
	}
	h := c.half(dir)
	if ch.Seq != 0 {
		// One sequence for both halves (Chunk.Seq): a chunk lost in either direction is found at the
		// connection's next chunk, which gaps it rather than pair a later response with the wrong request
		// (I2). The count skips 0 when it wraps.
		want := c.lastSeq + 1
		if want == 0 {
			want = 1
		}
		if c.lastSeq != 0 && ch.Seq != want {
			return nil, fmt.Errorf("%w: %s chunk seq %d after %d: a chunk of the connection never reached the "+
				"reader", ErrMalformed, dir, ch.Seq, c.lastSeq)
		}
		c.lastSeq = ch.Seq
	}
	var msgs []*Message
	if dir == DirRequest && c.closeDelimitedEnded(ch.Data) {
		msg, err := c.endCloseDelimited()
		if msg != nil {
			msgs = append(msgs, msg)
		}
		if err != nil {
			return msgs, err
		}
	}
	if ch.Truncated {
		h.truncated, h.mtLost = true, true
	}
	if len(ch.Data) > 0 {
		if err := c.bufferChunk(h, ch.Data); err != nil {
			return msgs, err
		}
	}
	if !ch.TS.IsZero() {
		h.lastTS = ch.TS
	}
	if ch.MonoNS != 0 {
		h.lastNS = ch.MonoNS
	}
	more, err := c.parse(h, ch)
	msgs = append(msgs, more...)
	if err == nil {
		err = c.keepRest(h)
	} else if h.bufAliased {
		h.buf, h.bufAliased = nil, false // the connection is released with the error; never keep the caller's bytes
	}
	if err != nil || ch.Skipped == 0 || c.tunnel {
		return msgs, err
	}
	msg, err := c.hole(h, ch.Skipped)
	if msg != nil {
		msgs = append(msgs, msg)
	}
	return msgs, err
}

// bufferChunk puts a chunk's bytes behind what the half still holds. A half holding nothing parses the chunk
// where it lies (bufAliased), which is every chunk of a body and most of every head: nothing is copied and
// nothing reserved. Only bytes some element is still waiting to complete are kept past the feed (keepRest).
func (c *conn) bufferChunk(h *half, p []byte) error {
	if len(h.buf) == 0 {
		c.dropBuf(h)
		h.buf, h.bufAliased = p, true
		return nil
	}
	return c.growBuf(h, p)
}

// keepRest ends a feed's use of the caller's bytes: what the parse left of them is copied into an array of
// the half's own, and an own array left empty goes back to the budget, so a connection between elements holds
// none.
func (c *conn) keepRest(h *half) error {
	if h.bufAliased {
		rest := h.buf
		noLF, at := h.noLF, h.noLFAt
		h.buf, h.bufAliased = nil, false
		if len(rest) == 0 {
			h.noLF, h.noLFAt = 0, nil
			return nil
		}
		if err := c.growBuf(h, rest); err != nil {
			return err
		}
		if at == &rest[0] {
			h.noLF, h.noLFAt = noLF, &h.buf[0] // the copy holds no '\n' where the chunk held none
		}
		return nil
	}
	if len(h.buf) == 0 {
		c.dropBuf(h)
	}
	return nil
}

// headAllowance is the part of each half's own buffer that is not charged to the Budget. A start line, a
// header line or a chunk-size line split across two feeds is a few dozen bytes; charging it to a Budget that
// other connections' bodies hold in full gapped the whole keep-alive connection over those bytes, where a body
// the Budget cannot hold is only truncated. Uncharged, the allowance adds at most MaxConns × 2 × headAllowance
// to what the Budget bounds (32 MiB at DefaultMaxConns); only a buffer past it is charged, and only for the
// capacity past it.
const headAllowance = 4 << 10

// growBuf appends p to the half's own buffer. An array larger than headAllowance is reserved from the
// assembler's Budget, for its capacity past the allowance, before it exists, like a body's (growBody), and the
// old one's reservation given back once the copy is done. The bytes held here are a start line, a header block
// or a chunk-size line still arriving, bounded per half by R13's caps but not across MaxConns connections:
// 4096 of them each parked on a 63 KiB header grew the launcher by 260 MiB per direction past the budget that
// bounded bodies alone. With no room for the bytes the connection gaps why=size-cap, as a header block over
// R13's cap does: a head capture could not hold is a head it cannot parse, and cutting it would splice the
// header block the pairing rests on.
func (c *conn) growBuf(h *half, p []byte) error {
	need := len(h.buf) + len(p)
	if need <= cap(h.buf) {
		h.buf = append(h.buf, p...)
		return nil
	}
	// Doubling keeps a line arriving a byte at a time from being copied once per byte.
	size := int64(max(need, 2*len(h.buf)))
	var charged int64
	switch {
	case size <= headAllowance:
	case need <= headAllowance:
		size = headAllowance
	case c.budget != nil:
		got := c.budget.Take(size - headAllowance)
		if got < int64(need)-headAllowance {
			c.budget.Give(got)
			return fmt.Errorf("%w: %d unparsed %s bytes, the run's capture budget of %d bytes being in use",
				ErrSizeCap, need, h.dir, c.budget.Limit())
		}
		charged, size = got, got+headAllowance
	}
	next := make([]byte, len(h.buf), size)
	copy(next, h.buf)
	next = append(next, p...)
	kept := len(h.buf) > 0 && h.noLFAt == &h.buf[0]
	c.budget.Give(h.bufHeld)
	h.buf, h.bufHeld = next, charged
	if kept {
		h.noLFAt = &next[0]
	} else {
		h.noLF, h.noLFAt = 0, nil
	}
	return nil
}

// dropBuf gives the buffer's own array back to the budget and forgets the buffer.
func (c *conn) dropBuf(h *half) {
	c.budget.Give(h.bufHeld)
	h.buf, h.bufHeld, h.bufAliased = nil, 0, false
	h.noLF, h.noLFAt = 0, nil
}

// takeLine is takeLine on the half's buffer, searching only bytes not already known to hold no '\n'
// (noLF, R13). Bytes a search finds no line in are remembered, as long as the buffer keeps its start.
func (h *half) takeLine(max int) ([]byte, int, bool) {
	from := 0
	if len(h.buf) > 0 && h.noLFAt == &h.buf[0] {
		from = h.noLF
	}
	line, n, ok := takeLineFrom(h.buf, from, max)
	if !ok && n == 0 && len(h.buf) > 0 {
		h.noLF, h.noLFAt = len(h.buf), &h.buf[0]
	} else {
		h.noLF, h.noLFAt = 0, nil
	}
	return line, n, ok
}

// closeDelimitedEnded reports whether a request chunk means the connection's close-delimited response has
// ended. Such a body ends only when the connection closes (RFC 9112 §6.3, rule 8), and the client cannot send
// another request on a connection the server is about to close, so a request line arriving on this key while
// the response half is in one is a new connection the producer did not see the old one end for: glibc handing a
// freed SSL*'s address to the next SSL_new, with the SSL_free record lost or not seen (R3a). Only whole
// shapes count: the request half at a message boundary with nothing held, and the chunk starting a known method
// and a space.
func (c *conn) closeDelimitedEnded(data []byte) bool {
	r, q := &c.halves[DirResponse], &c.halves[DirRequest]
	if r.state != hsBody || r.framing != framingClose || r.msg == nil {
		return false
	}
	if q.state != hsStart || q.msg != nil || len(bytes.Trim(q.buf, "\r\n")) > 0 {
		return false
	}
	b := bytes.TrimLeft(data, "\r\n")
	i := 0
	for i < len(b) && tokenChar[b[i]] {
		i++
	}
	return i < len(b) && b[i] == ' ' && knownMethod(string(b[:i]))
}

// endCloseDelimited completes the close-delimited response as the connection's close would have (flush), and
// forgets what the ended connection still had queued: requests sent on it that it will never answer, each a
// lost exchange counted as one passed over (unpaired), which must not pair with the new connection's responses.
func (c *conn) endCloseDelimited() (*Message, error) {
	msg, err := c.complete(&c.halves[DirResponse])
	for _, p := range c.pending {
		if !p.headless {
			c.unpaired++
		}
	}
	c.pending, c.owed = nil, 0
	return msg, err
}

// hole accounts for n bytes that followed the chunk just parsed on the wire and never reached the reader
// (Chunk.Skipped). Before this, a call over R6's 128 KiB lost its tail with nothing to say how much: the
// request's Content-Length still counted the lost bytes, so it never completed, its response paired with
// nothing, and the connection gapped with every later exchange on it (R6; CPython hands a whole
// request body to one SSL_write_ex). Edge case #8 promises the prefix is recorded; it is now, and the
// connection goes on.
//
// Only a hole inside a body can be stepped over, because only there does the framing say how far it
// reaches: a Content-Length body, and the data of one chunk of a chunked body, shorten by the hole, and a
// close-delimited body simply ends later. The body keeps the prefix before the hole (cut: bytes after it
// would splice across the loss) and the message is Truncated. A hole that runs past the body's end, or falls
// in a start line, a header block, a chunk-size line or bytes the parser is still waiting to complete, took
// the framing with it, and the connection gaps. So does one on a half passing over a message it never saw the
// start of, which is still passing it over: the hole is more of that message.
func (c *conn) hole(h *half, n uint64) (*Message, error) {
	crossing := func() error {
		return fmt.Errorf("%w: %d %s bytes lost to capture cross the message framing", ErrMalformed, n, h.dir)
	}
	if len(h.buf) > 0 {
		return nil, crossing()
	}
	switch {
	case h.state == hsBody && h.framing == framingClose:
		h.wire += int64(min(n, uint64(math.MaxInt32)))
		h.truncated, h.cut, h.mtLost = true, true, true
		return nil, nil
	case h.state == hsBody:
		if n > uint64(h.bodyLeft) {
			return nil, crossing()
		}
		h.bodyLeft -= int64(n)
		h.wire += int64(n)
		h.truncated, h.cut, h.mtLost = true, true, true
		if h.bodyLeft > 0 {
			return nil, nil
		}
		return c.complete(h)
	case h.state == hsChunked && h.chunk.state == chunkData:
		if n > uint64(h.chunk.left) {
			return nil, crossing()
		}
		h.chunk.left -= int64(n)
		h.wire += int64(n)
		if h.chunk.left == 0 {
			h.chunk.state = chunkCRLF
		}
		h.truncated, h.cut, h.mtLost = true, true, true
		return nil, nil
	case h.state == hsStart && h.skipping:
		return nil, nil
	}
	return nil, crossing()
}

// parse drives one half until it runs out of bytes or needs more. It returns every message the bytes
// completed; an error abandons the connection (the caller turns it into the gap R37 names).
func (c *conn) parse(h *half, ch Chunk) ([]*Message, error) {
	var out []*Message
	for {
		before := len(h.buf)
		msg, err := c.step(h, ch)
		// The message comes first even when the step failed: R15 wants the prefix that decoded
		// emitted alongside the gap, never dropped in favour of the error.
		if msg != nil {
			out = append(out, msg)
		}
		if err != nil {
			return out, err
		}
		if msg == nil && len(h.buf) == before {
			return out, nil // nothing consumed and nothing produced: wait for more bytes
		}
	}
}

// step advances one half by one element: a start line, the header block, or as much body as is buffered.
// It returns a completed message, or nil when the half needs more bytes.
func (c *conn) step(h *half, ch Chunk) (*Message, error) {
	switch h.state {
	case hsStart:
		return nil, c.stepStart(h, ch)
	case hsHeaders:
		return c.stepHeaders(h)
	case hsBody:
		return c.stepBody(h)
	case hsChunked:
		return c.stepChunked(h)
	default:
		return nil, fmt.Errorf("%w: parser in state %d", ErrMalformed, h.state)
	}
}

// stepStart reads a request or status line, skipping the empty lines RFC 9112 §2.2 lets a sender put in
// front of one. An h2 preface on the request half aborts the whole connection before anything is parsed
// (R17).
func (c *conn) stepStart(h *half, ch Chunk) error {
	for len(h.buf) > 0 && (h.buf[0] == '\r' || h.buf[0] == '\n') {
		h.buf = h.buf[1:]
	}
	if len(h.buf) == 0 {
		return nil
	}
	if !h.started {
		h.startTS, h.startNS, h.started = ch.TS, ch.MonoNS, true
	}
	if h.dir == DirRequest {
		if err := checkPreface(h.buf); err != nil {
			return err
		}
		if h.skipping || c.requestResyncable() {
			line, n, ok := h.takeLine(maxStartLine)
			switch requestStart(h.buf, h.waited, line, n, ok) {
			case startTail:
				c.skipRequest(h)
				return nil
			case startWait:
				h.waited = true
				return nil
			}
		}
	}
	if h.dir == DirResponse && !statusLinePrefix(h.buf) && c.unanswered() {
		c.skip(h)
		return nil
	}
	if h.dir == DirResponse && !h.decided {
		// Here and not at the parsed status line: the line can arrive in pieces, and a request queued between
		// them came after this byte (noRequest).
		h.decided = true
		h.noRequest = c.owed == 0 && c.unanswered()
	}
	line, n, ok := h.takeLine(maxStartLine)
	if !ok {
		if n < 0 {
			return fmt.Errorf("%w: start line over %d bytes", ErrMalformed, maxStartLine)
		}
		return nil
	}
	msg := &Message{Key: c.key, Dir: h.dir, Header: http.Header{}, RequestIndex: -1,
		Index: h.count, Start: h.startTS, StartNS: h.startNS}
	h.startTS, h.startNS, h.started = time.Time{}, 0, false
	if h.dir == DirRequest {
		rl, err := parseRequestLine(line)
		if err != nil {
			return err
		}
		msg.Method, msg.Path, msg.Proto = rl.Method, rl.Path, rl.Proto
	} else {
		sl, err := parseStatusLine(line)
		if err != nil {
			return err
		}
		msg.Proto, msg.Status, msg.Reason = sl.Proto, sl.Status, sl.Reason
	}
	h.buf = h.buf[n:]
	h.msg = msg
	h.hdrBytes, h.hdrLines, h.lastHeader = n, 1, ""
	h.state = hsHeaders
	// A start line ends a run of passed-over bytes: whatever is passed over after it is another message's,
	// and is counted again.
	h.skipping, h.waited = false, false
	return nil
}

// requestResyncable reports whether bytes at the request half's message boundary can be the tail of a
// request whose head capture never saw: a probe placed between the SSL_write that carried a request's head
// and the one that carried its body (docs/p0/capture-derive.md R4, edge case 2; httpx writes the two
// apart). That can only be the first request capture sees on the connection, so the request half has
// completed nothing, and so has queued nothing and had nothing refused (R11); a tail already passed over
// holds its own place, but this is not asked while the half is still passing it over (skipping). The
// response half must be between messages with nothing buffered: a response already arriving could be the
// tail's early answer (a 413), and which request it answers is then left to fail closed.
func (c *conn) requestResyncable() bool {
	if c.halves[DirRequest].count > 0 {
		return false
	}
	r := &c.halves[DirResponse]
	return r.msg == nil && len(bytes.Trim(r.buf, "\r\n")) == 0
}

// startKind is what the bytes at a resynchronizable request boundary are (requestStart).
type startKind int

const (
	// startRequest is a request line, or bytes shaped enough like one that the parser's own verdict,
	// ErrMalformed included, is the right one.
	startRequest startKind = iota
	// startTail is the tail of a request whose head capture missed.
	startTail
	// startWait is too few bytes to tell.
	startWait
)

// knownMethods are RFC 9110 §9's methods and RFC 5789's PATCH. Only these can hold bytes back while
// requestStart waits for the rest of a line; see there.
var knownMethods = [...]string{"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"}

func knownMethod(m string) bool {
	for _, k := range knownMethods {
		if m == k {
			return true
		}
	}
	return false
}

// requestStart says whether buf, at a request boundary where requestResyncable holds or a tail is being
// passed over, starts a request. line, n and ok are takeLine's of buf under maxStartLine.
//
// A whole first line starts one when it begins with a known method, or with a token and a space: those are
// parsed as before, and a line of that shape that does not parse gaps the connection (R18) rather than
// being taken for a tail. Anything else — a JSON body's '{', a form body, the rest of a JSON string — is a
// tail.
//
// Waiting for the rest of a line is where a tail could hide: a tail that ends as a known method begins
// would be joined to the next request's line. So the request half waits only on bytes that are a known
// method still arriving or a known method and a space, and a line completed after a wait (waited) starts a
// request only if it has a known method and exactly the two spaces of RFC 9112 §3's request line. A tail
// joined to the next request's line has an unknown method ("P" + "POST") or a third space, so it is passed
// over whole, the next request with it; that request's response is then one with no request, passed over
// and counted in its turn (conn.pair), never paired with the tail.
func requestStart(buf []byte, waited bool, line []byte, n int, ok bool) startKind {
	i := 0
	for i < len(buf) && tokenChar[buf[i]] {
		i++
	}
	method := string(buf[:i])
	switch {
	case waited && ok:
		if knownMethod(method) && bytes.Count(line, []byte(" ")) == 2 {
			return startRequest
		}
		return startTail
	case waited && n < 0:
		return startTail
	case ok || n < 0:
		if knownMethod(method) || (i > 0 && i < len(buf) && buf[i] == ' ') {
			return startRequest
		}
		return startTail
	}
	if i == len(buf) {
		// A token still arriving: wait only if it can still become a known method, or the "PRI" of an h2
		// preface, which checkPreface names once it is whole (R17).
		for _, k := range knownMethods {
			if strings.HasPrefix(k, method) {
				return startWait
			}
		}
		if len(method) <= len("PRI") && method == "PRI"[:len(method)] {
			return startWait
		}
		return startTail
	}
	if (knownMethod(method) || method == "PRI") && buf[i] == ' ' {
		return startWait
	}
	return startTail
}

// skipRequest passes over request bytes that begin no request line where requestResyncable held: the rest
// of a request whose head was written before the probes. Nothing in the tail says where it ends, so whole
// chunks are passed over, none of which holds bytes of two calls, until a chunk starts a request line again. The
// exchange is one gap, counted at its first chunk, and its place in the pairing FIFO is kept (a headless
// entry), so its response is passed over with no second count and the next request pairs with its own.
// Before this, the tail was a malformed request line and every later exchange on the connection was lost
// with it.
func (c *conn) skipRequest(h *half) {
	if !h.skipping {
		h.skipping = true
		c.unpaired++
		c.pending = append(c.pending, pendingReq{Index: -1, headless: true})
	}
	h.buf = h.buf[:0]
	h.startTS, h.startNS, h.started = time.Time{}, 0, false
	h.truncated, h.capped, h.cut, h.sizeCut, h.waited = false, false, false, false, false
	h.wire = 0
}

// statusLinePrefix reports whether buf can be the start of a status line: it begins "HTTP/", or is too
// short to say and agrees with that prefix so far.
func statusLinePrefix(buf []byte) bool {
	const prefix = "HTTP/"
	if len(buf) < len(prefix) {
		return string(buf) == prefix[:len(buf)]
	}
	return string(buf[:len(prefix)]) == prefix
}

// unanswered reports whether the response half's next bytes can answer no request this connection saw:
// none is queued, and the request half holds nothing, neither a message in flight nor bytes of one. Only
// then can a response be passed over without handing any response to a request it did not answer. The
// request half must be empty as well because a server may answer a request before the whole of it has
// arrived (an early 413 or 431); passing that response over would leave the request queued for the next
// response's answer.
func (c *conn) unanswered() bool {
	if len(c.pending) > 0 {
		return false
	}
	h := &c.halves[DirRequest]
	return h.msg == nil && len(bytes.Trim(h.buf, "\r\n")) == 0
}

// skip passes over response bytes that begin no status line while nothing is waiting for an answer
// (unanswered): the rest of a response whose head capture never saw. A uprobe placed while the process
// was already inside the SSL_read that carried a response's head misses that read and sees the ones that
// follow (docs/p0/capture-derive.md R4, edge case 2). Nothing in a body says where it ends, so the half
// passes over whole chunks, none of which holds bytes of two calls, until a chunk starts a status line
// again. The exchange is one gap, counted at its first chunk; before this, those bytes were a malformed
// status line and the connection's every later exchange was lost with them. A response R11's refusal
// already owes was counted with its request and is not counted twice.
func (c *conn) skip(h *half) {
	if !h.skipping {
		h.skipping = true
		if c.owed > 0 {
			c.owed--
		} else {
			c.unpaired++
		}
	}
	h.buf = h.buf[:0]
	h.startTS, h.startNS, h.started = time.Time{}, 0, false
	h.truncated, h.capped, h.cut, h.sizeCut = false, false, false, false
	h.decided, h.noRequest = false, false
	h.wire = 0
}

// checkPreface reports an HTTP/2 connection preface at the head of the request half. The prefix is enough:
// once "PRI * HTTP/2" is on the wire nothing that follows is HTTP/1.1 (R17).
func checkPreface(buf []byte) error {
	const prefix = "PRI * HTTP/2"
	n := len(prefix)
	if len(buf) < n {
		n = len(buf)
	}
	if bytes.HasPrefix([]byte(prefix), buf[:n]) && len(buf) >= len(prefix) {
		return fmt.Errorf("%w: connection preface", ErrHTTP2)
	}
	return nil
}

// stepHeaders consumes the header block a line at a time until the empty line that ends it, then decides
// the body's framing. The caps of R13 apply to the block as a whole, counted in bytes on the wire and in
// lines, and a block over either is one gap for the connection rather than one per offending byte.
func (c *conn) stepHeaders(h *half) (*Message, error) {
	for {
		line, n, ok := h.takeLine(c.opts.MaxHeaderBytes - h.hdrBytes)
		if !ok {
			if n < 0 {
				return nil, fmt.Errorf("%w: header block over %d bytes", ErrSizeCap, c.opts.MaxHeaderBytes)
			}
			return nil, nil
		}
		h.buf = h.buf[n:]
		h.hdrBytes += n
		if len(line) == 0 {
			return c.headersDone(h)
		}
		h.hdrLines++
		if h.hdrLines > c.opts.MaxHeaderLines {
			return nil, fmt.Errorf("%w: header block over %d lines", ErrSizeCap, c.opts.MaxHeaderLines)
		}
		if h.hdrBytes > c.opts.MaxHeaderBytes {
			return nil, fmt.Errorf("%w: header block over %d bytes", ErrSizeCap, c.opts.MaxHeaderBytes)
		}
		name, err := addHeaderLine(h.msg.Header, h.lastHeader, line)
		if err != nil {
			return nil, err
		}
		h.lastHeader = name
	}
}

// headersDone applies RFC 9112 §6.3's framing rules and either completes a bodiless message or moves to
// the body state.
//
// An interim 1xx response is consumed and discarded here, never emitted: the assembler simply waits for
// the next status line as the real response, which handles both a server that sends 100 Continue and one
// that skips it (R12, edge case #16). A 101 that hands the connection to h2c is the h2 gap of R17.
func (c *conn) headersDone(h *half) (*Message, error) {
	msg := h.msg
	if h.dir == DirResponse && msg.Status < 200 {
		if msg.Status == http.StatusSwitchingProtocols {
			if upgradesToH2(msg.Header) {
				return nil, fmt.Errorf("%w: 101 upgrade to %s", ErrHTTP2, msg.Header.Get("Upgrade"))
			}
			return nil, fmt.Errorf("%w: 101 upgrade to %q leaves HTTP/1.1", ErrMalformed, msg.Header.Get("Upgrade"))
		}
		h.msg, h.state, h.lastHeader = nil, hsStart, ""
		h.decided, h.noRequest = false, false
		return nil, nil
	}
	headMethod, tunnel := false, false
	// Only a response that will pair with pending[0] is framed by that request's method. An owed response
	// answers a request R11 refused, whose method was not kept, and one decided at its first byte to answer
	// no request (noRequest) answers one capture never saw: each is framed as a response that may carry a
	// body. A HEAD queued after such a response's first byte is not its request.
	if h.dir == DirResponse && !h.noRequest && c.owed == 0 && len(c.pending) > 0 {
		headMethod = strings.EqualFold(c.pending[0].Method, http.MethodHead)
		// A 2xx to CONNECT has no body: the connection is a tunnel from the blank line on (RFC 9110
		// §9.3.6), and what follows on both halves is the tunnel's bytes, not HTTP (ADR 0035).
		tunnel = c.pending[0].Method == http.MethodConnect && msg.Status >= 200 && msg.Status <= 299
	}
	f, n, err := framing(msg.Header, h.dir == DirResponse, msg.Status, headMethod || tunnel)
	if err != nil {
		return nil, err
	}
	// Repeated field lines are one list (RFC 9110 §5.3): every line is read, not the first.
	msg.ContentEncoding = strings.TrimSpace(strings.Join(msg.Header.Values("Content-Encoding"), ", "))
	if tc := transferCodings(msg.Header); len(tc) > 0 {
		// A transfer coding (gzip, chunked) is undone as a content coding applied last, so the body is
		// never handed on compressed as if it were the content.
		if msg.ContentEncoding != "" {
			msg.ContentEncoding += ", "
		}
		msg.ContentEncoding += strings.Join(tc, ", ")
	}
	// SSE reduction is a response rule (R16): a request's body is kept as sent whatever Content-Type the
	// agent labels it with, or an event-stream label would empty it from the record.
	msg.SSE = h.dir == DirResponse && isEventStream(msg.Header)
	h.framing, h.bodyLeft = f, n
	h.chunk = chunkedReader{}
	if h.dir == DirRequest && c.opts.BodyScanner != nil {
		h.newMT, h.mtWanted = c.opts.BodyScanner, identityCoding(msg.ContentEncoding)
	}
	switch f {
	case framingNone:
		msg, err := c.complete(h)
		if tunnel {
			c.becomeTunnel()
		}
		return msg, err
	case framingChunked:
		h.state = hsChunked
	default:
		h.state = hsBody
	}
	return nil, nil
}

// identityCoding reports whether a Content-Encoding names no coding, so the body's bytes are its text.
func identityCoding(enc string) bool {
	return len(splitEncodings(enc)) == 0
}

// becomeTunnel ends HTTP on the connection: a 2xx answered CONNECT, so every later byte on either half is the
// tunnel's (ADR 0035). Nothing is parsed from here on and nothing is lost: the tunnel carries another
// TLS session, which an HTTPS proxy's client runs through its own SSL*, and capture follows that one as a
// connection of its own where it can read it at all. What the halves still buffer is dropped with the rest.
func (c *conn) becomeTunnel() {
	c.tunnel = true
	for i := range c.halves {
		h := &c.halves[i]
		c.dropBuf(h)
		h.msg, h.state = nil, hsStart
		h.dropBody(c.budget)
		h.mt, h.mtWanted, h.mtLost = nil, false, false
	}
}

// writeBody appends as much of p to the message in flight as Options.MaxBody and the assembler's Budget
// still allow, recording on the half when it had to drop bytes so the completed message can say it is
// truncated.
//
// The cap has to be applied here rather than only at completion. A body is assembled in memory before
// anything looks at its size, so a cap checked at the end bounds what is kept and not what is held: a
// peer that sends a gigabyte makes this process allocate a gigabyte first and shrink it afterwards.
// The launcher is the trusted process in this design and the bytes are chosen by whatever server the
// agent is talking to, so the bound belongs on the write. MaxBody bounds one body and the Budget all of
// them together (R14); a body the budget cuts is counted, one gap why=size-cap, where one that
// reaches MaxBody is this package's own bound and costs none.
//
// Dropping bytes does not stop the parse. Framing state is what keeps the two halves paired (R10), so
// the reader goes on consuming exactly as it would have; only the buffer stops growing. b is nil only for
// a half built by hand, which is then bounded by MaxBody alone.
func (h *half) writeBody(p []byte, maxBody int64, b *Budget) (starved bool) {
	if maxBody <= 0 {
		// NewAssembler always sets one, so this is only reachable from a hand-built Options; an
		// unset cap still has to be a bound, because unbounded here is unbounded launcher memory.
		maxBody = DefaultMaxBody
	}
	h.wire += int64(len(p))
	if h.mt != nil {
		_, _ = h.mt.Write(p)
	}
	if len(p) == 0 || h.cut {
		return false
	}
	n := int64(len(p))
	if room := maxBody - int64(len(h.body)); n > room {
		n = room
		h.capped = true
	}
	if n > 0 {
		if room := h.growBody(n, maxBody, b); room < n {
			n = room
			h.cut, starved = true, true
		}
	}
	if n < int64(len(p)) && h.mtWanted && h.mt == nil && !h.mtLost {
		// The body stops being kept whole here, so derive will not parse it: its max_tokens is read off every
		// byte from here on, starting with what was kept (Options.BodyScanner, R10). A body kept
		// whole costs nothing of this.
		h.mt = h.newMT()
		_, _ = h.mt.Write(h.body)
		_, _ = h.mt.Write(p)
	}
	if n <= 0 {
		return starved
	}
	h.body = append(h.body, p[:n]...)
	return starved
}

// growBody makes room for n more body bytes, up to maxBody, and returns the room there now is, which is less
// than n when the budget could not pay for the array n needs. A new array is reserved in full before it
// exists and the old one goes back once the copy is done, since both are live until then; one the budget
// can only partly pay for is still taken when it is larger than the old, so the body keeps what it can.
func (h *half) growBody(n, maxBody int64, b *Budget) int64 {
	length, capacity := int64(len(h.body)), int64(cap(h.body))
	need := length + n
	if need <= capacity {
		return n
	}
	// Doubling keeps a body that arrives in chunks from being copied once per chunk; the first array is
	// the size of what is in hand.
	size := min(max(need, 2*capacity), maxBody)
	if b == nil {
		next := make([]byte, length, size)
		copy(next, h.body)
		h.body = next
		return n
	}
	got := b.Take(size)
	if got <= capacity {
		b.Give(got)
		return capacity - length
	}
	next := make([]byte, length, got)
	copy(next, h.body)
	b.Give(capacity)
	h.body = next
	return min(n, got-length)
}

// dropBody gives the body's array back to the budget and forgets it.
func (h *half) dropBody(b *Budget) {
	if b != nil {
		b.Give(int64(cap(h.body)))
	}
	h.body = nil
}

// writeBody is half.writeBody under this connection's bounds, counting a body the budget cut once, as it is
// cut: a body that never completes still has its loss counted.
func (c *conn) writeBody(h *half, p []byte) {
	if h.writeBody(p, c.opts.MaxBody, c.budget) {
		c.starved++
		h.sizeCut = true
	}
}

// bodyWriter is writeBody as the chunked decoder's io.Writer. It never fails: a byte past the cap or the
// budget is counted there, not refused.
type bodyWriter struct {
	c *conn
	h *half
}

func (w bodyWriter) Write(p []byte) (int, error) {
	w.c.writeBody(w.h, p)
	return len(p), nil
}

// stepBody copies a Content-Length or close-delimited body. A close-delimited body completes only at
// Close, which is what makes the caller's idle timeout the authority on when a bodyless-framing response
// has ended (§4 "no internal timeouts").
func (c *conn) stepBody(h *half) (*Message, error) {
	if len(h.buf) == 0 {
		return nil, nil
	}
	if h.framing == framingClose {
		c.writeBody(h, h.buf)
		h.buf = h.buf[:0]
		return nil, nil
	}
	n := int64(len(h.buf))
	if n > h.bodyLeft {
		n = h.bodyLeft
	}
	c.writeBody(h, h.buf[:n])
	h.buf = h.buf[n:]
	h.bodyLeft -= n
	if h.bodyLeft > 0 {
		return nil, nil
	}
	return c.complete(h)
}

// stepChunked runs the incremental chunked decoder, whose state lives on the half so a size line split
// across two SSL_write calls reassembles (edge case #17).
//
// The decoder writes each decoded run of bytes straight through writeBody, so a chunked body is bounded by
// exactly the cap and the budget a Content-Length one is. It went through a scratch buffer on the half, which
// the idle-connection fix dropped at every message's end (R14), so every chunked message grew one from
// empty: 4 KiB and three allocations more per message in BenchmarkChunked, over the bench gate.
func (c *conn) stepChunked(h *half) (*Message, error) {
	used, err := h.chunk.feed(h.buf, bodyWriter{c: c, h: h})
	h.buf = h.buf[used:]
	if err != nil {
		return nil, err
	}
	if !h.chunk.done() {
		return nil, nil
	}
	return c.complete(h)
}

// complete finishes the message in flight: the body is decoded and the message is paired with its request
// (R15, R16). SSE framing is left intact for the provider parser, which needs event names and empty data
// frames to distinguish readable usage from incomplete accounting.
//
// A decode that fails mid-stream keeps the prefix that did decode, marks the message Truncated and returns
// the message together with the error, so the caller records one gap why=malformed and still has the bytes
// (R15, edge case #18). Emitting the message is the point: a body cut at R6's cap still parses far enough
// for derive to report what it saw.
//
// A response that answers no request capture saw is returned as neither message nor error: it is passed
// over (pair), its exchange counted, and the half is already back at a message boundary, so the
// connection's later exchanges pair as before.
func (c *conn) complete(h *half) (*Message, error) {
	msg := h.msg
	if msg == nil {
		return nil, fmt.Errorf("%w: completed a message that never started", ErrMalformed)
	}
	// The body's array goes with the message and the half keeps none of it (R14): Reset kept the
	// array, so every connection, idle ones included, pinned the capacity its largest body had grown to
	// until the table reached MaxConns. An emptied read buffer goes too, for the same reason;
	// the next message's first chunk allocates what it needs. The array's reservation stays with the
	// call that completed it (feedAllowance) and goes back when that call returns: from there the message
	// is the caller's, and a caller that keeps a body past the Feed that returned it (the uprobe source's
	// request awaiting its response) reserves it again from the same Budget.
	body := h.body
	h.body = nil
	c.allow.hold(int64(cap(body)))
	if len(h.buf) == 0 {
		c.dropBuf(h)
	}
	h.msg, h.state, h.lastHeader = nil, hsStart, ""
	h.count++
	msg.Truncated = msg.Truncated || h.truncated || h.capped || h.cut
	msg.SizeCut = h.sizeCut
	h.truncated, h.capped, h.cut, h.sizeCut = false, false, false, false
	if h.mt != nil && !h.mtLost {
		if v, ok := h.mt.Result(); ok {
			msg.MaxTokens = v
		}
	}
	h.mt, h.mtWanted, h.mtLost = nil, false, false
	msg.WireBytes = int(min(h.wire, math.MaxInt32))
	h.wire = 0

	if h.dir == DirResponse {
		// Paired before the body is decoded, so a response that is passed over costs no decoder.
		keep, err := c.pair(h, msg)
		if !keep {
			return nil, err
		}
	}
	headless := h.dir == DirRequest && len(c.pending) > 0 && c.pending[0].headless
	if h.dir == DirRequest && !headless && len(c.pending) >= c.opts.MaxPipeline {
		// R11 refuses this request (queue): no response will be paired with it, so nothing reads its body,
		// and a decoder run for it is launcher memory spent on bytes the record only sizes.
		msg.Refused = true
		msg.End, msg.EndNS = h.lastTS, h.lastNS
		c.queue(msg)
		return msg, nil
	}
	// A decode failure costs this body alone: it was framed whole, so the connection is still parseable
	// and its later exchanges must not be lost with it (R15). It is counted as one gap why=malformed
	// (drainDecodeFailedLocked) and the message carries the decoded prefix, Truncated.
	var derr error
	msg.Body, derr = c.decodeBody(body, msg)
	if derr != nil {
		c.decodeFailed++
		c.decodeErr = derr
	}
	msg.End, msg.EndNS = h.lastTS, h.lastNS

	if h.dir == DirRequest {
		if headless {
			// A request complete before the response to the one whose head capture missed: a pipelining
			// client, or the tail's server answering early (a 413) before the tail was done. The next
			// response answers either request, and nothing on the wire says which, so the connection
			// gaps (R18) rather than risk handing it to the wrong one (I3). The request itself was seen
			// whole, so it is still handed over.
			return msg, fmt.Errorf("%w: a request completed before the response to the one whose head "+
				"capture missed, so which of the two the next response answers cannot be told", ErrMalformed)
		}
		c.queue(msg)
	}
	return msg, nil
}

// decodeBody undoes a completed body's content codings under the call's allowance and the run's budget
// (R15), marking the message Truncated when the decoded form was cut: at MaxBody, which is this
// package's own bound and costs no gap, or short of it because the budget or the call's allowance had no
// room, which is counted as one gap why=size-cap like any body the budget cut.
func (c *conn) decodeBody(body []byte, msg *Message) ([]byte, error) {
	if len(splitEncodings(msg.ContentEncoding)) == 0 || len(body) == 0 {
		// An empty body (HEAD, 204, 304, Content-Length: 0, an empty chunked body) has nothing to decode,
		// and gzip and brotli fail on empty input.
		return body, nil
	}
	limit := c.opts.MaxBody
	short := false
	if room := c.allow.room; room < limit {
		limit, short = room, true
	}
	if limit <= 0 {
		// The call has decoded all it may: the body is kept as nothing rather than as the wire's bytes,
		// which a reader would take for the content.
		msg.Truncated, msg.SizeCut = true, true
		c.starved++
		return nil, nil
	}
	d := decodeBudgeted(body, msg.ContentEncoding, limit, c.budget)
	c.allow.hold(d.held)
	c.allow.room -= int64(len(d.out))
	if d.err != nil || d.limited || d.starved {
		msg.Truncated = true
	}
	if d.starved || (d.limited && short) {
		msg.SizeCut = true
		c.starved++
	}
	return d.out, d.err
}

// feedAllowance bounds what one call into the assembler — a Feed, a Close, a CloseWhere or CloseAll — decodes
// and hands back, and carries the budget reservations of the bodies it completes until that call returns
// (R15). One Feed can complete many messages: a 32 KiB chunk of pipelined requests, each a few dozen
// bytes of brotli, decoded to MaxBody apiece and all of them live together in the slice Feed returns. The
// decoded bytes of a call are held to MaxBody between them — one body at its largest, which is what one
// Feed completes in any traffic a server answers — and every array is reserved from the budget while the
// call runs; a body past either is cut and counted as gap why=size-cap. The reservations go back when the
// call returns, where the messages become the caller's: the uprobe source reserves again what it keeps.
type feedAllowance struct {
	budget *Budget
	room   int64
	held   int64
}

// begin opens a call with a fresh allowance of max decoded bytes.
func (f *feedAllowance) begin(max int64) {
	f.room, f.held = max, 0
}

// hold adds n bytes already reserved from the budget to what the call gives back at its end.
func (f *feedAllowance) hold(n int64) {
	if f == nil {
		return
	}
	f.held += n
}

// end gives back everything the call held.
func (f *feedAllowance) end() {
	f.budget.Give(f.held)
	f.held = 0
}

// pair gives a completed response the request it answers, or reports that it is to be passed over. I3: a
// response is only ever handed over as half of a pair, so one that answers no request capture saw is never
// emitted, and never paired with a request it did not answer.
//
// Three kinds of response are passed over rather than paired, each costing one count at most. One R11
// refused is owed (conn.owed) and was counted with its request. One whose request's tail was passed over
// pops that request's headless entry and was counted with the tail (skipRequest). One decided at its first
// byte to answer no request (half.noRequest) is counted here: a probe placed after the process's SSL_write
// and before its SSL_read (docs/p0/capture-derive.md R4, edge case 2) sees exactly that, and on a
// keep-alive connection the rest of the connection pairs as before. Until 2026-09-23 that response
// abandoned the connection and every later exchange on it under one gap that counted one, which kill test
// 2 met as 0 of 20 pairs.
//
// A response with nothing to pair when it completes that was not decided unanswered at its first byte
// began while a request was still arriving on the request half, and that request has not completed: the
// response may be its early answer (a 413 before its body is sent), and passing it over would leave the
// request queued for the next response's answer, so the connection gaps as R18 says.
func (c *conn) pair(h *half, msg *Message) (bool, error) {
	noRequest := h.noRequest
	// The decision was this response's; the next one is decided at its own first byte.
	h.decided, h.noRequest = false, false
	if noRequest {
		c.unpaired++
		return false, nil
	}
	if c.owed > 0 {
		c.owed--
		return false, nil
	}
	if len(c.pending) == 0 {
		return false, fmt.Errorf("%w: response with no request in flight", ErrMalformed)
	}
	req := c.pending[0]
	c.pending = c.pending[1:]
	c.owed = req.owedAfter
	if req.headless {
		return false, nil
	}
	msg.RequestIndex = req.Index
	return true, nil
}

// queue records a completed request as awaiting its response. At R11's depth the request that overflows is
// the one refused — "a 9th is gap why=size-cap on that request" — and the eight already in flight keep
// their places.
//
// Which end gives way is not a matter of taste. RFC 9112 §9.3 makes a server answer a pipelined connection
// in request order, so the head of this FIFO is precisely the next response's partner: evicting it would
// hand response N to request N+1, and every later response to a request it did not answer — a silent
// mispairing that flows straight into ssl_response.latency_ms and into headersDone's HEAD lookup. Refusing
// the newest costs exactly one unpairable exchange, the one the cap already declared lost.
//
// The refused request's place is still kept, as a count on the newest entry (owedAfter): its response
// comes after that entry's, and a request queued once the FIFO has room again comes after both. Without
// the count, that later request was the refused one's partner, and every response after it answered the
// request before.
func (c *conn) queue(msg *Message) {
	if len(c.pending) >= c.opts.MaxPipeline {
		c.overflow++
		if n := len(c.pending); n > 0 {
			c.pending[n-1].owedAfter++
		} else {
			c.owed++ // a depth of zero, which only a hand-built Options can ask for
		}
		return
	}
	c.pending = append(c.pending, pendingReq{Index: msg.Index, Method: msg.Method})
}

// release drops everything a connection was holding. A connection the assembler has gapped is never parsed
// or flushed again — Feed short-circuits on dead and closeLocked skips it — so its half buffers are state
// no one can reach: freeing them at the moment of death is what keeps a body that gapped mid-stream from
// pinning its bytes in launcher memory until Stop (§3, "launcher-process memory").
func (c *conn) release() {
	for i := range c.halves {
		h := &c.halves[i]
		c.dropBuf(h)
		h.msg = nil
		h.dropBody(c.budget)
		h.chunk = chunkedReader{}
		h.mt = nil
	}
	c.pending = nil
}

// retirable reports whether the connection holds nothing a later chunk or a Close could still turn into a
// message: it has already gapped, or both halves sit between messages with nothing buffered and no request
// waiting for a response. Only such a connection may be evicted to make room for another (assembler.go's
// evictLocked) — evicting one mid-message would turn its bytes into a silent absence, which I4 forbids.
func (c *conn) retirable() bool {
	if c.dead {
		return true
	}
	// A response still owed to a refused request is one a later chunk will bring, and a connection
	// retired before it would take that response for one whose request was never seen and count it again.
	if len(c.pending) > 0 || c.owed > 0 {
		return false
	}
	for i := range c.halves {
		h := &c.halves[i]
		// Trailing CRLFs are what a keep-alive sender leaves between messages (RFC 9112 §2.2);
		// stepStart skips them, so they are not bytes anyone is still waiting to parse.
		if h.msg != nil || len(bytes.Trim(h.buf, "\r\n")) > 0 {
			return false
		}
	}
	return true
}

// close flushes both halves and reports what was lost. A close-delimited response body ends normally here;
// a body short of its declared Content-Length, an unfinished chunked body and a half-read header block are
// each one gap (edge cases #22, #28).
func (c *conn) close() ([]*Message, []error) {
	if c.closed {
		return nil, nil
	}
	c.closed = true
	var msgs []*Message
	var errs []error
	for i := range c.halves {
		h := &c.halves[i]
		msg, err := c.flush(h)
		if msg != nil {
			msgs = append(msgs, msg)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	// A headless entry's exchange was counted when its tail was passed over (skipRequest).
	waiting := 0
	for _, p := range c.pending {
		if !p.headless {
			waiting++
		}
	}
	if waiting > 0 {
		errs = append(errs, fmt.Errorf("%w: %d requests with no response at close", ErrMalformed, waiting))
	}
	// Whatever a half still buffers is never parsed now; its reservation goes back (R13).
	for i := range c.halves {
		c.dropBuf(&c.halves[i])
	}
	return msgs, errs
}

// flush ends one half at Close.
func (c *conn) flush(h *half) (*Message, error) {
	switch {
	case h.msg == nil:
		if len(bytes.Trim(h.buf, "\r\n")) > 0 {
			return nil, fmt.Errorf("%w: %d unparsed bytes on the %s half at close", ErrMalformed, len(h.buf), h.dir)
		}
		return nil, nil
	case h.state == hsBody && h.framing == framingClose:
		// The only framing whose end is the close itself: a complete message, not a gap.
		msg, err := c.complete(h)
		return msg, err
	case h.state == hsBody || h.state == hsChunked:
		h.truncated = true
		msg, err := c.complete(h)
		if msg == nil && err == nil {
			return nil, nil // a response passed over (pair), whose exchange is already counted
		}
		if err == nil {
			err = fmt.Errorf("%w: body cut short on the %s half at close", ErrMalformed, h.dir)
		}
		return msg, err
	default:
		return nil, fmt.Errorf("%w: half-read %s at close", ErrMalformed, h.dir)
	}
}
