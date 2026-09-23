// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Sentinel errors of reassembly. Every one of them describes bytes a traced process produced, so a caller
// records a Gap and keeps feeding other connections; none of them ever ends a run (§7).
var (
	// ErrMalformed wraps every framing failure: a bad request or status line, a header without a colon,
	// a bad chunk-size, Content-Length together with Transfer-Encoding, a response while the request it
	// could answer is still arriving, a request completed before the response to one whose head capture
	// missed (R18). The wrapped cause names which. A response with no request at all is not one, nor the
	// tail of a request whose head capture missed: each is passed over and counted, and the connection
	// continues (conn.pair, conn.skipRequest).
	ErrMalformed = errors.New("httpstream: malformed HTTP/1.1")
	// ErrHTTP2 is an h2 connection preface on the request half: reassembly of that connection stops at once
	// and no partial Message is ever emitted from h2 bytes (R17). The preface is the only detection: an h2
	// client's first bytes are the preface (RFC 9113 §3.4), and the negotiated ALPN is read nowhere; NoteALPN,
	// which took it, had no caller and is gone.
	ErrHTTP2 = errors.New("httpstream: HTTP/2 connection")
	// ErrSizeCap is a bound this package enforces rather than a peer's mistake: the header cap (R13) or
	// the pipelining depth (R11).
	ErrSizeCap = errors.New("httpstream: size cap")
	// ErrRefusedAgain is Feed on a key the full connection table already turned away: the key's one size-cap
	// gap is recorded, so this chunk adds none. It wraps ErrSizeCap; a caller that reports a loss per refused
	// key, not per chunk, tells the first refusal from the rest by it (R11).
	ErrRefusedAgain = errors.New("httpstream: connection refused again")
	// ErrClosed is Feed on a key whose connection was already Closed.
	ErrClosed = errors.New("httpstream: connection closed")
)

// Gap reasons this package reports (record.GapPayload.Why, the closed set of R37).
const (
	// GapH2: an h2 connection preface on the traced connection.
	GapH2 = "h2"
	// GapMalformed: framing this package could not follow, R15's mid-stream decode error, and each
	// exchange passed over because capture missed the start of its request (one count per exchange).
	GapMalformed = "malformed"
	// GapSizeCap is R11's pipelining depth and R13's header cap (R37 files both under size-cap).
	GapSizeCap = "size-cap"
)

// Direction is which half of a connection a chunk belongs to.
type Direction uint8

// The two halves. A request travels client to server, a response server to client.
const (
	DirRequest  Direction = 0
	DirResponse Direction = 1
)

// String names the direction.
func (d Direction) String() string {
	if d == DirResponse {
		return "response"
	}
	return "request"
}

// ConnKey identifies one plaintext connection. Src says which mechanism produced the bytes; an uprobe
// connection is identified by (CgroupID, PidTgid, SSLPtr) and a forwarder connection by ConnID, so the two
// can never collide even inside one run (§2, §8 I11).
//
// Two threads sharing one SSL* under an external mutex become two ConnKeys and therefore two half-seen
// connections (edge case #11), which could pair one exchange's request with the next one's response: the
// uprobe source gives both up when one exchange's I/O is split across them (Assembler.Abandon).
type ConnKey struct {
	Src      record.Source
	CgroupID uint64
	PidTgid  uint64
	SSLPtr   uint64
	ConnID   uint64
}

// String renders the key for diagnostics and gap detail.
func (k ConnKey) String() string {
	if k.Src == record.SourceForwarder {
		return fmt.Sprintf("forwarder/%d", k.ConnID)
	}
	return fmt.Sprintf("ssl/%d/%d/%#x", k.CgroupID, k.PidTgid, k.SSLPtr)
}

// Chunk is one contiguous run of plaintext for one direction of one connection: a single SSL_write/SSL_read
// return, or one read of the forwarder's tee.
//
// Seq is the producer's own per-connection counter, one sequence for both directions, so a chunk lost in
// either direction is found at the connection's next chunk whichever direction that is. The assembler rejects
// a chunk that does not continue the sequence as malformed rather than silently accepting a hole (§8 I2): a
// whole response lost to a full ring would otherwise pair every later response with the request before its
// own. The first numbered chunk of a connection starts it wherever it starts, and the count skips
// 0 when it wraps; a producer that does not count leaves Seq zero on every chunk and the check is skipped.
// It was a per-direction count, which cannot show the loss of a direction's first chunk: the response of a
// connection's first exchange. Truncated says bytes before Data are missing,
// so the message in flight when the chunk arrives is marked Truncated too.
//
// Skipped is how many bytes of the same call followed Data on the wire and never reached the producer's
// reader: the tail of a call past R6's four chunks, or a chunk whose plaintext the probe could not read
// (R6). The hole is accounted for where it falls: inside a body it shortens what is still to
// come, the body keeps its prefix and the message is Truncated, and the connection goes on; a hole that
// crosses the framing — past the body's end, or inside a start line, a header block or a chunk-size line —
// leaves nothing to resynchronise on, and the connection gaps (why=malformed).
//
// Feed reads Data during the call and keeps none of it once it returns: the bytes a message still needs are
// copied (conn.keepRest).
type Chunk struct {
	Data      []byte
	Seq       uint32
	Truncated bool
	Skipped   uint64
	TS        time.Time
	MonoNS    uint64
}

// BodyScanner reads one value off a request body written to it in any number of pieces (Options.BodyScanner).
// Write never fails; Result is the value and whether the whole body stated one.
type BodyScanner interface {
	Write(p []byte) (int, error)
	Result() (int, bool)
}

// Message is one complete HTTP/1.1 message: a request or the response that answers it. Body is already
// decoded — Content-Encoding has been stripped, so a blob written from it hashes decoded content while
// ContentEncoding records what the wire carried (R15).
type Message struct {
	Key ConnKey
	Dir Direction

	// Method, Path and Proto are set on a request; Status and Reason on a response.
	Method string
	Path   string
	Proto  string
	Status int
	Reason string

	Header http.Header
	// Body is the decoded body, empty for a message that carries none.
	Body []byte
	// ContentEncoding is the Content-Encoding the wire used, "" for an identity body.
	ContentEncoding string
	// SSE is set when a response's body was text/event-stream. Body retains the decoded stream's framing,
	// including event names and empty data fields, in one Message for the whole stream (R16).
	// A request is never SSE: its body is kept as sent.
	SSE bool
	// RetryOf is filled by the forwarder, never by reassembly (R23).
	RetryOf string
	// Truncated says bytes are missing: a chunk the kernel cut (R6), a decoder that failed mid-stream
	// (R15), or a body shorter than its declared Content-Length at Close (edge case #22).
	Truncated bool
	// SizeCut says the byte budget, or the allowance of the call that completed the message, is what cut its
	// body or its decoded form short (one gap why=size-cap), rather than the kernel, a close or MaxBody. A
	// caller that meters spend from the body treats it as lost capture (limits-check-doctor-cli.md R1 (d)).
	SizeCut bool
	// WireBytes is the length of the body as the wire carried it, before any content coding was undone
	// and whatever of it Body kept.
	WireBytes int
	// Refused is a request R11's pipelining depth refused: no response will ever be paired with it, so its
	// body is not decoded and Body is nil (R11). It is handed over for its line alone, and a caller
	// keeps nothing of it for a response that will not come (R7a).
	Refused bool
	// MaxTokens is a request's top-level max_tokens, read by Options.BodyScanner off every byte of a body the
	// parser stopped keeping whole (MaxBody, the byte budget), which derive cannot parse (R10).
	// It is 0 for a body kept whole, which derive reads itself, and whenever no BodyScanner is configured or the
	// body did not state one by the scanner's rules, was not text, or lost bytes to capture.
	MaxTokens int

	// Index is the message's ordinal on its half of the connection, from zero.
	Index int
	// RequestIndex pairs a response with the request it answers; -1 on a request, and on a response
	// that arrived with no request left in the queue.
	RequestIndex int

	// Start and End are wall-clock times of the first and last chunk of this message, and StartNS/EndNS
	// the matching CLOCK_MONOTONIC readings a caller measures latency with (edge case #25).
	Start, End     time.Time
	StartNS, EndNS uint64
}

// BodyReader returns a reader over the decoded body. It is a fresh reader each call and never nil, so a
// caller that wants the io.ReadCloser shape of docs/p0/capture-derive.md §2 has one without copying Body.
func (m *Message) BodyReader() io.ReadCloser { return io.NopCloser(bytes.NewReader(m.Body)) }

// LatencyMS is the message's own wall span in milliseconds, from its first chunk to its last, measured on
// the monotonic clock NTP never steps (edge case #25).
func (m *Message) LatencyMS() int64 {
	if m.EndNS <= m.StartNS {
		return 0
	}
	return int64((m.EndNS - m.StartNS) / 1e6)
}

// Gap is one shortfall of reassembly, counted per reason. Capture turns it into a record gap event with
// what=capture (R37); this package never builds a record.Event itself.
type Gap struct {
	// Why is one of GapH2, GapMalformed, GapSizeCap.
	Why string
	// Detail names the connection and the cause for the operator log; never part of the ledger event.
	Detail string
	// Count is how many times this reason fired.
	Count int64
}
