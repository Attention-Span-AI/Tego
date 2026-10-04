// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// readRequest consumes the client's body once, so the retry key, the record and derive all see the same
// bytes, and the upstream leg replays exactly them. Reading the request is not the buffering R21
// forbids: that rule is about the response, which is streamed and never held. pid is the run's process that
// sent it: a retry is recognized only among that process's requests (R23).
func (l *Listener) readRequest(w http.ResponseWriter, r *http.Request, pid int) (x *exchange, err error) {
	// What capture may keep of this body: the length the client declared when it declared one — the
	// SDKs always do — so an ordinary call keeps no more than it uses, and never more than the run's
	// remaining capture budget (§3). The array is reserved as the bytes arrive, not when the length is
	// declared: requestChunk first, then doubling up to the declared length, so a body of up to
	// requestChunk is still one array of its own size. A declared length was reserved whole before a byte
	// of it had come, and eight uploads that declared MaxBody and sent one byte held the whole capture
	// budget until the connection closed, which left every later call's copy empty and its usage unread
	// (R27). A body of unknown length grows from bytes.MinRead as it arrives.
	want, chunk := l.opts.MaxBody, bytes.MinRead
	if n := r.ContentLength; n >= 0 {
		want = int(min(n, int64(want)))
		chunk = max(min(want, requestChunk), 1)
	}
	kept := l.budget.hold(want)
	defer func() {
		// An exchange that is never returned is never derived, so nothing else will give this back.
		if x == nil {
			kept.drop()
		}
	}()
	var src io.Reader = r.Body
	g := l.guardedBody(w, r)
	if g != nil {
		src = g
	}
	size, truncated, rest, err := readBody(src, kept, chunk)
	if err != nil {
		return nil, err
	}
	body := kept.bytes()
	now, mono := l.opts.Clock.Now(), l.opts.Clock.Mono()
	id, err := newExchangeID(l.opts.Rand)
	if err != nil {
		return nil, err
	}
	if r.ContentLength > size {
		// The client declared more than capture kept; the declared length is what it sent, and
		// every byte of it is still forwarded.
		size = r.ContentLength
	}
	x = &exchange{
		id:     id,
		pair:   source.NewPair(),
		method: r.Method,
		// The request target as sent, query included, so an ssl_request from the forwarder says the same
		// thing as one from the uprobe tier, which reads the request line off the wire. The ledger's
		// redaction stage removes the query values before any of it reaches disk (ledger.RedactTarget), so
		// the two tiers remain comparable in drift. Paths and retained names are not secret-filtered.
		path:      requestTarget(r),
		header:    r.Header.Clone(),
		body:      body,
		size:      size,
		truncated: truncated,
		started:   now,
		startMono: mono,
		rest:      rest,
		guard:     g,
		held:      kept.reserved(),
	}
	x.encoding = r.Header.Get("Content-Encoding")
	// The forwarder undoes no request coding — it replays the client's bytes upstream — so what derive
	// is told here is whether the body needs undoing at all, which is the same question the response
	// half asks through identityEncoding. `identity` names no coding (R15), so a body carrying it needs
	// nothing done and is not the "bytes that never became text" R29 reserves why=encoding for.
	x.decoded = identityEncoding(x.encoding)
	if x.rest != nil && x.decoded {
		// A body kept as a prefix does not parse, so derive cannot read its max_tokens, ADR 0036's bound for
		// a stream cut before its usage: it is read off every byte the upstream leg takes (R27).
		x.maxTokens, x.rest = newSentScanner(body, x.rest)
	}
	// R23's key is defined over the raw body. A body capture truncated at the cap yields a prefix, and
	// two requests that differ only past it hash alike — one long conversation appends its next turn
	// past the cap and repeats every byte before it — so a match there would tag a distinct turn
	// retry_of the one before it, and R33 would fold the whole remainder of the run into that one step.
	// An identity that cannot be established is not a retry: the hash path is skipped in both
	// directions, leaving the SDK's own counter (#29) as the only signal that can still attach it.
	if truncated {
		x.retryOf = l.retryByCount(pid, r.Header, mono)
		l.retries.rememberLatest(pid, id, mono)
	} else {
		key := ComputeRetryKey(x.method, x.path, body, credential(r.Header))
		x.retryOf = l.retryOf(pid, key, r.Header, mono)
		l.retries.remember(pid, key, id, mono)
	}
	return x, nil
}

// requestTarget rebuilds the origin-form target the client sent: path plus query. net/http splits them, and
// a path alone loses which parameters a request carried, which is the part drift compares.
func requestTarget(r *http.Request) string {
	p := r.URL.EscapedPath()
	if r.URL.ForceQuery || r.URL.RawQuery != "" {
		return p + "?" + r.URL.RawQuery
	}
	return p
}

// outbound builds the upstream request: the same method, path and query, the same body bytes, every
// header but the hop-by-hop ones, Accept-Encoding narrowed to what capture can decode, and Host, SNI and
// the identity headers rewritten (R20).
func (l *Listener) outbound(r *http.Request, x *exchange) (*http.Request, error) {
	target := *l.upstream
	host := l.hostHeader()
	if x.via != nil {
		target, host = *x.via.upstream, x.via.host
	}
	target.Path, target.RawPath, target.RawQuery = r.URL.Path, r.URL.RawPath, r.URL.RawQuery
	target.ForceQuery = r.URL.ForceQuery
	var body io.Reader = bytes.NewReader(x.body)
	if x.rest != nil {
		body = io.MultiReader(bytes.NewReader(x.body), x.rest)
		if r.ContentLength < 0 {
			// A body larger than capture kept and of a length the client never declared: what the client
			// sent is known only once the upstream leg has read it all (sentCounter).
			x.sent = &sentCounter{r: body, done: func() { l.emitRequest(x) }}
			body = x.sent
		}
	}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), body)
	if err != nil {
		return nil, fmt.Errorf("%w: build request: %w", ErrUpstream, err)
	}
	copyHeader(out.Header, r.Header)
	// The server answered the client's Expect: 100-continue when readRequest read the body, and the body
	// is in hand or replayed from here. Forwarded, it would make the Transport hold that body back for an
	// interim 100 the upstream may never send, up to ExpectContinueTimeout on every such request (R20).
	out.Header.Del("Expect")
	// An absent Accept-Encoding stays absent: net/http's Transport then offers gzip itself and hands back
	// the decoded body, which the client, having offered nothing, receives as identity.
	if offer := r.Header.Values(headerAcceptEncoding); len(offer) > 0 {
		narrowed, ok := narrowAcceptEncoding(offer)
		if !ok {
			return nil, fmt.Errorf("%w: no acceptable response encoding", ErrUpstream)
		}
		out.Header.Set(headerAcceptEncoding, narrowed)
	}
	out.Host = host
	out.ContentLength = r.ContentLength
	if r.ContentLength < 0 {
		out.TransferEncoding = []string{"chunked"}
	}
	runID := l.runRef().ID
	tr, err := newTrace(runID, r.Header, l.opts.Rand)
	if err != nil {
		return nil, fmt.Errorf("%w: trace identity: %w", ErrUpstream, err)
	}
	x.trace = tr
	out.Header.Set(HeaderRun, runID)
	out.Header.Set(HeaderTraceparent, tr.header())
	// A tracestate split across several header lines is one comma-joined list (W3C Trace Context §3.3.1,
	// RFC 9110 §5.3): every line's members are kept, not only the first line's.
	out.Header.Set(HeaderTracestate, tracestateFor(runID,
		strings.Join(r.Header.Values(HeaderTracestate), ","), tr.fresh()))
	return out, nil
}

// guardedBody is r.Body read under R27a's idle and total deadlines, or nil when the request has no body.
// Every read of a request body goes through it: net/http sets no deadline on a body of its own.
func (l *Listener) guardedBody(w http.ResponseWriter, r *http.Request) *idleBody {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	return &idleBody{r: r.Body, rc: http.NewResponseController(w), header: w.Header(), http2: r.ProtoMajor == 2,
		idle: l.opts.BodyIdleTimeout, deadline: time.Now().Add(l.opts.BodyTimeout), now: time.Now}
}

// idleBody is a request body read with a deadline for its next byte (Options.BodyIdleTimeout, R27) and
// one for its end (Options.BodyTimeout), both lifted once the body has ended so they never touch
// the response. An HTTP/1 body that fails before its end marks the reply
// "Connection: close": net/http otherwise drains an unread body under 256 KiB
// before writing the reply. HTTP/2's body failure affects only its own stream.
//
// The header is the handler's own map, which only the handler goroutine may touch. A body larger than MaxBody
// is read past its prefix by the upstream transport's writeLoop, so before the body is handed over the handler
// calls handOff, and from then on a failure only sets failed; the handler marks the reply itself (markClose)
// before it writes a status. A fail() writing the map from writeLoop raced the handler's relay and net/http's
// finishRequest, a fatal concurrent map access.
//
// The deadlines are set through the handler's ResponseWriter, which net/http forbids using once the handler
// has returned; writeLoop can still be reading then, when the upstream answered before the body ended. On a
// connection net/http keeps alive, such a late call overwrote the idle deadline it had set for the next
// request, or cleared it, and the connection then held its MaxConns slot with no bound. So the handler
// retires the body before it returns (forward defers retire), and a retired body never touches the
// connection again: a read after that fails with errBodyRetired, and one already under way sets no deadline
// when it ends.
type idleBody struct {
	r        io.Reader
	rc       *http.ResponseController
	header   http.Header // the reply's; nil is none to mark, or the body was handed off the handler goroutine
	http2    bool        // HTTP/2 failures end one stream, keeping unrelated streams usable
	idle     time.Duration
	deadline time.Time        // the whole body's; zero is none
	now      func() time.Time // the clock both deadlines are read from; nil is time.Now
	done     bool
	failed   atomic.Bool // the body stopped before its end; read by the handler after handOff

	mu      sync.Mutex // orders setDeadline against retire
	retired bool       // the handler has returned, or is about to: rc is no longer the body's to use
}

// errBodyTimeout is a request body still arriving at its whole-body deadline.
var errBodyTimeout = errors.New("forwarder: request body exceeded its total read deadline")

// errBodyRetired is a read of a request body after its handler returned.
var errBodyRetired = errors.New("forwarder: request body read after its handler returned")

func (b *idleBody) Read(p []byte) (int, error) {
	if b.done {
		return 0, io.EOF
	}
	now := time.Now
	if b.now != nil {
		now = b.now
	}
	t := now()
	next := t.Add(b.idle)
	if !b.deadline.IsZero() {
		if !t.Before(b.deadline) {
			// Checked here as well as set on the connection: a connection that cannot take a deadline
			// still ends the body at its deadline, between reads.
			b.setDeadline(time.Time{})
			b.fail()
			return 0, errBodyTimeout
		}
		if b.deadline.Before(next) {
			next = b.deadline
		}
	}
	// A connection that cannot take a deadline (a test's recorder) is read without one.
	if !b.setDeadline(next) {
		return 0, errBodyRetired
	}
	n, err := b.r.Read(p)
	if err != nil {
		b.done = err == io.EOF
		b.setDeadline(time.Time{})
		if !b.done {
			b.fail()
		}
	}
	return n, err
}

// setDeadline sets the connection's read deadline, unless the body is retired; false is retired.
func (b *idleBody) setDeadline(t time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.retired {
		return false
	}
	_ = b.rc.SetReadDeadline(t)
	return true
}

// retire is called on the handler goroutine before the handler returns: from then on no read of the body
// touches the connection, whose ResponseWriter net/http has taken back. Nil-safe.
func (b *idleBody) retire() {
	if b != nil {
		b.mu.Lock()
		b.retired = true
		b.mu.Unlock()
	}
}

// fail closes HTTP/1 after the reply; HTTP/2 already closes this body's pipe.
func (b *idleBody) fail() {
	b.failed.Store(true)
	if b.header != nil && !b.http2 {
		b.header.Set("Connection", "close")
	}
}

// handOff is called on the handler goroutine before the body is read anywhere else (the upstream leg's
// writeLoop): a later failure is only recorded, and markClose applies it. Nil-safe.
func (b *idleBody) handOff() {
	if b != nil {
		b.header = nil
	}
}

// markClose stops a failed upload on the handler goroutine before writing the
// status. HTTP/1 closes its connection; HTTP/2 stops only this stream. A failure
// after the status cannot change a reply already sent. Nil-safe.
func (b *idleBody) markClose(w http.ResponseWriter) {
	if b != nil && b.failed.Load() {
		if !b.http2 {
			w.Header().Set("Connection", "close")
		}
		_ = http.NewResponseController(w).SetReadDeadline(time.Now())
	}
}
