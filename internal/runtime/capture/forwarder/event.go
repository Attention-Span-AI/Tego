// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// exchange is one request the listener forwarded, from the moment its body was read to the moment its
// response ended. It is the only state the forwarder keeps per call.
type exchange struct {
	id string
	// pair links this exchange's ssl_request and ssl_response lines in the pipeline (Event.Pair).
	pair   uint64
	method string
	// path is the request target as sent (requestTarget), query included: drift and the retry key compare it. A
	// query may carry a credential; the ledger's RedactStage rewrites it through ledger.RedactTarget before the
	// ssl_request line reaches disk (R9a of docs/p0/record-ledger.md), not this package.
	path      string
	header    http.Header
	body      []byte
	size      int64 // bytes the client sent, whether or not capture kept them all
	truncated bool
	// rest is the part of a body larger than the capture cap: forwarded, never captured.
	rest io.Reader
	// guard is the request body's deadline reader, nil for a body-less request: the upstream leg reads rest
	// through it off the handler goroutine, so its failure reaches the reply only through markClose.
	guard *idleBody
	// sent counts a body of undeclared length as it is forwarded, when it is larger than the cap: size is
	// then its count (sentCounter). requestOnce writes the ssl_request line once (emitRequest).
	sent        *sentCounter
	requestOnce sync.Once
	// held is how many bytes of the run's capture budget body is holding (§3).
	held      int
	encoding  string
	decoded   bool
	trace     trace
	retryOf   string
	started   time.Time
	startMono uint64
	// pid is the run's process holding the connection (R19a's admission), and lane the slot among that
	// process's turns in flight this one took (lanes): the lines' pid, and the thread derive keys the turn by
	// (R34).
	pid  int
	lane uint64
	// maxTokens reads the request's max_tokens off every byte of a body larger than capture kept, as the
	// upstream leg reads it (anthropic.MaxTokensScanner, R27); nil for a body kept whole, which
	// derive reads.
	maxTokens *sentScanner
	// neverSent is an upstream leg that failed to connect: no byte of the request left, so the upstream
	// cannot have spent anything on it, and its missing answer is not reported unmetered (ADR 0037).
	neverSent bool
	// via is the route the request was sent by (ADR 0127); nil on an endpoint that declares none.
	via *routeChoice
	// asked is the request having waited for a person's approval (askExchange): only then is a route moved meanwhile a
	// reason not to send it (ADR 0127 §4).
	asked bool
}

// event builds the common fields every event of this listener carries. Seq, id and prev belong to the
// ledger; pid and tid are left for the pipeline to stamp, which fills in the launcher's own (runStamp,
// internal/runtime/pipeline.go): right for a gap, which has no process. An exchange's lines are stamped
// with its peer's pid instead (stampExchange).
func (l *Listener) event(kind record.Kind, ts time.Time, mono uint64) *record.Event {
	return &record.Event{
		V:      record.Version,
		TS:     ts,
		MonoNS: mono,
		Run:    l.runRef().ID,
		Agent:  l.runRef().Agent,
		Cgroup: l.runRef().CgroupID,
		Kind:   kind,
		Source: record.SourceForwarder,
	}
}

// stampExchange puts the exchange's process and lane on one of its lines (R34). The pipeline stamped
// the launcher's pid and tid on them, so the ledger named tego as the model's caller, and derive keyed every
// turn of the run on the launcher's one tid: two concurrent turns had one open step, and an action while both
// were in flight was attributed "likely" where R34 says unattributed. R19a's admission resolves the peer's
// pid; its tid is not knowable from a socket, which belongs to the process, so tid is left 0 (unknown) and
// the lane stands in for it, in process only (record.Event.Lane). At tier 1 the forwarder is the only
// capture, so this is the only way model turns reach attribution there.
func (x *exchange) stampExchange(ev *record.Event) {
	ev.PID, ev.Lane = x.pid, x.lane
}

// requestEvent is the ssl_request line: what the agent asked for, the identity the forwarder added, and
// the retry this attempt repeats, when it repeats one.
func (l *Listener) requestEvent(x *exchange) *record.Event {
	ev := l.event(record.KindSSLRequest, x.started, x.startMono)
	x.stampExchange(ev)
	ev.Pair = x.pair
	payload := record.SSLRequestPayload{
		Endpoint:     l.model.Provider,
		Method:       x.method,
		Path:         x.path,
		Host:         l.model.Host,
		RequestID:    x.id,
		Size:         int(x.sentSize()),
		TraceID:      x.trace.TraceID,
		SpanID:       x.trace.SpanID,
		ParentSpanID: x.trace.ParentSpanID,
		RetryOf:      x.retryOf,
		Headers:      recordedHeaders(x.header),
		Route:        x.via.taken(),
	}
	if rr, ok := l.opts.Deriver.(requestReader); ok {
		// Only the dispatch keys are read; l.meta would also read the clock, which the line's own time already did.
		rr.ReadRequest(x.requestMessage(), derive.Meta{Provider: l.model.Provider, Host: l.model.Host}).Apply(&payload)
	}
	// A body capture kept as a prefix says so on its line, with the length the client sent, so its blob does
	// not read as the whole body (record-ledger §2.2). The request is replayed upstream as the client's bytes,
	// never decoded, so that length is the wire's.
	l.setPayload(ev, &payload, x.body, x.truncated, x.truncated, func() {
		payload.Truncated, payload.WireSize = true, int(x.sentSize())
	})
	return ev
}

// responseEvent is the ssl_response line: the transport's own facts, whatever derive read out of the
// body, and the body itself. parser_version is always set, even when no parser claimed the exchange (I6).
func (l *Listener) responseEvent(x *exchange, r *upstreamResult, facts derive.Facts) *record.Event {
	ev := l.event(record.KindSSLResponse, r.ended, r.endedMono)
	x.stampExchange(ev)
	ev.Pair = x.pair
	payload := record.SSLResponsePayload{
		Status:          r.status,
		LatencyMS:       int64(time.Duration(r.endedMono - x.startMono).Milliseconds()),
		RequestID:       x.id,
		ContentEncoding: r.encoding,
		Headers:         recordedHeaders(r.header),
	}
	facts.Apply(&payload)
	l.setPayload(ev, &payload, r.body, r.truncated, r.sizeCut, func() {
		payload.Truncated, payload.WireSize = true, int(r.wireSize)
	})
	return ev
}

// setPayload attaches a payload and, when the run records bodies, the body itself under the key the
// ledger's blob stage turns into blob (R10 of docs/p0/record-ledger.md). truncated says the body is a
// prefix, for any reason, so a rune the cut left unfinished at its end is dropped and the prefix kept.
// sizeCut says capture's own bound kept the body short, which is counted as a gap why=size-cap; a body cut
// short otherwise (the client left, the upstream failed, a decode broke) had its gap counted where that
// happened, and is not counted twice. A body that is not valid UTF-8 — a content encoding this component
// cannot decode — is left off rather than mangled into replacement characters, which would make blob(sha)
// a hash of something the wire never carried. mark, when set, is called before payload is encoded if the
// body member it gets is a prefix of the body, for any of these reasons or the budget's cut of the copy:
// it sets the payload's truncated and wire_size, which are about the blob and so absent when no body is kept.
func (l *Listener) setPayload(ev *record.Event, payload any, body []byte, truncated, sizeCut bool, mark func()) {
	prefix := truncated || sizeCut
	if prefix {
		body = trimPartialRune(body)
	}
	raw, cut, err := l.encodePayload(payload, body, prefix, mark)
	if err != nil {
		l.note(GapMalformed, 1)
		l.opts.Logger.Warn("forwarder: payload not encoded", "run", l.runRef().ID, "err", err)
		return
	}
	ev.Payload = raw
	if sizeCut || cut {
		l.note(GapSizeCap, 1)
	}
}

// trimPartialRune drops the bytes of a rune a size cut left unfinished at the end of body, so a copy that
// was valid text up to the cut is kept as the prefix it is and not left off whole for one split rune. A body
// that is invalid before its tail is returned as it was (and is left off, setPayload).
func trimPartialRune(body []byte) []byte {
	if utf8.Valid(body) {
		return body
	}
	for n := 1; n < utf8.UTFMax && n <= len(body); n++ {
		if head := body[:len(body)-n]; utf8.Valid(head) {
			return head
		}
	}
	return body
}

// encodePayload is the payload object with the body spliced in as its "body" member, and whether the
// budget cut that member short of the body. When a member is spliced in that is a prefix of the body — prefix
// says the body itself is one, or the budget cut the member — mark is called first, so what it sets on the
// payload (a pointer) is encoded with it.
//
// The payload is an array of its own, and it outlives the exchange: it waits in the run queue for the
// ledger writer. So the body's copy in it is reserved from the capture budget like every other body
// capture holds (§3), and stays reserved until the collector finds the payload unreachable
// (holdWhileReachable). The event's own fields around it are not counted; §3 says what bounds them.
// What the grant does not cover is not kept: the copy is the longest prefix, cut between runes, whose
// encoding fits, and none at all when not even that fits — the same degradation as a body capture kept
// short.
//
// The copy is encoded once, straight into an array of its exact size. encoding/json would escape <, >
// and & as six bytes each by default, copy the body into a string first, and then re-marshal the whole
// object around it — about 46 times an 8 MiB body of '<' allocated for one event, none of it counted.
func (l *Listener) encodePayload(payload any, body []byte, prefix bool, mark func()) (json.RawMessage, bool, error) {
	// The copy is sized against the budget before the payload is encoded, since whether it is a prefix
	// decides the payload's own truncated field.
	var keep, cost int
	cut := false
	if l.opts.Bodies && len(body) > 0 && utf8.Valid(body) {
		// Any part of the copy the grant does not cover is cut from the record, so all of it is needed.
		need := quotedLen(body)
		grant := l.budget.take(need, need)
		keep, cost = quotedPrefix(body, grant)
		l.budget.give(grant - cost)
		cut = keep < len(body)
		if keep > 0 && (prefix || cut) && mark != nil {
			mark()
		}
	}
	var meta bytes.Buffer
	enc := json.NewEncoder(&meta)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		l.budget.give(cost)
		return nil, false, fmt.Errorf("forwarder: marshal payload: %w", err)
	}
	obj := bytes.TrimSuffix(meta.Bytes(), []byte("\n"))
	if len(obj) < 2 || obj[0] != '{' || obj[len(obj)-1] != '}' {
		l.budget.give(cost)
		return nil, false, fmt.Errorf("forwarder: payload is not a JSON object")
	}
	if keep == 0 {
		return obj, cut, nil
	}
	const member = `"body":`
	out := make([]byte, 0, len(obj)+1+len(member)+cost)
	out = append(out, obj[:len(obj)-1]...)
	if len(obj) > 2 {
		out = append(out, ',')
	}
	out = append(out, member...)
	out = appendQuoted(out, body[:keep])
	out = append(out, '}')
	l.budget.holdWhileReachable(out, cost)
	return out, cut, nil
}

// quotedByte is what one byte of a valid UTF-8 body costs inside a JSON string as appendQuoted writes it:
// the two-byte escapes JSON has, \u00XX for the other control bytes, and every other byte as itself.
// Nothing outside ASCII is escaped, so every byte a rune spans costs one.
func quotedByte(c byte) int {
	switch c {
	case '"', '\\', '\n', '\r', '\t', '\b', '\f':
		return 2
	}
	if c < 0x20 {
		return 6
	}
	return 1
}

// quotedLen is the length of body as a JSON string, quotes included.
func quotedLen(body []byte) int {
	n := 2
	for _, c := range body {
		n += quotedByte(c)
	}
	return n
}

// quotedPrefix is the longest prefix of body, cut between runes, whose JSON string fits in room, and that
// string's length. A cut inside a rune would leave invalid UTF-8, which a JSON decoder turns into U+FFFD
// and which would make blob(sha) a hash of bytes the wire never carried. An empty prefix is no copy at all,
// so it costs nothing: encodePayload keeps no copy to hold the cost, and would never give it back.
func quotedPrefix(body []byte, room int) (keep, cost int) {
	if room < 2 {
		return 0, 0
	}
	n := 2
	for i, c := range body {
		if utf8.RuneStart(c) {
			keep, cost = i, n
		}
		n += quotedByte(c)
		if n > room {
			if keep == 0 {
				return 0, 0
			}
			return keep, cost
		}
	}
	return len(body), n
}

// appendQuoted appends body, valid UTF-8, as a JSON string that decodes back to exactly its bytes.
func appendQuoted(dst, body []byte) []byte {
	const hex = "0123456789abcdef"
	dst = append(dst, '"')
	start := 0
	for i, c := range body {
		if quotedByte(c) == 1 {
			continue
		}
		dst = append(dst, body[start:i]...)
		switch c {
		case '"', '\\':
			dst = append(dst, '\\', c)
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		case '\b':
			dst = append(dst, '\\', 'b')
		case '\f':
			dst = append(dst, '\\', 'f')
		default:
			dst = append(dst, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
		}
		start = i + 1
	}
	dst = append(dst, body[start:]...)
	return append(dst, '"')
}

// gapEvent is one gap what=capture this listener reports as it happens: an exchange it could not carry
// (R37). A forwarder bypass is not among them — that is enforce's net verdict=refused (R38).
func (l *Listener) gapEvent(why string, ts time.Time, mono uint64) *record.Event {
	ev := l.event(record.KindGap, ts, mono)
	_ = ev.SetPayload(record.GapPayload{What: record.GapCapture, Why: why, Binary: l.model.Host})
	return ev
}

// sentSize is the bytes the client sent: its declared length, or what capture kept of a body that fit, or,
// for a larger body of undeclared length, what the upstream leg has read of it.
func (x *exchange) sentSize() int64 {
	if x.sent != nil {
		return x.sent.n.Load()
	}
	return x.size
}

// requestMessage is the exchange's request in the form derive reads.
func (x *exchange) requestMessage() *derive.Message {
	return &derive.Message{
		Method:          x.method,
		Path:            x.path,
		Proto:           "HTTP/1.1",
		Header:          x.header,
		Body:            x.body,
		ContentEncoding: x.encoding,
		RetryOf:         x.retryOf,
		Truncated:       x.truncated,
		Decoded:         x.decoded,
	}
}
