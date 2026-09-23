// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/capture/httpstream"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// requestIDHeaders are the fields a provider returns its own request id in, in the order they are tried.
var requestIDHeaders = []string{"Request-Id", "X-Request-Id", "Anthropic-Request-Id"}

// emitMessages turns reassembled messages into ledger events. It runs on the drain goroutine, which owns
// the pending-request table, and on the Stop path once that goroutine has returned — never on both at once.
func (u *Uprobe) emitMessages(msgs []*httpstream.Message) {
	for _, m := range msgs {
		if m.Dir == httpstream.DirRequest {
			u.emitRequest(m)
			continue
		}
		u.emitResponse(m)
	}
}

// maxPendingPerConn bounds the requests one connection keeps for responses still to come (R7a): the
// reassembler's pipelining depth, and as many again for requests it gave up without a response reaching here
// (a connection ended under the same key with them waiting, conn.endCloseDelimited), which the next response
// that does arrive clears and reports. Past it the oldest goes, body and all, and is reported as an
// unanswered request (ADR 0037); its response, should it still come, is recorded without derive.
const maxPendingPerConn = 2 * httpstream.DefaultMaxPipeline

// maxConnHosts bounds the table of each connection's last Host (connHosts). Past it the table starts afresh,
// and a connection lost after that is attributed to no host, which the loss accounting treats as a model
// host (meteredHost): the table can lose track of a host, never hide a loss.
const maxConnHosts = 2 * httpstream.DefaultMaxConns

// emitRequest records one ssl_request and remembers what its response will need.
//
// The host and path are the ones the request reaches (RFC 9112 §3.2.2): an absolute-form target
// ("POST https://api.anthropic.com/v1/messages HTTP/1.1") names its host in the URL, which a server uses in
// place of any Host header, and its path is the URL's. Taken from Host and the raw target, such a request was
// dispatched by a header the upstream ignores and classified by the path "/https:/api.anthropic.com/...",
// which spent nothing (R10). The ssl_request line keeps the target as the wire had it.
func (u *Uprobe) emitRequest(m *httpstream.Message) {
	host := m.Header.Get("Host")
	authority, path, targetOK := derive.SplitTarget(m.Path)
	tunnel := false
	if m.Method == http.MethodConnect {
		// CONNECT's target is authority-form (RFC 9112 §3.2.3), which SplitTarget does not take for a
		// resource: it names the host the tunnel reaches, and the exchange is a tunnel's opening, not a model
		// call (ADR 0035). A target that is not a host and port is still unreadable.
		authority, path, targetOK, tunnel = connectAuthority(m.Path)
	}
	if authority != "" {
		host = authority
	}
	u.noteHost(m.Key, host)
	payload := record.SSLRequestPayload{
		Endpoint:  u.endpoint(host),
		Method:    m.Method,
		Path:      m.Path,
		Host:      host,
		Size:      len(m.Body),
		RequestID: firstHeader(m, requestIDHeaders),
		Headers:   safeHeaderMap(m),
	}
	payload.TraceID, payload.ParentSpanID = parseTraceparent(m.Header.Get("Traceparent"))
	if m.Refused {
		// R11 refused it: no response will pair with it, so nothing is kept for one, and its body, which
		// httpstream did not decode, is recorded by its size on the wire and stored nowhere.
		payload.Size = m.WireBytes
		pair := source.NewPair()
		// Its body was not decoded, so a declared MCP server's messages in it cannot be read: they were still
		// sent, so it is read as a cut body, an unparsed decision (R41), rather than as nothing.
		var read derive.Result
		if msg := u.requestMessage(m, path, tunnel); msg != nil {
			msg.Body, msg.Truncated = nil, true
			read, _ = u.readRequest(msg, m, host)
			u.labelRequest(msg, m, host, &payload)
		}
		u.emit(record.KindSSLRequest, m, payload, pair)
		u.emitDerived(read.Events)
		// Its response is passed over unread, so what it spends is read by nothing: an unanswered request
		// as far as metering can tell, reported like every other path that gives up on one (ADR 0037).
		u.reportUnmetered(u.unanswered(&openRequest{Pair: pair, Method: m.Method, Path: path, Host: host,
			BadTarget: !targetOK, Tunnel: tunnel}), "a pipelined request past R11's depth was refused, so its response is not read")
		return
	}
	payload.Blob = u.blob(m)
	if m.Truncated {
		payload.Truncated, payload.WireSize = true, m.WireBytes
	}
	byIndex, ok := u.pending[m.Key]
	if !ok {
		byIndex = map[int]*openRequest{}
		u.pending[m.Key] = byIndex
	}
	if len(byIndex) >= maxPendingPerConn {
		oldest := -1
		for i := range byIndex {
			if oldest < 0 || i < oldest {
				oldest = i
			}
		}
		// Its response, should it still come, is recorded without derive, so what it spent is read by
		// nothing: an unanswered request as far as metering can tell (ADR 0037).
		u.reportUnmetered(u.unanswered(byIndex[oldest]), "a request's response was given up waiting for")
		u.releaseBody(byIndex[oldest])
		delete(byIndex, oldest)
	}
	inflight := &openRequest{Pair: source.NewPair(), Method: m.Method, Path: path, Host: host,
		BadTarget: !targetOK, Tunnel: tunnel, MaxTokens: m.MaxTokens, StartNS: m.StartNS}
	var read derive.Result
	if msg := u.requestMessage(m, path, tunnel); msg != nil {
		var readNow bool
		if read, readNow = u.readRequest(msg, m, host); readNow {
			inflight.ReadAs = read.Facts.ParserVersion
		} else {
			// Held until the response arrives, because a parser reads the pair: the request names the model
			// and whether the answer streams (R25-R31).
			inflight.Msg = msg
			u.holdBody(inflight)
			u.labelRequest(msg, m, host, &payload)
		}
	}
	byIndex[m.Index] = inflight
	u.emit(record.KindSSLRequest, m, payload, inflight.Pair)
	u.emitDerived(read.Events)
}

// readRequest is what derive reads of a request alone as it is captured (derive.Dispatcher.HandleRequest): a
// declared HTTP MCP server's initialize and tool calls (capture-derive R41), stamped with the request's own time
// and the thread that wrote it. ok is false for every other request, which derive reads with its response. Read
// now, a call is recorded whether or not an answer ever comes (the source's Stop, the connection's end and the
// pending bound all give one up without deriving it) and in the step it was sent in, however long the tool ran.
// msg is the request as requestMessage gave it.
func (u *Uprobe) readRequest(msg *derive.Message, m *httpstream.Message, host string) (derive.Result, bool) {
	d, ok := u.opts.Deriver.(requestDeriver)
	if !ok {
		return derive.Result{}, false
	}
	return d.HandleRequest(msg, u.meta(m, host))
}

// labelRequest stamps p with what derive reads off a request alone (derive.Dispatcher.ReadRequest, capture-derive
// R40, R42): side for a model host's side traffic, and the tool results a model turn reports. msg is the request as
// requestMessage gave it; a Deriver that cannot read requests leaves p as it was.
func (u *Uprobe) labelRequest(msg *derive.Message, m *httpstream.Message, host string, p *record.SSLRequestPayload) {
	if d, ok := u.opts.Deriver.(requestReader); ok {
		d.ReadRequest(msg, u.meta(m, host)).Apply(p)
	}
}

// requestMessage is a request in the form derive reads, nil when nothing derives it: no Deriver, or a tunnel's
// opening (ADR 0035). Only what a parser reads of a request is kept: its header map is not, which held up to R13's
// 64 KiB per pending request outside the byte budget (R7a).
func (u *Uprobe) requestMessage(m *httpstream.Message, path string, tunnel bool) *derive.Message {
	if u.opts.Deriver == nil || tunnel {
		return nil
	}
	msg := deriveMessage(m)
	msg.Header, msg.Path = nil, path
	return msg
}

// emitDerived hands derived events to the run's sink, in order.
func (u *Uprobe) emitDerived(events []*record.Event) {
	if len(events) == 0 {
		return
	}
	u.mu.Lock()
	sink := u.sink
	u.mu.Unlock()
	if sink == nil {
		return
	}
	for _, ev := range events {
		sink.Emit(ev)
	}
}

// emitResponse records one ssl_response against the request it answers, and the decisions derive reads out
// of the pair after it, in wire order, as the forwarder does (docs/p0/capture-derive.md §1: a derived event is
// identical in shape whichever mechanism captured the exchange).
//
// Capture assembles bytes and never parses a provider's wire shape itself: the model, response_id,
// stop_reason, usage and parser_version on the payload are the Deriver's facts (derive.Facts.Apply), and
// parser_version is the parser's own stamp (R32, I6). Without them `limits` would count no token of a run that
// captures through uprobes, since it reads ssl_response.usage. A source built with no Deriver records the
// exchange underived, with no parser_version.
func (u *Uprobe) emitResponse(m *httpstream.Message) {
	payload := record.SSLResponsePayload{
		Status:          m.Status,
		RequestID:       firstHeader(m, requestIDHeaders),
		ContentEncoding: m.ContentEncoding,
		Headers:         safeHeaderMap(m),
		LatencyMS:       m.LatencyMS(),
	}
	var req *openRequest
	if byIndex, ok := u.pending[m.Key]; ok {
		if r, ok := byIndex[m.RequestIndex]; ok {
			req = r
			payload.LatencyMS = latencyMS(req.StartNS, m.EndNS)
			delete(byIndex, m.RequestIndex)
		}
		// Responses come in request order (RFC 9112 §9.3), so a request older than the one this answers
		// never will be. R11's refused requests and those whose head capture missed never reach this table,
		// so what is left here is a request httpstream gave up on when its connection ended under the same
		// key without answering it (a close-delimited response ended by the next connection's first request,
		// conn.endCloseDelimited). Held, it would keep its body for derive until Stop; dropped silently, its
		// spend reached no budget. It is an unanswered request (ADR 0037).
		var lost int64
		for i, r := range byIndex {
			if i < m.RequestIndex {
				lost += u.unanswered(r)
				u.releaseBody(r)
				delete(byIndex, i)
			}
		}
		u.reportUnmetered(lost, "a request's response was never seen before its connection ended")
		if len(byIndex) == 0 {
			delete(u.pending, m.Key)
		}
	}
	// The request's body goes back to the budget once derive has read the pair, below.
	defer u.releaseBody(req)
	var (
		derived   []*record.Event
		unmetered bool
	)
	if u.opts.Deriver != nil && req != nil && req.Msg != nil {
		res, err := u.opts.Deriver.Handle(req.Msg, deriveMessage(m), u.meta(m, req.Host))
		if err != nil {
			u.log("uprobe: derive refused the exchange: %v", err)
		} else {
			// A cut stream derive could not bound for want of a max_tokens it could not parse: the one
			// httpstream read off every byte of the request, or the whole body's, is the bound (ADR 0036 (1)).
			if res.Facts.Unmetered {
				anthropic.BoundCutStream(&res.Facts, req.MaxTokens, req.MaxTokens > 0, m.Status)
			}
			res.Facts.Apply(&payload)
			derived = res.Events
			unmetered = res.Facts.Unmetered
		}
	}
	// A successful answer on a model host whose body the byte budget cut: what it spent past the cut, a
	// stream's closing usage above all, is not in what derive read (limits-check-doctor-cli.md R1 (d)).
	if req != nil && m.SizeCut && derive.Success(m.Status) && u.modelHost(req.Host) && !u.silent(req) {
		unmetered = true
	}
	// A successful answer to a request whose target says nothing capture can read (neither origin-form, "*"
	// nor an http(s) URL): what it reached, and so whether it spent, is unknown, which is never free (R10).
	if req != nil && req.BadTarget && derive.Success(m.Status) {
		unmetered = true
	}
	// A tunnel opened to a model host carries a TLS session of its own. Capture reads it only if the client runs
	// it through a probed SSL*, and nothing here can tell whether it does, so the model traffic it may carry is
	// as unreadable as h2's (ADR 0035). A tunnel to any other host spends nothing.
	if req != nil && req.Tunnel && derive.Success(m.Status) && u.modelHost(req.Host) {
		unmetered = true
	}
	if req != nil && req.ReadAs != "" {
		payload.ParserVersion = req.ReadAs // read when it was captured (readRequest); nothing more is derived
	}
	payload.Blob = u.blob(m)
	if m.Truncated {
		payload.Truncated, payload.WireSize = true, m.WireBytes
	}
	var pair uint64
	if req != nil {
		pair = req.Pair
	}
	u.emit(record.KindSSLResponse, m, payload, pair)
	u.emitDerived(derived)
	if unmetered && req != nil {
		u.reportUnmetered(1, derive.Route(req.Method, req.Path)+": usage unreadable")
	}
}

// noteHost remembers the Host of a connection's last request, which says whose exchanges are lost should the
// connection be (loseConn).
func (u *Uprobe) noteHost(key httpstream.ConnKey, host string) {
	if _, ok := u.connHosts[key]; !ok && len(u.connHosts) >= maxConnHosts {
		clear(u.connHosts)
	}
	u.connHosts[key] = host
}

// modelHost reports whether host is a model endpoint: one a models[] entry declares, or one the Deriver's
// parsers claim by default.
func (u *Uprobe) modelHost(host string) bool {
	if u.provider(host) != "" {
		return true
	}
	if p, ok := u.opts.Deriver.(interface {
		Parser(provider, host string) (derive.Parser, bool)
	}); ok {
		_, claimed := p.Parser("", agent.CanonicalHost(host))
		return claimed
	}
	return false
}

// meteredHost reports whether an exchange lost with its connection may have been model spend: its host is a
// model host, or capture never learned it.
func (u *Uprobe) meteredHost(host string) bool { return host == "" || u.modelHost(host) }

// loseConn is a connection capture can no longer follow — gapped after a sequence hole or a framing error, or
// an SSL* whose I/O split across threads (limits-check-doctor-cli.md R1 (f)): every request it was holding
// lost its response. Those whose host may have been a model's are reported unmetered, which ends a run with a
// token or cost budget; with none waiting that counts (none, or only requests to silent paths), the
// connection's own last host decides whether its lost bytes may have been: capture follows it no further, so
// what it carries next is lost too (an h2c upgrade's GET / is silent, the h2 after it is not).
func (u *Uprobe) loseConn(key httpstream.ConnKey, why string) {
	u.loseConns(why, key)
}

// loseConns gives up several connections at once as loseConn gives up one: every request they held is
// abandoned, and what they may have spent is reported as one loss, so a pair of connections lost together
// (a thread split) is not counted twice by the n==0 fallback.
func (u *Uprobe) loseConns(why string, keys ...httpstream.ConnKey) {
	var n int64
	metered := false
	for _, key := range keys {
		for _, r := range u.pending[key] {
			n += u.unanswered(r)
		}
		metered = metered || u.meteredHost(u.connHosts[key])
		u.dropPending(key)
	}
	if n == 0 && metered {
		n = 1
	}
	u.reportUnmetered(n, why)
}

// unanswered is 1 for a request that got no response capture saw and may have been model spend: its target
// was unreadable, or its host is a model's or was never learned (meteredHost). Every path that gives up on a
// request applies it — a lost connection, a closed one, a later response, the pending table's bound — so no
// path can pass one over that another would report (ADR 0035 (2), ADR 0037). A request
// whose path the Deriver calls silent (a health check, telemetry, token counting) spends nothing whatever its
// answer and is 0 (ADR 0037 amendment 2026-09-24).
func (u *Uprobe) unanswered(r *openRequest) int64 {
	if r == nil {
		return 0
	}
	// Whatever the verdict on spend, no ssl_response will end this request's step (derive.Steps.Abandon).
	u.mu.Lock()
	sink := u.sink
	u.mu.Unlock()
	source.ReportAbandoned(sink, r.Pair)
	if r.BadTarget {
		return 1
	}
	if !u.meteredHost(r.Host) || u.silent(r) {
		return 0
	}
	return 1
}

// silent reports that the Deriver calls r's path one that spends nothing (derive.SilentPaths). A request whose
// host capture never learned, a tunnel, or a Deriver that cannot say is not silent.
func (u *Uprobe) silent(r *openRequest) bool {
	if r.Host == "" || r.Tunnel {
		return false
	}
	d, ok := u.opts.Deriver.(interface {
		Silent(provider, host, method, target string) bool
	})
	return ok && d.Silent(u.provider(r.Host), agent.CanonicalHost(r.Host), r.Method, r.Path)
}

// reportUnmetered tells the run that n model exchanges went uncounted (source.ReportUnmetered).
func (u *Uprobe) reportUnmetered(n int64, why string) {
	u.mu.Lock()
	sink, activityOnly := u.sink, u.activityOnly
	u.mu.Unlock()
	if activityOnly {
		return // no capture to meter: the mechanism's own gap says so
	}
	source.ReportUnmetered(sink, n, why)
}

// holdBody reserves, from the budget the reassembler's bodies are reserved from, the request body a pending
// request keeps for derive until its response arrives (R14). Every request of every connection is held
// until then, and a response that never comes holds it until Stop: 24 unanswered 48 MiB requests grew the
// launcher by 1.5 GiB. A body the budget has no room for is not kept: derive reads the request
// without it, marked truncated, and the loss is one gap why=size-cap. The blob, which emitRequest wrote
// before this, keeps the whole body either way.
func (u *Uprobe) holdBody(r *openRequest) {
	body := r.Msg.Body
	want := int64(cap(body))
	if want == 0 {
		return
	}
	b := u.asm.Budget()
	if got := b.Take(want); got < want {
		b.Give(got)
		if r.MaxTokens == 0 && !r.Msg.Truncated {
			// derive will read the request without its body, so without its max_tokens: it is read now, while
			// the whole body is still in hand (R10).
			r.MaxTokens, _ = anthropic.RequestMaxTokens(body)
		}
		r.Msg.Body, r.Msg.Truncated = nil, true
		u.gap(httpstream.GapSizeCap, "", 1, fmt.Sprintf("a %d-byte request body not kept for derive: the capture "+
			"budget of %d bytes is in use", len(body), b.Limit()))
		return
	}
	r.held = want
}

// releaseBody gives a pending request's body back to the budget; nil and a request that holds none are
// nothing to give.
func (u *Uprobe) releaseBody(r *openRequest) {
	if r == nil || r.held == 0 {
		return
	}
	u.asm.Budget().Give(r.held)
	r.held = 0
}

// dropPending forgets every request a connection holds, giving their bodies back: the connection gapped or
// closed, so no response of it will ever pair with them.
func (u *Uprobe) dropPending(key httpstream.ConnKey) {
	for _, r := range u.pending[key] {
		u.releaseBody(r)
	}
	delete(u.pending, key)
	delete(u.connHosts, key)
}

// meta is what derive needs to know about an exchange beyond its bytes: the run and process m's own chunks name
// (the response's, or for a request read alone the request's: readRequest), the declared provider and host that
// choose the parser (R25), and m's stamps.
// The step is left at zero: derive's step tracker numbers the turn from the event stream (E28a).
func (u *Uprobe) meta(m *httpstream.Message, host string) derive.Meta {
	u.mu.Lock()
	run := u.run
	u.mu.Unlock()
	return derive.Meta{
		Run: run.ID, Agent: run.Agent,
		PID: int(m.Key.PidTgid >> 32), TID: int(uint32(m.Key.PidTgid)), Cgroup: m.Key.CgroupID,
		Source: record.SourceSSL, TS: stampOrNow(m.End, u.opts.Now), MonoNS: m.EndNS,
		Provider: u.provider(host), Host: agent.CanonicalHost(host), Port: tlsPort(host), Binary: agent.CanonicalHost(host),
	}
}

// tlsPort is the port a request's Host (or CONNECT authority) names, or 443 when it names none: every exchange this
// source reads ran over TLS, whose default port an origin with no explicit one is on (RFC 9110 §4.2.2). 0 when the
// port it names is not one, which matches no declared server.
//
// It is read in place rather than through net.SplitHostPort, whose error for the common Host with no port
// allocates on every response.
func tlsPort(host string) int {
	var p string
	switch {
	case strings.HasPrefix(host, "["):
		end := strings.IndexByte(host, ']')
		if end < 0 {
			return 0
		}
		rest := host[end+1:]
		if rest == "" {
			return 443
		}
		if rest[0] != ':' {
			return 0
		}
		p = rest[1:]
	case strings.Count(host, ":") != 1:
		return 443 // no port, or an unbracketed IPv6 literal, which can name none
	default:
		p = host[strings.IndexByte(host, ':')+1:]
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return 0
	}
	return n
}

// provider is the declared models[] provider a request's Host belongs to, "" when no entry names that host;
// derive then dispatches on the host alone (R25).
func (u *Uprobe) provider(host string) string {
	name := agent.CanonicalHost(host)
	if u.opts.Rules == nil || u.opts.Rules.Contract == nil {
		return ""
	}
	for _, m := range u.opts.Rules.Contract.Models {
		if agent.CanonicalHost(m.Host) == name {
			return m.Provider
		}
	}
	return ""
}

// deriveMessage is a reassembled message in the form derive reads. httpstream has already undone every
// content coding it supports (R15); a coding it does not, or more of them than it undoes, leaves the wire's
// bytes, which Decoded false tells a parser, so it answers unparsed why=encoding rather than reading them.
func deriveMessage(m *httpstream.Message) *derive.Message {
	return &derive.Message{
		Method: m.Method, Path: m.Path, Proto: m.Proto, Status: m.Status,
		Header: m.Header, Body: m.Body, ContentEncoding: m.ContentEncoding, SSE: m.SSE, WireSSE: m.SSE,
		Truncated: m.Truncated, Decoded: decodable(m.ContentEncoding),
	}
}

// decodable reports whether httpstream undoes every coding a Content-Encoding value lists.
func decodable(encoding string) bool {
	names := httpstream.SplitEncodings(encoding)
	if len(names) > httpstream.MaxCodings {
		return false
	}
	for _, n := range names {
		if !httpstream.SupportedEncoding(n) {
			return false
		}
	}
	return true
}

// latencyMS is the span between a request's first byte and its response's last, on the monotonic clock NTP
// never steps (edge case #25).
func latencyMS(startNS, endNS uint64) int64 {
	if endNS <= startNS {
		return 0
	}
	return int64((endNS - startNS) / 1e6)
}

// blob stores a decoded body and returns its sha256, or "" when there is no body or no store. The bytes go
// to the store directly rather than through a payload field, so what the blob holds is byte-for-byte what
// derive parses (I10) whether or not it is valid UTF-8.
func (u *Uprobe) blob(m *httpstream.Message) string {
	if len(m.Body) == 0 || u.opts.Blobs == nil {
		return ""
	}
	if u.opts.Rules != nil && u.opts.Rules.Record != agent.RecordFull {
		return "" // `record: summary` stores no bodies (spec/record/v1/README.md)
	}
	sha, _, err := u.opts.Blobs.PutStream(bytes.NewReader(m.Body))
	if err != nil {
		// A blob write that fails is a gap, never a failed call: capture is best-effort against
		// the agent and must never break what the agent is doing (§7's "Blob write failure" row).
		u.gap(httpstream.GapMalformed, "", 1, "blob write failed: "+err.Error())
		return ""
	}
	return sha
}

// emit stamps the common fields off the chunk's own kernel header and hands the event to the sink.
func (u *Uprobe) emit(kind record.Kind, m *httpstream.Message, payload any, pair uint64) {
	u.mu.Lock()
	run, sink := u.run, u.sink
	u.mu.Unlock()
	if sink == nil {
		return
	}
	ev := &record.Event{
		V:      record.Version,
		TS:     stampOrNow(m.End, u.opts.Now),
		MonoNS: m.EndNS,
		Run:    run.ID,
		Agent:  run.Agent,
		PID:    int(m.Key.PidTgid >> 32),
		TID:    int(uint32(m.Key.PidTgid)),
		Cgroup: m.Key.CgroupID,
		Kind:   kind,
		Source: record.SourceSSL,
		Pair:   pair,
	}
	if err := ev.SetPayload(payload); err != nil {
		// The payload structs are closed and always marshalable; a failure here is a bug, not a
		// runtime condition, and losing the event silently would break I4.
		u.gap(httpstream.GapMalformed, "", 1, "payload encode failed: "+err.Error())
		return
	}
	sink.Emit(ev)
}

// stampOrNow prefers the wall-clock stamp the chunk carried and falls back to the clock.
func stampOrNow(ts time.Time, now func() time.Time) time.Time {
	if !ts.IsZero() {
		return ts
	}
	return now()
}

// endpoint names the declared models[] entry a host belongs to, so a view can group a run's traffic by
// provider rather than by hostname. A host no contract declared keeps its own name, which is more useful
// than an empty field and never claims a provider that was not configured.
func (u *Uprobe) endpoint(host string) string {
	name := agent.CanonicalHost(host)
	if u.opts.Rules == nil || u.opts.Rules.Contract == nil {
		return name
	}
	for _, m := range u.opts.Rules.Contract.Models {
		if agent.CanonicalHost(m.Host) == name {
			return m.Provider
		}
	}
	return name
}

// safeHeaderMap returns the headers of a message that may reach a payload: the ledger's R9 allow-list, the
// forwarder's too, so no credential is ever placed in an event (I5) and both paths record one set of names.
func safeHeaderMap(m *httpstream.Message) map[string]string { return ledger.RecordedHeaders(m.Header) }

// firstHeader returns the first of several header fields that is set.
func firstHeader(m *httpstream.Message, names []string) string {
	for _, n := range names {
		if v := m.Header.Get(n); v != "" {
			return v
		}
	}
	return ""
}

// parseTraceparent reads the trace id and the caller's span id out of a W3C traceparent header, which is
// what spec/record/v1's ssl_request carries as trace_id and parent_span_id, by the rule the forwarder reads it
// by (derive.ParseTraceparent). A header that is not a valid version-00 one is ignored rather than guessed at;
// uprobe capture never writes one of its own (that is the forwarder's job, R20).
func parseTraceparent(v string) (traceID, parentSpanID string) {
	traceID, parentSpanID, _, ok := derive.ParseTraceparent(v)
	if !ok {
		return "", ""
	}
	return traceID, parentSpanID
}

// connectAuthority reads a CONNECT target (RFC 9112 §3.2.3: a host and a port, nothing else) as the host the
// tunnel reaches. ok is false for any other shape, which leaves the request's target unreadable.
func connectAuthority(target string) (authority, path string, ok, tunnel bool) {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" || port == "" || strings.ContainsAny(target, "/?#@") {
		return "", target, false, false
	}
	return target, target, true, true
}
