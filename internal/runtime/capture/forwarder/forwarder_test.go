// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// testRun is the run every case forwards for.
var testRun = source.RunRef{ID: "r-3f9c2a1b-0dllq06ts7400-k7m2pq", Agent: "retriever", CgroupID: 44821}

// fakeSink collects what the listener emitted.
type fakeSink struct {
	mu     sync.Mutex
	events []*record.Event
}

func (s *fakeSink) Emit(ev *record.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *fakeSink) all() []*record.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*record.Event(nil), s.events...)
}

// forget lets go of every event collected so far, the way the ledger writer does once it has written
// them, so the reservations their copies of bodies hold can go back (§3).
func (s *fakeSink) forget() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = nil
}

// waitFor blocks until at least n events of one kind have been emitted. The forwarder records an
// exchange once its response has been streamed, which is after the client's own last read returns, so
// every assertion about events waits for them rather than racing them.
func (s *fakeSink) waitFor(t *testing.T, kind record.Kind, n int) []*record.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got := s.of(kind); len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d %s events after 5s, want %d", len(s.of(kind)), kind, n)
		}
		time.Sleep(time.Millisecond)
	}
}

// of returns the events of one kind.
func (s *fakeSink) of(kind record.Kind) []*record.Event {
	var out []*record.Event
	for _, ev := range s.all() {
		if ev.Kind == kind {
			out = append(out, ev)
		}
	}
	return out
}

// fixedClock is a scripted clock: wall time steps by a millisecond per reading, the monotonic reading
// by the same amount, so latency and the retry window are deterministic.
type fixedClock struct {
	mu   sync.Mutex
	wall time.Time
	mono uint64
	step time.Duration
}

func newClock() *fixedClock {
	return &fixedClock{wall: time.Date(2026, 9, 22, 9, 0, 0, 0, time.UTC), step: 100 * time.Millisecond}
}

func (c *fixedClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall = c.wall.Add(c.step)
	c.mono += uint64(c.step)
	return c.wall
}

func (c *fixedClock) Mono() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mono
}

// zeroRand is a deterministic span-id and exchange-id source for the golden lines.
type countingRand struct {
	mu sync.Mutex
	n  byte
}

func (r *countingRand) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.n++
	for i := range p {
		p[i] = r.n
	}
	return len(p), nil
}

// harness is one bound listener in front of one httptest upstream.
type harness struct {
	t        *testing.T
	upstream *httptest.Server
	listener *Listener
	sink     *fakeSink
	client   *http.Client
}

// newHarness starts an upstream and a listener bound to it. The upstream is plain HTTP, so the test's
// transport is the upstream's own client transport rather than the TLS one production builds; every
// other rule on the path — Host rewriting, hop-by-hop removal, identity headers, streaming — is the
// production code's.
func newHarness(t *testing.T, handler http.HandlerFunc, opts Options) *harness {
	t.Helper()
	return newProviderHarness(t, "anthropic", handler, opts)
}

// newProviderHarness is newHarness for a models[] entry of another declared provider.
func newProviderHarness(t *testing.T, provider string, handler http.HandlerFunc, opts Options) *harness {
	t.Helper()
	// A TLS upstream, so the test exercises the real path: plaintext in, TLS out.
	up := httptest.NewTLSServer(handler)
	t.Cleanup(up.Close)
	host, port := hostPort(t, up.Listener.Addr().String())
	if opts.Clock == nil {
		opts.Clock = newClock()
	}
	if opts.Rand == nil {
		opts.Rand = &countingRand{}
	}
	if opts.Transport == nil {
		opts.Transport = up.Client().Transport
	}
	opts.Bodies = true
	model := agent.ModelEndpoint{Provider: provider, Host: host, Port: port}
	l, err := NewListener(model, opts)
	if err != nil {
		t.Fatalf("new listener: %v", err)
	}
	sink := &fakeSink{}
	// Every case below dials from the test process, so the run these listeners serve is the cgroup this
	// process is already in: R19a's peer admission then runs for real on each of them rather than being
	// switched off for the whole suite. A machine that cannot answer the cgroup question at all falls
	// back to admitting any local peer; admission itself is tested directly in peer_test.go.
	run := testRun
	if id, err := liveCgroupID(); err == nil {
		run.CgroupID = id
	} else {
		t.Logf("peer admission not exercised here: %v", err)
		l.peers = anyPeer
	}
	l.Bind(run, sink)
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- l.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = l.Close()
		if err := <-served; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return &harness{t: t, upstream: up, listener: l, sink: sink, client: &http.Client{}}
}

// hostPort splits an address into a host and a port.
func hostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %s: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port %s: %v", portStr, err)
	}
	return host, port
}

// do sends one request through the forwarder.
func (h *harness) do(req *http.Request) *http.Response {
	h.t.Helper()
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatalf("request: %v", err)
	}
	return resp
}

// post is the common case: a POST to the messages path.
func (h *harness) post(path string, body []byte, header http.Header) *http.Response {
	h.t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.listener.BaseURL()+path, bytes.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	return h.do(req)
}

// payloadOf decodes one event's payload.
func payloadOf[T any](t *testing.T, ev *record.Event) T {
	t.Helper()
	var p T
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return p
}

// The request reaches the upstream byte for byte with only Host, SNI and the identity headers
// rewritten, the hop-by-hop headers removed, and the response returns unchanged (R19–R21).
func TestForwardRewritesOnlyWhatItMust(t *testing.T) {
	var got *http.Request
	var gotBody []byte
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Clone(r.Context())
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("request-id", "req_011CS0001")
		w.Header().Set("retry-after", "3")
		w.Header().Set("x-should-retry", "false")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}, Options{})

	body := []byte(`{"model":"claude-opus-5","messages":[]}`)
	resp := h.post("/v1/messages?beta=true", body, http.Header{
		"Content-Type":      {"application/json"},
		"Anthropic-Version": {"2023-06-01"},
		"X-Api-Key":         {"sk-ant-test-credential"},
		"X-Custom":          {"a", "b"},
		"Keep-Alive":        {"timeout=5"},
		"Te":                {"trailers"},
		"Connection":        {"x-drop-me"},
		"X-Drop-Me":         {"1"},
	})
	defer resp.Body.Close()
	client, _ := io.ReadAll(resp.Body)

	if string(client) != `{"ok":true}` {
		t.Errorf("client body = %q", client)
	}
	if !bytes.Equal(gotBody, body) {
		t.Errorf("upstream body = %q, want the client's bytes", gotBody)
	}
	if got.Host != h.listener.hostHeader() {
		t.Errorf("upstream Host = %q, want the model host %q", got.Host, h.listener.hostHeader())
	}
	if got.URL.RawQuery != "beta=true" {
		t.Errorf("query = %q, want it forwarded", got.URL.RawQuery)
	}
	if v := got.Header.Values("X-Custom"); len(v) != 2 || v[0] != "a" || v[1] != "b" {
		t.Errorf("X-Custom = %v, want both values forwarded", v)
	}
	if got.Header.Get("X-Api-Key") != "sk-ant-test-credential" {
		t.Error("the credential was not forwarded untouched")
	}
	for _, dropped := range []string{"Keep-Alive", "Te", "X-Drop-Me"} {
		if got.Header.Get(dropped) != "" {
			t.Errorf("%s reached the upstream; hop-by-hop headers are removed (R20)", dropped)
		}
	}
	if got.Header.Get(HeaderRun) != testRun.ID {
		t.Errorf("X-Tego-Run = %q", got.Header.Get(HeaderRun))
	}
	// The response's own hop-by-hop header is removed on the way back; everything else passes.
	if resp.Header.Get("retry-after") != "3" || resp.Header.Get("x-should-retry") != "false" {
		t.Errorf("rate-limit headers did not reach the client: %v", resp.Header)
	}

	reqs := h.sink.waitFor(t, record.KindSSLRequest, 1)
	rp := payloadOf[record.SSLRequestPayload](t, reqs[0])
	// The recorded target is what the client sent, query included: the uprobe tier reads the request line
	// off the wire and records the whole target, so the forwarder must too or the same request reads
	// differently depending on which tier saw it. Query values never reach disk; ledger.RedactTarget
	// removes them in the pipeline.
	if rp.Method != http.MethodPost || rp.Path != "/v1/messages?beta=true" || rp.Host != h.listener.Model().Host {
		t.Errorf("ssl_request = %+v", rp)
	}
	if rp.Endpoint != "anthropic" {
		t.Errorf("endpoint = %q, want the declared provider", rp.Endpoint)
	}
	if rp.Size != len(body) {
		t.Errorf("size = %d, want %d", rp.Size, len(body))
	}
	if strings.Contains(strings.Join(mapValues(rp.Headers), " "), "sk-ant-") {
		t.Error("a credential reached the ssl_request payload (I5)")
	}
	if rp.Headers["anthropic-version"] != "2023-06-01" {
		t.Errorf("headers = %v, want the allow-listed ones kept", rp.Headers)
	}
	resps := h.sink.waitFor(t, record.KindSSLResponse, 1)
	sp := payloadOf[record.SSLResponsePayload](t, resps[0])
	if sp.Status != 200 || sp.RequestID != rp.RequestID {
		t.Errorf("ssl_response = %+v, want it correlated with the request", sp)
	}
	if sp.Headers["request-id"] != "req_011CS0001" {
		t.Errorf("response headers = %v, want the upstream request id kept", sp.Headers)
	}
}

// mapValues is the values of a string map, for a credential scan.
func mapValues(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// A server-sent event stream reaches the client as it is produced. The upstream waits for the
// client to have read chunk N before it writes chunk N+1, so the test cannot pass if anything buffers
// (capture-derive.md R21, E22).
func TestStreamingIsNotBuffered(t *testing.T) {
	const chunks = 4
	read := make(chan int, chunks)
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		for i := 0; i < chunks; i++ {
			if _, err := w.Write([]byte("data: {\"n\":" + itoa(i) + "}\n\n")); err != nil {
				return
			}
			if err := rc.Flush(); err != nil {
				return
			}
			select {
			case got := <-read:
				if got != i {
					t.Errorf("client read chunk %d while the server was at %d", got, i)
				}
			case <-time.After(5 * time.Second):
				t.Error("the client never saw a chunk the upstream had already flushed")
				return
			}
		}
	}, Options{})

	resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","stream":true}`), nil)
	defer resp.Body.Close()
	buf := make([]byte, 64)
	for i := 0; i < chunks; i++ {
		n, err := resp.Body.Read(buf)
		if err != nil {
			t.Fatalf("chunk %d: %v", i, err)
		}
		if !bytes.Contains(buf[:n], []byte("\"n\":"+itoa(i))) {
			t.Fatalf("chunk %d = %q", i, buf[:n])
		}
		read <- i
	}
	_, _ = io.Copy(io.Discard, resp.Body)
}

// A body larger than the capture cap is forwarded in full and recorded as truncated; capture
// bounds what it keeps, never what the agent sends.
func TestLargeBodyIsForwardedWhole(t *testing.T) {
	const size = 3 << 20
	body := bytes.Repeat([]byte("abcdefgh"), size/8)
	want := sha256.Sum256(body)
	var got [32]byte
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream read: %v", err)
		}
		got = sha256.Sum256(b)
		w.WriteHeader(http.StatusOK)
	}, Options{MaxBody: 64 << 10})

	resp := h.post("/v1/messages", body, nil)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if got != want {
		t.Error("the upstream did not receive the body byte for byte")
	}
	rp := payloadOf[record.SSLRequestPayload](t, h.sink.waitFor(t, record.KindSSLRequest, 1)[0])
	if rp.Size != size {
		t.Errorf("size = %d, want the whole %d the client sent", rp.Size, size)
	}
	h.sink.waitFor(t, record.KindSSLResponse, 1)
	gaps := h.sink.of(record.KindGap)
	if len(gaps) != 0 {
		t.Errorf("a capped capture emitted %d gap events; the cap is counted, not announced per body", len(gaps))
	}
	if n := gapCount(h.listener, GapSizeCap); n == 0 {
		t.Error("the capture cap was not counted as a gap for the run's report")
	}
}

// gapCount reads one why's count from a listener's report.
func gapCount(l *Listener, why string) int64 {
	for _, g := range l.Gaps() {
		if g.Why == why {
			return g.Count
		}
	}
	return 0
}

// A retry of a held request is recognised and recorded, and a first attempt never is (capture-derive.md R23).
func TestRetryRecognition(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, Options{})
	body := []byte(`{"model":"claude-opus-5","messages":[{"role":"user","content":"hi"}]}`)
	cred := http.Header{"X-Api-Key": {"sk-ant-test-credential"}}

	first := h.post("/v1/messages", body, cred)
	first.Body.Close()
	retry := h.post("/v1/messages", body, cred)
	retry.Body.Close()
	other := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","messages":[]}`), cred)
	other.Body.Close()
	counted := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","messages":[1]}`),
		http.Header{"X-Api-Key": {"sk-ant-test-credential"}, RetryHeader: {"2"}})
	counted.Body.Close()
	zero := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","messages":[2]}`),
		http.Header{"X-Api-Key": {"sk-ant-test-credential"}, RetryHeader: {"0"}})
	zero.Body.Close()
	bad := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","messages":[3]}`),
		http.Header{"X-Api-Key": {"sk-ant-test-credential"}, RetryHeader: {"not-a-number"}})
	bad.Body.Close()

	reqs := h.sink.waitFor(t, record.KindSSLRequest, 6)
	if len(reqs) != 6 {
		t.Fatalf("%d requests recorded, want 6 — a retry is recognised, never suppressed (R23)", len(reqs))
	}
	p := make([]record.SSLRequestPayload, len(reqs))
	for i, ev := range reqs {
		p[i] = payloadOf[record.SSLRequestPayload](t, ev)
	}
	if p[0].RetryOf != "" {
		t.Errorf("the first attempt was tagged retry_of=%q", p[0].RetryOf)
	}
	if p[1].RetryOf != p[0].RequestID {
		t.Errorf("retry_of = %q, want the original's id %q", p[1].RetryOf, p[0].RequestID)
	}
	if p[2].RetryOf != "" {
		t.Errorf("a different body was tagged retry_of=%q", p[2].RetryOf)
	}
	if p[3].RetryOf != p[2].RequestID {
		t.Errorf("a counted retry with a changed body: retry_of = %q, want the preceding request", p[3].RetryOf)
	}
	if p[4].RetryOf != "" || p[5].RetryOf != "" {
		t.Errorf("retry-count 0 and a non-numeric count are first attempts (#29): %q %q", p[4].RetryOf, p[5].RetryOf)
	}
}

// An upstream that fails is a 502 to the agent, an ssl_request with no response, and the one
// gap that explains the missing pair (R26, §7, I4).
func TestUpstreamFailure(t *testing.T) {
	h := newHarness(t, func(http.ResponseWriter, *http.Request) {}, Options{})
	h.upstream.Close() // nothing is listening any more

	resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5"}`), nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", resp.StatusCode)
	}
	h.sink.waitFor(t, record.KindGap, 1)
	if len(h.sink.of(record.KindSSLRequest)) != 1 {
		t.Error("the request was not recorded")
	}
	if len(h.sink.of(record.KindSSLResponse)) != 0 {
		t.Error("an ssl_response was recorded for a response that never arrived")
	}
	gaps := h.sink.of(record.KindGap)
	if len(gaps) != 1 {
		t.Fatalf("%d gap events, want exactly one", len(gaps))
	}
	g := payloadOf[record.GapPayload](t, gaps[0])
	if g.What != record.GapCapture || g.Why != GapMalformed {
		t.Errorf("gap = %+v, want what=capture why=malformed", g)
	}
}

// The health check is answered locally, with the upstream unreachable and whatever body the
// client attached drained and discarded (capture-derive.md R22, E30, #30).
func TestHelloIsAnsweredLocally(t *testing.T) {
	var reached bool
	h := newHarness(t, func(http.ResponseWriter, *http.Request) { reached = true }, Options{})
	h.upstream.Close()

	req, err := http.NewRequest(http.MethodHead, h.listener.BaseURL()+HelloPath,
		strings.NewReader("a body a health check should not have"))
	if err != nil {
		t.Fatal(err)
	}
	resp := h.do(req)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if resp.ContentLength != 0 {
		t.Errorf("content-length = %d, want 0", resp.ContentLength)
	}
	if reached {
		t.Error("the health check contacted the upstream")
	}
	if len(h.sink.all()) != 0 {
		t.Errorf("the local answer produced %d events, want none", len(h.sink.all()))
	}
}

// A tracestate the client split across several header lines is one list (W3C Trace
// Context): the members of every line travel upstream, after tego's own, as one line (R20).
func TestTracestateAcrossHeaderLinesIsOneList(t *testing.T) {
	var got []string
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Values(HeaderTracestate)
		w.WriteHeader(http.StatusOK)
	}, Options{})
	header := http.Header{}
	header.Set(HeaderTraceparent, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	header.Add(HeaderTracestate, "a=1")
	header.Add(HeaderTracestate, "b=2")
	resp := h.post("/v1/messages", []byte(`{}`), header)
	_ = resp.Body.Close()
	want := "tego=" + h.listener.runRef().ID + ",a=1,b=2"
	if len(got) != 1 || got[0] != want {
		t.Errorf("upstream tracestate = %q, want [%q]", got, want)
	}
}

// With a Dispatcher in place the ssl_response carries what the parser read and the decisions
// follow it — the forwarder path and the uprobe path produce the same shapes (§1, I11).
func TestDerivationFillsTheResponse(t *testing.T) {
	const body = `{"id":"msg_01Xq0001Z","type":"message","model":"claude-opus-5","stop_reason":"tool_use",` +
		`"content":[{"type":"tool_use","id":"toolu_010001A","name":"bash","input":{"command":"ls"}}],` +
		`"usage":{"input_tokens":1000,"output_tokens":102,"cache_creation_input_tokens":512}}`
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}, Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})

	resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","messages":[]}`), nil)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	sp := payloadOf[record.SSLResponsePayload](t, h.sink.waitFor(t, record.KindSSLResponse, 1)[0])
	if sp.Model != "claude-opus-5" || sp.ResponseID != "msg_01Xq0001Z" || sp.StopReason != "tool_use" {
		t.Errorf("ssl_response = %+v", sp)
	}
	if sp.ParserVersion != anthropic.ParserVersion {
		t.Errorf("parser_version = %q, want it always stamped (I6)", sp.ParserVersion)
	}
	if sp.Usage == nil || sp.Usage.Input != 1000 || sp.Usage.Output != 102 || sp.Usage.CacheWrite != 512 {
		t.Errorf("usage = %+v", sp.Usage)
	}
	decisions := h.sink.waitFor(t, record.KindDecision, 1)
	if len(decisions) != 1 {
		t.Fatalf("%d decisions, want 1", len(decisions))
	}
	d := payloadOf[record.DecisionPayload](t, decisions[0])
	if d.Tool != "bash" || d.ToolUseID != "toolu_010001A" || d.Unparsed {
		t.Errorf("decision = %+v", d)
	}
	// The response's recorded body is the body the client received, byte for byte (I10; the blob and
	// derive's own copy are compared by hash in TestDeriveReadsTheBytesTheBlobHolds).
	var recorded struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(h.sink.of(record.KindSSLResponse)[0].Payload, &recorded); err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256([]byte(recorded.Body)) != sha256.Sum256([]byte(body)) {
		t.Errorf("the recorded body is not the body that was streamed: %q", recorded.Body)
	}
}

// A gzip response is recorded and parsed decoded, while content_encoding still says what the
// wire carried (R15).
func TestGzipResponseIsDecodedForTheRecord(t *testing.T) {
	payload := `{"id":"msg_1","type":"message","model":"claude-opus-5","stop_reason":"end_turn",` +
		`"content":[{"type":"text","text":"hello"}],"usage":{"input_tokens":1,"output_tokens":1}}`
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gzipBytes(t, payload))
	}, Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})

	resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","messages":[]}`), nil)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	ev := h.sink.waitFor(t, record.KindSSLResponse, 1)[0]
	sp := payloadOf[record.SSLResponsePayload](t, ev)
	if sp.ContentEncoding != "gzip" {
		t.Errorf("content_encoding = %q, want what the wire used", sp.ContentEncoding)
	}
	if sp.Model != "claude-opus-5" {
		t.Errorf("the compressed body was not decoded before parsing: %+v", sp)
	}
	if !strings.Contains(string(ev.Payload), `hello`) {
		t.Error("the recorded body is not the decoded content")
	}
}

// An encoding this component cannot decode is recorded as what it is and derived as unparsed
// why=encoding, never parsed as noise (R15, R29).
func TestUndecodableEncodingIsUnparsed(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "br")
		_, _ = w.Write([]byte{0x1b, 0x2f, 0x00, 0xf8})
	}, Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})

	resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","messages":[]}`), nil)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	decisions := h.sink.waitFor(t, record.KindDecision, 1)
	if len(decisions) != 1 {
		t.Fatalf("%d decisions, want one unparsed", len(decisions))
	}
	d := payloadOf[record.DecisionPayload](t, decisions[0])
	if !d.Unparsed || d.Why != derive.WhyEncoding {
		t.Errorf("decision = %+v, want unparsed why=encoding", d)
	}
}

// T-fwd-15id: `Content-Encoding: identity` is the coding that says no coding was applied.
//
// R15's vocabulary treats "" and "identity" alike, and the response half reads exactly that rule through
// identityEncoding. The request half asks a narrower question — "is the header empty" — so a plain body
// labelled identity reaches derive as undecoded and comes back `decision: unparsed why=encoding`, losing
// the model, the tools and the messages of a request whose structure was never in question (R29: encoding
// is for bytes that never became text).
//
// Both checks are made without racing derive. The ssl_response is built from facts derive has already
// computed, and the upstream's reply names no model, so the model it carries can only be the request's.
// The decisions are emitted after the ssl_response, so they are read only once the reply's own tool_use
// decision is in: the parser puts an unparsed request half's decision ahead of the response's
// (anthropic.Parser.Parse), so by then any such decision is in the sink too.
func TestAnIdentityEncodedRequestIsNotReportedUndecoded(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","stop_reason":"tool_use",` +
			`"content":[{"type":"tool_use","id":"toolu_1","name":"bash","input":{"command":"ls"}}],` +
			`"usage":{"input_tokens":1,"output_tokens":1}}`))
	}, Options{Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New()})})

	resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","messages":[]}`),
		http.Header{"Content-Encoding": {"identity"}})
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	sp := payloadOf[record.SSLResponsePayload](t, h.sink.waitFor(t, record.KindSSLResponse, 1)[0])
	if sp.Model != "claude-opus-5" {
		t.Errorf("ssl_response model = %q, want the request's claude-opus-5: a request body labelled "+
			"Content-Encoding: identity was not read as the plain JSON it is (R15)", sp.Model)
	}

	var decisions []record.DecisionPayload
	deadline := time.Now().Add(5 * time.Second)
	for {
		decisions = decisions[:0]
		answered := false
		for _, ev := range h.sink.of(record.KindDecision) {
			d := payloadOf[record.DecisionPayload](t, ev)
			decisions = append(decisions, d)
			answered = answered || d.ToolUseID == "toolu_1"
		}
		if answered {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the reply's tool_use decision never arrived; decisions so far: %+v", decisions)
		}
		time.Sleep(time.Millisecond)
	}
	for _, d := range decisions {
		if d.Unparsed && d.Why == derive.WhyEncoding {
			t.Errorf("a request body labelled Content-Encoding: identity was derived %+v; identity "+
				"names no coding at all, so there was nothing for capture to undo (R15)", d)
		}
	}
}

// A request in flight when the run ends is closed to a gap, not dropped (#28, I4).
func TestCloseEndsInflightRequests(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	landed := make(chan struct{})
	h := newHarness(t, func(http.ResponseWriter, *http.Request) {
		defer close(landed)
		close(started)
		<-release
	}, Options{})
	// Registered after the harness so it runs first: a Fatal before the release below would otherwise
	// leave the upstream handler blocked, and httptest.Server.Close waits for it forever.
	var clients sync.WaitGroup
	unblock := releaseOnCleanup(t, release, &clients)
	clients.Add(1)
	go func() {
		defer clients.Done()
		resp, err := h.client.Post(h.listener.BaseURL()+"/v1/messages", "application/json",
			strings.NewReader(`{"model":"claude-opus-5"}`))
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-started
	if err := h.listener.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	unblock()
	gaps := h.sink.waitFor(t, record.KindGap, 1)
	if len(gaps) != 1 {
		t.Fatalf("%d gaps, want one for the request that was never answered", len(gaps))
	}
	if g := payloadOf[record.GapPayload](t, gaps[0]); g.Why != GapMalformed {
		t.Errorf("gap = %+v", g)
	}
	// The response arrives after Close claimed the exchange: it is recorded once, as the gap, and
	// never again as a pair.
	if err := h.listener.Close(); err != nil {
		t.Errorf("a second close: %v", err)
	}
	// Wait for the upstream's answer to be written, not for 20 ms. Close joined the listener's own handlers
	// before it claimed the exchange, so once the upstream has answered nothing is left running that could
	// record it.
	select {
	case <-landed:
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream handler did not return after its release")
	}
	clients.Wait()
	if n := len(h.sink.of(record.KindGap)); n != 1 {
		t.Errorf("%d gaps after the response landed and a second close, want 1", n)
	}
	if n := len(h.sink.of(record.KindSSLResponse)); n != 0 {
		t.Errorf("%d ssl_response events for an exchange the run ended, want 0", n)
	}
}

// An h2 preface on the plaintext listener is refused and recorded, never reassembled (R17,
// R19, R37). The handler is driven directly: Go's own HTTP/1.1 server rejects the preface before a
// handler would see it, which is the same refusal one layer lower.
func TestH2PrefaceIsAGap(t *testing.T) {
	h := newHarness(t, func(http.ResponseWriter, *http.Request) {
		t.Error("an h2 preface reached the upstream")
	}, Options{})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("PRI", "/", nil)
	req.RequestURI = "*"
	serveDirect(h.listener, rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	gaps := h.sink.of(record.KindGap)
	if len(gaps) != 1 {
		t.Fatalf("%d gaps, want one", len(gaps))
	}
	if g := payloadOf[record.GapPayload](t, gaps[0]); g.Why != GapH2 {
		t.Errorf("gap = %+v, want why=h2", g)
	}
}

// Concurrent requests keep their own identity, their own retry key and their own events.
func TestConcurrentRequests(t *testing.T) {
	h := newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, _ = w.Write(b)
	}, Options{})
	const n = 16
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp := h.post("/v1/messages", []byte(`{"model":"claude-opus-5","i":`+itoa(i)+`}`), nil)
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}(i)
	}
	wg.Wait()
	h.sink.waitFor(t, record.KindSSLResponse, n)
	if got := len(h.sink.of(record.KindSSLRequest)); got != n {
		t.Errorf("%d ssl_request events, want %d", got, n)
	}
	if got := len(h.sink.of(record.KindSSLResponse)); got != n {
		t.Errorf("%d ssl_response events, want %d", got, n)
	}
	ids := map[string]bool{}
	for _, ev := range h.sink.of(record.KindSSLRequest) {
		p := payloadOf[record.SSLRequestPayload](t, ev)
		if ids[p.RequestID] {
			t.Errorf("request id %q reused", p.RequestID)
		}
		ids[p.RequestID] = true
		if p.RetryOf != "" {
			t.Errorf("a distinct body was tagged retry_of=%q", p.RetryOf)
		}
	}
}

// A Manager serves one listener per declared entry and names the variables the run installs.
func TestManagerListenersAndVars(t *testing.T) {
	models := []agent.ModelEndpoint{
		{Provider: "anthropic", Host: "api.anthropic.com", Port: 443},
		{Provider: "google", Host: "generativelanguage.googleapis.com", Port: 443},
		{Provider: "unknown-provider", Host: "example.invalid", Port: 443},
	}
	m, err := NewManager(models, Options{})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer func() {
		if err := m.Stop(); err != nil {
			t.Errorf("stop: %v", err)
		}
	}()
	if len(m.Listeners()) != 3 {
		t.Fatalf("%d listeners, want one per models entry (R19)", len(m.Listeners()))
	}
	seen := map[string]bool{}
	for _, l := range m.Listeners() {
		if !strings.HasPrefix(l.BaseURL(), "http://127.0.0.1:") {
			t.Errorf("base url = %q, want a plaintext loopback url", l.BaseURL())
		}
		if seen[l.BaseURL()] {
			t.Errorf("two entries share one listener: %s", l.BaseURL())
		}
		seen[l.BaseURL()] = true
	}
	vars := m.Vars()
	if vars["ANTHROPIC_BASE_URL"] != m.Listeners()[0].BaseURL() {
		t.Errorf("ANTHROPIC_BASE_URL = %q", vars["ANTHROPIC_BASE_URL"])
	}
	for _, name := range []string{"GOOGLE_GEMINI_BASE_URL", "GOOGLE_VERTEX_BASE_URL", "CODE_ASSIST_ENDPOINT"} {
		if vars[name] != m.Listeners()[1].BaseURL() {
			t.Errorf("%s = %q", name, vars[name])
		}
	}
	if len(vars) != 4 {
		t.Errorf("vars = %v, want nothing for a provider with no known variable", vars)
	}

	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Start(ctx, testRun, sink); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := m.Start(ctx, testRun, sink); !errors.Is(err, ErrAlreadyStarted) {
		t.Errorf("second start: %v, want ErrAlreadyStarted", err)
	}
	if m.Name() != Name {
		t.Errorf("name = %q", m.Name())
	}
}

// A listener with no models host is refused before a run starts.
func TestNewListenerRefusesAnEmptyHost(t *testing.T) {
	if _, err := NewListener(agent.ModelEndpoint{Provider: "anthropic"}, Options{}); !errors.Is(err, ErrListener) {
		t.Errorf("err = %v, want ErrListener", err)
	}
}

// BenchmarkForward measures one forwarded request end to end: the budgeted path (§9 Benchmarks, ~100 µs
// per request against a local upstream).
func BenchmarkForward(b *testing.B) { benchmarkForward(b, Options{}) }

// BenchmarkForwardStallBudget is BenchmarkForward for a run with a stall budget, whose relays report their
// chunks to the stall check (Options.Activity, limits R4): the same path plus one clock read per chunk and at
// most one report per activityGrain. It must allocate what BenchmarkForward does and cost within 3% of it.
func BenchmarkForwardStallBudget(b *testing.B) {
	var reports atomic.Int64
	benchmarkForward(b, Options{Activity: func(uint64) { reports.Add(1) }})
}

// benchmarkForward is BenchmarkForward over opts, whose Transport it sets.
func benchmarkForward(b *testing.B, opts Options) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()
	host, portStr, _ := net.SplitHostPort(up.Listener.Addr().String())
	port, err := strconv.Atoi(portStr)
	if err != nil {
		b.Fatal(err)
	}
	opts.Transport = up.Client().Transport
	l, err := NewListener(agent.ModelEndpoint{Provider: "anthropic", Host: host, Port: port}, opts)
	if err != nil {
		b.Fatal(err)
	}
	l.Bind(testRun, &fakeSink{})
	// R19a's admission is per connection, and this loop reuses one, so measuring it here would divide
	// one /proc walk across every iteration and report it as noise on the per-request path this
	// benchmark sizes (§9 Benchmarks). It is left out rather than amortized into the number.
	l.peers = anyPeer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = l.Serve(ctx) }()
	defer l.Close()

	client := &http.Client{}
	body := []byte(`{"model":"claude-opus-5","messages":[{"role":"user","content":"hi"}]}`)
	b.ReportAllocs()
	for b.Loop() {
		resp, err := client.Post(l.BaseURL()+"/v1/messages", "application/json", bytes.NewReader(body))
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

// itoa is strconv.Itoa, named short because the streaming case builds many small bodies.
func itoa(i int) string { return strconv.Itoa(i) }

// gzipBytes compresses s the way an upstream does.
func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// Every listener's bound address is reported once, unwrapped and in declaration order, so the
// run can admit exactly the ports its own base URLs name (R38). A base URL the enforcement tier did not
// admit is a forwarder the agent cannot reach, which is why the two are read off the same listener.
func TestManagerEndpointsMatchTheBaseURLs(t *testing.T) {
	models := []agent.ModelEndpoint{
		{Provider: "anthropic", Host: "api.anthropic.com", Port: 443},
		{Provider: "anthropic", Host: "api.anthropic.com", Port: 443},
	}
	m, err := NewManager(models, Options{})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	defer func() {
		if err := m.Stop(); err != nil {
			t.Errorf("stop: %v", err)
		}
	}()
	eps := m.Endpoints()
	if len(eps) != len(models) {
		t.Fatalf("%d endpoints, want one per listener", len(eps))
	}
	for i, ep := range eps {
		if !ep.Addr().Is4() || !ep.Addr().IsLoopback() || ep.Port() == 0 {
			t.Errorf("endpoint %d is %v, want a bound IPv4 loopback address", i, ep)
		}
		if want := "http://" + ep.String(); m.Listeners()[i].BaseURL() != want {
			t.Errorf("listener %d serves %q but reports endpoint %v", i, m.Listeners()[i].BaseURL(), ep)
		}
	}
	if eps[0] == eps[1] {
		t.Errorf("two entries on one upstream share a port: %v", eps[0])
	}
}

// blockingClock holds the first reading of the clock until the test lets it go. readRequest takes that
// reading after the body is read and before the exchange is tracked, which puts a handler in the one
// window Close cannot claim its way out of: nothing is in inflight yet, so only joining the handler keeps
// what it goes on to emit ahead of the run's drain.
type blockingClock struct {
	inner   *fixedClock
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (c *blockingClock) Now() time.Time {
	c.once.Do(func() {
		close(c.entered)
		<-c.release
	})
	return c.inner.Now()
}

func (c *blockingClock) Mono() uint64 { return c.inner.Mono() }

// Close returns only once the handlers it interrupted have finished.
//
// srv.Close() closes the connections but never waits for the handlers running on them, and Manager.Stop
// waits only for the Serve goroutines. A handler still running past Stop emits into a queue the run has
// already drained (R8 of docs/p0/runtime-launch.md) — the events and the gap counters it raises reach
// nobody, which is the silent shortfall I4 forbids.
func TestCloseWaitsForTheHandlersItInterrupted(t *testing.T) {
	clock := &blockingClock{inner: newClock(), entered: make(chan struct{}), release: make(chan struct{})}
	h := newHarness(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}, Options{Clock: clock})
	go func() {
		resp, err := h.client.Post(h.listener.BaseURL()+"/v1/messages", "application/json",
			strings.NewReader(`{"model":"claude-opus-5"}`))
		if err == nil {
			resp.Body.Close()
		}
	}()
	<-clock.entered
	go func() {
		// Long enough that a Close which does not wait has returned well before the handler can
		// emit anything, so the assertion below is about the join and not about a race.
		time.Sleep(50 * time.Millisecond)
		close(clock.release)
	}()

	if err := h.listener.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if n := len(h.sink.of(record.KindSSLRequest)); n != 1 {
		t.Errorf("%d ssl_request events when Close returned, want the 1 the running handler owes: "+
			"an event emitted after the run's drain has no reader left (I4)", n)
	}
}
