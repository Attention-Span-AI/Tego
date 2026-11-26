// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/policy/httppolicy"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// limitHarness is a listener whose gate a test closes, in front of an upstream that counts what reaches it.
type limitHarness struct {
	*harness
	closed   atomic.Bool
	upstream atomic.Int64
}

func newLimitHarness(t *testing.T) *limitHarness {
	t.Helper()
	lh := &limitHarness{}
	lh.harness = newHarness(t, func(w http.ResponseWriter, r *http.Request) {
		lh.upstream.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","model":"m","content":[],"usage":{"input_tokens":1,"output_tokens":1}}`))
	}, Options{LimitGate: func() (string, record.Reason, bool) {
		if lh.closed.Load() {
			return "limits.repeats", record.ReasonLimitRepeats, true
		}
		return "", "", false
	}})
	return lh
}

// TestALimitGateAdmitsWhileOpenAndRefusesOnceClosed is the admission check: with the gate open a request is forwarded,
// recorded and answered; once the run's budget has closed it, the next request is answered here with 403, recorded once
// as a refused net line under the budget's rule and reason, and never reaches the upstream.
func TestALimitGateAdmitsWhileOpenAndRefusesOnceClosed(t *testing.T) {
	h := newLimitHarness(t)
	resp := h.post("/v1/messages", []byte(`{"model":"m","max_tokens":1}`), nil)
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || h.upstream.Load() != 1 {
		t.Fatalf("an open gate answered %d with %d upstream requests, want 200 and 1", resp.StatusCode, h.upstream.Load())
	}
	h.sink.waitFor(t, record.KindSSLResponse, 1)
	for _, e := range h.sink.of(record.KindNet) {
		t.Fatalf("an open gate recorded a net line: %+v", e)
	}
	requests := len(h.sink.of(record.KindSSLRequest))

	h.closed.Store(true)
	resp = h.post("/v1/messages", []byte(`{"model":"m","max_tokens":1,"x":2}`), nil)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a closed gate answered %d, want 403 (a status the SDKs do not retry)", resp.StatusCode)
	}
	if resp.Header.Get("X-Should-Retry") != "false" {
		t.Errorf("X-Should-Retry = %q, want false", resp.Header.Get("X-Should-Retry"))
	}
	if !strings.Contains(string(body), "limits.repeats") || !strings.Contains(string(body), "nothing more is sent to the model") {
		t.Errorf("refusal text %q does not say which limit and that nothing is sent on", body)
	}
	if n := h.upstream.Load(); n != 1 {
		t.Fatalf("%d requests reached the upstream, want only the one admitted before the gate closed", n)
	}
	nets := h.sink.waitFor(t, record.KindNet, 1)
	if len(nets) != 1 {
		t.Fatalf("%d net lines for one refused request, want 1", len(nets))
	}
	ev := nets[0]
	if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonLimitRepeats || ev.Rule != "limits.repeats" || ev.Authority != record.AuthorityRule {
		t.Errorf("net line verdict %q reason %q rule %q authority %q, want refused / limit-repeats / limits.repeats / rule",
			ev.Verdict, ev.Reason, ev.Rule, ev.Authority)
	}
	if got := payloadOf[record.NetPayload](t, ev); got.Op != "http_request" || got.Method != http.MethodPost || got.Path != "/v1/messages" {
		t.Errorf("net payload %+v, want the refused POST /v1/messages", got)
	}
	if n := len(h.sink.of(record.KindSSLRequest)); n != requests {
		t.Errorf("%d ssl_request lines, want the %d before the gate closed: a refused request is not a model request", n, requests)
	}
	if n := len(h.sink.of(record.KindSSLResponse)); n != 1 {
		t.Errorf("%d ssl_response lines, want 1: nothing was answered by the model after the gate closed", n)
	}
}

// TestAClosedLimitGateRefusesEveryKindOfRequest: a CONNECT, an upgrade and the health check are turned away by the same
// check, so no request of any kind is admitted toward the model, and none reaches the upstream.
func TestAClosedLimitGateRefusesEveryKindOfRequest(t *testing.T) {
	h := newLimitHarness(t)
	h.closed.Store(true)
	for _, c := range []struct {
		name   string
		method string
		path   string
		header http.Header
	}{
		{"get", http.MethodGet, "/v1/models", nil},
		{"health check", http.MethodHead, HelloPath, nil},
		{"upgrade", http.MethodGet, "/v1/messages", http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			u, _ := url.Parse(h.listener.BaseURL() + c.path)
			resp := h.do(&http.Request{Method: c.method, URL: u, Header: c.header})
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("%s answered %d, want 403", c.name, resp.StatusCode)
			}
		})
	}
	if n := h.upstream.Load(); n != 0 {
		t.Fatalf("%d requests reached the upstream through a closed gate", n)
	}
}

// TestALimitGateIsOneAtomicLoadOnTheRequestPath: no gate is no check, and an open one allocates nothing.
func TestALimitGateIsOneAtomicLoadOnTheRequestPath(t *testing.T) {
	var closed atomic.Bool
	gate := LimitGate(func() (string, record.Reason, bool) { return "", "", closed.Load() })
	if n := testing.AllocsPerRun(100, func() { _, _, _ = gate() }); n != 0 {
		t.Fatalf("an open gate allocated %v times per call, want 0", n)
	}
	l := &Listener{}
	if l.refuseAtLimit(nil, nil, 0) {
		t.Fatal("a listener with no gate refused a request")
	}
}

// TestManagerLimitGateReachesEveryListenerBeforeStart: the runtime wires the gate through the Manager, before Start; after
// Start the wiring is refused, so a handler never reads a gate being replaced.
func TestManagerLimitGateReachesEveryListenerBeforeStart(t *testing.T) {
	models := []agent.ModelEndpoint{{Provider: "anthropic", Host: "a.example"}, {Provider: "openai", Host: "b.example"}}
	m, err := NewManager(models, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop() })
	gate := func() (string, record.Reason, bool) { return "limits.tokens", record.ReasonLimitTokens, true }
	m.SetLimitGate(gate)
	for i, l := range m.Listeners() {
		if l.opts.LimitGate == nil {
			t.Fatalf("listener %d has no gate", i)
		}
	}
	if err := m.Start(t.Context(), testRun, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	m.SetLimitGate(nil)
	if m.Listeners()[0].opts.LimitGate == nil {
		t.Fatal("SetLimitGate replaced the gate of a started manager")
	}
}

// TestARequestHeldWhenTheGateClosesIsRefusedOnRelease: a request held for a person's approval when the run's budget is
// crossed is not sent when the approval comes: the second check, where every hold ends, refuses it as one arriving now, and
// records it once. Nothing reaches the upstream.
func TestARequestHeldWhenTheGateClosesIsRefusedOnRelease(t *testing.T) {
	var closed atomic.Bool
	var upstream atomic.Int64
	asked, release := make(chan struct{}), make(chan struct{})
	l, sink := askHarnessGated(t, 64, askBudget(t), func() (string, record.Reason, bool) {
		if closed.Load() {
			return "limits.tokens", record.ReasonLimitTokens, true
		}
		return "", "", false
	}, func(context.Context, ask.Request) (ask.Decision, error) {
		close(asked)
		<-release
		return ask.Decision{Approved: true}, nil
	}, func(w http.ResponseWriter, r *http.Request) { upstream.Add(1) })
	type answer struct {
		status int
		body   string
		err    error
	}
	done := make(chan answer, 1)
	go func() {
		resp, err := (&http.Client{Timeout: 30 * time.Second}).Post(l.BaseURL()+"/allowed", "text/plain", strings.NewReader("complete"))
		if err != nil {
			done <- answer{err: err}
			return
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		done <- answer{status: resp.StatusCode, body: string(b)}
	}()
	select {
	case <-asked:
	case <-time.After(10 * time.Second):
		t.Fatal("the request was never held for approval")
	}
	closed.Store(true)
	close(release)
	a := <-done
	if a.err != nil || a.status != http.StatusForbidden || !strings.Contains(a.body, "limits.tokens") {
		t.Fatalf("a request released after the gate closed got %d %q (%v), want 403 naming limits.tokens", a.status, a.body, a.err)
	}
	if n := upstream.Load(); n != 0 {
		t.Fatalf("%d requests reached the upstream after the gate closed while one was held", n)
	}
	refused := 0
	for _, e := range sink.of(record.KindNet) {
		if e.Rule == "limits.tokens" && e.Verdict == record.VerdictRefused && e.Reason == record.ReasonLimitTokens {
			refused++
		}
	}
	if refused != 1 {
		t.Fatalf("%d limit refusal lines for one held request, want 1", refused)
	}
	if n := len(sink.of(record.KindSSLRequest)); n != 0 {
		t.Fatalf("%d ssl_request lines for a request that was never sent", n)
	}
}

// TestARefusalLineClampsAHugePath: the refusal is written for a request nothing has validated, so its line carries at most
// httppolicy.MaxPathBytes of the path, as a policy line (whose path CanonicalPath checked first) never carries more.
func TestARefusalLineClampsAHugePath(t *testing.T) {
	h := newLimitHarness(t)
	h.closed.Store(true)
	path := "/v1/" + strings.Repeat("a", 900_000)
	resp := h.post(path, []byte(`{}`), nil)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a huge path answered %d, want 403", resp.StatusCode)
	}
	nets := h.sink.waitFor(t, record.KindNet, 1)
	if len(nets) != 1 {
		t.Fatalf("%d net lines, want 1", len(nets))
	}
	if got := payloadOf[record.NetPayload](t, nets[0]); len(got.Path) != httppolicy.MaxPathBytes || !strings.HasPrefix(got.Path, "/v1/aaaa") {
		t.Fatalf("recorded path of %d bytes, want the first %d", len(got.Path), httppolicy.MaxPathBytes)
	}
	for _, c := range []struct{ in, want string }{
		{"/short", "/short"},
		{strings.Repeat("a", httppolicy.MaxPathBytes-1) + "%2Fxyz", strings.Repeat("a", httppolicy.MaxPathBytes-1)},
		{strings.Repeat("a", httppolicy.MaxPathBytes-2) + "%2Fxyz", strings.Repeat("a", httppolicy.MaxPathBytes-2)},
		{strings.Repeat("a", httppolicy.MaxPathBytes-3) + "%2Fxyz", strings.Repeat("a", httppolicy.MaxPathBytes-3) + "%2F"},
	} {
		if got := clampPath(c.in); got != c.want {
			t.Errorf("clampPath(...%q) cut to %d bytes, want %d", c.in[len(c.in)-8:], len(got), len(c.want))
		}
	}
}

// TestAnOpenTunnelIsNotCutByTheGate pins the stated residue: a CONNECT tunnel that is already open keeps carrying bytes after
// the gate closes (until the run is killed), while a new CONNECT is refused. A net.proxy tunnel is refused only under token,
// cost and repeats budgets (ProxyPolicy.ValidateLimits), so a run with a wall or stall_after budget alone can have one open.
func TestAnOpenTunnelIsNotCutByTheGate(t *testing.T) {
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	go func() {
		c, err := up.Accept()
		if err == nil {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}
	}()
	host, port := hostPort(t, up.Addr().String())
	model := agent.ModelEndpoint{Host: host, Port: port}
	var closed atomic.Bool
	p := compiledProtocols(t, model, &agent.ProxyPolicy{Connect: []string{up.Addr().String()}})
	m, err := NewManager([]agent.ModelEndpoint{model}, Options{Proxy: p, LimitGate: func() (string, record.Reason, bool) {
		return "limits.wall", record.ReasonLimitWall, closed.Load()
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Stop() })
	id, err := liveCgroupID()
	if err != nil {
		t.Skipf("actual peer admission needs cgroup identity: %v", err)
	}
	run := testRun
	run.CgroupID, run.Contract = id, &agent.RuleTable{Record: agent.RecordSummary, Proxy: p}
	if err := m.Start(context.Background(), run, &fakeSink{}); err != nil {
		t.Fatal(err)
	}
	l := m.Listeners()[0]
	conn, reader, resp := protocolConn(t, l, connectRequest(up.Addr().String()), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT before the gate closed: %d", resp.StatusCode)
	}
	echo := func(s string) {
		t.Helper()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := conn.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(s))
		if _, err := io.ReadFull(reader, got); err != nil || string(got) != s {
			t.Fatalf("tunnel echo %q: %q, %v", s, got, err)
		}
	}
	echo("before")
	closed.Store(true)
	echo("after")
	if _, _, refused := protocolConn(t, l, connectRequest(up.Addr().String()), nil); refused.StatusCode != http.StatusForbidden {
		t.Fatalf("a new CONNECT after the gate closed: %d, want 403", refused.StatusCode)
	}
}
