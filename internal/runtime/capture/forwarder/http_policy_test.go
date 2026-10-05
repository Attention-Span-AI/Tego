// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/policy/httppolicy"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func policyFor(t *testing.T, host string, port int, allow, methods []string) *httppolicy.Policy {
	t.Helper()
	p, err := httppolicy.Compile([]httppolicy.Rule{{Host: host, Port: port, Allow: allow, Methods: methods}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type unreadBody struct{ reads int }

func (b *unreadBody) Read([]byte) (int, error) { b.reads++; return 0, fmt.Errorf("denied body read") }
func (*unreadBody) Close() error               { return nil }

func TestHTTPPolicyDeniesBeforeBodyAndTransport(t *testing.T) {
	l, err := NewListener(agent.ModelEndpoint{Host: "api.example.com", Port: 443}, Options{HTTPPolicy: policyFor(t, "api.example.com", 443, []string{"/v1/messages"}, []string{"POST"}), Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("denied request reached upstream")
		return nil, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	sink := &fakeSink{}
	run := testRun
	run.Contract = &agent.RuleTable{Record: agent.RecordOff}
	l.Bind(run, sink)
	for _, path := range []string{"/v1/messages-extra?secret=never-record", "/elsewhere"} {
		body := &unreadBody{}
		r := httptest.NewRequest("POST", "http://forged.example"+path, body)
		r.ContentLength = 100
		r.Header.Set("Expect", "100-continue")
		w := httptest.NewRecorder()
		serveDirect(l, w, r)
		if w.Code != 403 || body.reads != 0 || w.Header().Get("Connection") != "close" {
			t.Fatalf("status=%d reads=%d headers=%v", w.Code, body.reads, w.Header())
		}
	}
	if len(sink.of(record.KindSSLRequest)) != 0 || len(sink.of(record.KindSSLResponse)) != 0 {
		t.Fatal("policy refusal fabricated model exchange")
	}
	for _, ev := range sink.of(record.KindNet) {
		p := payloadOf[record.NetPayload](t, ev)
		if ev.Source != record.SourceForwarder || ev.Reason != record.ReasonNetHTTP || ev.Verdict != record.VerdictRefused || p.HTTPAuthority != "api.example.com:443" || p.Op != "http_request" || strings.Contains(p.Path, "?") {
			t.Fatalf("bad HTTP refusal %+v %+v", ev, p)
		}
	}
	if len(sink.of(record.KindNet)) != 2 {
		t.Fatal("record off dropped policy refusals")
	}
}

// policyHarness uses real TLS upstream sockets and production peer admission.
func policyHarness(t *testing.T, allow, methods []string, handler http.HandlerFunc) (*Listener, *fakeSink, *Manager) {
	t.Helper()
	up := httptest.NewTLSServer(handler)
	t.Cleanup(up.Close)
	host, port := hostPort(t, up.Listener.Addr().String())
	p := policyFor(t, host, port, allow, methods)
	m, err := NewManager([]agent.ModelEndpoint{{Provider: "anthropic", Host: host, Port: port}}, Options{HTTPPolicy: p, Transport: up.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	id, err := liveCgroupID()
	if err != nil {
		_ = m.Stop()
		t.Skipf("actual peer admission needs cgroup identity: %v", err)
	}
	run := testRun
	run.CgroupID = id
	run.Contract = &agent.RuleTable{Record: agent.RecordSummary, HTTP: p}
	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = m.Stop() })
	if err := m.Start(ctx, run, sink); err != nil {
		t.Fatal(err)
	}
	if !m.HTTPPolicyReady(p) {
		t.Fatal("accepted policy listener not ready")
	}
	return m.Listeners()[0], sink, m
}

func TestHTTPPolicyActualTLSUnionPeerAndFixedAuthority(t *testing.T) {
	var upstream atomic.Int64
	actual := make(chan string, 10)
	l, sink, _ := policyHarness(t, []string{"/v1/messages"}, []string{"POST"}, func(w http.ResponseWriter, r *http.Request) {
		upstream.Add(1)
		actual <- r.Host + " " + r.RequestURI
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	client := &http.Client{Timeout: 2 * time.Second}
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"POST", "/v1/messages?credential=unrecorded", 200}, {"POST", "/v1/messages/count_tokens", 200},
		{"GET", "/v1/messages", 403}, {"POST", "/v1/messages-extra", 403}, {"POST", "/v1/%2fmessages", 400}, {"POST", "/v1/%252fmessages", 400}, {"POST", "/v1/../messages", 400},
		// A server that cuts ;parameters before resolving serves these outside the prefix (SEMANTICS §5).
		{"POST", "/v1/messages/..;/admin", 400}, {"POST", "/v1/messages/..%3B/admin", 400}, {"POST", "/v1/messages/.;/x", 400},
	} {
		req, _ := http.NewRequest(tc.method, l.BaseURL()+tc.path, strings.NewReader("x"))
		req.Host = "attacker.invalid"
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("%s %s = %d", tc.method, tc.path, resp.StatusCode)
		}
	}
	if upstream.Load() != 2 {
		t.Fatalf("upstream requests %d", upstream.Load())
	}
	for i := 0; i < 2; i++ {
		got := <-actual
		if !strings.HasPrefix(got, l.hostHeader()+" /v1/messages") {
			t.Fatalf("fixed authority/request bytes changed: %q", got)
		}
	}
	for _, ev := range sink.waitFor(t, record.KindNet, 4) {
		if ev.PID != osPID() {
			t.Fatalf("request attributed to %d instead of accepted peer", ev.PID)
		}
		if strings.Contains(string(ev.Payload), "credential") {
			t.Fatal("HTTP decision retained query secret")
		}
	}
}

func osPID() int { return os.Getpid() }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestHTTPPolicyRawFramingAndPerRequestDecision(t *testing.T) {
	var upstream atomic.Int64
	l, _, _ := policyHarness(t, []string{"/allowed"}, []string{"GET"}, func(w http.ResponseWriter, r *http.Request) { upstream.Add(1); _, _ = w.Write([]byte("ok")) })
	for _, wire := range []string{
		"GET /allowed HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
		"GET /allowed HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nx",
		"POST /denied HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n",
		"POST /denied HTTP/1.1\r\nHost: a\r\nContent-Length: 1000\r\nExpect: 100-continue\r\n\r\n",
		"CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n",
		"GET /allowed HTTP/1.1\r\nHost: a\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n",
		"GET /allowed HTTP/1.1\r\nHost: a\r\nUpgrade: \r\nUpgrade: websocket\r\n\r\n",
		"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n",
	} {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.WriteString(c, wire)
		r, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			_ = c.Close()
			t.Fatalf("read refusal %q: %v", wire, err)
		}
		if r.StatusCode != 400 && r.StatusCode != 403 {
			t.Fatalf("raw request returned %d", r.StatusCode)
		}
		_ = r.Body.Close()
		_ = c.Close()
	}
	if upstream.Load() != 0 {
		t.Fatal("ambiguous/denied wire reached upstream")
	}
	// Same accepted socket, two decisions. The refusal closes only after its reply.
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(c, "GET /allowed HTTP/1.1\r\nHost: a\r\n\r\nGET /denied HTTP/1.1\r\nHost: a\r\n\r\n")
	br := bufio.NewReader(c)
	for _, want := range []int{200, 403} {
		r, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()
		if r.StatusCode != want {
			t.Fatalf("pipelined status %d want %d", r.StatusCode, want)
		}
	}
	if upstream.Load() != 1 {
		t.Fatalf("pipelined deny reached upstream: %d", upstream.Load())
	}
}

func TestHTTPPolicyManagerFailsBeforeReady(t *testing.T) {
	p := policyFor(t, "h", 443, []string{"/"}, nil)
	m, err := NewManager([]agent.ModelEndpoint{{Host: "h"}}, Options{HTTPPolicy: p})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	m.listeners[0].ln = brokenAccept{m.listeners[0].ln}
	if err := m.Start(context.Background(), testRun, &fakeSink{}); err == nil {
		t.Fatal("broken accept certified policy enforcement")
	}
	if m.HTTPPolicyReady(p) {
		t.Fatal("broken listener reported HTTP capability")
	}
}

func TestHTTPPolicyHealthAndUpgradeAreNotBroadGrants(t *testing.T) {
	p := policyFor(t, "h", 443, nil, nil)
	l, err := NewListener(agent.ModelEndpoint{Host: "h"}, Options{HTTPPolicy: p, Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("deny all/health reached upstream")
		return nil, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	sink := &fakeSink{}
	l.Bind(testRun, sink)
	for _, tc := range []struct {
		method, path string
		want         int
	}{{"HEAD", HelloPath, 200}, {"GET", HelloPath, 403}, {"POST", "/v1/messages", 403}} {
		w := httptest.NewRecorder()
		serveDirect(l, w, httptest.NewRequest(tc.method, "http://h"+tc.path, nil))
		if w.Code != tc.want {
			t.Fatalf("%s %s=%d", tc.method, tc.path, w.Code)
		}
	}
	if len(sink.of(record.KindNet)) != 2 {
		t.Fatal("local health fabricated upstream policy action")
	}
	foreign := httptest.NewRequest("POST", "http://h/v1/messages", nil)
	w := httptest.NewRecorder()
	l.ServeHTTP(w, foreign)
	l.emitq.flush(time.Second)
	if w.Code != 403 || len(sink.of(record.KindNet)) != 2 {
		t.Fatal("outsider attributed to HTTP policy/run")
	}
}

func TestHTTPPolicyUpstream101CannotTunnel(t *testing.T) {
	l, err := NewListener(agent.ModelEndpoint{Host: "h"}, Options{HTTPPolicy: policyFor(t, "h", 443, []string{"/"}, nil), Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 101, Header: http.Header{"Upgrade": {"websocket"}}, Body: io.NopCloser(strings.NewReader("never relay"))}, nil
	})})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.Bind(testRun, &fakeSink{})
	w := httptest.NewRecorder()
	serveDirect(l, w, httptest.NewRequest("GET", "http://h/allowed", nil))
	if w.Code != 502 || strings.Contains(w.Body.String(), "never relay") || w.Header().Get("Upgrade") != "" {
		t.Fatalf("unexpected upgrade relayed: %d %v %s", w.Code, w.Header(), w.Body)
	}
}

func TestHTTPPolicyAllowedSSEStillStreams(t *testing.T) {
	release := make(chan struct{})
	l, _, _ := policyHarness(t, []string{"/stream"}, []string{"GET"}, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "data: second\n\n")
	})
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(l.BaseURL() + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	first, err := br.ReadString('\n')
	if err != nil || first != "data: first\n" {
		t.Fatalf("first chunk held behind response completion: %q %v", first, err)
	}
	close(release)
	rest, err := io.ReadAll(br)
	if err != nil || !strings.Contains(string(rest), "data: second") {
		t.Fatalf("stream tail changed: %q %v", rest, err)
	}
}

func TestHTTPPolicyRedirectFollowIsANewDecision(t *testing.T) {
	var upstream atomic.Int64
	l, sink, _ := policyHarness(t, []string{"/allowed"}, []string{"GET"}, func(w http.ResponseWriter, r *http.Request) {
		upstream.Add(1)
		w.Header().Set("Location", "/denied")
		w.WriteHeader(http.StatusFound)
	})
	client := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(l.BaseURL() + "/allowed")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 302 || upstream.Load() != 1 {
		t.Fatal("forwarder followed redirect")
	}
	client.CheckRedirect = nil
	resp, err = client.Get(l.BaseURL() + "/allowed")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 403 || upstream.Load() != 2 {
		t.Fatalf("followed path bypassed policy: status=%d upstream=%d", resp.StatusCode, upstream.Load())
	}
	events := sink.waitFor(t, record.KindNet, 3)
	if events[2].Verdict != record.VerdictRefused {
		t.Fatal("redirect follow lacks new policy decision")
	}
}

func TestHTTPPolicyManagerCannotOmitDeclaredListeners(t *testing.T) {
	p, err := httppolicy.Compile([]httppolicy.Rule{{Host: "a", Port: 443}, {Host: "b", Port: 8443}})
	if err != nil {
		t.Fatal(err)
	}
	for _, models := range [][]agent.ModelEndpoint{nil, {{Host: "a"}}, {{Host: "a"}, {Host: "a"}}} {
		if m, err := NewManager(models, Options{HTTPPolicy: p}); err == nil {
			_ = m.Stop()
			t.Fatal("partial/ambiguous policy manager accepted")
		}
	}
}

func TestHTTPPolicyAbsoluteRequestCannotChooseUpstream(t *testing.T) {
	actual := make(chan string, 1)
	l, _, _ := policyHarness(t, []string{"/allowed"}, []string{"GET"}, func(w http.ResponseWriter, r *http.Request) {
		actual <- r.Host + " " + r.RequestURI
		_, _ = io.WriteString(w, "ok")
	})
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(c, "GET http://attacker.invalid/allowed?secret=no-policy-record HTTP/1.1\r\nHost: forged.invalid\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("absolute request rejected: %d", resp.StatusCode)
	}
	if got := <-actual; got != l.hostHeader()+" /allowed?secret=no-policy-record" {
		t.Fatalf("client picked upstream or request bytes changed: %q", got)
	}
}

func TestHTTPPolicyHealthExceptionIsExact(t *testing.T) {
	var upstream atomic.Int64
	l, _, _ := policyHarness(t, []string{"/"}, nil, func(w http.ResponseWriter, r *http.Request) { upstream.Add(1); w.WriteHeader(http.StatusNoContent) })
	client := &http.Client{Timeout: 2 * time.Second}
	for _, tc := range []struct {
		path   string
		status int
	}{{HelloPath, 200}, {HelloPath + "?x=1", 204}, {"/api/%68ello", 204}} {
		req, _ := http.NewRequest("HEAD", l.BaseURL()+tc.path, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("health spelling %q became unexpected local exemption: %d", tc.path, resp.StatusCode)
		}
	}
	if upstream.Load() != 2 {
		t.Fatalf("broader local health bypass: %d", upstream.Load())
	}
}

var _ source.Source = (*Manager)(nil)

func TestHTTPPolicyOptionsAsteriskMustAdmitPeer(t *testing.T) {
	p := policyFor(t, "h", 443, nil, nil)
	m, err := NewManager([]agent.ModelEndpoint{{Host: "h"}}, Options{HTTPPolicy: p})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	run := testRun
	run.CgroupID = foreignCgroupID
	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := m.Start(ctx, run, sink); err != nil {
		t.Fatal(err)
	}
	l := m.listeners[0]
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(c, "OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("outsider OPTIONS * bypassed admission: %d", resp.StatusCode)
	}
	l.emitq.flush(time.Second)
	if len(sink.of(record.KindNet)) != 0 || len(sink.of(record.KindGap)) != 0 {
		t.Fatal("outsider attributed to run")
	}
}

func TestHTTPPolicyUnreadRefusalClosesSocket(t *testing.T) {
	for _, tc := range []struct {
		name, method, wire string
		status             int
		foreign            bool
	}{
		{"chunked policy denial", "POST", "POST /denied HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n", 403, false},
		{"small stalled health upload", "HEAD", "HEAD /api/hello HTTP/1.1\r\nHost: a\r\nContent-Length: 1000\r\nExpect: 100-continue\r\n\r\n", 400, false},
		{"unsupported protocol upload", "CONNECT", "CONNECT example.org:443 HTTP/1.1\r\nHost: a\r\nContent-Length: 1000\r\n\r\n", 400, false},
		{"outsider stalled upload", "POST", "POST /allowed HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n", 403, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var upstream atomic.Int64
			l, sink, _ := policyHarness(t, []string{"/allowed"}, nil, func(w http.ResponseWriter, r *http.Request) { upstream.Add(1) })
			if tc.foreign {
				p := policyFor(t, "h", 443, []string{"/allowed"}, nil)
				m, err := NewManager([]agent.ModelEndpoint{{Host: "h"}}, Options{HTTPPolicy: p})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = m.Stop() })
				run := testRun
				run.CgroupID = foreignCgroupID
				sink = &fakeSink{}
				if err := m.Start(context.Background(), run, sink); err != nil {
					t.Fatal(err)
				}
				l = m.Listeners()[0]
			}
			c, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(time.Second))
			_, _ = io.WriteString(c, tc.wire)
			br := bufio.NewReader(c)
			resp, err := http.ReadResponse(br, &http.Request{Method: tc.method})
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil || resp.StatusCode != tc.status {
				t.Fatalf("final refusal %d, body %q: %v", resp.StatusCode, body, err)
			}
			if b, err := br.ReadByte(); err != io.EOF {
				t.Fatalf("unread request body retained the socket: byte %q, error %v", b, err)
			}
			if upstream.Load() != 0 {
				t.Fatal("refused body reached upstream")
			}
			l.emitq.flush(time.Second)
			if tc.foreign && (len(sink.of(record.KindNet)) != 0 || len(sink.of(record.KindGap)) != 0) {
				t.Fatal("outsider upload attributed to agent")
			}
		})
	}
}

func TestHTTPPolicyTransportHostAuthority(t *testing.T) {
	id, err := liveCgroupID()
	if err != nil {
		t.Skipf("actual peer admission needs cgroup identity: %v", err)
	}
	for _, tc := range []struct {
		host     string
		port     int
		wantHost string
		wantDial string
	}{
		{"[::1]", 0, "[::1]", "[::1]:443"},
		{"[::1]", 443, "[::1]", "[::1]:443"},
		{"[::1]", 8443, "[::1]:8443", "[::1]:8443"},
		{"EXAMPLE.COM.", 0, "example.com", "example.com:443"},
		{"EXAMPLE.COM.", 443, "example.com", "example.com:443"},
		{"example.com", 8443, "example.com:8443", "example.com:8443"},
		{"127.0.0.1", 0, "127.0.0.1", "127.0.0.1:443"},
		{"127.0.0.1", 443, "127.0.0.1", "127.0.0.1:443"},
		{"127.0.0.1", 8443, "127.0.0.1:8443", "127.0.0.1:8443"},
	} {
		t.Run(fmt.Sprintf("%s/%d", tc.host, tc.port), func(t *testing.T) {
			actual := make(chan string, 1)
			up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actual <- r.Host
				_, _ = io.WriteString(w, "fixed TLS upstream")
			}))
			defer up.Close()
			// Dial the private server without binding privileged port 443. TLS
			// still verifies the declared DNS/IP authority against its certificate.
			dialed := make(chan string, 1)
			transport := up.Client().Transport.(*http.Transport).Clone()
			defer transport.CloseIdleConnections()
			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialed <- addr
				return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, up.Listener.Addr().String())
			}
			c := &agent.Contract{Capture: agent.CaptureForwarder, Models: []agent.ModelEndpoint{{Host: tc.host, Port: tc.port}},
				Net: &agent.NetSection{HTTP: []agent.HTTPRule{{Host: tc.host, Allow: []string{"/allowed"}, Methods: []string{"GET"}}}}}
			p, err := agent.CompileHTTPPolicy(c)
			if err != nil {
				t.Fatal(err)
			}
			m, err := NewManager(c.Models, Options{HTTPPolicy: p, Transport: transport})
			if err != nil {
				t.Fatal(err)
			}
			defer m.Stop()
			run := testRun
			run.CgroupID = id
			if err := m.Start(t.Context(), run, &fakeSink{}); err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest(http.MethodGet, m.Listeners()[0].BaseURL()+"/allowed", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = "client-selected.invalid:9"
			resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil || resp.StatusCode != 200 || string(body) != "fixed TLS upstream" {
				t.Fatalf("upstream response %d %q: %v", resp.StatusCode, body, err)
			}
			got := <-actual
			if got != tc.wantHost {
				t.Fatalf("actual TLS request Host %q, want %q", got, tc.wantHost)
			}
			u, err := url.Parse("https://" + got + "/")
			if err != nil || u.Hostname() != agent.CanonicalHost(tc.host) {
				t.Fatalf("invalid declared Host authority %q: %v", got, err)
			}
			if got := <-dialed; got != tc.wantDial {
				t.Fatalf("transport selected %q, want fixed authority %q", got, tc.wantDial)
			}
		})
	}
}
