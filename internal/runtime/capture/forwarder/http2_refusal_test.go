// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/derive/anthropic"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// An explicit ClientConn cannot hide a GOAWAY by opening another connection.
// Policy/approval refusals deliver no bytes to the actual TLS upstream. An
// admitted upload can fail after its exact streamed prefix. Both cases must
// preserve a live sibling and a later allowed stream on the same connection.
func TestHTTP2RefusalPreservesOneConnectionAndMeteredSiblings(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, encoding   string
		body                           string
		status                         int
		partial, requestAsk, handedOff bool
	}{
		{name: "path", method: "POST", path: "/denied", status: 403},
		{name: "method", method: "GET", path: "/v1/messages", status: 403},
		{name: "escaped separator", method: "POST", path: "/v1/messages%2fother", status: 400},
		{name: "health upload", method: "HEAD", path: HelloPath, status: 400},
		{name: "response encoding", method: "POST", path: "/v1/messages", encoding: "identity;q=0, unsupported-coding", status: 406},
		{name: "body timeout", method: "POST", path: "/v1/messages", status: 400, partial: true},
		{name: "request approval denied", method: "POST", path: "/v1/ask-denied", body: "denied approval", status: 403, requestAsk: true},
		{name: "request approval body too large", method: "POST", path: "/v1/ask-denied", body: strings.Repeat("d", 5000), status: 413, requestAsk: true},
		{name: "streamed body failure after handoff", method: "POST", path: "/v1/streamed", status: 504, handedOff: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			defer close(release)
			// streamed is sent once the upstream handler has counted the handed-off upload: the forwarder answers
			// the client 504 as soon as the upstream stream fails, which can be before the handler's read returns.
			streamed := make(chan struct{}, 1)
			var upstreamCalls, upstreamBytes atomic.Int64
			up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				if err != nil && r.URL.Path != "/v1/streamed" {
					t.Errorf("upstream body: %v", err)
				}
				upstreamCalls.Add(1)
				upstreamBytes.Add(int64(len(body)))
				if r.URL.Path == "/v1/streamed" {
					// This request passed policy and deliberately exceeded the
					// capture prefix before stalling in the upstream writeLoop.
					if err == nil || len(body) != 4097 {
						t.Errorf("streamed upload did not fail after its exact prefix: bytes=%d err=%v", len(body), err)
					}
					select {
					case streamed <- struct{}{}:
					default:
					}
					conn, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						_ = conn.Close()
					}
					return
				}
				if r.Method != "POST" || r.URL.Path != "/v1/messages" {
					t.Errorf("refused request reached upstream: %s %s", r.Method, r.URL.Path)
				}
				if string(body) == "sibling" {
					close(entered)
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
				} else if string(body) != "later" {
					t.Errorf("refused body reached upstream: %q", body)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, encodedResponse)
			}))
			t.Cleanup(up.Close)
			host, port := hostPort(t, up.Listener.Addr().String())
			model := agent.ModelEndpoint{Host: host, Port: port, Provider: "anthropic"}
			p := compiledProtocols(t, model, &agent.ProxyPolicy{HTTP2: true, MaxStreams: 2})
			hp := policyFor(t, host, port, []string{"/v1/messages", "/v1/ask-denied", "/v1/streamed"}, []string{"POST"})
			m, err := NewManager([]agent.ModelEndpoint{model}, Options{Proxy: p, HTTPPolicy: hp,
				Transport: up.Client().Transport, BodyIdleTimeout: 50 * time.Millisecond, MaxBody: 4096,
				Deriver: derive.NewDispatcher([]derive.Parser{anthropic.New(host)})})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = m.Stop() })
			if tc.requestAsk {
				// The HTTP hold coordinator receives isolated immutable rule
				// inputs; protocol/policy compilation and sockets are real.
				rt := &agent.RuleTable{AskConfig: &agent.AskConfig{Hold: agent.AskHoldRequest, Timeout: agent.Duration(time.Second), MaxPending: 8},
					NetAsk: []agent.NetRule{{Host: host, Port: port, Proto: agent.ProtoTCP, Verdict: agent.VerdictAsk}}}
				if err := m.ConfigureAsk(rt, func(_ context.Context, r ask.Request) (ask.Decision, error) {
					return ask.Decision{Approved: !strings.HasSuffix(r.Target, "/v1/ask-denied"), Reason: ask.ReasonDenied}, nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			id, err := liveCgroupID()
			if err != nil {
				t.Skipf("actual peer admission needs cgroup identity: %v", err)
			}
			run := testRun
			run.CgroupID, run.Contract = id, nil
			sink := &fakeSink{}
			ctx, cancel := context.WithCancel(t.Context())
			t.Cleanup(cancel)
			if err := m.Start(ctx, run, sink); err != nil {
				t.Fatal(err)
			}
			base := m.Listeners()[0].BaseURL()
			u, err := url.Parse(base)
			if err != nil {
				t.Fatal(err)
			}
			var dials atomic.Int64
			transport := &http.Transport{Protocols: new(http.Protocols), HTTP2: &http.HTTP2Config{StrictMaxConcurrentRequests: true},
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					dials.Add(1)
					return (&net.Dialer{}).DialContext(ctx, network, address)
				}}
			transport.Protocols.SetUnencryptedHTTP2(true)
			cc, err := transport.NewClientConn(ctx, u.Scheme, u.Host)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cc.Close() })
			client := &http.Client{Transport: cc, Timeout: 3 * time.Second}
			perform := func(method, path string, body io.Reader, length int64, encoding string, want int) error {
				req, err := http.NewRequest(method, base+path, body)
				if err != nil {
					return err
				}
				if length >= 0 {
					req.ContentLength = length
				}
				if encoding != "" {
					req.Header.Set("Accept-Encoding", encoding)
				}
				resp, err := client.Do(req)
				if err != nil {
					return err
				}
				_, readErr := io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.ProtoMajor != 2 || resp.StatusCode != want {
					return fmt.Errorf("response=%s %d, want HTTP/2 %d", resp.Proto, resp.StatusCode, want)
				}
				return readErr
			}
			sibling := make(chan error, 1)
			go func() { sibling <- perform("POST", "/v1/messages", strings.NewReader("sibling"), -1, "", 200) }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("allowed sibling did not reach upstream")
			}
			reader, writer := io.Pipe()
			t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
			var denied io.ReadCloser = reader
			if tc.partial {
				denied = struct {
					io.Reader
					io.Closer
				}{io.MultiReader(strings.NewReader("{"), reader), reader}
			}
			before := time.Now()
			var deniedBody io.Reader = denied
			deniedLength := int64(64)
			if tc.body != "" {
				deniedBody, deniedLength = strings.NewReader(tc.body), int64(len(tc.body))
			}
			if tc.handedOff {
				deniedBody = struct {
					io.Reader
					io.Closer
				}{io.MultiReader(strings.NewReader(strings.Repeat("x", 4097)), reader), reader}
				deniedLength = 5000
			}
			if err := perform(tc.method, tc.path, deniedBody, deniedLength, tc.encoding, tc.status); err != nil {
				t.Fatalf("refused unread upload: %v", err)
			}
			if elapsed := time.Since(before); elapsed >= time.Second {
				t.Fatalf("refusal took %s with a stalled unread upload", elapsed)
			}
			wantCalls, wantBytes := int64(1), int64(len("sibling"))
			if tc.handedOff {
				wantCalls++
				wantBytes += 4097
				// Under load the 504 reached the client before the upstream handler's read of the failed upload
				// returned, and the count below read one call (19 runs of 20 under 16 busy loops, 2026-10-16).
				select {
				case <-streamed:
				case <-time.After(10 * time.Second):
					t.Fatal("the handed-off upload never finished in the upstream handler")
				}
			}
			if upstreamCalls.Load() != wantCalls || upstreamBytes.Load() != wantBytes {
				t.Fatalf("unexpected upstream delivery: calls=%d bytes=%d", upstreamCalls.Load(), upstreamBytes.Load())
			}
			if err := perform("POST", "/v1/messages", strings.NewReader("later"), -1, "", 200); err != nil {
				t.Fatalf("later allowed stream on the same physical connection: %v", err)
			}
			// The sibling stayed live throughout the refusal and the next request.
			release <- struct{}{}
			if err := <-sibling; err != nil {
				t.Fatalf("concurrent allowed sibling: %v", err)
			}
			if dials.Load() != 1 || upstreamCalls.Load() != wantCalls+1 || upstreamBytes.Load() != wantBytes+int64(len("later")) {
				t.Fatalf("one-connection proof: dials=%d upstream calls=%d bytes=%d", dials.Load(), upstreamCalls.Load(), upstreamBytes.Load())
			}
			responses := sink.waitFor(t, record.KindSSLResponse, 2)
			if len(responses) != 2 {
				t.Fatalf("refused request fabricated response: %d", len(responses))
			}
			for _, ev := range responses {
				payload := payloadOf[record.SSLResponsePayload](t, ev)
				if payload.Usage == nil || payload.Usage.Input != 1000 || payload.Usage.Output != 102 {
					t.Fatalf("allowed sibling lost metering: %+v", payload.Usage)
				}
			}
		})
	}
}

func TestHTTP2OutsiderRefusalReleasesConnectionSlot(t *testing.T) {
	var upstreamCalls atomic.Int64
	up := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamCalls.Add(1) }))
	defer up.Close()
	host, port := hostPort(t, up.Listener.Addr().String())
	model := agent.ModelEndpoint{Host: host, Port: port, Provider: "anthropic"}
	p := compiledProtocols(t, model, &agent.ProxyPolicy{HTTP2: true, MaxStreams: 2})
	m, err := NewManager([]agent.ModelEndpoint{model}, Options{Proxy: p, Transport: up.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Stop()
	if _, err := liveCgroupID(); err != nil {
		t.Skipf("actual peer admission needs cgroup identity: %v", err)
	}
	run := testRun
	// The real client belongs to the current cgroup, never this nonexistent one.
	// No injected peer resolver or membership verdict is used.
	run.CgroupID, run.Contract = ^uint64(0), nil
	sink := &fakeSink{}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := m.Start(ctx, run, sink); err != nil {
		t.Fatal(err)
	}
	l := m.Listeners()[0]
	capacity := l.ln.(*capListener)
	u, err := url.Parse(l.BaseURL())
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Protocols: new(http.Protocols)}
	transport.Protocols.SetUnencryptedHTTP2(true)
	cc, err := transport.NewClientConn(ctx, u.Scheme, u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	client := &http.Client{Transport: cc, Timeout: time.Second}
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	req, err := http.NewRequest("POST", l.BaseURL()+"/v1/messages", reader)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = 64
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, readErr := io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 403 || resp.ProtoMajor != 2 || readErr != nil {
		t.Fatalf("outsider stalled upload: %s %d read=%v", resp.Proto, resp.StatusCode, readErr)
	}
	// Continual stream attempts must not keep the outsider's physical slot live.
	deadline := time.Now().Add(2 * time.Second)
	for (capacity.outsiders.Load() != 0 || cc.Err() == nil) && time.Now().Before(deadline) {
		req, err := http.NewRequest("POST", l.BaseURL()+"/v1/messages", strings.NewReader("outsider"))
		if err != nil {
			t.Fatal(err)
		}
		if resp, err := client.Do(req); err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != 403 {
				t.Fatalf("outsider gained admission: %d", resp.StatusCode)
			}
		}
		time.Sleep(time.Millisecond)
	}
	if capacity.outsiders.Load() != 0 || capacity.open.Load() != 0 || cc.Err() == nil {
		t.Fatalf("outsider connection was retained: outsider slots=%d governed slots=%d connection error=%v", capacity.outsiders.Load(), capacity.open.Load(), cc.Err())
	}
	if upstreamCalls.Load() != 0 || len(sink.of(record.KindSSLRequest)) != 0 || len(sink.of(record.KindNet)) != 0 {
		t.Fatal("outsider delivered upstream bytes or was attributed to the run")
	}
}
