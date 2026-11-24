// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/policy/mcptool"
)

func TestBusinessRulesRefuseLegacyConstruction(t *testing.T) {
	for _, sv := range []Server{
		{Name: "square", Command: []string{"worker"}, BusinessRules: true},
		{Name: "square", URL: "http://127.0.0.1:1/mcp", BusinessRules: true},
	} {
		s, err := New(Options{Servers: []Server{sv}})
		if s != nil {
			s.closeListeners()
		}
		if s != nil || !errors.Is(err, ErrBusinessUnavailable) {
			t.Fatalf("legacy service admitted business: %v %v", s, err)
		}
		b, err := ClientConfig("/tego", []Server{sv}, map[string]string{"square": "http://127.0.0.1:2/mcp"})
		if b != nil || !errors.Is(err, ErrBusinessUnavailable) {
			t.Fatalf("legacy client config: %s %v", b, err)
		}
	}
	if h, err := newHTTPRelay(nil, Server{Name: "square", URL: "http://127.0.0.1:1/mcp", BusinessRules: true}); h != nil || !errors.Is(err, ErrBusinessUnavailable) {
		if h != nil {
			h.close()
		}
		t.Fatalf("HTTP business constructed: %v %v", h, err)
	}
}

func TestBusinessRulesRefuseEveryLegacyIntakeShortcut(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"tool call", toolCall(1, "make_api_request")},
		{"batch", "[" + toolCall(1, "make_api_request") + "," + toolCall(2, "other") + "]"},
		{"notification", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"make_api_request","arguments":{}}}`},
		{"control", `{"jsonrpc":"2.0","id":1,"method":"ping"}`},
		{"initialize", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`},
		{"list", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`},
		{"list change", `{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}`},
		{"malformed", "{"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			s := &Service{servers: map[string]Server{"square": {BusinessRules: true}}, sink: &sink{}, opts: Options{Now: time.Now, Mono: func() uint64 { return 1 }}}
			c := &stdioConn{s: s, server: "square", fw: NewFrameWriter(&output), inflight: map[string]struct{}{}}
			c.clientLine([]byte(tc.line))
			assertBusinessRefusal(t, &output)
		})
	}
}

func TestBusinessRulesRefuseDirectDecision(t *testing.T) {
	var out bytes.Buffer
	s := &Service{servers: map[string]Server{"square": {BusinessRules: true}}, sink: &sink{}, opts: Options{Now: time.Now, Mono: func() uint64 { return 1 }}}
	c := &stdioConn{s: s, server: "square", fw: NewFrameWriter(&out)}
	c.decideCall(call{id: json.RawMessage("1"), tool: "make_api_request", isCall: true}, []byte(toolCall(1, "make_api_request")))
	assertBusinessRefusal(t, &out)
}

func TestBusinessRulesSuppressForgedServerFrames(t *testing.T) {
	var out bytes.Buffer
	s := &Service{servers: map[string]Server{"square": {BusinessRules: true}}}
	c := &stdioConn{s: s, server: "square", fw: NewFrameWriter(&out)}
	c.serverLine([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	reader := NewFrameReader(&out, 0)
	if f, err := reader.Read(); !errors.Is(err, io.EOF) {
		t.Fatalf("forged server response forwarded: %+v %v", f, err)
	}
}

func TestBusinessRulesRefuseProtocolThreeBeforeStage(t *testing.T) {
	sv := Server{Name: "square", Command: []string{"worker"}, BusinessRules: true}
	s := &Service{servers: map[string]Server{"square": sv}, pending: map[int]pendingStart{}, conns: map[*stdioConn]struct{}{}, opts: Options{Logger: slog.New(slog.DiscardHandler), admit: func(net.Conn, int, uint64) (admission, error) { return admission{pid: os.Getpid()}, nil }}}
	service, client := net.Pipe()
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); s.serveStdio(service) }()
	if err := NewFrameWriter(client).Write(Frame{V: 3, Server: "square", Argv: sv.Command, PID: os.Getpid()}); err != nil {
		t.Fatal(err)
	}
	f, err := NewFrameReader(client, 0).Read()
	if err != nil || f.OK || !strings.Contains(f.Error, "legacy protocol 3") {
		t.Fatalf("legacy hello admitted: %+v %v", f, err)
	}
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("legacy refusal did not close connection")
	}
	if len(s.pending) != 0 {
		t.Fatal("business stage registered")
	}
}

func TestBusinessRulesRefuseEveryHTTPEntry(t *testing.T) {
	var forwarded atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Add(1); w.WriteHeader(http.StatusNoContent) }))
	defer upstream.Close()
	s, _, _ := start(t, nil, Server{Name: "web", URL: upstream.URL})
	h := s.https[0]
	h.sv.BusinessRules = true // simulate accidental handler entry after constructor checks
	h.admitConn = func(netip.AddrPort, netip.AddrPort, uint64) error { return nil }
	h.holderPID = func() int { return os.Getpid() }
	for _, method := range []string{"POST", "GET", "DELETE", "OPTIONS"} {
		t.Run(method, func(t *testing.T) {
			var body io.Reader
			if method == "POST" {
				body = strings.NewReader(toolCall(1, "make_api_request"))
			}
			r := httptest.NewRequest(method, "http://127.0.0.1/mcp", body)
			r.RemoteAddr = "127.0.0.1:1234"
			r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2345}))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			response := w.Result()
			b, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusForbidden || !strings.Contains(string(b), "business rules require") {
				t.Fatalf("HTTP %s: %d %s", method, w.Code, b)
			}
		})
	}
	if forwarded.Load() != 0 {
		t.Fatalf("HTTP forwarded %d requests", forwarded.Load())
	}
}

// assertBusinessRefusal drains the same buffered reader through EOF. Looking at
// the underlying buffer cannot detect a forwarding frame already read ahead.
func assertBusinessRefusal(t *testing.T, input io.Reader) {
	t.Helper()
	reader := NewFrameReader(input, 0)
	frames, refusals, forwarded := 0, 0, 0
	for {
		f, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		frames++
		if len(f.ToServer) != 0 {
			forwarded++
		}
		if len(f.ToClient) == 0 {
			continue
		}
		refusals++
		var reply struct {
			ID    any `json:"id"`
			Error struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
				Data    struct {
					Tego struct{ Rule, Reason string } `json:"tego"`
				} `json:"data"`
			} `json:"error"`
		}
		if err := json.Unmarshal(f.ToClient, &reply); err != nil {
			t.Fatal(err)
		}
		if reply.ID != nil || reply.Error.Code != mcptool.RefusalCode || reply.Error.Data.Tego.Reason != "business-rule-unavailable" || !strings.Contains(reply.Error.Message, "durable admission owner") {
			t.Fatalf("unsafe refusal: %s", f.ToClient)
		}
	}
	if frames != 1 || refusals != 1 || forwarded != 0 {
		t.Fatalf("business output: %d frames, %d refusals, %d forwarded frames; want 1, 1 and 0", frames, refusals, forwarded)
	}
}
