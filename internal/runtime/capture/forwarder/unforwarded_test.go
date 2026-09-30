// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
)

// A request forward gives up before it goes upstream is one gap why=malformed whatever the cause, so the cause
// is logged: a body that stopped short of its Content-Length and a broken entropy source were otherwise the same
// uncaused gap, where the upstream's own failure just below was logged with its error.
func TestARequestGivenUpBeforeUpstreamLogsItsCause(t *testing.T) {
	plain := func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"ok":true}`) }
	body := `{"model":"claude-opus-5","messages":[]}`
	cases := []struct {
		name   string
		rand   io.Reader
		send   func(t *testing.T, h *harness) int
		status int
		msg    string
		cause  string
	}{
		{
			name: "a body short of its Content-Length",
			send: func(t *testing.T, h *harness) int {
				conn, err := net.Dial("tcp", h.listener.ln.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = conn.Close() }()
				_, err = io.WriteString(conn, "POST /v1/messages HTTP/1.1\r\nHost: forwarder\r\n"+
					"Content-Type: application/json\r\nContent-Length: 4096\r\n\r\n"+body)
				if err != nil {
					t.Fatal(err)
				}
				if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
					t.Fatal(err)
				}
				resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
				if err != nil {
					t.Fatalf("read response: %v", err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				return resp.StatusCode
			},
			status: http.StatusBadRequest,
			msg:    "the request could not be read",
			cause:  "unexpected EOF",
		},
		{
			name: "an exchange id that could not be drawn",
			rand: &failingRand{after: 0},
			send: func(t *testing.T, h *harness) int {
				return roundTrip(t, h, newPost(t, h, []byte(body)))
			},
			status: http.StatusBadRequest,
			msg:    "the request could not be read",
			cause:  "no randomness",
		},
		{
			name: "an outbound leg that could not be built",
			rand: &failingRand{after: 1},
			send: func(t *testing.T, h *harness) int {
				return roundTrip(t, h, newPost(t, h, []byte(body)))
			},
			status: http.StatusBadGateway,
			msg:    "the upstream request could not be prepared",
			cause:  "no randomness",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logged syncBuffer
			h := newHarness(t, plain, Options{MaxBody: 4096, Rand: tc.rand,
				Logger: slog.New(slog.NewTextHandler(&logged, nil))})
			if got := tc.send(t, h); got != tc.status {
				t.Fatalf("status = %d, want %d: the case did not take the path it names", got, tc.status)
			}
			out := logged.String()
			var line string
			for l := range strings.SplitSeq(out, "\n") {
				if strings.Contains(l, tc.msg) {
					line = l
				}
			}
			if line == "" || !strings.Contains(line, "level=WARN") || !strings.Contains(line, tc.cause) {
				t.Errorf("no warn line %q naming %q was logged:\n%s", tc.msg, tc.cause, out)
			}
		})
	}
}
