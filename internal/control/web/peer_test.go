// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// trustPeer lets a test's in-memory requests (httptest.NewRequest has no listener address and a 192.0.2.1
// client) past the peer-uid check and the governed-agent check; the checks themselves are tested below and in
// governed_test.go.
func trustPeer(s *Server) {
	s.peer = func(*http.Request) error { return nil }
	s.governed = func(*http.Request) error { return nil }
}

const tcpHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

// tcpRow is one /proc/net/tcp row: local and remote cells as the kernel prints them, and the socket's uid.
func tcpRow(local, remote string, uid int) string {
	return fmt.Sprintf("   0: %s %s 01 00000000:00000000 00:00000000 00000000 %5d        0 12345 1 0000000000000000 20 4 30 10 -1\n",
		local, remote, uid)
}

// 127.0.0.1:40000 (the client) and 127.0.0.1:8484 (the dashboard), and the client as a v4-mapped v6 address.
const (
	clientCell   = "0100007F:9C40"
	serverCell   = "0100007F:2124"
	client6Cell  = "0000000000000000FFFF00000100007F:9C40"
	server6Cell  = "0000000000000000FFFF00000100007F:2124"
	clientRemote = "127.0.0.1:40000"
)

// fakeTables serves tcp and tcp6 from memory; a missing name is os.ErrNotExist.
func fakeTables(tables map[string]string) func(string) ([]byte, error) {
	return func(name string) ([]byte, error) {
		t, ok := tables[name]
		if !ok {
			return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
		}
		return []byte(t), nil
	}
}

// peerRequest is a token-exchange request that arrived on 127.0.0.1:8484 from clientRemote.
func peerRequest() *http.Request {
	r := httptest.NewRequest("GET", "/?t=tok123", nil)
	r.Host = "127.0.0.1:8484"
	r.RemoteAddr = clientRemote
	la := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8484}
	return r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, net.Addr(la)))
}

func peerServer(t *testing.T, read func(string) ([]byte, error)) *Server {
	t.Helper()
	s := newServer(t, t.TempDir())
	s.peer = peerCheck{read: read, euid: 1000}.owns
	return s
}

// TestPeerUIDRefusesOtherUser: a client socket owned by uid 4242 gets the 403 page and no session cookie, even
// with the right token, and even though the dashboard's own end of the connection (the reversed row) is the
// serving user's.
func TestPeerUIDRefusesOtherUser(t *testing.T) {
	s := peerServer(t, fakeTables(map[string]string{
		"/proc/net/tcp": tcpHeader + tcpRow(serverCell, clientCell, 1000) + tcpRow(clientCell, serverCell, 4242),
	}))
	w := httptest.NewRecorder()
	s.ServeHTTP(w, peerRequest())
	if w.Code != http.StatusForbidden {
		t.Fatalf("other uid: %d %s", w.Code, w.Body)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatalf("other uid got a cookie: %v", w.Result().Cookies())
	}
	body := w.Body.String()
	for _, want := range []string{"serves only the user who started it", "uid 4242", "start your own"} {
		if !strings.Contains(body, want) {
			t.Errorf("403 page lacks %q:\n%s", want, body)
		}
	}
}

// TestPeerUIDGuardsEveryRoute: another user's socket gets 403 even with the session's cookie, on the live updates
// (the /events stream, /status.json, a region request) as on pages and posts: the check comes before any route.
func TestPeerUIDGuardsEveryRoute(t *testing.T) {
	s := peerServer(t, fakeTables(map[string]string{
		"/proc/net/tcp": tcpHeader + tcpRow(clientCell, serverCell, 4242),
	}))
	cookie := &http.Cookie{Name: s.cookie, Value: s.session}
	for _, tc := range []struct{ method, target, header string }{
		{"GET", "/events", ""},
		{"GET", "/status.json", ""},
		{"GET", "/", regionHeader},
		{"GET", "/rules", ""},
		{"POST", "/rules/change", ""},
		{"POST", "/runs/r-x/lines/1", ""},
	} {
		r := peerRequest()
		r.Method, r.URL.Path, r.URL.RawQuery = tc.method, tc.target, ""
		r.AddCookie(cookie)
		if tc.header != "" {
			r.Header.Set(tc.header, "r-nav:x")
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || strings.Contains(w.Header().Get("Content-Type"), "event-stream") {
			t.Errorf("%s %s from another uid: %d %q", tc.method, tc.target, w.Code, w.Header().Get("Content-Type"))
		}
	}
}

// TestPeerUIDFailsClosed: every way the owner cannot be shown is a 403, and the serving user's own socket, in
// either table, is let in.
func TestPeerUIDFailsClosed(t *testing.T) {
	own := tcpHeader + tcpRow(clientCell, serverCell, 1000)
	cases := []struct {
		name   string
		tables map[string]string
		read   func(string) ([]byte, error)
		req    func() *http.Request
		want   int
	}{
		{name: "own socket in tcp", tables: map[string]string{"/proc/net/tcp": own, "/proc/net/tcp6": tcpHeader}, want: http.StatusSeeOther},
		{name: "own socket in tcp, no tcp6 table", tables: map[string]string{"/proc/net/tcp": own},
			want: http.StatusSeeOther},
		{name: "own v4-mapped socket in tcp6", tables: map[string]string{"/proc/net/tcp": tcpHeader,
			"/proc/net/tcp6": tcpHeader + tcpRow(client6Cell, server6Cell, 1000)}, want: http.StatusSeeOther},
		{name: "other uid in tcp6", tables: map[string]string{"/proc/net/tcp": tcpHeader,
			"/proc/net/tcp6": tcpHeader + tcpRow(client6Cell, server6Cell, 4242)}, want: http.StatusForbidden},
		{name: "only the server's own row", tables: map[string]string{
			"/proc/net/tcp": tcpHeader + tcpRow(serverCell, clientCell, 1000)}, want: http.StatusForbidden},
		{name: "no row", tables: map[string]string{"/proc/net/tcp": tcpHeader, "/proc/net/tcp6": tcpHeader},
			want: http.StatusForbidden},
		{name: "no tcp table", tables: map[string]string{"/proc/net/tcp6": own}, want: http.StatusForbidden},
		{name: "unreadable table", read: func(string) ([]byte, error) { return nil, os.ErrPermission },
			want: http.StatusForbidden},
		{name: "bad uid", tables: map[string]string{
			"/proc/net/tcp": tcpHeader + strings.Replace(tcpRow(clientCell, serverCell, 1000), " 1000 ", " x ", 1)},
			want: http.StatusForbidden},
		{name: "no listener address", tables: map[string]string{"/proc/net/tcp": own}, want: http.StatusForbidden,
			req: func() *http.Request {
				r := httptest.NewRequest("GET", "/?t=tok123", nil)
				r.Host, r.RemoteAddr = "127.0.0.1:8484", clientRemote
				return r
			}},
		{name: "unparsable client address", tables: map[string]string{"/proc/net/tcp": own},
			want: http.StatusForbidden, req: func() *http.Request {
				r := peerRequest()
				r.RemoteAddr = "pipe"
				return r
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			read := tc.read
			if read == nil {
				read = fakeTables(tc.tables)
			}
			req := peerRequest
			if tc.req != nil {
				req = tc.req
			}
			s := peerServer(t, read)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, req())
			if w.Code != tc.want {
				t.Fatalf("got %d, want %d: %s", w.Code, tc.want, w.Body)
			}
		})
	}
}

// TestPeerUIDAcceptsOwn dials the dashboard over real loopback with the real check: the serving user's own client
// gets in whether the browser names it 127.0.0.1 or localhost, and [::1] is refused at connect as before (the
// dashboard listens on 127.0.0.1 only).
func TestPeerUIDAcceptsOwn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	s, err := New(Config{Ledger: t.TempDir(), Port: port, Token: "tok123"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, s) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	noRedirect := &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, host := range []string{"127.0.0.1", "localhost"} {
		t.Run(host, func(t *testing.T) {
			resp, err := noRedirect.Get(fmt.Sprintf("http://%s:%d/?t=tok123", host, port))
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusSeeOther {
				t.Fatalf("own user via %s: %d %s", host, resp.StatusCode, body)
			}
		})
	}
	t.Run("[::1]", func(t *testing.T) {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("[::1]:%d", port), 2*time.Second)
		if err == nil {
			_ = c.Close()
			t.Fatal("the dashboard answered on [::1]; it listens on 127.0.0.1 only")
		}
		var op *net.OpError
		if !errors.As(err, &op) {
			t.Fatalf("[::1]: %v", err)
		}
	})
}
