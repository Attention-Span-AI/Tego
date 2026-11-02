// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
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

// kernelCell is ap as the kernel prints it in a /proc/net/tcp row, or a tcp6 row for a v6 address (a v4-mapped one
// included), on this host: each four of the address's bytes read as a u32 in the host's byte order and printed %08X,
// as get_tcp4_sock and get_tcp6_sock print each __be32, then the port, %04X. Tables built from it hold on a host of
// either byte order; TestKernelCellIsTheKernelsSpelling holds it to the kernel's own digits.
func kernelCell(ap netip.AddrPort) string {
	raw := ap.Addr().AsSlice()
	var b strings.Builder
	for i := 0; i < len(raw); i += 4 {
		fmt.Fprintf(&b, "%08X", binary.NativeEndian.Uint32(raw[i:]))
	}
	fmt.Fprintf(&b, ":%04X", ap.Port())
	return b.String()
}

// 127.0.0.1:40000 (the client) and 127.0.0.1:8484 (the dashboard) as tcp prints them, and as tcp6 prints them for a
// v4-mapped socket.
var (
	clientCell  = kernelCell(netip.MustParseAddrPort("127.0.0.1:40000"))
	serverCell  = kernelCell(netip.MustParseAddrPort("127.0.0.1:8484"))
	client6Cell = kernelCell(netip.MustParseAddrPort("[::ffff:127.0.0.1]:40000"))
	server6Cell = kernelCell(netip.MustParseAddrPort("[::ffff:127.0.0.1]:8484"))
)

// clientRemote is the client's end as the request names it.
const clientRemote = "127.0.0.1:40000"

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
// serving user's. TestPeerUIDRefusesAnotherRealUser (peer_root_integration_test.go, as root) is the same refusal on
// the kernel's own table, of a client that runs as another uid.
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

// TestPeerUIDAcceptsOwn dials the dashboard over real loopback with the real checks: the serving user's own client
// signs in to a dashboard on 127.0.0.1 whether the browser names it so or localhost, and to one on ::1 over [::1],
// where its socket is in /proc/net/tcp6 and sock_diag finds it in AF_INET6. A dashboard answers only on the address
// it listens on: the one on 127.0.0.1 is not reached at [::1].
func TestPeerUIDAcceptsOwn(t *testing.T) {
	noRedirect := &http.Client{Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	signIn := func(t *testing.T, hostPort string) {
		t.Helper()
		resp, err := noRedirect.Get("http://" + hostPort + "/?t=tok123")
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("own user via %s: %d %s", hostPort, resp.StatusCode, body)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(serveOwn(t, ln))
	for _, host := range []string{"127.0.0.1", "localhost"} {
		t.Run(host, func(t *testing.T) { signIn(t, net.JoinHostPort(host, port)) })
	}
	t.Run("[::1] reaches no dashboard on 127.0.0.1", func(t *testing.T) {
		c, err := net.DialTimeout("tcp", net.JoinHostPort("::1", port), 2*time.Second)
		if err == nil {
			_ = c.Close()
			t.Fatal("the dashboard on 127.0.0.1 answered on [::1]")
		}
		var op *net.OpError
		if !errors.As(err, &op) {
			t.Fatalf("[::1]: %v", err)
		}
	})
	t.Run("[::1]", func(t *testing.T) {
		ln6, err := net.Listen("tcp", "[::1]:0")
		if err != nil {
			t.Skipf("no IPv6 loopback here: %v", err)
		}
		signIn(t, net.JoinHostPort("::1", strconv.Itoa(serveOwn(t, ln6))))
	})
}

// serveOwn serves a dashboard with the real peer and governed checks on ln until the test ends, and returns its port.
func serveOwn(t *testing.T, ln net.Listener) int {
	t.Helper()
	at := ln.Addr().(*net.TCPAddr)
	s, err := New(Config{Ledger: t.TempDir(), Host: at.IP.String(), Port: at.Port, Token: "tok123"})
	if err != nil {
		_ = ln.Close()
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
	return at.Port
}

// TestParseTCPAddr: a cell the kernel printed on this host reads back as its socket's address and port, whichever
// byte order the host has, a v4-mapped one unmapped as connEnds unmaps the request's ends; a cell that is not an
// address and a port matches nothing. On a big-endian host it fails when the words are read little-endian there
// (7F000001 as 1.0.0.127, which refused every request).
func TestParseTCPAddr(t *testing.T) {
	for _, tc := range []struct{ socket, want string }{
		{"127.0.0.1:8484", "127.0.0.1:8484"},
		{"127.0.0.53:53", "127.0.0.53:53"},
		{"10.1.2.3:65535", "10.1.2.3:65535"},
		{"0.0.0.0:0", "0.0.0.0:0"},
		{"[::1]:631", "[::1]:631"},
		{"[2001:db8::a0b:c0d]:443", "[2001:db8::a0b:c0d]:443"},
		{"[::ffff:127.0.0.1]:40000", "127.0.0.1:40000"},
	} {
		cell := kernelCell(netip.MustParseAddrPort(tc.socket))
		if got, ok := parseTCPAddr(cell); !ok || got != netip.MustParseAddrPort(tc.want) {
			t.Errorf("parseTCPAddr(%q), the cell of %s: %v, %v; want %s", cell, tc.socket, got, ok, tc.want)
		}
	}
	for _, cell := range []string{"", "0100007F", "0100007F:", "0100007:2124", "0100007F0:2124", "0100007F0100007F:2124",
		"0000000000000000FFFF00000100007:2124", "zzzzzzzz:2124", "0100007F:zzzz", "0100007F:12345"} {
		if got, ok := parseTCPAddr(cell); ok {
			t.Errorf("parseTCPAddr(%q) = %s, want no match", cell, got)
		}
	}
}

// TestKernelCellIsTheKernelsSpelling holds kernelCell, which builds every table in these tests, and the parse to the
// digits the kernel prints for three sockets on each byte order (the little-endian ones copied from an amd64 host's
// tcp and tcp6 tables): this host's digits read back as the socket, and the other order's as some other address, so
// a row matches in the host's order only.
func TestKernelCellIsTheKernelsSpelling(t *testing.T) {
	littleHost := binary.NativeEndian.Uint16([]byte{1, 0}) == 1
	for _, tc := range []struct{ socket, little, big string }{
		{"127.0.0.1:8484", "0100007F:2124", "7F000001:2124"},
		{"[::ffff:127.0.0.1]:40000", "0000000000000000FFFF00000100007F:9C40", "00000000000000000000FFFF7F000001:9C40"},
		{"[::1]:631", "00000000000000000000000001000000:0277", "00000000000000000000000000000001:0277"},
	} {
		ap := netip.MustParseAddrPort(tc.socket)
		own, other := tc.little, tc.big
		if !littleHost {
			own, other = tc.big, tc.little
		}
		if got := kernelCell(ap); got != own {
			t.Errorf("kernelCell(%s) = %q, want the kernel's %q", ap, got, own)
		}
		want := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		if got, ok := parseTCPAddr(own); !ok || got != want {
			t.Errorf("parseTCPAddr(%q) = %v, %v; want %s", own, got, ok, want)
		}
		if got, ok := parseTCPAddr(other); ok && got == want {
			t.Errorf("parseTCPAddr(%q), the other byte order's digits, = %s as well", other, got)
		}
	}
}
