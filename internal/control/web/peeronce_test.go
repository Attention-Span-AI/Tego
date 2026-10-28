// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// serveCounting serves s on a fresh loopback port with its peer check replaced by one that counts its calls and
// answers with refuse's verdict, and returns the port and the count.
func serveCounting(t *testing.T, refuse func(n int32) error) (int, *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	s, err := New(Config{Ledger: t.TempDir(), Port: port, Token: "tok123"})
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int32
	s.peer = func(*http.Request) error { return refuse(n.Add(1)) }
	s.governed = func(*http.Request) error { return nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, s) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	return port, &n
}

// connGet fetches path on port over c and returns the status, reading the body so the connection can be reused.
func connGet(t *testing.T, c *http.Client, port int, path string) int {
	t.Helper()
	resp, err := c.Get(fmt.Sprintf("http://127.0.0.1:%d%s", port, path))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestPeerOncePerConn: two requests on one keep-alive connection ask the peer check once; a new connection asks it
// again.
func TestPeerOncePerConn(t *testing.T) {
	port, n := serveCounting(t, func(int32) error { return nil })
	keep := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxConnsPerHost: 1},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if got := connGet(t, keep, port, "/?t=tok123"); got != http.StatusSeeOther {
		t.Fatalf("sign-in: %d", got)
	}
	if got := connGet(t, keep, port, "/static/app.css"); got != http.StatusUnauthorized { // no cookie jar: 401, peer passed
		t.Fatalf("second request: %d", got)
	}
	if got := n.Load(); got != 1 {
		t.Errorf("two requests on one connection asked the peer check %d times, want 1", got)
	}
	other := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{}}
	connGet(t, other, port, "/")
	if got := n.Load(); got != 2 {
		t.Errorf("a second connection: %d checks in all, want 2", got)
	}
}

// TestPeerRefusalNotKept: a refusal is not remembered for the connection; its next request is checked again, and
// passes when the check does.
func TestPeerRefusalNotKept(t *testing.T) {
	port, n := serveCounting(t, func(n int32) error {
		if n == 1 {
			return fmt.Errorf("%w: the table could not be read just then", errPeer)
		}
		return nil
	})
	keep := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxConnsPerHost: 1},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if got := connGet(t, keep, port, "/?t=tok123"); got != http.StatusForbidden {
		t.Fatalf("refused first request: %d, want 403", got)
	}
	if got := connGet(t, keep, port, "/?t=tok123"); got != http.StatusSeeOther {
		t.Fatalf("next request on the connection: %d, want 303", got)
	}
	if got := n.Load(); got != 2 {
		t.Errorf("%d checks, want 2 (a refusal is asked again)", got)
	}
}

// TestPeerOnceWithoutConn: a request that did not come through Serve (no connection state) is still checked, every
// time.
func TestPeerOnceWithoutConn(t *testing.T) {
	s := newServer(t, fixture(t))
	var n int
	s.peer = func(*http.Request) error { n++; return errors.New("refused") }
	for range 2 {
		if w := do(s, "GET", "/?t=tok123", "127.0.0.1:8484", nil); w.Code != http.StatusForbidden {
			t.Fatalf("no connection state: %d, want 403", w.Code)
		}
	}
	if n != 2 {
		t.Errorf("%d checks for two requests without connection state, want 2", n)
	}
}

// BenchmarkPeerKeepAlive is one signed-in static request on a keep-alive connection with the real peer check (the
// kernel's tcp tables): served by Serve (once per connection) and by a plain http.Server (every request, as before).
func BenchmarkPeerKeepAlive(b *testing.B) {
	for _, mode := range []string{"per-conn", "per-request"} {
		b.Run(mode, func(b *testing.B) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				b.Fatal(err)
			}
			port := ln.Addr().(*net.TCPAddr).Port
			s, err := New(Config{Ledger: b.TempDir(), Port: port, Token: "tok123"})
			if err != nil {
				b.Fatal(err)
			}
			s.governed = func(*http.Request) error { return nil }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "per-conn" {
				go func() { _ = Serve(ctx, ln, s) }()
			} else {
				srv := &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second}
				go func() { _ = srv.Serve(ln) }()
				defer func() { _ = srv.Close() }()
			}
			c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{MaxConnsPerHost: 1},
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			resp, err := c.Get(fmt.Sprintf("http://127.0.0.1:%d/?t=tok123", port))
			if err != nil {
				b.Fatal(err)
			}
			_ = resp.Body.Close()
			cookie := resp.Cookies()[0]
			req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/static/app.css", port), nil)
			req.AddCookie(cookie)
			b.ResetTimer()
			for range b.N {
				resp, err := c.Do(req)
				if err != nil {
					b.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					b.Fatalf("static: %d", resp.StatusCode)
				}
			}
		})
	}
}
