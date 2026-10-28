// SPDX-License-Identifier: Apache-2.0

package web

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// openTarget is the path and query of an OpenURL address, for do().
func openTarget(t *testing.T, u string) string {
	t.Helper()
	_, q, ok := strings.Cut(u, "/?o=")
	if !ok || len(q) != 32 || strings.Trim(q, "0123456789abcdef") != "" {
		t.Fatalf("OpenURL %q: want http://127.0.0.1:<port>/?o=<32 hex>", u)
	}
	return "/?o=" + q
}

// TestOpenCodeSignsInOnce: the opener's address signs in once (303, the session cookie, the code gone from the
// address), a second use of it is refused, and it never carries the reusable token.
func TestOpenCodeSignsInOnce(t *testing.T) {
	s := newServer(t, fixture(t))
	u := s.OpenURL()
	if strings.Contains(u, s.Token()) || !strings.HasPrefix(u, "http://127.0.0.1:8484/?o=") {
		t.Fatalf("OpenURL %q: want the dashboard's address with a one-time code, never the token", u)
	}
	target := openTarget(t, u)
	w := do(s, "GET", target, "127.0.0.1:8484", nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("first use: %d %q, want 303 to /", w.Code, w.Header().Get("Location"))
	}
	var c *http.Cookie
	for _, k := range w.Result().Cookies() {
		if k.Name == s.cookie && k.HttpOnly && k.SameSite == http.SameSiteStrictMode {
			c = k
		}
	}
	if c == nil {
		t.Fatal("first use set no HttpOnly SameSite=Strict session cookie")
	}
	if w := do(s, "GET", "/", "127.0.0.1:8484", c); w.Code != http.StatusOK {
		t.Fatalf("the session the code gave: %d, want 200", w.Code)
	}
	if w := do(s, "GET", target, "127.0.0.1:8484", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("second use without the session: %d, want 401", w.Code)
	}
	// The browser that signed in asks again (an opener that opens twice): it keeps its session, the code is dropped.
	if w := do(s, "GET", target, "127.0.0.1:8484", c); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" ||
		len(w.Result().Cookies()) != 0 {
		t.Errorf("second use with the session: %d %q %v, want 303 to / and no new cookie", w.Code, w.Header().Get("Location"),
			w.Result().Cookies())
	}
	// The printed token still works as before.
	login(t, s)
}

// TestOpenCodeExpires: a code unused for openCodeTTL is refused, a wrong or short code is refused, and a HEAD does
// not use a code up.
func TestOpenCodeExpires(t *testing.T) {
	s := newServer(t, fixture(t))
	now := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	s.cfg.Now = func() time.Time { return now }

	late := openTarget(t, s.OpenURL())
	now = now.Add(openCodeTTL)
	if w := do(s, "GET", late, "127.0.0.1:8484", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("a code %v old: %d, want 401", openCodeTTL, w.Code)
	}
	if len(s.openCodes) != 0 {
		t.Errorf("the expired code is still held: %v", s.openCodes)
	}

	fresh := openTarget(t, s.OpenURL())
	for _, bad := range []string{"/?o=" + strings.Repeat("0", 32), "/?o=abc", "/?o=" + strings.ToUpper(fresh[4:])} {
		if w := do(s, "GET", bad, "127.0.0.1:8484", nil); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d, want 401", bad, w.Code)
		}
	}
	if w := do(s, "HEAD", fresh, "127.0.0.1:8484", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("HEAD with a code: %d, want 401", w.Code)
	}
	now = now.Add(openCodeTTL - time.Second)
	if w := do(s, "GET", fresh, "127.0.0.1:8484", nil); w.Code != http.StatusSeeOther {
		t.Errorf("a code used within its minute, after a HEAD and wrong codes: %d, want 303", w.Code)
	}
}

// TestOpenCodeBounded: minting more than maxOpenCodes drops the oldest.
func TestOpenCodeBounded(t *testing.T) {
	s := newServer(t, fixture(t))
	first := openTarget(t, s.OpenURL())
	for range maxOpenCodes {
		s.OpenURL()
	}
	if len(s.openCodes) != maxOpenCodes {
		t.Fatalf("%d codes held, want %d", len(s.openCodes), maxOpenCodes)
	}
	if w := do(s, "GET", first, "127.0.0.1:8484", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("the dropped oldest code: %d, want 401", w.Code)
	}
}

// TestOpenCodeGoverned: a governed agent cannot sign in with an open code either, and the refusal does not use it up.
func TestOpenCodeGoverned(t *testing.T) {
	s := newServer(t, fixture(t))
	target := openTarget(t, s.OpenURL())
	s.governed = func(*http.Request) error { return errors.New("run r-x") }
	if w := do(s, "GET", target, "127.0.0.1:8484", nil); w.Code != http.StatusForbidden || len(w.Result().Cookies()) != 0 {
		t.Fatalf("governed open code: %d %v, want 403 and no cookie", w.Code, w.Result().Cookies())
	}
	s.governed = func(*http.Request) error { return nil }
	if w := do(s, "GET", target, "127.0.0.1:8484", nil); w.Code != http.StatusSeeOther {
		t.Errorf("the same code from outside a run: %d, want 303", w.Code)
	}
}
