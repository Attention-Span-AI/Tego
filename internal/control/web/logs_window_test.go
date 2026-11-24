// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestRelativeTimeIsPinned (C83): a time range set as "the last hour" is answered with the same search written in
// absolute times, so a refresh shows the window the person set; the page shows the times and a link that moves the
// window to now, and the preset stays marked.
func TestRelativeTimeIsPinned(t *testing.T) {
	root, _ := queryFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	now := s.cfg.Now()
	since := now.Add(-time.Hour).Local().Format("2006-01-02T15:04:05")

	w := do(s, "GET", "/logs?where="+url.QueryEscape("kind:exec since:1h"), "127.0.0.1:8484", c)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("a relative time range answered %d, want a redirect to the pinned one", w.Code)
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil || loc.Path != "/logs" {
		t.Fatalf("redirect to %q: %v", w.Header().Get("Location"), err)
	}
	if got := loc.Query().Get("where"); got != "kind:exec since:"+since {
		t.Errorf("pinned query %q, want since:%s", got, since)
	}
	if got := loc.Query().Get("span"); got != "1h@"+since {
		t.Errorf("span %q", got)
	}

	// The pinned address is the page: no redirect, and the same window an hour later.
	for _, shift := range []time.Duration{0, time.Hour} {
		s.cfg.Now = func() time.Time { return now.Add(shift) }
		p := do(s, "GET", loc.RequestURI(), "127.0.0.1:8484", c)
		if p.Code != http.StatusOK {
			t.Fatalf("the pinned address answered %d", p.Code)
		}
		page := p.Body.String()
		mustContain(t, "the pinned page", page, "From "+now.Add(-time.Hour).Local().Format("2006-01-02 15:04:05")+" until now",
			"Move to now", `href="/logs?where=kind%3Aexec&#43;since%3A1h"`, `aria-current="true">1 hour<`)
	}
	s.cfg.Now = func() time.Time { return now }

	// Absolute times and every other query stay as they are.
	for _, q := range []string{"since:" + since, "kind:exec", "until:2026-10-25T12:00:02Z"} {
		if p := do(s, "GET", "/logs?where="+url.QueryEscape(q), "127.0.0.1:8484", c); p.Code != http.StatusOK {
			t.Errorf("where=%s answered %d", q, p.Code)
		}
	}
	// Moving the window to now of a typed time keeps its length, to the minute.
	typed := do(s, "GET", "/logs?where="+url.QueryEscape("since:"+now.Add(-90*time.Minute).Local().Format("2006-01-02T15:04")), "127.0.0.1:8484", c).Body.String()
	mustContain(t, "a typed time", typed, "Move to now", `href="/logs?where=since%3A90m"`)
	// A range typed with a relative until is pinned too.
	if u := do(s, "GET", "/logs?where=until:10m", "127.0.0.1:8484", c); u.Code != http.StatusSeeOther || strings.Contains(u.Header().Get("Location"), "10m") {
		t.Errorf("relative until: %d %q", u.Code, u.Header().Get("Location"))
	}
}
