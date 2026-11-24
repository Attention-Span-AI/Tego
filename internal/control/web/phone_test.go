// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestPhoneRunsFilterFallback(t *testing.T) {
	s := newServer(t, fixture(t))
	s.cfg.Now = func() time.Time { return time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC) }
	c := login(t, s)
	for _, tc := range []struct{ path, want, absent string }{
		{"/runs?filters=1&state=running&q=demo-harm", `class="filter-fallback panel panel-body"`, "demo-clean</span>"},
		{"/runs?state=ended&q=demo-clean", `class="phone-who">demo-clean</span>`, `class="phone-who">demo-harm</span>`},
		{"/runs?q=unfindable", "No runs match these filters", `class="phone-row"`},
		{"/runs?period=today", "started today", `class="phone-row"`},
		{"/more", "Auto follows your device.", `aria-current="page">Overview`},
	} {
		page := get(t, s, c, tc.path)
		if !strings.Contains(page, tc.want) || strings.Contains(page, tc.absent) {
			t.Errorf("%s: missing %q or has %q", tc.path, tc.want, tc.absent)
		}
	}
	page := get(t, s, c, "/runs?filters=1&state=running&q=demo-harm&period=24h")
	for _, want := range []string{`method="get"`, `action="/runs"`, `name="q" value="demo-harm"`, `value="running" selected`, `value="24h" selected`, `href="/runs">Clear filters`} {
		if !strings.Contains(page, want) {
			t.Errorf("fallback missing %s", want)
		}
	}
	u, err := url.Parse(runsQuery("ended", "cursor", "Mira & co", "7d"))
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("q") != "Mira & co" || u.Query().Get("period") != "7d" || u.Query().Get("before") != "cursor" {
		t.Fatal(u)
	}
}
