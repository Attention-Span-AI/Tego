// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestMCPAndRoutesPagesAreLive: the MCP tools and Model routes pages carry the live state and a "content" region, so
// live.js follows the ledger instead of leaving the page stale; a new line moves the region's hash and a region request
// answers it. The preview pages stay without (a form being checked must not be replaced under the person).
func TestMCPAndRoutesPagesAreLive(t *testing.T) {
	for _, tc := range []struct {
		name, path, preview string
		root                func(*testing.T) string
		kind, extra, source string
	}{
		{"mcp", "/mcp?run=" + harmRun, "/mcp/preview?run=" + harmRun + "&server=files&tool=delete_file&decision=allow", mcpFixture,
			"mcp", `"rule":"mcp[files]","verdict":"allow","authority":"rule","name":"files","transport":"stdio","tool":"read_file"`, "proxy"},
		{"routes", "/routes?run=" + harmRun, "/routes/preview?run=" + harmRun + "&endpoint=" + routesEndpoint + "&route=corp", routesFixture,
			"ssl_request", `"endpoint":"anthropic","method":"POST","path":"/v1/messages","host":"api.anthropic.com","size":120,"route":{"name":"direct","authority":"api.anthropic.com:443"}`, "forwarder"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := tc.root(t)
			s := newServer(t, root)
			c := login(t, s)
			body := do(s, "GET", tc.path, "127.0.0.1:8484", c).Body.String()
			have := regionsIn(body)
			if have["content"] == "" || !strings.Contains(body, ` data-sig="`) {
				t.Fatalf("no content region or no live state on the page: %v", have)
			}
			if w := doRegions(s, tc.path, "127.0.0.1:8484", c, headerOf(have)); w.Code != http.StatusOK || w.Body.Len() != 0 {
				t.Fatalf("unchanged page answered %d %q", w.Code, w.Body.String())
			}
			// A call the relay records moves the tool's count: the region answers with the new number.
			appendLine(t, root, harmRun, strings.Replace(line(harmRun, "demo-harm", 40, time.Now(), tc.kind, tc.extra), `"source":"supervisor"`, `"source":"`+tc.source+`"`, 1))
			w := doRegions(s, tc.path, "127.0.0.1:8484", c, headerOf(have))
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `<template data-live="content"`) {
				t.Fatalf("a moved ledger did not answer the content region: %d %q", w.Code, w.Body.String())
			}
			pv := do(s, "GET", tc.preview, "127.0.0.1:8484", c).Body.String()
			if strings.Contains(pv, ` data-sig="`) || regionsIn(pv)["content"] != "" {
				t.Fatal("the preview page follows the ledger")
			}
		})
	}
}

// TestLogsLineCarriesItsRevision: an opened row's panel (GET /logs/line) names its revision, so a panel left open asks
// again when the state behind it moves: unchanged it answers 304 with no body, and a line that came after it (the
// panel says "line 3 of N") gives a new revision and the new panel.
func TestLogsLineCarriesItsRevision(t *testing.T) {
	root, _ := progFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	target := "/logs/line?run=" + progRun + "&seq=2"
	ask := func(inm string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", target, nil)
		r.Host = "127.0.0.1:8484"
		r.AddCookie(c)
		if inm != "" {
			r.Header.Set("If-None-Match", inm)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	first := ask("")
	rev := first.Header().Get("ETag")
	if first.Code != http.StatusOK || rev == "" || !strings.Contains(first.Body.String(), "lx-kv") {
		t.Fatalf("the panel: %d, ETag %q", first.Code, rev)
	}
	if again := ask(rev); again.Code != http.StatusNotModified || again.Body.Len() != 0 {
		t.Fatalf("an unchanged panel answered %d with %d bytes", again.Code, again.Body.Len())
	}
	appendLine(t, root, progRun, line(progRun, "codex", 153, progT0.Add(153*time.Second), "net", `"verdict":"refused","rule":"net.deny[evil.example]","reason":"net-not-allowed","proto":"tcp","dst":"203.0.113.9:443","host":"evil.example"`))
	moved := ask(rev)
	if moved.Code != http.StatusOK || moved.Header().Get("ETag") == rev || moved.Body.Len() == 0 {
		t.Fatalf("after a line came the panel answered %d, ETag %q", moved.Code, moved.Header().Get("ETag"))
	}
}

// TestLogsSaysWhatFollowsTheRecord: the results panel says, in each view, what refreshes by itself and what does not
// (C92): the lines view brings new lines in and keeps an opened row, a grouped view follows only at the top, an older
// page stays as loaded.
func TestLogsSaysWhatFollowsTheRecord(t *testing.T) {
	root, _ := progFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	for _, tc := range []struct{ path, want string }{
		{"/logs", "new lines arrive at the top while you are there"},
		{"/logs?group=process", "groups follow the record while you are at the top of this page"},
		{"/logs?before=zzz", "This is an older page: it stays as it was loaded"},
	} {
		body := do(s, "GET", tc.path, "127.0.0.1:8484", c).Body.String()
		if !strings.Contains(body, `class="soft lq-live-note"`) || !strings.Contains(body, tc.want) {
			t.Errorf("%s does not say %q", tc.path, tc.want)
		}
	}
}
