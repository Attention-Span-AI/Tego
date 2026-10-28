// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestFlashShowsOnce: an action's 303 names a flash its page shows once; a reload of the same address shows the
// page alone and posts nothing.
func TestFlashShowsOnce(t *testing.T) {
	got := fakeBroker(t)
	s := newServer(t, fixture(t))
	c := login(t, s)
	tok := csrfOf(t, s, c, "/approvals")
	w := post(s, "/approvals/answer", url.Values{"csrf": {tok}, "run": {harmRun}, "ask": {"ask-7"}, "decision": {"deny"}}, own, own+"/approvals", c)
	loc := w.Header().Get("Location")
	if b := follow(t, s, c, w); !strings.Contains(b, `id="flash"`) || !strings.Contains(b, "Denied: connection to example.com") {
		t.Fatalf("first view lacks the flash: %s", b)
	}
	if b := do(s, "GET", loc, "127.0.0.1:8484", c).Body.String(); strings.Contains(b, `id="flash"`) {
		t.Error("a reload shows the flash again")
	}
	if got.calls != 1 {
		t.Errorf("the broker was called %d times, want 1", got.calls)
	}
}

// TestDenyFlashLinksToTheRule: a denial on a run with a contract file offers to make it permanent, on the ask's
// line page; a run without one (tego watch) offers nothing.
func TestDenyFlashLinksToTheRule(t *testing.T) {
	fakeBroker(t)
	root := fixture(t)
	p := filepath.Join(root, harmRun, "events.jsonl")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	withContract := strings.Replace(string(b), `"command":["sh","agent.sh"]`, `"command":["sh","agent.sh"],"contract_source":{"path":"/p/agent.yaml"}`, 1)
	if err := os.WriteFile(p, []byte(withContract), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	tok := csrfOf(t, s, c, "/approvals")
	page := follow(t, s, c, post(s, "/approvals/answer", url.Values{"csrf": {tok}, "run": {harmRun}, "ask": {"ask-7"}, "decision": {"deny"}}, own, own+"/runs/"+harmRun, c))
	if !strings.Contains(page, `href="/runs/`+harmRun+`/lines/5?decided=1#act">Make it permanent: Never allow</a>`) {
		t.Errorf("the Deny line does not link to the ask's line page")
	}

	plain := newServer(t, fixture(t))
	pc := login(t, plain)
	ptok := csrfOf(t, plain, pc, "/approvals")
	if b := follow(t, plain, pc, post(plain, "/approvals/answer", url.Values{"csrf": {ptok}, "run": {harmRun}, "ask": {"ask-7"}, "decision": {"deny"}}, own, "", pc)); strings.Contains(b, "Make it permanent") {
		t.Error("a run with no contract file offers to make a denial permanent")
	}
}

// TestBlockReturnsWithALine: a block of a run that is not running returns to the page with a plain line and no
// package name; the run page's prefill keys are dropped from the address it returns to.
func TestBlockReturnsWithALine(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	tok := csrfOf(t, s, c, "/runs/"+harmRun)
	w := post(s, "/runs/"+harmRun+"/block", url.Values{"csrf": {tok}, "kind": {"exec"}, "value": {"ls"}}, own, own+"/runs/"+harmRun+"?block=exec&value=ls", c)
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/runs/"+harmRun+"?flash=") {
		t.Errorf("block returned to %q", loc)
	}
	b := follow(t, s, c, w)
	if !strings.Contains(b, "Not done: the run is not running") || strings.Contains(b, "runact:") {
		t.Error("the block's line is not plain")
	}
	b = follow(t, s, c, post(s, "/runs/"+harmRun+"/block", url.Values{"csrf": {tok}, "kind": {"net"}, "value": {"garbage host"}}, own, "", c))
	if !strings.Contains(b, "Not done: ") || strings.Contains(b, "liveblock:") {
		t.Error("an invalid block shows a package name")
	}
}

// TestSamePage: an action returns only to a page of this dashboard.
func TestSamePage(t *testing.T) {
	const host = "127.0.0.1:8484"
	for raw, want := range map[string]string{
		"":                                      "",
		"/approvals":                            "/approvals",
		"http://127.0.0.1:8484/logs?q=x":        "/logs?q=x",
		"http://127.0.0.1:8484/runs/r-a/stop":   "/runs/r-a",
		"/runs/r-a?block=exec&value=ls&flash=1": "/runs/r-a",
		"http://evil.example/x":                 "",
		"http://127.0.0.1:9999/x":               "",
		"https://127.0.0.1:8484/x":              "",
		"//evil.example/x":                      "",
		"/\\evil.example":                       "",
		"javascript:alert(1)":                   "",
		"http://u:p@127.0.0.1:8484/":            "",
		"logs":                                  "",
	} {
		if got := samePage(raw, host); got != want {
			t.Errorf("samePage(%q) = %q, want %q", raw, got, want)
		}
	}
	r, _ := http.NewRequest("POST", "/x", nil)
	r.Host = host
	r.Header.Set("Referer", "http://evil.example/")
	if got := backTo(r, "/approvals"); got != "/approvals" {
		t.Errorf("a foreign Referer returned %q", got)
	}
}

// TestFlashEscapesAgentText: a flash names what the agent asked for, which the agent chose; markup in it is shown as
// text, in the line and in its link, never run.
func TestFlashEscapesAgentText(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	id := s.putFlash(flash{Text: `Denied: read of /tmp/"><script>alert(1)</script>`, Link: `/runs/x/lines/1#act" onmouseover="alert(2)`, LinkText: "Never allow <b>it</b>"})
	b := do(s, "GET", "/approvals?flash="+id, "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(b, `id="flash"`) {
		t.Fatalf("the flash is not shown: %s", b)
	}
	for _, bad := range []string{"<script>alert(1)", `" onmouseover=`, "<b>it</b>"} {
		if strings.Contains(b, bad) {
			t.Errorf("the flash renders %q unescaped", bad)
		}
	}
	if !strings.Contains(b, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("the flash's text is missing or not escaped as text")
	}
}

// TestInlineAnswerIsTheFlashLine: a form static/live.js posts in the background (X-Tego-Inline) gets the line a plain
// form's 303 would carry to the next page, as JSON, and no flash is kept for a page to show it again: the line is
// said once, in live.js's toast.
func TestInlineAnswerIsTheFlashLine(t *testing.T) {
	fakeBroker(t)
	s := newServer(t, fixture(t))
	c := login(t, s)
	tok := csrfOf(t, s, c, "/approvals")
	r := httptest.NewRequest("POST", "/approvals/answer", strings.NewReader(url.Values{"csrf": {tok}, "run": {harmRun}, "ask": {"ask-7"}, "decision": {"deny"}}.Encode()))
	r.Host = "127.0.0.1:8484"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", own)
	r.Header.Set(inlineHeader, "1")
	r.AddCookie(c)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var a inlineAnswer
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") || json.Unmarshal(w.Body.Bytes(), &a) != nil {
		t.Fatalf("inline answer: %d %q %s", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	if !a.OK || !strings.HasPrefix(a.Text, "Denied: connection to example.com") {
		t.Errorf("inline answer %+v, want the Denied line", a)
	}
	s.flashMu.Lock()
	kept := len(s.flashes)
	s.flashMu.Unlock()
	if kept != 0 {
		t.Errorf("an inline answer kept %d flashes for a page", kept)
	}
}

// TestFlashInLiveRegion: the flash line is part of the layout's r-banner live region, so the page that shows it is
// live like any other; a region request with the page's ?flash= in its address does not take the flash again.
func TestFlashInLiveRegion(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	id := s.putFlash(flash{OK: true, Text: "Allowed once: the request"})
	b := do(s, "GET", "/runs/"+harmRun+"?flash="+id, "127.0.0.1:8484", c).Body.String()
	banner := regexp.MustCompile(`(?s)<div class="lr" data-live="r-banner"[^>]*>(.*?)</div>\s*<div class="lr" data-live="r-run-top"`).FindStringSubmatch(b)
	if banner == nil || !strings.Contains(banner[1], `id="flash"`) || !strings.Contains(banner[1], "Allowed once: the request") {
		t.Fatalf("the flash is not inside the r-banner region: %s", b)
	}
	id = s.putFlash(flash{OK: true, Text: "Stopped demo-harm."})
	if w := doRegions(s, "/runs/"+harmRun+"?flash="+id, "127.0.0.1:8484", c, "r-banner:x"); w.Code != http.StatusOK {
		t.Fatalf("region request: %d", w.Code)
	}
	if f := s.takeFlash(id); f == nil {
		t.Error("a region request took the page's flash")
	}
}
