// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

// TestViewLinksWithoutJS: the views live.js changes in place ("keeping the reader's place") are still plain links and
// GET forms, and a plain GET of each address renders the filtered page, so the dashboard works as before without
// JavaScript and every view is a link to share.
func TestViewLinksWithoutJS(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	runs := do(s, "GET", "/runs", "127.0.0.1:8484", c).Body.String()
	for _, want := range []string{`<a class="chip" href="/runs?state=ended">`, `<a class="chip" href="/runs?state=running">`} {
		if !strings.Contains(runs, want) {
			t.Errorf("Runs lacks the plain link %s", want)
		}
	}
	w := do(s, "GET", "/runs?state=ended", "127.0.0.1:8484", c)
	if w.Code != http.StatusOK {
		t.Fatalf("/runs?state=ended: %d", w.Code)
	}
	ended := w.Body.String()
	if !regexp.MustCompile(`href="/runs\?state=ended" aria-current="true">Ended 1<`).MatchString(ended) {
		t.Error("the Ended view does not mark its chip")
	}
	if !strings.Contains(ended, `data-k="`+cleanRun+`"`) || strings.Contains(ended, `data-k="`+harmRun+`"`) {
		t.Error("the Ended view lists the running run, or lacks the ended one")
	}

	logs := do(s, "GET", "/logs", "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(logs, `<form class="filters lq-form" action="/logs" method="get"`) {
		t.Error("the Logs query form is no longer a GET form")
	}
	refused := do(s, "GET", "/logs?where=verdict%3Arefused", "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(refused, `<span class="mono">verdict:refused</span>`) || strings.Contains(refused, `out/hello.txt`) {
		t.Error("the refused view lacks its query chip, or shows an allowed line")
	}

	tabs := do(s, "GET", "/runs/"+harmRun+"/receipt", "127.0.0.1:8484", c).Body.String()
	if !regexp.MustCompile(`href="/runs/` + harmRun + `/receipt" aria-current="page">Receipt<`).MatchString(tabs) {
		t.Error("the run page's Receipt tab is not a plain link marked current on its own address")
	}
}

// TestKeepPlaceScript: place.js keeps the reader's place by progressive enhancement only, within the page's CSP
// (live.js loads it from /static once its merge is ready): no eval, no string timer, no inline handler; and it leaves
// the browser's own behaviour to a modified click, a target, a download and a #place.
func TestKeepPlaceScript(t *testing.T) {
	b, err := assets.ReadFile("static/place.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	live, err := assets.ReadFile("static/live.js")
	if err != nil || !strings.Contains(string(live), "ps.src = '/static/place.js';") {
		t.Errorf("live.js does not load place.js (%v)", err)
	}
	// MCP tools and Model routes render no signature: live.js lends its merge and loads place.js before it stops there.
	stop := "\n  if (!d.sig) return; //"
	if l := string(live); !strings.Contains(l, stop) || strings.Index(l, "window.tegoLive = {") > strings.Index(l, stop) ||
		strings.Index(l, "ps.src = '/static/place.js';") > strings.Index(l, stop) {
		t.Error("live.js stops on a page without a signature before it defines tegoLive and loads place.js")
	}
	for _, bad := range []string{"eval(", "new Function", "setTimeout('", `setTimeout("`, "onclick", "javascript:"} {
		if strings.Contains(js, bad) {
			t.Errorf("place.js has %q", bad)
		}
	}
	for _, want := range []string{
		"e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey", // a modified or middle click
		"a.hasAttribute('download')",                                         // CSV, JSONL
		"(a.target && a.target !== '_self')",                                 // target=_blank
		"if (u.hash) return null;",                                           // Never allow's #act-check loads its page
		"history[same ? 'replaceState' : 'pushState']",                       // a view is a link to share
		"window.addEventListener('popstate'",                                 // Back and Forward
		"location.assign(u.href)",                                            // a failed fetch loads the page
		"var L = window.tegoLive",                                            // live.js's merge, not a second one
		"window.addEventListener('beforeunload', leave);",                    // a reload keeps the browser's restore
		"!doc.body.dataset.sig !== !body.dataset.sig",                        // a view only of a page of the same kind
		"stalled = true; ctl.abort();",                                       // a stalled view loads its page
	} {
		if !strings.Contains(js, want) {
			t.Errorf("place.js lacks %s", want)
		}
	}
}
