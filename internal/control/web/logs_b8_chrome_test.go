// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

// The Logs pages that changed, in a real browser (headless Chrome over the DevTools pipe, chrome_test.go's cdp): a window
// set as "the last hour" is pinned to times and shown as them, with a link that moves it to now; a rule change made
// while Logs is open comes in as a row with no new line and no reload; kind:change lists the rule changes alone; and a
// window with no line still shows the change made in it. Each state is checked at 390 and 1280 wide, light and dark,
// for a page that scrolls sideways, and saved under $TEGO_CHROME_SHOTS when that is set. Run it by hand:
//
//	TEGO_CHROME_SHOTS=<dir> go test -tags chrome -run TestLogsB8InChrome ./internal/control/web

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// b8Shots checks tb at 390 and 1280 wide in light and dark for sideways scrolling and saves each as name-<w>-<scheme>.
func b8Shots(t *testing.T, tb *tab, name string) {
	t.Helper()
	tb.c.call(t, "", "Target.activateTarget", map[string]any{"targetId": tb.target})
	for _, w := range []int{1280, 390} {
		for _, scheme := range []string{"light", "dark"} {
			tb.c.call(t, tb.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": w, "height": 900, "deviceScaleFactor": 1, "mobile": w < 600})
			tb.c.call(t, tb.session, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{{"name": "prefers-color-scheme", "value": scheme}}})
			time.Sleep(250 * time.Millisecond)
			if tb.eval(t, `document.documentElement.scrollWidth > window.innerWidth`) != "false" {
				t.Errorf("%s at %d (%s): the page scrolls sideways", name, w, scheme)
			}
			if dir := os.Getenv("TEGO_CHROME_SHOTS"); dir != "" {
				var r struct{ Data []byte }
				_ = json.Unmarshal(tb.c.call(t, tb.session, "Page.captureScreenshot", map[string]any{"format": "png"}), &r)
				if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%s-%d-%s.png", name, w, scheme)), r.Data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	tb.c.call(t, tb.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 1280, "height": 900, "deviceScaleFactor": 1, "mobile": false})
	tb.c.call(t, tb.session, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{{"name": "prefers-color-scheme", "value": "light"}}})
}

func TestLogsB8InChrome(t *testing.T) {
	root, _, _ := askFixture(t)
	holdLock(t, filepath.Join(root, actRun))
	var s *Server
	s, addr, ck := liveServerConfig(t, Config{Ledger: root, Machine: config.Builtin(), Now: time.Now}, 10*time.Second, 30*time.Second)
	s.cfg.Rules = &rules.Service{Ledger: root, Now: time.Now, Check: func(string, string, []byte) error { return nil }}
	s.cfg.Now = time.Now

	c := placeChrome(t)
	tb := sweepTab(t, c, "logs", 1280, 900, "light")
	nav := func(path string) {
		t.Helper()
		tb.c.call(t, tb.session, "Page.navigate", map[string]any{"url": path})
		time.Sleep(300 * time.Millisecond)
		tb.until(t, "loaded "+path, `document.readyState === "complete" && !window.__tegoMark`)
		time.Sleep(300 * time.Millisecond)
	}
	nav("http://" + addr + "/logs?t=tok123")
	tb.until(t, "the page is followed", `document.documentElement.classList.contains("lq-js")`)
	tb.eval(t, `window.__tegoMark = "kept"`)
	if tb.eval(t, `document.querySelectorAll("tr.rc-row").length`) != "0" {
		t.Fatal("a rule change before any was made")
	}

	// C99: a rule change made while Logs is open comes in as a row: no new line, no reload.
	line := "/runs/" + actRun + "/lines/4"
	web := func(method, path string, form url.Values) (int, string) {
		t.Helper()
		var body io.Reader
		if form != nil {
			body = strings.NewReader(form.Encode())
		}
		req, err := http.NewRequest(method, "http://"+addr+path, body)
		if err != nil {
			t.Fatal(err)
		}
		req.AddCookie(ck)
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Origin", "http://"+addr)
		}
		cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	_, preview := web("GET", line+"?a=block&level=0", nil)
	before := tb.eval(t, `document.querySelectorAll("#lq-rows tr.lq-r").length`)
	code, out := web("POST", line, url.Values{"csrf": {s.csrf}, "a": {"block"}, "level": {"0"}, "base": {baseOf(t, preview)}, "now": {actRun}})
	if code != 303 {
		t.Fatalf("the change was not saved: %d %s", code, out)
	}
	tb.until(t, "the change row", `document.querySelectorAll("#lq-rows tr.rc-row").length === 1`)
	if tb.eval(t, `window.__tegoMark`) != `"kept"` {
		t.Error("the page reloaded for the rule change")
	}
	if tb.eval(t, `document.querySelectorAll("#lq-rows tr.lq-r").length`) != before {
		t.Error("the event rows changed with the rule change")
	}
	b8Shots(t, tb, "b8-live-change")

	// C97 and C98: kind:change lists the change alone; a window around it with no line still shows it.
	nav("http://" + addr + "/logs?where=kind%3Achange")
	if tb.eval(t, `document.querySelectorAll("tr.rc-row").length === 1 && document.querySelectorAll("tr.lq-r").length === 0`) != "true" {
		t.Error("kind:change does not show the rule change alone")
	}
	b8Shots(t, tb, "b8-kind-change")
	feed, err := s.cfg.Rules.(*rules.Service).Feed()
	if err != nil || len(feed) == 0 {
		t.Fatalf("feed %v %v", feed, err)
	}
	at := feed[0].At
	where := "since:" + at.Add(-time.Millisecond).UTC().Format(time.RFC3339Nano) + " until:" + at.Add(time.Millisecond).UTC().Format(time.RFC3339Nano)
	nav("http://" + addr + "/logs?where=" + url.QueryEscape(where))
	if tb.eval(t, `document.querySelectorAll("tr.rc-row").length === 1 && document.querySelectorAll("tr.lq-r").length === 0 && document.body.innerText.includes("No lines match in this time frame")`) != "true" {
		t.Error("a window with no line does not show its rule change")
	}
	b8Shots(t, tb, "b8-empty-window")

	// C83: since:1h is pinned to the time it means, and a reload shows the same window.
	nav("http://" + addr + "/logs?where=since%3A1h")
	pinned := tb.eval(t, `location.search`)
	if !strings.Contains(pinned, "since%3A20") || !strings.Contains(pinned, "span=1h%40") {
		t.Fatalf("the address was not pinned: %s", pinned)
	}
	words := tb.eval(t, `document.querySelector(".lq-window-t").textContent`)
	if !strings.Contains(words, "until now") || tb.eval(t, `!!document.querySelector(".lq-window a.link")`) != "true" {
		t.Errorf("the window is not shown with Move to now: %s", words)
	}
	time.Sleep(1500 * time.Millisecond)
	tb.eval(t, `location.reload()`)
	tb.until(t, "reloaded", `document.readyState === "complete"`)
	time.Sleep(300 * time.Millisecond)
	if again := tb.eval(t, `location.search`); again != pinned {
		t.Errorf("a reload moved the window: %s then %s", pinned, again)
	}
	if tb.eval(t, `document.querySelector(".lq-window-t").textContent`) != words {
		t.Error("a reload changed the words of the window")
	}
	if tb.eval(t, `!!document.querySelector('a.chip[aria-current="true"]') && document.querySelector('a.chip[aria-current="true"]').textContent`) != `"1 hour"` {
		t.Error("the 1 hour preset is not marked")
	}
	b8Shots(t, tb, "b8-pinned-window")
	time.Sleep(1100 * time.Millisecond) // the clock moved on: Move to now writes the new time
	tb.eval(t, `document.querySelector(".lq-window a.link").click()`)
	tb.until(t, "moved to now", `location.search.includes("span=1h") && document.querySelector(".lq-window-t") && document.querySelector(".lq-window-t").textContent !== `+fmt.Sprintf("%q", strings.Trim(words, `"`)))
}
