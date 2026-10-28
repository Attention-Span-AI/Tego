// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestLiveShotsInChrome screenshots the pages PF-4 changed over the ledger root in TEGO_LIVE_SHOT_ROOT (read only;
// give it a copy) into TEGO_CHROME_SHOTS, named after TEGO_SHOT_PREFIX: the Overview, Runs (its top and its foot)
// and the newest running run's page, at 1440 and 390 wide, light and dark. It fails when a page scrolls sideways,
// and, when a run is live, when its duration so far does not tick in the browser. It is skipped without both.
func TestLiveShotsInChrome(t *testing.T) {
	root, dir := os.Getenv("TEGO_LIVE_SHOT_ROOT"), os.Getenv("TEGO_CHROME_SHOTS")
	if root == "" || dir == "" {
		t.Skip("TEGO_LIVE_SHOT_ROOT and TEGO_CHROME_SHOTS name no ledger and no folder")
	}
	prefix := os.Getenv("TEGO_SHOT_PREFIX")
	chrome := os.Getenv("TEGO_CHROME")
	if chrome == "" {
		chrome = "google-chrome"
	}
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	cmdR, cmdW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// Chrome's helpers can still be writing the profile after the browser is killed: removed best effort, not by
	// t.TempDir, whose cleanup would fail the test.
	prof, err := os.MkdirTemp("", "tego-shots-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(prof) })
	cmd := exec.Command(chrome, "--headless=new", "--remote-debugging-pipe", "--user-data-dir="+prof,
		"--no-first-run", "--no-default-browser-check", "--disable-gpu", "--disable-extensions", "--disable-sync",
		"--disable-background-networking", "--disable-component-update", "--hide-scrollbars", "about:blank")
	cmd.ExtraFiles = []*os.File{cmdR, outW}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = cmdR.Close()
	_ = outW.Close()
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	c := &cdp{w: cmdW, wait: map[int]chan json.RawMessage{}}
	go c.read(outR)
	tb := c.open(t, "live", "http://"+addr+"/?t=tok123")
	tb.until(t, "signed in", `location.pathname === "/" && !location.search && document.readyState === "complete" && !!document.body.dataset.sig`)
	// The newest running run, from the Overview's Running now table.
	live := strings.Trim(tb.eval(t, `(document.querySelector('[data-live="r-ov-live"] tr[data-k]') || {dataset: {k: ""}}).dataset.k`), `"`)
	pages := []struct{ name, path, scroll string }{
		{"overview", "/", ""},
		{"runs", "/runs", ""},
		{"runs-foot", "/runs", "document.body.scrollHeight"},
	}
	if live != "" {
		pages = append(pages, struct{ name, path, scroll string }{"run", "/runs/" + live, ""})
	}
	for _, p := range pages {
		for _, w := range []int{1440, 390} {
			for _, scheme := range []string{"light", "dark"} {
				tb.c.call(t, tb.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": w, "height": 1000, "deviceScaleFactor": 1, "mobile": w < 600})
				tb.c.call(t, tb.session, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{{"name": "prefers-color-scheme", "value": scheme}}})
				sep := "?"
				if strings.Contains(p.path, "?") {
					sep = "&"
				}
				tb.c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + p.path + sep + "t=tok123"})
				time.Sleep(300 * time.Millisecond)
				tb.until(t, p.name+" loaded", `document.readyState === "complete" && !!document.body.dataset.sig`)
				if p.scroll != "" {
					tb.eval(t, `window.scrollTo(0, `+p.scroll+`)`)
				}
				time.Sleep(200 * time.Millisecond)
				if over := tb.eval(t, `document.documentElement.scrollWidth > window.innerWidth`); over != "false" {
					t.Errorf("%s at %d (%s): the page scrolls sideways", p.name, w, scheme)
				}
				var r struct{ Data []byte }
				_ = json.Unmarshal(tb.c.call(t, tb.session, "Page.captureScreenshot", map[string]any{"format": "png"}), &r)
				if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%s%s-%d-%s.png", prefix, p.name, w, scheme)), r.Data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		// A running run's duration so far ticks in the browser, with no region answer.
		// (A clock started 5 s ago reads 5 to 7 s a second later; the run's own may show whole minutes or hours. The
		// regions are unhooked first, so no region answer puts the run's own start back.)
		if live != "" && p.name != "runs-foot" {
			tb.eval(t, `(function () { document.querySelectorAll("[data-live]").forEach(function (e) { e.removeAttribute("data-live"); }); var n = document.querySelector("[data-since]"); if (n) n.dataset.since = new Date(Date.now() - 5000).toISOString(); return ""; })()`)
			time.Sleep(1200 * time.Millisecond)
			if got := tb.eval(t, `(document.querySelector("[data-since]") || {}).textContent || ""`); got != `"5 s"` && got != `"6 s"` && got != `"7 s"` {
				t.Errorf("%s: the duration so far does not tick: a clock started 5 s ago reads %s", p.name, got)
			}
		}
	}
}
