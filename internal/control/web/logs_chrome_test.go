// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

// Logs in a real browser (static/logs.js): headless Chrome over the DevTools pipe (chrome_test.go's cdp) opens Logs
// on a live run of 153 lines, beside an older run with the same refusal, and checks, with a marker that a reload
// would clear: older lines come in place; a new line comes in at the top while the reader is there, and leaves the
// other run's row; lower down it waits in an "N new lines" pill that brings it in; a row opens in place with every
// field of its line and closes with Escape; j and k move through the rows. Run it by hand, through the box's memory
// slice:
//
//	go test -tags chrome -run TestLogsInChrome ./internal/control/web
//
// With TEGO_CHROME_SHOTS set it saves screenshots of the open row and the pill at 1440 and 390, light and dark.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLogsInChrome(t *testing.T) {
	chrome := os.Getenv("TEGO_CHROME")
	if chrome == "" {
		chrome = "google-chrome"
	}
	if _, err := exec.LookPath(chrome); err != nil {
		t.Fatalf("no %s: %v", chrome, err)
	}
	root, _ := progFixture(t)
	// Another, older run refused the same connection as line 2: the live tail must leave its row alone.
	if err := os.MkdirAll(filepath.Join(root, otherRun), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, otherRun, "events.jsonl"), []byte(otherRunLine()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".live"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".live", progRun), nil, 0o600); err != nil {
		t.Fatal(err)
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
	prof := filepath.Join(t.TempDir(), "profile")
	cmd := exec.Command(chrome, "--headless=new", "--remote-debugging-pipe", "--user-data-dir="+prof, "--no-first-run",
		"--no-default-browser-check", "--disable-gpu", "--disable-extensions", "--disable-sync",
		"--disable-background-networking", "--disable-component-update", "about:blank")
	cmd.ExtraFiles = []*os.File{cmdR, outW}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = cmdR.Close()
	_ = outW.Close()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("chrome stderr:\n%s", stderr.String())
		}
	})
	c := &cdp{w: cmdW, wait: map[int]chan json.RawMessage{}}
	go c.read(outR)

	lg := c.open(t, "logs", "http://"+addr+"/logs?t=tok123")
	lg.c.call(t, lg.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 1440, "height": 1000, "deviceScaleFactor": 1, "mobile": false})
	lg.until(t, "loaded", `document.readyState === "complete" && document.documentElement.classList.contains("lq-js")`)
	lg.eval(t, `window.__tegoMark = "kept"`)
	rows := `document.querySelectorAll("#lq-rows tr.lq-r")`
	kept := func(when string) {
		t.Helper()
		if lg.eval(t, `window.__tegoMark`) != `"kept"` {
			t.Fatalf("the page reloaded %s", when)
		}
	}
	if lg.eval(t, `!!document.querySelector('[data-live="r-logs-rows"]')`) != "false" {
		t.Error("the rows region is still left to live.js")
	}

	// 1. Older lines come in place.
	lg.eval(t, `document.getElementById("lq-older").click()`)
	lg.until(t, "154 rows after Older lines", rows+`.length === 154 && document.getElementById("lq-older").hidden`)
	lg.until(t, "the count says so", `document.querySelector(".lq-shown").textContent === "154"`)
	kept("after Older lines")

	// 2. At the top, a new line comes in at the top.
	lg.eval(t, `window.scrollTo(0, 0)`)
	at := func(i int) time.Time { return progT0.Add(time.Duration(i) * time.Second) }
	appendLine(t, root, progRun, line(progRun, "codex", 153, at(153), "net", `"verdict":"refused","rule":"net.deny[evil.example]","reason":"net-not-allowed","proto":"tcp","dst":"203.0.113.9:443","host":"evil.example"`))
	lg.until(t, "the new line at the top", rows+`[0].dataset.k === "`+progRun+`-153"`)
	// It is the same refusal as line 2: one folded row of two lines, the older row gone, and the counts agree.
	lg.until(t, "the counts after it", `document.querySelector(".lq-shown").textContent === "154" && document.querySelector(".lq-total").textContent === "154"`)
	if lg.eval(t, `!!document.querySelector('tr[data-k="`+progRun+`-2"]') || !document.querySelector("#lq-rows tr.lq-r .xn")`) != "false" {
		t.Error("the folded refusal's older row stayed, or the new row lacks its ×2")
	}
	if lg.eval(t, `!!document.querySelector('tr[data-k="`+otherRun+`-0"]')`) != "true" {
		t.Error("the live tail dropped another run's row of the same refusal")
	}
	kept("when a line came at the top")

	// 3. A row opens in place and closes with Escape; j and k move.
	lg.eval(t, rows+`[1].querySelector(".lx-tog").click()`)
	lg.until(t, "the open row's fields", `!!document.querySelector("tr.lx-row .lx-fields") && document.querySelector("tr.lx-row").textContent.includes("Every field")`)
	if lg.eval(t, rows+`[1].querySelector(".lx-tog").getAttribute("aria-expanded")`) != `"true"` {
		t.Error("the open row's button does not say it is open")
	}
	shots(t, lg, "logs-open-row")
	lg.eval(t, `document.dispatchEvent(new KeyboardEvent("keydown", {key: "j", bubbles: true}))`)
	lg.eval(t, `document.dispatchEvent(new KeyboardEvent("keydown", {key: "j", bubbles: true}))`)
	if got := lg.eval(t, `document.querySelector("tr.lq-cur").dataset.k`); got != strconv.Quote(progRun+"-150") {
		t.Errorf("after j j from the open row (152) the current row is %s, want line 150", got)
	}
	lg.eval(t, `document.dispatchEvent(new KeyboardEvent("keydown", {key: "k", bubbles: true}))`)
	lg.eval(t, `document.dispatchEvent(new KeyboardEvent("keydown", {key: "k", bubbles: true}))`)
	if got := lg.eval(t, `document.querySelector("tr.lq-cur").dataset.k`); got != strconv.Quote(progRun+"-152") {
		t.Errorf("after k k the current row is %s, want line 152", got)
	}
	lg.eval(t, `document.querySelector("tr.lq-cur").dispatchEvent(new KeyboardEvent("keydown", {key: "Escape", bubbles: true}))`)
	lg.until(t, "Escape closed the row", `document.querySelector("tr.lx-row").hidden`)
	kept("while rows opened and closed")

	// 4. Lower down, new lines wait in the pill, which brings them in.
	lg.eval(t, `window.scrollTo(0, 2500)`)
	appendLine(t, root, progRun, line(progRun, "codex", 154, at(154), "fs", `"verdict":"allow","rule":"fs.read[/w/x/proj]","op":"open","path":"/w/x/proj/late.txt","flags":0`))
	appendLine(t, root, progRun, line(progRun, "codex", 155, at(155), "fs", `"verdict":"allow","rule":"fs.read[/w/x/proj]","op":"open","path":"/w/x/proj/later.txt","flags":0`))
	lg.until(t, "the pill", `!document.querySelector(".lq-pill").hidden && document.querySelector(".lq-pill").textContent.includes("2 new rows")`)
	if lg.eval(t, rows+`[0].dataset.k`) != strconv.Quote(progRun+"-153") {
		t.Error("new rows moved the rows under a reader lower down")
	}
	shots(t, lg, "logs-pill")
	lg.eval(t, `document.querySelector(".lq-pill").click()`)
	lg.until(t, "the pill's rows at the top", rows+`[0].dataset.k === "`+progRun+`-155" && document.querySelector(".lq-pill").hidden`)
	kept("after the pill")

	// 5. The pill brought the reader up to the new rows (r9 QG-3: scroll anchoring kept them down the page, and the
	// pill came straight back), and at the top a busy run's lines (20 a second) come in on their own, with no pill.
	if y, _ := strconv.Atoi(lg.eval(t, `String(Math.round(window.scrollY))`)); y >= 200 {
		t.Errorf("after the pill the page is at scrollY %d, want the top (< 200)", y)
	}
	last := 155
	end := time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(end) {
		last++
		appendLine(t, root, progRun, line(progRun, "codex", last, at(last), "fs", `"verdict":"allow","rule":"fs.read[/w/x/proj]","op":"open","path":"/w/x/proj/busy`+strconv.Itoa(last)+`.txt","flags":0`))
		if lg.eval(t, `document.querySelector(".lq-pill").hidden`) != "true" {
			t.Fatalf("at the top the pill came back after line %d", last)
		}
		time.Sleep(50 * time.Millisecond)
	}
	lg.until(t, "the busy run's newest line at the top", rows+`[0].dataset.k === "`+progRun+`-`+strconv.Itoa(last)+`"`)
	if lg.eval(t, `document.querySelector(".lq-pill").hidden`) != "true" {
		t.Error("at the top the pill came back")
	}
	kept("while a busy run wrote at the top")
	fmt.Println("logs in chrome: older rows in place, the live tail at the top and in the pill, a row opened and closed in place, j/k; no reload")
}

// shots saves name at 1440 and 390 wide, light and dark, when TEGO_CHROME_SHOTS names a folder.
func shots(t *testing.T, tb *tab, name string) {
	t.Helper()
	dir := os.Getenv("TEGO_CHROME_SHOTS")
	if dir == "" {
		return
	}
	tb.c.call(t, "", "Target.activateTarget", map[string]any{"targetId": tb.target})
	y := tb.eval(t, `String(window.scrollY)`)
	for _, w := range []int{1440, 390} {
		for _, scheme := range []string{"light", "dark"} {
			tb.c.call(t, tb.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": w, "height": 1000, "deviceScaleFactor": 1, "mobile": w < 600})
			tb.c.call(t, tb.session, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{{"name": "prefers-color-scheme", "value": scheme}}})
			tb.eval(t, `(function(){var r=document.querySelector("tr.lx-row:not([hidden])");if(r)r.scrollIntoView({block:"center"});})()`)
			time.Sleep(200 * time.Millisecond)
			over := tb.eval(t, `document.documentElement.scrollWidth > window.innerWidth`)
			if over != "false" {
				t.Errorf("%s at %d (%s): the page scrolls sideways", name, w, scheme)
			}
			var r struct{ Data []byte }
			_ = json.Unmarshal(tb.c.call(t, tb.session, "Page.captureScreenshot", map[string]any{"format": "png"}), &r)
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%s-%d-%s.png", name, w, scheme)), r.Data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	tb.c.call(t, tb.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 1440, "height": 1000, "deviceScaleFactor": 1, "mobile": false})
	tb.c.call(t, tb.session, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{{"name": "prefers-color-scheme", "value": "light"}}})
	tb.eval(t, `window.scrollTo(0, `+y+`)`)
}

// TestLogsShotsInChrome screenshots Logs over the ledger root in TEGO_LOGS_SHOT_ROOT (read only; give it a copy) into
// TEGO_CHROME_SHOTS: lines, the three groupings and a row opened in place, at 1440 and 390 wide, light and dark, and
// fails when a page scrolls sideways. It is skipped without both.
func TestLogsShotsInChrome(t *testing.T) {
	root, dir := os.Getenv("TEGO_LOGS_SHOT_ROOT"), os.Getenv("TEGO_CHROME_SHOTS")
	if root == "" || dir == "" {
		t.Skip("TEGO_LOGS_SHOT_ROOT and TEGO_CHROME_SHOTS name no ledger and no folder")
	}
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
	cmd := exec.Command(chrome, "--headless=new", "--remote-debugging-pipe", "--user-data-dir="+filepath.Join(t.TempDir(), "profile"),
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
	tb := c.open(t, "logs", "http://"+addr+"/?t=tok123")
	tb.until(t, "signed in", `document.readyState === "complete"`)
	for _, p := range []struct{ name, path string }{
		{"lines", "/logs"},
		{"refused", "/logs?verdict=refused"},
		{"by-process", "/logs?group=process"},
		{"by-target", "/logs?group=target&verdict=refused"},
		{"by-rule", "/logs?group=rule"},
		{"open-row", "/logs?verdict=refused&sys=hide"},
	} {
		for _, w := range []int{1440, 390} {
			for _, scheme := range []string{"light", "dark"} {
				tb.c.call(t, tb.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": w, "height": 1000, "deviceScaleFactor": 1, "mobile": w < 600})
				tb.c.call(t, tb.session, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{{"name": "prefers-color-scheme", "value": scheme}}})
				// A navigation the browser starts itself carries no same-site cookie: the sign-in link each time.
				sep := "?"
				if strings.Contains(p.path, "?") {
					sep = "&"
				}
				tb.c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + p.path + sep + "t=tok123"})
				time.Sleep(300 * time.Millisecond)
				tb.until(t, p.name+" loaded", `document.readyState === "complete" && !!document.querySelector("#log-results")`)
				if p.name == "open-row" {
					tb.eval(t, `document.querySelector("#lq-rows tr.lq-r .lx-tog").click()`)
					tb.until(t, "the open row", `!!document.querySelector("tr.lx-row .lx-sent")`)
					tb.eval(t, `document.querySelector("tr.lx-row").scrollIntoView({block: "start"}); window.scrollBy(0, -160)`)
				}
				time.Sleep(200 * time.Millisecond)
				if over := tb.eval(t, `document.documentElement.scrollWidth > window.innerWidth`); over != "false" {
					t.Errorf("%s at %d (%s): the page scrolls sideways", p.name, w, scheme)
				}
				var r struct{ Data []byte }
				_ = json.Unmarshal(tb.c.call(t, tb.session, "Page.captureScreenshot", map[string]any{"format": "png"}), &r)
				if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("demo-%s-%d-%s.png", p.name, w, scheme)), r.Data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
}
