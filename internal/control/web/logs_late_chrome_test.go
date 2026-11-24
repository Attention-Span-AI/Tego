// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

// A43 in a real browser: Live Logs followed the newest row's sort key, so a line appended later but stamped before the
// newest row never came in until a reload. The page now carries an append cursor (data-tail). This test opens Logs on
// a live run, appends (a) a line to another run stamped ten seconds into the live run's story, far before the newest
// row, (b) a second such line, and (c) a whole new run stamped before it, and checks, with a marker a reload would
// clear, that each one reaches the open page. Run it by hand through the box's memory slice:
//
//	go test -tags chrome -run TestLogsLateLineInChrome ./internal/control/web

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestLogsLateLineInChrome(t *testing.T) {
	chrome := os.Getenv("TEGO_CHROME")
	if chrome == "" {
		chrome = "google-chrome"
	}
	if _, err := exec.LookPath(chrome); err != nil {
		t.Fatalf("no %s: %v", chrome, err)
	}
	root, _ := progFixture(t)
	if err := os.MkdirAll(filepath.Join(root, otherRun), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, otherRun, "events.jsonl"), []byte(otherRunLine()), 0o644); err != nil {
		t.Fatal(err)
	}
	markLive(t, root, progRun)
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
	var stderr chromeOutput
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
	kept := func(when string) {
		t.Helper()
		if lg.eval(t, `window.__tegoMark`) != `"kept"` {
			t.Fatalf("the page reloaded %s", when)
		}
	}
	has := func(k string) string { return `!!document.querySelector('tr[data-k="` + k + `"]')` }
	if lg.eval(t, has(otherRun+"-1")) != "false" {
		t.Fatal("the late line is on the page before it is written")
	}
	newest := lg.eval(t, `document.querySelector("#lq-rows tr.lq-r").dataset.k`)
	total := lg.eval(t, `document.querySelector(".lq-total").textContent`)

	// (a) A line appended now, stamped ten seconds into the live run's story: far before its newest row.
	lg.eval(t, `window.scrollTo(0, 0)`)
	appendLine(t, root, otherRun, line(otherRun, "claude", 1, progT0.Add(10*time.Second), "net", `"verdict":"allow","rule":"net[late.example:443]","proto":"tcp","dst":"198.51.100.7:443","host":"late.example"`))
	lg.until(t, "the late line", has(otherRun+"-1"))
	kept("when a line stamped before the newest row was appended")
	if lg.eval(t, `document.querySelector(".lq-total").textContent`) == total {
		t.Errorf("the late line came in but the total stayed %s", total)
	}

	// (b) A second one, stamped even earlier than the first.
	appendLine(t, root, otherRun, line(otherRun, "claude", 2, progT0.Add(5*time.Second), "net", `"verdict":"allow","rule":"net[late.example:443]","proto":"tcp","dst":"198.51.100.7:443","host":"late.example"`))
	lg.until(t, "the second late line", has(otherRun+"-2"))
	kept("when a second late line was appended")

	// (c) A run created after the page, stamped before the newest row, is new whole.
	const lateRun = "r-aaaaaaaa-0000000000005-latexx"
	if err := os.MkdirAll(filepath.Join(root, lateRun), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, lateRun, "events.jsonl"), []byte(line(lateRun, "claude", 0, progT0.Add(time.Second), "net", `"verdict":"allow","rule":"net[x.example:443]","proto":"tcp","dst":"198.51.100.8:443","host":"x.example"`)), 0o644); err != nil {
		t.Fatal(err)
	}
	lg.until(t, "the late run's line", has(lateRun+"-0"))
	kept("when a run began after the page")
	if got := lg.eval(t, `document.querySelectorAll('tr[data-k="`+otherRun+`-1"]').length`); got != "1" {
		t.Errorf("the late line is on the page %s times, want once", got)
	}
	_ = newest
}
