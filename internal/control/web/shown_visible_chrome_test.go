// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/pkg/spec/askproto"
)

// TestBidiAndToastInChrome (QA BR-1, BR-3) in a real browser: the approval card names a file the agent called
// a<U+202E>txt.exe as a⟦U+202E⟧txt.exe, in its path and in its "shown exactly" box; Deny on a request for a 3.7 KB
// path leaves a toast that names it cut in the middle, no taller than 40% of the window, its × on screen, at 1440x900
// and 390x844. With TEGO_CHROME_SHOTS set it saves the card at 1920x1080 and the toast at both sizes.
//
//	go test -tags chrome -run TestBidiAndToastInChrome ./internal/control/web
func TestBidiAndToastInChrome(t *testing.T) {
	chrome := os.Getenv("TEGO_CHROME")
	if chrome == "" {
		chrome = "google-chrome"
	}
	if _, err := exec.LookPath(chrome); err != nil {
		t.Fatalf("no %s: %v", chrome, err)
	}
	const (
		rtlo    = "\u202e" // U+202E RIGHT-TO-LEFT OVERRIDE
		run     = "r-aaaaaaaa-0000000000004-bidich"
		cardAsk = "q-0123456789abcdef0123456789abcd1a"
		deepAsk = "q-0123456789abcdef0123456789abcd1b"
	)
	var deep strings.Builder
	deep.WriteString("/p/proj/confidential/")
	for i := 1; i <= 14; i++ {
		deep.WriteString("D" + strconv.Itoa(i) + strings.Repeat("x", 250) + "/")
	}
	deep.WriteString("deep.txt")
	root := t.TempDir()
	now := time.Now().UTC()
	ls := line(run, "supply-chain-codex-chatgpt", 0, now.Add(-time.Minute), "run_start", `"tier":"landlock","cwd":"/p/proj","contract_source":{"path":"/p/proj/contract.yaml"},"command":["codex"]`) +
		line(run, "supply-chain-codex-chatgpt", 1, now.Add(-3*time.Second), "ask", `"ask_id":"`+cardAsk+`","ask_rule":"fs.ask_read[./confidential/]","hold":"open","op":"read","target":"/p/proj/confidential/a`+rtlo+`txt.exe"`) +
		line(run, "supply-chain-codex-chatgpt", 2, now.Add(-2*time.Second), "ask", `"ask_id":"`+deepAsk+`","ask_rule":"fs.ask_read[./confidential/]","hold":"open","op":"read","target":"`+deep.String()+`"`)
	for _, f := range []struct {
		path string
		body string
	}{{filepath.Join(root, run, "events.jsonl"), ls}, {filepath.Join(root, ".live", run), ""}} {
		if err := os.MkdirAll(filepath.Dir(f.path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.path, []byte(f.body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := answerAsk
	t.Cleanup(func() { answerAsk = old })
	answerAsk = func(_ context.Context, _, run, id string, approve, always bool) (runact.Answered, error) {
		d := askproto.Decision{AskID: id, Approved: approve, Always: always}
		return runact.Answered{Run: run, Decision: d, Word: runact.AnswerWord(d, always)}, nil
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

	size := func(tb *tab, w, h int, mobile bool) {
		tb.c.call(t, "", "Target.activateTarget", map[string]any{"targetId": tb.target})
		tb.c.call(t, tb.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": w, "height": h, "deviceScaleFactor": 1, "mobile": mobile})
	}
	save := func(tb *tab, name string) {
		dir := os.Getenv("TEGO_CHROME_SHOTS")
		if dir == "" {
			return
		}
		var r struct{ Data []byte }
		_ = json.Unmarshal(tb.c.call(t, tb.session, "Page.captureScreenshot", map[string]any{"format": "png"}), &r)
		if err := os.WriteFile(filepath.Join(dir, name+".png"), r.Data, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	ap := c.open(t, "approvals", "http://"+addr+"/approvals?t=tok123")
	size(ap, 1920, 1080, false)
	ap.until(t, "the card", `document.readyState === "complete" && !!document.querySelector("#`+cardAsk+` .ut-box")`)
	ap.eval(t, `document.getElementById("`+cardAsk+`").scrollIntoView({block: "center"}), true`)
	time.Sleep(200 * time.Millisecond)
	save(ap, "bidi-card-1920x1080")
	var box, bold string
	_ = json.Unmarshal([]byte(ap.eval(t, `document.querySelector("#`+cardAsk+` .ut-box").textContent`)), &box)
	_ = json.Unmarshal([]byte(ap.eval(t, `document.querySelector("#`+cardAsk+` .ask-path .sp-b").textContent`)), &bold)
	if !strings.Contains(box, "confidential/a⟦U+202E⟧txt.exe") || strings.Contains(box, rtlo) || bold != "a⟦U+202E⟧txt.exe" {
		t.Errorf("the card names %s in bold and %s in its box, want a⟦U+202E⟧txt.exe in both", bold, box)
	}

	// BR-3: Deny on the deep path; the toast stays (it carries Make it permanent) and its × is on screen.
	for _, sz := range []struct {
		w, h   int
		mobile bool
	}{{1440, 900, false}, {390, 844, true}} {
		tb := c.open(t, "approvals", "http://"+addr+"/approvals?t=tok123")
		size(tb, sz.w, sz.h, sz.mobile)
		tb.until(t, "the deep card", `document.readyState === "complete" && !!document.querySelector('#`+deepAsk+` button[value="deny"]')`)
		tb.eval(t, `document.querySelector('#`+deepAsk+` button[value="deny"]').click(), true`)
		tb.until(t, "a toast", `!!document.querySelector(".toast") && document.querySelector(".toast").textContent.includes("Never allow")`)
		time.Sleep(200 * time.Millisecond)
		save(tb, "toast-deep-path-"+strconv.Itoa(sz.w)+"x"+strconv.Itoa(sz.h))
		var m struct {
			XTop, XBottom, Height, Inner, Lines float64
			Text                                string
		}
		if err := json.Unmarshal([]byte(tb.eval(t, `(() => { const t = document.querySelector(".toast"), x = t.querySelector(".toast-x"), s = t.querySelector("span");
			const r = x.getBoundingClientRect(), lh = parseFloat(getComputedStyle(s).lineHeight) || 20;
			return {XTop: r.top, XBottom: r.bottom, Height: t.getBoundingClientRect().height, Inner: innerHeight, Lines: Math.round(s.getBoundingClientRect().height / lh), Text: s.textContent}; })()`)), &m); err != nil {
			t.Fatal(err)
		}
		if m.XTop < 0 || m.XBottom > m.Inner || m.Height > 0.4*m.Inner+1 || !strings.Contains(m.Text, "…") || !strings.Contains(m.Text, "/deep.txt · Make it permanent") {
			t.Errorf("%dx%d: the toast is %.0f px tall in a %.0f px window, its × at %.0f-%.0f px", sz.w, sz.h, m.Height, m.Inner, m.XTop, m.XBottom)
		}
		t.Logf("%dx%d: toast %.0f px, %.0f lines, %d characters: %s", sz.w, sz.h, m.Height, m.Lines, len([]rune(m.Text)), m.Text)
	}
}
