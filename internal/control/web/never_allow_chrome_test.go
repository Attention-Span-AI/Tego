// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

// The Never allow beat in a real browser: headless Chrome over the DevTools pipe
// (chrome_test.go's cdp) opens the asked token line of a live run at 1440x900, clicks Never allow and measures that
// "Check the change" and "Confirm: never allow" sit inside the window and inside the sticky aside with no scroll by
// hand; the same after the Deny notice's "Make it permanent" link, and at 1440x520. It confirms, opens the preview
// again and checks the calm "already never allowed" banner and that the aside does not scroll sideways. Last it
// confirms a change with its "Also apply now" box ticked and opens the Saved panel once the run has put the block in
// force: Live now, then Undo with its acknowledgement and "Also lift". Run it by hand, through the box's memory slice:
//
//	go test -tags chrome -run TestNeverAllowInChrome ./internal/control/web
//
// With TEGO_CHROME_SHOTS set it saves the preview, a no-JS Confirm that saved nothing, the reopened preview, the
// preview with its "Also apply now" box ticked and that Saved panel at 1440 and 390, light and dark, and fails if any
// of them scrolls sideways.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/liveblock"
)

// actMeasure is where the step-3 heading and the Confirm button sit, against the window and the aside.
const actMeasure = `(function(){
var a=document.querySelector(".ev-side"), h=null, b=null;
document.querySelectorAll("#act h3").forEach(function(x){ if(x.textContent.indexOf("Check the change")>=0) h=x; });
b=document.querySelector("#act-confirm button[type=submit]");
function r(e){ if(!e) return null; var q=e.getBoundingClientRect(); return {top:Math.round(q.top), bottom:Math.round(q.bottom)}; }
var ar=a.getBoundingClientRect();
return JSON.stringify({vh:innerHeight, winY:Math.round(scrollY), check:r(h), confirm:r(b), confirmText:b?b.textContent:"",
  aside:{top:Math.round(ar.top), bottom:Math.round(ar.bottom), scrollTop:Math.round(a.scrollTop), scrollH:a.scrollHeight,
  clientH:a.clientHeight, scrollW:a.scrollWidth, clientW:a.clientWidth},
  pageOver: document.documentElement.scrollWidth > innerWidth});
})()`

type box struct{ Top, Bottom int }

type actM struct {
	VH, WinY       int
	Check, Confirm *box
	ConfirmText    string
	Aside          struct{ Top, Bottom, ScrollTop, ScrollH, ClientH, ScrollW, ClientW int }
	PageOver       bool
}

func TestNeverAllowInChrome(t *testing.T) {
	chrome := os.Getenv("TEGO_CHROME")
	if chrome == "" {
		chrome = "google-chrome"
	}
	if _, err := exec.LookPath(chrome); err != nil {
		t.Fatalf("no %s: %v", chrome, err)
	}
	root, _, _ := askFixture(t)
	holdLock(t, filepath.Join(root, actRun)) // a live run, as on stage: Also apply now and Block now fill the aside
	s, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	s.cfg.Rules = &rules.Service{Ledger: root, Now: s.cfg.Now, Check: func(string, string, []byte) error { return nil }}

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

	base := "http://" + addr
	line := base + "/runs/" + actRun + "/lines/3"
	tb := c.open(t, "line", base+"/?t=tok123")
	tb.until(t, "logged in", `document.readyState === "complete" && !!document.body.dataset.sig`)
	size := func(w, h int, scheme string) {
		tb.c.call(t, tb.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": w, "height": h, "deviceScaleFactor": 1, "mobile": w < 600})
		tb.c.call(t, tb.session, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{{"name": "prefers-color-scheme", "value": scheme}}})
	}
	visit := func(u string) {
		// Through about:blank, so the same address with a fragment loads again instead of only scrolling.
		tb.c.call(t, tb.session, "Page.navigate", map[string]any{"url": "about:blank"})
		tb.until(t, "blank", `location.href === "about:blank" && document.readyState === "complete"`)
		tb.c.call(t, tb.session, "Page.navigate", map[string]any{"url": u})
		tb.until(t, "loaded "+u, `location.protocol === "http:" && document.readyState === "complete" && !!document.body.dataset.sig`)
		time.Sleep(400 * time.Millisecond)
	}
	measure := func(what string) actM {
		var m actM
		var raw string
		if err := json.Unmarshal([]byte(tb.eval(t, actMeasure)), &raw); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: %s", what, raw)
		return m
	}
	inView := func(what string, m actM) {
		t.Helper()
		if m.Check == nil || m.Confirm == nil {
			t.Fatalf("%s: no step 3 on the page", what)
		}
		for _, e := range []struct {
			n string
			b *box
		}{{"Check the change", m.Check}, {"Confirm", m.Confirm}} {
			if e.b.Top < 0 || e.b.Bottom > m.VH || e.b.Top < m.Aside.Top || e.b.Bottom > m.Aside.Bottom {
				t.Errorf("%s: %s at %d..%d is outside the window (0..%d) or the aside (%d..%d)", what, e.n, e.b.Top, e.b.Bottom,
					m.VH, m.Aside.Top, m.Aside.Bottom)
			}
		}
	}

	// 1. Never allow, clicked on the line page at 1440x900.
	size(1440, 900, "light")
	visit(line)
	tb.eval(t, `window.__g2 = 1; Array.prototype.find.call(document.querySelectorAll("#act .ev-acts a.btn"), function(a){ return a.textContent.indexOf("Never allow") >= 0; }).click()`)
	tb.until(t, "the preview", `window.__g2 === undefined && document.readyState === "complete" && location.search.indexOf("a=block") >= 0`)
	time.Sleep(400 * time.Millisecond)
	m := measure("Never allow at 1440x900")
	inView("Never allow at 1440x900", m)
	if m.ConfirmText != "Confirm: never allow" {
		t.Errorf("the button reads %q", m.ConfirmText)
	}
	if v := tb.eval(t, `location.hash`); v != `"#act-check"` {
		t.Errorf("the preview's fragment is %s", v)
	}

	// 2. The Deny notice's "Make it permanent: Never allow" link (its href, as the notice writes it).
	visit(base + "/runs/" + actRun + "/lines/1?decided=1#act")
	inView("Make it permanent at 1440x900", measure("Make it permanent at 1440x900"))

	// For comparison, where the panel's top (#act, every action link before r10) lands.
	visit(line + "?a=block&level=1#act")
	measure("old landing #act at 1440x900")

	// 3. A short window: 1440x520.
	size(1440, 520, "light")
	visit(line + "?a=block&level=1#act")
	measure("old landing #act at 1440x520")
	visit(line + "?a=block&level=1#act-check")
	inView("Never allow at 1440x520", measure("Never allow at 1440x520"))
	// One column (the aside is not sticky up to 1000 px): the window scrolls, and step 3 clears the 52 px topbar.
	size(900, 700, "light")
	visit(line + "?a=block&level=1#act-check")
	if m := measure("Never allow at 900x700, one column"); m.Check == nil || m.Check.Top < 52 || m.Confirm.Bottom > m.VH {
		t.Errorf("one column: step 3 is under the topbar or Confirm below the window: %+v %+v", m.Check, m.Confirm)
	}
	size(1440, 900, "light")

	shots := func(name, u string) {
		dir := os.Getenv("TEGO_CHROME_SHOTS")
		if dir == "" {
			return
		}
		tb.c.call(t, "", "Target.activateTarget", map[string]any{"targetId": tb.target})
		for _, w := range []int{1440, 390} {
			for _, scheme := range []string{"light", "dark"} {
				h := 900
				if w < 600 {
					h = 844
				}
				size(w, h, scheme)
				visit(u)
				if over := tb.eval(t, `document.documentElement.scrollWidth > window.innerWidth`); over != "false" {
					t.Errorf("%s at %d (%s): the page scrolls sideways", name, w, scheme)
				}
				if over := tb.eval(t, `(function(){var a=document.querySelector(".ev-side");return a.scrollWidth > a.clientWidth;})()`); over != "false" {
					t.Errorf("%s at %d (%s): the aside scrolls sideways", name, w, scheme)
				}
				var r struct{ Data []byte }
				_ = json.Unmarshal(tb.c.call(t, tb.session, "Page.captureScreenshot", map[string]any{"format": "png"}), &r)
				if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%s-%d-%s.png", name, w, scheme)), r.Data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
		size(1440, 900, "light")
	}
	shots("g2-preview", line+"?a=block&level=1#act-check")

	// 3b. Without JavaScript, a Confirm on a stale base saves nothing and comes back to #flash, so its "Not saved:
	// ..." banner is in view (#act and #act-check both scrolled it out). form.submit() fires no submit event, so live.js stays out,
	// as it would with scripts off. The flash is shown once, so each size posts again.
	for _, w := range []int{1440, 390} {
		for _, scheme := range []string{"light", "dark"} {
			h := 900
			if w < 600 {
				h = 844
			}
			size(w, h, scheme)
			visit(line + "?a=block&level=1#act-check")
			tb.eval(t, `window.__g2 = 1; (function(f){ f.querySelector("input[name=base]").value = "`+fmt.Sprintf("%064d", 0)+`"; f.submit(); })(document.getElementById("act-confirm"))`)
			tb.until(t, "the not-saved page", `window.__g2 === undefined && document.readyState === "complete" && location.search.indexOf("flash=") >= 0`)
			time.Sleep(200 * time.Millisecond)
			got := tb.eval(t, `(function(){var f=document.getElementById("flash"), r=f&&f.getBoundingClientRect();
return JSON.stringify({hash:location.hash, text:f?f.textContent:"", top:r?Math.round(r.top):-1, bottom:r?Math.round(r.bottom):-1,
vh:innerHeight, over:document.documentElement.scrollWidth > innerWidth});})()`)
			var raw string
			_ = json.Unmarshal([]byte(got), &raw)
			var ns struct {
				Hash, Text      string
				Top, Bottom, VH int
				Over            bool
			}
			_ = json.Unmarshal([]byte(raw), &ns)
			t.Logf("not saved at %d (%s): %s", w, scheme, raw)
			if ns.Hash != "#flash" || !bytes.Contains([]byte(ns.Text), []byte("Not saved")) || ns.Top < 0 || ns.Bottom > ns.VH || ns.Over {
				t.Errorf("not saved at %d (%s): the banner is not in view at #flash, or the page scrolls sideways: %+v", w, scheme, ns)
			}
			if dir := os.Getenv("TEGO_CHROME_SHOTS"); dir != "" {
				var r struct{ Data []byte }
				_ = json.Unmarshal(tb.c.call(t, tb.session, "Page.captureScreenshot", map[string]any{"format": "png"}), &r)
				if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("g2-notsaved-%d-%s.png", w, scheme)), r.Data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	size(1440, 900, "light")

	// 4. Confirm, then open the same preview again: calm, already never allowed, no sideways scroll.
	visit(line + "?a=block&level=1#act-check")
	tb.eval(t, `document.querySelector("#act-confirm button[type=submit]").click()`)
	tb.until(t, "saved", `!!document.querySelector("#act .ev-saved")`)
	visit(line + "?a=block&level=1#act-check")
	got := tb.eval(t, `(function(){var b=document.querySelector("#act .banner");var a=document.querySelector(".ev-side");
return JSON.stringify({role:b&&b.getAttribute("role"), id:b&&b.id, danger:!!document.querySelector("#act .banner-danger"),
text:b?b.textContent:"", scrollW:a.scrollWidth, clientW:a.clientWidth});})()`)
	t.Logf("reopened preview: %s", got)
	var re struct {
		Role, ID, Text   string
		Danger           bool
		ScrollW, ClientW int
	}
	var raw string
	_ = json.Unmarshal([]byte(got), &raw)
	_ = json.Unmarshal([]byte(raw), &re)
	if re.Role != "status" || re.ID != "act-check" || re.Danger || !bytes.Contains([]byte(re.Text), []byte("./vault/ are already never allowed")) {
		t.Errorf("the reopened preview's banner: %+v", re)
	}
	if re.ScrollW > re.ClientW {
		t.Errorf("the reopened preview's aside scrolls sideways: %d > %d", re.ScrollW, re.ClientW)
	}
	shots("g2-reopened", line+"?a=block&level=1#act-check")

	// 5. A change whose "Also apply now" box can be ticked (git, on line #4), confirmed with the box ticked, and the
	// Saved panel it leads to: the live block's line, then Undo with its acknowledgement and "Also lift". The run's
	// confirming line is written as its launcher writes it, so the panel says Live now, as on stage.
	git := base + "/runs/" + actRun + "/lines/4?a=block&level=0#act-check"
	shots("g2-alsonow", git)
	visit(git)
	if v := tb.eval(t, `!!document.querySelector("#act-confirm .ev-now input[name=now]:checked")`); v != "true" {
		t.Fatal("the git preview's Also apply now box is not ticked")
	}
	tb.eval(t, `document.querySelector("#act-confirm button[type=submit]").click()`)
	tb.until(t, "the Saved panel's Also lift", `!!document.querySelector("#act .ev-saved #act-undo input[name=lift]:checked")`)
	var here string
	if err := json.Unmarshal([]byte(tb.eval(t, `location.pathname + location.search`)), &here); err != nil || !strings.Contains(here, "?saved=") {
		t.Fatalf("the Saved panel's address is %q (%v)", here, err)
	}
	o, err := liveblock.Read(filepath.Join(root, actRun), actRun)
	if err != nil || len(o.Blocks) != 1 {
		t.Fatalf("the live blocks after Also apply now: %+v %v", o, err)
	}
	seq := strings.Count(readFile(t, filepath.Join(root, actRun, "events.jsonl")), "\n")
	appendLine(t, root, actRun, liveGapLine(actRun, seq, time.Now(), string(o.Blocks[0].Kind), o.Blocks[0].Value, int(o.Serial)))
	visit(base + here + "#act")
	if v := tb.eval(t, `!!document.querySelector("#act .ev-saved .ev-live-chip") && !!document.querySelector("#act-undo input[name=ack]")`); v != "true" {
		t.Error("the Saved panel does not say Live now beside Undo's acknowledgement")
	}
	shots("g2-saved", base+here+"#act")
	fmt.Println("never allow in chrome: step 3 and Confirm in view after Never allow and Make it permanent; the reopened preview is calm;" +
		" the Saved panel says Live now beside Undo")
}

// jsString quotes s as a JavaScript string literal.
func jsString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
