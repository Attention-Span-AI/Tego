// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestShellHeadAndNoScriptInChrome measures the shell with a waiting ask. With scripts disabled there is no
// enhancement to move content, so the band must stay in the flow and leave the page head readable.
// Page-head links must also meet the 24px target minimum even beside the banner's controls.
func TestShellHeadAndNoScriptInChrome(t *testing.T) {
	_, addr, _ := liveServer(t, fixture(t), 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	for _, js := range []bool{true, false} {
		for _, width := range []int{390, 1280} {
			t.Run(fmt.Sprintf("js=%t/width=%d", js, width), func(t *testing.T) {
				tb := sweepTab(t, c, t.Name(), width, 900, "light")
				c.call(t, tb.session, "Emulation.setScriptExecutionDisabled", map[string]any{"value": !js})
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/detections?t=tok123"})
				tb.until(t, "detections loaded", `document.readyState === "complete" && !!document.querySelector(".head-actions > a.link")`)
				if got := tb.eval(t, `Array.from(document.querySelectorAll(".head-actions > a.link")).every(e => innerWidth<=600 ? !e.checkVisibility({contentVisibilityAuto:true}) : e.getBoundingClientRect().height>=24)`); got != "true" {
					t.Error("page-head links must be hidden on phone or at least 24px high on larger screens")
				}
				if !js {
					if got := tb.eval(t, `getComputedStyle(document.getElementById("ask-banner")).position`); got != `"static"` && got != `"relative"` {
						t.Errorf("scripts off: the banner floats without room: %s", got)
					}
					if got := tb.eval(t, `document.querySelector("main h1").getBoundingClientRect().top >= document.getElementById("ask-banner").getBoundingClientRect().bottom`); got != "true" {
						t.Error("scripts off: the waiting banner covers the page head")
					}
				}
				tb.clean(t, "shell")
				c.closeTarget(t, tb.target)
			})
		}
	}
}

// TestShellFontFallbackPrintAndCopyInChrome checks the three enhancements against the real HTTP server and CSP:
// a readable wordmark when the font fails, light print even with dark selected, and fixed copy feedback in a live
// region after a merge. The clipboard is replaced only in the browser test, so it never changes the user's clipboard.
func TestShellFontFallbackPrintAndCopyInChrome(t *testing.T) {
	_, addr, _ := liveServer(t, fixture(t), 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	tb := sweepTab(t, c, "font-print-copy", 1280, 900, "dark")
	c.call(t, tb.session, "DOM.enable", map[string]any{})
	c.call(t, tb.session, "CSS.enable", map[string]any{})
	c.call(t, tb.session, "Network.enable", map[string]any{})
	c.call(t, tb.session, "Network.setBlockedURLs", map[string]any{"urls": []string{"*.woff2"}})
	c.call(t, tb.session, "Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": `Object.defineProperty(navigator, "clipboard", {value: {writeText: function (s) { window.copiedText = s; return Promise.resolve(); }}});`})
	c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/runs/" + harmRun + "/lines/3?t=tok123"})
	tb.until(t, "line loaded without font", `document.readyState === "complete" && document.fonts.status === "loaded" && !!document.querySelector(".copy-lbl[aria-live=polite]")`)
	if got := tb.eval(t, `document.fonts.check("28px Anton")`); got != "false" {
		t.Error("the test did not block the font")
	}
	// Ask Chrome which font actually painted the wordmark; object titles use the system face even with Anton present.
	const faceNode = ".brand .word"
	if tb.eval(t, fmt.Sprintf(`getComputedStyle(document.querySelector(%q)).fontFamily.startsWith('Anton')`, faceNode)) != "true" {
		t.Fatal("fallback probe does not request Anton")
	}
	var doc struct{ Root struct{ NodeID int } }
	_ = json.Unmarshal(c.call(t, tb.session, "DOM.getDocument", map[string]any{}), &doc)
	var node struct{ NodeID int }
	_ = json.Unmarshal(c.call(t, tb.session, "DOM.querySelector", map[string]any{"nodeId": doc.Root.NodeID, "selector": faceNode}), &node)
	var fonts struct {
		Fonts []struct {
			FamilyName string
			GlyphCount int
		}
	}
	_ = json.Unmarshal(c.call(t, tb.session, "CSS.getPlatformFontsForNode", map[string]any{"nodeId": node.NodeID}), &fonts)
	if len(fonts.Fonts) == 0 {
		t.Fatal("the wordmark painted no fallback glyphs")
	}
	for _, f := range fonts.Fonts {
		if strings.Contains(f.FamilyName, "Anton") || f.GlyphCount == 0 {
			t.Errorf("unexpected fallback: %+v", f)
		}
	}
	// A view merge strips enhancement attributes absent from its server template. The view's
	// enter event must restore the label before a click, even without a later live refresh.
	tb.eval(t, `var cb=document.querySelector("button.copy-btn"), fresh=cb.cloneNode(true); fresh.querySelector(".copy-lbl").removeAttribute("aria-live"); window.tegoLive.merge(cb,fresh); document.dispatchEvent(new CustomEvent("tego:enter")); ""`)
	if tb.eval(t, `document.querySelector(".copy-lbl").getAttribute("aria-live") === "polite"`) != "true" {
		t.Error("view entry left the Copy label without polite feedback")
	}
	// A merged label receives the same live-region semantics before its first click.
	tb.eval(t, `var l = document.querySelector(".copy-lbl"); l.removeAttribute("aria-live"); document.dispatchEvent(new CustomEvent("tego:merged")); document.querySelector("button.copy-btn").click(); ""`)
	tb.until(t, "copy announced", `document.querySelector(".copy-lbl[aria-live=polite]").textContent === "Copied" && typeof window.copiedText === "string"`)
	for _, theme := range []string{"auto", "dark"} {
		if theme == "dark" {
			tb.eval(t, `document.documentElement.dataset.theme = "dark"; ""`)
		}
		c.call(t, tb.session, "Emulation.setEmulatedMedia", map[string]any{"media": "print", "features": []map[string]string{{"name": "prefers-color-scheme", "value": "dark"}}})
		if got := tb.eval(t, `getComputedStyle(document.body).backgroundColor`); got != `"rgb(251, 250, 248)"` {
			t.Errorf("print with %s theme: background %s", theme, got)
		}
	}
}
