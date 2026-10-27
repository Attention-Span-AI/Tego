// SPDX-License-Identifier: Apache-2.0

package web

import (
	"regexp"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// The keyboard and accessibility floor of the main journey (Overview, a run, a line's "Act on this", Approvals Allow
// and Deny): every page is parsed and checked for the attributes a keyboard or screen-reader user depends on.
// It is a floor, not an audit: a real screen reader and a human pass are still owed.

func parseHTML(t *testing.T, name, body string) *html.Node {
	t.Helper()
	n, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return n
}

func walk(n *html.Node, f func(*html.Node)) {
	if n.Type == html.ElementNode {
		f(n)
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walk(c, f)
	}
}

func attr(n *html.Node, k string) (string, bool) {
	for _, a := range n.Attr {
		if a.Key == k {
			return a.Val, true
		}
	}
	return "", false
}

func hasAttr(n *html.Node, k string) bool { _, ok := attr(n, k); return ok }

// text is n's rendered text for a name: its descendants' text, without any subtree that is aria-hidden.
func text(n *html.Node) string {
	var b strings.Builder
	var rec func(*html.Node)
	rec = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
			return
		}
		if n.Type == html.ElementNode {
			if v, _ := attr(n, "aria-hidden"); v == "true" || n.Data == "svg" || n.Data == "script" {
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			rec(c)
		}
	}
	rec(n)
	return strings.Join(strings.Fields(b.String()), " ")
}

// name is the accessible name of a control: aria-labelledby, aria-label, a label (for= or wrapping), its own text.
func name(n *html.Node, byID map[string]*html.Node, labelFor map[string][]*html.Node) string {
	if v, _ := attr(n, "aria-labelledby"); v != "" {
		var parts []string
		for _, id := range strings.Fields(v) {
			if t := byID[id]; t != nil {
				parts = append(parts, text(t))
			}
		}
		if s := strings.Join(parts, " "); s != "" {
			return s
		}
	}
	if v, _ := attr(n, "aria-label"); strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	switch n.Data {
	case "input", "select", "textarea":
		if id, _ := attr(n, "id"); id != "" {
			for _, l := range labelFor[id] {
				if s := text(l); s != "" {
					return s
				}
			}
		}
		for p := n.Parent; p != nil; p = p.Parent {
			if p.Data == "label" {
				return text(p)
			}
		}
		if ty, _ := attr(n, "type"); ty == "submit" || ty == "button" {
			v, _ := attr(n, "value")
			return v
		}
		return ""
	}
	return text(n)
}

func focusable(n *html.Node) bool {
	if hasAttr(n, "disabled") {
		return false
	}
	switch n.Data {
	case "a":
		return hasAttr(n, "href")
	case "button", "select", "textarea", "summary":
		return true
	case "input":
		ty, _ := attr(n, "type")
		return ty != "hidden"
	}
	v, ok := attr(n, "tabindex")
	return ok && v != "-1"
}

// genericLink names a link says nothing by itself: out of context (a screen reader's links list) they are
// indistinguishable, so such a link carries an aria-label that says where it goes.
var genericLink = map[string]bool{"run": true, "review": true, "more": true, "details": true, "here": true, "open": true}

// numberOnly is a count standing alone as a link's name ("3"): it says nothing of what it counts.
var numberOnly = regexp.MustCompile(`^\d+$`)

func checkPage(t *testing.T, label, body string) {
	t.Helper()
	doc := parseHTML(t, label, body)
	byID := map[string]*html.Node{}
	labelFor := map[string][]*html.Node{}
	var order []*html.Node // focusable elements, DOM order
	h1, mains := 0, 0
	navs := 0
	walk(doc, func(n *html.Node) {
		if id, ok := attr(n, "id"); ok {
			if byID[id] != nil {
				t.Errorf("%s: id %q is used twice", label, id)
			}
			byID[id] = n
		}
		if n.Data == "label" {
			if f, ok := attr(n, "for"); ok {
				labelFor[f] = append(labelFor[f], n)
			}
		}
	})
	walk(doc, func(n *html.Node) {
		switch n.Data {
		case "html":
			if v, _ := attr(n, "lang"); v == "" {
				t.Errorf("%s: <html> has no lang", label)
			}
		case "h1":
			h1++
		case "main":
			mains++
			if v, _ := attr(n, "id"); v != "main" {
				t.Errorf("%s: <main> must be the skip link's target #main", label)
			}
		case "nav":
			navs++
			if v, _ := attr(n, "aria-label"); v == "" {
				t.Errorf("%s: a <nav> has no aria-label to tell the landmarks apart", label)
			}
		case "svg":
			if v, _ := attr(n, "aria-hidden"); v != "true" {
				t.Errorf("%s: an <svg> icon is not aria-hidden", label)
			}
		case "table":
			cap := false
			walk(n, func(c *html.Node) { cap = cap || c.Data == "caption" })
			if !cap {
				t.Errorf("%s: a <table> has no caption", label)
			}
		case "th":
			if v, _ := attr(n, "scope"); v == "" {
				t.Errorf("%s: a <th> has no scope", label)
			}
		case "button":
			if ty, _ := attr(n, "type"); ty == "" {
				t.Errorf("%s: button %q has no type", label, text(n))
			}
		}
		if v, ok := attr(n, "tabindex"); ok && v != "0" && v != "-1" {
			t.Errorf("%s: tabindex=%q on <%s> changes the tab order", label, v, n.Data)
		}
		if hasAttr(n, "autofocus") {
			t.Errorf("%s: autofocus on <%s> moves focus without being asked", label, n.Data)
		}
		for _, k := range []string{"aria-labelledby", "aria-describedby"} {
			if v, ok := attr(n, k); ok {
				for _, id := range strings.Fields(v) {
					if byID[id] == nil {
						t.Errorf("%s: %s=%q names no element", label, k, id)
					}
				}
			}
		}
		if focusable(n) {
			order = append(order, n)
			nm := name(n, byID, labelFor)
			if nm == "" {
				t.Errorf("%s: <%s %v> has no accessible name", label, n.Data, n.Attr)
			}
			if n.Data == "a" && (genericLink[strings.ToLower(strings.Trim(nm, " .…"))] || numberOnly.MatchString(nm)) {
				t.Errorf("%s: link %q names nothing by itself (generic words or a bare number); give it an aria-label", label, nm)
			}
		}
		if n.Data == "input" || n.Data == "select" || n.Data == "textarea" {
			if ty, _ := attr(n, "type"); ty != "hidden" && name(n, byID, labelFor) == "" {
				t.Errorf("%s: a form field has no label", label)
			}
		}
	})
	if h1 != 1 {
		t.Errorf("%s: %d <h1>, want 1", label, h1)
	}
	if mains != 1 {
		t.Errorf("%s: %d <main>, want 1", label, mains)
	}
	// Tab order: the skip link is the first stop and goes to #main; the main landmark's content follows the chrome.
	if len(order) == 0 || order[0].Data != "a" {
		t.Fatalf("%s: no first stop", label)
	}
	if v, _ := attr(order[0], "href"); v != "#main" {
		t.Errorf("%s: the first tab stop is %q, want the skip link to #main", label, v)
	}
	if b := byID["ask-banner"]; b != nil {
		if v, _ := attr(b, "aria-live"); v != "assertive" && v != "polite" {
			t.Errorf("%s: the approvals banner has no aria-live", label)
		}
		if v, _ := attr(b, "aria-atomic"); v != "true" {
			t.Errorf("%s: the approvals banner is not aria-atomic, a screen reader would read a fragment", label)
		}
		// The banner is before the page's own content in the tab order, so a waiting ask is the first thing reached.
		var first *html.Node
		walk(byID["main"], func(n *html.Node) {
			if first == nil && focusable(n) {
				first = n
			}
		})
		inBanner := false
		for p := first; p != nil; p = p.Parent {
			inBanner = inBanner || p == b
		}
		if !inBanner {
			t.Errorf("%s: the approvals banner is not the first thing in <main>'s tab order", label)
		}
	}
}

// before reports whether the first focusable control whose name contains a comes before the first containing b.
func before(t *testing.T, label, body, a, b string) {
	t.Helper()
	doc := parseHTML(t, label, body)
	byID := map[string]*html.Node{}
	labelFor := map[string][]*html.Node{}
	i, ia, ib := 0, -1, -1
	walk(doc, func(n *html.Node) {
		if id, ok := attr(n, "id"); ok {
			byID[id] = n
		}
	})
	walk(doc, func(n *html.Node) {
		if !focusable(n) {
			return
		}
		nm := name(n, byID, labelFor)
		if ia < 0 && strings.Contains(nm, a) {
			ia = i
		}
		if ib < 0 && strings.Contains(nm, b) {
			ib = i
		}
		i++
	})
	if ia < 0 || ib < 0 || ia > ib {
		t.Errorf("%s: tab order: %q at %d, %q at %d, want the first before the second", label, a, ia, b, ib)
	}
}

// TestJourneyPagesAreKeyboardAndReaderUsable renders every page of the main journey and checks the attributes above.
func TestJourneyPagesAreKeyboardAndReaderUsable(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	for _, p := range []string{"/", "/runs", "/runs/" + harmRun, "/runs/" + harmRun + "/refusals", "/runs/" + harmRun + "/receipt",
		"/runs/" + harmRun + "/stop", "/runs/" + cleanRun, "/approvals", "/logs", "/rules", "/machine", "/compare?a=" + harmRun + "&b=" + cleanRun} {
		checkPage(t, p, get(t, s, c, p))
	}
	before(t, "/approvals", get(t, s, c, "/approvals"), "Allow once", "Deny")

	ds, dc, _, _ := detailServer(t)
	for _, p := range []string{"/runs/" + detailRun + "/lines/2", "/runs/" + detailRun + "/lines/2?a=block", "/runs/" + detailRun + "/lines/3?a=allow&cmd=1"} {
		body := get(t, ds, dc, p)
		checkPage(t, p, body)
		if !strings.Contains(body, `id="act"`) || !strings.Contains(body, "Act on this") {
			t.Errorf("%s: no Act on this section", p)
		}
	}
	before(t, "act", get(t, ds, dc, "/runs/"+detailRun+"/lines/2?a=block"), "Block next time", "Confirm")
}

// TestFocusRingIsVisibleInBothThemes: no rule removes the focus outline except main's own (a skip link target, not a
// control), the ring is drawn on :focus-visible with --c-focus, and --c-focus clears 3:1 (WCAG 1.4.11) on every
// surface in the light theme and in both dark blocks.
func TestFocusRingIsVisibleInBothThemes(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	outlineOff := regexp.MustCompile(`([^{}]+)\{[^{}]*outline:\s*(none|0)\b`)
	for _, f := range []string{"app.css", "mvp.css", "signal.css", "event.css"} {
		css := do(s, "GET", "/static/"+f, "127.0.0.1:8484", c).Body.String()
		for _, m := range outlineOff.FindAllStringSubmatch(css, -1) {
			if strings.TrimSpace(m[1]) != "main:focus" {
				t.Errorf("%s: %q removes the focus outline", f, strings.TrimSpace(m[1]))
			}
		}
	}
	app := do(s, "GET", "/static/app.css", "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(app, ":focus-visible { outline: 2px solid var(--c-focus)") {
		t.Error("app.css lacks the :focus-visible ring drawn with --c-focus")
	}
	css := do(s, "GET", "/static/tokens.css", "127.0.0.1:8484", c).Body.String()
	for name, tk := range map[string]map[string]string{
		"light": tokenBlock(t, css, ":root {\n"), "auto dark": tokenBlock(t, css, `:root:not([data-theme="light"]) {`),
		"dark": tokenBlock(t, css, `:root[data-theme="dark"] {`)} {
		for _, bg := range []string{"bg", "surface", "sunken"} {
			if r := contrast(tk["focus"], tk[bg]); r < 3 {
				t.Errorf("%s: --c-focus on --c-%s is %.2f:1, under 3:1", name, bg, r)
			}
		}
	}
}
