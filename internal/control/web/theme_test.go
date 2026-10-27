// SPDX-License-Identifier: Apache-2.0

package web

import (
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestThemeSwitchAndScript: every page carries the Auto/Light/Dark switch and loads theme.js early in <head> as a
// same-origin file (the CSP allows no inline script), and the script is served as JavaScript.
func TestThemeSwitchAndScript(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	w := do(s, "GET", "/runs", "127.0.0.1:8484", c)
	body := w.Body.String()
	head, _, _ := strings.Cut(body, "</head>")
	i, j := strings.Index(head, `<script src="/static/theme.js"></script>`), strings.Index(head, `/static/live.js`)
	if i < 0 || j < 0 || i > j {
		t.Errorf("theme.js must load in <head> before live.js, without defer: %d %d", i, j)
	}
	if m := regexp.MustCompile(`<script(\s[^>]*)?>`).FindAllString(body, -1); len(m) != 2 {
		t.Errorf("want exactly the two same-origin scripts, got %q", m)
	}
	for _, x := range []string{`id="theme-w" hidden`, `<select class="select" id="theme"`, `value="auto"`, `value="light"`, `value="dark"`, `for="theme"`} {
		if !strings.Contains(body, x) {
			t.Errorf("switch lacks %q", x)
		}
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self';") || strings.Contains(csp, "unsafe-inline") {
		t.Errorf("CSP %q", csp)
	}
	js := do(s, "GET", "/static/theme.js", "127.0.0.1:8484", c)
	if js.Code != http.StatusOK {
		t.Fatalf("theme.js: %d", js.Code)
	}
	if ct := js.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("theme.js content type %q", ct)
	}
	for _, x := range []string{"data-theme", "localStorage", "catch"} {
		if !strings.Contains(js.Body.String(), x) {
			t.Errorf("theme.js lacks %q", x)
		}
	}
}

func rgb(hex string) (r, g, b float64) {
	v, _ := strconv.ParseUint(strings.TrimPrefix(hex, "#"), 16, 32)
	return float64(v>>16&255) / 255, float64(v>>8&255) / 255, float64(v&255) / 255
}

func luminance(hex string) float64 {
	r, g, b := rgb(hex)
	f := func(c float64) float64 {
		if c <= 0.03928 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*f(r) + 0.7152*f(g) + 0.0722*f(b)
}

func contrast(a, b string) float64 {
	la, lb := luminance(a), luminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

func hue(hex string) float64 {
	r, g, b := rgb(hex)
	mx, mn := math.Max(r, math.Max(g, b)), math.Min(r, math.Min(g, b))
	d := mx - mn
	var h float64
	switch {
	case d == 0:
		return 0
	case mx == r:
		h = math.Mod((g-b)/d, 6)
	case mx == g:
		h = (b-r)/d + 2
	default:
		h = (r-g)/d + 4
	}
	h *= 60
	if h < 0 {
		h += 360
	}
	return h
}

func tokenBlock(t *testing.T, css, start string) map[string]string {
	t.Helper()
	i := strings.Index(css, start)
	if i < 0 {
		t.Fatalf("tokens.css lacks %q", start)
	}
	rest := css[i+len(start):]
	rest, _, _ = strings.Cut(rest, "}")
	m := map[string]string{}
	for _, x := range regexp.MustCompile(`--c-([a-z0-9-]+): (#[0-9A-Fa-f]{6});`).FindAllStringSubmatch(rest, -1) {
		m[x[1]] = x[2]
	}
	return m
}

// TestThemeTokens: in both themes the link colour is not the refusal colour (the hues sit well apart), every text
// token clears WCAG AA (4.5:1) on every surface it is drawn on, and the media-query dark block and the
// data-theme="dark" block hold the same values, so Auto and the switch look alike.
func TestThemeTokens(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	css := do(s, "GET", "/static/tokens.css", "127.0.0.1:8484", c).Body.String()
	light := tokenBlock(t, css, ":root {\n")
	auto := tokenBlock(t, css, `:root:not([data-theme="light"]) {`)
	dark := tokenBlock(t, css, `:root[data-theme="dark"] {`)
	if len(dark) == 0 || len(auto) != len(dark) {
		t.Fatalf("dark blocks: %d auto vs %d explicit", len(auto), len(dark))
	}
	for k, v := range dark {
		if auto[k] != v {
			t.Errorf("--c-%s: auto dark %s, explicit dark %s", k, auto[k], v)
		}
	}
	for name, tk := range map[string]map[string]string{"light": light, "dark": dark} {
		d := math.Abs(hue(tk["accent-text"]) - hue(tk["danger"]))
		if d > 180 {
			d = 360 - d
		}
		if d < 30 {
			t.Errorf("%s: link %s and refusal %s are only %.0f degrees of hue apart", name, tk["accent-text"], tk["danger"], d)
		}
		for _, fg := range []string{"text", "text2", "text3", "accent-text", "danger", "success", "warn", "info"} {
			for _, bg := range []string{"bg", "surface", "sunken"} {
				if r := contrast(tk[fg], tk[bg]); r < 4.5 {
					t.Errorf("%s: --c-%s on --c-%s is %.2f:1, under AA", name, fg, bg, r)
				}
			}
		}
		for fg, bg := range map[string]string{"danger": "danger-soft", "success": "success-soft", "warn": "warn-soft", "accent-text": "accent-soft", "info": "info-soft"} {
			if r := contrast(tk[fg], tk[bg]); r < 4.5 {
				t.Errorf("%s: --c-%s on --c-%s is %.2f:1, under AA", name, fg, bg, r)
			}
		}
	}
}
