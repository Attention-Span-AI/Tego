// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"path"
	"regexp"
	"strings"
	"testing"
)

// TestShellAssetsServedUnderTheCSP: the shell's files come from the binary, each with its own type, nosniff and the
// dashboard's Content-Security-Policy, behind the session as every static file is. The headline font is
// font/woff2 whatever the host's mime.types says, the stylesheet's @font-face names it by a same-origin path the
// server answers (font-src falls back to default-src 'self'), and no page loads anything from another origin.
func TestShellAssetsServedUnderTheCSP(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	for _, tc := range []struct{ path, ctype, starts string }{
		{"/static/fonts/anton.woff2", "font/woff2", "wOF2"},
		{"/static/tokens.css", "text/css", "/* SPDX-License-Identifier: Apache-2.0 */"},
		{"/static/app.css", "text/css", "/* SPDX-License-Identifier: Apache-2.0 */"},
		{"/static/mvp.css", "text/css", "/* SPDX-License-Identifier: Apache-2.0 */"},
		{"/static/phone.css", "text/css", "/* SPDX-License-Identifier: Apache-2.0 */"},
		{"/static/guide.css", "text/css", "/* SPDX-License-Identifier: Apache-2.0 */"},
		{"/static/guide.js", "javascript", "// SPDX-License-Identifier: Apache-2.0"},
		{"/static/copy.js", "javascript", "// SPDX-License-Identifier: Apache-2.0"},
		{"/static/theme.js", "javascript", "// SPDX-License-Identifier: Apache-2.0"},
		{"/static/sprite.svg", "image/svg+xml", "<!--"},
	} {
		w := do(s, "GET", tc.path, "127.0.0.1:8484", c)
		if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Type"), tc.ctype) || !strings.HasPrefix(w.Body.String(), tc.starts) {
			t.Errorf("%s: %d %q %.20q", tc.path, w.Code, w.Header().Get("Content-Type"), w.Body.String())
		}
		if w.Header().Get("Content-Security-Policy") != csp || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: CSP %q, nosniff %q", tc.path, w.Header().Get("Content-Security-Policy"), w.Header().Get("X-Content-Type-Options"))
		}
		if w := do(s, "GET", tc.path, "127.0.0.1:8484", nil); w.Code != http.StatusUnauthorized {
			t.Errorf("%s without the session: %d", tc.path, w.Code)
		}
	}
	// A missing font is the plain 404 of the file server, not a font.
	if w := do(s, "GET", "/static/fonts/none.woff2", "127.0.0.1:8484", c); w.Code != http.StatusNotFound || strings.Contains(w.Header().Get("Content-Type"), "font") {
		t.Errorf("a missing font: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	if !strings.Contains(csp, "default-src 'self'") || strings.Contains(csp, "font-src") {
		t.Errorf("the CSP no longer covers the font by default-src 'self': %q", csp)
	}

	app := do(s, "GET", "/static/app.css", "127.0.0.1:8484", c).Body.String()
	urls := regexp.MustCompile(`url\(\s*"?([^")]+)"?\s*\)`).FindAllStringSubmatch(app, -1)
	if len(urls) != 1 {
		t.Fatalf("app.css url()s: %v", urls)
	}
	font := path.Join("/static", urls[0][1])
	if font != "/static/fonts/anton.woff2" {
		t.Errorf("the @font-face names %s", font)
	}
	face := regexp.MustCompile(`@font-face \{[^}]*\}`).FindString(app)
	for _, x := range []string{"font-family: Anton", `format("woff2")`, "font-display: swap"} {
		if !strings.Contains(face, x) {
			t.Errorf("the @font-face lacks %q: %s", x, face)
		}
	}
	// The headline face has a fallback, so a page reads the same with the font blocked.
	tokens := do(s, "GET", "/static/tokens.css", "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(tokens, "--font-display: Anton, var(--font-sans);") {
		t.Error("--font-display has no fallback to the system stack")
	}

	for _, p := range []string{"/", "/runs", "/runs/" + harmRun, "/logs", "/approvals", "/rules", "/machine", "/glossary", "/nope"} {
		b := do(s, "GET", p, "127.0.0.1:8484", c).Body.String()
		// Preload starts the request with the document; crossorigin lets the stylesheet reuse that fetch.
		if !strings.Contains(b, `<link rel="preload" href="/static/fonts/anton.woff2" as="font" type="font/woff2" crossorigin>`) {
			t.Errorf("%s does not preload the headline font", p)
		}
		for _, m := range regexp.MustCompile(`(?:src|href)="([^"]*)"`).FindAllStringSubmatch(b, -1) {
			if u := m[1]; strings.Contains(u, "//") || strings.HasPrefix(u, "data:") || strings.HasPrefix(u, "javascript:") {
				t.Errorf("%s loads or links %q, not a path of this dashboard", p, u)
			}
		}
		if strings.Contains(b, " style=") || strings.Contains(b, "<style") {
			t.Errorf("%s has an inline style the CSP would refuse", p)
		}
	}
}

// TestShellActivityColourMeaning keeps fresh activity neutral. The waiting tint belongs only to held requests.
func TestShellActivityColourMeaning(t *testing.T) {
	css, err := assets.ReadFile("static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ rule, want string }{
		{`body\.nav-busy::before \{[^}]*\}`, "background: var(--c-text)"},
		{`@keyframes live-new \{ from \{[^}]*\}`, "background: var(--c-sunken)"},
		{`\.live-new \{ animation: none;[^}]*\}`, "background: var(--c-sunken)"},
	} {
		got := regexp.MustCompile(tc.rule).FindString(string(css))
		if !strings.Contains(got, tc.want) {
			t.Errorf("activity colour: %s, want %s", got, tc.want)
		}
	}
}
