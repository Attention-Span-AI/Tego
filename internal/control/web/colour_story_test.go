// SPDX-License-Identifier: Apache-2.0

package web

import (
	"regexp"
	"strings"
	"testing"
)

// TestColourStory (QU-2, one meaning per colour): a refusal chip is the stopped tone (green, kept safe), an allowed
// line is grey, only what got through or a broken or lost record is red, states that are only states (running,
// verified) are the neutral success grey, and links are their own blue. The chips' and links' text clears WCAG AA
// (4.5:1) on what it is drawn on, in both themes.
func TestColourStory(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	tokens := do(s, "GET", "/static/tokens.css", "127.0.0.1:8484", c).Body.String()
	app := do(s, "GET", "/static/app.css", "127.0.0.1:8484", c).Body.String()
	rule := func(css, sel string) string {
		t.Helper()
		m := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(sel) + ` \{([^}]*)\}`).FindStringSubmatch(css)
		if m == nil {
			t.Fatalf("no rule %q", sel)
		}
		return m[1]
	}
	if r := rule(app, ".b-refused"); !strings.Contains(r, "var(--c-stopped)") || !strings.Contains(r, "var(--c-stopped-soft)") {
		t.Errorf(".b-refused is not the stopped tone: %s", r)
	}
	if r := rule(app, ".b-allowed, .b-timedout"); !strings.Contains(r, "var(--c-text2)") || !strings.Contains(r, "transparent") {
		t.Errorf(".b-allowed is not neutral: %s", r)
	}
	if r := rule(app, ".b-lost, .b-halted, .b-broken"); !strings.Contains(r, "var(--c-danger)") {
		t.Errorf("a lost, halted or broken badge is not red: %s", r)
	}
	// A blocked row's edge is neutral: a blocked Low is not "kept safe", so it does not wear the green.
	if r := rule(app, ".tl.v-refused"); !strings.Contains(r, "var(--c-control)") || strings.Contains(r, "stopped") {
		t.Errorf("a blocked timeline row's edge is not neutral: %s", r)
	}
	for name, tk := range map[string]map[string]string{
		"light": tokenBlock(t, tokens, ":root {\n"),
		"auto":  tokenBlock(t, tokens, `:root:not([data-theme="light"]) {`),
		"dark":  tokenBlock(t, tokens, `:root[data-theme="dark"] {`),
	} {
		for _, k := range []string{"stopped", "stopped-soft", "stopped-edge"} {
			if tk[k] == "" {
				t.Fatalf("%s: tokens.css lacks --c-%s", name, k)
			}
		}
		if tk["stopped"] == tk["success"] {
			t.Errorf("%s: the stopped tone %s is the success tone: green means kept safe only", name, tk["stopped"])
		}
		if tk["success"] != tk["text2"] || tk["success-soft"] != tk["sunken"] {
			t.Errorf("%s: the success tone %s/%s is not the neutral grey", name, tk["success"], tk["success-soft"])
		}
		pairs := [][2]string{{"stopped", "stopped-soft"}, {"text2", "surface"}, {"text2", "sunken"}, {"text2", "bg"},
			{"link", "surface"}, {"link", "bg"}, {"link", "sunken"}}
		for _, p := range pairs {
			if r := contrast(tk[p[0]], tk[p[1]]); r < 4.5 {
				t.Errorf("%s: --c-%s on --c-%s is %.2f:1, under AA", name, p[0], p[1], r)
			} else {
				t.Logf("%s: --c-%s on --c-%s is %.2f:1", name, p[0], p[1], r)
			}
		}
	}
}
