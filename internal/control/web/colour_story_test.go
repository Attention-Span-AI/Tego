// SPDX-License-Identifier: Apache-2.0

package web

import (
	"regexp"
	"strings"
	"testing"
)

// TestColourStory pins the phone amendment at every width: orange waiting,
// dashed red Refused, filled red Read allowed, and neutral routine states.
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
	if r := rule(app, ".b-refused"); !strings.Contains(r, "var(--c-stopped)") || !strings.Contains(r, "var(--c-stopped-soft)") || !strings.Contains(r, "border-style: dashed") {
		t.Errorf(".b-refused is not the stopped tone: %s", r)
	}
	if r := rule(app, ".b-allowed, .b-timedout"); !strings.Contains(r, "var(--c-text2)") || !strings.Contains(r, "transparent") {
		t.Errorf(".b-allowed is not neutral: %s", r)
	}
	if r := rule(app, ".b-lost, .b-broken"); !strings.Contains(r, "var(--c-danger)") {
		t.Errorf("a lost or broken badge is not crimson: %s", r)
	}
	if r := rule(app, ".b-halted"); strings.Contains(r, "danger") || strings.Contains(r, "through") || strings.Contains(r, "stopped") {
		t.Errorf("a run that exited non-zero is drawn as an alarm or a refusal: %s", r)
	}
	if r := rule(app, ".b-waiting"); !strings.Contains(r, "var(--c-ask)") || !strings.Contains(r, "var(--c-on-ask)") {
		t.Errorf("a waiting request is not the orange waiting chip: %s", r)
	}
	// A refused row retains its decision color whatever its severity.
	if r := rule(app, ".tl.v-refused"); !strings.Contains(r, "var(--c-refused-edge)") || strings.Contains(r, "danger") || strings.Contains(r, "through") {
		t.Errorf("a refused timeline row's edge is not the refusal's: %s", r)
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
			t.Errorf("%s: the stopped tone %s is the success tone: the refusal's colour means a refusal only", name, tk["stopped"])
		}
		if tk["stopped"] != tk["danger"] || tk["refused"] != tk["stopped"] || tk["through"] != tk["danger"] {
			t.Errorf("%s: refused %s/%s and went through %s/%s do not share the red decision tone and aliases", name, tk["refused"], tk["stopped"], tk["through"], tk["danger"])
		}
		if tk["link"] != tk["text"] {
			t.Errorf("%s: the link %s is not the ink %s: a link is ink with an underline", name, tk["link"], tk["text"])
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
