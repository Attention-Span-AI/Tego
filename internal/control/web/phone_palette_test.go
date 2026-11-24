// SPDX-License-Identifier: Apache-2.0

package web

import (
	"regexp"
	"strings"
	"testing"
)

// These are the actual foreground/background roles used by the shared shell.
// Every changed semantic pair keeps its numeric minimum, including borders.
func TestPhonePaletteContrast(t *testing.T) {
	b, err := assets.ReadFile("static/tokens.css")
	if err != nil {
		t.Fatal(err)
	}
	for theme, marker := range map[string]string{"light": ":root {\n", "dark": `:root[data-theme="dark"] {`} {
		tk := tokenBlock(t, string(b), marker)
		block := strings.SplitN(strings.SplitN(string(b), marker, 2)[1], "}", 2)[0]
		for _, m := range regexp.MustCompile(`--ch-([a-z-]+): (#[A-Fa-f0-9]{6});`).FindAllStringSubmatch(block, -1) {
			tk["ch-"+m[1]] = m[2]
		}
		for _, p := range []struct {
			fg, bg string
			min    float64
		}{
			{"text", "bg", 4.5}, {"text", "surface", 4.5}, {"text", "raised", 4.5},
			{"text2", "raised", 4.5}, {"text3", "raised", 4.5}, {"control", "raised", 3},
			{"control", "surface", 3}, {"control", "ask-soft", 3}, {"on-brand", "brand", 4.5},
			{"on-primary", "primary", 4.5}, {"on-primary", "primary-hover", 4.5},
			{"on-ask", "ask", 4.5}, {"ask-text", "ask-soft", 4.5}, {"ask", "ask-soft", 3},
			{"refused", "refused-soft", 4.5}, {"on-through", "through", 4.5},
			{"allowed", "raised", 4.5}, {"passed", "raised", 4.5}, {"info", "raised", 4.5},
			{"ch-stop", "surface", 3}, {"ch-through", "surface", 3}, {"ch-ink", "surface", 3}, {"ch-allowed", "surface", 3},
			{"text", "select", 4.5}, {"text", "sunken-2", 4.5}, {"control", "bg", 3},
			{"focus", "raised", 3}, {"text", "ask-soft", 4.5}, {"on-ask-bar", "ask-bar", 4.5},
		} {
			if tk[p.fg] == "" || tk[p.bg] == "" {
				t.Fatalf("%s missing %s/%s", theme, p.fg, p.bg)
			}
			r := contrast(tk[p.fg], tk[p.bg])
			t.Logf("%s %s/%s %.2f:1", theme, p.fg, p.bg, r)
			if r < p.min {
				t.Errorf("%s %s/%s %.2f < %.1f", theme, p.fg, p.bg, r, p.min)
			}
		}
	}
}

// Historical asks are not evidence that a person can still answer them.
func TestOrangeOnlyForPendingRequests(t *testing.T) {
	b, err := assets.ReadFile("static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`(?m)^([^{}]+)\{([^{}]*)\}`).FindAllStringSubmatch(string(b), -1) {
		for _, hook := range []string{".v-asked", ".is-ask", ".b-asked"} {
			if strings.Contains(m[1], hook) && (strings.Contains(m[2], "var(--c-ask)") || strings.Contains(m[2], "var(--c-ask-soft)")) {
				t.Errorf("historical hook %s uses waiting orange: %s", hook, m[0])
			}
		}
	}
}
