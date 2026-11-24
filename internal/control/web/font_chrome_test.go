// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"encoding/json"
	"sort"
	"testing"
)

// platformFonts names the fonts Chrome painted the text of the first element matching selector with (the DevTools
// CSS.getPlatformFontsForNode answer), in the order of the glyphs each one drew, most first. It is what the person's
// screen used, not what the stylesheet asked for: system-ui resolves to whichever sans the host has.
func platformFonts(t *testing.T, tb *tab, selector string) []string {
	t.Helper()
	tb.c.call(t, tb.session, "DOM.enable", map[string]any{})
	tb.c.call(t, tb.session, "CSS.enable", map[string]any{})
	var doc struct{ Root struct{ NodeID int } }
	if err := json.Unmarshal(tb.c.call(t, tb.session, "DOM.getDocument", map[string]any{"depth": 0}), &doc); err != nil {
		t.Fatal(err)
	}
	var found struct{ NodeID int }
	if err := json.Unmarshal(tb.c.call(t, tb.session, "DOM.querySelector", map[string]any{"nodeId": doc.Root.NodeID, "selector": selector}), &found); err != nil {
		t.Fatal(err)
	}
	if found.NodeID == 0 {
		t.Fatalf("no element matches %q to read its font from", selector)
	}
	var fonts struct {
		Fonts []struct {
			FamilyName string
			GlyphCount int
		}
	}
	if err := json.Unmarshal(tb.c.call(t, tb.session, "CSS.getPlatformFontsForNode", map[string]any{"nodeId": found.NodeID}), &fonts); err != nil {
		t.Fatal(err)
	}
	sort.SliceStable(fonts.Fonts, func(i, j int) bool { return fonts.Fonts[i].GlyphCount > fonts.Fonts[j].GlyphCount })
	var out []string
	for _, f := range fonts.Fonts {
		out = append(out, f.FamilyName)
	}
	return out
}

// inFont reports whether the font that painted most of the text (the first of fonts, as platformFonts orders them) is
// family. It is what a bound measured in one font checks before it is asserted: ADR 0123's pixel bounds (lines of a
// request sentence, widths of action labels) were measured in Noto Sans, and in another font (a host with DejaVu Sans
// alone is about a tenth wider) a test holds the facts that are true in any font and reports which font it saw, so it
// neither fails nor passes because of the font.
func inFont(fonts []string, family string) bool {
	return len(fonts) > 0 && fonts[0] == family
}
