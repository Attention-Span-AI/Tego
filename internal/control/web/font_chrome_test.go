// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"encoding/json"
	"sort"
	"testing"
)

// paintedFonts names the fonts Chrome painted the text of every element matching selector with (the DevTools
// CSS.getPlatformFontsForNode answer, which is per element and only for the text that element holds itself, so a
// sentence whose target sits in a nested monospace span needs each span asked), most glyphs first, each family once.
// It is what the person's screen used, not what the stylesheet asked for: system-ui resolves to whichever sans the host
// has, and the monospace stack to the first of its families the host has.
func paintedFonts(t *testing.T, tb *tab, selector string) []string {
	t.Helper()
	tb.c.call(t, tb.session, "DOM.enable", map[string]any{})
	tb.c.call(t, tb.session, "CSS.enable", map[string]any{})
	var doc struct{ Root struct{ NodeID int } }
	if err := json.Unmarshal(tb.c.call(t, tb.session, "DOM.getDocument", map[string]any{"depth": 0}), &doc); err != nil {
		t.Fatal(err)
	}
	var found struct{ NodeIDs []int }
	if err := json.Unmarshal(tb.c.call(t, tb.session, "DOM.querySelectorAll", map[string]any{"nodeId": doc.Root.NodeID, "selector": selector}), &found); err != nil {
		t.Fatal(err)
	}
	if len(found.NodeIDs) == 0 {
		t.Fatalf("no element matches %q to read its fonts from", selector)
	}
	glyphs := map[string]int{}
	for _, id := range found.NodeIDs {
		var fonts struct {
			Fonts []struct {
				FamilyName string
				GlyphCount int
			}
		}
		if err := json.Unmarshal(tb.c.call(t, tb.session, "CSS.getPlatformFontsForNode", map[string]any{"nodeId": id}), &fonts); err != nil {
			t.Fatal(err)
		}
		for _, f := range fonts.Fonts {
			glyphs[f.FamilyName] += f.GlyphCount
		}
	}
	var out []string
	for name := range glyphs {
		out = append(out, name)
	}
	sort.Slice(out, func(i, j int) bool {
		if glyphs[out[i]] != glyphs[out[j]] {
			return glyphs[out[i]] > glyphs[out[j]]
		}
		return out[i] < out[j]
	})
	return out
}

// onlyFonts reports whether every font in fonts is one of the families. ADR 0123's pixel bounds (lines of a request
// sentence, widths of action labels) were measured on pages painted in two families, a sans for the words and a
// monospace for the target, and in others (DejaVu Sans is about a tenth wider than Noto Sans, DejaVu Sans Mono about a
// tenth wider than Ubuntu Sans Mono) a test holds the facts that are true in any font and reports which fonts it saw, so
// it neither fails nor passes because of the font.
func onlyFonts(fonts []string, families ...string) bool {
	if len(fonts) == 0 {
		return false
	}
	for _, f := range fonts {
		ok := false
		for _, want := range families {
			ok = ok || f == want
		}
		if !ok {
			return false
		}
	}
	return true
}
