// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"fmt"
	"testing"
	"time"
)

// Equal shrinking columns can split short action words without clipping them.
// Measure the actual text fragments, not just the buttons' overflow dimensions. Both checks (a label is one fragment
// inside its button, the page has no sideways scroll) are facts of any font, so no font is assumed: the runner image
// paints in DejaVu Sans, about a tenth wider than the Noto Sans the layout was drawn in.
func TestAskBandButtonLabelsInChrome(t *testing.T) {
	_, addr, _ := liveServer(t, fixture(t), 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	for _, width := range []int{320, 360, 390, 768, 860, 861, 1280} {
		for _, theme := range []string{"light", "dark"} {
			for _, path := range []string{"/", "/runs"} {
				t.Run(fmt.Sprintf("%d/%s/%s", width, theme, path), func(t *testing.T) {
					tb := sweepTab(t, c, t.Name(), width, 800, theme)
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + path + "?t=tok123"})
					tb.until(t, "request controls and font", `document.readyState === 'complete' && document.fonts.status === 'loaded' && document.querySelectorAll('#ask-banner .ab-act .btn').length === 3`)
					if got := tb.eval(t, `JSON.stringify(Array.from(document.querySelectorAll('#ask-banner .ab-act .btn')).flatMap(b=>{const out=[],w=document.createTreeWalker(b,NodeFilter.SHOW_TEXT),box=b.getBoundingClientRect();let n;while(n=w.nextNode()){if(!n.textContent.trim())continue;const r=document.createRange();r.selectNodeContents(n);const rs=Array.from(r.getClientRects()).filter(x=>x.width&&x.height);if(rs.length!==1||rs.some(x=>x.left<box.left-1||x.right>box.right+1||x.top<box.top-1||x.bottom>box.bottom+1))out.push({text:n.textContent,fragments:rs.length,buttonWidth:box.width});}return out;}))`); got != `"[]"` {
						t.Errorf("request action label breaks or escapes its button: %s", got)
					}
					// A fact of any font: the page does not scroll sideways at this width (a column too narrow for its label
					// pushes the grid out of the window).
					if tb.eval(t, `document.documentElement.scrollWidth <= innerWidth`) != "true" {
						t.Errorf("the page scrolls sideways at %d px", width)
					}
					c.closeTarget(t, tb.target)
				})
			}
		}
	}
}
