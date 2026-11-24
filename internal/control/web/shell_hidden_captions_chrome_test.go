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

// Hidden native captions must retain their tiny masked boxes across the card
// breakpoint without changing visible table geometry or its accessible name.
func TestShellHiddenCaptionsInChrome(t *testing.T) {
	_, addr, _ := liveServer(t, logsRuleTitleFixture(t), 10*time.Second, 30*time.Second)
	c := placeChrome(t)
	for _, theme := range []string{"light", "dark"} {
		for _, width := range []int{320, 390, 640, 641, 768, 1280} {
			t.Run(fmt.Sprintf("%s/%d", theme, width), func(t *testing.T) {
				tb := sweepTab(t, c, t.Name(), width, 900, theme)
				defer c.closeTarget(t, tb.target)
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/detections?t=tok123"})
				tb.until(t, "detections captions and font", `document.readyState === 'complete' && document.fonts.status === 'loaded' && !!document.querySelector('.t caption.sr')`)
				geometry := tb.eval(t, `(()=>{
  const captions=[...document.querySelectorAll('.t caption.sr')];
  const boxes=()=>captions.map(e=>{const r=e.closest('table').getBoundingClientRect();return [r.left,r.top,r.width,r.height];});
  const before=boxes();
  const measured=captions.map(e=>{const r=e.getBoundingClientRect(),s=getComputedStyle(e);return {width:r.width,height:r.height,position:s.position,clip:s.clip,clipPath:s.clipPath};});
  const saved=captions.map(e=>e.getAttribute('style'));
  let stable;
  try {
    captions.forEach(e=>e.style.setProperty('padding','0','important'));
    const after=boxes();
    stable=before.every((r,i)=>r.every((value,j)=>Math.abs(value-after[i][j])<=0.25));
  } finally {
    captions.forEach((e,i)=>{if(saved[i]===null)e.removeAttribute('style');else e.setAttribute('style',saved[i]);});
  }
  return {captions:measured,stable};
})()`)
				var measured struct {
					Captions []struct {
						Width, Height            float64
						Position, Clip, ClipPath string
					}
					Stable bool
				}
				if err := json.Unmarshal([]byte(geometry), &measured); err != nil {
					t.Fatal(err)
				}
				if len(measured.Captions) == 0 {
					t.Fatal("fixture has no hidden native table caption")
				}
				for _, caption := range measured.Captions {
					if caption.Width > 2 || caption.Height > 2 {
						t.Errorf("hidden caption has a visible-size layout box: %+v", caption)
					}
					if caption.Position != "absolute" || !strings.Contains(caption.ClipPath, "inset(50%") || caption.Clip != "rect(0px, 0px, 0px, 0px)" {
						t.Errorf("hidden caption lost its positioning or masks: %+v", caption)
					}
				}
				if !measured.Stable {
					t.Errorf("caption padding changes visible table geometry: %s", geometry)
				}
				var ax struct {
					Nodes []struct {
						Ignored bool
						Role    struct{ Value string }
						Name    struct{ Value string }
					}
				}
				if err := json.Unmarshal(c.call(t, tb.session, "Accessibility.getFullAXTree", map[string]any{}), &ax); err != nil {
					t.Fatal(err)
				}
				found := false
				for _, node := range ax.Nodes {
					found = found || (!node.Ignored && node.Role.Value == "table" && node.Name.Value == "Refused actions, High first")
				}
				if !found {
					t.Error("native detections table lost its full caption as its accessible name")
				}
			})
		}
	}
}
