// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// TestNumberMarkersKeepTheirSpaceInChrome: a number's marker (numbers.go) must not change how its words read. In a
// flex container a span with a box of its own becomes a flex item and the space after the number collapses
// ("1running now"); every bare marker therefore makes no box. The test measures, on real pages at phone and desktop
// widths, the rendered gap between a marked number and the word beside it on the same line.
func TestNumberMarkersKeepTheirSpaceInChrome(t *testing.T) {
	const probe = `(()=>{let bad=[],n=0;
const at=(node,i)=>{const r=document.createRange();r.setStart(node,i);r.setEnd(node,i+1);return r.getBoundingClientRect();};
for(const m of document.querySelectorAll('span[data-number]:not([class])')){
 const t=m.firstChild;if(!t||t.nodeType!==3||!t.data.trim())continue;
 const nx=m.nextSibling,pv=m.previousSibling;
 if(nx&&nx.nodeType===3&&/^\s+\S/.test(nx.data)){const a=at(t,t.data.replace(/\s+$/,'').length-1),b=at(nx,nx.data.search(/\S/));
  if(a.width&&b.width&&Math.abs(a.top-b.top)<2){n++;if(b.left-a.right<2)bad.push(m.dataset.number+' "'+t.data+'|'+nx.data.slice(0,14)+'"');}}
 if(pv&&pv.nodeType===3&&/\S\s+$/.test(pv.data)){const a=at(pv,pv.data.replace(/\s+$/,'').length-1),b=at(t,t.data.search(/\S/));
  if(a.width&&b.width&&Math.abs(a.top-b.top)<2){n++;if(b.left-a.right<2)bad.push(m.dataset.number+' "'+pv.data.slice(-14)+'|'+t.data+'"');}}
}
return JSON.stringify({n,bad:bad.slice(0,8)});})()`
	c := placeChrome(t)
	_, addr, _ := liveServer(t, numberLedger(t), 10*time.Second, 30*time.Second)
	checked := 0
	for _, width := range []int{360, 1280} {
		for _, path := range []string{"/", "/runs", "/runs/" + numRichRun, "/runs/" + numRichRun + "/receipt", "/logs", "/logs?group=rule", "/detections", "/approvals?tab=history", "/rules?run=" + numRichRun} {
			t.Run(fmt.Sprintf("%d%s", width, path), func(t *testing.T) {
				tb := sweepTab(t, c, t.Name(), width, 900, "light")
				defer c.closeTarget(t, tb.target)
				c.call(t, tb.session, "Page.navigate", map[string]any{"url": a1URL(addr, path)})
				tb.until(t, "page", `document.readyState==='complete' && document.fonts.status==='loaded' && !!document.querySelector('main')`)
				var got struct {
					N   int
					Bad []string
				}
				raw := tb.eval(t, probe)
				var text string
				if err := json.Unmarshal([]byte(raw), &text); err == nil {
					raw = text
				}
				if err := json.Unmarshal([]byte(raw), &got); err != nil {
					t.Fatal(err)
				}
				checked += got.N
				for _, b := range got.Bad {
					t.Errorf("a marked number touches its word: %s", b)
				}
			})
		}
	}
	if checked < 20 {
		t.Errorf("only %d number and word pairs measured", checked)
	}
}
