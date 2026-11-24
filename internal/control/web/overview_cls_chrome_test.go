// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"os"
	"sort"
	"strconv"
	"testing"
	"time"
)

// clsObserver records every layout shift without recent input, with the nodes that moved, from the first byte.
const clsObserver = `window.__cls=0;window.__clsSrc=[];try{new PerformanceObserver(l=>{for(const e of l.getEntries())if(!e.hadRecentInput){window.__cls+=e.value;window.__clsSrc.push(e.value.toFixed(4)+' @'+Math.round(e.startTime)+' '+e.sources.map(x=>x.node?(x.node.nodeType===1?x.node.tagName+'.'+x.node.className+(x.node.id?'#'+x.node.id:''):'#text '+(x.node.textContent||'').trim().slice(0,24)):'?').join(' + '))}}).observe({type:'layout-shift',buffered:true})}catch(e){}`

// TestOverviewLayoutShiftInChrome loads the Overview TEGO_CLS_LOADS times (default 5) at 1280 px, light, over a ledger with a
// live run and a waiting request, and fails when the median cumulative layout shift of a load passes
// TEGO_CLS_MAX (default 0.01). Every load's score and the nodes that moved are logged (go test -v). TEGO_CLS_WAIT
// (milliseconds, default 2500) is how long each load is watched after its first paint: the one late sample on record
// (C79) was at 3382 ms, past the default, so a hunt for it sets 6000 or more.
func TestOverviewLayoutShiftInChrome(t *testing.T) {
	loads, limit := 5, 0.01
	if v, err := strconv.Atoi(os.Getenv("TEGO_CLS_LOADS")); err == nil && v > 0 {
		loads = v
	}
	if v, err := strconv.ParseFloat(os.Getenv("TEGO_CLS_MAX"), 64); err == nil {
		limit = v
	}
	throttle, _ := strconv.Atoi(os.Getenv("TEGO_CLS_THROTTLE")) // CPU slowdown factor: a slow machine's late font, script and region timing
	wait := 2500 * time.Millisecond
	if v, err := strconv.Atoi(os.Getenv("TEGO_CLS_WAIT")); err == nil && v > 0 {
		wait = time.Duration(v) * time.Millisecond
	}
	move := os.Getenv("TEGO_CLS_MOVE") != "" // a run's line arrives a second after the load, as a live run's do
	root := fixture(t)
	_, addr, _ := liveServer(t, root, 10*time.Second, 30*time.Second)
	c := b11Browser(t)
	var scores []float64
	for i := 0; i < loads; i++ {
		tb := c.open(t, "cls", "about:blank")
		c.call(t, tb.session, "Runtime.enable", map[string]any{})
		c.call(t, tb.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 1280, "height": 800, "deviceScaleFactor": 1, "mobile": false})
		c.call(t, tb.session, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{{"name": "prefers-color-scheme", "value": "light"}}})
		if throttle > 1 {
			c.call(t, tb.session, "Emulation.setCPUThrottlingRate", map[string]any{"rate": throttle})
		}
		c.call(t, tb.session, "Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": clsObserver})
		c.call(t, tb.session, "Page.navigate", map[string]any{"url": "http://" + addr + "/?t=tok123"})
		tb.until(t, "loaded", `document.readyState === "complete" && document.body.innerText.includes("Overview")`)
		if move {
			time.Sleep(1000 * time.Millisecond)
			appendLine(t, root, harmRun, line(harmRun, "demo-harm", 50+i, time.Now(), "exec", `"target":"/usr/bin/true","verdict":"allow"`))
		}
		time.Sleep(wait) // the stream's first state, the clocks and the regions' first refresh
		score, _ := strconv.ParseFloat(tb.eval(t, `window.__cls`), 64)
		t.Logf("load %d: CLS %.6f sources %s", i+1, score, tb.eval(t, `JSON.stringify(window.__clsSrc)`))
		scores = append(scores, score)
		c.closeTarget(t, tb.target)
	}
	sort.Float64s(scores)
	med := scores[len(scores)/2]
	t.Logf("median CLS %.6f over %d loads", med, loads)
	if med > limit {
		t.Errorf("Overview median CLS %.6f passes %.4f", med, limit)
	}
}
