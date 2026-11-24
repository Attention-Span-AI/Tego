// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Rewrite the feature selector and pseudo-element together to simulate an engine
// that cannot reveal closed details through ::details-content. Native summaries
// must remain available; keyboard activation must still expose the actual body.
func TestNativeDisclosureFallbackInChrome(t *testing.T) {
	const body = `<main><div class="run-content"><details class="run-highlights"><summary>Highlights</summary><p>Full highlights</p></details></div><details class="cmp-details"><summary>Run details and charts</summary><p>Full comparison</p></details><details class="cmp-picker"><summary>Change the runs</summary><p>Complete picker</p></details><details class="iv-question"><summary>How did it get there?</summary><p>Full process context</p></details><details class="iv-facts-detail"><summary>Detection details</summary><p>Complete detection</p></details></main>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/static/") {
			b, err := assets.ReadFile(strings.TrimPrefix(r.URL.Path, "/"))
			if err != nil {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/css")
			fmt.Fprint(w, strings.ReplaceAll(string(b), "::details-content", "::tego-unsupported-details-content"))
			return
		}
		fmt.Fprint(w, `<!doctype html><html><head><meta name="viewport" content="width=device-width, initial-scale=1">`)
		for _, name := range []string{"tokens", "app", "phone", "run", "compare", "evidence"} {
			fmt.Fprintf(w, `<link rel="stylesheet" href="/static/%s.css">`, name)
		}
		fmt.Fprint(w, `</head><body>`+body+`</body></html>`)
	}))
	defer srv.Close()
	c := placeChrome(t)
	tb := sweepTab(t, c, "native-disclosure-fallback", 1280, 900, "light")
	defer c.closeTarget(t, tb.target)
	c.call(t, tb.session, "Page.navigate", map[string]any{"url": srv.URL})
	tb.until(t, "fallback fixture", `document.readyState==='complete'&&document.querySelectorAll('main details').length===5`)
	if tb.eval(t, `CSS.supports('selector(::tego-unsupported-details-content)')`) != "false" {
		t.Fatal("fixture did not simulate an unsupported pseudo-element")
	}
	for _, class := range []string{"run-highlights", "cmp-details", "cmp-picker", "iv-question", "iv-facts-detail"} {
		t.Run(class, func(t *testing.T) {
			sel := fmt.Sprintf("details.%s", class)
			if tb.eval(t, fmt.Sprintf(`(()=>{const d=document.querySelector(%q),s=d.querySelector('summary');return !d.open&&s.checkVisibility()&&getComputedStyle(s).display!=='none'&&s.getBoundingClientRect().height>=24;})()`, sel)) != "true" {
				t.Fatal("closed disclosure lost its native recovery control")
			}
			tb.eval(t, fmt.Sprintf(`document.querySelector(%q).focus();''`, sel+" > summary"))
			tb.press(t, "Enter")
			if tb.eval(t, fmt.Sprintf(`(()=>{const d=document.querySelector(%q);return d.open&&d.querySelector('p').checkVisibility()&&d.querySelector('p').getBoundingClientRect().height>0;})()`, sel)) != "true" {
				t.Error("native keyboard activation did not expose the full disclosure")
			}
		})
	}
}
