// SPDX-License-Identifier: Apache-2.0

//go:build chrome

package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/contractsrc"
	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestGeneralSourceInChrome audits the actual read-only templates and assets with
// modeled trusted source facts; filesystem ownership is tested by config separately.
func TestGeneralSourceInChrome(t *testing.T) {
	s, _, _ := generalServer(t)
	g := contractsrc.General{State: "loaded", Scope: "Your agents on this machine", Name: strings.Repeat("long-agent-", 25), Hash: strings.Repeat("a", 64), Note: contractsrc.LoadedNote,
		Sources: []contractsrc.Source{{Layer: "system", State: config.LayerAbsent}, {Layer: "user", Path: "/home/" + strings.Repeat("long-folder-", 35) + "/.tego/general.yaml", State: config.LayerPresent, SHA256: strings.Repeat("b", 64)}}, Profiles: []contractsrc.Profile{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/static/") {
			s.static.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Security-Policy", csp)
		shown := g
		if state := r.URL.Query().Get("state"); state != "" && state != "loaded" {
			shown.State = state
			shown.Hash = ""
			shown.Note = "General contract " + state + ": source needs review"
		}
		s.render(w, http.StatusOK, "rules", s.chromeOf(&ledgerview.Snapshot{}, "Contracts", "rules"), rulesData{General: &shown, BaselineState: "Configured entries are NOT YET APPLIED to runs."})
	}))
	t.Cleanup(srv.Close)
	c := placeChrome(t)
	tb := c.open(t, "general contracts", srv.URL+"/rules")
	for _, state := range []string{"loaded", "absent", "invalid", "unknown"} {
		for _, width := range []int{1280, 390, 320} {
			for _, scheme := range []string{"light", "dark"} {
				for _, scripts := range []bool{true, false} {
					name := fmt.Sprintf("%s/%d/%s/scripts=%v", state, width, scheme, scripts)
					c.call(t, tb.session, "Emulation.setDeviceMetricsOverride", map[string]any{"width": width, "height": 900, "deviceScaleFactor": 1, "mobile": width < 600})
					c.call(t, tb.session, "Emulation.setEmulatedMedia", map[string]any{"features": []map[string]string{{"name": "prefers-color-scheme", "value": scheme}}})
					c.call(t, tb.session, "Emulation.setScriptExecutionDisabled", map[string]any{"value": !scripts})
					target := srv.URL + "/rules?state=" + state + "&case=" + url.QueryEscape(name)
					c.call(t, tb.session, "Page.navigate", map[string]any{"url": target})
					tb.until(t, name, `location.href === `+strconv.Quote(target)+` && document.readyState === 'complete' && document.fonts.status === 'loaded' && document.querySelector('.general-contract') !== null`)
					// Expand decisive provenance with the browser's normal details element.
					tb.eval(t, `document.querySelector('.general-contract details').open=true`)
					if got := tb.eval(t, `document.documentElement.scrollWidth <= window.innerWidth`); got != "true" {
						t.Errorf("%s: horizontal scroll", name)
					}
					if got := tb.eval(t, `!!(document.querySelector('#h-general').compareDocumentPosition(document.querySelector('#h-general-baseline')) & Node.DOCUMENT_POSITION_FOLLOWING)`); got != "true" {
						t.Errorf("%s: baseline precedes general", name)
					}
					if got := tb.eval(t, `document.querySelector('.general-contract').innerText.includes('`+shownStateWord(state)+`')`); got != "true" {
						t.Errorf("%s: wrong state", name)
					}
					if got := tb.eval(t, `document.querySelector('.general-contract summary').getBoundingClientRect().height >= 30`); got != "true" {
						t.Errorf("%s: provenance control collapsed", name)
					}
				}
			}
		}
	}
}

func shownStateWord(state string) string {
	if state == "loaded" {
		return contractsrc.LoadedNote
	}
	return "General contract " + state
}
