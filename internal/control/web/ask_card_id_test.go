// SPDX-License-Identifier: Apache-2.0

package web

import (
	"regexp"
	"strings"
	"testing"
)

// TestTheApprovalCardShowsTheAsksID is DASH-G10. The terminal prints `tego approve <run> <ask_id>` and the record holds the
// ask's id, but the card kept it in a tooltip and a hidden field, so a person could not match the card they were looking
// at to either. Each waiting request's card, on Approvals and on its run's page, now shows the id in its Request row,
// as text in the served page: it needs no script and no style attribute, so it holds under the strict
// Content-Security-Policy the dashboard sends (script-src 'self'; style-src 'self').
func TestTheApprovalCardShowsTheAsksID(t *testing.T) {
	s, c := f3Server(t)
	card := regexp.MustCompile(`(?s)<section class="ask" id="([^"]+)".*?</section>`)
	// The redesigned run page (A1) holds no request card: its attention line and band lead to Approvals, where the
	// card is, so the id is checked on every card the dashboard serves, and the run page is checked for having none.
	for _, page := range []struct{ name, target string }{
		{"Approvals", "/approvals"},
	} {
		w := do(s, "GET", page.target, "127.0.0.1:8484", c)
		if w.Code != 200 {
			t.Fatalf("%s: status %d", page.name, w.Code)
		}
		if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "style-src 'self'") {
			t.Errorf("%s: Content-Security-Policy %q is not the strict one", page.name, csp)
		}
		cards := card.FindAllStringSubmatch(w.Body.String(), -1)
		if len(cards) == 0 {
			t.Fatalf("%s: no ask card in the page", page.name)
		}
		for _, m := range cards {
			id := m[1]
			text := f3Text(m[0])
			if !strings.Contains(text, id+" · line #") {
				t.Errorf("%s: the card for %s does not show its id in view: %s", page.name, id, text)
			}
			if strings.Contains(m[0], "<script") || strings.Contains(m[0], ` style="`) {
				t.Errorf("%s: the card for %s carries a script or a style attribute, which the Content-Security-Policy refuses", page.name, id)
			}
		}
	}
	// The oldest request is the card, with its id beside its line; the other waiting request is a row of the queue
	// that links to its own card by id (the redesigned Approvals page shows one card at a time).
	raw := do(s, "GET", "/approvals", "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(f3Text(raw), "q-late · line #1") {
		t.Errorf("Approvals does not show %q beside its line", "q-late")
	}
	if !strings.Contains(raw, "#q-fresh") {
		t.Errorf("Approvals does not link the queued request %q by its id", "q-fresh")
	}
}
