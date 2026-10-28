// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
)

// ackField is the acknowledgement checkbox a page renders: its value is the preview's Ack (rules ack.go).
var ackField = regexp.MustCompile(`<input type="checkbox" name="ack" value="([0-9a-f]{64})" required>`)

// ackIn is the first acknowledgement a page offers; the test fails when it offers none.
func ackIn(t *testing.T, page string) string {
	t.Helper()
	m := ackField.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("the page offers no acknowledgement checkbox:\n%s", page)
	}
	return m[1]
}

// TestNoBooleanAckInTemplates: no template posts the old boolean acknowledgement (ackwiden=1, ackfree=1), which any
// form could carry; every acknowledgement checkbox posts its preview's Ack.
func TestNoBooleanAckInTemplates(t *testing.T) {
	es, err := assets.ReadDir("templates")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range es {
		b, err := assets.ReadFile("templates/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"ackwiden", "ackfree", `name="ack" value="1"`} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s holds %q", e.Name(), bad)
			}
		}
	}
}

// TestWideningAckBound: on the event page, a widening confirm with a valid csrf and base and the old ackwiden=1
// writes nothing, a wrong Ack writes nothing, the preview's own Ack writes, and a narrowing writes with no Ack at all.
// Two GETs of the same preview render the same Act panel (the Ack has no nonce or clock), so the live region keeps its
// hash. The inline path (live.js, X-Tego-Inline) carries the Ack the same way.
func TestWideningAckBound(t *testing.T) {
	s, c, contract, _ := askServer(t)
	line := "/runs/" + actRun + "/lines/3"
	preview := do(s, "GET", line+"?a=allow&level=1", "127.0.0.1:8484", c).Body.String()
	again := do(s, "GET", line+"?a=allow&level=1", "127.0.0.1:8484", c).Body.String()
	h1 := regexp.MustCompile(`data-live="r-act" data-h="([^"]+)"`).FindStringSubmatch(preview)
	h2 := regexp.MustCompile(`data-live="r-act" data-h="([^"]+)"`).FindStringSubmatch(again)
	if h1 == nil || h2 == nil || h1[1] != h2[1] {
		t.Errorf("two GETs of one preview: r-act hashes %v and %v", h1, h2)
	}
	ack := ackIn(t, preview)
	if ack != ackIn(t, again) {
		t.Error("two GETs of one preview carry two Acks")
	}
	form := url.Values{"csrf": {s.csrf}, "a": {"allow"}, "level": {"1"}, "base": {baseOf(t, preview)}, "ackwiden": {"1"}}
	notTicked, otherChange := "Not saved · tick", "Not saved · the preview changed"
	for name, tc := range map[string]struct{ ack, line string }{
		"the old ackwiden=1": {"", notTicked}, "a wrong Ack": {strings.Repeat("0", 64), otherChange}, "a short Ack": {ack[:10], otherChange},
	} {
		f := url.Values{}
		for k, vs := range form {
			f[k] = vs
		}
		if tc.ack != "" {
			f.Set("ack", tc.ack)
		}
		mustContain(t, name, follow(t, s, c, post(s, line, f, own, "", c)), tc.line)
		if b, _ := os.ReadFile(contract); string(b) != askContract {
			t.Fatalf("a widening with %s wrote the contract", name)
		}
	}
	// The inline post, as live.js makes it from the form's fields: the ticked checkbox posts the Ack.
	inl := url.Values{"csrf": {s.csrf}, "a": {"allow"}, "level": {"1"}, "base": {baseOf(t, preview)}, "ack": {strings.Repeat("1", 64)}}
	if a := inline(t, s, line, inl, c); a.OK {
		t.Fatalf("an inline widening with a wrong Ack: %+v", a)
	}
	if b, _ := os.ReadFile(contract); string(b) != askContract {
		t.Fatal("an inline widening with a wrong Ack wrote the contract")
	}
	inl.Set("ack", ack)
	a := inline(t, s, line, inl, c)
	if !a.OK || !strings.HasPrefix(a.Text, "Saved:") {
		t.Fatalf("an inline widening with the preview's Ack: %+v", a)
	}
	if b, _ := os.ReadFile(contract); string(b) == askContract {
		t.Fatal("the inline widening with its Ack wrote nothing")
	}
	// Back to the asked contract, then a narrowing (Never allow) with no Ack at all: written.
	if err := os.WriteFile(contract, []byte(askContract), 0o600); err != nil {
		t.Fatal(err)
	}
	never := do(s, "GET", line+"?a=block&level=1", "127.0.0.1:8484", c).Body.String()
	if strings.Contains(never, `name="ack"`) {
		t.Error("a narrowing's preview asks for the acknowledgement")
	}
	w := post(s, line, url.Values{"csrf": {s.csrf}, "a": {"block"}, "level": {"1"}, "base": {baseOf(t, never)}}, own, "", c)
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, line+"?saved=") {
		t.Fatalf("a narrowing with no Ack: %d %q", w.Code, loc)
	}
}
