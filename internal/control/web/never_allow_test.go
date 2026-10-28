// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// TestActLandsOnCheck: every link that picks an action lands on its step 3 (#act-check), the one
// element of the panel that carries that id, so "Check the change" and Confirm come into view in the sticky aside;
// the Deny notice's "Make it permanent" redirect and a not-saved confirm land there too.
func TestActLandsOnCheck(t *testing.T) {
	s, c, _, _ := askServer(t)
	line := "/runs/" + actRun + "/lines/3"

	page := do(s, "GET", line, "127.0.0.1:8484", c).Body.String()
	acts := regexp.MustCompile(`href="`+regexp.QuoteMeta(line)+`\?a=(block|ask|allow)&amp;[^"]*"`).FindAllString(page, -1)
	if len(acts) == 0 {
		t.Fatal("the line page shows no action link")
	}
	for _, a := range acts {
		if !strings.HasSuffix(a, `#act-check"`) {
			t.Errorf("an action link lands elsewhere: %s", a)
		}
	}
	if strings.Contains(page, `id="act-check"`) {
		t.Error("the page with no action picked carries #act-check")
	}

	preview := do(s, "GET", line+"?a=block&level=1", "127.0.0.1:8484", c).Body.String()
	if n := strings.Count(preview, `id="act-check"`); n != 1 {
		t.Fatalf("the preview carries id=\"act-check\" %d times, want 1", n)
	}
	if !strings.Contains(preview, `<div class="panel-body stack-sm ev-confirm" id="act-check">`) {
		t.Error("#act-check is not on the step-3 block")
	}
	// With an action picked a scope chip keeps it and lands on step 3; Cancel and the form go back to #act.
	if !regexp.MustCompile(`class="chip[^"]*" href="` + regexp.QuoteMeta(line) + `\?level=\d&amp;a=block#act-check"`).MatchString(preview) {
		t.Error("a scope chip with Never allow picked does not land on #act-check")
	}
	mustContain(t, "the preview", preview, `action="`+line+`#act"`, `?level=1#act">Cancel</a>`)

	r := do(s, "GET", "/runs/"+actRun+"/lines/1?decided=1", "127.0.0.1:8484", c)
	if r.Code != http.StatusSeeOther || r.Header().Get("Location") != line+"?a=block#act-check" {
		t.Errorf("Make it permanent: %d %q", r.Code, r.Header().Get("Location"))
	}
}

// TestNeverAllowReopened: after Never allow is confirmed, the same preview opened again (a reload, a
// second tab) says calmly, in the panel's short paths, that the read is already never allowed, on the one #act-check
// element, with no red alert and no "profile" wording.
func TestNeverAllowReopened(t *testing.T) {
	s, c, _, proj := askServer(t)
	line := "/runs/" + actRun + "/lines/3"
	preview := do(s, "GET", line+"?a=block&level=1", "127.0.0.1:8484", c).Body.String()
	form := url.Values{"csrf": {s.csrf}, "a": {"block"}, "level": {"1"}, "base": {baseOf(t, preview)}}
	if loc := post(s, line, form, own, "", c).Header().Get("Location"); !strings.HasPrefix(loc, line+"?saved=") {
		t.Fatalf("confirm returned to %q", loc)
	}

	again := do(s, "GET", line+"?a=block&level=1", "127.0.0.1:8484", c).Body.String()
	panel := again[strings.Index(again, `id="act"`):]
	if strings.Contains(panel, "banner-danger") || strings.Contains(panel, `role="alert"`) {
		t.Errorf("the reopened preview shows a red alert:\n%s", panel)
	}
	const calm = `<div class="banner" role="status" id="act-check">`
	i := strings.Index(panel, calm)
	if i < 0 {
		t.Fatalf("the reopened preview has no calm banner on #act-check:\n%s", panel)
	}
	banner := panel[i : i+strings.Index(panel[i:], "</div></div>")]
	if !strings.Contains(banner, "reads of files under ./vault/ are already never allowed") || strings.Contains(banner, "profile") ||
		strings.Contains(banner, proj) {
		t.Errorf("the reopened preview's banner: %s", banner)
	}
	if n := strings.Count(again, `id="act-check"`); n != 1 {
		t.Errorf("the reopened preview carries id=\"act-check\" %d times, want 1", n)
	}
	if strings.Contains(panel, "Confirm: never allow") {
		t.Error("the reopened preview offers the change again")
	}
}
