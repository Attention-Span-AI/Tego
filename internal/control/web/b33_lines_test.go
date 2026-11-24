// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// C126: both raw editors carry the line-number marker and load the script that reads it, the Check's diagnostic lines
// link into the editor, and the page works as before without the script (the diagnostic's own context lines stay).
func TestRawEditorsOfferLineNumbers(t *testing.T) {
	f := newChangeFix(t)
	ref := f.ref(t, f.source).Ref
	_, body := f.get(t, "/rules/change?c="+ref+"&raw=1&view=full")
	for _, want := range []string{`id="yaml-text"`, ` data-lines`, `/static/lines.js`} {
		if !strings.Contains(body, want) {
			t.Errorf("the Change rules editor lacks %q", want)
		}
	}
	code, bad := f.post(t, "/rules/change?c="+ref+"#yaml", url.Values{"mode": {"raw"}, "builder": {"1"}, "current-view": {"full"}, "c": {ref},
		"step": {"check"}, "view": {"full"}, "text": {"version: 0\nname: x\ncommand: [sh\n"}})
	if code != 200 {
		t.Fatalf("check: %d", code)
	}
	if !strings.Contains(bad, `data-goto-line="`) || !strings.Contains(bad, `data-goto-for="yaml-text"`) || !strings.Contains(bad, `id="yl-`) {
		t.Errorf("a diagnostic's line must link into the editor and keep its context lines:\n%s", bad)
	}
	if i := strings.Index(bad, `data-goto-line="`); i >= 0 {
		rest := bad[i+len(`data-goto-line="`):]
		n := rest[:strings.Index(rest, `"`)]
		if !strings.Contains(bad, `href="#yl-`+n+`"`) {
			t.Errorf("the link for line %s must still point at its context line without the script", n)
		}
	}
	// The builder's own Full editor takes the same marker and script.
	f.s.cfg.Setup = f.svc
	dir := filepath.Join(f.proj, "lines-new")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	w := post(f.s, "/rules/new", url.Values{"csrf": {f.s.csrf}, "builder": {"1"}, "step": {"preview"}, "mode": {"blank"}, "dir": {dir}, "name": {"lines-new"},
		"to": {"project"}, "view": {"full"}, "current-view": {"full"}, "text": {"version: 0\nname: lines-new\ncommand: [/bin/sh]\n"}}, own, "", f.c)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `id="builder-text"`) || !strings.Contains(w.Body.String(), "data-lines") || !strings.Contains(w.Body.String(), "/static/lines.js") {
		t.Errorf("the new-contract Full editor lacks the line numbers: %d", w.Code)
	}
	if _, err := assets.ReadFile("static/lines.js"); err != nil {
		t.Errorf("static/lines.js is not served: %v", err)
	}
}
