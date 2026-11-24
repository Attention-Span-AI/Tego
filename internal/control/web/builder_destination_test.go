// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestBuilderProjectSaveRetainsReviewedDestination(t *testing.T) {
	for _, mode := range []string{"presets", "blank"} {
		t.Run(mode, func(t *testing.T) {
			f := newRulesFix(t)
			reg := f.withRegistry(t)
			dir := filepath.Join(filepath.Dir(f.proj), "project-save")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			q := url.Values{"mode": {mode}, "dir": {dir}, "name": {"project-save"}, "cmd": {"/bin/sh"}, "to": {"project"}, "preview": {"1"}}
			if mode == "presets" {
				q.Set("preset", "no-secrets")
			}
			code, body := f.get(t, "/rules/new?"+q.Encode())
			if code != http.StatusOK {
				t.Fatalf("preview: %d %s", code, body)
			}
			form := builderRenderedSaveForm(t, body)
			if form.Get("to") != "project" {
				t.Errorf("reviewed project destination missing from Save: %v", form["to"])
			}
			w := post(f.s, "/rules/new", form, own, "", f.c)
			if w.Code != http.StatusSeeOther {
				t.Fatalf("save: %d %s", w.Code, w.Body.String())
			}
			if _, err := os.Stat(filepath.Join(dir, "agent.yaml")); err != nil {
				t.Errorf("reviewed project file was not written: %v", err)
			}
			if _, err := os.Stat(filepath.Join(reg, "agents", "project-save.yaml")); !os.IsNotExist(err) {
				t.Errorf("unreviewed registry destination was written or unreadable: %v", err)
			}
		})
	}
}

// Post the values the server actually rendered, so losing a hidden field cannot
// be masked by a test that reconstructs the intended request itself.
func builderRenderedSaveForm(t *testing.T, body string) url.Values {
	t.Helper()
	_, part, ok := strings.Cut(body, `id="builder-save"`)
	if !ok {
		t.Fatal("no Save section")
	}
	_, part, ok = strings.Cut(part, "<form ")
	if !ok {
		t.Fatal("no Save form")
	}
	part, _, ok = strings.Cut(part, "</form>")
	if !ok {
		t.Fatal("unclosed Save form")
	}
	form := make(url.Values)
	for _, field := range regexp.MustCompile(`name="([^"]+)" value="([^"]*)"`).FindAllStringSubmatch(part, -1) {
		form.Add(field[1], html.UnescapeString(field[2]))
	}
	for _, field := range regexp.MustCompile(`(?s)<textarea name="([^"]+)"[^>]*>(.*?)</textarea>`).FindAllStringSubmatch(part, -1) {
		form.Add(field[1], html.UnescapeString(field[2]))
	}
	return form
}
