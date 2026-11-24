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
	"time"
)

func TestBuilderHostnameRenderedSaveHTTPJourney(t *testing.T) {
	for _, scope := range []struct {
		list     string
		maxStale bool
	}{{"allow", false}, {"ask", false}, {"allow", true}, {"ask", true}} {
		list := scope.list
		for _, edit := range []bool{false, true} {
			name := list + "/new"
			if edit {
				name = list + "/edit"
			}
			if scope.maxStale {
				name += "/max-stale"
			}
			t.Run(name, func(t *testing.T) {
				f := newChangeFix(t)
				f.s.cfg.Setup = f.svc
				f.svc.Resolver = failHosts{} // The separate preview warning must not use system DNS.
				text := "version: 0\nname: hostname\ncommand: [sh]\nnet:\n  " + list + ": ['api.example:443']\n"
				if scope.maxStale {
					text += "  dns: {max_stale: 30s}\n"
				}
				var target, path string
				var form url.Values
				if edit {
					c := f.ref(t, f.other)
					// The old compiled table also contains a hostname, so both halves of
					// the comparison must survive a later Save compilation.
					if err := os.WriteFile(c.Path, []byte(text), 0600); err != nil {
						t.Fatal(err)
					}
					c = f.ref(t, f.other)
					target, path = "/rules/change", c.Path
					form = url.Values{"csrf": {f.s.csrf}, "builder": {"1"}, "mode": {"raw"}, "c": {c.Ref}, "base": {c.Base}, "text": {text + "\n# reviewed edit\n"}, "view": {"full"}, "current-view": {"full"}, "step": {"check"}}
				} else {
					dir := filepath.Join(filepath.Dir(f.proj), "hostname-new")
					if err := os.Mkdir(dir, 0700); err != nil {
						t.Fatal(err)
					}
					target, path = "/rules/new", filepath.Join(dir, "agent.yaml")
					form = url.Values{"csrf": {f.s.csrf}, "builder": {"1"}, "mode": {"blank"}, "dir": {dir}, "name": {"hostname"}, "to": {"project"}, "text": {text}, "view": {"full"}, "current-view": {"full"}, "step": {"preview"}}
				}
				w := post(f.s, target, form, own, "", f.c)
				if w.Code != http.StatusOK {
					t.Fatalf("preview: %d %s", w.Code, w.Body.String())
				}
				previewCompleted := time.Now()
				body := w.Body.String()
				if edit {
					form = builderRenderedEditForm(t, body)
					// HTML textarea parsing discards the first line break after its tag.
					form.Set("text", strings.TrimPrefix(form.Get("text"), "\n"))
					// A person checks the rendered acknowledgement before pressing Save.
					ack := regexp.MustCompile(`name="ack" value="([^"]+)"`).FindStringSubmatch(body)
					if ack == nil {
						t.Fatal("no rendered edit acknowledgement")
					}
					form.Set("ack", html.UnescapeString(ack[1]))
					form.Set("step", "save")
				} else {
					form = builderRenderedSaveForm(t, body)
				}
				if !time.Now().After(previewCompleted) {
					t.Fatal("wall clock did not advance between Preview and Save")
				}
				w = post(f.s, target, form, own, "", f.c)
				if w.Code != http.StatusSeeOther {
					t.Fatalf("Save after clock advance: status %d, want %d", w.Code, http.StatusSeeOther)
				}
				saved, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(saved), "api.example:443") || !strings.Contains(string(saved), list+":") {
					t.Fatalf("saved hostname %s rule was lost: %s", list, saved)
				}
			})
		}
	}
}
