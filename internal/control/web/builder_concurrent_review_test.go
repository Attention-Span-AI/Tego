// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

// Check reviews B after an editor opened at A. Only a later change to C must
// invalidate that review; the historical A-to-B warning is not a Save guard.
func TestBuilderReviewAfterConcurrentEdit(t *testing.T) {
	for _, kind := range []string{"raw", "structured"} {
		for _, again := range []bool{false, true} {
			condition := "save-reviewed-B"
			if again {
				condition = "refuse-unreviewed-C"
			}
			t.Run(kind+"/"+condition, func(t *testing.T) {
				f := newChangeFix(t)
				c := f.ref(t, f.other)
				target := "/rules/change"
				_, body := f.get(t, target+"?c="+c.Ref+"&view=full")
				editor := builderRenderedEditForm(t, body)
				// Native HTML parsing discards the formatting newline after <textarea>.
				editor.Set("text", strings.TrimPrefix(editor.Get("text"), "\n"))
				if editor.Get("base") != c.Base {
					t.Fatal("editor did not open at A")
				}
				b := readText(t, c.Path) + "\n# outside B\n"
				if err := os.WriteFile(c.Path, []byte(b), 0600); err != nil {
					t.Fatal(err)
				}
				var form url.Values
				if kind == "raw" {
					editor.Set("text", editor.Get("text")+"\n# reviewed edit\n")
					editor.Set("step", "check")
					editor.Set("view", "full")
					w := post(f.s, target, editor, own, "", f.c)
					body = w.Body.String()
					if w.Code != http.StatusOK || !strings.Contains(body, "It compiles.") {
						t.Fatalf("Check B: %d %s", w.Code, body)
					}
					form = builderRenderedEditForm(t, body)
					form.Set("text", strings.TrimPrefix(form.Get("text"), "\n"))
					ack := ackField.FindStringSubmatch(body)
					if ack == nil {
						t.Fatal("Check offered no acknowledgement")
					}
					form.Set("ack", ack[1])
					form.Set("step", "save")
					form.Set("view", "full")
				} else {
					q := url.Values{"c": {c.Ref}, "base": {editor.Get("base")}, "op": {"add"}, "key": {"exec.allow"}, "v": {"/bin/echo"}}
					code, checked := f.get(t, target+"/preview?"+q.Encode())
					body = checked
					if code != http.StatusOK || !strings.Contains(body, "checked as it is now") {
						t.Fatalf("Check B: %d %s", code, body)
					}
					form = builderLostStructuredForm(t, body)
				}
				if form.Get("base") == c.Base || form.Get("base") == "" {
					t.Fatal("Check did not post B as reviewed base")
				}
				if kind == "raw" && !strings.Contains(body, "-# outside B") {
					t.Fatal("Check did not render diff against B")
				}
				expectedDisk := b
				if again {
					expectedDisk = b + "# outside C\n"
					if err := os.WriteFile(c.Path, []byte(expectedDisk), 0600); err != nil {
						t.Fatal(err)
					}
				}
				observed := &builderLostPlans{builderReadPlans: &builderReadPlans{Service: f.svc}}
				f.s.cfg.Rules = observed
				w := post(f.s, target, form, own, "", f.c)
				if observed.calls != 0 {
					t.Fatal("Save rebuilt reviewed proposal")
				}
				if again {
					refused := w.Code == http.StatusConflict || w.Code == http.StatusSeeOther && strings.HasPrefix(w.Header().Get("Location"), "/rules/change/preview?")
					if !refused || readText(t, c.Path) != expectedDisk {
						t.Fatalf("C was not refused without writing: %d %s", w.Code, w.Header().Get("Location"))
					}
				} else {
					if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/rules/change/saved") {
						t.Fatalf("reviewed B refused: status %d location %q stale=%t body %q", w.Code, w.Header().Get("Location"), strings.Contains(w.Body.String(), "changed since"), w.Body.String())
					}
					saved := readText(t, c.Path)
					if kind == "raw" && saved != form.Get("text") {
						t.Fatal("saved bytes differ from reviewed candidate")
					}
					if kind == "structured" && (!strings.Contains(saved, "/bin/echo") || !strings.Contains(saved, "# outside B")) {
						t.Fatal("reviewed structured edit missing")
					}
				}
			})
		}
	}
}
