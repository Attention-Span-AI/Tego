// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// Raw Full already protects the textarea's formatting LF. Switching through
// Simple must preserve the same reviewed bytes in its hidden textarea too.
func TestBuilderRawLeadingNewlinesSurviveRenderedForms(t *testing.T) {
	for _, leading := range []int{0, 1, 2} {
		t.Run(fmt.Sprintf("leading-%d", leading), func(t *testing.T) {
			f := newChangeFix(t)
			c := f.ref(t, f.other)
			before := strings.Repeat("\n", leading) + readText(t, c.Path)
			if err := os.WriteFile(c.Path, []byte(before), 0600); err != nil {
				t.Fatal(err)
			}
			c = f.ref(t, f.other)
			code, body := f.get(t, "/rules/change?c="+c.Ref+"&view=full")
			if code != http.StatusOK {
				t.Fatalf("open Full: %d %s", code, body)
			}
			form := builderParsedNewForm(t, body, "builder-edit")
			if got := form.Get("text"); got != before {
				t.Fatalf("Full open changed source bytes: want %q, got %q", before, got)
			}
			want := before + "\n# reviewed trailing comment\n"
			form.Set("text", want)
			form.Set("step", "check")
			form.Set("view", "full")
			w := post(f.s, "/rules/change", form, own, "", f.c)
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "It compiles.") {
				t.Fatalf("Full Check: %d %s", w.Code, w.Body.String())
			}
			body = w.Body.String()
			for step, view := range []string{"full", "simple", "full", "simple"} {
				if step > 0 {
					form = builderParsedNewForm(t, body, "builder-edit")
					form.Set("step", "check")
					form.Set("view", view)
					w = post(f.s, "/rules/change", form, own, "", f.c)
					if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "It compiles.") {
						t.Fatalf("Check switch to %s: %d %s", view, w.Code, w.Body.String())
					}
					body = w.Body.String()
				}
				form = builderParsedNewForm(t, body, "builder-edit")
				if got := form.Get("text"); got != want {
					t.Fatalf("%s changed reviewed bytes: want %q, got %q", view, want, got)
				}
			}
			// An unchecked required checkbox is absent from the parsed form. The
			// person now explicitly consents using its rendered review token.
			if form.Get("ack") != "" {
				t.Fatal("native form submitted an unchecked acknowledgement")
			}
			var ack string
			walk(parseHTML(t, "raw consent", body), func(n *html.Node) {
				name, _ := attr(n, "name")
				kind, _ := attr(n, "type")
				if n.Data == "input" && name == "ack" && kind == "checkbox" {
					ack, _ = attr(n, "value")
				}
			})
			if ack == "" {
				t.Fatal("Check offered no explicit review acknowledgement")
			}
			form.Set("ack", ack)
			form.Set("step", "save")
			form.Set("view", "simple")
			w = post(f.s, "/rules/change", form, own, "", f.c)
			if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/rules/change/saved") {
				t.Fatalf("Save reviewed blank lines: %d %s %s", w.Code, w.Header().Get("Location"), w.Body.String())
			}
			if got := readText(t, c.Path); got != want {
				t.Fatalf("saved bytes differ from review: want %q, got %q", want, got)
			}
		})
	}
}
