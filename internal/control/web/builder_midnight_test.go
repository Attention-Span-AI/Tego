// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	htmlnode "golang.org/x/net/html"
)

// The native structured review carries its dated YAML diff across midnight.
func TestBuilderStructuredPreviewSaveAcrossMidnight(t *testing.T) {
	for _, key := range []string{"net.allow", "net.ask"} {
		t.Run(key, func(t *testing.T) {
			f := newChangeFix(t)
			f.svc.Resolver = failHosts{}
			now := time.Date(2026, 11, 12, 23, 59, 59, 0, time.UTC)
			f.svc.Now = func() time.Time { return now }
			c := f.ref(t, f.other)
			if err := os.WriteFile(c.Path, []byte("version: 0\nname: other-agent\ncommand: [sh]\nnet: {allow: []}\n"), 0600); err != nil {
				t.Fatal(err)
			}
			c = f.ref(t, f.other)
			before := readText(t, c.Path)
			q := url.Values{"c": {c.Ref}, "base": {c.Base}, "op": {"add"}, "key": {key}, "v": {"api.example:443"}}
			code, body := f.get(t, "/rules/change/preview?"+q.Encode())
			if code != http.StatusOK {
				t.Fatalf("Preview: %d %s", code, body)
			}
			var form url.Values
			var diff string
			walk(parseHTML(t, "structured preview", body), func(n *htmlnode.Node) {
				if n.Data == "pre" {
					if label, _ := attr(n, "aria-label"); label == "The file's change" && n.FirstChild != nil {
						diff = n.FirstChild.Data
					}
				}
				if n.Data == "form" {
					if class, _ := attr(n, "class"); strings.Contains(class, "rc-confirm") {
						form = url.Values{}
						walk(n, func(input *htmlnode.Node) {
							if input.Data == "input" {
								name, _ := attr(input, "name")
								value, _ := attr(input, "value")
								if name != "" {
									form.Add(name, value)
								}
							}
						})
					}
				}
			})
			if form.Get("ack") == "" || !strings.Contains(diff, "2026-11-12") {
				t.Fatalf("no valid dated review: %s", diff)
			}
			// Reconstruct the exact reviewed candidate from the displayed unified diff.
			original := strings.Split(strings.TrimSuffix(before, "\n"), "\n")
			expected := []string{}
			cursor := 0
			for _, line := range strings.Split(diff, "\n") {
				if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "+++") {
					continue
				}
				if strings.HasPrefix(line, "@@") {
					var from int
					if _, err := fmt.Sscanf(line, "@@ line %d", &from); err != nil {
						t.Fatal(err)
					}
					for cursor < from-1 {
						expected = append(expected, original[cursor])
						cursor++
					}
					continue
				}
				if strings.HasPrefix(line, " ") {
					expected = append(expected, line[1:])
					cursor++
				} else if strings.HasPrefix(line, "+") {
					expected = append(expected, line[1:])
				} else if strings.HasPrefix(line, "-") {
					cursor++
				}
			}
			expected = append(expected, original[cursor:]...)
			want := strings.Join(expected, "\n") + "\n"
			now = now.Add(2 * time.Second)
			w := post(f.s, "/rules/change", form, own, "", f.c)
			if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "/rules/change/saved") {
				t.Fatalf("Save across midnight: %d %s", w.Code, w.Header().Get("Location"))
			}
			saved, err := os.ReadFile(c.Path)
			if err != nil {
				t.Fatal(err)
			}
			if string(saved) != want {
				t.Fatalf("saved bytes differ from reviewed bytes:\nwant %q\ngot %q", want, saved)
			}
		})
	}
}
