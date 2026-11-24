// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// HTML removes the first LF after a textarea's opening tag. The rendered editor
// and Save form must preserve blank lines that belong to the reviewed YAML.
func TestBuilderNewLeadingNewlinesSurviveRenderedForms(t *testing.T) {
	for _, leading := range []int{0, 1, 2} {
		t.Run(fmt.Sprintf("leading-%d", leading), func(t *testing.T) {
			f := newChangeFix(t)
			f.s.cfg.Setup = f.svc
			dir := filepath.Join(f.proj, "leading-newline")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			want := strings.Repeat("\n", leading) + "version: 0\nname: leading-newline\ncommand: [/bin/sh]\nexec:\n  allow: [/bin/sh]\nnet:\n  allow: []\nenv:\n  pass: []\n"
			form := url.Values{"csrf": {f.s.csrf}, "builder": {"1"}, "step": {"preview"}, "mode": {"blank"}, "dir": {dir}, "name": {"leading-newline"}, "to": {"project"}, "view": {"full"}, "current-view": {"full"}, "text": {want}}
			w := post(f.s, "/rules/new", form, own, "", f.c)
			if w.Code != http.StatusOK {
				t.Fatalf("Full Check: %d %s", w.Code, w.Body.String())
			}
			body := w.Body.String()
			for step, view := range []string{"full", "simple", "full"} {
				if step > 0 {
					form = builderParsedNewForm(t, body, "builder-edit")
					form.Set("step", "preview")
					form.Set("view", view)
					w = post(f.s, "/rules/new", form, own, "", f.c)
					if w.Code != http.StatusOK {
						t.Fatalf("switch to %s: %d %s", view, w.Code, w.Body.String())
					}
					body = w.Body.String()
				}
				form = builderParsedNewForm(t, body, "builder-edit")
				if got := form.Get("text"); got != want {
					t.Fatalf("%s editor changed reviewed bytes: want %q, got %q", view, want, got)
				}
				save := builderParsedNewForm(t, body, "builder-save")
				if got := save.Get("text"); got != want {
					t.Fatalf("%s Save form changed reviewed bytes: want %q, got %q", view, want, got)
				}
			}
			w = post(f.s, "/rules/new", builderParsedNewForm(t, body, "builder-save"), own, "", f.c)
			if w.Code != http.StatusSeeOther {
				t.Fatalf("Save reviewed blank lines: %d %s", w.Code, w.Body.String())
			}
			saved, err := os.ReadFile(filepath.Join(dir, "agent.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			if string(saved) != want {
				t.Fatalf("saved bytes differ from review: want %q, got %q", want, saved)
			}
		})
	}
}

// Parse controls as HTML, including textarea's first-LF rule. Regex extraction
// would preserve the source LF and hide a difference from what browsers submit.
func builderParsedNewForm(t *testing.T, body, id string) url.Values {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var root, form *html.Node
	walk(doc, func(n *html.Node) {
		if value, _ := attr(n, "id"); value == id {
			root = n
		}
	})
	if root == nil {
		t.Fatalf("no rendered %s", id)
	}
	walk(root, func(n *html.Node) {
		if n.Data == "form" && form == nil {
			form = n
		}
	})
	if form == nil {
		t.Fatalf("no form in %s", id)
	}
	out := url.Values{}
	walk(form, func(n *html.Node) {
		name, _ := attr(n, "name")
		if name == "" || hasAttr(n, "disabled") {
			return
		}
		switch n.Data {
		case "input":
			kind, _ := attr(n, "type")
			if (kind == "radio" || kind == "checkbox") && !hasAttr(n, "checked") {
				return
			}
			value, _ := attr(n, "value")
			out.Add(name, value)
		case "textarea":
			var value strings.Builder
			for child := n.FirstChild; child != nil; child = child.NextSibling {
				if child.Type == html.TextNode {
					value.WriteString(child.Data)
				}
			}
			out.Add(name, value.String())
		}
	})
	return out
}
