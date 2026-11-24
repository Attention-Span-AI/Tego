// SPDX-License-Identifier: Apache-2.0

package web

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"
)

func TestNumberCollectorNegativeControls(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"request card descendant", `<div data-number-exclude="approvals.identity-4"><span class="mono">12 refused</span></div>`},
		{"log action descendant", `<button data-number-exclude="logs.fact-1"><span class="mono">12 refused</span></button>`},
		{"block identity descendant", `<a data-number-exclude="highlights.fact-4"><span class="mono">12 refused</span></a>`},
		{"monospace", `<span class="mono">12 refused</span>`},
		{"tooltip", `<span title="12 refused">Details</span>`},
		{"never asked", `<span>never asked</span>`},
		{"nowhere", `<span>nowhere: every request carrying it is refused</span>`},
		{"nowhere else", `<span>and nowhere else</span>`},
		{"zero sentence", `<p>No matching event recorded in this run.</p>`},
		{"split zero", `<p>No <b>hits</b></p>`},
		{"submit value", `<input type="submit" value="12 waiting">`},
		{"document title", `<title>(3+) Approvals</title>`},
		{"spoken label", `<a aria-label="12 waiting">Review</a>`},
		{"description", `<span aria-description="12 refused">Details</span>`},
		{"image alternate", `<img alt="12 refused">`},
		{"placeholder", `<input placeholder="12 waiting">`},
		{"output value", `<output value="12"></output>`},
		{"meter value", `<meter value="12"></meter>`},
		{"spoken range", `<span role="progressbar" aria-valuenow="12"></span>`},
		{"spoken value", `<span aria-valuetext="12 refused"></span>`},
		{"visible input", `<input value="12 refused">`},
		{"meter bound", `<meter max="12"></meter>`},
		{"deferred visible text", `<span data-late="No requests waiting">Soon</span>`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := unmarkedNumbers(t, tc.body)
			t.Logf("rejected: %v", got)
			if len(got) == 0 || strings.Contains(tc.name, "descendant") && !strings.Contains(strings.Join(got, " "), `text "12 refused"`) {
				t.Fatal("collector accepted an unmarked quantity")
			}
		})
	}
}

// An exception belongs to exactly one source element or one shown field of it.
// Reusing a styling class or an id across different elements is not an exception.
func TestNumberExclusionsNameOneSourceElement(t *testing.T) {
	defs := numberExclusions(t)
	files, err := fs.Glob(assets, "templates/*.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	pattern := regexp.MustCompile(`data-number-exclude(?:-[a-z-]+)?="([a-z0-9.-]+)"`)
	for _, f := range files {
		b, err := fs.ReadFile(assets, f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range pattern.FindAllStringSubmatch(string(b), -1) {
			counts[m[1]]++
			if defs[m[1]] == "" {
				t.Errorf("%s names unknown exclusion %s", f, m[1])
			}
		}
	}
	for id, reason := range defs {
		if counts[id] != 1 {
			t.Errorf("%s (%s): %d source elements, want one", id, reason, counts[id])
		}
	}
}

func TestNumberInsideRequestCardIsFound(t *testing.T) {
	s := newServer(t, twoRequestFixture(t))
	body := getRaw(t, s, login(t, s), "/approvals")
	const target = `<div class="ap-card-body">`
	if !strings.Contains(body, target) {
		t.Fatal("fixture did not render the request card")
	}
	body = strings.Replace(body, target, target+`<span class="mono">12 refused</span>`, 1)
	if !strings.Contains(strings.Join(unmarkedNumbers(t, body), " "), `text "12 refused"`) {
		t.Fatal("request card hid an unmarked descendant quantity")
	}
}

func TestEveryNumberExclusionKeepsWalkingChildren(t *testing.T) {
	for id := range numberExclusions(t) {
		body := `<span data-number-exclude="` + id + `">identity42<span>12 refused</span></span>`
		got := strings.Join(unmarkedNumbers(t, body), " ")
		if !strings.Contains(got, `text "12 refused"`) || strings.Contains(got, "identity42") {
			t.Errorf("%s has the wrong exclusion scope: %s", id, got)
		}
	}
}
