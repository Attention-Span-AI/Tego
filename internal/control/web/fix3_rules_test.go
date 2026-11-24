// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"golang.org/x/net/html"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rulesview"
)

func TestRuleZeroHitsUsesRetainedScope(t *testing.T) {
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	// The rule's hit is outside the retained window, so its retained tally is zero.
	for _, scope := range []countScope{{Lower: true, Reason: reasonWindow}, {Error: "run unreadable"}} {
		var b bytes.Buffer
		if err := pages["rules"].ExecuteTemplate(&b, "hits", withNumbers(rulesview.Rule{}, countScopes{Window: scope})); err != nil {
			t.Fatal(err)
		}
		words := text(parseHTML(t, "hits", b.String()))
		if words == "No hits" || !strings.Contains(words, "retained") && !strings.Contains(words, "could not be read") {
			t.Fatalf("zero claims complete absence: %q", words)
		}
		if len(numberMarkers(t, b.String())["contracts.hits"]) != 1 {
			t.Fatal("zero-form lost its quantity marker")
		}
	}
}

func TestContractZeroHitOutsideRetainedWindow(t *testing.T) {
	root := numberLedger(t)
	f, err := os.OpenFile(filepath.Join(root, numRichRun, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	at := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	for i := 45; i < 33045; i++ {
		b.WriteString(line(numRichRun, "Counter", i, at, "exec", `"verdict":"allow","op":"exec","path":"/bin/true"`))
	}
	_, err = f.WriteString(b.String())
	cerr := f.Close()
	if err != nil || cerr != nil {
		t.Fatalf("append: %v %v", err, cerr)
	}
	s := newServer(t, root)
	c := login(t, s)
	body := getRaw(t, s, c, "/rules?run="+numRichRun)
	snap, err := ledgerview.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if r := snap.Find(numRichRun); r == nil || !r.Cut {
		t.Fatal("fixture retained the rule's early hit")
	}
	selected := ""
	walk(parseHTML(t, "Contract", body), func(n *html.Node) {
		if href, ok := attr(n, "href"); ok {
			u, err := url.Parse(href)
			if err == nil && strings.Contains(u.Query().Get("rule"), "/home/u/.ssh/") {
				selected = href
			}
		}
	})
	if selected == "" {
		t.Fatal("fixture has no link to its protected-path rule")
	}
	detail := getRaw(t, s, c, selected)
	for name, rendered := range map[string]string{"contract": body, "rule": detail} {
		matches := numberMarkers(t, rendered)["contracts.hits"]
		if len(matches) == 0 {
			t.Errorf("%s has no hits/zero marker", name)
		}
		found := false
		for _, m := range matches {
			// The release line's source check runs in a helper that reads the whole run, so the early hit may be seen
			// (counted "at least"); read in the dashboard's retained window alone it is a qualified zero.
			found = found || strings.Contains(m, "seen in what is retained") || strings.Contains(m, "at least")
		}
		if !found || !strings.Contains(rendered, reasonWindow) || !strings.Contains(rendered, "/logs.jsonl?run="+numRichRun) {
			t.Errorf("%s claims an absence without the retained scope, reason and recovery", name)
		}
	}
}
