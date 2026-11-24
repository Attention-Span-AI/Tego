// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"golang.org/x/net/html"
)

func TestNumberScopeRequired(t *testing.T) {
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := pages["run"].ExecuteTemplate(&b, "tlrows", tlOf(nil, false, false, changesAt{})); err == nil {
		t.Fatal("a numbers template accepted a missing scope")
	}
}

func TestTimelineFragmentKeepsScope(t *testing.T) {
	old := ledgerview.MaxLines
	ledgerview.MaxLines = 16
	t.Cleanup(func() { ledgerview.MaxLines = old })
	root := numberLedger(t)
	for i := 45; i < 80; i++ {
		appendLine(t, root, numRichRun, line(numRichRun, "Counter", i, time.Now(), "refused", `"op":"connect","target":"203.0.113.9:8443","rule":"unmatched"`))
	}
	s := newServer(t, root)
	c := login(t, s)
	body := getRaw(t, s, c, "/runs/"+numRichRun+"/rows?after=0")
	ms := numberMarkers(t, body)["run.refusal-repeat"]
	// exec rows fold too; every retained folded count is qualified.
	if len(ms) == 0 {
		t.Fatalf("no folded timeline count: %s", body)
	}
	for _, m := range ms {
		if !strings.Contains(m, "at least") {
			t.Fatalf("fragment lost source completeness: %q", m)
		}
	}
}

func TestRunChromeKeepsGlobalScopes(t *testing.T) {
	root := numberLedger(t)
	if err := os.RemoveAll(filepath.Join(root, harmRun)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, ".live", harmRun)); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	// Read the run first, then add a run that cannot be listed.
	getRaw(t, s, c, "/runs/"+numRichRun)
	makeUnreadableCandidate(t, root)
	body := getRaw(t, s, c, "/runs/"+numRichRun)
	if strings.Contains(body, "Nothing running") {
		t.Fatal("local run scope erased the global read failure")
	}
	if !strings.Contains(body, "Could not read running state") {
		t.Fatal("global running state lost its failure")
	}
}

func makeUnreadableCandidate(t *testing.T, root string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, numUnlisted, "events.jsonl"), 0700); err != nil {
		t.Fatal(err)
	}
}

func TestRunCandidatesKeepTheirOwnScope(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope countScope
		want  string
	}{
		{"display cap", countScope{Lower: true, Reason: reasonOmitted}, "3"},
		{"unlisted candidate", countScope{Error: "unreadable candidate"}, "could not read"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, err := quantityOf("shared.run-candidates", 3, countScopes{Runs: tc.scope})
			if err != nil {
				t.Fatal(err)
			}
			if q.Text != tc.want {
				t.Fatalf("candidate total %q want %q", q.Text, tc.want)
			}
		})
	}
}

func TestComparisonZeroSummaryUsesRetainedScope(t *testing.T) {
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	a := &ledgerview.Run{ID: numRichRun, Agent: "Counter", Cut: true}
	b := &ledgerview.Run{ID: cleanRun, Agent: "Other"}
	cmp := &ledgerview.Comparison{A: ledgerview.CmpSide{Run: a}, B: ledgerview.CmpSide{Run: b}, Summary: "Run A read no secret file. Run B read no secret file."}
	var out bytes.Buffer
	if err := pages["compare"].ExecuteTemplate(&out, "content", page{Data: compareData{Runs: []*ledgerview.Run{a, b}, Cmp: cmp}}); err != nil {
		t.Fatal(err)
	}
	words := numberMarkers(t, out.String())["compare.summary"]
	if len(words) != 1 || !strings.Contains(words[0], "seen in what is retained") {
		t.Fatalf("comparison retained zero claimed complete absence: %v", words)
	}
}

func TestNewContractChromeKeepsUnreadableRootScope(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ledger-file")
	if err := os.WriteFile(root, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	setup := newRulesFix(t)
	setup.withSetup(t)
	s.cfg.Setup = setup.s.cfg.Setup
	c := login(t, s)
	body := getRaw(t, s, c, "/rules/new?mode=run")
	if strings.Contains(body, "Record one first") || strings.Contains(body, "Nothing running") || !strings.Contains(body, "could not tell whether a request is waiting") || !strings.Contains(body, "<title data-number=\"shared.waiting\">(?)") {
		t.Fatal("new contract's chrome guessed an empty global source")
	}
}

func TestRetiredRuleChromeKeepsGlobalScopes(t *testing.T) {
	root := twoRequestFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	getRaw(t, s, c, "/approvals")
	makeUnreadableCandidate(t, root)
	r := httptest.NewRequest(http.MethodPost, "/rule", nil)
	r.PostForm = url.Values{"run": {harmRun}, "seq": {"7"}}
	w := httptest.NewRecorder()
	s.ruleGonePost(w, r)
	if w.Code != http.StatusGone {
		t.Fatalf("retired form: %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "data-sig=") {
		t.Error("retired POST receipt would live-refresh through its invalid GET address")
	}
	title := ""
	walk(parseHTML(t, "retired", body), func(n *html.Node) {
		if n.Data == "title" {
			title = text(n)
		}
	})
	if !strings.HasPrefix(title, "(2+)") || !strings.Contains(body, "at least 2 waiting") || strings.Contains(body, "Nothing running") {
		t.Fatalf("retired form discarded the global queue/source scope: title=%q", title)
	}
}

func TestRenderPageRequiresGlobalScope(t *testing.T) {
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	renderPage(w, http.StatusOK, pages["overview"], "overview", page{chrome: chrome{Title: "Missing scope"}})
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "global numbers scope is required") {
		t.Fatal("render helper accepted missing global scopes")
	}
}

func TestMalformedStartQualifiesCategoryAbsences(t *testing.T) {
	root := t.TempDir()
	id := "r-aaaaaaaa-0000000000008-badstart"
	if err := os.MkdirAll(filepath.Join(root, id), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, id, "events.jsonl"), []byte("{broken start}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	for _, tc := range []struct{ path, id string }{{"/machine", "machine.tier-runs"}, {"/mcp", "mcp.runs-zero"}, {"/routes", "routes.runs"}} {
		t.Run(tc.path, func(t *testing.T) {
			body := getRaw(t, s, c, tc.path)
			ms := numberMarkers(t, body)[tc.id]
			if len(ms) == 0 {
				t.Fatal("fixture did not render the category absence")
			}
			for _, m := range ms {
				if !strings.Contains(m, "seen in what is retained") {
					t.Fatalf("unreadable category claimed exact absence: %q", m)
				}
			}
		})
	}
}
