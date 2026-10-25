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

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const ruleRunName = "r-aaaa-0003-rulexx"

const ruleContractText = `version: 0
name: rule-web
# keep me
command:
  - sh
fs:
  write:
    - ./out/
tier: landlock
`

// ruleFixture is a ledger root with one run whose line #1 read proj/secret.txt; it returns the root and the
// contract's path.
func ruleFixture(t *testing.T) (root, contract string) {
	t.Helper()
	root = t.TempDir()
	proj := filepath.Join(t.TempDir(), "proj")
	if err := os.MkdirAll(proj, 0o700); err != nil {
		t.Fatal(err)
	}
	contract = filepath.Join(filepath.Dir(proj), "agent.yaml")
	if err := os.WriteFile(contract, []byte(ruleContractText), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(e *record.Event) { e.Run = ruleRunName }
	start := ledgertest.Event(t, record.KindRunStart, record.RunStartPayload{Tier: "landlock", Capture: "off",
		ContractHash: strings.Repeat("0", 64), Command: []string{"sh"}, Cwd: proj, Kernel: "6", StopGrace: "1s",
		ContractSource: &record.ContractSource{Path: contract}}, run)
	read := ledgertest.Event(t, record.KindFS, record.FSPayload{Op: "open", Path: filepath.Join(proj, "secret.txt")}, run,
		func(e *record.Event) {
			e.Seq, e.Prev, e.Source, e.Rule, e.Verdict, e.Authority = 1, strings.Repeat("a", 64), record.SourceSeccomp, "unmatched",
				record.VerdictAllow, record.AuthorityRule
			e.Attr = &record.Attribution{Confidence: "unattributed", Method: "none"}
		})
	var buf bytes.Buffer
	for _, e := range []*record.Event{start, read} {
		l, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(append(l, '\n'))
	}
	if err := os.MkdirAll(filepath.Join(root, ruleRunName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ruleRunName, "events.jsonl"), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return root, contract
}

func rulePost(s *Server, form url.Values, origin string, c *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/rule", strings.NewReader(form.Encode()))
	r.Host = "127.0.0.1:8484"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	r.AddCookie(c)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

// TestRuleGetRedirects: GET /rule sends an old link to the event page's Act on this panel (F11) and writes nothing.
func TestRuleGetRedirects(t *testing.T) {
	root, contract := ruleFixture(t)
	s := newServer(t, root)
	s.cfg.Rules = &rules.Service{Ledger: root, Now: s.cfg.Now, Check: func(string, string, []byte) error { return nil }}
	c := login(t, s)
	for target, want := range map[string]string{
		"/rule?run=" + ruleRunName + "&seq=1":         "/runs/" + ruleRunName + "/lines/1#act",
		"/rule?run=" + ruleRunName + "&seq=1&a=block": "/runs/" + ruleRunName + "/lines/1#act",
	} {
		w := do(s, "GET", target, "127.0.0.1:8484", c)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != want {
			t.Errorf("GET %s: %d %q, want 303 %q", target, w.Code, w.Header().Get("Location"), want)
		}
	}
	if w := do(s, "GET", "/rule?run="+ruleRunName+"&seq=x", "127.0.0.1:8484", c); w.Code != http.StatusBadRequest {
		t.Errorf("GET with no line: %d", w.Code)
	}
	if b, _ := os.ReadFile(contract); string(b) != ruleContractText {
		t.Fatal("GET wrote the contract")
	}
}

// TestPostRuleGone: POST /rule, the retired Confirm form of the old Rule page, answers 410 Gone with a link to the
// line's page and writes nothing, also for a widening (allow at the folder) with the token and the Origin, which it
// once wrote with no acknowledgement (SEC-1). The checks every form passes still come first.
func TestPostRuleGone(t *testing.T) {
	root, contract := ruleFixture(t)
	s := newServer(t, root)
	checked := 0
	s.cfg.Rules = &rules.Service{Ledger: root, Now: s.cfg.Now, Check: func(string, string, []byte) error { checked++; return nil }}
	c := login(t, s)
	before := rulefile.Sum([]byte(ruleContractText))
	for _, a := range []string{"allow", "block", "ask"} {
		form := url.Values{"run": {ruleRunName}, "seq": {"1"}, "a": {a}, "folder": {"1"}, "csrf": {s.csrf}}
		w := rulePost(s, form, "http://127.0.0.1:8484", c)
		if w.Code != http.StatusGone || !strings.Contains(w.Body.String(), "This form is retired") ||
			!strings.Contains(w.Body.String(), `href="/runs/`+ruleRunName+`/lines/1#act"`) {
			t.Errorf("POST /rule a=%s: %d %s", a, w.Code, w.Body.String())
		}
	}
	if w := rulePost(s, url.Values{"run": {"../x"}, "seq": {"1"}, "csrf": {s.csrf}}, "http://127.0.0.1:8484", c); w.Code != http.StatusGone ||
		strings.Contains(w.Body.String(), "../x") {
		t.Errorf("POST /rule with a path for a run: %d, or the link carries it", w.Code)
	}
	bad := url.Values{"run": {ruleRunName}, "seq": {"1"}, "a": {"allow"}, "csrf": {"nope"}}
	if w := rulePost(s, bad, "http://127.0.0.1:8484", c); w.Code != http.StatusForbidden {
		t.Errorf("no token: %d", w.Code)
	}
	b, _ := os.ReadFile(contract)
	if rulefile.Sum(b) != before || checked != 0 {
		t.Fatalf("POST /rule changed the contract (or compiled one): %s", b)
	}
	if _, err := os.Stat(contract + ".bak"); err == nil {
		t.Error("POST /rule left a .bak")
	}
}

// TestRuleLinkOnRows: a Rule link, to the event page's Act on this panel, is offered only where a rule can be made
// and is worth making: on a run that names its contract file, and on a row that was refused or asked about. The
// fixture's allowed read keeps its line link (whose page acts on any line) but no Rule link.
func TestRuleLinkOnRows(t *testing.T) {
	root, _ := ruleFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	for _, p := range []string{"/runs/" + ruleRunName, "/logs"} {
		b := do(s, "GET", p, "127.0.0.1:8484", c).Body.String()
		if strings.Contains(b, `href="/runs/`+ruleRunName+`/lines/1#act"`) || !strings.Contains(b, `/runs/`+ruleRunName+`/lines/1"`) {
			t.Errorf("%s: an allowed read offers Rule, or lost its line link", p)
		}
	}
	for _, tc := range []struct {
		name     string
		e        ledgerview.Event
		contract bool
		want     bool
	}{
		{"refused read", ledgerview.Event{Kind: "fs", Verdict: "refused"}, true, true},
		{"asked connect", ledgerview.Event{Kind: "net", Verdict: "ask"}, true, true},
		{"unpaired refused line", ledgerview.Event{Kind: "refused"}, true, true},
		{"allowed write", ledgerview.Event{Kind: "fs", Verdict: "allow"}, true, false},
		{"refused, watch run", ledgerview.Event{Kind: "fs", Verdict: "refused"}, false, false},
		{"answer line", ledgerview.Event{Kind: "answer"}, true, false},
	} {
		if got := rowActsOf(tc.e, false, tc.contract).Rule; got != tc.want {
			t.Errorf("%s: Rule %v, want %v", tc.name, got, tc.want)
		}
	}
}
