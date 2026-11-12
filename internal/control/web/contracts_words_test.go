// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rules"
)

// TestContractsAddressesLeadToRules: the pages are named Contracts, and their addresses stay /rules. /contracts,
// /contracts/new and /contracts/change answer 303 to the same page under /rules with the query kept, so the name can be
// typed; any other path under /contracts is not a page; /rules itself answers as before.
func TestContractsAddressesLeadToRules(t *testing.T) {
	f := newRulesFix(t)
	f.withSetup(t)
	for from, to := range map[string]string{
		"/contracts":                      "/rules",
		"/contracts?run=" + rulesRunA:     "/rules?run=" + rulesRunA,
		"/contracts/new?mode=run&from=x":  "/rules/new?mode=run&from=x",
		"/contracts/change":               "/rules/change",
		"/contracts/change/preview?c=abc": "/rules/change/preview?c=abc",
	} {
		w := do(f.s, "GET", from, "127.0.0.1:8484", f.c)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != to || w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("GET %s: %d to %q (Cache-Control %q), want 303 to %q, not cached", from, w.Code, w.Header().Get("Location"),
				w.Header().Get("Cache-Control"), to)
		}
	}
	for _, p := range []string{"/contracts/x", "/contracts/../etc", "/contractsx"} {
		if w := do(f.s, "GET", p, "127.0.0.1:8484", f.c); w.Code != http.StatusNotFound {
			t.Errorf("GET %s: %d, want 404", p, w.Code)
		}
	}
	if w := do(f.s, "GET", "/contracts", "127.0.0.1:8484", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("GET /contracts without a session: %d, want 401", w.Code)
	}
	if code, body := f.get(t, "/rules?run="+rulesRunA); code != http.StatusOK || !strings.Contains(body, "<title>Contract · rules-demo · Tego") {
		t.Errorf("GET /rules: %d, or its title is not Contract · rules-demo", code)
	}
}

// oldWord finds the dashboard's older words where a person reads them: Policy or Policies as a word, and Blocked as
// a verdict (a column, a tab, a chip, a heading). Block now, Blocked live and live blocks are the live control and stay.
var oldWord = regexp.MustCompile(`(?i)>[^<]*\bpolic(y|ies)\b[^<]*<|>(Blocked|Blocked only)<|>Blocked <span|Nothing blocked|High</a> blocked`)

// spokenText is what a person reads or a screen reader says: a text node (a caption's too), or the value of an
// aria-label, title, alt or placeholder attribute.
var spokenText = regexp.MustCompile(`>([^<]*)<|\b(?:aria-label|title|alt|placeholder)="([^"]*)"`)

// blockedWord is Blocked, any case, as a word. "Blocked live" (a live block's rule label) and an Adjustable fence's
// entry that "starts blocked" are the live control, not a verdict.
var blockedWord = regexp.MustCompile(`(?i)(\bstarts )?\bblocked\b( live\b)?`)

// saysBlocked is the first text of body, outside its <pre> blocks, that says Blocked as a verdict, "" for none.
func saysBlocked(body string) string {
	for _, m := range spokenText.FindAllStringSubmatch(preText.ReplaceAllString(body, "<pre></pre>"), -1) {
		for _, w := range blockedWord.FindAllStringSubmatch(m[1]+m[2], -1) {
			if w[1] == "" && w[2] == "" {
				return strings.TrimSpace(m[0])
			}
		}
	}
	return ""
}

// preText is a <pre> block and its text.
var preText = regexp.MustCompile(`(?s)<pre[^>]*>.*?</pre>`)

// TestPagesSayContractAndRefused (docs/DASHBOARD.md, Contract and refused): the nav, the page titles and the pages a newcomer reads say contract
// and refused, the command line's words, never policy, and never Blocked as a verdict.
func TestPagesSayContractAndRefused(t *testing.T) {
	f := newRulesFix(t)
	f.withSetup(t)
	for _, p := range []string{"/", "/runs", "/detections", "/logs", "/approvals", "/glossary", "/rules", "/rules?run=" + rulesRunA,
		"/rules/new", "/rules/new?mode=run&from=" + rulesRunA, "/runs/" + rulesRunA, "/runs/" + rulesRunA + "/least-privilege",
		"/runs/" + rulesRunA + "/refusals", "/runs/" + rulesRunA + "/unused", "/severity", "/machine"} {
		code, body := f.get(t, p)
		if code != http.StatusOK {
			t.Errorf("GET %s: %d", p, code)
			continue
		}
		// A contract's own text (a <pre>) is the file as written, and the Glossary says the older words once, to name
		// them (TestGlossary holds it to that).
		shown := preText.ReplaceAllString(body, "<pre></pre>")
		if p == "/glossary" {
			shown = strings.ReplaceAll(shown, "called it a policy before", "")
			shown = strings.ReplaceAll(shown, "said blocked before", "")
		}
		if m := oldWord.FindString(shown); m != "" {
			t.Errorf("%s says the older word: %q", p, m)
		}
		if m := saysBlocked(shown); m != "" {
			t.Errorf("%s says Blocked where a person reads or hears it: %q", p, m)
		}
		if !strings.Contains(body, `<span class="lbl">Contracts</span>`) {
			t.Errorf("%s: the nav does not say Contracts", p)
		}
	}
}

// TestLinePagesSayRefused: a line page says Refused, not Blocked, in its facts (Refused by, the mechanism that
// refused) and in the guard panel of a line a rule already refuses; Logs names a built-in rule's line "Host IPC
// refused"; and no text or label a screen reader says on these pages says Blocked.
func TestLinePagesSayRefused(t *testing.T) {
	root := t.TempDir()
	proj := filepath.Join(t.TempDir(), "proj")
	if err := os.MkdirAll(filepath.Join(proj, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	contract := filepath.Join(proj, "agent.yaml")
	if err := os.WriteFile(contract, []byte("version: 0\nname: g\ncommand:\n  - sh\nfs:\n  deny_read:\n    - ./keys/\nexec:\n  allow:\n    - sh\ntier: landlock\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	factsLines(t, root, factsRun, time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC), [][3]string{
		{"100", "run_start", `"tier":"landlock","command":["sh"],"cwd":"` + proj + `","contract_hash":"` + strings.Repeat("0", 64) + `","contract_source":{"path":"` + contract + `"}`},
		{"100", "fs", `"verdict":"refused","authority":"rule","rule":"fs.deny_read[./keys/]","reason":"read-denied","op":"open","path":"` + proj + `/keys/k","errno":13,"mechanism":"landlock"`},
		{"100", "fs", `"verdict":"refused","authority":"rule","rule":"builtin.host_ipc","reason":"read-denied","op":"open","path":"/run/user/1000/bus","errno":13,"mechanism":"landlock"`},
		{"100", "run_end", `"reason":"exit","exit_code":0`},
	})
	s := newServer(t, root)
	s.cfg.Rules = &rules.Service{Ledger: root, Now: s.cfg.Now, Check: func(string, string, []byte) error { return nil }}
	c := login(t, s)
	landlock := "<dt>Refused by</dt><dd>the kernel&#39;s Landlock rules</dd>"
	for path, want := range map[string][]string{
		"/runs/" + factsRun + "/lines/1": {landlock, "Already refused by: <strong>", "Already refused next run"},
		"/runs/" + factsRun + "/lines/2": {landlock},
		"/logs?run=" + factsRun:          {"Host IPC refused"},
	} {
		page := get(t, s, c, path)
		for _, w := range want {
			if !strings.Contains(page, w) {
				t.Errorf("%s lacks %q", path, w)
			}
		}
		if m := saysBlocked(page); m != "" {
			t.Errorf("%s says Blocked where a person reads or hears it: %q", path, m)
		}
	}
}

// TestOverviewChartsSayRefused: the Overview's charts row, with a refused line to chart, names itself and its grid
// with Refused, not Blocked, in the labels a screen reader says.
func TestOverviewChartsSayRefused(t *testing.T) {
	root := detectionsRoot(t, "r-aaaaaaaa-0000000000013-chartw", "landlock",
		[2]string{"refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"203.0.113.9:443"`})
	s := newServer(t, root)
	page := get(t, s, login(t, s), "/")
	for _, want := range []string{`<section class="ch-row" aria-label="Refused and secrets">`, `<caption class="sr">Refused actions by severity and channel</caption>`} {
		if !strings.Contains(page, want) {
			t.Errorf("the Overview lacks %q", want)
		}
	}
	if m := saysBlocked(page); m != "" {
		t.Errorf("the Overview says Blocked where a person reads or hears it: %q", m)
	}
}
