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
)

// TestRunHighlightsAndGroupedRefusals: on an enforced run buried in background refusals, the Highlights card shows
// the SSH key refused and the attacker's port refused at the top, each linking to its Logs lines, and the Refusals
// tab shows them first with the background folded into one counted fold.
func TestRunHighlightsAndGroupedRefusals(t *testing.T) {
	root := t.TempDir()
	run := "r-aaaaaaaa-0000000000003-signal"
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	ls := []string{line(run, "supply-chain", 0, t0, "run_start", `"tier":"landlock","command":["codex"],"cwd":"/w/proj"`),
		line(run, "supply-chain", 1, t0.Add(time.Second), "net", `"rule":"net[tcp://chatgpt.com:443]","verdict":"allow","dst":"104.18.32.47:443","host":"chatgpt.com"`)}
	seq := 2
	// Route probes: the UDP action line says what the refused lines to that address are.
	ls = append(ls, line(run, "supply-chain", seq, t0.Add(time.Second), "net", `"rule":"unmatched","verdict":"refused","reason":"net-not-allowed","proto":"udp","dst":"104.18.32.47:65535"`))
	seq++
	for i := 0; i < 400; i++ {
		ls = append(ls, line(run, "supply-chain", seq, t0.Add(2*time.Second), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"104.18.32.47:65535"`))
		seq++
	}
	for _, extra := range []string{
		`"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"127.0.0.1:8802"`,
		`"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"127.0.0.1:8802"`,
		`"rule":"fs.deny_read[/w/home/.ssh/]","reason":"read-denied","op":"open","target":"/w/home/.ssh/id_rsa"`,
	} {
		ls = append(ls, line(run, "supply-chain", seq, t0.Add(time.Minute), "refused", extra))
		seq++
	}
	ls = append(ls, line(run, "supply-chain", seq, t0.Add(2*time.Minute), "run_end", `"reason":"exit","exit_code":0`))
	if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	contract := "fs:\n  deny_read:\n    - /w/home/.ssh/\nnet:\n  allow:\n    - tcp://chatgpt.com:443\n"
	if err := os.WriteFile(filepath.Join(root, run, "contract.yaml"), []byte(contract), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)

	body := get(t, s, c, "/runs/"+run)
	hl := pageElement(t, body, "aria-labelledby", "h-hl")
	for _, want := range []string{
		`class="sev sev-High"`, "400 routine", "/w/home/.ssh/id_rsa", "Never read",
		"127.0.0.1:8802", "After a secret read", "chatgpt.com:443", "In rules file", "Routine · 1 host",
		`href="/logs?q=%2Fw%2Fhome%2F.ssh%2Fid_rsa&amp;run=` + run + `"`, `href="/logs?q=127.0.0.1%3A8802&amp;run=` + run + `"`,
	} {
		if !strings.Contains(hl, want) {
			t.Errorf("Highlights lack %q", want)
		}
	}
	if strings.Index(hl, "127.0.0.1:8802") > strings.Index(hl, "chatgpt.com:443") {
		t.Error("the refused attacker port is not above the allowed destination")
	}

	body = get(t, s, c, "/runs/"+run+"/refusals")
	rf := body[strings.Index(body, `id="h-rf"`):]
	key, port, bg := strings.Index(rf, "/w/home/.ssh/id_rsa"), strings.Index(rf, "127.0.0.1"), strings.Index(rf, `id="bg"`)
	if key < 0 || port < 0 || bg < 0 || key > port || port > bg {
		t.Fatalf("grouped order: key %d, attacker %d, background fold %d", key, port, bg)
	}
	if h := strings.Index(rf, `<h3 class="rf-sev-h">High (`); h < 0 || h > key {
		t.Errorf("the refusals tab does not open on its High section above the key (at %d, key at %d)", h, key)
	}
	if !strings.Contains(rf, "Routine (400 refusals in 1 group: system lookups, probes)") || !strings.Contains(rf, "×400") ||
		!strings.Contains(rf, "a route probe to port 65535") || strings.Contains(rf[bg:bg+40], " open") {
		t.Errorf("background fold wrong:\n%s", rf[bg:min(len(rf), bg+600)])
	}
	if b := get(t, s, c, "/runs/"+run+"/refusals?bg=open"); !strings.Contains(b, `id="bg" open`) {
		t.Error("?bg=open does not open the Background fold")
	}
	if b := get(t, s, c, "/runs/"+run+"/refusals?view=lines"); !strings.Contains(b, "Reason the agent got") || strings.Contains(b, `id="bg"`) {
		t.Error("the every-line view is not the folded line list")
	}
}

// get is a page as the words tests read it: each bare number marker (numbers.go) is replaced by its words, which
// keep any "at least" or "could not read" qualification. getRaw keeps the markers, for the number inventory tests.
func get(t *testing.T, s *Server, c *http.Cookie, path string) string {
	t.Helper()
	return unmarked(getRaw(t, s, c, path))
}

func getRaw(t *testing.T, s *Server, c *http.Cookie, path string) string {
	t.Helper()
	w := doRaw(s, "GET", path, "127.0.0.1:8484", c)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
	}
	return w.Body.String()
}

func TestRestoredFenceRefusalOutsideRoutineFold(t *testing.T) {
	root := t.TempDir()
	const run = "r-aaaaaaaa-0000000000003-fencer"
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	extras := []struct{ kind, body string }{
		{"run_start", `"tier":"cgroup","command":["agent"],"cwd":"/w/proj","live_mode":"adjustable","live_fence":{"sha256":"0a0a","entries":[{"kind":"net","value":"api.stripe.com:443","source":"new","rule":"live.fence[net:api.stripe.com:443]"}]}`},
		{"gap", `"what":"enforce","why":"live-rule-lifted","live_block":{"op":"lift","kind":"net","value":"api.stripe.com:443","rule":"live.fence[net:api.stripe.com:443]"}`},
		{"net", `"rule":"live.fence[net:api.stripe.com:443]","verdict":"allow","host":"api.stripe.com","dst":"203.0.113.10:443","proto":"tcp"`},
		{"gap", `"what":"enforce","why":"live-rule-restored","live_block":{"op":"restore","kind":"net","value":"api.stripe.com:443","rule":"live.fence[net:api.stripe.com:443]"}`},
		{"refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"203.0.113.10:8443"`},
		{"refused", `"rule":"held-unsupported","reason":"fs-gate","op":"open","target":"/dev/tty"`},
		{"run_end", `"reason":"exit","exit_code":0`},
	}
	var lines []string
	for seq, e := range extras {
		lines = append(lines, line(run, "agent", seq, t0.Add(time.Duration(seq)*time.Minute), e.kind, e.body))
	}
	if err := os.MkdirAll(filepath.Join(root, run), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(strings.Join(lines, "")), 0600); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	body := get(t, s, login(t, s), "/runs/"+run+"/refusals")
	rf := body[strings.Index(body, `id="h-rf"`):]
	host, routine := strings.Index(rf, "203.0.113.10"), strings.Index(rf, `id="bg"`)
	if host < 0 || routine < 0 || host > routine {
		t.Fatalf("restored fence refusal at %d, routine fold at %d", host, routine)
	}
}

// numberMarkerSpan is the "quantity" template's own markup (layout.tmpl): a span with only the marker and a title.
var pathTokenSpan = regexp.MustCompile(`<span class="path-token"(?: data-number-exclude="layout.path-token")?>([^<]*)</span>`)

var numberMarkerSpan = regexp.MustCompile(`<span data-number="[a-z0-9.-]+"(?: title="[^"]*")?>([^<]*)</span>`)

// unmarked replaces each bare number marker span by its words.
var auditOnlyAttribute = regexp.MustCompile(` data-number-(?:exclude(?:-[a-z-]+)?|title|aria-label|aria-description|alt|placeholder|value)="[^"]*"`)
var bareAuditSpan = regexp.MustCompile(`(?s)<span data-number-exclude="(?:highlights.specific-1|procs.explicit-8|layout.duration-ended|event.integrity-line|approvals.request-agent)">(.*?)</span>`)
var auditNumberAttribute = regexp.MustCompile(` data-number="[^"]*"`)
var titleNumberAttribute = regexp.MustCompile(`(<title) data-number="[^"]*"`)

func unmarked(body string) string {
	// Leaf identity wrappers do not change the path words these older markup assertions compare.
	body = pathTokenSpan.ReplaceAllString(body, "$1")
	body = numberMarkerSpan.ReplaceAllString(body, "$1")
	body = bareAuditSpan.ReplaceAllString(body, "$1")
	body = auditOnlyAttribute.ReplaceAllString(body, "")
	body = auditNumberAttribute.ReplaceAllString(body, "")
	body = titleNumberAttribute.ReplaceAllString(body, "$1")
	return body
}
