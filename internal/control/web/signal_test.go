// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"os"
	"path/filepath"
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
	hl := body[strings.Index(body, `id="h-hl"`):strings.Index(body, "run-facts")]
	for _, want := range []string{
		`class="sev sev-High"`, "400 routine", "/w/home/.ssh/id_rsa", "Never read",
		"127.0.0.1:8802", "After a secret read", "chatgpt.com:443", "In policy", "Routine · 1 host",
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

func get(t *testing.T, s *Server, c *http.Cookie, path string) string {
	t.Helper()
	w := do(s, "GET", path, "127.0.0.1:8484", c)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
	}
	return w.Body.String()
}
