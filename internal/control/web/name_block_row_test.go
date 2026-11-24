// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRefusalRowSaysWhoseAddressItIs (ADR 0157): a refused connect to an address the run reached under a CIDR entry, while
// a live block by name stands. A ledger at record minor 41 names the addresses the block was enforced on, so the row says
// the address is that host's; a block whose line names none (a ledger below 41) leaves the row saying the name is unknown.
// A recorded list that does not include the address says neither.
func TestRefusalRowSaysWhoseAddressItIs(t *testing.T) {
	const run = "r-aaaa-0042-names"
	block := func(addrs string) string {
		return `"what":"enforce","why":"live-block-added","live_block":{"op":"add","kind":"net","value":"chatgpt.com","rule":"live.block[net:chatgpt.com]","by":"uid:1000","serial":1,"at":"2026-11-20T09:00:00Z"` + addrs + `}`
	}
	for _, c := range []struct {
		name, addrs  string
		want, absent string
	}{
		{"recorded", `,"addrs":["2001:db8::7"]`, "this address is one a live block on chatgpt.com was enforced on", "name unknown"},
		{"no addresses recorded", ``, "name unknown", "this address is one a live block on chatgpt.com was enforced on"},
		{"other addresses recorded", `,"addrs":["2001:db8::99"]`, "", "this address is one a live block on chatgpt.com was enforced on"},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			t0 := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
			ls := []string{
				line(run, "codex", 0, t0, "run_start", `"tier":"landlock","command":["codex"],"cwd":"/w/x/proj","record_minor":41`),
				line(run, "codex", 1, t0.Add(time.Second), "gap", block(c.addrs)),
				line(run, "codex", 2, t0.Add(2*time.Second), "net", `"rule":"net[tcp://2001:db8::/32:443]","verdict":"allow","proto":"tcp","dst":"[2001:db8::7]:443"`),
				line(run, "codex", 3, t0.Add(3*time.Second), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"[2001:db8::7]:8443"`),
				line(run, "codex", 4, t0.Add(4*time.Second), "run_end", `"reason":"exit","exit_code":0`),
			}
			if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
				t.Fatal(err)
			}
			s := newServer(t, root)
			body := get(t, s, login(t, s), "/runs/"+run+"/refusals")
			if !strings.Contains(body, "2001:db8::7") {
				t.Fatalf("the refused connect is not on the page:\n%s", body)
			}
			if c.want != "" && !strings.Contains(body, c.want) {
				t.Errorf("the row does not say %q", c.want)
			}
			if strings.Contains(body, c.absent) {
				t.Errorf("the row says %q", c.absent)
			}
		})
	}
}
