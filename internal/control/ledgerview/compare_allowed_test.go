// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"strings"
	"testing"
	"time"
)

// TestCompareSaysWhatAPersonAllowed: Compare's sentence never says an enforced run "read 1 secret file" for a file a
// person allowed (the contract asked, the person said yes): it says "read 1 file a person allowed (confidential/plan.md)",
// named from the run's working directory. A secret the run read with no one asked still counts as a secret file read.
func TestCompareSaysWhatAPersonAllowed(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	const ra, rb = "r-aaaa-0011-watchx", "r-aaaa-0012-guardx"
	writeRun(t, root, ra,
		line(ra, "watch", 0, t0, "run_start", `"tier":"observe","cwd":"/d/without/proj","command":["codex"]`),
		line(ra, "watch", 1, t0.Add(time.Second), "fs", `"verdict":"observed","rule":"unmatched","op":"open","path":"/d/without/home/.ssh/id_rsa"`),
		line(ra, "watch", 2, t0.Add(2*time.Second), "net", `"verdict":"observed","rule":"unmatched","proto":"tcp","dst":"127.0.0.1:8801"`),
		line(ra, "watch", 3, t0.Add(3*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	writeRun(t, root, rb,
		line(rb, "guard", 0, t0, "run_start", `"tier":"landlock","cwd":"/d/with/proj","command":["codex"]`),
		line(rb, "guard", 1, t0.Add(time.Second), "fs", `"verdict":"refused","rule":"fs.deny_read[/d/with/home/.ssh/]","op":"open","path":"/d/with/home/.ssh/id_rsa"`),
		line(rb, "guard", 2, t0.Add(2*time.Second), "net", `"verdict":"refused","rule":"unmatched","proto":"tcp","dst":"127.0.0.1:8802"`),
		line(rb, "guard", 3, t0.Add(3*time.Second), "ask", `"ask_id":"q-1","hold":"open","op":"read","target":"/d/with/proj/confidential/plan.md","ask_rule":"fs.ask_read[./confidential/]"`),
		line(rb, "guard", 4, t0.Add(4*time.Second), "answer", `"ask_id":"q-1","by":"uid:1000 pid:7","approved":true,"ask_rule":"fs.ask_read[./confidential/]","op":"read","target":"/d/with/proj/confidential/plan.md"`),
		line(rb, "guard", 5, t0.Add(4*time.Second), "fs", `"verdict":"allow","rule":"fs.ask_read[./confidential/]","op":"open","path":"/d/with/proj/confidential/plan.md"`),
		line(rb, "guard", 6, t0.Add(5*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	c := Compare(s.Find(ra), s.Find(rb), false)
	if !strings.Contains(c.Summary, "Run B (guard, enforced by Tego) read 1 file a person allowed (confidential/plan.md) and made no off-list connection") {
		t.Errorf("the summary says %q", c.Summary)
	}
	if strings.Contains(c.Summary, "Run B (guard, enforced by Tego) read 1 secret file") {
		t.Error("the summary counts the file a person allowed as a secret file read")
	}
	if !strings.Contains(c.Summary, "Run A (watch, watched) read 1 secret file and made 1 off-list connection") {
		t.Errorf("the watched side's sentence changed: %q", c.Summary)
	}
	both := CmpSide{SecretsOpened: 1, SecretsAllowed: 1, AllowedNames: []string{"confidential/plan.md"}}
	if got := both.did(); !strings.HasPrefix(got, "read 1 secret file and 1 file a person allowed (confidential/plan.md), and made no off-list connection") {
		t.Errorf("both kinds read %q", got)
	}
}
