// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestReceiptTabNamesTheFrozenDirectories (GAPS A12): the Receipt tab names, under what the receipt can vouch for, the
// directories run_start's deny_read_frozen names, in the words `tego receipt` prints, so the page and the terminal do
// not disagree. A run_start without the field shows no such line.
func TestReceiptTabNamesTheFrozenDirectories(t *testing.T) {
	const run, plain = "r-aaaaaaaa-0000000000052-frozen", "r-aaaaaaaa-0000000000053-nofrzn"
	root := t.TempDir()
	t0 := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	write := func(id, start string) {
		t.Helper()
		ls := line(id, "demo", 0, t0, "run_start", start) +
			line(id, "demo", 1, t0.Add(time.Second), "run_end", `"reason":"exit","exit_code":0`)
		if err := os.MkdirAll(filepath.Join(root, id), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, id, "events.jsonl"), []byte(ls), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(run, `"tier":"landlock","command":["true"],"record_minor":30,"deny_read_frozen":{"dirs":["/","/home","/home/u"],"omitted":2}`)
	write(plain, `"tier":"landlock","command":["true"],"record_minor":30`)
	s := newServer(t, root)
	c := login(t, s)
	const want = "Frozen at launch: deny_read listed /, /home, /home/u and 2 more once; a file or directory made directly " +
		"in one of them during the run could not be read."
	if page := get(t, s, c, "/runs/"+run+"/receipt"); !strings.Contains(page, want) {
		t.Errorf("the Receipt tab lacks %q", want)
	}
	if page := get(t, s, c, "/runs/"+plain+"/receipt"); strings.Contains(page, "Frozen at launch") {
		t.Error("a run_start without deny_read_frozen shows a frozen line")
	}
}
