// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"testing"
	"time"
)

// Compare worded a held write "open", as the ask lines call the hold; the row's note names what the person was asked to
// allow (linewords.AskOp), a write for an fs.ask entry and a read for an fs.ask_read one.
func TestCompareWordsAHeldWriteAsAWrite(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	const ra, rb = "r-aaaa-0001-watchx", "r-aaaa-0002-guardx"
	writeRun(t, root, ra, line(ra, "watch", 0, t0, "run_start", `"tier":"observe","cwd":"/d/p","command":["codex"]`),
		line(ra, "watch", 1, t0.Add(time.Second), "run_end", `"reason":"exit","exit_code":0`))
	writeRun(t, root, rb, line(rb, "guard", 0, t0, "run_start", `"tier":"landlock","cwd":"/d/p","command":["codex"]`),
		line(rb, "guard", 1, t0.Add(time.Second), "ask", `"ask_id":"q-1","hold":"open","op":"open","target":"/d/p/out/a.txt","ask_rule":"fs.ask[./out/]"`),
		line(rb, "guard", 2, t0.Add(2*time.Second), "answer", `"ask_id":"q-1","by":"human","approved":true`),
		line(rb, "guard", 3, t0.Add(3*time.Second), "ask", `"ask_id":"q-2","hold":"open","op":"open","target":"/d/p/docs/b.md","ask_rule":"fs.ask_read[./docs/]"`),
		line(rb, "guard", 4, t0.Add(4*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range Compare(s.Find(ra), s.Find(rb), true).Rows {
		if r.Class == ClassAsk {
			got[r.Target] = r.Note
		}
	}
	if len(got) != 2 {
		t.Fatalf("ask rows: %v", got)
	}
	for _, note := range got {
		if note != "write" && note != "read" {
			t.Errorf("a held open is worded %q: %v", note, got)
		}
	}
}
