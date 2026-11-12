// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSameFileRowSaysWhy: a live block on /bin/ls refused /bin/sleep, another name of the same program file on a
// multi-call host; the refused row names /bin/sleep and the rule names /bin/ls, so the row says why, on the run page
// and in Logs: "same program file as /bin/ls, which is blocked" (liveblock.SameFileNote, which says nothing of the
// refusal of /bin/ls itself).
func TestSameFileRowSaysWhy(t *testing.T) {
	root := fixture(t)
	t0 := time.Date(2026, 10, 25, 12, 1, 10, 0, time.UTC)
	f, err := os.OpenFile(filepath.Join(root, harmRun, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{
		line(harmRun, "demo-harm", 7, t0, "gap", `"what":"enforce","why":"live-block-added","live_block":{"op":"add","kind":"exec","value":"/bin/ls","rule":"live.block[exec:/bin/ls]","by":"uid:4000000000 pid:9 dashboard","serial":1,"at":"2026-10-25T12:01:10Z"}`),
		line(harmRun, "demo-harm", 8, t0.Add(time.Second), "exec", `"verdict":"refused","rule":"live.block[exec:/bin/ls]","reason":"exec-not-allowed","argv":["/bin/sleep","0.1"],"path":"/bin/sleep"`),
		line(harmRun, "demo-harm", 9, t0.Add(2*time.Second), "exec", `"verdict":"refused","rule":"live.block[exec:/bin/ls]","reason":"exec-not-allowed","argv":["/bin/ls"],"path":"/bin/ls"`),
	} {
		if _, err := f.WriteString(l); err != nil {
			t.Fatal(err)
		}
	}
	_ = f.Close()
	s := newServer(t, root)
	c := login(t, s)
	const why = "same program file as /bin/ls, which is blocked"
	for _, page := range []string{"/runs/" + harmRun, "/logs?q=sleep"} {
		body := html.UnescapeString(do(s, "GET", page, "127.0.0.1:8484", c).Body.String())
		if !strings.Contains(body, why) {
			t.Errorf("%s does not say why /bin/sleep was refused", page)
		}
	}
	// One line's own page: the /bin/sleep line says it, the /bin/ls line, refused by its own name, does not.
	for _, l := range []struct {
		seq  string
		says bool
	}{{"8", true}, {"9", false}} {
		page := "/runs/" + harmRun + "/lines/" + l.seq
		body := html.UnescapeString(do(s, "GET", page, "127.0.0.1:8484", c).Body.String())
		if !strings.Contains(body, "live.block[exec:/bin/ls]") && !strings.Contains(body, "Blocked live") {
			t.Fatalf("%s does not show the line's block", page)
		}
		if got := strings.Contains(body, why); got != l.says {
			t.Errorf("%s says %q: %v, want %v", page, why, got, l.says)
		}
	}
}
