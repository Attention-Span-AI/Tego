// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// Historical rows must classify their own reads even after the newest retained
// window has lost every sensitive path. The Event and Receipt are independent
// readers of the same full record and keep the same own-login exception.
func TestHistoricalProtectedReadParity(t *testing.T) {
	for i, tc := range []struct {
		name, path, verdict, want string
	}{
		{"built-in secret", "/home/u/.ssh/id_rsa", "allow", "through i-triangle-alert Read allowed"},
		{"own login allowed", "/home/u/.codex/auth.json", "allow", "neutral i-check Allowed"},
		{"own login observed", "/home/u/.codex/auth.json", "observed", "through i-triangle-alert Read, not refused"},
		{"contract secret", "/p/workpapers/plan.data", "allow", "through i-triangle-alert Read allowed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "contract secret" && ledgerview.IsSecretPath(tc.path) {
				t.Fatal("fixture must be sensitive only through the contract")
			}
			root := t.TempDir()
			run := fmt.Sprintf("r-aaaaaaaa-0000000000093-old%03d", i)
			dir := filepath.Join(root, run)
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			t0 := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
			var lines strings.Builder
			lines.WriteString(line(run, "codex", 0, t0, "run_start", `"tier":"landlock","capture":"forwarder","command":["codex"],"cwd":"/p"`))
			lines.WriteString(line(run, "codex", 1, t0.Add(time.Millisecond), "fs", `"rule":"unmatched","verdict":"`+tc.verdict+`","op":"open","flags":0,"path":"`+tc.path+`"`))
			for seq := 2; seq < 33002; seq++ {
				lines.WriteString(line(run, "codex", seq, t0.Add(time.Duration(seq)*time.Millisecond), "fs", `"rule":"unmatched","verdict":"allow","op":"open","flags":0,"path":"/usr/lib/routine.data"`))
			}
			lines.WriteString(line(run, "codex", 33002, t0.Add(34*time.Second), "run_end", `"reason":"exit","exit_code":0`))
			if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(lines.String()), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte("version: 0\nagent: codex\nfs:\n  deny_read:\n    - ./workpapers/\n"), 0600); err != nil {
				t.Fatal(err)
			}
			r, err := ledgerview.LoadRun(root, run)
			if err != nil {
				t.Fatal(err)
			}
			if !r.Cut {
				t.Fatal("fixture did not truncate the newest event window")
			}
			for _, e := range r.AllEvents() {
				if e.Seq == 1 {
					t.Fatal("sensitive read unexpectedly remains in the newest event window")
				}
			}
			s := newServer(t, root)
			cookie := login(t, s)
			timeline := get(t, s, cookie, "/runs/"+run+"?before=100")
			event := get(t, s, cookie, "/runs/"+run+"/lines/1")
			rc := get(t, s, cookie, "/runs/"+run+"/receipt")
			row := pageElement(t, timeline, "id", "l1")
			for _, v := range []struct{ name, page, from, to string }{
				{"historical desktop", row, `<span class="tl-end">`, "</div>"},
				{"historical phone", row, `<a class="phone-row run-event-row"`, "</a>"},
				{"Event", event, `<p class="ev-lede">`, "</p>"},
				{"Event context", event, `aria-current="true"><span class="mono ev-seq">#1`, "</li>"},
			} {
				if got := chipIn(t, v.name, v.page, v.from, v.to); got != tc.want {
					t.Errorf("%s chip %q, want %q", v.name, got, tc.want)
				}
			}
			start := strings.Index(rc, `class="rc-chips"`)
			if start < 0 {
				t.Fatal("Receipt has no sensitive read chips")
			}
			end := strings.Index(rc[start:], "</li>")
			if end < 0 {
				t.Fatal("Receipt sensitive read has no closing row")
			}
			part := rc[start : start+end]
			class, rest, _ := strings.Cut(tc.want, " ")
			icon, word, _ := strings.Cut(rest, " ")
			if !strings.Contains(part, `class="b b-`+class+`"`) || !strings.Contains(part, `sprite.svg#`+icon+`"`) || !strings.Contains(part, word+` 1</span>`) {
				t.Errorf("Receipt chip differs: %s", part)
			}
		})
	}
}
