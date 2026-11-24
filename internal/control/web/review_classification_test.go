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

func TestProtectedReadChipsAgreeWithRunAndContract(t *testing.T) {
	for i, tc := range []struct {
		name, path, want string
		send, failed     bool
	}{
		{"own login", "/home/u/.codex/auth.json", "neutral i-check Allowed", false, false},
		{"own login next to send", "/home/u/.codex/auth.json", "neutral i-check Allowed", true, false},
		{"contract secret", "/p/workpapers/plan.data", "through i-triangle-alert Read allowed", false, false},
		{"contract secret next to send", "/p/workpapers/plan.data", "through i-triangle-alert Read allowed", true, false},
		{"contract secret failed open", "/p/workpapers/plan.data", "allowed i-check Allowed", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if strings.HasPrefix(tc.name, "contract secret") && ledgerview.IsSecretPath(tc.path) {
				t.Fatal("fixture must be sensitive only through the contract")
			}
			run := fmt.Sprintf("r-aaaaaaaa-0000000000091-read%02d", i)
			root := t.TempDir()
			dir := filepath.Join(root, run)
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			t0 := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
			ls := []string{
				line(run, "codex", 0, t0, "run_start", `"tier":"landlock","capture":"forwarder","command":["codex"],"cwd":"/p"`),
				line(run, "codex", 1, t0.Add(time.Second), "fs", `"rule":"unmatched","verdict":"allow","op":"open","flags":0,"path":"`+tc.path+`"`),
				line(run, "codex", 2, t0.Add(2*time.Second), "run_end", `"reason":"exit","exit_code":0`),
			}
			if tc.failed {
				ls[1] = line(run, "codex", 1, t0.Add(time.Second), "fs", `"rule":"unmatched","verdict":"allow","op":"open","flags":0,"path":"`+tc.path+`","syscall_ret":-13`)
			}
			if tc.send {
				ls = append(ls[:2], line(run, "codex", 2, t0.Add(1500*time.Millisecond), "net", `"rule":"unmatched","verdict":"allow","dst":"203.0.113.9:443","proto":"tcp"`), line(run, "codex", 3, t0.Add(2*time.Second), "run_end", `"reason":"exit","exit_code":0`))
			}
			if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(strings.Join(ls, "")), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), []byte("version: 0\nagent: codex\nfs:\n  deny_read:\n    - ./workpapers/\n"), 0600); err != nil {
				t.Fatal(err)
			}
			s := newServer(t, root)
			c := login(t, s)
			timeline := get(t, s, c, "/runs/"+run)
			event := get(t, s, c, "/runs/"+run+"/lines/1")
			logs := get(t, s, c, "/logs?run="+run)
			live := get(t, s, c, "/runs/"+run+"/rows?after=0")
			receipt := get(t, s, c, "/runs/"+run+"/receipt")
			for _, v := range []struct{ name, page, from, to string }{
				{"Run", pageElement(t, timeline, "id", "l1"), `<span class="tl-end">`, "</div>"},
				{"Run phone", pageElement(t, timeline, "id", "l1"), `<a class="phone-row run-event-row"`, "</a>"},
				{"Event", event, `<p class="ev-lede">`, "</p>"},
				{"Event facts", event, `<h2 id="h-facts">What happened</h2>`, "</div>"},
				{"Event context", event, `aria-current="true"><span class="mono ev-seq">#1`, "</li>"},
				{"Run live", pageElement(t, live, "id", "l1"), `<span class="tl-end">`, "</div>"},
				{"Logs", logs, `data-k="` + run + `-1"`, "</tr>"},
			} {
				if got := chipIn(t, v.name, v.page, v.from, v.to); got != tc.want {
					t.Errorf("%s chip %q, want %q", v.name, got, tc.want)
				}
			}
			if tc.failed {
				sensitive := pageElement(t, receipt, "class", "panel-body rc-block rc-sens")
				if strings.Contains(sensitive, `class="rc-chips"`) {
					t.Fatalf("failed open listed as sensitive read: %s", sensitive)
				}
				return
			}
			start := strings.Index(receipt, `class="rc-chips"`)
			if start < 0 {
				t.Fatal("receipt has no sensitive read chips")
			}
			end := strings.Index(receipt[start:], "</li>")
			part := receipt[start : start+end]
			class, rest, _ := strings.Cut(tc.want, " ")
			icon, word, _ := strings.Cut(rest, " ")
			if !strings.Contains(part, `class="b b-`+class+`"`) || !strings.Contains(part, `sprite.svg#`+icon+`"`) || !strings.Contains(part, word+` 1</span>`) {
				t.Errorf("Receipt chip differs: %s", part)
			}
		})
	}
}

func TestSensitiveReadRecordedUsesActualReadChips(t *testing.T) {
	const path = "/home/u/.codex/auth.json"
	for _, tc := range []struct {
		name, readVerdict, writeVerdict string
		want                            bool
	}{
		{"allowed own login and observed write", "allow", "observed", false},
		{"observed own login and allowed write", "observed", "allow", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &ledgerview.Run{Command: "codex", Events: []ledgerview.Event{
				{Kind: "fs", Verdict: tc.readVerdict, Target: path, Raw: `{"op":"open","flags":0}`},
				{Kind: "fs", Verdict: tc.writeVerdict, Target: path, Raw: `{"op":"open","flags":1}`},
			}}
			sig := &ledgerview.RunSignal{Secrets: []ledgerview.SecretTouch{{Path: path, Allowed: 1, Observed: 1, Unread: 1}}}
			if got := sensitiveReadRecorded(r, sig); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
