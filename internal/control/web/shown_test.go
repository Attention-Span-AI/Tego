// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// TestMaskHidesCredentials: a row masks what looks like a credential in a command line and keeps the rest.
func TestMaskHidesCredentials(t *testing.T) {
	for in, want := range map[string]string{
		"curl -s -H Authorization: Bearer svc_demo_FAKE_SERVICE_TOKEN_0000 -d ok http://x": "curl -s -H Authorization: Bearer •••• -d ok http://x",
		"tool --token abcdef123456 --verbose":                                              "tool --token •••• --verbose",
		"tool --password=hunter22":                                                         "tool --password=••••",
		"curl https://api.x/v1?api_key=AAAABBBBCCCC&q=1":                                   "curl https://api.x/v1?api_key=••••&q=1",
		"git clone https://me:s3cretpass@github.com/x/y":                                   "git clone https://me:••••@github.com/x/y",
		"echo sk-abcdefghijklmnopqrstuvwx":                                                 "echo sk-a••••",
		"cat /home/me/.config/telemetry/token /etc/hosts":                                  "cat /home/me/.config/telemetry/token /etc/hosts",
		"python3 -m unittest -v":                                                           "python3 -m unittest -v",
		"curl -H 'Authorization: Basic dXNlcjpwYXNz' http://x":                             "curl -H 'Authorization: Basic ••••' http://x",
		"curl -H \"Token abcdef123456\" http://x":                                          "curl -H \"Token ••••\" http://x",
		"wget --header Bearer abcdef123456 http://x":                                       "wget --header Bearer •••• http://x",
		"echo token generated":                                                             "echo token generated",
		"pip install basic requests":                                                       "pip install basic requests",
	} {
		if got := mask(in); got != want {
			t.Errorf("mask(%q)\n = %q\nwant %q", in, got, want)
		}
	}
}

// TestWhoNamesPeople: a ledger principal reads as a person's name, with where they acted.
func TestWhoNamesPeople(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skip("no current user")
	}
	if got := who("uid:" + u.Uid + " pid:1754516 dashboard"); got != u.Username+", from the dashboard" {
		t.Errorf("who(dashboard) = %q", got)
	}
	if got := who("uid:" + u.Uid + " pid:1"); got != u.Username {
		t.Errorf("who(cli) = %q", got)
	}
	if got := who("uid:4000000000 pid:1"); got != "user 4000000000" {
		t.Errorf("who(unknown uid) = %q", got)
	}
	if got := who("human"); got != "human" {
		t.Errorf("who(human) = %q", got)
	}
}

// TestShownRows: an answer row says what was answered and by whom, a host that only repeats the address is dropped,
// and a held open under fs.ask is a write.
func TestShownRows(t *testing.T) {
	ans := ledgerview.Event{Kind: "answer", Raw: `{"ask_id":"q-1","approved":false,"answer_reason":"ask-denied","by":"human","after_s":89.06}`}
	// The answer is the row's operation; its text is what it answered (none on this line).
	if got, op := shown(ans), shownOp(ans); got != "" || op != "Denied by human after 1\u00a0m\u00a029\u00a0s" {
		t.Errorf("answer row %q %q", op, got)
	}
	if got := shown(ledgerview.Event{Kind: "net", Target: "127.0.0.1 (127.0.0.1:59465)"}); got != "127.0.0.1:59465" {
		t.Errorf("net row %q", got)
	}
	if got := shown(ledgerview.Event{Kind: "net", Target: "example.com (93.184.216.34:443)"}); got != "example.com (93.184.216.34:443)" {
		t.Errorf("named net row %q", got)
	}
	if v := askVerb("open", "fs.ask[./held/]", "open"); v != "write to" {
		t.Errorf("a held open under fs.ask reads %q, want write to", v)
	}
	if v := askVerb("open", "fs.ask_read[/p/]", "open"); v != "read" {
		t.Errorf("a held open under fs.ask_read reads %q, want read", v)
	}
}

// liveBlockFixture is fixture plus, on the live run, a live block of ls added from the dashboard, the exec it refused
// (the action line and its mirror), and an answered ask.
func liveBlockFixture(t *testing.T) string {
	t.Helper()
	root := fixture(t)
	t0 := time.Date(2026, 10, 25, 12, 1, 10, 0, time.UTC)
	f, err := os.OpenFile(filepath.Join(root, harmRun, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	for _, l := range []string{
		line(harmRun, "demo-harm", 7, t0, "gap", `"what":"enforce","why":"live-block-added","live_block":{"op":"add","kind":"exec","value":"ls","rule":"live.block[exec:ls]","by":"uid:4000000000 pid:9 dashboard","serial":1,"at":"2026-10-25T12:01:10Z"}`),
		line(harmRun, "demo-harm", 8, t0.Add(time.Second), "exec", `"verdict":"refused","rule":"live.block[exec:ls]","reason":"exec-not-allowed","argv":["ls","-la"],"path":"/usr/bin/ls"`),
		line(harmRun, "demo-harm", 9, t0.Add(time.Second), "refused", `"rule":"live.block[exec:ls]","reason":"exec-not-allowed","op":"exec","target":"/usr/bin/ls"`),
		line(harmRun, "demo-harm", 10, t0.Add(2*time.Second), "ask", `"ask_id":"q-2","ask_rule":"fs.ask[./held/]","hold":"open","op":"open","target":"/p/held/note.md"`),
		line(harmRun, "demo-harm", 11, t0.Add(3*time.Second), "answer", `"ask_id":"q-2","ask_rule":"fs.ask[./held/]","approved":true,"by":"uid:4000000000 pid:9","after_s":1,"op":"open","target":"/p/held/note.md"`),
	} {
		if _, err := f.WriteString(l); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// TestLiveBlockRowsSayWhoBlocked: a refusal of a live block reads "Blocked live at … by …", never the contract's
// "A command the contract does not allow"; the block row and the answer row name the person; Approvals lists the
// answer under Answered recently.
func TestLiveBlockRowsSayWhoBlocked(t *testing.T) {
	s := newServer(t, liveBlockFixture(t))
	c := login(t, s)
	run := do(s, "GET", "/runs/"+harmRun, "127.0.0.1:8484", c).Body.String()
	for _, want := range []string{"Blocked live at ", "by user 4000000000, from the dashboard", "ls, blocked live by user 4000000000", "Allowed once by user 4000000000"} {
		if !strings.Contains(run, want) {
			t.Errorf("the run page lacks %q", want)
		}
	}
	for _, bad := range []string{"A command the contract does not allow", "uid:4000000000", "exit exit"} {
		if strings.Contains(run, bad) {
			t.Errorf("the run page says %q", bad)
		}
	}
	logs := do(s, "GET", "/logs?q=ls", "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(logs, "Blocked live at ") {
		t.Error("Logs does not say the refusal was a live block")
	}
	ap := do(s, "GET", "/approvals", "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(ap, "Answered recently") || !strings.Contains(ap, `asked to <span class="op" title="open">write to</span>`) {
		t.Error("Approvals lacks the recent answer, or reads a held write as something else")
	}
}

// TestRunHeaderSaysWhoAndWhichRules: the run header says who started the run and which rules it ran under, or, for a
// run with no contract file (tego watch), that nothing was enforced.
func TestRunHeaderSaysWhoAndWhichRules(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	b := do(s, "GET", "/runs/"+harmRun, "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(b, `<p class="run-who"><b title="Started by">`) || !strings.Contains(b, `<span class="watch-only">Watched only</span>`) {
		t.Error("a run with no contract file does not say who started it and that it was watched only")
	}
}

// TestRefusalPagesMaskCredentials: a refused command line with a credential in it reads masked on every page that
// summarises it (the timeline, the Refusals tab in both views, Logs, the Overview, Detections), not only on the timeline.
func TestRefusalPagesMaskCredentials(t *testing.T) {
	root := fixture(t)
	const run = "r-aaaaaaaa-0000000000003-maskxx"
	t0 := time.Date(2026, 10, 25, 13, 0, 0, 0, time.UTC)
	ls := []string{
		line(run, "demo-mask", 0, t0, "run_start", `"tier":"landlock","command":["sh"]`),
		line(run, "demo-mask", 1, t0.Add(time.Second), "refused", `"rule":"unmatched","reason":"exec-not-allowed","op":"exec","target":"curl -H Authorization: Bearer svc_demo_FAKE_SERVICE_TOKEN_0000 http://x"`),
		line(run, "demo-mask", 2, t0.Add(2*time.Second), "run_end", `"reason":"exit","exit_code":0`),
	}
	if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	for _, page := range []string{"/runs/" + run, "/runs/" + run + "/refusals", "/runs/" + run + "/refusals?view=lines", "/logs", "/", "/detections"} {
		b := do(s, "GET", page, "127.0.0.1:8484", c).Body.String()
		if i := strings.Index(b, "svc_demo_FAKE_SERVICE_TOKEN_0000"); i >= 0 {
			t.Errorf("%s shows the credential in clear: …%s…", page, b[max(0, i-200):i])
		}
		// The grouped views name an exec by its program, so they show no command line at all.
		if (page == "/runs/"+run || strings.Contains(page, "view=lines") || page == "/logs") && !strings.Contains(b, "Bearer ••••") {
			t.Errorf("%s does not show the masked command", page)
		}
	}
}

// TestInvestigateMasksTheSubject: a subject with a credential in it reads masked in the page's title and body and stays
// out of its links' addresses, on Detections and on Investigate.
func TestInvestigateMasksTheSubject(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000011-maskiv"
	const token = "svc_demo_FAKE_SERVICE_TOKEN_0000"
	s := newServer(t, detectionsRoot(t, run, "landlock",
		[2]string{"refused", `"rule":"unmatched","reason":"write-outside-contract","op":"open","target":"/w/proj/Authorization: Bearer ` + token + `"`}))
	c := login(t, s)
	list := get(t, s, c, "/detections")
	m := investigateLink.FindStringSubmatch(list)
	if m == nil {
		t.Fatalf("no Investigate link:\n%s", list)
	}
	page := get(t, s, c, m[1])
	for what, b := range map[string]string{"Detections": list, "Investigate": page} {
		if i := strings.Index(b, token); i >= 0 {
			t.Errorf("%s shows the credential in clear: …%s…", what, b[max(0, i-200):i])
		}
	}
	if !regexp.MustCompile(`<title>[^<]*Bearer ••••`).MatchString(page) {
		t.Errorf("the title does not read masked:\n%s", page)
	}
	if !strings.Contains(page, `href="/logs?run=`+run+`&amp;verdict=refused"`) {
		t.Errorf("the Logs link does not fall back to the run's blocked lines:\n%s", page)
	}
}

// TestSplitAsksFoldsRepeats: the Highlights Approvals card leads with a waiting ask, then people's answers up to its
// cut, and folds Tego's at-once repeats of a "for this run" answer, which a long run writes by the hundred.
func TestSplitAsksFoldsRepeats(t *testing.T) {
	apps := []ledgerview.Approval{{AskID: "a1", State: "approved", By: "uid:1000 always"}}
	for i := 0; i < 50; i++ {
		apps = append(apps, ledgerview.Approval{AskID: "s", State: "approved", By: "standing:a1"})
	}
	apps = append(apps, ledgerview.Approval{AskID: "a2", State: "denied", By: "uid:1000"}, ledgerview.Approval{AskID: "a3", State: "pending"})
	got := splitAsks(apps, 2)
	if len(got.Head) != 2 || got.Head[0].AskID != "a3" || got.Head[1].AskID != "a1" || len(got.More) != 1 || got.More[0].AskID != "a2" || len(got.Repeats) != 50 {
		t.Errorf("head %v, more %v, %d repeats", got.Head, got.More, len(got.Repeats))
	}
}
