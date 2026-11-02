// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/liveblock"
)

const (
	leftRun  = "r-aaaaaaaa-0000000000021-leftxx"
	rightRun = "r-aaaaaaaa-0000000000022-rightx"
	lostRun  = "r-aaaaaaaa-0000000000023-lostxx"
	askRun   = "r-aaaaaaaa-0000000000024-askxxx"
)

// storyFixture is the supply-chain demo as the QA lane recorded it, in small: LEFT watched (robbed: the key and the
// token read next to sends to its sink), RIGHT enforced (both reads and both sends refused, the token asked first),
// a lost run with an open ask, and a live run with an ask waiting.
func storyFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	write := func(run, contract string, ls ...string) {
		if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
			t.Fatal(err)
		}
		if contract != "" {
			if err := os.WriteFile(filepath.Join(root, run, "contract.yaml"), []byte(contract), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	const user = `"launcher_user":"alice","launcher_uid":1000`
	write(leftRun, "fs:\n  write:\n    - ./\n",
		line(leftRun, "watch-codex", 0, at(0), "run_start", `"tier":"observe","command":["codex"],"cwd":"/d/without/proj",`+user),
		line(leftRun, "watch-codex", 1, at(1), "net", `"rule":"unmatched","verdict":"observed","dst":"127.0.0.1:45805","proto":"tcp"`),
		line(leftRun, "watch-codex", 2, at(1), "fs", `"rule":"unmatched","verdict":"observed","op":"open","flags":524288,"path":"/d/without/home/.ssh/id_rsa"`),
		line(leftRun, "watch-codex", 3, at(1), "fs", `"rule":"unmatched","verdict":"observed","op":"open","flags":524288,"path":"/d/without/home/.config/telemetry/token"`),
		line(leftRun, "watch-codex", 4, at(1), "net", `"rule":"unmatched","verdict":"observed","dst":"127.0.0.1:45805","proto":"tcp"`),
		// The project's own API, which the enforced run's contract allows, a line after the sends.
		line(leftRun, "watch-codex", 5, at(1), "net", `"rule":"unmatched","verdict":"observed","dst":"127.0.0.1:59465","proto":"tcp"`),
		line(leftRun, "watch-codex", 6, at(1), "net", `"rule":"net.resolver","verdict":"observed","dst":"127.0.0.53:53","proto":"udp"`),
		line(leftRun, "watch-codex", 7, at(2), "run_end", `"reason":"exit","exit_code":0`))
	write(rightRun, "fs:\n  ask:\n    - ./held/\n  deny_read:\n    - /d/with/home/.ssh/\n  ask_read:\n    - /d/with/home/.config/telemetry/\nnet:\n  allow:\n    - 127.0.0.1:59465\n",
		line(rightRun, "codex-tego", 0, at(60), "run_start", `"tier":"landlock","command":["codex"],"cwd":"/d/with/proj",`+user),
		line(rightRun, "codex-tego", 1, at(61), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"127.0.0.1:43437"`),
		line(rightRun, "codex-tego", 2, at(61), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"127.0.0.1:43437"`),
		line(rightRun, "codex-tego", 3, at(61), "refused", `"rule":"fs.deny_read[/d/with/home/.ssh/]","reason":"read-denied","op":"open","target":"/d/with/home/.ssh/id_rsa"`),
		line(rightRun, "codex-tego", 4, at(61), "ask", `"ask_id":"q-1","ask_rule":"fs.ask_read[/d/with/home/.config/telemetry/]","hold":"open","op":"read","target":"/d/with/home/.config/telemetry/token"`),
		line(rightRun, "codex-tego", 5, at(90), "answer", `"ask_id":"q-1","approved":false,"by":"uid:1000 pid:42","after_s":29.0`),
		line(rightRun, "codex-tego", 6, at(90), "refused", `"rule":"fs.ask_read[/d/with/home/.config/telemetry/]","reason":"ask-denied","op":"open","target":"/d/with/home/.config/telemetry/token"`),
		line(rightRun, "codex-tego", 7, at(91), "net", `"rule":"net[127.0.0.1:59465]","verdict":"allow","dst":"127.0.0.1:59465","host":"127.0.0.1","proto":"tcp"`),
		line(rightRun, "codex-tego", 8, at(92), "run_end", `"reason":"exit","exit_code":0`))
	write(lostRun, "",
		line(lostRun, "crashed", 0, at(120), "run_start", `"tier":"landlock","command":["sh"],"cwd":"/d/loop"`),
		line(lostRun, "crashed", 1, at(121), "ask", `"ask_id":"q-9","ask_rule":"fs.ask[/d/loop/held/]","hold":"open","op":"write","target":"/d/loop/held/note.md"`))
	write(askRun, "",
		line(askRun, "asker", 0, at(200), "run_start", `"tier":"landlock","command":["sh"],"cwd":"/d/ask"`),
		line(askRun, "asker", 1, at(290), "ask", `"ask_id":"q-5","ask_rule":"fs.ask_read[/d/ask/confidential/]","hold":"open","op":"read","target":"/d/ask/confidential/plan.md"`))
	if err := os.MkdirAll(filepath.Join(root, ".live"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".live", askRun), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestStoryRunPagesSayWhatHappened(t *testing.T) {
	s := newServer(t, storyFixture(t))
	c := login(t, s)

	left := get(t, s, c, "/runs/"+leftRun)
	for _, want := range []string{
		`verdict-leak`, "Secrets left: id_rsa, token sent to 127.0.0.1:45805",
		"Secrets left: ", "Watched only · nothing blocked",
		"Got through", watchedLabel,
		// The run's home (without/home, beside without/proj) reads as ~/, the file name in bold.
		`<span class="sp-d">~/<wbr>.ssh/</span><wbr><b class="sp-b">id_rsa</b>`, `title="/d/without/home/.ssh/id_rsa"`,
	} {
		if !strings.Contains(left, want) {
			t.Errorf("LEFT run page lacks %q", want)
		}
	}
	if strings.Contains(left, "In policy") {
		t.Error("a watched run says In policy")
	}
	// The watched run is read against the enforced run's contract: its own API is allowed there, so it is neither
	// "Got through" nor "After a secret read", and the card names the run whose contract it was checked against.
	lhl := left[strings.Index(left, `id="h-hl-o"`):strings.Index(left, `id="h-hl-a"`)]
	if i := strings.Index(lhl, "127.0.0.1:59465"); i < 0 {
		t.Error("LEFT Outbound lacks the API")
	} else if api := lhl[i:min(len(lhl), i+700)]; strings.Contains(api[:strings.Index(api, "</li>")], "Got through") ||
		strings.Contains(api[:strings.Index(api, "</li>")], "After a secret read") || !strings.Contains(api, "Allowed in the enforced run") {
		t.Errorf("LEFT marks the allowed API as part of the theft: %s", api)
	}
	if !strings.Contains(lhl, "Checked against <a") {
		t.Error("LEFT does not say which contract its sends were checked against")
	}

	right := get(t, s, c, "/runs/"+rightRun)
	for _, want := range []string{
		`verdict-ok`, "Protected: 2 secret reads and 2 sends to 127.0.0.1:43437 blocked", "1 request asked",
		// The answer names the person (the run recorded uid 1000 as alice), never "uid:1000 pid:42".
		"by alice after 29 s", "Denied by " + who("uid:1000") + " after 29\u00a0s",
	} {
		if !strings.Contains(right, want) {
			t.Errorf("RIGHT run page lacks %q", want)
		}
	}
	if strings.Contains(right, "uid:1000") {
		t.Error("the RIGHT run page shows a raw principal")
	}
	// The contract's own API, allowed right after the token read, is not marked next to a secret.
	hl := right[strings.Index(right, `id="h-hl-o"`):strings.Index(right, `id="h-hl-a"`)]
	if api := hl[strings.Index(hl, "127.0.0.1:59465"):]; strings.Contains(api[:min(len(api), 600)], "After a secret read") {
		t.Error("the allowed API is marked next to a secret")
	}

	// A lost run's ask is never waiting: no ask card, the Approvals card says it was never answered.
	lost := get(t, s, c, "/runs/"+lostRun)
	if strings.Contains(lost, `class="ask"`) || !strings.Contains(lost, "Never answered (run lost)") {
		t.Error("the lost run's ask is shown as waiting")
	}
	// An fs.ask folder is a write folder, not a secret.
	if strings.Contains(lost, "note.md</b></a><span class=\"hl-v\">") {
		t.Error("an fs.ask write folder is listed as a secret")
	}

	// Least privilege on an enforced run keeps every deny and ask entry; tego learn's from-scratch proposal is
	// folded below it. A watched run keeps the proposal only.
	lp := get(t, s, c, "/runs/"+rightRun+"/least-privilege")
	for _, want := range []string{"Keep: your protections", "Never readable: /d/with/home/.ssh/",
		"Asks before a read: /d/with/home/.config/telemetry/", "Asks before a change: ./held/", `class="lp-learn"`} {
		if !strings.Contains(lp, want) {
			t.Errorf("enforced Least privilege lacks %q", want)
		}
	}
	if lpl := get(t, s, c, "/runs/"+leftRun+"/least-privilege"); strings.Contains(lpl, "Keep: your protections") || strings.Contains(lpl, `class="lp-learn"`) {
		t.Error("a watched run's Least privilege shows the enforced view")
	}
}

func TestStoryOverviewRunsLogs(t *testing.T) {
	s := newServer(t, storyFixture(t))
	c := login(t, s)

	ov := get(t, s, c, "/")
	for _, want := range []string{
		"1 needs you", ">2 exposed<", ">2 protected<", ">Compare</a>",
		"/compare?a=" + leftRun + "&amp;b=", " routine</span>",
		// The Recent refusals keep the file name: ~/.ssh/id_rsa, not the start of its folder.
		`<b class="sp-b">id_rsa</b>`, `<b class="sp-b">token</b>`,
	} {
		if !strings.Contains(ov, want) {
			t.Errorf("Overview lacks %q", want)
		}
	}
	runs := get(t, s, c, "/runs")
	if !strings.Contains(runs, ">Secrets</th>") || !strings.Contains(runs, ">2 exposed<") || !strings.Contains(runs, ">2 protected<") {
		t.Error("the Runs page has no Secrets column with the verdicts")
	}

	logs := get(t, s, c, "/logs?q=id_rsa")
	for _, want := range []string{`<b class="sp-b">id_rsa</b>`, watchedLabel, "Never read"} {
		if !strings.Contains(logs, want) {
			t.Errorf("Logs for id_rsa lack %q", want)
		}
	}

	// /status.json counts only a live run's ask: the lost run's open ask waits on nobody.
	var st liveState
	if err := json.Unmarshal([]byte(get(t, s, c, "/status.json")), &st); err != nil || st.Pending != 1 {
		t.Errorf("status %+v (%v), want 1 pending: the live run's, not the lost run's", st, err)
	}

	// The waiting ask's card asks in words and carries its timestamp for live.js's countdown.
	ap := get(t, s, c, "/approvals")
	for _, want := range []string{
		`Let asker <span title="read">read</span> this file?`, "Your rules ask before any read under /d/ask/confidential/",
		`data-ago="2026-10-25T12:04:50Z"`, "asked 10 s ago", "some agents give up after about 30 s", ">Allow once</button>",
	} {
		if !strings.Contains(ap, want) {
			t.Errorf("Approvals lacks %q", want)
		}
	}
	if strings.Contains(ap, "q-9") {
		t.Error("Approvals offers the lost run's ask")
	}
}

func TestStoryWords(t *testing.T) {
	d := &rulesview.Drifted{Rows: []rulesview.DriftRow{{Unused: true}, {Unused: true}, {Unused: true}, {}}}
	d.Rows[0].Rule, d.Rows[1].Rule, d.Rows[2].Rule, d.Rows[3].Rule = "fs.write[./tmp/]", "fs.ask[./held/]", "fs.deny_read[/h/.ssh/]", "exec[git]"
	if got := cutOf(d); len(got) != 1 || got[0] != "fs.write[./tmp/]" {
		t.Errorf("cut %v, want only the unused grant: a deny or ask entry is a protection, never cut", got)
	}
	if got := ruleName("unmatched"); got != "Not in policy" {
		t.Errorf("unmatched reads %q", got)
	}
	r := &ledgerview.Run{User: "alice", UID: 1000}
	at := time.Date(2026, 10, 27, 21, 50, 53, 0, time.Local)
	blocks := []liveblock.Entry{{Kind: liveblock.KindExec, Value: "ls", By: "uid:1000 pid:7 dashboard", At: at}}
	// A live block's refusal never says the contract does not allow it: the contract does.
	if e := (ledgerview.Event{Kind: "refused", Rule: "live.block[exec:ls]", Reason: "exec-not-allowed"}); reasonOf(e) != "" || codeOf(e) != "" {
		t.Error("a live-block refusal carries the contract's reason sentence")
	}
	if got := blockLine(blocks[0], r, ""); got != (blockText{"Program", "ls", "ls", ": blocked by alice, from the dashboard at 21:50:53"}) {
		t.Errorf("block line %+v", got)
	}
	if got := whoIn("uid:1000 pid:7 cli", r); got != "alice, from a terminal" {
		t.Errorf("whoIn %q", got)
	}
	if got := whoIn("uid:4242 pid:7 cli", r); got != who("uid:4242 pid:7 cli") {
		t.Errorf("whoIn names another uid %q", got)
	}
	if reasonOf(ledgerview.Event{Kind: "run_end", Reason: "exit"}) != "" {
		t.Error("run_end repeats its reason")
	}
}

func TestShortPathKeepsTheFileName(t *testing.T) {
	for _, c := range []struct {
		p, home, dir, base string
	}{
		{"/d/without/home/.ssh/id_rsa", "/d/without/home", "~/.ssh/", "id_rsa"},
		{"/home/somebody/.cache/tego-workdir/demoq/dash-qa/w/with/home/.config/telemetry/token", "", "/home/…/home/.config/telemetry/", "token"},
		{"/etc/hosts", "", "/etc/", "hosts"},
	} {
		got := shortPath(c.p, c.home)
		if len(got) != 1 || got[0] != (pathPart{c.p, c.dir, c.base}) {
			t.Errorf("shortPath(%q, %q) = %+v, want dir %q base %q", c.p, c.home, got, c.dir, c.base)
		}
	}
	if got := shortPath("/a/b/x.pyc.123 → /a/b/x.pyc", ""); len(got) != 2 || got[1].Base != "x.pyc" {
		t.Errorf("a rename is two parts: %+v", got)
	}
	if got := shortTarget("127.0.0.1:8801", "", 44); got.Parts != nil || got.Text != "127.0.0.1:8801" {
		t.Errorf("a destination is not a path: %+v", got)
	}
	// Rendered through the page templates, agent-written text is escaped like any other.
	s := newServer(t, storyFixture(t))
	var b strings.Builder
	if err := s.pages["run"].ExecuteTemplate(&b, "spv", shortPath(`/x/<b>/"q"`, "")); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "<b>/") || !strings.Contains(b.String(), "&lt;b&gt;") {
		t.Errorf("spv does not escape: %s", b.String())
	}
}

// The ask card names Codex's own wait only on a Codex run; any other agent gets a general line.
func TestGiveUp(t *testing.T) {
	for harness, want := range map[string]string{"codex": "Codex gives up at about 30 s", "claude-code": "some agents give up after about 30 s", "": "some agents give up after about 30 s"} {
		if got := giveUp(harness); got != want {
			t.Errorf("giveUp(%q) = %q, want %q", harness, got, want)
		}
	}
}

// Overview's half-width run tables hide columns by class, so the columns can move without breaking the narrow layout.
func TestRunTableHidesColumnsByClass(t *testing.T) {
	tmpl, err := assets.ReadFile("templates/layout.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	css := map[string]string{}
	for _, f := range []string{"static/mvp.css", "static/signal.css"} {
		b, err := assets.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		css[f] = string(b)
	}
	all := css["static/mvp.css"] + css["static/signal.css"]
	if strings.Contains(all, ".t-rows th:nth-child") || strings.Contains(all, ".t-rows td:nth-child") {
		t.Error("a run table column is still hidden by position")
	}
	rt := string(tmpl)
	rt = rt[strings.Index(rt, `{{define "runthead"}}`):] // the head, then the rows (runrows)
	rt = rt[:strings.Index(rt, `{{/* spv`)]
	for _, c := range []string{"c-run", "c-lines", "c-asks"} {
		if !strings.Contains(all, ".panel.s8 .t-rows ."+c) {
			t.Errorf("no narrow-width rule hides .%s", c)
		}
		if n := strings.Count(rt, c); n != 2 {
			t.Errorf("the run table has %d cells with class %s, want its th and its td", n, c)
		}
	}
}

// A watched run with no enforced run of its program to borrow a contract from: the destination the banner names is
// red, and another send next to a secret is only "Not on a list", since nothing says whether the job needs it.
func TestWatchedRunWithoutReference(t *testing.T) {
	root := t.TempDir()
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	const run = "r-aaaaaaaa-0000000000031-alonex"
	ls := []string{
		line(run, "watch-python3", 0, t0, "run_start", `"tier":"observe","command":["python3"],"cwd":"/d/w/proj"`),
		line(run, "watch-python3", 1, t0, "fs", `"rule":"unmatched","verdict":"observed","op":"open","flags":524288,"path":"/d/w/home/.ssh/id_rsa"`),
		line(run, "watch-python3", 2, t0, "net", `"rule":"unmatched","verdict":"observed","dst":"127.0.0.1:45805","proto":"tcp"`),
		line(run, "watch-python3", 3, t0, "net", `"rule":"unmatched","verdict":"observed","dst":"127.0.0.1:59465","proto":"tcp"`),
		line(run, "watch-python3", 4, t0, "run_end", `"reason":"exit","exit_code":0`),
	}
	if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	page := get(t, s, login(t, s), "/runs/"+run)
	out := page[strings.Index(page, `id="h-hl-o"`):strings.Index(page, `id="h-hl-a"`)]
	item := func(key string) string {
		i := strings.Index(out, key)
		if i < 0 {
			t.Fatalf("Outbound lacks %s", key)
		}
		return out[i : i+strings.Index(out[i:], "</li>")]
	}
	if sink := item("127.0.0.1:45805"); !strings.Contains(sink, "Got through") || !strings.Contains(sink, "After a secret read") {
		t.Errorf("the named destination is not red: %s", sink)
	}
	if api := item("127.0.0.1:59465"); strings.Contains(api, "Got through") || !strings.Contains(api, "Not on a list") {
		t.Errorf("the other destination is marked like the attacker's: %s", api)
	}
	if !strings.Contains(out, "No policy to check against") {
		t.Error("the card does not say a watched run had no contract to check against")
	}
}

// TestSigMemoReadsEachRunOnce: one request's Signals (the Overview's refusals, verdicts and tiles) read each run's
// Signal once, the enforced run a watched run is read against included, and say what signalOf said run by run: the
// watched run read against the enforced run's allow list, the others by their own contract.
func TestSigMemoReadsEachRunOnce(t *testing.T) {
	root := storyFixture(t)
	s := newServer(t, root)
	snap, err := ledgerview.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	m := s.signals(snap.Runs)
	for _, r := range snap.Runs {
		got := m.of(r)
		if again := m.of(r); again != got {
			t.Errorf("%s: read twice in one request", r.ID)
		}
		want := ledgerview.Signal(r, s.sensitiveOf(rulesview.RunLists(root, r.ID), r))
		if ref := ledgerview.ReferenceRun(snap.Runs, r); ref != nil {
			l := rulesview.RunLists(root, ref.ID)
			want = want.Against(ledgerview.NewReference(ref.ID, l.Net, ledgerview.Signal(ref, s.sensitiveOf(l, ref))))
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: the request's Signal differs from signalOf's", r.ID)
		}
	}
	if got := m.of(snap.Find(leftRun)).AllowedFrom; got != rightRun {
		t.Errorf("the watched run was read against %q, want the enforced run", got)
	}
	if len(m.own) != len(snap.Runs) || len(m.lists) != len(snap.Runs) {
		t.Errorf("%d Signals and %d contract reads for %d runs, want one each", len(m.own), len(m.lists), len(snap.Runs))
	}
}

// Compare's suggested pair is the watched run against the enforced run of the same program, when one is listed: a
// newer enforced run of another program does not take its place.
func TestComparePicksTheSameProgram(t *testing.T) {
	runs := []*ledgerview.Run{ // newest first
		{ID: "r-loop", Tier: "landlock", Command: "bash ./loop.sh"},
		{ID: "r-left", Tier: "observe", Command: "python3 -m unittest"},
		{ID: "r-right", Tier: "landlock", Command: "/usr/bin/python3 -m unittest"},
	}
	if p := cmpPick(runs); p.A != "r-left" || p.B != "r-right" {
		t.Errorf("cmpPick = %+v, want r-left against r-right", p)
	}
	for id, want := range map[string]string{"r-left": "r-right", "r-right": "r-left", "r-loop": "r-left"} {
		if got := suggestOther(runs, id); got != want {
			t.Errorf("suggestOther(%s) = %s, want %s", id, got, want)
		}
	}
	// With no watched run the pickers still open on two different runs: the newest against the next.
	enforced := []*ledgerview.Run{{ID: "r-new", Tier: "landlock"}, {ID: "r-old", Tier: "landlock"}}
	if p := cmpPick(enforced); p.A != "r-old" || p.B != "r-new" {
		t.Errorf("cmpPick(enforced only) = %+v, want r-old against r-new", p)
	}
	if p := cmpPick(enforced[:1]); p.A != "" || p.B != "r-new" {
		t.Errorf("cmpPick(one run) = %+v, want only B", p)
	}
}

// A live block's value reads as its kind and a path the page shortens, never as the raw "read:/home/..." key.
func TestBlockKV(t *testing.T) {
	for v, want := range map[string]blockKind{
		"read:/home/u/.config/telemetry": {Kind: "read", Path: "/home/u/.config/telemetry"},
		"exec:ls":                        {Kind: "exec", Value: "ls"},
		"net:api.example.com:443":        {Kind: "net", Value: "api.example.com:443"},
		"odd":                            {Value: "odd"},
		"read:":                          {Value: "read:"},
	} {
		if got := blockKV(v); got != want {
			t.Errorf("blockKV(%q) = %+v, want %+v", v, got, want)
		}
	}
}

// A rule's words name a path under the run's home as ~/…, and only a path that starts there.
func TestHomeIn(t *testing.T) {
	const home = "/home/u/stage/with/home"
	for in, want := range map[string]string{
		"Secret, never readable: " + home + "/.ssh/id_rsa":        "Secret, never readable: ~/.ssh/id_rsa",
		"Asks you before a read: " + home + "/.config/telemetry/": "Asks you before a read: ~/.config/telemetry/",
		home + "/x":                            "~/x",
		"Writable: /srv" + home + "/x":         "Writable: /srv" + home + "/x",
		"Not on any allow list (default deny)": "Not on any allow list (default deny)",
	} {
		if got := homeIn(in, home); got != want {
			t.Errorf("homeIn(%q) = %q, want %q", in, got, want)
		}
	}
	if got := homeIn("Readable: /home/u/x", ""); got != "Readable: /home/u/x" {
		t.Errorf("no home: %q", got)
	}
}

// A later enforced take of the same program (a Block now take, a rehearsal) is not the watched take's pair: the
// reference, the run page's Compare and the suggested pair all name the run that started with it.
func TestPairIsTheClosestStart(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 19, 46, 52, 0, time.UTC)
	runs := []*ledgerview.Run{ // newest first
		{ID: "r-later", Tier: "landlock", Command: "codex --no-daemon", Start: t0.Add(13 * time.Minute)},
		{ID: "r-left", Tier: "observe", Command: "codex --no-daemon", Start: t0},
		{ID: "r-right", Tier: "landlock", Command: "/usr/bin/codex --no-daemon", Start: t0.Add(time.Second)},
	}
	if ref := ledgerview.ReferenceRun(runs, runs[1]); ref == nil || ref.ID != "r-right" {
		t.Errorf("ReferenceRun = %v, want r-right", ref)
	}
	if got := suggestOther(runs, "r-left"); got != "r-right" {
		t.Errorf("suggestOther(r-left) = %s, want r-right", got)
	}
	if got := suggestOther(runs, "r-later"); got != "r-left" {
		t.Errorf("suggestOther(r-later) = %s, want r-left", got)
	}
	if p := cmpPick(runs); p.A != "r-left" || p.B != "r-right" {
		t.Errorf("cmpPick = %+v, want r-left against r-right", p)
	}
}
