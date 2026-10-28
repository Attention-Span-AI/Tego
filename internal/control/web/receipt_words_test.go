// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

const (
	markWatchRun = "r-aaaaaaaa-0000000000041-mkwatc"
	markGuardRun = "r-aaaaaaaa-0000000000042-mkguar"
)

// markFixture is the demo's pair in small: the watched run reads a .pyc, the SSH key and the telemetry token, calls
// the project's API (allowed by the enforced run's contract), sends to the sink at 127.0.0.1:9821 and reads another
// .pyc; the enforced run of the same program is refused both reads and the send.
func markFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t0 := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	write := func(run, contract string, ls []string) {
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
	var ls []string
	seq := 0
	add := func(run string, ms int, kind, extra string) {
		ls = append(ls, line(run, "codex", seq, t0.Add(time.Duration(ms)*time.Millisecond), kind, extra))
		seq++
	}
	obs := func(run string, ms int, path string) {
		add(run, ms, "fs", `"rule":"unmatched","verdict":"observed","op":"open","flags":524288,"path":"`+path+`"`)
	}
	add(markWatchRun, 0, "run_start", `"tier":"observe","command":["codex"],"cwd":"/s/without/proj"`)
	obs(markWatchRun, 5, "/s/without/proj/__pycache__/app.cpython-313.pyc")                                      // 1
	obs(markWatchRun, 10, "/s/without/home/.ssh/id_rsa")                                                         // 2
	obs(markWatchRun, 12, "/s/without/home/.config/telemetry/token")                                             // 3
	add(markWatchRun, 15, "net", `"rule":"unmatched","verdict":"observed","dst":"127.0.0.1:9813","proto":"tcp"`) // 4
	add(markWatchRun, 20, "net", `"rule":"unmatched","verdict":"observed","dst":"127.0.0.1:9821","proto":"tcp"`) // 5
	obs(markWatchRun, 25, "/s/without/proj/__pycache__/util.cpython-313.pyc")                                    // 6
	add(markWatchRun, 30, "run_end", `"reason":"exit","exit_code":0`)
	write(markWatchRun, "", ls)

	ls, seq = nil, 0
	refuse := func(ms int, kind, rule, reason, op, target, payload string) {
		add(markGuardRun, ms, kind, `"rule":"`+rule+`","verdict":"refused","reason":"`+reason+`",`+payload)
		add(markGuardRun, ms, "refused", `"rule":"`+rule+`","reason":"`+reason+`","op":"`+op+`","target":"`+target+`"`)
	}
	add(markGuardRun, 60000, "run_start", `"tier":"landlock","command":["codex"],"cwd":"/s/with/proj"`)
	refuse(60010, "fs", "fs.deny_read[/s/with/home/.ssh/]", "read-denied", "open", "/s/with/home/.ssh/id_rsa",
		`"op":"open","path":"/s/with/home/.ssh/id_rsa"`)
	refuse(60012, "fs", "fs.deny_read[/s/with/home/.config/telemetry/]", "read-denied", "open", "/s/with/home/.config/telemetry/token",
		`"op":"open","path":"/s/with/home/.config/telemetry/token"`)
	add(markGuardRun, 60015, "net", `"rule":"net[127.0.0.1:9813]","verdict":"allow","dst":"127.0.0.1:9813","proto":"tcp"`)
	refuse(60020, "net", "unmatched", "net-not-allowed", "net", "127.0.0.1:9821", `"dst":"127.0.0.1:9821","proto":"tcp"`)
	add(markGuardRun, 60030, "run_end", `"reason":"exit","exit_code":1`)
	write(markGuardRun, "fs:\n  deny_read:\n    - /s/with/home/.ssh/\n    - /s/with/home/.config/telemetry/\nnet:\n  allow:\n    - 127.0.0.1:9813\n", ls)
	return root
}

// markRow is the timeline row of line seq on a run page.
func markRow(t *testing.T, page string, seq string) string {
	t.Helper()
	i := strings.Index(page, `" id="l`+seq+`"`)
	if i < 0 {
		t.Fatalf("no timeline row for line %s", seq)
	}
	start := strings.LastIndex(page[:i], `<div class="tl `)
	end := strings.Index(page[i:], `<div class="tl `)
	if end < 0 {
		end = len(page) - i
	}
	return page[start : i+end]
}

// TestWatchedLeakRowsStandOut (QU-3): on the watched run the id_rsa and token reads read "Secret read" and the send to
// the sink "Sent out", in red; the .pyc reads and the project's own API stay a grey "Observed"; the timeline head
// says once that nothing was enforced, and the quick filter is "Secrets and sends", which keeps those three rows.
func TestWatchedLeakRowsStandOut(t *testing.T) {
	s := newServer(t, markFixture(t))
	c := login(t, s)
	page := get(t, s, c, "/runs/"+markWatchRun)
	for seq, want := range map[string]string{"2": "Secret read", "3": "Secret read", "5": "Sent out"} {
		row := markRow(t, page, seq)
		if !strings.Contains(row, `class="b b-bad"`) || !strings.Contains(row, want) || !strings.Contains(row, "mk-leak") {
			t.Errorf("line %s does not read %q in red:\n%s", seq, want, row)
		}
	}
	for _, seq := range []string{"1", "4", "6"} {
		row := markRow(t, page, seq)
		if strings.Contains(row, "mk-leak") || !strings.Contains(row, "Observed</span>") || strings.Contains(row, watchedLabel) {
			t.Errorf("line %s is not a quiet Observed row:\n%s", seq, row)
		}
	}
	if n := strings.Count(page, "Watched only, not enforced"); n != 1 {
		t.Errorf(`"Watched only, not enforced" is said %d times on the watched run page, want once (the timeline head)`, n)
	}
	if !strings.Contains(page, ">Secrets and sends<") || strings.Contains(page, ">Refused only<") {
		t.Error("the watched run's quick filter is not Secrets and sends")
	}
	only := get(t, s, c, "/runs/"+markWatchRun+"?verdict=leak")
	var got []string
	for _, m := range regexp.MustCompile(`<div class="tl [^"]*" id="l(\d+)"`).FindAllStringSubmatch(only, -1) {
		got = append(got, m[1])
	}
	if strings.Join(got, ",") != "5,3,2" {
		t.Errorf("Secrets and sends shows lines %v, want 5,3,2", got)
	}
	// The live rows a watched run's page polls carry the same marks.
	frag := do(s, "GET", "/runs/"+markWatchRun+"/rows?after=0", "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(frag, "Secret read") || !strings.Contains(frag, "Sent out") {
		t.Errorf("the live rows of a watched run lack the marks:\n%s", frag)
	}
	// The enforced run marks nothing, and its timeline keeps "Blocked only".
	guard := get(t, s, c, "/runs/"+markGuardRun)
	if strings.Contains(guard, "mk-leak") || !strings.Contains(guard, ">Blocked only<") {
		t.Error("the enforced run's timeline is marked, or lost Blocked only")
	}
}

// TestRenameOneLine (QU-9): a rename reads "a.pyc → b.pyc" with its folder under it, "~/" for the run's home.
func TestRenameOneLine(t *testing.T) {
	rn := renameOf("/h/proj/__pycache__/app.pyc.123 → /h/proj/__pycache__/app.pyc", "/h")
	if rn == nil || rn.From != "app.pyc.123" || rn.To != "app.pyc" || rn.Where != "in ~/proj/__pycache__/" {
		t.Errorf("rename %+v", rn)
	}
	if rn := renameOf("/a/x → /b/y", ""); rn == nil || rn.Where != "from /a/ to /b/" {
		t.Errorf("a move %+v", rn)
	}
	if renameOf("/h/proj/app.py", "/h") != nil || renameOf("python3 -m x → y", "") != nil {
		t.Error("a plain path or a command reads as a rename")
	}
}

// TestReceiptWords (QU-16): the Receipt says durations as every page does ("30 ms", not "30ms"), drops the stall block on a short
// run, and words a gap in the record calmly.
func TestReceiptWords(t *testing.T) {
	s := newServer(t, markFixture(t))
	c := login(t, s)
	page := get(t, s, c, "/runs/"+markGuardRun+"/receipt")
	if m := regexp.MustCompile(`· took (\d+ ms)</span>`).FindStringSubmatch(page); m == nil || !strings.Contains(page, `<span class="rc-v">`+m[1]+`</span>`) {
		t.Errorf("the Receipt's time taken is not in the dashboard's duration form: %v", m)
	}
	if strings.Contains(page, "Stall minutes") {
		t.Error("a 30 ms run shows the stall block")
	}
	v := &receiptView{}
	if got := v.GapWords("record", "1 gap line: tego knows it missed some actions, so the counts are a floor"); got != "1 gap in the record (counts are a minimum)" {
		t.Errorf("one gap reads %q", got)
	}
	if got := v.GapWords("record", "3 gap lines: …"); got != "3 gaps in the record (counts are a minimum)" {
		t.Errorf("three gaps read %q", got)
	}
	if v.GapWords("stall", "x") != "" {
		t.Error("another coverage gap was reworded")
	}
}

// TestComparePairsByStart: the watched take is paired with the enforced run of its program that started
// closest to it, not with a later rehearsal of the enforced side.
func TestComparePairsByStart(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	runs := []*ledgerview.Run{ // newest first
		{ID: "r-right3", Tier: "landlock", Command: "codex", Start: t0.Add(5 * time.Minute)},
		{ID: "r-left2", Tier: "observe", Command: "codex", Start: t0.Add(time.Minute)},
		{ID: "r-right2", Tier: "landlock", Command: "codex", Start: t0.Add(time.Minute)},
		{ID: "r-other", Tier: "landlock", Command: "bash", Start: t0.Add(time.Minute)},
		{ID: "r-left1", Tier: "observe", Command: "codex", Start: t0},
	}
	if p := cmpPick(runs); p.A != "r-left2" || p.B != "r-right2" {
		t.Errorf("cmpPick = %+v, want r-left2 against r-right2", p)
	}
}

// TestCompareHeadline (QU-11, QU-22): Compare opens on two stat blocks, red for what left the watched run and green
// for what Tego stopped on the enforced one, the sentence muted under them; with fewer than two runs it says how to
// make the pair instead of offering two empty pickers.
func TestCompareHeadline(t *testing.T) {
	s := newServer(t, markFixture(t))
	c := login(t, s)
	page := get(t, s, c, "/compare?a="+markWatchRun+"&b="+markGuardRun)
	for _, want := range []string{
		`<div class="cmp-stat cmp-stat-leak"><span class="cmp-stat-k">A · Watched</span><strong class="cmp-stat-h">2 secrets left the machine</strong><span class="cmp-stat-d">id_rsa, token → 127.0.0.1:9821</span>`,
		`<div class="cmp-stat cmp-stat-ok"><span class="cmp-stat-k">B · Enforced</span><strong class="cmp-stat-h">0 left</strong><span class="cmp-stat-d">3 attempts stopped</span>`,
		`class="cmp-sum cmp-sum-quiet"`, `href="/static/compare.css"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("Compare lacks %q", want)
		}
	}
	empty := newServer(t, t.TempDir())
	ce := login(t, empty)
	none := get(t, empty, ce, "/compare")
	if !strings.Contains(none, "Compare needs two runs") || !strings.Contains(none, "tego watch -- &lt;agent&gt;") ||
		!strings.Contains(none, "tego run &lt;policy.yaml&gt; -- &lt;agent&gt;") || strings.Contains(none, `class="cmp-form"`) {
		t.Error("an empty Compare does not say how to make two runs, or still shows the pickers")
	}
}
