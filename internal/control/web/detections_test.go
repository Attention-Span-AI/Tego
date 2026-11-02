// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// detectionsRoot is a ledger of one ended run with the given lines (line's extra) after its run_start.
func detectionsRoot(t *testing.T, run, tier string, extras ...[2]string) string {
	t.Helper()
	root := t.TempDir()
	addDetectionsRun(t, root, run, tier, extras...)
	return root
}

// addDetectionsRun writes one ended run into root, its lines a second apart.
func addDetectionsRun(t *testing.T, root, run, tier string, extras ...[2]string) {
	t.Helper()
	addRunEvery(t, root, run, tier, time.Second, extras...)
}

// addRunEvery writes one ended run into root, its lines gap apart.
func addRunEvery(t *testing.T, root, run, tier string, gap time.Duration, extras ...[2]string) {
	t.Helper()
	t0 := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)
	ls := []string{line(run, "agent", 0, t0, "run_start", `"tier":"`+tier+`","command":["agent"],"cwd":"/w/proj"`)}
	for _, x := range extras {
		ls = append(ls, line(run, "agent", len(ls), t0.Add(time.Duration(len(ls))*gap), x[0], x[1]))
	}
	ls = append(ls, line(run, "agent", len(ls), t0.Add(time.Hour), "run_end", `"reason":"exit","exit_code":0`))
	if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestDetectionsPort53: refused connects to port 53 of another machine are listed as any other refused connect, each
// try counted, and the run's banner says what was stopped. They read Routine on every try, right after a key read.
func TestDetectionsPort53(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000019-port53"
	ex := [][2]string{{"fs", `"rule":"unmatched","verdict":"allow","op":"open","path":"/w/home/.ssh/id_rsa"`}}
	for range 20 {
		ex = append(ex, [2]string{"net", `"rule":"unmatched","verdict":"refused","reason":"net-not-allowed","proto":"tcp","dst":"203.0.113.9:53"`},
			[2]string{"refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"203.0.113.9:53"`})
	}
	s := newServer(t, detectionsRoot(t, run, "landlock", ex...))
	c := login(t, s)
	d := get(t, s, c, "/detections")
	for _, want := range []string{`<td><span class="sev sev-High">`, "203.0.113.9", "After a secret read"} {
		if !strings.Contains(d, want) {
			t.Errorf("Detections lacks %q:\n%s", want, d)
		}
	}
	if strings.Contains(d, "Nothing blocked") || strings.Contains(d, "Routine 20") {
		t.Errorf("the attempts read as routine:\n%s", d)
	}
	if b := get(t, s, c, "/runs/"+run); !strings.Contains(b, "Protected: 20 sends to 203.0.113.9:53 blocked") {
		t.Errorf("the run's banner:\n%s", b)
	}
}

// TestBurstRowLeadsToItsLines: a burst reads as one row that says how many addresses it holds, and the row's Logs link
// and its Severity link use text that finds them, which the range as written would not.
func TestBurstRowLeadsToItsLines(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000003-bursts"
	connect := func(target string) [2]string {
		return [2]string{"refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"` + target + `"`}
	}
	s := newServer(t, detectionsRoot(t, run, "landlock", connect("185.199.108.133:443"), connect("185.199.109.133:443")))
	c := login(t, s)
	body := get(t, s, c, "/detections")
	if strings.Count(body, `<td><span class="sev sev-High">`) != 1 || !strings.Contains(body, "185.199.0.0/16") || !strings.Contains(body, ">2 addresses</span>") {
		t.Fatalf("the burst is not one row:\n%s", body)
	}
	m := investigateLink.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("the row links to no Investigate page")
	}
	page := get(t, s, c, m[1])
	for _, want := range []string{`href="/logs?q=185.199.&amp;run=` + run + `"`, "match=185.199.", ">2 addresses</span>"} {
		if !strings.Contains(page, want) {
			t.Errorf("Investigate lacks %q", want)
		}
	}
	if logs := get(t, s, c, "/logs?q=185.199.&run="+run); !strings.Contains(logs, "185.199.108.133") || !strings.Contains(logs, "185.199.109.133") {
		t.Errorf("the Logs link finds no lines:\n%s", logs)
	}
	if rf := get(t, s, c, "/runs/"+run+"/refusals"); !strings.Contains(rf, ">2 addresses</span>") || !strings.Contains(rf, "q=185.199.&amp;run=") && !strings.Contains(rf, "q=185.199.&amp;verdict=") {
		t.Errorf("the run's Blocked tab lacks the row or its link:\n%s", rf)
	}
}

// TestPortScanIsOneDetection: the lines a port scan of this machine really writes, 150 connects and their mirrors 2.5 s
// apart. Detections has one row, which says how many ports and attempts it holds; the Overview's headline, grid and
// list read that one row; and nothing is lost by it: Investigate lists the ports, its links reach each port and each
// line, and the line page shows that line.
func TestPortScanIsOneDetection(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000024-portsc"
	var ex [][2]string
	for i := range 150 {
		target := fmt.Sprintf("127.0.0.1:%d", 19100+i)
		ex = append(ex, [2]string{"net", `"rule":"unmatched","verdict":"refused","reason":"net-not-allowed","proto":"tcp","dst":"` + target + `"`},
			[2]string{"refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"` + target + `"`})
	}
	root := t.TempDir()
	addRunEvery(t, root, run, "landlock", 1250*time.Millisecond, ex...)
	s := newServer(t, root)
	c := login(t, s)

	d := get(t, s, c, "/detections")
	if n := strings.Count(d, `<td><span class="sev sev-High">`); n != 1 {
		t.Errorf("%d High rows, want one", n)
	}
	for _, want := range []string{">150 ports</span>", `data-label="Times">150</td>`, `title="150 ports, 150 attempts: 19100–19249"`} {
		if !strings.Contains(d, want) {
			t.Errorf("Detections lacks %q:\n%s", want, d)
		}
	}

	o := get(t, s, c, "/")
	for _, want := range []string{`href="/detections?sev=high">1 High</a> blocked`, `aria-label="1 High, Network"`, ">150 ports</span>"} {
		if !strings.Contains(o, want) {
			t.Errorf("the Overview lacks %q", want)
		}
	}
	top := o[strings.Index(o, `id="h-ref"`):]
	if n := strings.Count(top[:strings.Index(top, "</section>")], `<span class="sev sev-High">`); n != 1 {
		t.Errorf("Newest High and Medium lists %d rows, want one", n)
	}

	m := investigateLink.FindStringSubmatch(d)
	if m == nil {
		t.Fatal("the row links to no Investigate page")
	}
	page := get(t, s, c, m[1])
	for _, want := range []string{"150 times", "150 ports", "19100–19249", `href="/logs?q=127.0.0.1%3A&amp;run=` + run + `"`, "match=127.0.0.1%3a"} {
		if !strings.Contains(page, want) {
			t.Errorf("Investigate lacks %q:\n%s", want, page)
		}
	}
	byPort := regexp.MustCompile(`href="(/logs\?group=target[^"]*)"[^>]*>Each in Logs`).FindStringSubmatch(page)
	if byPort == nil {
		t.Fatalf("Investigate does not link each port:\n%s", page)
	}
	if l := get(t, s, c, strings.ReplaceAll(byPort[1], "&amp;", "&")); !strings.Contains(l, "150 groups of 150 lines") || !strings.Contains(l, "127.0.0.1:<wbr>19100") {
		t.Errorf("Logs by target does not hold each port:\n%s", l)
	}
	if l := get(t, s, c, "/logs?q=127.0.0.1%3A&run="+run); !strings.Contains(l, "127.0.0.1:<wbr>19249") {
		t.Errorf("the row's Logs link finds no lines:\n%s", l)
	}
	if rf := get(t, s, c, "/runs/"+run+"/refusals"); !strings.Contains(rf, "150 ports <span") || !strings.Contains(rf, "19100–19249") || strings.Contains(rf, "19100, 19101") {
		t.Errorf("the run's Blocked tab:\n%s", rf)
	}
	// Line 1 is the first connect: the page names its own port, not the row's host.
	if l := get(t, s, c, "/runs/"+run+"/lines/1"); !strings.Contains(l, "19100") {
		t.Errorf("the line page lacks its destination:\n%s", l)
	}
	if l := get(t, s, c, "/logs?q=127.0.0.1%3A19149&run="+run); !strings.Contains(l, `<span class="sev sev-High">High</span>`) || !strings.Contains(l, "127.0.0.1:<wbr>19149") {
		t.Errorf("a line of the scan does not read High in Logs:\n%s", l)
	}
}

// TestScanNamesWhatHappenedInIt: a row that holds a scan lasts as long as the scan, so What else reads from all of it: a key
// read and the sends beside it, minutes after the scan began, are on its page, and it is on theirs.
func TestScanNamesWhatHappenedInIt(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000026-scankey"
	var ex [][2]string
	for i := range 100 {
		if i == 60 {
			ex = append(ex, [2]string{"refused", `"rule":"fs.deny_read[/w/home/.ssh/id_rsa]","reason":"read-denied","op":"open","target":"/w/home/.ssh/id_rsa"`})
		}
		ex = append(ex, [2]string{"refused", fmt.Sprintf(`"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"127.0.0.1:%d"`, 19100+i)})
	}
	root := t.TempDir()
	addRunEvery(t, root, run, "landlock", 2500*time.Millisecond, ex...)
	s := newServer(t, root)
	c := login(t, s)
	d := get(t, s, c, "/detections")
	if n := strings.Count(d, "After a secret read"); n != 4 {
		t.Errorf("%d rows next to the key's read, want 4", n)
	}
	row := regexp.MustCompile(`href="(/runs/[^"]+/investigate/\d+)" aria-label="Investigate: connect 127\.0\.0\.1"`).FindStringSubmatch(d)
	if row == nil {
		t.Fatalf("no row for the scan:\n%s", d)
	}
	page := get(t, s, c, row[1])
	whatElse := page[strings.Index(page, `id="h-else"`):strings.Index(page, `id="h-now"`)]
	if !strings.Contains(whatElse, "id_rsa") || !strings.Contains(whatElse, "127.0.0.1:19160") {
		t.Errorf("What else lacks what happened in the scan:\n%s", whatElse)
	}
	if !strings.Contains(page, " to <time") {
		t.Errorf("When does not say how long it lasted:\n%s", page)
	}
	near := regexp.MustCompile(`href="(/runs/[^"]+/investigate/\d+)" aria-label="Investigate: connect 127\.0\.0\.1:19160"`).FindStringSubmatch(d)
	if near == nil {
		t.Fatalf("no row for the connect after the read:\n%s", d)
	}
	page = get(t, s, c, near[1])
	if whatElse := page[strings.Index(page, `id="h-else"`):strings.Index(page, `id="h-now"`)]; !strings.Contains(whatElse, `>connect</span> `) || !strings.Contains(whatElse, "127.0.0.1<") {
		t.Errorf("the send's page does not name the scan around it:\n%s", whatElse)
	}
}

// TestManyPortsStayShort: a row's words do not grow with what it holds.
func TestManyPortsStayShort(t *testing.T) {
	seq := func(from, n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = strconv.Itoa(from + i)
		}
		return out
	}
	for _, c := range []struct {
		ports []string
		spans int
		want  string
	}{
		{[]string{"443"}, 12, "443"},
		{[]string{"443", "80"}, 12, "80, 443"},
		{seq(19100, 150), 12, "19100–19249"},
		{[]string{"8080", "22", "8081", "23", "443"}, 12, "22–23, 443, 8080–8081"},
		{[]string{"8080", "22", "8081", "23", "443"}, 2, "22–23, 443 and 2 more"},
		{append(seq(1, 3), "not-a-port"), 12, "1–3 and 1 more"},
		{nil, 12, ""},
	} {
		if got := portSpans(c.ports, c.spans); got != c.want {
			t.Errorf("portSpans(%v, %d) = %q, want %q", c.ports, c.spans, got, c.want)
		}
	}
	if got := someOf([]string{"a", "b", "c"}, 2); got != "a, b and 1 more" {
		t.Errorf("someOf = %q", got)
	}
	if got := someOf([]string{"a"}, 2); got != "a" {
		t.Errorf("someOf one = %q", got)
	}
}

// TestWriteThatRunsLaterIsHigh: a refused write to an agent's settings leads Detections and says why on Investigate; the
// same file read, or a cache written, stays where it was.
func TestWriteThatRunsLaterIsHigh(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000025-settin"
	write := func(path, reason string) [2]string {
		return [2]string{"refused", `"rule":"unmatched","reason":"` + reason + `","op":"open","target":"` + path + `"`}
	}
	s := newServer(t, detectionsRoot(t, run, "landlock", write("/w/proj/.claude/settings.json", "write-outside-contract"),
		write("/home/u/.codex/version.json", "read-denied")))
	c := login(t, s)
	d := get(t, s, c, "/detections")
	if strings.Count(d, `<td><span class="sev sev-High">`) != 1 || strings.Count(d, `<td><span class="sev sev-Medium">`) != 1 {
		t.Fatalf("want the write High and the read Medium:\n%s", d)
	}
	m := investigateLink.FindStringSubmatch(d)
	if m == nil {
		t.Fatal("the row links to no Investigate page")
	}
	if page := get(t, s, c, m[1]); !strings.Contains(page, `<p class="lede">Runs code later</p>`) {
		t.Errorf("Investigate does not say why:\n%s", page)
	}
}

// watchedLeak is a watched run's lines: a key read, then a send next to it.
var watchedLeak = [][2]string{
	{"fs", `"rule":"unmatched","verdict":"observed","op":"open","path":"/w/home/.ssh/id_rsa"`},
	{"net", `"rule":"unmatched","verdict":"observed","dst":"198.51.100.7:443","proto":"tcp"`},
}

// TestBySeverityKeepsTheView: Logs' By severity gives a watched run's lines their own group, not Allowed, and its link
// narrows the view it was read in instead of dropping it.
func TestBySeverityKeepsTheView(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000004-watchd"
	s := newServer(t, detectionsRoot(t, run, "observe", watchedLeak...))
	c := login(t, s)
	b := get(t, s, c, "/logs?group=severity&run="+run)
	if !strings.Contains(b, `<span class="g-main">Observed</span>`) {
		t.Fatalf("no Observed group:\n%s", b)
	}
	m := regexp.MustCompile(`<a class="link" href="([^"]*)" title="Show these lines">2</a>`).FindStringSubmatch(b)
	if m == nil {
		t.Fatalf("the Observed group links nowhere:\n%s", b)
	}
	if !strings.Contains(m[1], "verdict%3Aobserved") || !strings.Contains(m[1], "run="+run) {
		t.Errorf("the link %s does not narrow the view to the observed lines of this run", m[1])
	}
	lines := get(t, s, c, strings.ReplaceAll(m[1], "&amp;", "&"))
	if !strings.Contains(lines, "id_rsa") || !strings.Contains(lines, "198.51.100.7") {
		t.Errorf("the link does not reach the observed lines:\n%s", lines)
	}
}

// TestBySeverityLinksHoldTheirGroup: each group's link shows exactly the lines its row counts, and the row's count
// keeps a person's no out of Allowed and the run's own lines out of both.
func TestBySeverityLinksHoldTheirGroup(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000032-groupl"
	s := newServer(t, detectionsRoot(t, run, "landlock",
		[2]string{"fs", `"rule":"fs.ask[/w/proj/held/]","verdict":"ask","op":"open","path":"/w/proj/held/a"`},
		[2]string{"ask", `"ask_id":"q-1","ask_rule":"fs.ask[/w/proj/held/]","hold":"open","op":"write","target":"/w/proj/held/a"`},
		[2]string{"answer", `"ask_id":"q-1","approved":false,"by":"uid:1000 pid:42","after_s":1.0,"answer_reason":"ask-denied"`},
		[2]string{"gap", `"what":"fs","why":"overflow"`},
		[2]string{"fs", `"rule":"unmatched","verdict":"observed","op":"open","path":"/w/proj/seen.go"`},
		[2]string{"fs", `"rule":"fs.read[./]","verdict":"allow","op":"open","path":"/w/proj/main.go"`}))
	c := login(t, s)
	b := get(t, s, c, "/logs?group=severity&run="+run)
	for name, want := range map[string]int{"Observed": 1, "Asked": 2, "Answered": 1, "Allowed": 1, "Recorded": 3} {
		m := regexp.MustCompile(`<span class="g-main">` + name + `</span>.*?<a class="link" href="([^"]*)" title="Show these lines">(\d+)</a>`).FindStringSubmatch(b)
		if m == nil {
			t.Errorf("no %s group with a link:\n%s", name, b)
			continue
		}
		if m[2] != strconv.Itoa(want) {
			t.Errorf("%s holds %s lines, want %d", name, m[2], want)
		}
		if got := matchedOn(t, get(t, s, c, html.UnescapeString(m[1]))); got != want {
			t.Errorf("%s's link %s shows %d lines, want %d", name, m[1], got, want)
		}
	}
}

// TestBySeverityRoutineHasNoLink: no query holds routine lines alone, and verdict:refused, the nearest one, lists the
// High and Medium lines too. A count linked to that promises lines it does not show: 1 opened 3.
func TestBySeverityRoutineHasNoLink(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000033-routin"
	s := newServer(t, detectionsRoot(t, run, "landlock",
		[2]string{"refused", `"rule":"fs.deny_read[~/.ssh/]","reason":"read-denied","op":"open","target":"/w/home/.ssh/id_rsa"`},
		[2]string{"refused", `"rule":"unmatched","reason":"net-outside-contract","op":"connect","target":"203.0.113.9:443"`},
		[2]string{"refused", `"rule":"unmatched","reason":"write-outside-contract","op":"open","target":"/dev/tty"`}))
	c := login(t, s)
	b := get(t, s, c, "/logs?group=severity&run="+run)
	if !strings.Contains(b, `href="/detections?sev=high"`) {
		t.Fatalf("no High group, so this test measures nothing:\n%s", b)
	}
	var row string
	for _, r := range strings.Split(b, `<tr role="row"`) {
		if strings.Contains(r, `<span class="g-main">Routine</span>`) {
			row = r
		}
	}
	if row == "" {
		t.Fatalf("no Routine group:\n%s", b)
	}
	if !strings.Contains(row, `class="g-n">1</td>`) {
		t.Errorf("the Routine row does not count one line:\n%s", row)
	}
	if strings.Contains(row, "Show these lines") {
		t.Errorf("the Routine row links lines no query holds alone:\n%s", row)
	}
}

// TestBySeverityAgreesWithDetections: a path only the run's contract calls secret is High on both pages.
func TestBySeverityAgreesWithDetections(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000005-contrc"
	root := detectionsRoot(t, run, "landlock",
		[2]string{"refused", `"rule":"unmatched","reason":"write-outside-contract","op":"open","target":"/w/vault/plan.md"`})
	if err := os.WriteFile(filepath.Join(root, run, "contract.yaml"), []byte("fs:\n  deny_read:\n    - /w/vault/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	if b := get(t, s, c, "/detections"); !strings.Contains(b, `<td><span class="sev sev-High">`) {
		t.Fatalf("Detections does not read the contract's secret as High:\n%s", b)
	}
	if b := get(t, s, c, "/logs?group=severity"); !strings.Contains(b, `href="/detections?sev=high"`) {
		t.Errorf("By severity disagrees with Detections:\n%s", b)
	}
}

// watchedRead is a watched run's key read and, gap lines of 1 s later, a send to 203.0.113.9:443.
func watchedRead(gap int) [][2]string {
	ex := [][2]string{{"fs", `"rule":"unmatched","verdict":"observed","op":"open","path":"/w/home/.ssh/id_rsa"`}}
	for range gap {
		ex = append(ex, [2]string{"fs", `"rule":"unmatched","verdict":"observed","op":"open","path":"/w/proj/main.go"`})
	}
	return append(ex, [2]string{"net", `"rule":"unmatched","verdict":"observed","proto":"tcp","dst":"203.0.113.9:443"`})
}

// TestWatchedSecretReadIsNoAllClear: a watched run that read a key and sent seven seconds later is outside the verdict's
// window, so it is no leak, and nothing may say it went well. Its banner said "no send after", the Overview "All quiet",
// and Detections put a check mark over it. The banner now says only what the window can, and counts where the run got to.
func TestWatchedSecretReadIsNoAllClear(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000020-watchd"
	s := newServer(t, detectionsRoot(t, run, "observe", watchedRead(6)...))
	c := login(t, s)
	rp := get(t, s, c, "/runs/"+run)
	for _, want := range []string{"Watched only: 1 secret read, no new destination next to it", "Nothing blocked · 1 destination reached"} {
		if !strings.Contains(rp, want) {
			t.Errorf("the run page lacks %q:\n%s", want, rp)
		}
	}
	ov := get(t, s, c, "/")
	if !strings.Contains(ov, "<h1>1 run read secrets</h1>") || strings.Contains(ov, "All quiet") {
		t.Errorf("the Overview's headline:\n%s", ov)
	}
	if !strings.Contains(ov, "id_rsa read; no new destination next to it") {
		t.Errorf("the Secrets chip's title:\n%s", ov)
	}
	d := get(t, s, c, "/detections")
	if strings.Contains(d, "#i-check") || !strings.Contains(d, "Nothing blocked") {
		t.Errorf("Detections puts a check mark over a watched secret read:\n%s", d)
	}

	// The same pages on a watched run that read no secret have nothing to hold back.
	const quiet = "r-aaaaaaaa-0000000000021-quiets"
	s = newServer(t, detectionsRoot(t, quiet, "observe",
		[2]string{"fs", `"rule":"unmatched","verdict":"observed","op":"open","path":"/w/proj/main.go"`}))
	c = login(t, s)
	if ov := get(t, s, c, "/"); !strings.Contains(ov, "<h1>All quiet</h1>") {
		t.Errorf("a quiet ledger's headline:\n%s", ov)
	}
	if d := get(t, s, c, "/detections"); !strings.Contains(d, "#i-check") {
		t.Errorf("a quiet ledger lost its check mark:\n%s", d)
	}
}

// TestDetectionsSaysRoutineWasBlocked: the header's "Routine N" is blocked actions, so the page under it cannot say that
// nothing was blocked, with a leak above it or without one.
func TestDetectionsSaysRoutineWasBlocked(t *testing.T) {
	routine := [][2]string{{"refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"127.0.0.53:53"`},
		{"refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"127.0.0.53:53"`}}
	const enforced, watched = "r-aaaaaaaa-0000000000022-routin", "r-aaaaaaaa-0000000000023-watchd"
	root := detectionsRoot(t, enforced, "landlock", routine...)
	s := newServer(t, root)
	c := login(t, s)
	body := get(t, s, c, "/detections")
	if !strings.Contains(body, "Only routine actions blocked") || !strings.Contains(body, "Routine 2") || strings.Contains(body, "Nothing blocked") {
		t.Errorf("only routine lines:\n%s", body)
	}
	if !strings.Contains(body, "#i-check") {
		t.Errorf("a ledger of routine lines lost its check mark:\n%s", body)
	}
	addDetectionsRun(t, root, watched, "observe", watchedLeak...)
	s = newServer(t, root)
	c = login(t, s)
	body = get(t, s, c, "/detections")
	if !strings.Contains(body, "Only routine actions blocked") || strings.Contains(body, "No blocked actions") {
		t.Errorf("a leak and routine lines:\n%s", body)
	}
}

// TestLeaksLeadDetections: secrets that left are the worst thing the ledger can say, and no refusal group holds them. A
// watched run's leak leads the page, above the filters and above a High row of another run, and stays there under a
// filter that leaves nothing else; an all-watched ledger never shows a check mark and "Nothing blocked" beside it.
func TestLeaksLeadDetections(t *testing.T) {
	const watched, enforced = "r-aaaaaaaa-0000000000002-watchd", "r-aaaaaaaa-0000000000001-enforc"
	const banner = "Secrets left: id_rsa sent to 198.51.100.7:443"

	root := detectionsRoot(t, watched, "observe", watchedLeak...)
	s := newServer(t, root)
	c := login(t, s)
	body := get(t, s, c, "/detections")
	if !strings.Contains(body, banner) || !strings.Contains(body, "Watched only · nothing blocked") || !strings.Contains(body, `href="/runs/`+watched+`"`) {
		t.Errorf("Detections lacks the leak:\n%s", body)
	}
	if strings.Contains(body, "Nothing blocked") || strings.Contains(body, "#i-check") {
		t.Errorf("an all-watched ledger shows a check mark or Nothing blocked beside a leak:\n%s", body)
	}
	if !strings.Contains(body, "No blocked actions") {
		t.Error("the list does not say that nothing was blocked")
	}

	addDetectionsRun(t, root, enforced, "landlock",
		[2]string{"refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"203.0.113.9:443"`})
	s = newServer(t, root)
	c = login(t, s)
	body = get(t, s, c, "/detections")
	lead, filters, high := strings.Index(body, banner), strings.Index(body, `dt-filter`), strings.Index(body, `<td><span class="sev sev-High">`)
	if lead < 0 || filters < 0 || high < 0 || lead > filters || filters > high {
		t.Errorf("order: leak %d, filters %d, first High row %d", lead, filters, high)
	}
	if b := get(t, s, c, "/detections?sev=low"); !strings.Contains(b, banner) || strings.Contains(b, "#i-check") {
		t.Errorf("a filter hides the leak or puts a check mark beside it:\n%s", b)
	}
}

// TestRepeatsStayOnDetections: an attempt repeated 50 times stays where one attempt is: on Detections at its severity,
// in the Overview's grid and in its headline. The repeats used to fold it to Routine and out of all three.
func TestRepeatsStayOnDetections(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000001-repeat"
	var extras [][2]string
	for range 50 {
		extras = append(extras, [2]string{"refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"203.0.113.9:443"`})
	}
	s := newServer(t, detectionsRoot(t, run, "landlock", extras...))
	c := login(t, s)
	body := get(t, s, c, "/detections")
	if !strings.Contains(body, `<td><span class="sev sev-High">`) || !strings.Contains(body, "203.0.113.9") {
		t.Fatalf("the repeated connect is not a High row:\n%s", body)
	}
	if strings.Contains(body, "Routine 50") {
		t.Error("Detections folds the repeated connect as routine")
	}
	if o := get(t, s, c, "/"); !strings.Contains(o, `href="/detections?sev=high">1 High</a> blocked`) {
		t.Errorf("the Overview's headline lacks the repeated connect:\n%s", o)
	}
}

// TestDetections: the page lists blocked actions High first, a channel filter keeps only that channel, and the
// menu links it.
func TestDetections(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	body := get(t, s, c, "/detections")
	rows := body[strings.Index(body, "<tbody>"):]
	high, med := strings.Index(rows, `<td><span class="sev sev-High">`), strings.Index(rows, `<td><span class="sev sev-Medium">`)
	if high < 0 {
		t.Fatal("no High row")
	}
	if med >= 0 && med < high {
		t.Error("a Medium row comes before the first High row")
	}
	if !strings.Contains(body, `href="/detections" aria-current="page"`) {
		t.Error("the menu does not mark Detections")
	}
	// On a phone the table's head is hidden, so a bare count or time keeps its name through data-label (signal.css).
	for _, label := range []string{`data-label="Agent · Project"`, `data-label="Times"`, `data-label="Last"`} {
		if !strings.Contains(rows, label) {
			t.Errorf("a Detections row has no %s", label)
		}
	}
	net := get(t, s, c, "/detections?ch=network")
	for _, m := range strings.Split(net, `<div class="meta">`)[1:] {
		if !strings.HasPrefix(m, "Network ·") {
			t.Errorf("the Network filter shows %q", m[:min(len(m), 40)])
		}
	}
}

// TestApprovalsHistory: Approvals opens on Waiting; History lists the answers by run, each run once, or says none.
func TestApprovalsHistory(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	if b := get(t, s, c, "/approvals"); !strings.Contains(b, `href="/approvals" aria-current="page">Waiting`) {
		t.Error("Approvals does not open on Waiting")
	}
	b := get(t, s, c, "/approvals?tab=history")
	if !strings.Contains(b, `href="/approvals?tab=history" aria-current="page">History`) {
		t.Fatal("the History tab is not marked")
	}
	if !strings.Contains(b, `class="list ans-list"`) && !strings.Contains(b, "No answers yet") {
		t.Error("History shows neither answers nor its empty state")
	}
	seen := map[string]bool{}
	for _, part := range strings.Split(b, `<section class="panel" aria-label="`)[1:] {
		head := part[:strings.Index(part, `"`)]
		if seen[head] {
			t.Errorf("run %q listed twice", head)
		}
		seen[head] = true
	}
}

// TestGlossary: every page's top bar links the Glossary, which names each severity.
func TestGlossary(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	if !strings.Contains(get(t, s, c, "/"), `href="/glossary"`) {
		t.Error("the top bar does not link the Glossary")
	}
	g := get(t, s, c, "/glossary")
	for _, want := range []string{"<dt>High</dt>", "<dt>Policy</dt>", "<dt>Protection level</dt>"} {
		if !strings.Contains(g, want) {
			t.Errorf("Glossary lacks %s", want)
		}
	}
	// The dashboard says Basic, Strong and Strongest; the terminal, the docs and policy files say tier.
	for _, want := range []string{"Basic (no admin rights), Strong or Strongest (root)", "tier 1 (landlock), tier 2 (cgroup) and tier 3 (bpflsm)"} {
		if !strings.Contains(g, want) {
			t.Errorf("Glossary's Protection level does not connect the names: lacks %q", want)
		}
	}
}
