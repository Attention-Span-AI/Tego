// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/csv"
	"html"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// A watched run's lines read as watched wherever a page names their rule (PW-3): no rule decided them, so By rule
// keeps them apart from the lines their rule decided.

const (
	pw3Watch = "r-aaaaaaaa-0000000000041-watchx"
	pw3Enf   = "r-aaaaaaaa-0000000000042-enforx"
)

// pw3Fixture is a watched run (tier observe) and an enforced run of one contract, which never lets the agent read
// ~/.ssh/ or ~/.aws/. The watched run read the ssh key and connected to a host the contract does not allow, and
// recorded both as observed under the rule each would have matched, with the authority rule a watched run's lines
// carry; the enforced run's same read and connection were refused by those rules, and so was its read of the aws
// credentials, which the watched run did not make.
func pw3Fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	const contract = "fs:\n  deny_read:\n    - /w/x/home/.ssh/\n    - /w/x/home/.aws/\n  write:\n    - /w/x/proj/\n"
	write := func(run string, ls ...string) {
		if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, run, "contract.yaml"), []byte(contract), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	deny := `"rule":"fs.deny_read[/w/x/home/.ssh/]","authority":"rule","op":"open","path":"/w/x/home/.ssh/id_rsa","flags":0`
	aws := `"rule":"fs.deny_read[/w/x/home/.aws/]","authority":"rule","op":"open","path":"/w/x/home/.aws/credentials","flags":0`
	send := `"rule":"unmatched","authority":"rule","proto":"tcp","dst":"127.0.0.1:8802"`
	write(pw3Watch,
		line(pw3Watch, "watch-codex", 0, at(0), "run_start", `"tier":"observe","command":["codex"],"cwd":"/w/x/proj"`),
		line(pw3Watch, "watch-codex", 1, at(1), "fs", `"verdict":"observed",`+deny),
		line(pw3Watch, "watch-codex", 2, at(2), "net", `"verdict":"observed",`+send),
		line(pw3Watch, "watch-codex", 3, at(3), "run_end", `"reason":"exit","exit_code":0`))
	write(pw3Enf,
		line(pw3Enf, "codex", 0, at(10), "run_start", `"tier":"landlock","command":["codex"],"cwd":"/w/x/proj"`),
		line(pw3Enf, "codex", 1, at(11), "fs", `"verdict":"refused","reason":"read-denied",`+deny),
		line(pw3Enf, "codex", 2, at(11), "refused", `"rule":"fs.deny_read[/w/x/home/.ssh/]","reason":"read-denied","op":"open","target":"/w/x/home/.ssh/id_rsa"`),
		line(pw3Enf, "codex", 3, at(12), "net", `"verdict":"refused","reason":"net-not-allowed",`+send),
		line(pw3Enf, "codex", 4, at(12), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"127.0.0.1:8802"`),
		line(pw3Enf, "codex", 5, at(13), "fs", `"verdict":"refused","reason":"read-denied",`+aws),
		line(pw3Enf, "codex", 6, at(13), "refused", `"rule":"fs.deny_read[/w/x/home/.aws/]","reason":"read-denied","op":"open","target":"/w/x/home/.aws/credentials"`),
		line(pw3Enf, "codex", 7, at(14), "run_end", `"reason":"exit","exit_code":0`))
	return root
}

// lineRowKey reads a Logs row's run and line (its data-k).
var lineRowKey = regexp.MustCompile(`<tr role="row" data-k="([^"]+)"`)

// rowKeys is the run-line of every row a Logs page lists, sorted.
func rowKeys(page string) []string {
	ks := []string{}
	for _, m := range lineRowKey.FindAllStringSubmatch(page, -1) {
		ks = append(ks, m[1])
	}
	slices.Sort(ks)
	return ks
}

// ruleGroupRe reads a By rule row: its words, their title, the rule key, the lines link and count, and the blocked count.
var ruleGroupRe = regexp.MustCompile(`<span class="g-main"(?: title="([^"]*)")?>([^<]*)</span><span class="g-sub mono">([^<]*)</span></td><td role="cell" data-label="Lines" class="g-n"><a class="link" href="([^"]*)" title="Show these lines">([\d,]+)</a></td><td role="cell" data-label="Refused" class="g-n">(?:<span class="n-refused">([\d,]+)</span>|<span class="soft">0</span>)`)

type ruleGroupCell struct {
	words, title, key, link string
	lines, blocked          int
}

// ruleGroups is the By rule rows of a Logs page, by their words.
func ruleGroups(t *testing.T, page string) map[string]ruleGroupCell {
	t.Helper()
	out := map[string]ruleGroupCell{}
	for _, m := range ruleGroupRe.FindAllStringSubmatch(page, -1) {
		g := ruleGroupCell{title: html.UnescapeString(m[1]), words: html.UnescapeString(m[2]), key: html.UnescapeString(m[3]),
			link: html.UnescapeString(m[4])}
		g.lines, _ = strconv.Atoi(strings.ReplaceAll(m[5], ",", ""))
		g.blocked, _ = strconv.Atoi(strings.ReplaceAll(m[6], ",", ""))
		if _, dup := out[g.words]; dup {
			t.Errorf("two By rule rows read %q", g.words)
		}
		out[g.words] = g
	}
	return out
}

// TestByRuleKeepsWatchedLinesApart: By rule counts the watched run's read under the deny_read entry and its send as
// "Watched only", never under the rule that refused the enforced run's same read and connection, and each group's
// count opens exactly its lines, also from a search that already names rules: the Secret files view
// (rule:fs.deny_read*), the group's own rule, and that rule beside another entry's. The same key twice reads as either
// value, so a link that added the group's rule beside the query's listed the other entry's lines too, and one that
// toggled it off a query that named it lost the rule.
func TestByRuleKeepsWatchedLinesApart(t *testing.T) {
	s := newServer(t, pw3Fixture(t))
	c := login(t, s)
	const ssh, aws = "fs.deny_read[/w/x/home/.ssh/]", "fs.deny_read[/w/x/home/.aws/]"
	type want struct {
		key     string
		rows    []string // the group's lines, run-line, sorted
		blocked int
		watched bool
	}
	groupsOf := map[string]want{
		"Never read: /w/x/home/.ssh/":                {ssh, []string{pw3Enf + "-1"}, 1, false},
		"Watched only · Never read: /w/x/home/.ssh/": {ssh, []string{pw3Watch + "-1"}, 0, true},
		"Never read: /w/x/home/.aws/":                {aws, []string{pw3Enf + "-5"}, 1, false},
		"Not in contract":                            {"unmatched", []string{pw3Enf + "-3"}, 1, false},
		"Watched only":                               {"unmatched", []string{pw3Watch + "-2"}, 0, true},
	}
	sshGroups := []string{"Never read: /w/x/home/.ssh/", "Watched only · Never read: /w/x/home/.ssh/"}
	for _, tc := range []struct {
		where string
		words []string // the groups the search shows
	}{
		{"", slices.Collect(maps.Keys(groupsOf))},
		{"rule:fs.deny_read*", append([]string{"Never read: /w/x/home/.aws/"}, sshGroups...)},
		{"rule:" + ssh, sshGroups},
		{"rule:" + aws + " rule:" + ssh, append([]string{"Never read: /w/x/home/.aws/"}, sshGroups...)},
		{"rule:fs.deny_read* -rule:" + aws, sshGroups}, // a rule the query leaves out stays out
	} {
		where := tc.where
		groups := ruleGroups(t, get(t, s, c, "/logs?group=rule&where="+url.QueryEscape(where)))
		if len(groups) != len(tc.words) {
			t.Errorf("where %q: By rule rows %+v, want %q", where, groups, tc.words)
		}
		for _, words := range tc.words {
			w := groupsOf[words]
			g, ok := groups[words]
			if !ok {
				t.Errorf("where %q: no By rule row reads %q (rows %+v)", where, words, groups)
				continue
			}
			if g.key != w.key || g.lines != len(w.rows) || g.blocked != w.blocked {
				t.Errorf("where %q, %q: %+v, want %+v", where, words, g, w)
			}
			if w.watched != strings.Contains(g.title, "their runs were watched, not enforced") {
				t.Errorf("where %q, %q: title %q", where, words, g.title)
			}
			page := get(t, s, c, g.link)
			if n, rows := matchedOn(t, page), rowKeys(page); n != g.lines || !slices.Equal(rows, w.rows) {
				t.Errorf("where %q, %q: its link %s lists %d lines %q, the group holds %d: %q", where, words, g.link, n, rows,
					g.lines, w.rows)
			}
		}
	}
	// One watched run alone: every rule row is watched, and its link opens its lines as recorded only (verdict:observed),
	// though no line the rule decided is in the search.
	for words, g := range ruleGroups(t, get(t, s, c, "/logs?group=rule&run="+pw3Watch)) {
		if !strings.HasPrefix(words, "Watched only") {
			t.Errorf("the watched run's By rule reads %q", words)
		}
		u, err := url.Parse(g.link)
		if err != nil {
			t.Fatal(err)
		}
		where := u.Query().Get("where")
		if !strings.Contains(where, "verdict:observed") || strings.Contains(where, "-verdict:observed") {
			t.Errorf("the watched run's %q opens %q, not its recorded-only lines", words, where)
		}
		page := get(t, s, c, g.link)
		if rows := rowKeys(page); matchedOn(t, page) != g.lines || len(rows) != g.lines {
			t.Errorf("the watched run's %q: its link %s lists %q, the group holds %d", words, g.link, rows, g.lines)
		}
	}
	// An enforced run's line its rule did not decide is apart as well, in the words its row's verdict uses.
	for _, tc := range []struct {
		g            ledgerview.GroupRow
		words, title string
	}{
		{ledgerview.GroupRow{Rule: "path-unreliable", Observed: true}, "Observed · path-unreliable", "No rule decided these lines: they were recorded only"},
		{ledgerview.GroupRow{Rule: "unmatched", Observed: true, Watched: true}, "Watched only", "No rule decided these lines: their runs were watched, not enforced"},
		{ledgerview.GroupRow{Rule: "fs.deny_read[/x/]"}, "Never read: /x/", ""},
	} {
		if words, title := ruleGroupWords(tc.g); words != tc.words || title != tc.title {
			t.Errorf("%+v reads %q (%q), want %q (%q)", tc.g, words, title, tc.words, tc.title)
		}
	}
}

// openedLine is a Logs row opened in place (GET /logs/line).
func openedLine(t *testing.T, s *Server, c *http.Cookie, run, seq string) string {
	t.Helper()
	w := do(s, "GET", "/logs/line?run="+run+"&seq="+seq, "127.0.0.1:8484", c)
	if w.Code != http.StatusOK {
		t.Fatalf("%s line %s opened in place: %d", run, seq, w.Code)
	}
	return w.Body.String()
}

// lineDecision is the decision column of a line page.
func lineDecision(t *testing.T, s *Server, c *http.Cookie, run, seq string) string {
	t.Helper()
	page := get(t, s, c, "/runs/"+run+"/lines/"+seq)
	i, j := strings.Index(page, `id="h-dec"`), strings.Index(page, `id="h-who"`)
	if i < 0 || j < i {
		t.Fatalf("%s line %s: no decision column", run, seq)
	}
	return page[i:j]
}

// authorityField reads the authority field in a line page's Every field, and openAuthorityField in a row opened in
// place.
var (
	authorityField     = regexp.MustCompile(`ev-fkey">authority</span></th><td class="ev-fv"><span class="ev-wrap"[^>]*>([^<]*)</span>`)
	openAuthorityField = regexp.MustCompile(`<dt title="authority">Decided by</dt><dd><span class="ut lx-v">([^<]*)</span>`)
)

// TestWatchedLineNamesNoDecider: a watched run's line names no one who decided it. Its Logs row reads "Watched only,
// not enforced"; opened in place, and on its line page, its rule reads watched only beside the rule it would have
// matched, the line page has no "Decided by" row, and the line's authority field, which record v1 puts on every
// action, reads "no one". The enforced run's same lines keep their rule and who decided them.
func TestWatchedLineNamesNoDecider(t *testing.T) {
	s := newServer(t, pw3Fixture(t))
	c := login(t, s)
	logs := get(t, s, c, "/logs?run="+pw3Watch)
	if i := strings.Index(logs, `data-k="`+pw3Watch+`-1"`); i < 0 || !strings.Contains(logs[i:i+strings.Index(logs[i:], "</tr>")], watchedLabel) {
		t.Errorf("the watched read's Logs row does not read %q", watchedLabel)
	}
	opened := func(run, seq string) string { return openedLine(t, s, c, run, seq) }
	mustContain(t, "the watched read opened in place", opened(pw3Watch, "1"),
		`<dt>Rule</dt><dd>Watched only · Never read: /w/x/home/.ssh/ <span class="mono soft">fs.deny_read[/w/x/home/.ssh/]</span>`)
	mustContain(t, "the watched send opened in place", opened(pw3Watch, "2"),
		`<dt>Rule</dt><dd>Watched only <span class="mono soft">unmatched</span>`)
	mustContain(t, "the refused read opened in place", opened(pw3Enf, "1"),
		`<dt>Rule</dt><dd>Never read: /w/x/home/.ssh/ <span class="mono soft">fs.deny_read[/w/x/home/.ssh/]</span>`)
	mustContain(t, "the refused connection opened in place", opened(pw3Enf, "3"),
		`<dt>Rule</dt><dd>Host not in contract <span class="mono soft">unmatched</span>`)

	decision := func(run, seq string) string { return lineDecision(t, s, c, run, seq) }
	for _, seq := range []string{"1", "2"} {
		if d := decision(pw3Watch, seq); strings.Contains(d, "<dt>Decided by</dt>") {
			t.Errorf("the watched run's line %s names who decided it:\n%s", seq, d)
		}
	}
	// The contract line the watched read would have matched, in the run's state: watched only.
	mustContain(t, "the watched read's decision", decision(pw3Watch, "1"), "Can never read files in ~/.ssh/",
		`<span class="b b-neutral">watched only</span>`)
	if d := decision(pw3Watch, "2"); !strings.Contains(d, `<dt>Rule</dt><dd>Watched only <span class="mono muted ev-wrap">unmatched</span>`) ||
		strings.Contains(d, "not in contract") {
		t.Errorf("the watched send's rule does not read Watched only:\n%s", d)
	}
	refused := decision(pw3Enf, "1")
	mustContain(t, "the refused read's decision", refused, `<dt>Decided by</dt><dd class="ev-wrap">a rule</dd>`,
		"Can never read files in ~/.ssh/")
	if strings.Contains(refused, "watched only") {
		t.Errorf("the enforced run's refusal reads watched only:\n%s", refused)
	}
	mustContain(t, "the refused connection's decision", decision(pw3Enf, "3"),
		`<dt>Decided by</dt><dd class="ev-wrap">a rule</dd>`, `<dt>Rule</dt><dd>Host not in contract <span class="mono muted ev-wrap">unmatched</span>`)

	// The authority field, in the line page's Every field and in the row opened in place.
	for _, tc := range []struct{ run, seq, want string }{
		{pw3Watch, "1", "no one: recorded only"}, {pw3Watch, "2", "no one: recorded only"},
		{pw3Enf, "1", "a rule"}, {pw3Enf, "3", "a rule"},
	} {
		if m := authorityField.FindStringSubmatch(get(t, s, c, "/runs/"+tc.run+"/lines/"+tc.seq)); m == nil || m[1] != tc.want {
			t.Errorf("%s line %s: the authority field reads %q, want %q", tc.run, tc.seq, m, tc.want)
		}
		if m := openAuthorityField.FindStringSubmatch(opened(tc.run, tc.seq)); m == nil || m[1] != tc.want {
			t.Errorf("%s line %s opened in place: the authority field reads %q, want %q", tc.run, tc.seq, m, tc.want)
		}
	}
}

// pw3Held is an enforced run that recorded two opens as observed. A person allowed the first, a held open whose object
// turned out to have no name: the supervisor claims no verdict on a nameless object and records it under the person
// who allowed it (emitHeldOutcome). The second was on a path the supervisor could not read, under the authority rule
// that record v1 puts on every action.
const pw3Held = "r-aaaaaaaa-0000000000043-heldxx"

func pw3HeldFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	ls := []string{
		line(pw3Held, "codex", 0, at(0), "run_start", `"tier":"landlock","command":["codex"],"cwd":"/w/x/proj"`),
		line(pw3Held, "codex", 1, at(1), "ask", `"verdict":"ask","ask_id":"q-7","ask_rule":"fs.ask_read[/w/x/proj/c/]","hold":"open","op":"read","target":"/w/x/proj/c/plan.md"`),
		line(pw3Held, "codex", 2, at(3), "answer", `"ask_id":"q-7","approved":true,"by":"uid:1000 pid:9 dashboard","after_s":2,"op":"read","target":"/w/x/proj/c/plan.md"`),
		line(pw3Held, "codex", 3, at(3), "fs", `"verdict":"observed","authority":"human","rule":"path-unreliable","op":"open","path":"/w/x/proj/c/plan.md","flags":0,"operation_completed":true,"fd_delivered":false`),
		line(pw3Held, "codex", 4, at(4), "fs", `"verdict":"observed","authority":"rule","rule":"path-unreliable","op":"open","path":"/w/x/proj/a","flags":0`),
		line(pw3Held, "codex", 5, at(5), "run_end", `"reason":"exit","exit_code":0`),
	}
	if err := os.MkdirAll(filepath.Join(root, pw3Held), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, pw3Held, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestObservedLineKeepsWhoAllowedIt: only the authority every action carries (rule) reads as no one on a line recorded
// as observed. The open a person allowed keeps "Decided by: a person" on its line page, and its authority field reads
// "a person" there and opened in place; the same run's observed line under the authority rule names no one.
func TestObservedLineKeepsWhoAllowedIt(t *testing.T) {
	s := newServer(t, pw3HeldFixture(t))
	c := login(t, s)
	mustContain(t, "the allowed open's decision", lineDecision(t, s, c, pw3Held, "3"),
		"Recorded only, not decided", `<dt>Decided by</dt><dd class="ev-wrap">a person</dd>`)
	if d := lineDecision(t, s, c, pw3Held, "4"); strings.Contains(d, "<dt>Decided by</dt>") {
		t.Errorf("the observed open under the authority rule names who decided it:\n%s", d)
	}
	for _, tc := range []struct{ seq, want string }{{"3", "a person"}, {"4", "no one: recorded only"}} {
		page := get(t, s, c, "/runs/"+pw3Held+"/lines/"+tc.seq)
		if m := authorityField.FindStringSubmatch(page); m == nil || m[1] != tc.want {
			t.Errorf("line %s: the authority field reads %q, want %q", tc.seq, m, tc.want)
		}
		if m := openAuthorityField.FindStringSubmatch(openedLine(t, s, c, pw3Held, tc.seq)); m == nil || m[1] != tc.want {
			t.Errorf("line %s opened in place: the authority field reads %q, want %q", tc.seq, m, tc.want)
		}
	}
	for _, tc := range []struct{ verdict, authority, verdictWords, by string }{
		{"observed", "rule", "Recorded only, not decided", ""},
		{"observed", "human", "Recorded only, not decided", "a person"},
		{"observed", "gate", "Recorded only, not decided", "a gate"},
		{"refused", "rule", "Refused", "a rule"},
	} {
		v, by := decisionWords(&ledgerview.Event{Kind: "fs", Verdict: tc.verdict, Authority: tc.authority})
		if v != tc.verdictWords || by != tc.by {
			t.Errorf("a line %s under %s: %q, decided by %q, want %q, %q", tc.verdict, tc.authority, v, by, tc.verdictWords,
				tc.by)
		}
	}
}

// csvRuleWords is the "Rule in words" of each line a Logs CSV download holds, by run-line.
func csvRuleWords(t *testing.T, s *Server, c *http.Cookie, q string) map[string]string {
	t.Helper()
	w := do(s, "GET", "/logs.csv?"+q, "127.0.0.1:8484", c)
	recs, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if w.Code != http.StatusOK || err != nil || len(recs) < 2 {
		t.Fatalf("/logs.csv?%s: %d, %v, %d records", q, w.Code, err, len(recs))
	}
	run, seq, words := slices.Index(recs[0], "Run"), slices.Index(recs[0], "Line"), slices.Index(recs[0], "Rule in words")
	if run < 0 || seq < 0 || words < 0 {
		t.Fatalf("/logs.csv header %q", recs[0])
	}
	out := map[string]string{}
	for _, r := range recs[1:] {
		out[r[run]+"-"+r[seq]] = r[words]
	}
	return out
}

// logsRuleCell reads a Logs row's Rule cell.
var logsRuleCell = regexp.MustCompile(`data-label="Rule" class="c-rule"><span class="clamp" title="[^"]*"><span>([^<]*)</span>`)

// TestLogsCSVRuleReadsAsTheRow: the CSV, which DASHBOARD.md says is in the page's words, words each line's rule as its
// Logs row does. A watched run's observed line reads "Watched only, not enforced", never the deny rule it would have
// matched nor the default deny's "Host not in policy"; the enforced run's refusals keep their rules' words; a live
// block's refusal reads who blocked it and when, as its row does.
func TestLogsCSVRuleReadsAsTheRow(t *testing.T) {
	s := newServer(t, pw3Fixture(t))
	c := login(t, s)
	got := csvRuleWords(t, s, c, "")
	for key, want := range map[string]string{
		pw3Watch + "-1": watchedLabel,
		pw3Watch + "-2": watchedLabel,
		pw3Enf + "-1":   "Never read: /w/x/home/.ssh/",
		pw3Enf + "-3":   "Host not in contract",
		pw3Enf + "-5":   "Never read: /w/x/home/.aws/",
	} {
		if got[key] != want {
			t.Errorf("the CSV words line %s's rule %q, want %q", key, got[key], want)
		}
	}

	s = newServer(t, liveBlockFixture(t))
	c = login(t, s)
	key := harmRun + "-8"
	logs := get(t, s, c, "/logs?q=ls")
	i := strings.Index(logs, `data-k="`+key+`"`)
	if i < 0 {
		t.Fatalf("Logs lists no row %s", key)
	}
	m := logsRuleCell.FindStringSubmatch(logs[i : i+strings.Index(logs[i:], "</tr>")])
	if m == nil || !strings.HasPrefix(html.UnescapeString(m[1]), "Blocked live at ") {
		t.Fatalf("the live block's Logs row reads %q", m)
	}
	if words := csvRuleWords(t, s, c, "q=ls")[key]; words != html.UnescapeString(m[1]) {
		t.Errorf("the CSV words the live block's refusal %q, its Logs row %q", words, html.UnescapeString(m[1]))
	}
}
