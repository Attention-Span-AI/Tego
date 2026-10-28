// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

const queryRun = "r-aaaaaaaa-0000000000003-queryx"

// queryLines is one ended run, with no refused action (so no mirror line): every line is a line Logs counts, and the
// JSONL download of the whole ledger is the events file byte for byte.
func queryLines() []string {
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	return []string{
		line(queryRun, "codex", 0, at(0), "run_start", `"tier":"landlock","command":["codex","exec"],"cwd":"/w/x/proj"`),
		line(queryRun, "codex", 1, at(1), "exec", `"verdict":"allow","rule":"exec.allow[rm]","path":"/bin/rm","argv":["rm","-rf","/tmp/my dir"]`),
		line(queryRun, "codex", 2, at(2), "exec", `"verdict":"allow","rule":"exec.allow[sh]","path":"/bin/sh","argv":["=cmd|' /C calc'!A0","+1","@x"]`),
		line(queryRun, "codex", 3, at(3), "refused", `"rule":"net.deny[chatgpt.com]","reason":"net-not-allowed","op":"connect","target":"chatgpt.com:443"`),
		line(queryRun, "codex", 4, at(4), "fs", `"verdict":"refused","rule":"fs.deny_read[~/.ssh]","reason":"read-denied","op":"open","path":"/w/x/home/.ssh/id_rsa","flags":0`),
		line(queryRun, "codex", 5, at(5), "net", `"verdict":"allow","rule":"net.allow[pypi.org]","proto":"tcp","dst":"151.101.0.223:443","host":"pypi.org"`),
		line(queryRun, "codex", 6, at(6), "run_end", `"reason":"exit","exit_code":0`),
	}
}

func queryFixture(t *testing.T) (root string, lines []string) {
	t.Helper()
	root = t.TempDir()
	lines = queryLines()
	if err := os.MkdirAll(filepath.Join(root, queryRun), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, queryRun, "events.jsonl"), []byte(strings.Join(lines, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, lines
}

var logsMatched = regexp.MustCompile(`<p class="lede">([\d,]+) lines? ·`)

func matchedOn(t *testing.T, body string) int {
	t.Helper()
	m := logsMatched.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no lede in %.400s", body)
	}
	var n int
	fmt.Sscan(strings.ReplaceAll(m[1], ",", ""), &n)
	return n
}

// TestLogsFiltersAndExports: every filter answers with its count on the page, and each download holds that many lines.
func TestLogsFiltersAndExports(t *testing.T) {
	root, lines := queryFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	for q, want := range map[string]int{
		"":                                        7,
		"q=-rf+/tmp/my+dir":                       1, // the literal search: a leading - and a space are text
		"q=" + url.QueryEscape("-rf"):             1,
		"where=" + url.QueryEscape("-rf"):         6, // the query language: - leaves the word out
		"where=kind:exec":                         2,
		"where=verdict:refused":                   2,
		"where=host:chatgpt.com":                  1,
		"where=host:pypi.org":                     1,
		"where=" + url.QueryEscape("path:~/.ssh"): 1,
		"where=" + url.QueryEscape("rule:fs.*"):   1,
		"where=pid:10":                            7,
		"where=pid:11":                            0,
		"where=source:supervisor":                 7,
		"where=" + url.QueryEscape("since:2026-10-25T12:00:04Z"): 3,
		"where=" + url.QueryEscape("until:2026-10-25T12:00:02Z"): 2,
		"where=-kind:run&verdict=refused":                        2,
		"where=kind:exec&verdict=refused":                        0,
		"where=run:" + queryRun:                                  7,
		"where=agent:codex&kind=exec":                            2,
		"where=" + url.QueryEscape(`"/tmp/my dir"`):              1,
	} {
		w := do(s, "GET", "/logs?"+q, "127.0.0.1:8484", c)
		if w.Code != http.StatusOK {
			t.Errorf("%s: %d", q, w.Code)
			continue
		}
		if got := matchedOn(t, w.Body.String()); got != want {
			t.Errorf("/logs?%s: %d lines, want %d", q, got, want)
		}
		j := do(s, "GET", "/logs.jsonl?"+q, "127.0.0.1:8484", c)
		if j.Code != http.StatusOK || !strings.HasPrefix(j.Header().Get("Content-Disposition"), "attachment;") {
			t.Errorf("jsonl %s: %d %q", q, j.Code, j.Header().Get("Content-Disposition"))
		}
		if got := strings.Count(j.Body.String(), "\n"); got != want {
			t.Errorf("/logs.jsonl?%s: %d lines, want %d", q, got, want)
		}
		v := do(s, "GET", "/logs.csv?"+q, "127.0.0.1:8484", c)
		recs, err := csv.NewReader(strings.NewReader(v.Body.String())).ReadAll()
		if v.Code != http.StatusOK || err != nil || len(recs) != want+1 {
			t.Errorf("/logs.csv?%s: %d, %v, %d records, want %d and a header", q, v.Code, err, len(recs), want)
		}
	}
	// The whole ledger as JSONL is the events file, byte for byte.
	if b := do(s, "GET", "/logs.jsonl", "127.0.0.1:8484", c).Body.String(); b != strings.Join(lines, "") {
		t.Errorf("jsonl differs from the events file:\n%s", b)
	}
	if b := do(s, "GET", "/logs.jsonl?order=newest&where=kind:exec", "127.0.0.1:8484", c).Body.String(); b != lines[2]+lines[1] {
		t.Errorf("newest first:\n%s", b)
	}
	// A cell a spreadsheet would read as a formula is prefixed with '.
	recs, err := csv.NewReader(strings.NewReader(do(s, "GET", "/logs.csv?where=pid:10+%22calc%22", "127.0.0.1:8484", c).Body.String())).ReadAll()
	if err != nil || len(recs) != 2 {
		t.Fatalf("csv: %v %d", err, len(recs))
	}
	if what := recs[1][7]; !strings.HasPrefix(what, "'=cmd") {
		t.Errorf("formula cell %q not prefixed", what)
	}
	for i, h := range recs[0] {
		if strings.ContainsAny(h[:1], "=+-@") {
			t.Errorf("header %d %q", i, h)
		}
	}
}

// noiseRoot is one ended run with a line the Logs page shows and two system reads it hides.
func noiseRoot(t *testing.T, run string) string {
	return detectionsRoot(t, run, "landlock",
		[2]string{"fs", `"rule":"fs.read[./]","verdict":"allow","op":"open","path":"/w/proj/main.go"`},
		[2]string{"fs", `"rule":"unmatched","verdict":"allow","op":"open","path":"/usr/lib/libc.so"`},
		[2]string{"fs", `"rule":"unmatched","verdict":"allow","op":"open","path":"/proc/self/status"`})
}

// TestLogsGroupViewsSayWhatIsHidden: the lines view says system reads are hidden and offers them; every group view
// does the same, whose counts leave them out as well.
func TestLogsGroupViewsSayWhatIsHidden(t *testing.T) {
	s := newServer(t, noiseRoot(t, "r-aaaaaaaa-0000000000033-noisey"))
	c := login(t, s)
	for _, g := range []string{"", ledgerview.GroupProcess, ledgerview.GroupTarget, ledgerview.GroupRule, ledgerview.GroupSeverity} {
		b := get(t, s, c, "/logs?group="+g)
		if !strings.Contains(b, "2 system lines hidden") {
			t.Errorf("group %q says nothing of the hidden lines:\n%s", g, b)
		}
		if !strings.Contains(b, "noise=show") {
			t.Errorf("group %q has no way to show them", g)
		}
	}
	if b := get(t, s, c, "/logs?group=rule&noise=show"); strings.Contains(b, "system lines hidden") {
		t.Errorf("the notice stays once the lines show:\n%s", b)
	}
}

// TestLogsExportTitlesCountTheFile: a download keeps the system reads the page hides, and its title counts them.
func TestLogsExportTitlesCountTheFile(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000034-noisey"
	s := newServer(t, noiseRoot(t, run))
	c := login(t, s)
	// A search that is not one whole run, so the JSONL is the matching lines and not the events file.
	const q = "where=kind:fs"
	page := get(t, s, c, "/logs?"+q)
	lines := strings.Count(do(s, "GET", "/logs.jsonl?"+q, "127.0.0.1:8484", c).Body.String(), "\n")
	if lines != 3 || matchedOn(t, page) != 1 {
		t.Fatalf("the file holds %d lines and the page %d, want 3 and 1", lines, matchedOn(t, page))
	}
	for _, want := range []string{"The 3 matching lines, the 2 hidden system lines included, as a spreadsheet", "The 3 matching ledger lines, the 2 hidden system lines included, byte for byte"} {
		if !strings.Contains(page, want) {
			t.Errorf("the title does not say %q:\n%s", want, page)
		}
	}
	// Only hidden lines match: the buttons still download them.
	only := get(t, s, c, "/logs?q=/usr/lib/libc.so")
	if !strings.Contains(only, `href="/logs.csv?q=`) {
		t.Errorf("no download for a search that holds only hidden lines:\n%s", only)
	}
	// Nothing hidden: the title says what it always said.
	if b := get(t, s, c, "/logs?where=kind:fs&noise=show"); !strings.Contains(b, "The 3 matching lines as a spreadsheet") {
		t.Errorf("with the lines shown the title changed:\n%s", b)
	}
}

func TestLogsExportAccess(t *testing.T) {
	root, _ := queryFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	for _, p := range []string{"/logs.jsonl", "/logs.csv"} {
		if w := do(s, "GET", p, "127.0.0.1:8484", nil); w.Code != http.StatusUnauthorized {
			t.Errorf("%s without the cookie: %d", p, w.Code)
		}
		if w := do(s, "GET", p, "evil.example:8484", c); w.Code != http.StatusMisdirectedRequest {
			t.Errorf("%s from another host: %d", p, w.Code)
		}
		if w := do(s, "POST", p, "127.0.0.1:8484", c); w.Code == http.StatusOK {
			t.Errorf("POST %s answered 200", p)
		}
		if w := do(s, "HEAD", p, "127.0.0.1:8484", c); w.Code != http.StatusOK || w.Body.Len() != 0 {
			t.Errorf("HEAD %s: %d with %d bytes", p, w.Code, w.Body.Len())
		}
		if w := do(s, "GET", p, "127.0.0.1:8484", c); w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q", p, w.Header().Get("Cache-Control"))
		}
	}
}

// TestLogsPageQueryParts: the chips, facets, presets and downloads, and a query error that leaves the rest working.
func TestLogsPageQueryParts(t *testing.T) {
	root, _ := queryFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	b := do(s, "GET", "/logs?where="+url.QueryEscape("kind:exec -host:x.org"), "127.0.0.1:8484", c).Body.String()
	for _, want := range []string{
		`class="chip lq-chip"`, `>kind:exec<`, `class="chip lq-chip lq-neg"`, `aria-label="Remove kind:exec from the query"`,
		`href="/logs?where=-host%3Ax.org"`, // removing kind:exec keeps the other term
		`data-live="r-logs-facets"`, `<h2 class="lq-fh">Verdict</h2>`, `aria-current="true"><span class="lq-l">Commands</span><span class="lq-n">2</span>`,
		`href="/logs.jsonl?where=kind%3Aexec&#43;-host%3Ax.org"`, `href="/logs.csv?where=kind%3Aexec&#43;-host%3Ax.org"`,
		"Not masked", `href="/static/logs.css"`, ">5 min<", ">Latest run<",
	} {
		if !strings.Contains(b, want) {
			t.Errorf("page lacks %s", want)
		}
	}
	b = do(s, "GET", "/logs?where="+url.QueryEscape("pid:abc kind:exec"), "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(b, "Part of the query was left out: pid:abc: not a process number") || matchedOn(t, b) != 2 {
		t.Errorf("query error: %d lines", matchedOn(t, b))
	}
	// A facet value adds its token; its − leaves it out.
	b = do(s, "GET", "/logs", "127.0.0.1:8484", c).Body.String()
	for _, want := range []string{`href="/logs?where=host%3Apypi.org"`, `href="/logs?where=-host%3Apypi.org"`, `href="/logs?where=verdict%3Arefused"`} {
		if !strings.Contains(b, want) {
			t.Errorf("facets lack %s", want)
		}
	}
	// The time presets replace a time range rather than add to it (html/template writes + as &#43;).
	b = do(s, "GET", "/logs?where="+url.QueryEscape("kind:exec since:1h"), "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(b, `href="/logs?where=kind%3Aexec&#43;since%3A5m"`) || !strings.Contains(b, `aria-current="true">1 hour<`) {
		t.Error("time presets do not replace the range")
	}
}

// TestLogsTextStaysLiteral: the event page's links (/logs?q=<value>) find the same lines as a plain substring search.
func TestLogsTextStaysLiteral(t *testing.T) {
	root, _ := queryFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	snap, err := ledgerview.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"-rf /tmp/my dir", "run:" + queryRun, "path:/w", `"quoted"`, "chatgpt.com:443", "unix:/var/run/nscd/socket"} {
		want := snap.Query(ledgerview.Filter{Text: v}).Matched
		if got := matchedOn(t, do(s, "GET", "/logs?q="+url.QueryEscape(v), "127.0.0.1:8484", c).Body.String()); got != want {
			t.Errorf("q=%q: %d lines, the literal search %d", v, got, want)
		}
	}
}

func TestRunChoices(t *testing.T) {
	var runs []*ledgerview.Run
	for i := range 60 {
		runs = append(runs, &ledgerview.Run{ID: fmt.Sprintf("r-x-%04d-aaaa", i)})
	}
	list, more := runChoices(runs, "")
	if len(list) != logsRunList || more != 10 {
		t.Errorf("%d listed, %d more", len(list), more)
	}
	list, _ = runChoices(runs, "r-x-0055-aaaa")
	if len(list) != logsRunList+1 || list[logsRunList].ID != "r-x-0055-aaaa" {
		t.Errorf("selected old run not listed: %d", len(list))
	}
	if list, more := runChoices(runs[:3], ""); len(list) != 3 || more != 0 {
		t.Errorf("short list %d %d", len(list), more)
	}
}

func TestCSVCell(t *testing.T) {
	for in, want := range map[string]string{"=1+1": "'=1+1", "+x": "'+x", "-rf": "'-rf", "@SUM": "'@SUM", "\tx": "'\tx", "\rx": "'\rx", "ok": "ok", "": ""} {
		if got := csvCell(in); got != want {
			t.Errorf("csvCell(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCountWord(t *testing.T) {
	for n, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", 17462: "17,462", 1234567: "1,234,567"} {
		if got := countWord(n); got != want {
			t.Errorf("countWord(%d) = %q", n, got)
		}
	}
}
