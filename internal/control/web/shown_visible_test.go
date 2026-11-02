// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"context"
	"encoding/csv"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/pkg/spec/askproto"
)

// rlo is U+202E RIGHT-TO-LEFT OVERRIDE: "a" + rlo + "txt.exe" shows as "aexe.txt" when written as it is.
const rlo = "\u202e"

func TestVisibleText(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", ""},
		{"/home/u/proj/out/report.md", "/home/u/proj/out/report.md"},
		{"naïve résumé 日本 שלום مرحبا", "naïve résumé 日本 שלום مرحبا"},
		{"line\nnext\ttab", "line\nnext\ttab"}, // controls are not format characters: breakPieces wraps at them
		{"confidential/a" + rlo + "txt.exe", "confidential/a⟦U+202E⟧txt.exe"},
		{"\u202a\u202b\u202c\u202d", "⟦U+202A⟧⟦U+202B⟧⟦U+202C⟧⟦U+202D⟧"},
		{"iso\u2066x\u2067y\u2068z\u2069", "iso⟦U+2066⟧x⟦U+2067⟧y⟦U+2068⟧z⟦U+2069⟧"},
		{"marks\u200e\u200f\u061c", "marks⟦U+200E⟧⟦U+200F⟧⟦U+061C⟧"},
		{"zw\u200bsp\u2060wj\ufeffbom\u00adshy", "zw⟦U+200B⟧sp⟦U+2060⟧wj⟦U+FEFF⟧bom⟦U+00AD⟧shy"},
		{"tag\U000e0041", "tag⟦U+E0041⟧"},
		{"sep\u2028x", "sep⟦U+2028⟧x"},
		// The zero-width joiner and a variation selector make emoji, and reorder nothing: kept.
		{"family 👨\u200d👩\u200d👧 heart ❤\ufe0f", "family 👨\u200d👩\u200d👧 heart ❤\ufe0f"},
		{"bad\xffutf8" + rlo, "bad\xffutf8⟦U+202E⟧"},
	} {
		got := visibleText(tc.in)
		if got != tc.want {
			t.Errorf("visibleText(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if visibleText(got) != got {
			t.Errorf("visibleText is not stable on %q", got)
		}
		if hasHidden(got) {
			t.Errorf("visibleText(%q) = %q still holds a hidden rune", tc.in, got)
		}
	}
}

// TestVisibleTextPlainIsSame: text with nothing to write is returned as it is, without a copy.
func TestVisibleTextPlainIsSame(t *testing.T) {
	in := strings.Repeat("~/proj/confidential/plan.md · ", 100)
	if got := visibleText(in); got != in {
		t.Fatalf("visibleText changed plain text")
	}
	if n := testing.AllocsPerRun(10, func() { _ = visibleText(in) }); n != 0 {
		t.Errorf("visibleText of plain text allocated %v times", n)
	}
	page := []byte(`<p title="a/b">` + in + `</p>`)
	if got := visibleHTML(page); &got[0] != &page[0] || len(got) != len(page) {
		t.Errorf("visibleHTML copied a page with nothing to write")
	}
}

// TestVisibleHTML: text, titles and labels are written visibly; a form's value, a textarea and a <template
// data-exact> stay as written; a region's <template data-live> is a page part like any other.
func TestVisibleHTML(t *testing.T) {
	name := "a" + rlo + "txt.exe"
	seen := "a⟦U+202E⟧txt.exe"
	for _, tc := range []struct{ in, want string }{
		{`<b class="sp-b">` + name + `</b>`, `<b class="sp-b">` + seen + `</b>`},
		{`<span class="ut" title="/p/` + name + `">x</span>`, `<span class="ut" title="/p/` + seen + `">x</span>`},
		{`<pre aria-label="` + name + `">` + name + `</pre>`, `<pre aria-label="` + seen + `">` + seen + `</pre>`},
		{`<input type="hidden" name="value" value="/p/` + name + `">` + name, `<input type="hidden" name="value" value="/p/` + name + `">` + seen},
		{"<option\nvalue=\"" + name + "\">" + name + "</option>", "<option\nvalue=\"" + name + "\">" + seen + "</option>"},
		{`<i data-value="` + name + `"></i>`, `<i data-value="` + seen + `"></i>`},
		{`<textarea name="text">` + name + `</textarea>` + name, `<textarea name="text">` + name + `</textarea>` + seen},
		{`<template data-exact class="lx-raw">` + name + `</template>` + name, `<template data-exact class="lx-raw">` + name + `</template>` + seen},
		{`<template data-live="content" data-h="1"><p>` + name + `<template data-exact>` + name + `</template>` + name + `</p></template>`,
			`<template data-live="content" data-h="1"><p>` + seen + `<template data-exact>` + name + `</template>` + seen + `</p></template>`},
		{`<template class="other">` + name + `</template>`, `<template class="other">` + seen + `</template>`},
		{`<textarea>` + name, `<textarea>` + name}, // unclosed: kept to the end
		{name + "\u200d" + name, seen + "\u200d" + seen},
	} {
		if got := string(visibleHTML([]byte(tc.in))); got != tc.want {
			t.Errorf("visibleHTML(%q)\n got %q\nwant %q", tc.in, got, tc.want)
		}
	}
}

// BenchmarkVisibleHTML is the check every page pays: a large page with nothing to write, and one with a name to write.
func BenchmarkVisibleHTML(b *testing.B) {
	row := `<tr class="lq-r" data-k="1"><td><span class="ut pw" title="/home/u/proj/src/main.go">./src/<wbr><b class="sp-b">main.go</b></span> · read · allowed</td><td><input type="hidden" name="value" value="/home/u/proj/src/main.go"></td></tr>` + "\n"
	plain := []byte(strings.Repeat(row, 8000))
	marked := []byte(strings.Repeat(row, 7999) + strings.ReplaceAll(row, "main.go", "a"+rlo+"txt.exe"))
	for _, bc := range []struct {
		name string
		page []byte
	}{{"plain", plain}, {"marked", marked}} {
		b.Run(bc.name, func(b *testing.B) {
			b.SetBytes(int64(len(bc.page)))
			for range b.N {
				_ = visibleHTML(bc.page)
			}
		})
	}
}

const bidiRun = "r-aaaaaaaa-0000000000003-bidixx"

// bidiAsk is the request waiting in bidiFixture; bidiTarget the file it asks to read, named so that, written as it
// is, it reads as confidential/aexe.txt.
const (
	bidiAsk    = "q-0123456789abcdef0123456789abcd0e"
	bidiTarget = "/p/proj/confidential/a" + rlo + "txt.exe"
	bidiSeen   = "confidential/a⟦U+202E⟧txt.exe"
)

// bidiFixture is a ledger root with one live run whose agent wrote U+202E into everything it chose: the command,
// paths, a host, a refused read, an answered request and one still waiting.
func bidiFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t0 := time.Date(2026, 10, 25, 12, 4, 0, 0, time.UTC) // newServer's clock reads 12:05: the last ask waits 10 s
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	ls := []string{
		line(bidiRun, "bidi-agent", 0, at(0), "run_start", `"tier":"landlock","cwd":"/p/proj","command":["sh","-c","cat a`+rlo+`txt.exe"]`),
		line(bidiRun, "bidi-agent", 1, at(1), "fs", `"verdict":"allow","op":"open","path":"/p/proj/out/b`+rlo+`gnp.sh","flags":577`),
		line(bidiRun, "bidi-agent", 2, at(2), "refused", `"rule":"unmatched","reason":"read-denied","op":"open","target":"/p/proj/secret/c`+rlo+`fdp.exe"`),
		line(bidiRun, "bidi-agent", 3, at(3), "exec", `"verdict":"allow","rule":"exec.allow[cat]","path":"/bin/cat","argv":["cat","d`+rlo+`txt.exe"]`),
		line(bidiRun, "bidi-agent", 4, at(4), "net", `"verdict":"allow","rule":"net.allow[x]","proto":"tcp","dst":"93.184.216.34:443","host":"ev`+rlo+`moc.li"`),
		line(bidiRun, "bidi-agent", 5, at(5), "ask", `"ask_id":"q-1","ask_rule":"fs.ask_read[./confidential/]","hold":"open","op":"read","target":"/p/proj/confidential/e`+rlo+`txt.exe"`),
		line(bidiRun, "bidi-agent", 6, at(6), "answer", `"ask_id":"q-1","ask_rule":"fs.ask_read[./confidential/]","approved":false,"by":"uid:4000000000 pid:9","after_s":1,"answer_reason":"ask-denied","op":"read","target":"/p/proj/confidential/e`+rlo+`txt.exe"`),
		line(bidiRun, "bidi-agent", 7, at(7), "refused", `"rule":"fs.ask_read[./confidential/]","reason":"ask-denied","op":"open","target":"/p/proj/confidential/e`+rlo+`txt.exe"`),
		line(bidiRun, "bidi-agent", 8, at(50), "ask", `"ask_id":"`+bidiAsk+`","ask_rule":"fs.ask_read[./confidential/]","hold":"open","op":"read","target":"`+bidiTarget+`"`),
	}
	if err := os.MkdirAll(filepath.Join(root, bidiRun), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, bidiRun, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".live"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".live", bidiRun), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

// noRawHidden fails when body, an HTML response, shows a hidden rune as itself anywhere but in the spans
// visibleHTML keeps as written.
func noRawHidden(t *testing.T, what string, body []byte) {
	t.Helper()
	if got := visibleHTML(body); !bytes.Equal(got, body) {
		i := 0
		for i < len(body) && i < len(got) && body[i] == got[i] {
			i++
		}
		t.Errorf("%s shows a hidden rune as itself near %q", what, body[max(0, i-120):min(len(body), i+40)])
	}
}

// TestBidiNameOnApprovalCardAndLogs (QA BR-1): a file the agent named a<U+202E>txt.exe reads as that on the
// approval card, in its "shown exactly" box and on Logs, never as aexe.txt; the hidden form value Never allow posts
// and the line Copy copies keep the name as written.
func TestBidiNameOnApprovalCardAndLogs(t *testing.T) {
	s := newServer(t, bidiFixture(t))
	c := login(t, s)

	w := do(s, "GET", "/approvals", "127.0.0.1:8484", c)
	if w.Code != http.StatusOK {
		t.Fatalf("/approvals: %d", w.Code)
	}
	body := w.Body.String()
	card := body[strings.Index(body, `id="`+bidiAsk+`"`):]
	card = card[:strings.Index(card, "</section>")]
	box := card[strings.Index(card, `class="ut ut-box"`):]
	box = box[:strings.Index(box, "</span>")]
	if !strings.Contains(box, "/p/proj/"+bidiSeen) {
		t.Errorf("the card's shown-exactly box lacks %q: %s", bidiSeen, box)
	}
	if !strings.Contains(card, `<b class="sp-b">a⟦U+202E⟧txt.exe</b>`) {
		t.Errorf("the card's path does not name a⟦U+202E⟧txt.exe in bold: %s", card)
	}
	noRawHidden(t, "/approvals", w.Body.Bytes())

	w = do(s, "GET", "/logs", "127.0.0.1:8484", c)
	body = w.Body.String()
	for _, want := range []string{"a⟦U+202E⟧txt.exe", "b⟦U+202E⟧gnp.sh", "c⟦U+202E⟧fdp.exe", "d⟦U+202E⟧txt.exe", "ev⟦U+202E⟧moc.li"} {
		if !strings.Contains(body, want) {
			t.Errorf("/logs lacks %q", want)
		}
	}
	noRawHidden(t, "/logs", w.Body.Bytes())
	// A row opened in place: its words write the name visibly, its Copy the line keeps it as written.
	w = do(s, "GET", "/logs/line?run="+bidiRun+"&seq=8", "127.0.0.1:8484", c)
	shown, raw, ok := strings.Cut(w.Body.String(), `<template data-exact class="lx-raw">`)
	if !ok || !strings.Contains(shown, "a⟦U+202E⟧txt.exe") || !strings.Contains(raw, "a"+rlo+"txt.exe") {
		t.Errorf("a Logs row opened in place does not show the name visibly and copy it as written: %s", w.Body.String())
	}
	noRawHidden(t, "/logs/line", w.Body.Bytes())

	// The line page: the sentence after the name reads forwards, the line shows the override, Copy has it as written.
	w = do(s, "GET", "/runs/"+bidiRun+"/lines/8", "127.0.0.1:8484", c)
	body = w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "a⟦U+202E⟧txt.exe") {
		t.Fatalf("line page: %d, lacks the name written visibly", w.Code)
	}
	noRawHidden(t, "line page", w.Body.Bytes())
	exact := body[strings.Index(body, `<template data-exact id="ev-rawline-exact">`):]
	exact = exact[:strings.Index(exact, "</template>")]
	if !strings.Contains(exact, "a"+rlo+"txt.exe") {
		t.Errorf("the line's Copy source is not the line as written: %q", exact)
	}
	if !strings.Contains(body, "but for its invisible characters, shown as ⟦U+…⟧; Copy gives them as written") {
		t.Errorf("the line page does not say its line shows invisible characters as ⟦U+…⟧")
	}

	// The JSONL download is the ledger's bytes; the CSV writes the name as the page does.
	w = do(s, "GET", "/logs.jsonl?run="+bidiRun, "127.0.0.1:8484", c)
	ledger, err := os.ReadFile(filepath.Join(s.cfg.Ledger, bidiRun, "events.jsonl"))
	if err != nil || !bytes.Equal(w.Body.Bytes(), ledger) {
		t.Errorf("/logs.jsonl is not the events file byte for byte (%v)", err)
	}
	w = do(s, "GET", "/logs.csv?run="+bidiRun, "127.0.0.1:8484", c)
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if err != nil || len(rows) < 2 {
		t.Fatalf("/logs.csv: %v, %d rows", err, len(rows))
	}
	if strings.Contains(w.Body.String(), rlo) || !strings.Contains(w.Body.String(), "a⟦U+202E⟧txt.exe") {
		t.Errorf("/logs.csv holds U+202E as itself, or lacks the name written visibly")
	}
}

// TestBidiNoRawHiddenOnAnyPage: no page, region, row or line shows the run's U+202E as itself.
func TestBidiNoRawHiddenOnAnyPage(t *testing.T) {
	s := newServer(t, bidiFixture(t))
	c := login(t, s)
	paths := []string{"/", "/runs", "/runs/" + bidiRun, "/runs/" + bidiRun + "/refusals", "/runs/" + bidiRun + "/refusals?view=lines",
		"/runs/" + bidiRun + "/receipt", "/runs/" + bidiRun + "/rows?after=0", "/runs/" + bidiRun + "/stop", "/logs", "/logs?verdict=refused",
		"/logs?group=target", "/logs/rows", "/approvals", "/rules", "/rules?run=" + bidiRun, "/machine", "/mcp", "/routes",
		"/compare?a=" + bidiRun + "&b=" + bidiRun, "/detections", "/severity", "/glossary"}
	if m := investigateLink.FindStringSubmatch(do(s, "GET", "/detections", "127.0.0.1:8484", c).Body.String()); m != nil {
		paths = append(paths, m[1])
	}
	for seq := 0; seq <= 8; seq++ {
		paths = append(paths, "/runs/"+bidiRun+"/lines/"+strconv.Itoa(seq), "/logs/line?run="+bidiRun+"&seq="+strconv.Itoa(seq))
	}
	for _, p := range paths {
		w := do(s, "GET", p, "127.0.0.1:8484", c)
		if w.Code != http.StatusOK {
			t.Errorf("%s: %d", p, w.Code)
			continue
		}
		noRawHidden(t, p, w.Body.Bytes())
		if have := regionsIn(w.Body.String()); len(have) > 0 {
			for n := range have {
				have[n] = "stale"
			}
			r := doRegions(s, p, "127.0.0.1:8484", c, headerOf(have))
			noRawHidden(t, p+" (regions)", r.Body.Bytes())
		}
	}
}

// TestDenyNoticeShortensADeepPath (QA BR-3): the line after Deny names a 3.7 KB path in about two lines of a toast,
// its file name kept, and an invisible character in it as the page writes it.
func TestDenyNoticeShortensADeepPath(t *testing.T) {
	root := bidiFixture(t)
	var deep strings.Builder
	deep.WriteString("/p/proj/confidential/")
	for i := 1; i <= 14; i++ {
		deep.WriteString("D" + strconv.Itoa(i) + strings.Repeat("x", 250) + "/")
	}
	deep.WriteString("deep" + rlo + "txt.exe")
	const deepAsk = "q-0123456789abcdef0123456789abcd0f"
	appendLine(t, root, bidiRun, line(bidiRun, "bidi-agent", 9, time.Date(2026, 10, 25, 12, 4, 55, 0, time.UTC), "ask",
		`"ask_id":"`+deepAsk+`","ask_rule":"fs.ask_read[./confidential/]","hold":"open","op":"read","target":"`+deep.String()+`"`))
	old := answerAsk
	t.Cleanup(func() { answerAsk = old })
	answerAsk = func(_ context.Context, _, run, id string, approve, always bool) (runact.Answered, error) {
		d := askproto.Decision{AskID: id, Approved: approve, Always: always}
		return runact.Answered{Run: run, Decision: d, Word: runact.AnswerWord(d, always)}, nil
	}
	s := newServer(t, root)
	c := login(t, s)
	tok := csrfOf(t, s, c, "/approvals")
	a := inline(t, s, "/approvals/answer", url.Values{"csrf": {tok}, "run": {bidiRun}, "ask": {deepAsk}, "decision": {"deny"}}, c)
	if !a.OK || !strings.HasPrefix(a.Text, "Denied: read of ") {
		t.Fatalf("deny answered %+v", a)
	}
	target := strings.TrimPrefix(a.Text, "Denied: read of ")
	if n := utf8.RuneCountInString(target); n > noticeMax+utf8.RuneCountInString("⟦U+202E⟧")-1 {
		t.Errorf("the notice names a %d-character target: %q", n, target)
	}
	if !strings.HasPrefix(target, "./confidential/D1x") || !strings.Contains(target, "x…x") || !strings.HasSuffix(target, "x/deep⟦U+202E⟧txt.exe") {
		t.Errorf("the notice's target is not ./confidential/…/deep⟦U+202E⟧txt.exe shortened in the middle: %q", target)
	}
	if strings.Contains(a.Text+a.LinkText, rlo) {
		t.Errorf("the toast holds U+202E as itself: %q", a.Text)
	}
}

func TestNoticeTarget(t *testing.T) {
	rr := &ledgerview.Run{Cwd: "/p/proj"}
	for _, tc := range []struct{ in, prefix, suffix string }{
		{"/p/proj/confidential/plan.md", "./confidential/plan.md", ""}, // short: whole
		{"example.com:443", "example.com:443", ""},
		{"/p/proj/src/a.tmp → /p/proj/src/a", "./src/a.tmp → ./src/a", ""},                                   // a held rename's two names, each shortened
		{"/p/proj/src/current → ../releases/v2", "./src/current → ../releases/v2", ""},                       // a symlink's stored target as written
		{"/p/proj/" + strings.Repeat("folder/", 40) + "plan.md", "./folder/folder/", "older/folder/plan.md"}, // the file name kept
		{"/p/proj/" + strings.Repeat("n", 300), "./nnn", "nnn"},                                              // one huge name
		{"curl " + strings.Repeat("a", 300), "curl aaa", "aaa"},                                              // a command line
	} {
		got := noticeTarget(tc.in, rr)
		short := tc.suffix == ""
		switch {
		case short && got != tc.prefix:
			t.Errorf("noticeTarget(%q) = %q, want %q", tc.in, got, tc.prefix)
		case !short && (utf8.RuneCountInString(got) != noticeMax || !strings.HasPrefix(got, tc.prefix) || !strings.HasSuffix(got, tc.suffix) || strings.Count(got, "…") != 1):
			t.Errorf("noticeTarget(%.40q…) = %q, want %d characters, %q…%q", tc.in, got, noticeMax, tc.prefix, tc.suffix)
		}
	}
}
