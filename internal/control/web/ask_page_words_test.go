// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Tests of the sign-in page (no token, a used and an expired one-time code), the honest give-up words, the
// Timed out chip, paths shortened against the run's home, and no floating banner over a run page's own ask card.

const (
	f3LateRun  = "r-aaaaaaaa-0000000000011-f3late"
	f3FreshRun = "r-aaaaaaaa-0000000000012-f3frsh"
	f3DoneRun  = "r-aaaaaaaa-0000000000013-f3done"
)

// f3Now is the time the f3 server reads its pages at.
var f3Now = time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)

// f3Fixture is three runs: a live Codex run whose ask is 2 minutes old under a contract that holds asks for 3 m, a
// live run of another harness whose ask is 5 s old, and an ended run whose ask timed out.
func f3Fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
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
	ago := func(d time.Duration) time.Time { return f3Now.Add(-d) }
	write(f3LateRun, "fs:\n  ask_read:\n    - /d/with/home/.config/telemetry/\nask:\n  timeout: 3m\n",
		line(f3LateRun, "codex-tego", 0, ago(3*time.Minute), "run_start", `"tier":"landlock","command":["codex"],"cwd":"/d/with/proj","harness":{"name":"codex"}`),
		line(f3LateRun, "codex-tego", 1, ago(2*time.Minute), "ask", `"ask_id":"q-late","ask_rule":"fs.ask_read[/d/with/home/.config/telemetry/]","hold":"open","op":"read","target":"/d/with/home/.config/telemetry/token"`))
	write(f3FreshRun, "",
		line(f3FreshRun, "asker", 0, ago(time.Minute), "run_start", `"tier":"landlock","command":["sh"],"cwd":"/e/ask/proj"`),
		line(f3FreshRun, "asker", 1, ago(5*time.Second), "ask", `"ask_id":"q-fresh","ask_rule":"fs.ask_read[/e/ask/home/.aws/]","hold":"open","op":"read","target":"/e/ask/home/.aws/credentials"`))
	write(f3DoneRun, "",
		line(f3DoneRun, "codex-tego", 0, ago(time.Hour), "run_start", `"tier":"landlock","command":["codex"],"cwd":"/d/with/proj","harness":{"name":"codex"}`),
		line(f3DoneRun, "codex-tego", 1, ago(59*time.Minute), "ask", `"ask_id":"q-old","ask_rule":"fs.ask_read[/d/with/home/.config/telemetry/]","hold":"open","op":"read","target":"/d/with/home/.config/telemetry/token"`),
		line(f3DoneRun, "codex-tego", 2, ago(54*time.Minute), "answer", `"ask_id":"q-old","approved":false,"by":"timeout","after_s":300,"answer_reason":"ask-timeout","op":"read","target":"/d/with/home/.config/telemetry/token","ask_rule":"fs.ask_read[/d/with/home/.config/telemetry/]"`),
		line(f3DoneRun, "codex-tego", 3, ago(53*time.Minute), "run_end", `"reason":"exit","exit_code":0`))
	for _, run := range []string{f3LateRun, f3FreshRun} {
		markLive(t, root, run)
	}
	return root
}

func f3Server(t *testing.T) (*Server, *http.Cookie) {
	t.Helper()
	s := newServer(t, f3Fixture(t))
	s.cfg.Now = func() time.Time { return f3Now }
	return s, login(t, s)
}

var f3Tags = regexp.MustCompile(`<[^>]*>`)

// f3Text is a page's text as a person reads it: tags dropped, entities left as written, spaces folded.
func f3Text(html string) string {
	return strings.Join(strings.Fields(f3Tags.ReplaceAllString(html, "")), " ")
}

// TestR9F3SignInPage: without a session a browser gets the sign-in page (title, viewport, colour scheme, the
// command to copy, no script); a used or an expired one-time code is told so, as a page and as the plain line; a
// code of another shape gets the usual page; none of them signs in.
func TestSignInPage(t *testing.T) {
	s := newServer(t, fixture(t))
	now := time.Date(2026, 10, 27, 9, 0, 0, 0, time.UTC)
	s.cfg.Now = func() time.Time { return now }
	get := func(target, accept string) *http.Response {
		r, _ := http.NewRequest("GET", "http://127.0.0.1:8484"+target, nil)
		r.Host = "127.0.0.1:8484"
		if accept != "" {
			r.Header.Set("Accept", accept)
		}
		return f3Serve(s, r)
	}
	const html = "text/html,application/xhtml+xml,*/*;q=0.8"
	check := func(name string, res *http.Response, codeWords bool) {
		t.Helper()
		page := respBody(t, res)
		if res.StatusCode != http.StatusUnauthorized || len(res.Cookies()) != 0 {
			t.Fatalf("%s: %d, cookies %v; want 401 and no session", name, res.StatusCode, res.Cookies())
		}
		for _, want := range []string{"<title>Sign in · Tego</title>", `<meta name="viewport" content="width=device-width, initial-scale=1">`,
			`<meta name="color-scheme" content="light dark">`, "Open the dashboard from the link in your terminal", "<code>tego serve --open</code>"} {
			if !strings.Contains(page, want) {
				t.Errorf("%s: the page lacks %q", name, want)
			}
		}
		if strings.Contains(page, "<script") || strings.Contains(res.Header.Get("Content-Security-Policy"), "script-src") {
			t.Errorf("%s: the sign-in page carries or allows script", name)
		}
		if got := strings.Contains(page, codeUsedWords); got != codeWords {
			t.Errorf("%s: names a used or expired code: %v, want %v", name, got, codeWords)
		}
	}
	check("no token", get("/", html), false)
	check("wrong token", get("/?t=nope", html), false)
	check("a code of another shape", get("/?o=NOTAHEXCODE", html), false)

	used := openTarget(t, s.OpenURL())
	if res := get(used, html); res.StatusCode != http.StatusSeeOther {
		t.Fatalf("the code's first use: %d, want 303", res.StatusCode)
	}
	check("a used code", get(used, html), true)
	if res := get(used, ""); res.StatusCode != http.StatusUnauthorized || !strings.Contains(respBody(t, res), codeUsedWords) ||
		!strings.HasPrefix(res.Header.Get("Content-Type"), "text/plain") {
		t.Errorf("a used code, plain: %d %q", res.StatusCode, res.Header.Get("Content-Type"))
	}

	late := openTarget(t, s.OpenURL())
	now = now.Add(openCodeTTL + time.Second)
	check("an expired code", get(late, html), true)
	check("a code never minted", get("/?o="+strings.Repeat("ab", 16), html), true)
}

// f3Serve serves r and returns its response.
func f3Serve(s *Server, r *http.Request) *http.Response {
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w.Result()
}

// TestR9F3AskWords: a Codex ask older than 30 s says Codex has likely given up and when Tego refuses it (the run's
// ask.timeout), on the card and in the banner; a fresh ask keeps giveUp's words and carries the late words for
// live.js; paths read against the run's home; the request names its line, its id in the title.
func TestAskWords(t *testing.T) {
	s, c := f3Server(t)
	ap := do(s, "GET", "/approvals", "127.0.0.1:8484", c).Body.String()
	text := f3Text(ap)
	for _, want := range []string{
		"asked 2 m 0 s ago · Codex has likely given up; Tego refuses it at 3 m",
		"~/.config/telemetry/token",            // the card's short path, against the run's home
		"~/.aws/credentials",                   // the other run's, against its own
		"/d/with/home/.config/telemetry/token", // the agent's exact text, in its box
	} {
		if !strings.Contains(text, want) {
			t.Errorf("Approvals lacks %q", want)
		}
	}
	if strings.Contains(text, "Codex gives up at about 30 s") {
		t.Error("Approvals still says Codex gives up at about 30 s two minutes after the ask")
	}
	if !strings.Contains(ap, `<dt>Request</dt><dd><span title="Request q-late">line #1</span></dd>`) || strings.Contains(text, "q-late · line") {
		t.Error("the request's id is not in a title, or still sits in the row")
	}
	// The fresh ask: giveUp's words now, the late ones for live.js at ask + 30 s.
	lateAt := f3Now.Add(-5 * time.Second).Add(harnessWait).Format(time.RFC3339Nano)
	if !strings.Contains(ap, `data-late-at="`+lateAt+`" data-late="some agents give up after about 30 s; Tego refuses it when its time runs out">some agents give up after about 30 s</span>`) {
		t.Errorf("the fresh ask's note does not carry its late words for %s", lateAt)
	}

	ov := do(s, "GET", "/", "127.0.0.1:8484", c).Body.String()
	banner := ov[strings.Index(ov, `id="ask-banner"`):]
	banner = banner[:strings.Index(banner, "</section>")]
	if bt := f3Text(banner); !strings.Contains(bt, "~/.config/telemetry/token") || !strings.Contains(bt, "Codex has likely given up; Tego refuses it at 3 m") ||
		strings.Contains(bt, "/d/with/home") {
		t.Errorf("the banner does not shorten against the run's home or keeps the old words: %s", bt)
	}
	wait := ov[strings.Index(ov, `id="h-asks"`):]
	wait = wait[:strings.Index(wait, "</section>")]
	if wt := f3Text(wait); !strings.Contains(wt, "~/.config/telemetry/token") || strings.Contains(wt, "/d/with/home/.conf") {
		t.Errorf("Waiting on you does not read the path against the run's home: %s", wt)
	}
}

// TestR9F3WaitOf: the note before and after the agent's own wait, per harness, with and without a known timeout.
func TestWaitOf(t *testing.T) {
	asked := f3Now
	for _, tc := range []struct {
		name       string
		m          askMeta
		at         time.Duration
		text, late string
	}{
		{"codex fresh", askMeta{Harness: "codex", Timeout: 5 * time.Minute}, 10 * time.Second, "Codex gives up at about 30 s", "Codex has likely given up; Tego refuses it at 5 m"},
		{"codex at 30 s", askMeta{Harness: "codex", Timeout: 5 * time.Minute}, 30 * time.Second, "Codex has likely given up; Tego refuses it at 5 m", ""},
		{"codex late, odd timeout", askMeta{Harness: "codex", Timeout: 90 * time.Second}, 3 * time.Minute, "Codex has likely given up; Tego refuses it at 1 m 30 s", ""},
		{"no timeout known", askMeta{}, time.Minute, "some agents give up after about 30 s; Tego refuses it when its time runs out", ""},
	} {
		w := waitOf(tc.m, asked, asked.Add(tc.at))
		if w.Text != tc.text || w.Late != tc.late || (tc.late != "" && !w.LateAt.Equal(asked.Add(harnessWait))) {
			t.Errorf("%s: %+v, want %q then %q", tc.name, w, tc.text, tc.late)
		}
	}
}

// TestR9F3TimedOutChip: an ask nobody answered in time is "Timed out" in a neutral chip, not "Denied".
func TestTimedOutChip(t *testing.T) {
	s, c := f3Server(t)
	ap := do(s, "GET", "/approvals", "127.0.0.1:8484", c).Body.String()
	i := strings.Index(ap, `id="h-recent-ans"`)
	if i < 0 {
		t.Fatal("no Answered recently")
	}
	rec := ap[i:]
	rec = rec[:strings.Index(rec, "</section>")]
	if !strings.Contains(rec, `<span class="b b-neutral" title="Nobody answered in time, so Tego refused it">Timed out</span>`) ||
		strings.Contains(rec, ">Denied</span>") || !strings.Contains(f3Text(rec), "timed out, so refused after 5 m 0 s") ||
		!strings.Contains(f3Text(rec), "~/.config/telemetry/token") {
		t.Errorf("a timed-out answer's row: %s", f3Text(rec))
	}
}

// TestR9F3NoBannerOverCard: a run page with its own ask card renders no floating banner (it could cover the card's
// Allow once and Deny); a page without a card still gets it; Approvals never does.
func TestNoBannerOverCard(t *testing.T) {
	s, c := f3Server(t)
	for _, tc := range []struct {
		path   string
		banner bool
	}{
		{"/runs/" + f3LateRun, false},
		{"/runs/" + f3FreshRun, false},
		{"/runs/" + f3DoneRun, true},
		{"/approvals", false},
		{"/", true},
	} {
		b := do(s, "GET", tc.path, "127.0.0.1:8484", c).Body.String()
		if got := strings.Contains(b, `id="ask-banner"`); got != tc.banner {
			t.Errorf("%s: banner %v, want %v", tc.path, got, tc.banner)
		}
	}
	// The run page's own card reads the path against the run's home too.
	if b := f3Text(do(s, "GET", "/runs/"+f3LateRun, "127.0.0.1:8484", c).Body.String()); !strings.Contains(b, "~/.config/telemetry/token") ||
		!strings.Contains(b, "Codex has likely given up; Tego refuses it at 3 m") {
		t.Error("the run page's ask card does not shorten its path or keeps the old words")
	}
}

// TestR9F3Shell: the sidebar has no foot sentence (the pill's title says it), the Runs filter shows no "Lost 0",
// a long hostname is cut with the whole name on hover, and This machine folds the ids under Capability flags.
func TestShell(t *testing.T) {
	s, c := f3Server(t)
	s.host = "somebody-ACME-LAB-Gaming-X15-ZQ123AB4"
	runs := do(s, "GET", "/runs", "127.0.0.1:8484", c).Body.String()
	if strings.Contains(runs, "side-foot") || strings.Contains(runs, "Allow, Deny and Stop act on your runs") {
		t.Error("the sidebar still carries its foot sentence")
	}
	if strings.Contains(runs, "state=lost") {
		t.Error("Runs shows a Lost chip with no lost run")
	}
	if !strings.Contains(runs, `title="This computer: somebody-ACME-LAB-Gaming-X15-ZQ123AB4">`) || strings.Contains(runs, ">somebody-ACME-LAB-Gaming-X15-ZQ123AB4<") {
		t.Error("the hostname is not cut with the full name in its title")
	}
	if lost := do(s, "GET", "/runs?state=lost", "127.0.0.1:8484", c).Body.String(); !strings.Contains(lost, `href="/runs?state=lost" aria-current="true">Lost 0</a>`) {
		t.Error("the Lost filter in use lost its chip")
	}
	if m := do(s, "GET", "/machine", "127.0.0.1:8484", c).Body.String(); !strings.Contains(m, "<summary>Capability flags</summary>") ||
		!strings.Contains(m, `<details class="cli-more">`) {
		t.Error("This machine does not fold the ids under Capability flags, or lost the gap after them")
	}
}
