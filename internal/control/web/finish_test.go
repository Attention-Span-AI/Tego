// SPDX-License-Identifier: Apache-2.0

package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// UX-FINISH's tests: the 401 page after a restart, the favicon, the terminal devices fold and the open defaults on
// the Rules page, This machine per tier when the newest run only watched, and the Receipt tab's activity sections.

// TestUnauthorizedPage: a browser asking for a page without the session gets 401 with a page that says the
// dashboard restarted or the link expired and how to get back in, under its own CSP (no script, one hashed style);
// any other client, curl and live.js's fetches, gets the plain line, still 401.
func TestUnauthorizedPage(t *testing.T) {
	s := newServer(t, fixture(t))
	get := func(target, accept string) *http.Response {
		r, _ := http.NewRequest("GET", "http://127.0.0.1:8484"+target, nil)
		r.Host = "127.0.0.1:8484"
		if accept != "" {
			r.Header.Set("Accept", accept)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w.Result()
	}
	res := get("/runs", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	page := respBody(t, res)
	if res.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("browser 401: %d %q", res.StatusCode, res.Header.Get("Content-Type"))
	}
	for _, want := range []string{"<title>Sign in · Tego</title>", "Open the dashboard from the link in your terminal",
		"tego-control serve --open", `rel="icon"`, `name="viewport"`, `name="color-scheme" content="light dark"`} {
		if !strings.Contains(strings.ToLower(page), strings.ToLower(want)) {
			t.Errorf("401 page lacks %q", want)
		}
	}
	csp := res.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "style-src 'sha256-") || strings.Contains(csp, "unsafe-inline") ||
		strings.Contains(page, "<script") || strings.Contains(page, "ledger") {
		t.Errorf("401 page CSP %q or body leaks:\n%s", csp, page)
	}
	for _, accept := range []string{"", "*/*", "text/event-stream", "application/json"} {
		res := get("/status.json", accept)
		if b := respBody(t, res); res.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/plain") || !strings.Contains(b, "needs the link") {
			t.Errorf("Accept %q: %d %q %q", accept, res.StatusCode, res.Header.Get("Content-Type"), b)
		}
	}
	// A wrong token is the same 401 page for a browser.
	if res := get("/?t=wrong", "text/html"); res.StatusCode != http.StatusUnauthorized || !strings.Contains(respBody(t, res), "restarted") {
		t.Error("a wrong token does not get the 401 page")
	}
}

// TestFavicon: the favicon is served without the session (the 401 page shows it too), at /favicon.ico as well, and is
// linked on every page; no other static file is.
func TestFavicon(t *testing.T) {
	s := newServer(t, fixture(t))
	if w := do(s, "GET", "/static/favicon.svg", "127.0.0.1:8484", nil); w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "svg") || !strings.Contains(w.Body.String(), "<svg") {
		t.Errorf("favicon: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	for _, p := range []string{"/static/app.css", "/static/sprite.svg", "/static/favicon.svg/../app.css"} {
		if w := do(s, "GET", p, "127.0.0.1:8484", nil); w.Code != http.StatusUnauthorized {
			t.Errorf("%s without the session: %d", p, w.Code)
		}
	}
	if w := do(s, "POST", "/static/favicon.svg", "127.0.0.1:8484", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("POST favicon without the session: %d", w.Code)
	}
	// /favicon.ico, which a browser asks for by itself on a page that links no icon, is the same file, also without
	// the session; a POST to it, or a path beside it, is not.
	svg := do(s, "GET", "/static/favicon.svg", "127.0.0.1:8484", nil).Body.String()
	if w := do(s, "GET", "/favicon.ico", "127.0.0.1:8484", nil); w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "svg") ||
		w.Body.String() != svg || w.Header().Get("Cache-Control") != "private, max-age=300" {
		t.Errorf("/favicon.ico: %d %q %q", w.Code, w.Header().Get("Content-Type"), w.Header().Get("Cache-Control"))
	}
	for _, tc := range []struct{ method, path string }{{"POST", "/favicon.ico"}, {"GET", "/favicon.ico/x"}, {"GET", "/favicon.png"}} {
		if w := do(s, tc.method, tc.path, "127.0.0.1:8484", nil); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without the session: %d", tc.method, tc.path, w.Code)
		}
	}
	c := login(t, s)
	for _, p := range []string{"/", "/runs", "/machine", "/rules"} {
		if w := do(s, "GET", p, "127.0.0.1:8484", c); !strings.Contains(w.Body.String(), `<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">`) {
			t.Errorf("%s does not link the favicon", p)
		}
	}
}

// finishRules is a rules file with the four terminal devices, no net and no env keys (both wide open).
const finishRules = `version: 0
name: dev-agent
command: [sh]
fs:
  write: ["./out/", "/dev/null", "/dev/tty", "/dev/ptmx", "/dev/pts/"]
exec:
  allow: [sh]
`

// TestRulesFoldAndOpen: on the Rules page the terminal devices fold into one row whose expander keeps each device's
// rule, line and hits; an open default (any address, every variable) is marked Open with a Narrow this link; an
// allowed rule's chip is neutral, not green; and a rule the kernel enforces in full leaves its Enforced by cell empty.
func TestRulesFoldAndOpen(t *testing.T) {
	f := newRulesFix(t)
	src := filepath.Join(f.proj, "dev.yaml")
	run := "r-aaaaaaaa-0000000000034-devfol"
	f.run(t, run, src, finishRules, time.Now().Add(-10*time.Minute).UTC(), false,
		`"kind":"fs","source":"seccomp","rule":"fs.write[/dev/tty]","verdict":"allow","op":"open","path":"/dev/tty","flags":1`,
		`"kind":"run_end","source":"supervisor","reason":"exit","exit_code":0`)
	code, body := f.get(t, "/rules?run="+run)
	if code != 200 {
		t.Fatalf("GET: %d %s", code, body)
	}
	if n := strings.Count(body, `<details class="r-fold">`); n != 1 {
		t.Errorf("%d terminal device folds, want 1", n)
	}
	for _, want := range []string{"Can change terminal devices (4)", "Can change /dev/null", "Can change /dev/tty", "Can change /dev/ptmx",
		"Can change files in /dev/pts/", "dev.yaml:5", "Can change files in ./out/",
		`<span class="b b-asked" title="Wide open: a contract usually narrows this">`, "Can connect to any address",
		"Gets every variable in your shell, secrets included.", "Narrow this", "#rc-net.allow",
		"kernel unless noted", `<span class="b b-neutral b-allow">`} {
		if !strings.Contains(body, want) {
			t.Errorf("rules page lacks %q", want)
		}
	}
	// The folded row sums the devices' hits; /dev/tty's one hit is in its expander.
	fold := body[strings.Index(body, `<details class="r-fold">`):]
	fold = fold[:strings.Index(fold, "</tr>")]
	if !strings.Contains(fold, "1 hit") {
		t.Errorf("the fold lost /dev/tty's hit:\n%s", fold)
	}
	if strings.Contains(body, `<span class="b b-allowed">`) {
		t.Error("an allowed rule still has a green chip")
	}
	if strings.Contains(body, ">Enforced by the operating system<") || strings.Contains(body, ">Enforced by the operating system</td>") {
		t.Error("a kernel-enforced rule still says so in its cell")
	}
	// The programs default is narrowed here: not marked open.
	if strings.Contains(body, "Can run any") {
		t.Error("the programs default reads open on a contract with exec.allow")
	}
}

// TestMachineNewestWatched: when the newest run only watched, This machine still names the newest run at each tier
// it used, says the newest was watch-only, and keeps the capability ids under Technical detail.
func TestMachineNewestWatched(t *testing.T) {
	root := fixture(t)
	watch := "r-aaaaaaaa-0000000000009-watchx"
	t0 := time.Date(2026, 10, 25, 12, 4, 0, 0, time.UTC)
	finishRun(t, root, watch,
		line(watch, "watch-agent-sh", 0, t0, "run_start", `"tier":"observe","command":["./agent.sh"],"capabilities":{"fs.deny_read":false,"record.exec_open_connect":true}`),
		line(watch, "watch-agent-sh", 1, t0.Add(time.Second), "run_end", `"reason":"exit","exit_code":0`))
	s := newServer(t, root)
	w := do(s, "GET", "/machine", "127.0.0.1:8484", login(t, s))
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("machine: %d %s", w.Code, body)
	}
	for _, want := range []string{"Last: ", "demo-harm", "Watched only", "Available", "Up to <strong>Basic</strong>",
		"tier 1 · Landlock", "tier 2 · cgroup BPF", "tier 3 · BPF LSM",
		`<details class="mc-tech">`, "fs.deny_read", "Not used yet", "Run with sudo"} {
		if !strings.Contains(body, want) {
			t.Errorf("machine page lacks %q", want)
		}
	}
	if strings.Contains(body, "Not seen in the newest run") || strings.Contains(body, "did not run at tier 1") {
		t.Error("a watched newest run still reads as tier 1 not seen")
	}
	if i, j := strings.Index(body, "fs.deny_read"), strings.Index(body, `<details class="mc-tech">`); i < j {
		t.Error("a capability id shows outside Technical detail")
	}
}

// TestReceiptActivity: a watched run's Receipt tab lists the secret-looking files it read, where it connected and
// the programs it ran, from the receipt's own lists.
func TestReceiptActivity(t *testing.T) {
	root := t.TempDir()
	run := "r-aaaaaaaa-0000000000010-rcwatc"
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	finishRun(t, root, run,
		line(run, "watch-agent-sh", 0, t0, "run_start", `"tier":"observe","record":"full","command":["./agent.sh"]`),
		line(run, "watch-agent-sh", 1, t0.Add(time.Second), "exec", `"verdict":"observed","argv":["cat","/home/u/.ssh/id_rsa"],"exec_id":"x/10/2","path":"/usr/bin/cat"`),
		line(run, "watch-agent-sh", 2, t0.Add(2*time.Second), "fs", `"verdict":"observed","op":"open","path":"/home/u/.ssh/id_rsa","flags":0`),
		line(run, "watch-agent-sh", 3, t0.Add(3*time.Second), "net", `"verdict":"observed","proto":"tcp","dst":"203.0.113.9:443"`),
		line(run, "watch-agent-sh", 4, t0.Add(4*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	s := newServer(t, root)
	w := do(s, "GET", "/runs/"+run+"/receipt", "127.0.0.1:8484", login(t, s))
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("receipt: %d %s", w.Code, body)
	}
	for _, want := range []string{"Sensitive files read", "id_rsa", "Read, not blocked 1", "Connections", "203.0.113.9:<wbr>443",
		"Recorded, not blocked 1", "Programs run", "bin/<wbr>cat"} {
		if !strings.Contains(body, want) {
			t.Errorf("receipt tab lacks %q", want)
		}
	}
}

// TestReceiptFilesTile: the Receipt's files tile counts the files written, the number tego run's end line gives
// ("wrote N files"), and says under it what else the run made, deleted and renamed. A write to /dev/null is no file.
func TestReceiptFilesTile(t *testing.T) {
	root := t.TempDir()
	run := "r-aaaaaaaa-0000000000013-rcfile"
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	fs := func(seq int, payload string) string {
		return line(run, "a", seq, t0.Add(time.Duration(seq)*time.Second), "fs", `"verdict":"allow","rule":"fs.write[/w/]",`+payload)
	}
	finishRun(t, root, run,
		line(run, "a", 0, t0, "run_start", `"tier":"landlock","command":["./agent.sh"]`),
		fs(1, `"op":"open","path":"/w/new.txt","flags":65,"created":true`),
		fs(2, `"op":"open","path":"/w/old.txt","flags":1`),
		fs(3, `"op":"open","path":"/dev/null","flags":1`),
		fs(4, `"op":"unlink","path":"/w/gone.txt"`),
		fs(5, `"op":"rename","path":"/w/a","path2":"/w/b"`),
		line(run, "a", 6, t0.Add(6*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	s := newServer(t, root)
	w := do(s, "GET", "/runs/"+run+"/receipt", "127.0.0.1:8484", login(t, s))
	if w.Code != 200 {
		t.Fatalf("receipt: %d %s", w.Code, w.Body.String())
	}
	const tile = `<span class="rc-k">Files written</span><span class="rc-v">2</span><span class="rc-s">1 new · 1 deleted · 1 renamed</span>`
	if body := w.Body.String(); !strings.Contains(body, tile) {
		t.Errorf("the files tile is not %s:\n%s", tile, body)
	}
}

// TestReceiptNoReadsRecorded: the Receipt tab shows the check mark and "None" for sensitive reads only on a run that
// recorded its reads. The default tier 1 run keeps no allowed read, so its empty list says it does not know.
func TestReceiptNoReadsRecorded(t *testing.T) {
	const none, unknown = "None: no file that looks like a secret", "Not known: this run did not record every read"
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, run, tier, caps string
		unknown               bool
	}{
		{"recorded", "r-aaaaaaaa-0000000000011-rcread", "observe", `"record.reads_mmap_chmod":true`, false},
		{"tier 1 default", "r-aaaaaaaa-0000000000012-rcnone", "landlock", `"record.reads_mmap_chmod":false`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			finishRun(t, root, tc.run,
				line(tc.run, "a", 0, t0, "run_start", `"tier":"`+tc.tier+`","command":["./agent.sh"],"capabilities":{`+tc.caps+`}`),
				line(tc.run, "a", 1, t0.Add(time.Second), "run_end", `"reason":"exit","exit_code":0`))
			s := newServer(t, root)
			w := do(s, "GET", "/runs/"+tc.run+"/receipt", "127.0.0.1:8484", login(t, s))
			if w.Code != 200 {
				t.Fatalf("receipt: %d %s", w.Code, w.Body.String())
			}
			body := w.Body.String()
			if strings.Contains(body, none) == tc.unknown || strings.Contains(body, unknown) != tc.unknown {
				t.Errorf("unknown %v, the receipt tab:\n%s", tc.unknown, body)
			}
		})
	}
}

// TestRunPageWords: the refusals tab calls noise refusals Routine (Background is the run origin's word), and a
// timeline row with no rule does not repeat its kind as a second line.
func TestRunPageWords(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	rf := do(s, "GET", "/runs/"+harmRun+"/refusals", "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(rf, "Routine (") || strings.Contains(rf, "<summary>Background") {
		t.Errorf("refusals tab words:\n%s", rf)
	}
	tl := do(s, "GET", "/runs/"+cleanRun, "127.0.0.1:8484", c).Body.String()
	if strings.Contains(tl, `<span class="clamp" title="A run_end line`) {
		t.Error("the run_end row repeats its kind as a second line")
	}
}

// respBody is a response's whole body.
func respBody(t *testing.T, res *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// finishRun writes one run's events.jsonl under root.
func finishRun(t *testing.T, root, run string, lines ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(strings.Join(lines, "")), 0o644); err != nil {
		t.Fatal(err)
	}
}
