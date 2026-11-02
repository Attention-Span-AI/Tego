// SPDX-License-Identifier: Apache-2.0

package web

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestStatusJSON: /status.json is the live state behind the session cookie, and its ask fingerprint is the one the
// page was rendered with until an ask comes or goes.
func TestStatusJSON(t *testing.T) {
	root := fixture(t)
	s := newServer(t, root)
	if w := do(s, "GET", "/status.json", "127.0.0.1:8484", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("no cookie: %d", w.Code)
	}
	c := login(t, s)
	read := func() liveState {
		t.Helper()
		w := do(s, "GET", "/status.json", "127.0.0.1:8484", c)
		if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("status.json: %d %q", w.Code, w.Header().Get("Content-Type"))
		}
		var st liveState
		if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	st := read()
	if st.Live != 1 || st.Pending != 1 || st.Sig == "" || st.Rev == "" {
		t.Fatalf("status: %+v", st)
	}
	if b := do(s, "GET", "/", "127.0.0.1:8484", c).Body.String(); !strings.Contains(b, `data-sig="`+st.Sig+`"`) || !strings.Contains(b, `data-rev="`+st.Rev+`"`) {
		t.Error("the overview does not carry the live state it was rendered with")
	}
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, time.Date(2026, 10, 25, 12, 1, 7, 0, time.UTC), "fs", `"verdict":"allow","op":"open","path":"a.txt"`))
	st2 := read()
	if st2.Sig != st.Sig || st2.Rev == st.Rev {
		t.Errorf("a new line: sig %q->%q rev %q->%q, want the same sig and a new rev", st.Sig, st2.Sig, st.Rev, st2.Rev)
	}
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 8, time.Date(2026, 10, 25, 12, 1, 8, 0, time.UTC), "answer", `"ask_id":"ask-7","verdict":"allow"`))
	if st3 := read(); st3.Pending != 0 || st3.Sig == st2.Sig {
		t.Errorf("after the answer: %+v, want no ask and a new sig", st3)
	}
}

func appendLine(t *testing.T, root, run, l string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(root, run, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(l); err != nil {
		t.Fatal(err)
	}
}

// TestAskBanner: while an ask waits, every page but Approvals itself carries the banner with Approve and Deny (the
// answer form with the session's token), the count is in the title and on the nav item, and the meta refresh is
// in <noscript> with live.js loaded. With nothing waiting there is no banner and no count.
func TestAskBanner(t *testing.T) {
	got := fakeBroker(t)
	s := newServer(t, fixture(t))
	c := login(t, s)
	for _, p := range []string{"/", "/runs", "/logs", "/runs/" + cleanRun, "/rules"} {
		b := do(s, "GET", p, "127.0.0.1:8484", c).Body.String()
		for _, want := range []string{`id="ask-banner"`, "demo-harm is waiting for you", "about 30 s", `<title>(1) `,
			`name="ask" value="ask-7"`, `value="approve"`, `value="deny"`, `<span class="count" aria-live="polite">1`, `<script src="/static/live.js" defer>`} {
			if !strings.Contains(b, want) {
				t.Errorf("%s lacks %q", p, want)
			}
		}
	}
	b := do(s, "GET", "/approvals", "127.0.0.1:8484", c).Body.String()
	if strings.Contains(b, `id="ask-banner"`) || !strings.Contains(b, "<noscript><meta http-equiv=\"refresh\"") {
		t.Error("Approvals shows the banner, or its refresh is not in <noscript>")
	}
	// The asking run's own page shows the ask in full, so the banner does not repeat it; the count stays.
	b = do(s, "GET", "/runs/"+harmRun, "127.0.0.1:8484", c).Body.String()
	if strings.Contains(b, `id="ask-banner"`) || !strings.Contains(b, `<title>(1) `) || !strings.Contains(b, `id="ask-7"`) {
		t.Error("the asking run's page repeats its ask in the banner, or lost the count or the ask card")
	}
	// Allow once from the banner reaches the broker like the Approvals card does, and the person lands back on the
	// page they were on (a GET, which live.js may reload without posting again), with the answer in a line.
	tok := csrfOf(t, s, c, "/logs")
	w := post(s, "/approvals/answer", url.Values{"csrf": {tok}, "run": {harmRun}, "ask": {"ask-7"}, "decision": {"approve"}}, own, own+"/logs", c)
	if loc := w.Header().Get("Location"); w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/logs?flash=") || got.calls != 1 || !got.approve || got.always {
		t.Fatalf("banner approve: %d %q calls=%d approve=%v always=%v", w.Code, loc, got.calls, got.approve, got.always)
	}
	if b := follow(t, s, c, w); !strings.Contains(b, "Allowed once: connection to") {
		t.Error("the page the banner answer returns to lacks its line")
	}

	quiet := newServer(t, fixture(t))
	root := quiet.cfg.Ledger
	if err := os.Remove(filepath.Join(root, ".live", harmRun)); err != nil {
		t.Fatal(err)
	}
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, time.Date(2026, 10, 25, 12, 1, 7, 0, time.UTC), "run_end", `"reason":"exit","exit_code":0`))
	b = do(quiet, "GET", "/", "127.0.0.1:8484", login(t, quiet)).Body.String()
	if strings.Contains(b, `id="ask-banner"`) || strings.Contains(b, "<title>(") || strings.Contains(b, `class="count"`) {
		t.Error("nothing is waiting, yet the page shows a banner or a count")
	}
}

// busyRun writes a live run of n allowed reads (seq 1..n after run_start), with a refusal repeated at seq 10 and n.
func busyRun(t *testing.T, root string, n int) string {
	t.Helper()
	const run = "r-aaaaaaaa-0000000000003-busyxx"
	t0 := time.Date(2026, 10, 25, 12, 2, 0, 0, time.UTC)
	var b strings.Builder
	b.WriteString(line(run, "demo-busy", 0, t0, "run_start", `"tier":"landlock","command":["sh"]`))
	for i := 1; i <= n; i++ {
		ts := t0.Add(time.Duration(i) * time.Millisecond)
		if i == 10 || i == n {
			b.WriteString(line(run, "demo-busy", i, ts, "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"10.0.0.1:65535"`))
			continue
		}
		b.WriteString(line(run, "demo-busy", i, ts, "fs", fmt.Sprintf(`"verdict":"allow","op":"open","path":"f%d.txt"`, i)))
	}
	if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	markLive(t, root, run)
	return run
}

var tlRow = regexp.MustCompile(`<div class="tl [^"]*" id="l(\d+)"`)

// TestTimelinePages: a run's timeline shows the newest timelinePage rows, and "Older rows" pages back by seq until
// the first line; only the newest page of a live run is followed live.
func TestTimelinePages(t *testing.T) {
	root := fixture(t)
	run := busyRun(t, root, 449) // 450 lines; the two refusals fold into one row at seq 449, so 449 rows
	s := newServer(t, root)
	c := login(t, s)
	older := regexp.MustCompile(`id="tl-older" href="([^"]+)"`)
	target, seen, pages := "/runs/"+run, 0, 0
	for target != "" {
		b := do(s, "GET", target, "127.0.0.1:8484", c).Body.String()
		rows := tlRow.FindAllStringSubmatch(b, -1)
		if len(rows) == 0 || len(rows) > timelinePage {
			t.Fatalf("%s: %d rows", target, len(rows))
		}
		live := strings.Contains(b, `data-rows="/runs/`+run+`/rows?after="`)
		if live != (pages == 0) {
			t.Errorf("%s: followed live = %v", target, live)
		}
		if pages == 0 && (rows[0][1] != "449" || !strings.Contains(b, `data-after="449"`) || !strings.Contains(b, "The newest 200 of 449 rows")) {
			t.Errorf("newest page starts at #%s or lacks its cursor and count", rows[0][1])
		}
		seen += len(rows)
		pages++
		target = ""
		if m := older.FindStringSubmatch(b); m != nil && !strings.Contains(b, `id="tl-older" href="`+m[1]+`" hidden`) {
			target = strings.ReplaceAll(m[1], "&amp;", "&")
		}
	}
	if pages != 3 || seen != 449 {
		t.Errorf("%d pages, %d rows; want 3 pages of 449 rows in all", pages, seen)
	}
}

// TestRowsAfter: /runs/<id>/rows?after=<seq> is the rows newer than seq, a folded group with its whole count and
// its fold key, with the next cursor and whether the run is still live; gzip when the browser takes it.
func TestRowsAfter(t *testing.T) {
	root := fixture(t)
	run := busyRun(t, root, 449)
	s := newServer(t, root)
	c := login(t, s)
	w := do(s, "GET", "/runs/"+run+"/rows?after=445", "127.0.0.1:8484", c)
	b := w.Body.String()
	rows := tlRow.FindAllStringSubmatch(b, -1)
	if w.Code != http.StatusOK || len(rows) != 4 || rows[0][1] != "449" || rows[3][1] != "446" {
		t.Fatalf("rows after 445: %d %v", w.Code, rows)
	}
	if w.Header().Get("X-Tego-After") != "449" || w.Header().Get("X-Tego-Live") != "1" {
		t.Errorf("headers: after %q live %q", w.Header().Get("X-Tego-After"), w.Header().Get("X-Tego-Live"))
	}
	if !strings.Contains(b, "×2") || !strings.Contains(b, `data-k="`) || strings.Contains(b, "<html") {
		t.Error("the folded refusal lacks its whole count or its key, or the fragment is a page")
	}
	if w := do(s, "GET", "/runs/"+run+"/rows?after=449", "127.0.0.1:8484", c); w.Body.Len() != 0 || w.Code != http.StatusOK {
		t.Errorf("nothing new: %d, %d bytes", w.Code, w.Body.Len())
	}
	if w := do(s, "GET", "/runs/"+run+"/rows?verdict=refused&after=0", "127.0.0.1:8484", c); len(tlRow.FindAllString(w.Body.String(), -1)) != 1 {
		t.Error("refused only: want the one folded row")
	}
	if w := do(s, "GET", "/runs/"+cleanRun+"/rows?after=0", "127.0.0.1:8484", c); w.Header().Get("X-Tego-Live") != "0" {
		t.Error("an ended run is reported live")
	}
	for _, p := range []string{"/runs/" + run + "/rows", "/runs/" + run + "/rows?after=x"} {
		if w := do(s, "GET", p, "127.0.0.1:8484", c); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", p, w.Code)
		}
	}
	if w := do(s, "GET", "/runs/r-nope/rows?after=0", "127.0.0.1:8484", c); w.Code != http.StatusNotFound {
		t.Errorf("unknown run: %d", w.Code)
	}
	if w := do(s, "GET", "/runs/"+run+"/rows?after=0", "127.0.0.1:8484", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("no cookie: %d", w.Code)
	}

	r, _ := http.NewRequest("GET", "/runs/"+run+"/rows?after=0", nil)
	r.Host = "127.0.0.1:8484"
	r.AddCookie(c)
	r.Header.Set("Accept-Encoding", "gzip")
	zw := &recorder{h: http.Header{}}
	s.ServeHTTP(zw, r)
	if zw.h.Get("Content-Encoding") != "gzip" {
		t.Fatal("not gzipped")
	}
	zr, err := gzip.NewReader(strings.NewReader(zw.body.String()))
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(zr)
	if n := len(tlRow.FindAll(plain, -1)); n != timelinePage || zw.body.Len()*4 > len(plain) {
		t.Errorf("gzip: %d rows, %d bytes for %d", n, zw.body.Len(), len(plain))
	}
}

type recorder struct {
	h    http.Header
	body strings.Builder
	code int
}

func (r *recorder) Header() http.Header         { return r.h }
func (r *recorder) Write(b []byte) (int, error) { return r.body.Write(b) }
func (r *recorder) WriteHeader(c int)           { r.code = c }

// TestLiveJS: live.js is served, small, and the pages call nothing inline.
func TestLiveJS(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	w := do(s, "GET", "/static/live.js", "127.0.0.1:8484", c)
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("live.js: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	// 320 until the 401 banner and the tab strip scroll were added the 401 banner and the tab strip scroll; 360 until the banner fade, give-up swap, sign-in
	// check); 400 until the night UX pass lent its merge to static/place.js (window.tegoLive, hold, the keyboard's focus).
	if n := strings.Count(w.Body.String(), "\n"); n >= 440 {
		t.Errorf("live.js is %d lines; it stays under 440", n)
	}
	b := do(s, "GET", "/runs/"+harmRun, "127.0.0.1:8484", c).Body.String()
	if strings.Contains(b, "<script>") || regexp.MustCompile(`\son[a-z]+=`).MatchString(b) {
		t.Error("a page has inline script or an inline handler")
	}
}
