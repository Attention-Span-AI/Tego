// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
)

var regionRe = regexp.MustCompile(`data-live="([^"]+)" data-h="([0-9a-f]{16})"`)

// regionsIn is each live region a page shows, with its hash, as live.js reads them.
func regionsIn(body string) map[string]string {
	out := map[string]string{}
	for _, m := range regionRe.FindAllStringSubmatch(body, -1) {
		out[m[1]] = m[2]
	}
	return out
}

func headerOf(have map[string]string) string {
	var parts []string
	for n, h := range have {
		parts = append(parts, n+":"+h)
	}
	return strings.Join(parts, ",")
}

func doRegions(s *Server, target, host string, c *http.Cookie, have string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", target, nil)
	r.Host = host
	if c != nil {
		r.AddCookie(c)
	}
	r.Header.Set(regionHeader, have)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

var monoRe = regexp.MustCompile(`"mono_ns":(\d+)`)

// atMono is ledger text ls with each line's mono_ns (line writes seq+1) moved onto base, a CLOCK_MONOTONIC reading.
func atMono(ls string, base uint64) string {
	return monoRe.ReplaceAllStringFunc(ls, func(m string) string {
		n, _ := strconv.ParseUint(monoRe.FindStringSubmatch(m)[1], 10, 64)
		return `"mono_ns":` + strconv.FormatUint(base+n, 10)
	})
}

// youngRun moves live run's mono_ns onto CLOCK_MONOTONIC as it reads now, as a launcher stamps them, and returns that
// base for the lines a test appends later (atMono). The Receipt tab measures a running run to that clock
// (ledgerview.LoadReceipt), and line's own stamps make the run as old as the machine has been up: minutes on a fresh
// CI runner, days on a workstation. Its time taken is a clock the region's hash leaves out, but its stall line (in
// tenths of a minute) and its chart (a bar a minute) are not, so two renders a step apart differed. A run a moment old
// shows no stall line and one bar for its first minute.
func youngRun(t *testing.T, root, run string) uint64 {
	t.Helper()
	base := ledger.SystemClock{}.Mono()
	p := filepath.Join(root, run, "events.jsonl")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(atMono(string(b), base)), 0o644); err != nil {
		t.Fatal(err)
	}
	return base
}

// TestRegionsInPages: every page shows the layout's regions and its own, each once, hashed.
func TestRegionsInPages(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	for path, want := range map[string][]string{
		"/":                              {"r-ov-head", "r-ov-tiles", "r-ov-live", "r-ov-asks", "r-ov-recent", "r-ov-refusals"},
		"/approvals":                     {"content"},
		"/runs":                          {"r-runs-head", "r-runs-live", "r-runs-table", "r-runs-foot"},
		"/runs/" + harmRun:               {"r-run-top", "r-run-live", "r-run-hl", "r-tl-head", "r-tl-foot"},
		"/runs/" + harmRun + "/refusals": {"r-run-top", "r-run-live", "r-run-hl", "r-run-tab"},
		"/runs/" + cleanRun + "/receipt": {"r-run-top", "r-run-live", "r-run-hl", "r-run-tab"},
		"/logs":                          {"r-logs-head", "r-logs-rows"},
		"/rules":                         {"content"},
		"/rules/new":                     {"content"},
		"/runs/" + harmRun + "/lines/1":  {"r-act"},
	} {
		b := do(s, "GET", path, "127.0.0.1:8484", c).Body.String()
		got := regionsIn(b)
		for _, n := range append([]string{"r-top", "r-nav", "r-banner"}, want...) {
			if got[n] == "" || strings.Count(b, `data-live="`+n+`"`) != 1 {
				t.Errorf("%s: region %s missing or repeated (%v)", path, n, got)
			}
		}
	}
	// Logs' rows follow only at the top of the first page.
	if b := do(s, "GET", "/logs", "127.0.0.1:8484", c).Body.String(); !strings.Contains(b, `data-live="r-logs-rows" data-h="`) || !regexp.MustCompile(`data-live="r-logs-rows" data-h="[0-9a-f]+" data-top>`).MatchString(b) {
		t.Error("Logs' rows region is not marked data-top")
	}
}

// TestRegionRequest: a page's address with X-Tego-Regions answers only the regions whose HTML changed, rendered by the
// page's own templates (escaped agent text, the form token), behind the same Host and cookie checks; unchanged, it
// answers nothing.
func TestRegionRequest(t *testing.T) {
	root := fixture(t)
	mono := youngRun(t, root, harmRun) // so its Receipt moves only by its time taken, a clock, for a minute
	s := newServer(t, root)
	c := login(t, s)
	pages := []string{"/", "/approvals", "/runs", "/runs/" + harmRun, "/runs/" + harmRun + "/refusals", "/runs/" + harmRun + "/receipt", "/logs"}
	have := map[string]map[string]string{}
	for _, p := range pages {
		have[p] = regionsIn(do(s, "GET", p, "127.0.0.1:8484", c).Body.String())
		w := doRegions(s, p, "127.0.0.1:8484", c, headerOf(have[p]))
		if w.Code != http.StatusOK || w.Body.Len() != 0 {
			t.Errorf("%s unchanged: %d %q, want 200 and nothing", p, w.Code, w.Body.String())
		}
		if w.Header().Get("X-Tego-Sig") == "" || strings.Contains(w.Body.String(), "<html") {
			t.Errorf("%s: a region answer has no state, or is a page", p)
		}
	}
	// Security: the same checks as a page.
	if w := doRegions(s, "/", "127.0.0.1:8484", nil, "r-nav:x"); w.Code != http.StatusUnauthorized {
		t.Errorf("no cookie: %d", w.Code)
	}
	if w := doRegions(s, "/", "evil.example:8484", c, "r-nav:x"); w.Code != http.StatusMisdirectedRequest {
		t.Errorf("wrong Host: %d", w.Code)
	}
	if w := doRegions(s, "/", "127.0.0.1:8484", c, strings.Repeat("x", 2000)); w.Code != http.StatusBadRequest {
		t.Errorf("oversized header: %d", w.Code)
	}
	if w := doRegions(s, "/", "127.0.0.1:8484", c, ":abc"); w.Code != http.StatusBadRequest {
		t.Errorf("malformed header: %d", w.Code)
	}

	// The live run writes a refusal whose target is markup, and a second ask.
	t0 := time.Date(2026, 10, 25, 12, 1, 10, 0, time.UTC)
	appendLine(t, root, harmRun, atMono(line(harmRun, "demo-harm", 7, t0, "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"<img src=x onerror=alert(2)>:443"`), mono))
	appendLine(t, root, harmRun, atMono(line(harmRun, "demo-harm", 8, t0.Add(time.Second), "fs", `"verdict":"ask","rule":"fs.ask[/p/]","op":"write","path":"/p/held.txt"`), mono))
	appendLine(t, root, harmRun, atMono(line(harmRun, "demo-harm", 9, t0.Add(2*time.Second), "ask", `"ask_id":"ask-9","hold":"fs"`), mono))
	for _, tc := range []struct {
		page string
		want map[string][]string // region → what its fresh HTML holds
		same []string            // regions that did not change
	}{
		{"/", map[string][]string{"r-nav": {`<span class="count" aria-live="polite">2`}, "r-banner": {"2 requests are waiting for you", `value="` + s.csrf + `"`}, "r-ov-head": {"2 need you"}, "r-ov-refusals": {"&lt;img src=x onerror=alert(2)&gt;"}, "r-ov-asks": {"ask-9"}}, []string{"r-top", "r-ov-recent"}},
		{"/approvals", map[string][]string{"content": {`id="ask-9"`, "tego approve " + harmRun + " ask-9", `name="csrf" value="` + s.csrf + `"`}}, []string{"r-top", "r-banner"}},
		{"/runs", map[string][]string{"r-runs-live": {`data-k="` + harmRun + `"`}}, []string{"r-top", "r-runs-head", "r-runs-table", "r-runs-foot"}},
		{"/runs/" + harmRun, map[string][]string{"r-run-top": {`id="ask-9"`}, "r-run-hl": {"Timeline <span class=\"n\">9</span>"}, "r-tl-foot": {"9 rows"}}, []string{"r-top"}},
		{"/runs/" + harmRun + "/refusals", map[string][]string{"r-run-tab": {"&lt;img src=x onerror=alert(2)&gt;"}}, []string{"r-top"}},
		{"/runs/" + harmRun + "/receipt", map[string][]string{"r-run-tab": {"Refused actions", "&lt;img src=x onerror=alert(2)&gt;"}}, nil},
		{"/logs", map[string][]string{"r-logs-head": {"13 lines", "4 asked"}, "r-logs-rows": {"&lt;img src=x onerror=alert(2)&gt;", `data-k="` + harmRun + `-7"`}}, nil},
	} {
		w := doRegions(s, tc.page, "127.0.0.1:8484", c, headerOf(have[tc.page]))
		b := w.Body.String()
		if w.Code != http.StatusOK || strings.Contains(b, "<html") || strings.Contains(b, "<img src=x") {
			t.Fatalf("%s: %d, a page, or unescaped agent text: %s", tc.page, w.Code, b)
		}
		frags := map[string]string{}
		for _, m := range regexp.MustCompile(`(?s)<template data-live="([^"]+)" data-h="([0-9a-f]{16})">(.*?)</template>`).FindAllStringSubmatch(b, -1) {
			frags[m[1]] = m[3]
			if m[2] == have[tc.page][m[1]] {
				t.Errorf("%s: region %s sent with its old hash", tc.page, m[1])
			}
		}
		for n, wants := range tc.want {
			for _, want := range wants {
				if !strings.Contains(frags[n], want) {
					t.Errorf("%s: region %s lacks %q:\n%s", tc.page, n, want, frags[n])
				}
			}
		}
		for _, n := range tc.same {
			if _, ok := frags[n]; ok {
				t.Errorf("%s: region %s did not change but was sent", tc.page, n)
			}
		}
		// Only the regions asked for come back.
		if w := doRegions(s, tc.page, "127.0.0.1:8484", c, "r-top:0"); strings.Count(w.Body.String(), "<template ") != 1 {
			t.Errorf("%s: asked for r-top only, got %q", tc.page, w.Body.String())
		}
	}
}

// liveServer serves s on a real loopback listener (so the stream meets real connection deadlines) with the short
// timeouts given, and returns its address.
func liveServer(t *testing.T, root string, read, write time.Duration) (*Server, string, *http.Cookie) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	s, err := New(Config{Ledger: root, Port: port, Token: "tok123", EventTick: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: s, ReadHeaderTimeout: read, ReadTimeout: read, WriteTimeout: write}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return s, "127.0.0.1:" + strconv.Itoa(port), &http.Cookie{Name: s.cookie, Value: s.session}
}

// readEvent reads the stream up to the next blank line and returns what came, or fails after d.
func readEvent(t *testing.T, br *bufio.Reader, d time.Duration) string {
	t.Helper()
	type res struct {
		s   string
		err error
	}
	ch := make(chan res, 1)
	go func() {
		var b strings.Builder
		for {
			l, err := br.ReadString('\n')
			b.WriteString(l)
			if err != nil || l == "\n" {
				ch <- res{b.String(), err}
				return
			}
		}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("stream ended: %v after %q", r.err, r.s)
		}
		return r.s
	case <-time.After(d):
		t.Fatal("no event in time")
		return ""
	}
}

// TestEventsStream: GET /events is behind the Host and cookie checks, pushes the state at once and again when a live
// run writes a line, sends heartbeats while nothing changes, and outlives the server's read and write timeouts.
func TestEventsStream(t *testing.T) {
	root := fixture(t)
	// The refusals are asked of a server with the timeouts the other live tests use: they are not what the short
	// timeouts below test. Under those, each refusal had to be written within 300 ms of its request being read, or the
	// server closed the connection unanswered. The test failed once with "Get .../events: EOF" in a -race run of five
	// packages; its raw log is gone, so which request failed is not known, and a late refusal write is the inferred
	// cause. Injected, a refusal write held back 350 ms gives that error every time.
	gate, gateAddr, gateCookie := liveServer(t, root, 10*time.Second, 30*time.Second)
	// The stream's own server keeps read and write timeouts the stream must outlive.
	s, addr, c := liveServer(t, root, 300*time.Millisecond, 300*time.Millisecond)
	get := func(at, host string, cookie *http.Cookie) *http.Response {
		req, _ := http.NewRequest("GET", "http://"+at+"/events", nil)
		req.Host = host
		if cookie != nil {
			req.AddCookie(cookie)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	for _, tc := range []struct {
		host   string
		cookie *http.Cookie
		code   int
	}{{gateAddr, nil, http.StatusUnauthorized}, {"evil.example", gateCookie, http.StatusMisdirectedRequest}, {gateAddr, &http.Cookie{Name: gate.cookie, Value: "nope"}, http.StatusUnauthorized}} {
		resp := get(gateAddr, tc.host, tc.cookie)
		_ = resp.Body.Close()
		if resp.StatusCode != tc.code {
			t.Errorf("host %s cookie %v: %d, want %d", tc.host, tc.cookie, resp.StatusCode, tc.code)
		}
	}
	resp := get(addr, addr, c)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" || resp.Header.Get("Content-Security-Policy") == "" {
		t.Fatalf("stream: %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	br := bufio.NewReader(resp.Body)
	if ev := readEvent(t, br, 2*time.Second); ev != "retry: 2000\n\n" {
		t.Fatalf("first: %q", ev)
	}
	first := readEvent(t, br, 2*time.Second)
	st, _ := s.liveNow(true)
	if !strings.HasPrefix(first, "event: state\ndata: {") || !strings.Contains(first, `"sig":"`+st.Sig+`"`) || !strings.Contains(first, `"pending":1`) {
		t.Fatalf("state: %q (want %+v)", first, st)
	}
	// Quiet: heartbeats, past the 300 ms read and write timeouts.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if ev := readEvent(t, br, 2*time.Second); ev != ": hb\n\n" {
			t.Fatalf("quiet stream sent %q", ev)
		}
	}
	appendLine(t, root, harmRun, line(harmRun, "demo-harm", 7, time.Now(), "exec", `"verdict":"allow","op":"exec","path":"/bin/echo"`))
	for {
		ev := readEvent(t, br, 3*time.Second)
		if ev == ": hb\n\n" {
			continue
		}
		if !strings.HasPrefix(ev, "event: state\n") || strings.Contains(ev, `"rev":"`+st.Rev+`"`) {
			t.Fatalf("after a line: %q, want a state with a new rev", ev)
		}
		break
	}
}

// TestServeEndsStreams: Serve's shutdown ends an open stream at once, instead of waiting out its grace.
func TestServeEndsStreams(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	s, err := New(Config{Ledger: fixture(t), Port: port, Token: "tok123", EventTick: 20 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, ln, s) }()
	req, _ := http.NewRequest("GET", "http://127.0.0.1:"+strconv.Itoa(port)+"/events", nil)
	req.AddCookie(&http.Cookie{Name: s.cookie, Value: s.session})
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	br := bufio.NewReader(resp.Body)
	readEvent(t, br, 2*time.Second)
	start := time.Now()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("shutdown took %v with a stream open", d)
	}
}

// TestStreamsBounded: past maxStreams a stream is refused, and the page polls instead.
func TestStreamsBounded(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	s.streams.Store(maxStreams)
	if w := do(s, "GET", "/events", "127.0.0.1:8484", c); w.Code != http.StatusServiceUnavailable {
		t.Errorf("a stream past the bound: %d", w.Code)
	}
}

// TestStreamSaysLost: when the ledger cannot be read the stream says so and ends, so the page shows "reconnecting" and
// polls, instead of showing Live over a stream that never sends a state.
func TestStreamSaysLost(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	notDir := filepath.Join(t.TempDir(), "ledger")
	if err := os.WriteFile(notDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s.cfg.Ledger = notDir // reading a file as the ledger root fails
	w := do(s, "GET", "/events", "127.0.0.1:8484", c)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "event: lost\n") || strings.Contains(w.Body.String(), "event: state") {
		t.Errorf("unreadable ledger: %d %q", w.Code, w.Body.String())
	}
}
