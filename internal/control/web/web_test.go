// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const port = 8484

func line(run, agent string, seq int, ts time.Time, kind, extra string) string {
	l := fmt.Sprintf(`{"v":1,"seq":%d,"id":"%064x","prev":"","ts":"%s","mono_ns":%d,"run":"%s","agent":"%s","pid":10,"tid":10,"cgroup":1,"kind":"%s","source":"supervisor"`,
		seq, seq+1, ts.UTC().Format(time.RFC3339Nano), seq+1, run, agent, kind)
	if extra != "" {
		l += "," + extra
	}
	return l + "}\n"
}

const (
	cleanRun = "r-aaaaaaaa-0000000000001-cleanx"
	harmRun  = "r-aaaaaaaa-0000000000002-harmxx"
)

// fixture writes a ledger root with one clean ended run and one live run that has refusals and a pending ask.
func fixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	write := func(run string, ls ...string) {
		if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(cleanRun,
		line(cleanRun, "demo-clean", 0, t0, "run_start", `"tier":"landlock","command":["sh","-c","echo hi"]`),
		line(cleanRun, "demo-clean", 1, t0.Add(time.Second), "fs", `"verdict":"allow","op":"open","path":"out/hello.txt","flags":577`),
		line(cleanRun, "demo-clean", 2, t0.Add(2*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	write(harmRun,
		line(harmRun, "demo-harm", 0, t0.Add(time.Minute), "run_start", `"tier":"landlock","command":["sh","agent.sh"]`),
		line(harmRun, "demo-harm", 1, t0.Add(time.Minute+1), "refused", `"rule":"unmatched","reason":"write-outside-contract","op":"open","target":"/p/stolen.txt"`),
		line(harmRun, "demo-harm", 2, t0.Add(time.Minute+2), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"unix:/var/run/nscd/socket"`),
		line(harmRun, "demo-harm", 3, t0.Add(time.Minute+3), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"unix:/var/run/nscd/socket"`),
		line(harmRun, "demo-harm", 4, t0.Add(time.Minute+4), "net", `"verdict":"ask","rule":"net.ask[example.com]","proto":"tcp","dst":"93.184.216.34:443","host":"example.com"`),
		line(harmRun, "demo-harm", 5, t0.Add(time.Minute+5), "ask", `"ask_id":"ask-7","hold":"net"`),
		line(harmRun, "demo-harm", 6, t0.Add(time.Minute+6), "refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"<script>alert(1)</script>"`))
	if err := os.MkdirAll(filepath.Join(root, ".live"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".live", harmRun), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func newServer(t *testing.T, root string) *Server {
	t.Helper()
	s, err := New(Config{Ledger: root, Port: port, Token: "tok123",
		Now: func() time.Time { return time.Date(2026, 10, 25, 12, 5, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	trustPeer(s)
	return s
}

func do(s *Server, method, target, host string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	r.Host = host
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

// login exchanges the URL token for the session cookie.
func login(t *testing.T, s *Server) *http.Cookie {
	t.Helper()
	w := do(s, "GET", "/logs?t=tok123&verdict=refused", "127.0.0.1:8484", nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/logs?verdict=refused" {
		t.Fatalf("token exchange: %d %q", w.Code, w.Header().Get("Location"))
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == s.cookie && c.HttpOnly && c.SameSite == http.SameSiteStrictMode {
			return c
		}
	}
	t.Fatal("no HttpOnly SameSite=Strict session cookie")
	return nil
}

func TestPagesRender(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	for path, want := range map[string][]string{
		"/":                              {"1 needs you", "demo-harm", "demo-clean", "Newest High and Medium", "system lookup"},
		"/runs":                          {"2 runs", "demo-harm", "Running", "Exit 0"},
		"/runs/" + harmRun:               {"Timeline", "/p/stolen.txt", "×2", "system lookup", "Stop run", `action="/approvals/answer"`},
		"/runs/" + harmRun + "/refusals": {"Grouped", "Not in policy", "Highlights"},
		"/runs/" + harmRun + "/refusals?view=lines": {"Reason the agent got", "Write outside policy", "write-outside-contract"},
		"/runs/" + cleanRun + "/receipt":            {"Receipt", "Exit 0", "Time taken", "Tests result", "not recorded", "never asked", "tego receipt " + cleanRun, "What this receipt can vouch for"},
		"/runs/" + harmRun + "/receipt":             {"Refused, by rule", "write-outside-contract", "Refusals over time"},
		"/logs":                                     {"Logs", " blocked</span>", "/p/stolen.txt"},
		"/logs?verdict=refused&sys=hide":            {"system lines hidden"},
		"/logs?q=nomatch":                           {"No matching lines"},
		"/approvals":                                {"tego approve " + harmRun + " ask-7", "tego deny " + harmRun + " ask-7", "example.com", `action="/approvals/answer"`, `value="approve"`, `value="deny"`},
		"/rules":                                    {"Policy", "demo-harm", "the run left no contract.yaml"},
	} {
		w := do(s, "GET", path, "127.0.0.1:8484", c)
		if w.Code != http.StatusOK {
			t.Errorf("%s: %d %s", path, w.Code, w.Body.String())
			continue
		}
		body := w.Body.String()
		for _, x := range want {
			if !strings.Contains(body, x) {
				t.Errorf("%s: body lacks %q", path, x)
			}
		}
		if strings.Contains(body, "<script>alert(1)") {
			t.Errorf("%s: agent text not escaped", path)
		}
		if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("%s: CSP %q", path, csp)
		}
		if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Referrer-Policy") != "same-origin" {
			t.Errorf("%s: headers %v", path, w.Header())
		}
	}
	if w := do(s, "GET", "/runs/r-nope-0000-none", "127.0.0.1:8484", c); w.Code != http.StatusNotFound {
		t.Errorf("missing run: %d", w.Code)
	}
	if w := do(s, "GET", "/static/app.css", "127.0.0.1:8484", c); w.Code != http.StatusOK {
		t.Errorf("static: %d", w.Code)
	}
}

func TestEmptyLedger(t *testing.T) {
	s := newServer(t, filepath.Join(t.TempDir(), "not-yet"))
	c := login(t, s)
	for path, want := range map[string]string{"/": "No runs yet", "/runs": "No runs here", "/approvals": "Nothing waiting", "/logs": "No matching lines"} {
		if w := do(s, "GET", path, "localhost:8484", c); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), want) {
			t.Errorf("%s: %d, want %q", path, w.Code, want)
		}
	}
}

func TestAccessChecks(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	if w := do(s, "GET", "/", "127.0.0.1:8484", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("no cookie: %d", w.Code)
	}
	if w := do(s, "GET", "/static/app.css", "127.0.0.1:8484", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("static without cookie: %d", w.Code)
	}
	if w := do(s, "GET", "/?t=wrong", "127.0.0.1:8484", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong token: %d", w.Code)
	}
	bad := &http.Cookie{Name: s.cookie, Value: "forged"}
	if w := do(s, "GET", "/", "127.0.0.1:8484", bad); w.Code != http.StatusUnauthorized {
		t.Errorf("forged cookie: %d", w.Code)
	}
	for _, host := range []string{"evil.example:8484", "127.0.0.1:9999", "attacker.localhost:8484", ""} {
		if w := do(s, "GET", "/", host, c); w.Code != http.StatusMisdirectedRequest {
			t.Errorf("host %q: %d", host, w.Code)
		}
	}
	for _, host := range []string{"localhost:8484", "[::1]:8484"} {
		if w := do(s, "GET", "/", host, c); w.Code != http.StatusOK {
			t.Errorf("host %q: %d", host, w.Code)
		}
	}
	for _, m := range []string{"PUT", "DELETE", "PATCH"} {
		if w := do(s, m, "/", "127.0.0.1:8484", c); w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: %d", m, w.Code)
		}
	}
	if !strings.HasPrefix(s.URL(), "http://127.0.0.1:8484/?t=tok123") {
		t.Errorf("URL %q", s.URL())
	}
}

func TestLiveRunRefreshes(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	if b := do(s, "GET", "/runs/"+harmRun, "127.0.0.1:8484", c).Body.String(); !strings.Contains(b, `http-equiv="refresh"`) {
		t.Error("live run page does not refresh")
	}
	if b := do(s, "GET", "/runs/"+cleanRun, "127.0.0.1:8484", c).Body.String(); strings.Contains(b, `http-equiv="refresh"`) {
		t.Error("ended run page refreshes")
	}
}

// Logs names the list a default decision fell outside of, as a short label, as the run page does, never "Not in the
// rules (default)" when the run kept its contract; a host socket's refusal reads in words.
func TestLogsRefusalsNameTheList(t *testing.T) {
	root := fixture(t)
	if err := os.WriteFile(filepath.Join(root, harmRun, "contract.yaml"), []byte("version: 0\nfs:\n  write: [\"./out/\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	w := do(s, "GET", "/logs?verdict=refused", "127.0.0.1:8484", c)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, "Outside writable folders") {
		t.Fatalf("logs %d lacks the writable list:\n%s", w.Code, body)
	}
	if got := ruleName("host-sockets"); strings.Contains(got, "host-sockets") {
		t.Errorf("ruleName(host-sockets) = %q, want words", got)
	}
	// An Adjustable run's fence rule reads in the fence panel's words, never as the raw key on the Overview or Logs.
	for rule, want := range map[string]string{
		"live.fence[read:/srv/exports]":      "Fence: /srv/exports",
		"live.fence[net:api.stripe.com:443]": "Fence: api.stripe.com:443",
		"live.fence[exec:/usr/bin/psql]":     "Fence: /usr/bin/psql",
		"live.fence[]":                       "Fence: ",
	} {
		if got := ruleName(rule); got != want {
			t.Errorf("ruleName(%s) = %q, want %q", rule, got, want)
		}
	}
}

var navHref = regexp.MustCompile(`<nav class="side"[\s\S]*?</nav>`)

// TestShellWording: no page calls the dashboard an MVP or unreviewed; every link of the main nav answers 200, and
// the Preview pages are left out of it by default; the empty states give commands that tego run and tego watch accept.
func TestShellWording(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	for _, p := range []string{"/", "/runs", "/runs/" + harmRun, "/logs", "/approvals", "/rules", "/machine", "/nope"} {
		b := do(s, "GET", p, "127.0.0.1:8484", c).Body.String()
		for _, bad := range []string{"MVP", "unreviewed", "not in this MVP"} {
			if strings.Contains(b, bad) {
				t.Errorf("%s says %q", p, bad)
			}
		}
	}
	b := do(s, "GET", "/", "127.0.0.1:8484", c).Body.String()
	nav := navHref.FindString(b)
	if nav == "" {
		t.Fatal("no side nav")
	}
	for _, m := range regexp.MustCompile(`<a href="([^"]+)"`).FindAllStringSubmatch(nav, -1) {
		if w := do(s, "GET", m[1], "127.0.0.1:8484", c); w.Code != http.StatusOK {
			t.Errorf("nav link %s: %d", m[1], w.Code)
		}
	}
	for _, hidden := range []string{"MCP tools", "Model routes"} {
		if strings.Contains(b, ">"+hidden+"<") {
			t.Errorf("%s is in the nav without Preview", hidden)
		}
	}
	s.cfg.Preview = true
	nav = navHref.FindString(do(s, "GET", "/", "127.0.0.1:8484", c).Body.String())
	for _, link := range []string{"/mcp", "/routes"} {
		if !strings.Contains(nav, `href="`+link+`"`) {
			t.Errorf("%s is not a link in the Preview nav", link)
		}
	}
	if !strings.Contains(nav, `href="/rules"`) || !strings.Contains(b, `<span title="Every run's record, hash-chained and verified">Record <span class="mono">`) {
		t.Error("Rules is not in the nav, or the footer lost its record line")
	}
	empty := newServer(t, filepath.Join(t.TempDir(), "none"))
	e := do(empty, "GET", "/", "127.0.0.1:8484", login(t, empty)).Body.String()
	for _, cmd := range []string{"tego run agent.yaml -- claude", "tego watch -- codex"} {
		if !strings.Contains(e, cmd) {
			t.Errorf("the empty overview lacks %q", cmd)
		}
	}
}

// TestCookiePerPort: two dashboards on one host use different cookie names, so signing in to one keeps the other.
func TestCookiePerPort(t *testing.T) {
	a := newServer(t, fixture(t))
	b, err := New(Config{Ledger: a.cfg.Ledger, Port: 8485, Token: "tok123"})
	if err != nil {
		t.Fatal(err)
	}
	if a.cookie == b.cookie || !strings.HasSuffix(a.cookie, "8484") {
		t.Fatalf("cookie names %q and %q", a.cookie, b.cookie)
	}
}
