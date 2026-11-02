// SPDX-License-Identifier: Apache-2.0

package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runlock"
)

const own = "http://127.0.0.1:8484"

// post sends a form POST with the given Origin and Referer ("" leaves the header out).
func post(s *Server, target string, form url.Values, origin, referer string, cookie *http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", target, strings.NewReader(form.Encode()))
	r.Host = "127.0.0.1:8484"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if referer != "" {
		r.Header.Set("Referer", referer)
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

var csrfField = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)

// follow checks that w is an action's answer, 303 See Other to a page of this dashboard with a flash, and returns
// that page's body as the next GET shows it (without the address's #fragment, which a browser does not send).
func follow(t *testing.T, s *Server, c *http.Cookie, w *httptest.ResponseRecorder) string {
	t.Helper()
	loc := w.Header().Get("Location")
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/") || strings.HasPrefix(loc, "//") || !strings.Contains(loc, "flash=") {
		t.Fatalf("action answered %d Location %q, want 303 to a page of the dashboard with a flash: %s", w.Code, loc, w.Body.String())
	}
	page, _, _ := strings.Cut(loc, "#") // a browser keeps the fragment to itself
	g := do(s, "GET", page, "127.0.0.1:8484", c)
	if g.Code != http.StatusOK {
		t.Fatalf("GET %s: %d", loc, g.Code)
	}
	return g.Body.String()
}

// csrfOf reads the session's CSRF token from a page's form, as a browser would submit it.
func csrfOf(t *testing.T, s *Server, c *http.Cookie, page string) string {
	t.Helper()
	m := csrfField.FindStringSubmatch(do(s, "GET", page, "127.0.0.1:8484", c).Body.String())
	if m == nil {
		t.Fatalf("%s has no csrf field", page)
	}
	return m[1]
}

// TestPostChecks: a state-changing request needs the session cookie, the session's CSRF token in the form, and the
// dashboard's own Origin (or, with no Origin, its own Referer); anything else is refused before any handler runs.
func TestPostChecks(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	tok := csrfOf(t, s, c, "/approvals")
	form := func(csrf string) url.Values {
		return url.Values{"csrf": {csrf}, "run": {harmRun}, "ask": {"q-0123456789abcdef0123456789abcdef"}, "decision": {"approve"}}
	}
	for _, tc := range []struct {
		name            string
		form            url.Values
		origin, referer string
		cookie          *http.Cookie
		want            int
	}{
		{"no cookie", form(tok), own, "", nil, http.StatusUnauthorized},
		{"no csrf", form(""), own, "", c, http.StatusForbidden},
		{"wrong csrf", form(strings.Repeat("0", len(tok))), own, "", c, http.StatusForbidden},
		{"cross origin", form(tok), "http://evil.example", "", c, http.StatusForbidden},
		{"null origin", form(tok), "null", "", c, http.StatusForbidden},
		{"other port", form(tok), "http://127.0.0.1:9999", "", c, http.StatusForbidden},
		{"no origin no referer", form(tok), "", "", c, http.StatusForbidden},
		{"cross referer", form(tok), "", "http://evil.example/x", c, http.StatusForbidden},
		{"look-alike referer", form(tok), "", own + ".evil.example/", c, http.StatusForbidden},
		// Past the checks: the answer goes back to the page with a line saying the run is not running.
		{"own origin", form(tok), own, "", c, http.StatusSeeOther},
		{"own referer", form(tok), "", own + "/approvals", c, http.StatusSeeOther},
	} {
		if w := post(s, "/approvals/answer", tc.form, tc.origin, tc.referer, tc.cookie); w.Code != tc.want {
			t.Errorf("%s: %d, want %d: %s", tc.name, w.Code, tc.want, w.Body.String())
		}
	}
	r := httptest.NewRequest("POST", "/approvals/answer", strings.NewReader(`{"csrf":"`+tok+`"}`))
	r.Host, r.Header["Origin"] = "127.0.0.1:8484", []string{own}
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(c)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("json body: %d", w.Code)
	}
	// Only POST changes state: GET of the answer address is no answer.
	if w := do(s, "GET", "/approvals/answer?run="+harmRun+"&decision=approve&csrf="+tok, "127.0.0.1:8484", c); w.Code != http.StatusNotFound {
		t.Errorf("GET answer: %d", w.Code)
	}
	// The stop address's GET is the confirm step, which changes nothing.
	if w := do(s, "GET", "/runs/"+harmRun+"/stop", "127.0.0.1:8484", c); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `name="confirm" value="yes"`) {
		t.Errorf("GET stop: %d", w.Code)
	}
	// A stop without confirm=yes shows the confirm step again.
	if w := post(s, "/runs/"+harmRun+"/stop", url.Values{"csrf": {tok}}, own, "", c); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Confirm the stop") {
		t.Errorf("POST stop unconfirmed: %d", w.Code)
	}
	if b := follow(t, s, c, post(s, "/approvals/answer", form(tok), own, "", c)); !strings.Contains(b, "Not done: the run is not running") {
		t.Error("an answer to a run that is not running does not say so")
	}
	if b := follow(t, s, c, post(s, "/approvals/answer", url.Values{"csrf": {tok}, "run": {harmRun}, "ask": {"ask-7"}, "decision": {"maybe"}}, own, "", c)); !strings.Contains(b, "Not done: the answer is Allow once, Deny") {
		t.Error("bad decision: no plain line")
	}
	if b := follow(t, s, c, post(s, "/approvals/answer", url.Values{"csrf": {tok}, "run": {"../etc"}, "ask": {"q-0123456789abcdef0123456789abcdef"}, "decision": {"deny"}}, own, "", c)); !strings.Contains(b, "no such run") {
		t.Error("bad run: no plain line")
	}
	// Another server's token is not this session's.
	if other := newServer(t, fixture(t)); other.csrf == s.csrf {
		t.Error("two servers made the same CSRF token")
	}
}

// holderEnv makes this test binary a run's lock holder (TestMain-free: the test re-executes itself).
const holderEnv = "TEGO_WEB_TEST_LOCK_HOLDER"

// TestHelperLockHolder is not a test: run with holderEnv set to a run directory, it flocks <dir>/lock, writes the
// lock line a launcher writes, and on SIGTERM records whether the stop marker was there, then exits.
func TestHelperLockHolder(t *testing.T) {
	dir := os.Getenv(holderEnv)
	if dir == "" {
		t.Skip("helper process")
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM)
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		os.Exit(3)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		os.Exit(4)
	}
	start, err := runlock.StartBootNS(os.Getpid())
	if err != nil {
		os.Exit(5)
	}
	if _, err := fmt.Fprintf(f, "%d %d %d\n", os.Getpid(), start, runlock.OwnPIDNS()); err != nil {
		os.Exit(6)
	}
	select {
	case <-sig:
		_, err := os.Stat(filepath.Join(dir, "stop.request"))
		_ = os.WriteFile(filepath.Join(dir, "got-term"), []byte(fmt.Sprint(err == nil)), 0o600)
		os.Exit(0)
	case <-time.After(60 * time.Second):
		os.Exit(7)
	}
}

// TestStopThroughHandler: the Stop form, confirmed, places the stop marker and sends SIGTERM to the verified lock
// holder, as tego stop does, and the page says "stopped" once the lock is free.
func TestStopThroughHandler(t *testing.T) {
	root := fixture(t)
	dir := filepath.Join(root, harmRun)
	letGo(dir) // the helper is the run's launcher here
	holder := exec.Command(os.Args[0], "-test.run=^TestHelperLockHolder$")
	holder.Env = append(os.Environ(), holderEnv+"="+dir)
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- holder.Wait() }()
	t.Cleanup(func() {
		_ = holder.Process.Kill()
		<-done
	})
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if held, info, err := runlock.ProbeLock(dir); err == nil && held && info.PID == holder.Process.Pid {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the helper never held the run's lock")
		}
	}
	s := newServer(t, root)
	c := login(t, s)
	tok := csrfOf(t, s, c, "/runs/"+harmRun+"/stop")
	b := follow(t, s, c, post(s, "/runs/"+harmRun+"/stop", url.Values{"csrf": {tok}, "confirm": {"yes"}}, own, own+"/runs/"+harmRun+"/stop", c))
	if !strings.Contains(b, "Stopped demo-harm") || !strings.Contains(b, "<h1>demo-harm</h1>") {
		t.Fatalf("stop did not land on the run page with Stopped: %s", b)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "got-term")); err != nil || string(b) != "true" {
		t.Fatalf("the holder's SIGTERM came with the stop marker in place: %q %v", b, err)
	}
	// A second stop finds nothing running.
	if b := follow(t, s, c, post(s, "/runs/"+harmRun+"/stop", url.Values{"csrf": {tok}, "confirm": {"yes"}}, own, "", c)); !strings.Contains(b, "was not running") {
		t.Fatalf("second stop: %s", b)
	}
}

// TestRulesShowsContract: /rules shows a run's contract.yaml escaped, and says when its hash is not the run's.
func TestRulesShowsContract(t *testing.T) {
	root := fixture(t)
	if err := os.WriteFile(filepath.Join(root, cleanRun, "contract.yaml"), []byte("version: 0\nname: demo-clean\ncommand: [\"<b>x</b>\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	b := do(s, "GET", "/rules?run="+cleanRun, "127.0.0.1:8484", c).Body.String()
	for _, want := range []string{"name: demo-clean", "&lt;b&gt;x&lt;/b&gt;", "No hash recorded", "not compiled"} {
		if !strings.Contains(b, want) {
			t.Errorf("/rules lacks %q", want)
		}
	}
	if strings.Contains(b, "<b>x</b>") {
		t.Error("contract text not escaped")
	}
}
