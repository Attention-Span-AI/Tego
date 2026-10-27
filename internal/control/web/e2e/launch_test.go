// SPDX-License-Identifier: Apache-2.0

//go:build integration

package e2e

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// The main journey over one real, governed run: the tego binary runs a contract at
// tier landlock whose agent, a shell script, reads a file under fs.ask_read and writes one under fs.ask at the same
// time; tego-control serve shows both asks to a person who answers over HTTP as a browser does (session cookie, CSRF
// field, Origin): Deny the read, Allow the write. The person then turns a line's "Act on this" into a live block, and
// the agent's next exec of that program is refused while the run is still going; at last Stop ends the run and the
// dashboard reads it Stopped, with how it was started. Everything runs unprivileged and in the test's own
// directories: tegotesthooks builds, a machine config, chain anchor, own log and runtime directory under one
// temporary directory (testutil.TegoEnv), and a notify-send stand-in.

const (
	secretBody = "REAL-SECRET\n"
	originalW  = "ORIGINAL\n"
)

// agentScript is the agent. $SECRET is the file under fs.ask_read; held/ is an fs.ask directory. The two held calls run
// in the background so both asks are pending at once. The agent then runs /bin/echo once, waits for out/go (the test's
// signal, written after it has added the live block), runs /bin/echo again, and stays until the run is stopped.
const agentScript = `#!/bin/sh
( cat "$SECRET" > out/got.txt 2> out/err.txt; echo $? > out/rc_read ) &
( echo W 2> out/werr.txt > held/w.txt; echo $? > out/rc_write ) &
wait
/bin/echo first > out/first.txt; echo $? > out/rc_first
until [ -e out/go ]; do /bin/sleep 0.1; done
/bin/echo second 2> out/err2.txt > out/second.txt; echo $? > out/rc_second
until [ -e out/end ]; do /bin/sleep 0.1; done
`

const contractText = `version: 0
name: e2e-journey
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/"]
  ask: ["./held/"]
  ask_read: [%q]
exec:
  allow: ["/bin/sh", "/bin/cat", "/bin/echo", "/bin/sleep"]
net: {}
env:
  pass: ["PATH", "HOME"]
ask:
  timeout: 60s
limits:
  pids: 64
record: summary
`

// until polls cond every 20 ms until it holds or the deadline passes, and fails the test with what it waited for.
func until(t *testing.T, what string, limit time.Duration, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(limit); ; time.Sleep(20 * time.Millisecond) {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", limit, what)
		}
	}
}

// syncBuf is an output buffer a process writes while the test reads it.
type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// build compiles one command of the module as a tegotesthooks build into dir.
func build(t *testing.T, dir, pkg string) string {
	t.Helper()
	bin := filepath.Join(dir, filepath.Base(pkg))
	cmd := exec.Command("go", "build", "-tags", "tegotesthooks", "-trimpath", "-o", bin, pkg)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", pkg, err, out)
	}
	return bin
}

// mkdir makes dir and the directories above it, with mode 0o755 whatever the umask.
func mkdir(t *testing.T, dir string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(dir, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}
}

func write(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func readTrim(path string) string {
	b, _ := os.ReadFile(path)
	return strings.TrimSpace(string(b))
}

// world is the journey's directories and the environment of every tego process it starts.
type world struct {
	base, proj, ledger, secret, held string
	env                              []string
	tego, control                    string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	// A short name: the run's sockets live under <base>/x/tego/<run id>, and sun_path holds 107 bytes.
	base, err := os.MkdirTemp("", "e")
	if err != nil {
		t.Fatal(err)
	}
	if base, err = filepath.EvalSymlinks(base); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	mkdir(t, base, 0o755)
	w := &world{base: base, proj: filepath.Join(base, "proj"), ledger: filepath.Join(base, "ledger"),
		secret: filepath.Join(base, "vault", "token"), held: filepath.Join(base, "proj", "held")}
	for _, d := range []string{w.proj, filepath.Join(w.proj, "out"), w.held, filepath.Dir(w.secret), filepath.Join(base, "cfg")} {
		mkdir(t, d, 0o755)
	}
	mkdir(t, w.ledger, 0o700)
	xdg := filepath.Join(base, "x")
	mkdir(t, xdg, 0o700)
	write(t, w.secret, secretBody, 0o600)
	write(t, filepath.Join(w.held, "w.txt"), originalW, 0o644)
	write(t, filepath.Join(w.proj, "agent.sh"), strings.ReplaceAll(agentScript, "$SECRET", w.secret), 0o700)
	write(t, filepath.Join(w.proj, "agent.yaml"), fmt.Sprintf(contractText, w.secret), 0o600)
	cfg := filepath.Join(base, "cfg", "machine.yaml")
	write(t, cfg, fmt.Sprintf("version: 0\nledger_root: %s\nstop_grace: 2s\n", w.ledger), 0o600)
	stub := filepath.Join(base, "notify-send")
	write(t, stub, "#!/bin/sh\nexit 0\n", 0o755)
	w.env = testutil.TegoEnv(t, base, "TEGO_CONFIG="+cfg, "TEGO_TEST_NOTIFY_SEND="+stub, "XDG_RUNTIME_DIR="+xdg, "HISTFILE=/dev/null")
	bins := filepath.Join(base, "bin")
	mkdir(t, bins, 0o755)
	w.tego, w.control = build(t, bins, "github.com/attention-span-ai/tego/cmd/tego"), build(t, bins, "github.com/attention-span-ai/tego/cmd/tego-control")
	return w
}

// start starts a command that already has the world's environment, and kills it when the test ends if it is still there.
func start(t *testing.T, cmd *exec.Cmd) *exited {
	t.Helper()
	e := &exited{done: make(chan struct{})}
	if cmd.Stdout == nil {
		cmd.Stdout = &e.out
	}
	if cmd.Stderr == nil {
		cmd.Stderr = &e.out
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { e.err = cmd.Wait(); close(e.done) }()
	t.Cleanup(func() {
		if !e.over() {
			_ = cmd.Process.Kill()
			<-e.done
		}
		if t.Failed() {
			t.Logf("%s said:\n%s", filepath.Base(cmd.Path), e.out.String())
		}
	})
	return e
}

// exited tells when a started process is over.
type exited struct {
	done chan struct{}
	err  error
	out  syncBuf
}

func (e *exited) over() bool {
	select {
	case <-e.done:
		return true
	default:
		return false
	}
}

// ledgerLine is one line of a run's events.jsonl as far as this journey reads it.
type ledgerLine struct {
	Seq     int            `json:"seq"`
	Kind    string         `json:"kind"`
	Verdict string         `json:"verdict"`
	Reason  string         `json:"reason"`
	Rule    string         `json:"rule"`
	Payload map[string]any `json:"-"` // the whole line: a payload's fields sit beside the common ones
	Raw     string         `json:"-"`
}

// ledgerOf is the lines of the run's events.jsonl, complete lines only.
func ledgerOf(t *testing.T, root, run string) []ledgerLine {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, run, "events.jsonl"))
	if err != nil {
		return nil
	}
	var out []ledgerLine
	for _, l := range strings.SplitAfter(string(b), "\n") {
		if !strings.HasSuffix(l, "\n") {
			break
		}
		var e ledgerLine
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatalf("a ledger line is not JSON: %v: %q", err, l)
		}
		if err := json.Unmarshal([]byte(l), &e.Payload); err != nil {
			t.Fatal(err)
		}
		e.Raw = strings.TrimSpace(l)
		out = append(out, e)
	}
	return out
}

func kindsOf(lines []ledgerLine, kind string) []ledgerLine {
	var out []ledgerLine
	for _, l := range lines {
		if l.Kind == kind {
			out = append(out, l)
		}
	}
	return out
}

// runID is the one run directory of the ledger root, "" while there is none.
func runID(root string) string {
	ents, _ := os.ReadDir(root)
	for _, e := range ents {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			return e.Name()
		}
	}
	return ""
}

// browser is a signed-in HTTP client of the dashboard: the session cookie from the token URL, the CSRF field from a
// page's form, and the dashboard's own Origin on every POST, as a browser sends them.
type browser struct {
	t      *testing.T
	root   string // http://127.0.0.1:<port>
	c      *http.Client
	bare   *http.Client // no cookie jar
	csrf   string
	tokURL string
}

func newBrowser(t *testing.T, tokenURL string) *browser {
	t.Helper()
	u, err := url.Parse(tokenURL)
	if err != nil || u.Host == "" {
		t.Fatalf("the dashboard URL %q: %v", tokenURL, err)
	}
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, root: u.Scheme + "://" + u.Host, tokURL: tokenURL,
		c:    &http.Client{Jar: jar, Timeout: 15 * time.Second},
		bare: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (b *browser) do(c *http.Client, method, path string, form url.Values, hdr map[string]string) (int, string) {
	b.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, b.root+path, body)
	if err != nil {
		b.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	page, err := io.ReadAll(resp.Body)
	if err != nil {
		b.t.Fatal(err)
	}
	return resp.StatusCode, string(page)
}

func (b *browser) get(path string) (int, string) { return b.do(b.c, "GET", path, nil, nil) }

// post sends a form with the session, the dashboard's own Origin and the CSRF field.
func (b *browser) post(path string, form url.Values) (int, string) {
	b.t.Helper()
	f := url.Values{"csrf": {b.csrf}}
	for k, v := range form {
		f[k] = v
	}
	return b.do(b.c, "POST", path, f, map[string]string{"Origin": b.root})
}

var csrfField = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)

// signIn exchanges the token URL for the cookie; the CSRF token comes later, from a page that has a form.
func (b *browser) signIn() {
	b.t.Helper()
	if code, _ := b.do(b.bare, "GET", "/status.json", nil, nil); code != http.StatusUnauthorized {
		b.t.Fatalf("status.json without the cookie: %d, want 401", code)
	}
	if code, page := b.do(b.c, "GET", strings.TrimPrefix(b.tokURL, b.root), nil, nil); code != http.StatusOK || !strings.Contains(page, "Overview") {
		b.t.Fatalf("the token URL: %d", code)
	}
}

// readCSRF reads the session's CSRF token from the form of a page, as a browser submits it.
func (b *browser) readCSRF(page string) {
	b.t.Helper()
	m := csrfField.FindStringSubmatch(page)
	if m == nil {
		b.t.Fatal("the page has no CSRF field")
	}
	b.csrf = m[1]
}

type liveState struct {
	Live    int `json:"live"`
	Pending int `json:"pending"`
}

func (b *browser) status() liveState {
	b.t.Helper()
	code, page := b.get("/status.json")
	var st liveState
	if code != http.StatusOK || json.Unmarshal([]byte(page), &st) != nil {
		b.t.Fatalf("status.json: %d %q", code, page)
	}
	return st
}

// card is one pending request of the Approvals page: its id, and the target it names.
type card struct{ id, target string }

var askCard = regexp.MustCompile(`<section class="ask" id="(q-[0-9a-f]+)"[\s\S]*?<span class="ut ut-box">([^<]*)</span>`)

func (b *browser) cards() []card {
	b.t.Helper()
	_, page := b.get("/approvals")
	var out []card
	for _, m := range askCard.FindAllStringSubmatch(page, -1) {
		out = append(out, card{m[1], m[2]})
	}
	return out
}

// TestDashboardJourneyOverALiveRun is the journey in the file comment.
func TestDashboardJourneyOverALiveRun(t *testing.T) {
	outsideEveryRun(t)
	if os.Geteuid() == 0 {
		t.Skip("tego-control refuses to run as root (the dashboard runs as the user)")
	}
	w := newWorld(t)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("the run's ledger:\n%s", rawOf(ledgerOf(t, w.ledger, runID(w.ledger))))
		}
	})
	began := time.Now()

	// The run: stdin is /dev/null and stdout a pipe, so the dashboard labels it Background.
	cmd := exec.Command(w.tego, "run", filepath.Join(w.proj, "agent.yaml"), "--", "/bin/sh", "agent.sh")
	cmd.Dir = w.proj
	cmd.Env = w.env
	run := start(t, cmd)
	var id string
	until(t, "the run's run_start line", 30*time.Second, func() bool {
		if run.over() {
			t.Fatalf("tego run ended first: %v\n%s", run.err, run.out.String())
		}
		id = runID(w.ledger)
		return id != "" && len(kindsOf(ledgerOf(t, w.ledger, id), "run_start")) == 1
	})

	// The dashboard, on a free loopback port of its own, over that ledger root.
	serve := exec.Command(w.control, "serve", "--addr", "127.0.0.1:0", "--ledger", w.ledger)
	serve.Env = w.env
	pipe, err := serve.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	srv := start(t, serve)
	first := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(pipe)
		for sc.Scan() {
			if u, ok := strings.CutPrefix(sc.Text(), "Tego dashboard: "); ok {
				first <- u
				break
			}
		}
		_, _ = io.Copy(io.Discard, pipe)
	}()
	var tokenURL string
	select {
	case tokenURL = <-first:
	case <-srv.done:
		t.Fatalf("tego-control serve ended first: %v\n%s", srv.err, srv.out.String())
	case <-time.After(30 * time.Second):
		t.Fatal("tego-control serve printed no URL")
	}
	if host, _, err := net.SplitHostPort(strings.TrimPrefix(strings.SplitN(tokenURL, "/?", 2)[0], "http://")); err != nil || host != "127.0.0.1" {
		t.Fatalf("the dashboard URL %q is not on 127.0.0.1", tokenURL)
	}
	b := newBrowser(t, tokenURL)
	b.signIn()

	// Both asks wait: the live state, Overview's banner and Approvals say so.
	until(t, "two pending asks in status.json", 30*time.Second, func() bool { return b.status().Pending == 2 })
	if st := b.status(); st.Live != 1 {
		t.Errorf("status.json: %+v, want one live run", st)
	}
	_, overview := b.get("/")
	b.readCSRF(overview)
	for _, want := range []string{`id="ask-banner"`, "2 requests are waiting for you", "e2e-journey", "<title>(2) "} {
		if !strings.Contains(overview, want) {
			t.Errorf("Overview lacks %q", want)
		}
	}
	cards := b.cards()
	if len(cards) != 2 {
		t.Fatalf("Approvals shows %d cards, want 2", len(cards))
	}
	var readID, writeID string
	for _, c := range cards {
		switch c.target {
		case w.secret:
			readID = c.id
		case filepath.Join(w.held, "w.txt"):
			writeID = c.id
		}
		if !strings.Contains(overview, `name="ask" value="`+c.id+`"`) {
			t.Errorf("Overview's banner has no answer form for %s", c.id)
		}
	}
	if readID == "" || writeID == "" {
		t.Fatalf("Approvals names %+v, want the secret %s and the held write %s", cards, w.secret, filepath.Join(w.held, "w.txt"))
	}
	if got := readTrim(filepath.Join(w.proj, "out", "rc_read")) + readTrim(filepath.Join(w.proj, "out", "rc_write")); got != "" {
		t.Fatalf("the agent went on while both requests waited: %q", got)
	}

	// A waiting request cannot be frozen, so the run's page offers no Pause while one waits and says why, and a
	// pause posted anyway is refused before it reaches the run (no live_control line).
	if _, runPage := b.get("/runs/" + id); strings.Contains(runPage, `action="/runs/`+id+`/pause"`) ||
		!strings.Contains(runPage, "Answer its waiting request first; then Pause freezes it.") {
		t.Error("the run's page offers Pause while its requests wait, or does not say why it does not")
	}
	if _, page := b.do(b.c, "POST", "/runs/"+id+"/pause", url.Values{"csrf": {b.csrf}}, map[string]string{"Origin": b.root}); !strings.Contains(page, "waits on a request. Answer it first") {
		t.Error("a pause posted while a request waits was not refused in plain words")
	}
	if strings.Contains(rawOf(ledgerOf(t, w.ledger, id)), `"live_control"`) {
		t.Error("a refused pause reached the run's launcher")
	}

	// A request without the CSRF field, from another origin, or without the cookie is refused and answers nothing.
	answer := url.Values{"run": {id}, "ask": {readID}, "decision": {"deny"}}
	noCSRF := url.Values{"run": {id}, "ask": {readID}, "decision": {"deny"}}
	for name, c := range map[string]int{
		"no csrf field": func() int {
			code, _ := b.do(b.c, "POST", "/approvals/answer", noCSRF, map[string]string{"Origin": b.root})
			return code
		}(),
		"other origin": func() int {
			f := url.Values{"csrf": {b.csrf}, "run": {id}, "ask": {readID}, "decision": {"deny"}}
			code, _ := b.do(b.c, "POST", "/approvals/answer", f, map[string]string{"Origin": "http://evil.example"})
			return code
		}(),
		"no cookie": func() int {
			f := url.Values{"csrf": {b.csrf}, "run": {id}, "ask": {readID}, "decision": {"deny"}}
			code, _ := b.do(b.bare, "POST", "/approvals/answer", f, map[string]string{"Origin": b.root})
			return code
		}(),
	} {
		if c != http.StatusForbidden && c != http.StatusUnauthorized {
			t.Errorf("a POST with %s: %d, want 403 or 401", name, c)
		}
	}
	if st := b.status(); st.Pending != 2 {
		t.Fatalf("a refused POST changed the pending asks: %+v", st)
	}

	// Deny the read, Allow the write, as the cards' buttons do: each answer returns to Approvals (303, which the
	// client follows) with the answer in one line, never a raw ledger line.
	code, page := b.post("/approvals/answer", answer)
	if code != http.StatusOK || !strings.Contains(page, "Denied: read of ") || strings.Contains(page, `"after_s"`) {
		t.Fatalf("Deny: %d\n%s", code, page)
	}
	code, page = b.post("/approvals/answer", url.Values{"run": {id}, "ask": {writeID}, "decision": {"approve"}})
	if code != http.StatusOK || !strings.Contains(page, "Allowed once: write to ") {
		t.Fatalf("Allow: %d\n%s", code, page)
	}
	until(t, "no pending ask in status.json", 10*time.Second, func() bool { return b.status().Pending == 0 })
	out := func(name string) string { return readTrim(filepath.Join(w.proj, "out", name)) }
	until(t, "the agent's two results", 20*time.Second, func() bool { return out("rc_read") != "" && out("rc_write") != "" && out("rc_first") != "" })
	if out("rc_write") != "0" {
		t.Errorf("the allowed write exited %q, want 0 (%s)", out("rc_write"), out("werr.txt"))
	}
	if got, _ := os.ReadFile(filepath.Join(w.held, "w.txt")); string(got) != "W\n" {
		t.Errorf("held/w.txt holds %q, want the agent's write", got)
	}
	if out("rc_read") == "0" || out("got.txt") != "" || strings.Contains(out("err.txt"), "REAL-SECRET") {
		t.Errorf("the denied read exited %q and left %q (%q), want a failure and no secret", out("rc_read"), out("got.txt"), out("err.txt"))
	}
	lines := ledgerOf(t, w.ledger, id)
	if asks := kindsOf(lines, "ask"); len(asks) != 2 {
		t.Errorf("%d ask lines, want 2", len(asks))
	}
	approved := map[any]int{}
	for _, a := range kindsOf(lines, "answer") {
		approved[a.Payload["approved"]]++
		if a.Payload["approved"] == false && a.Reason != "ask-denied" && a.Payload["answer_reason"] != "ask-denied" {
			t.Errorf("the denied answer line %s lacks the reason ask-denied", a.Raw)
		}
		if by, _ := a.Payload["by"].(string); !strings.HasPrefix(by, "uid:") {
			t.Errorf("an answer line is by %q, want the person's uid", by)
		}
	}
	if approved[true] != 1 || approved[false] != 1 {
		t.Errorf("answers %v, want one approved and one denied", approved)
	}

	// Act on this: the details page of the agent's first /bin/echo offers Block now; adding it refuses the next exec.
	var echoSeq = -1
	for _, l := range kindsOf(lines, "exec") {
		if argv, _ := l.Payload["argv"].([]any); len(argv) == 2 && argv[1] == "first" {
			echoSeq = l.Seq
		}
	}
	if echoSeq < 0 {
		t.Fatalf("no exec line of /bin/echo first in the ledger:\n%s", rawOf(lines))
	}
	if out("rc_second") != "" {
		t.Fatal("the agent ran its second echo before the block")
	}
	line := fmt.Sprintf("/runs/%s/lines/%d", id, echoSeq)
	code, page = b.get(line)
	form := regexp.MustCompile(`action="/runs/` + regexp.QuoteMeta(id) + `/block"><input type="hidden" name="csrf" value="[0-9a-f]+"><input type="hidden" name="kind" value="([a-z]+)"><input type="hidden" name="value" value="([^"]+)">`).FindStringSubmatch(page)
	if code != http.StatusOK || !strings.Contains(page, "Act on this") || form == nil || form[1] != "exec" {
		t.Fatalf("line %d's page: %d, Block now form %v", echoSeq, code, form)
	}
	code, page = b.post("/runs/"+id+"/block", url.Values{"kind": {form[1]}, "value": {form[2]}})
	if code != http.StatusOK || !strings.Contains(page, "Blocked "+form[2]+" on run ") {
		t.Fatalf("Block now: %d\n%s", code, page)
	}
	until(t, "the live-block-added line", 20*time.Second, func() bool {
		for _, g := range kindsOf(ledgerOf(t, w.ledger, id), "gap") {
			if strings.Contains(g.Raw, "live-block-added") {
				return true
			}
		}
		return false
	})
	write(t, filepath.Join(w.proj, "out", "go"), "", 0o644)
	until(t, "the agent's second echo", 20*time.Second, func() bool { return out("rc_second") != "" })
	if out("rc_second") == "0" || out("second.txt") != "" {
		t.Errorf("the blocked program ran: status %q, output %q (%s)", out("rc_second"), out("second.txt"), out("err2.txt"))
	}
	var refused bool
	for _, l := range kindsOf(ledgerOf(t, w.ledger, id), "exec") {
		if l.Verdict == "refused" && strings.HasPrefix(l.Rule, "live.block[exec:") {
			refused = true
		}
	}
	if !refused {
		t.Errorf("no exec line refused by the live block:\n%s", rawOf(ledgerOf(t, w.ledger, id)))
	}
	if out("rc_first") != "0" {
		t.Errorf("the first echo exited %q, want 0: the block must not reach back", out("rc_first"))
	}

	// Stop from the dashboard: the confirm step changes nothing, the confirmed one ends the run.
	code, page = b.get("/runs/" + id + "/stop")
	if code != http.StatusOK || !strings.Contains(page, `name="confirm" value="yes"`) || run.over() {
		t.Fatalf("the Stop confirm step: %d (run over: %v)", code, run.over())
	}
	if code, page = b.post("/runs/"+id+"/stop", url.Values{"confirm": {"yes"}}); code != http.StatusOK || !(strings.Contains(page, "Stopped ") || strings.Contains(page, "Stopping ")) {
		t.Fatalf("Stop: %d\n%s", code, page)
	}
	select {
	case <-run.done:
	case <-time.After(30 * time.Second):
		t.Fatalf("tego run did not end after Stop\n%s", run.out.String())
	}
	var end ledgerLine
	if ends := kindsOf(ledgerOf(t, w.ledger, id), "run_end"); len(ends) != 1 {
		t.Fatalf("%d run_end lines after Stop", len(ends))
	} else {
		end = ends[0]
	}
	if end.Payload["reason"] != "stopped" {
		t.Errorf("run_end %s, want reason stopped", end.Raw)
	}
	until(t, "the dashboard to read the run as ended", 10*time.Second, func() bool { return b.status().Live == 0 })
	_, runPage := b.get("/runs/" + id)
	badge := regexp.MustCompile(`class="b b-origin b-origin-[a-z]+"[^>]*>([A-Za-z]+)</span>`).FindStringSubmatch(runPage)
	if !strings.Contains(runPage, ">Stopped</span>") || badge == nil || badge[1] != "Background" {
		t.Errorf("the run page lacks the Stopped word or the Background label (%v)", badge)
	}
	// Runs shows no Background pill (only Interactive and Deployed are worth one); the status says it in its title.
	if _, ended := b.get("/runs?state=ended"); !strings.Contains(ended, "Stopped") || !strings.Contains(ended, `title="Started without a terminal"`) {
		t.Error("Runs?state=ended lacks the Stopped word or the Started without a terminal title")
	}
	if elapsed := time.Since(began); elapsed > 60*time.Second {
		t.Errorf("the journey took %s after the build, the bound is 60 s", elapsed.Round(time.Second))
	}
}

func rawOf(lines []ledgerLine) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.Raw + "\n")
	}
	return b.String()
}
