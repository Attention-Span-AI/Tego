// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The demo beat on the event page: "Never allow" on a line an ask entry decided, the
// preview in sentences with its direction, "Also apply now" on a live run, the saved state with Undo, Block now at the
// picked scope, and the Deny answer's link to it.

// actRun is a run id the live-block writer takes (ledger.IsRunID).
const actRun = "r-aaaaaaaa-0000000000006-askedx"

// askContract asks before any read under ./vault/.
const askContract = `version: 0
name: asked
command:
  - sh
fs:
  write:
    - ./out/
  ask_read:
    - ./vault/
exec:
  allow:
    - sh
    - git
net:
  allow:
    - api.example.com:443
tier: landlock
`

var baseField = regexp.MustCompile(`name="base" value="([0-9a-f]{64})"`)

// baseOf is the base hash a preview's confirm form carries.
func baseOf(t *testing.T, page string) string {
	t.Helper()
	m := baseField.FindStringSubmatch(page)
	if m == nil {
		t.Fatalf("the preview has no base field:\n%s", page)
	}
	return m[1]
}

// askFixture is a ledger root with actRun: #1 the ask for vault/token under fs.ask_read, #2 the person's no, #3 the
// read it refused with ask-denied, #4 an allowed `git status`, #5 an allowed connection to api.example.com:443.
func askFixture(t *testing.T) (root, contract, proj string) {
	t.Helper()
	root = t.TempDir()
	proj = filepath.Join(t.TempDir(), "proj")
	if err := os.MkdirAll(filepath.Join(proj, "vault"), 0o700); err != nil {
		t.Fatal(err)
	}
	contract = filepath.Join(proj, "agent.yaml")
	if err := os.WriteFile(contract, []byte(askContract), 0o600); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(proj, "vault", "token")
	evs := []*record.Event{
		ledgertest.Event(t, record.KindRunStart, record.RunStartPayload{Tier: "landlock", Capture: "off",
			ContractHash: strings.Repeat("0", 64), Command: []string{"sh"}, Cwd: proj, Kernel: "6", StopGrace: "1s",
			ContractSource: &record.ContractSource{Path: contract}}),
		ledgertest.Event(t, record.KindAsk, struct {
			record.AskPayload
			AskRule string `json:"ask_rule"`
		}{record.AskPayload{AskID: testAsk, Hold: "open"}, "fs.ask_read[./vault/]"}),
		ledgertest.Event(t, record.KindAnswer, record.AnswerPayload{AskID: testAsk, By: "uid:1000", AfterS: 2}),
		ledgertest.Event(t, record.KindFS, record.FSPayload{Op: "open", Path: token}, func(e *record.Event) {
			e.Source, e.Rule, e.Verdict, e.Reason = record.SourceSeccomp, "fs.ask_read[./vault/]", record.VerdictRefused, record.ReasonAskDenied
			e.Authority = record.AuthorityHuman
			e.Attr = &record.Attribution{Confidence: "unattributed", Method: "none"}
		}),
		ledgertest.Event(t, record.KindExec, record.ExecPayload{Path: "/usr/bin/git", Argv: []string{"git", "status"}, ExecID: "x/1/1"}, allowedBy("exec[git]")),
		ledgertest.Event(t, record.KindNet, record.NetPayload{Op: "connect", Dst: "1.2.3.4:443", Host: "api.example.com", Proto: "tcp"},
			allowedBy("net[api.example.com:443]")),
	}
	writeLines(t, root, actRun, evs)
	return root, contract, proj
}

// allowedBy marks a line allowed by rule, as the supervisor writes it.
func allowedBy(rule string) func(*record.Event) {
	return func(e *record.Event) {
		e.Source, e.Rule, e.Verdict, e.Authority = record.SourceSeccomp, rule, record.VerdictAllow, record.AuthorityRule
		e.Attr = &record.Attribution{Confidence: "unattributed", Method: "none"}
	}
}

// writeLines writes evs as the events.jsonl of run under root, numbered from 0.
func writeLines(t *testing.T, root, run string, evs []*record.Event) {
	t.Helper()
	t0 := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	for i, e := range evs {
		e.Run, e.Seq, e.TS = run, uint64(i), t0.Add(time.Duration(i)*time.Second)
		if i > 0 {
			e.Prev = strings.Repeat("a", 64)
		}
		l, err := e.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(append(l, '\n'))
	}
	if err := os.MkdirAll(filepath.Join(root, run), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func askServer(t *testing.T) (*Server, *http.Cookie, string, string) {
	t.Helper()
	root, contract, proj := askFixture(t)
	s := newServer(t, root)
	s.cfg.Rules = &rules.Service{Ledger: root, Now: s.cfg.Now, Check: func(string, string, []byte) error { return nil }}
	return s, login(t, s), contract, proj
}

// holdLock makes run directory dir's run live until the test ends: its lock held, as its launcher holds it from taking
// the lock to run_end, and the run listed in the dashboard's live index (<root>/.live), so it reads as live to the
// pages, the rule service and the live-block writer. The hold is this process's own, markLive's (it takes the place of
// one markLive already holds on the run): each of those only asks whether the lock is held, on a descriptor of its own
// (runlock.ProbeLock, ledger.LockHeld), and a flock this process holds answers that exactly as a launcher's does. A
// helper process (TestHelperLockHolder) used to hold it, with 10 s to take it, and in the race job it once did not
// (TestLiftGovernedPeer: "the helper never held the run's lock"), though none of these tests needs the holder to be
// another process. Stop, which proves and signals the holder, still starts one (TestStopThroughHandler).
func holdLock(t *testing.T, dir string) {
	t.Helper()
	letGo(dir)
	markLive(t, filepath.Dir(dir), filepath.Base(dir))
}

// inline posts form to target as static/live.js does (X-Tego-Inline) and returns the action's JSON answer.
func inline(t *testing.T, s *Server, target string, form url.Values, c *http.Cookie) inlineAnswer {
	t.Helper()
	r := httptest.NewRequest("POST", target, strings.NewReader(form.Encode()))
	r.Host = "127.0.0.1:8484"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", own)
	r.Header.Set(inlineHeader, "1")
	r.AddCookie(c)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var a inlineAnswer
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") || json.Unmarshal(w.Body.Bytes(), &a) != nil {
		t.Fatalf("inline answer of %s: %d %q %s", target, w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	return a
}

func mustContain(t *testing.T, what, page string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(page, w) {
			t.Errorf("%s lacks %q", what, w)
		}
	}
}

// TestNeverAllowOnAskedLine: the refused token line opens on the folder that asked with "Never allow" leading; its
// preview says the change in sentences, marked Narrows, and confirms with the base it showed; a stale base writes
// nothing and goes back to the preview with a line saying why; the confirm answers 303 to the line's page with the
// saved state (the sentence, the diff and Undo), which a reload shows again; the journal holds one dashboard entry,
// and Undo gives the contract its old text back, each answer a line on the page it returns to.
func TestNeverAllowOnAskedLine(t *testing.T) {
	s, c, contract, proj := askServer(t)
	line := "/runs/" + actRun + "/lines/3"
	page := do(s, "GET", line, "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the asked line", page,
		`aria-current="true">vault/</a>`, "(the folder that asked)", `class="btn btn-primary" href="`+line+`?a=block&amp;level=1#act-check"`,
		"Never allow</a>", "Why not the others")
	if strings.Contains(page, "Block next time") {
		t.Error("an asked line names Block next time, not Never allow")
	}
	// Short paths: the panel's words name ./vault/, never the project's absolute path (F12); only titles (hover text)
	// and the hidden Block now value keep it in full.
	panel := page[strings.Index(page, `id="act"`):strings.Index(page, `</aside>`)]
	panel = regexp.MustCompile(`(title|value)="[^"]*"`).ReplaceAllString(panel, "")
	if strings.Contains(panel, proj+"/vault") {
		t.Errorf("the panel names the absolute path:\n%s", panel)
	}

	preview := do(s, "GET", line+"?a=block", "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the preview", preview,
		"Asks you before it reads ./vault/", "Can never read ./vault/", `b b-narrows ev-dir`, "Applies from the next run of",
		`name="level" value="1"`, "Confirm: never allow", `class="btn btn-primary" type="submit"`)
	if strings.Contains(preview, "ev-widen") {
		t.Error("a narrowing shows the widening box")
	}
	base := baseOf(t, preview)
	if b, _ := os.ReadFile(contract); string(b) != askContract {
		t.Fatal("a GET wrote the contract")
	}

	form := url.Values{"csrf": {s.csrf}, "a": {"block"}, "level": {"1"}, "base": {strings.Repeat("0", 64)}}
	w := post(s, line, form, own, "", c)
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, line+"?a=block&level=1&flash=") || !strings.HasSuffix(loc, "#flash") {
		t.Errorf("a stale base returned to %q", loc)
	}
	mustContain(t, "a stale base's page", follow(t, s, c, w), "Not saved · the contract changed since you looked", "Confirm: never allow")
	if b, _ := os.ReadFile(contract); string(b) != askContract {
		t.Fatal("a stale base wrote the contract")
	}

	form.Set("base", base)
	w = post(s, line, form, own, "", c)
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, line+"?saved=") {
		t.Fatalf("confirm returned to %q", loc)
	}
	saved := follow(t, s, c, w)
	mustContain(t, "the saved state", saved, "Saved: Can never read ./vault/, from the next run of agent.yaml.", "ev-saved",
		"Can never read ./vault/", "The change to the file", `name="undo" value="`,
		`<input type="checkbox" name="ack" value="`, "Undo lets the next run do more again: <strong>Asks you before it reads ./vault/</strong>",
		"Undo this change", "agent.yaml.bak")
	// The saved state is kept, not taken: a reload of the address without its flash shows it again.
	reload, _, _ := strings.Cut(loc, "&flash=")
	mustContain(t, "a reload of the saved state", do(s, "GET", reload, "127.0.0.1:8484", c).Body.String(), "ev-saved", `name="undo" value="`)
	got, _ := os.ReadFile(contract)
	if !strings.Contains(string(got), "deny_read:\n    - ./vault/") || strings.Contains(string(got), "ask_read") {
		t.Errorf("the contract is\n%s", got)
	}
	js, err := rulefile.ReadJournal(s.cfg.Ledger)
	if err != nil || len(js) != 1 || js[0].Via != "dashboard" || js[0].Direction != "narrows" || js[0].Run != actRun ||
		len(js[0].Sentences) != 1 || js[0].Sentences[0] != "Asks you before it reads ./vault/ → Can never read ./vault/" {
		t.Fatalf("journal %+v %v", js, err)
	}

	undo := url.Values{"csrf": {s.csrf}, "undo": {js[0].ID}, "base": {js[0].NewSHA256}}
	mustContain(t, "Undo without the acknowledgement", follow(t, s, c, post(s, line, undo, own, "", c)), "Not undone", "Next run may do more")
	undo.Set("ackwiden", "1") // the old boolean is no acknowledgement
	mustContain(t, "Undo with ackwiden=1", follow(t, s, c, post(s, line, undo, own, "", c)), "Not undone", "Next run may do more")
	undo.Set("ack", ackIn(t, saved))
	w = post(s, line, undo, own, "", c)
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, line+"?flash=") {
		t.Errorf("Undo returned to %q, not the line's options", loc)
	}
	mustContain(t, "the page after Undo", follow(t, s, c, w), "Undone: from its next run, agent.yaml has the rules it had before that change.", "Never allow</a>")
	if b, _ := os.ReadFile(contract); string(b) != askContract {
		t.Errorf("after Undo the contract is\n%s", b)
	}
	// A second Undo of the same change finds other text and undoes nothing.
	mustContain(t, "a second Undo", follow(t, s, c, post(s, line, undo, own, "", c)), "Not undone")
}

// TestNeverAllowInPlace: posted by static/live.js (X-Tego-Inline), the confirm answers its line as JSON with the
// address of the saved state ("here"), whose Act panel region shows Saved and Undo, so the panel changes in place
// without a page load; the Undo's answer names the line's options. No flash is kept for either.
func TestNeverAllowInPlace(t *testing.T) {
	s, c, contract, _ := askServer(t)
	line := "/runs/" + actRun + "/lines/3"
	base := baseOf(t, do(s, "GET", line+"?a=block", "127.0.0.1:8484", c).Body.String())
	a := inline(t, s, line, url.Values{"csrf": {s.csrf}, "a": {"block"}, "level": {"1"}, "base": {base}}, c)
	if !a.OK || a.Text != "Saved: Can never read ./vault/, from the next run of agent.yaml." || !strings.HasPrefix(a.Here, line+"?saved=") ||
		!strings.HasSuffix(a.Here, "#act") || a.Go != "" {
		t.Fatalf("inline confirm: %+v", a)
	}
	if b, _ := os.ReadFile(contract); string(b) == askContract {
		t.Fatal("the inline confirm wrote nothing")
	}
	here, _, _ := strings.Cut(a.Here, "#")
	w := doRegions(s, here, "127.0.0.1:8484", c, "r-act:x")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `<template data-live="r-act"`) || !strings.Contains(w.Body.String(), "ev-saved") ||
		!strings.Contains(w.Body.String(), `id="act-undo"`) || strings.Contains(w.Body.String(), "<html") {
		t.Fatalf("the saved state's region: %d %s", w.Code, w.Body.String())
	}
	js, err := rulefile.ReadJournal(s.cfg.Ledger)
	if err != nil || len(js) != 1 {
		t.Fatalf("journal %+v %v", js, err)
	}
	region := w.Body.String()
	u := inline(t, s, line, url.Values{"csrf": {s.csrf}, "undo": {js[0].ID}, "base": {js[0].NewSHA256}, "ack": {ackIn(t, region)}}, c)
	if !u.OK || !strings.HasPrefix(u.Text, "Undone:") || u.Here != line+"#act" {
		t.Errorf("inline Undo: %+v", u)
	}
	s.flashMu.Lock()
	kept := len(s.flashes)
	s.flashMu.Unlock()
	if kept != 0 {
		t.Errorf("the inline answers kept %d flashes", kept)
	}
}

// TestAlsoApplyNowAndBlockNowScope: on a live run a narrowing offers "Also apply now", ticked, in place of Block
// now, and the confirm places the live block; a path block the run cannot enforce now is shown, unticked and
// disabled, with why; Block now names the picked folder or the whole host (F19).
func TestAlsoApplyNowAndBlockNowScope(t *testing.T) {
	s, c, contract, proj := askServer(t)
	holdLock(t, filepath.Join(s.cfg.Ledger, actRun))
	line := "/runs/" + actRun + "/lines/4"
	preview := do(s, "GET", line+"?a=block&level=0", "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the exec preview", preview, "Also apply now", `name="now" value="`+actRun+`" checked`, "This run", "exec:git",
		"May run git", "Cannot run git", "b b-narrows")
	if strings.Contains(preview, `action="/runs/`+actRun+`/block"`) {
		t.Error("the preview offers Block now beside Also apply now")
	}
	// The command scope keeps the program, and says so.
	cmd := do(s, "GET", line+"?cmd=1", "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the command scope", cmd, `name="value" value="/usr/bin/git"`, "A live block names a whole program")
	saved := follow(t, s, c, post(s, line, url.Values{"csrf": {s.csrf}, "a": {"block"}, "level": {"0"}, "base": {baseOf(t, preview)}, "now": {actRun}}, own, "", c))
	// No launcher confirms the block in this test, so the panel says it is being put in force, never in force.
	mustContain(t, "the saved state with also-now", saved, "Putting it in force on this run…", `data-state="waiting"`)
	if strings.Contains(saved, "Live now on this run") {
		t.Error("the saved state says Live now before the launcher confirmed the block")
	}
	bs, err := runact.Blocks(s.cfg.Ledger, actRun)
	if err != nil || len(bs) != 1 || bs[0].Key() != "exec:git" {
		t.Errorf("live blocks %+v %v", bs, err)
	}
	if got, _ := os.ReadFile(contract); strings.Contains(string(got), "    - git\n") {
		t.Errorf("git is still allowed:\n%s", got)
	}

	// Never allow on the token line: the path block is shown but cannot be ticked (this dashboard has no machine
	// config to tell whether the run holds its reads), so Block now stays, naming the folder that asked.
	page := do(s, "GET", "/runs/"+actRun+"/lines/3?a=block", "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the folder preview", page, `name="now" value="`+actRun+`" disabled`, "whether this run holds its reads",
		`name="kind" value="path"`, `name="value" value="`+filepath.Join(proj, "vault")+`"`)
	// The file alone: Block now names the file.
	page = do(s, "GET", "/runs/"+actRun+"/lines/3?level=0", "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the file scope", page, `name="value" value="`+filepath.Join(proj, "vault", "token")+`"`)
	// The destination itself, then the whole host (every port).
	page = do(s, "GET", "/runs/"+actRun+"/lines/5", "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the destination scope", page, `name="value" value="api.example.com:443"`)
	// The whole host: Block now names the host, every port.
	page = do(s, "GET", "/runs/"+actRun+"/lines/5?host=1", "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the host scope", page, `name="kind" value="net"`, `name="value" value="api.example.com"`)
	// git is blocked live now: its line says so, with the way to remove it, instead of offering Block now again.
	page = do(s, "GET", line+"?cmd=1", "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the command scope after the save", page, "Blocked live on this run", `title="exec:git"`)
}

// TestHeldLiveBlockOnAScopedLine: a connect's line keeps its scope id and a live block holds none, so the line of a connect
// the block refuses read as not covered by it, and the panel offered Block now for a block already in place.
func TestHeldLiveBlockOnAScopedLine(t *testing.T) {
	s, c, _, _ := askServer(t)
	root := s.cfg.Ledger
	holdLock(t, filepath.Join(root, actRun))
	const block = "[2001:db8::1]:8443"
	n := strings.Count(readFile(t, filepath.Join(root, actRun, "events.jsonl")), "\n")
	at := time.Now()
	appendLine(t, root, actRun, line(actRun, "probe", n, at, "refused",
		`"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"[2001:db8::1%1]:8443"`))
	addOverlay(t, root, actRun, [2]string{"net", block})
	appendLine(t, root, actRun, liveGapLine(actRun, n+1, at, "net", block, 1))
	page := do(s, "GET", "/runs/"+actRun+"/lines/"+strconv.Itoa(n), "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the line under the block", page, "ev-held", "Blocked live on this run", `title="net:`+block+`"`)
	if strings.Contains(page, `id="act-block"`) {
		t.Error("the panel offers Block now for a block already in place")
	}
}

// TestDenyOffersNeverAllow: the Deny answer's line links "Make it permanent: Never allow" to the ask, which the event
// page sends on to the line the answer decided with Never allow picked; Allow has no such link.
func TestDenyOffersNeverAllow(t *testing.T) {
	fakeBroker(t)
	s, c, _, _ := askServer(t)
	tok := s.csrf // no request is pending, so no page of this fixture has an answer form
	page := follow(t, s, c, post(s, "/approvals/answer", url.Values{"csrf": {tok}, "run": {actRun}, "ask": {testAsk}, "decision": {"deny"}}, own, "", c))
	link := `href="/runs/` + actRun + `/lines/1?decided=1#act"`
	if !strings.Contains(page, link) || !strings.Contains(page, "Make it permanent: Never allow") {
		t.Fatalf("Deny:\n%s", page)
	}
	if b := follow(t, s, c, post(s, "/approvals/answer", url.Values{"csrf": {tok}, "run": {actRun}, "ask": {testAsk}, "decision": {"approve"}}, own, "", c)); strings.Contains(b, "Make it permanent") {
		t.Error("Allow offers Never allow")
	}
	r := do(s, "GET", "/runs/"+actRun+"/lines/1?decided=1", "127.0.0.1:8484", c)
	if r.Code != http.StatusSeeOther || r.Header().Get("Location") != "/runs/"+actRun+"/lines/3?a=block#act-check" {
		t.Fatalf("the ask's link: %d %q", r.Code, r.Header().Get("Location"))
	}
	if page := do(s, "GET", "/runs/"+actRun+"/lines/3?a=block", "127.0.0.1:8484", c).Body.String(); !strings.Contains(page, "Confirm: never allow") {
		t.Error("the decided line does not open on Never allow")
	}
}

// TestWidenWantsTheTick: Allow next time on the asked line widens, so its confirm sits behind the amber box with a
// required checkbox naming what the next run may then do; a confirm without the tick writes nothing (the service's
// ErrNeedsAck, a line on the preview), with it the contract changes, and the saved widening's Undo (a narrowing)
// wants no tick.
func TestWidenWantsTheTick(t *testing.T) {
	s, c, contract, _ := askServer(t)
	line := "/runs/" + actRun + "/lines/3"
	preview := do(s, "GET", line+"?a=allow&level=1", "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the widening preview", preview, "ev-widen", `<input type="checkbox" name="ack" value="`, "Next run may do more")
	if strings.Contains(preview, `class="btn btn-primary" type="submit"`) {
		t.Error("a widening's confirm is primary")
	}
	form := url.Values{"csrf": {s.csrf}, "a": {"allow"}, "level": {"1"}, "base": {baseOf(t, preview)}}
	mustContain(t, "a widening without the tick", follow(t, s, c, post(s, line, form, own, "", c)), "Not saved · tick", "Next run may do more")
	if b, _ := os.ReadFile(contract); string(b) != askContract {
		t.Fatal("a widening without the tick wrote the contract")
	}
	// The box ticked, but the acknowledgement made for another change (a dashboard restart's new key, the day's
	// dated comment): the line says so, not that the box was left unticked.
	form.Set("ack", strings.Repeat("0", 64))
	mustContain(t, "a widening with another change's acknowledgement", follow(t, s, c, post(s, line, form, own, "", c)),
		"Not saved · the preview changed", "Next run may do more")
	if b, _ := os.ReadFile(contract); string(b) != askContract {
		t.Fatal("a widening with another change's acknowledgement wrote the contract")
	}
	form.Set("ack", ackIn(t, preview))
	saved := follow(t, s, c, post(s, line, form, own, "", c))
	mustContain(t, "a widening with the tick", saved, "ev-saved")
	if b, _ := os.ReadFile(contract); string(b) == askContract {
		t.Error("the acknowledged widening wrote nothing")
	}
	if strings.Contains(saved, `name="ack"`) {
		t.Error("the Undo of a widening (a narrowing) asks for the tick")
	}
}

// TestDecidedByTheAsksOwnRefusal: with two asks pending under one entry and the later one denied first, the link
// from each ask opens its own refusal, and an ask whose refusal is not written yet opens none.
func TestDecidedByTheAsksOwnRefusal(t *testing.T) {
	root := t.TempDir()
	type askLine struct {
		record.AskPayload
		Op      string `json:"op"`
		Target  string `json:"target"`
		AskRule string `json:"ask_rule"`
	}
	refusal := func(path string) *record.Event {
		return ledgertest.Event(t, record.KindFS, record.FSPayload{Op: "open", Path: path}, func(e *record.Event) {
			e.Source, e.Rule, e.Verdict, e.Reason = record.SourceSeccomp, "fs.ask_read[./vault/]", record.VerdictRefused, record.ReasonAskDenied
			e.Authority = record.AuthorityHuman
			e.Attr = &record.Attribution{Confidence: "unattributed", Method: "none"}
		})
	}
	evs := []*record.Event{
		ledgertest.Event(t, record.KindRunStart, record.RunStartPayload{Tier: "landlock", Capture: "off",
			ContractHash: strings.Repeat("0", 64), Command: []string{"sh"}, Cwd: "/p", Kernel: "6", StopGrace: "1s"}),
		ledgertest.Event(t, record.KindAsk, askLine{record.AskPayload{AskID: "a1", Hold: "open"}, "open", "/p/vault/a", "fs.ask_read[./vault/]"}),
		ledgertest.Event(t, record.KindAsk, askLine{record.AskPayload{AskID: "a2", Hold: "open"}, "open", "/p/vault/b", "fs.ask_read[./vault/]"}),
		refusal("/p/vault/b"),
	}
	writeLines(t, root, actRun, evs)
	rr, err := ledgerview.LoadRun(root, actRun)
	if err != nil {
		t.Fatal(err)
	}
	if d := decidedBy(rr, &rr.Events[1]); d != nil {
		t.Errorf("the first ask opens #%d, the other ask's refusal", d.Seq)
	}
	if d := decidedBy(rr, &rr.Events[2]); d == nil || d.Seq != 3 {
		t.Errorf("the second ask opens %+v", d)
	}
	writeLines(t, root, actRun, append(evs, refusal("/p/vault/a")))
	if rr, err = ledgerview.LoadRun(root, actRun); err != nil {
		t.Fatal(err)
	}
	if d := decidedBy(rr, &rr.Events[1]); d == nil || d.Seq != 4 {
		t.Errorf("the first ask opens %+v, not its own refusal #4", d)
	}
}

// TestDecidedByANetAsksOwnRefusal: a connection's ask names its address (udp://… for UDP), its refusal's net line
// reads "host (address)" and that line's kind=refused mirror the address alone. With asks pending under one net.ask
// entry (TCP and UDP to the same address among them), the link from each opens its own refusal's net line: never
// another ask's, never a mirror, never the refusal of a connect nobody was asked about; a first write's refusal names
// its ask's target; an ask whose refusal is not written yet opens none.
func TestDecidedByANetAsksOwnRefusal(t *testing.T) {
	root := t.TempDir()
	const rule = "net.ask[api.example.com:443]"
	type askLine struct {
		record.AskPayload
		Op      string `json:"op"`
		Target  string `json:"target"`
		AskRule string `json:"ask_rule"`
	}
	ask := func(id, hold, target string) *record.Event {
		return ledgertest.Event(t, record.KindAsk, askLine{record.AskPayload{AskID: id, Hold: hold}, "connect", target, rule})
	}
	// refusal is the net line a refused connect writes (supervisor refuseAskConnect) and the mirror the pipeline adds.
	refusal := func(proto, dst string, reason record.Reason) []*record.Event {
		return []*record.Event{
			ledgertest.Event(t, record.KindNet, record.NetPayload{Proto: proto, Dst: dst, Host: "api.example.com"}, func(e *record.Event) {
				e.Rule, e.Verdict, e.Reason, e.Authority = rule, record.VerdictRefused, reason, record.AuthorityHuman
				e.Attr = &record.Attribution{Confidence: "unattributed", Method: "none"}
			}),
			ledgertest.Event(t, record.KindRefused, record.RefusedPayload{Op: "net", Target: dst}, func(e *record.Event) {
				e.Rule, e.Reason = rule, reason
			}),
		}
	}
	evs := []*record.Event{
		ledgertest.Event(t, record.KindRunStart, record.RunStartPayload{Tier: "landlock", Capture: "off",
			ContractHash: strings.Repeat("0", 64), Command: []string{"sh"}, Cwd: "/p", Kernel: "6", StopGrace: "1s"}),
		ask("n1", "connect", "192.0.2.1:443"),
		ask("n2", "connect", "192.0.2.2:443"),
		ask("n3", "connect", "udp://192.0.2.1:443"),
		ask("n4", "first_write", "192.0.2.4:443"),
	}
	evs = append(evs, refusal("tcp", "192.0.2.2:443", record.ReasonAskDenied)...)      // #5, #6: n2's
	evs = append(evs, refusal("tcp", "192.0.2.3:443", record.ReasonAskUnavailable)...) // #7, #8: nobody was asked
	evs = append(evs, ledgertest.Event(t, record.KindRefused, record.RefusedPayload{Op: "first_write", Target: "192.0.2.4:443"},
		func(e *record.Event) { e.Rule, e.Reason = rule, record.ReasonAskDenied })) // #9: n4's
	open := func(phase string, want map[int]uint64) {
		t.Helper()
		writeLines(t, root, actRun, evs)
		rr, err := ledgerview.LoadRun(root, actRun)
		if err != nil {
			t.Fatal(err)
		}
		for i, seq := range want {
			got := uint64(0) // none
			if d := decidedBy(rr, &rr.Events[i]); d != nil {
				got = d.Seq
			}
			if got != seq {
				t.Errorf("%s: ask #%d opens #%d, want #%d (#0: none)", phase, i, got, seq)
			}
		}
	}
	open("one denied", map[int]uint64{1: 0, 2: 5, 3: 0, 4: 9})
	evs = append(evs, refusal("udp", "192.0.2.1:443", record.ReasonAskDenied)...) // #10, #11: n3's
	open("the UDP one denied", map[int]uint64{1: 0, 3: 10})
	evs = append(evs, refusal("tcp", "192.0.2.1:443", record.ReasonAskTimeout)...) // #12, #13: n1's
	open("all answered", map[int]uint64{1: 12, 2: 5, 3: 10, 4: 9})
}

// TestShortenerFoldsWholePaths: the Act panel writes a path under the run's working directory ./… and under its home
// ~/…, and either folder itself ./ or ~/ as the contract spells a folder, wherever the path stands in the engine's
// sentence (after a space, "[", ":", "(" or a quote; before "/", the end, a space, ",", ";", ")", "]", a quote or ": ").
// Only a whole path is folded: a sibling that shares the folder's name as a prefix, another path that holds the
// folder inside it, and a name that goes on past it stay as they are.
func TestShortenerFoldsWholePaths(t *testing.T) {
	sh := shortener{cwd: "/w/proj", home: "/h/u"}
	for in, want := range map[string]string{
		"/w/proj/vault/token":              "./vault/token",
		"Can never read /w/proj/vault/":    "Can never read ./vault/",
		"Every file under /w/proj/":        "Every file under ./",
		"Can never write /w/proj":          "Can never write ./",
		"/w/proj":                          "./",
		"(/w/proj)":                        "(./)",
		"fs.write[/w/proj]":                "fs.write[./]",
		"read:/w/proj, write:/w/proj/out":  "read:./, write:./out",
		`entry "/w/proj" and "/h/u/.ssh/"`: `entry "./" and "~/.ssh/"`,
		"the folder of /h/u/x is /h/u: too wide; name the file": "the folder of ~/x is ~/: too wide; name the file",
		"/h/u/.ssh/id_rsa":             "~/.ssh/id_rsa",
		"Opening /h/u":                 "Opening ~/",
		"Can never read /w/projects/x": "Can never read /w/projects/x",
		"/w/proj2":                     "/w/proj2",
		"/w/proj.bak":                  "/w/proj.bak",
		"/w/proj:x":                    "/w/proj:x",
		"/srv/w/proj/vault/":           "/srv/w/proj/vault/",
		"/mnt/h/u/.ssh/":               "/mnt/h/u/.ssh/",
		"/h/user/.ssh/":                "/h/user/.ssh/",
		"Cannot read /etc/shadow":      "Cannot read /etc/shadow",
		"":                             "",
	} {
		if got := sh.text(in); got != want {
			t.Errorf("text(%q) = %q, want %q", in, got, want)
		}
	}
	// The deeper folder wins, whichever of the two it is; a tie goes to the working directory; "/" and "" fold nothing.
	for _, c := range []struct {
		sh       shortener
		in, want string
	}{
		{shortener{cwd: "/h/u/proj", home: "/h/u"}, "/h/u/proj/a /h/u/proj /h/u/b /h/u", "./a ./ ~/b ~/"},
		{shortener{cwd: "/h", home: "/h/u"}, "/h/u/a /h/v /h", "~/a ./v ./"},
		{shortener{cwd: "/h/u", home: "/h/u"}, "/h/u/a /h/u", "./a ./"},
		{shortener{cwd: "/", home: ""}, "/a /", "/a /"},
	} {
		if got := c.sh.text(c.in); got != c.want {
			t.Errorf("%+v text(%q) = %q, want %q", c.sh, c.in, got, c.want)
		}
	}
}

// revertErr is an ActService whose Revert refuses with err.
type revertErr struct{ err error }

func (revertErr) ActOn(context.Context, rules.ActReq) (*rules.ActPlan, error) { return nil, nil }
func (r revertErr) Revert(context.Context, rules.RevertReq) (*rules.Reverted, error) {
	return nil, r.err
}

// TestUndoSaysWhichAckFailed: an Undo with no acknowledgement and one with another change's acknowledgement get
// different lines, so a person who ticked the box is not told they did not.
func TestUndoSaysWhichAckFailed(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{rules.ErrNeedsAck, "tick"},
		{rules.ErrAckMismatch, "out of date"},
	} {
		if f := undo(context.Background(), revertErr{tc.err}, url.Values{"undo": {"rc-1"}, "ack": {"x"}}); f.OK || !strings.Contains(f.Text, tc.want) {
			t.Errorf("%v: %+v, want %q", tc.err, f, tc.want)
		}
	}
}
