// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

const (
	detailRun  = "r-aaaa-0004-detail"
	detailRun2 = "r-aaaa-0005-detail"
)

const detailContract = `version: 0
name: detail
command:
  - sh
fs:
  write:
    - ./out/
exec:
  allow:
    - sh
    - git
net:
  allow:
    - api.example.com:443
tier: landlock
`

// detailFixture is a ledger root with two runs of one contract: the first read proj/a/b/secret.txt (#1), ran
// `git push <b>x</b>` (#2) and `git status` (#3), connected to api.example.com:443 (#4) and read eight more files;
// the second ran git push once.
func detailFixture(t *testing.T) (root, contract, proj string) {
	t.Helper()
	root = t.TempDir()
	proj = filepath.Join(t.TempDir(), "proj")
	if err := os.MkdirAll(filepath.Join(proj, "a", "b"), 0o700); err != nil {
		t.Fatal(err)
	}
	contract = filepath.Join(proj, "agent.yaml")
	if err := os.WriteFile(contract, []byte(detailContract), 0o600); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	write := func(run string, evs ...*record.Event) {
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
	start := func() *record.Event {
		return ledgertest.Event(t, record.KindRunStart, record.RunStartPayload{Tier: "landlock", Capture: "off",
			ContractHash: strings.Repeat("0", 64), Command: []string{"sh"}, Cwd: proj, Kernel: "6", StopGrace: "1s",
			ContractSource: &record.ContractSource{Path: contract}})
	}
	allowed := func(rule string) func(*record.Event) {
		return func(e *record.Event) {
			e.Source, e.Rule, e.Verdict, e.Authority = record.SourceSeccomp, rule, record.VerdictAllow, record.AuthorityRule
			e.Attr = &record.Attribution{Confidence: "unattributed", Method: "none"}
		}
	}
	read := func(p string) *record.Event {
		return ledgertest.Event(t, record.KindFS, record.FSPayload{Op: "open", Path: p}, allowed("unmatched"))
	}
	git := func(args ...string) *record.Event {
		return ledgertest.Event(t, record.KindExec, record.ExecPayload{Path: "/usr/bin/git", Argv: append([]string{"git"}, args...),
			ExecID: "x/1/1"}, allowed("exec[git]"))
	}
	evs := []*record.Event{start(), read(filepath.Join(proj, "a", "b", "secret.txt")), git("push", "<b>x</b>"), git("status"),
		ledgertest.Event(t, record.KindNet, record.NetPayload{Op: "connect", Dst: "1.2.3.4:443", Host: "api.example.com", Proto: "tcp"},
			allowed("net[api.example.com:443]"))}
	for i := range 8 {
		evs = append(evs, read(filepath.Join(proj, "f"+strconv.Itoa(i)+".txt")))
	}
	write(detailRun, evs...)
	write(detailRun2, start(), git("push"))
	return root, contract, proj
}

func detailServer(t *testing.T) (*Server, *http.Cookie, string, string) {
	t.Helper()
	root, contract, proj := detailFixture(t)
	s := newServer(t, root)
	s.cfg.Rules = &rules.Service{Ledger: root, Now: s.cfg.Now, Check: func(string, string, []byte) error { return nil }}
	return s, login(t, s), contract, proj
}

// TestEventDetailsPage: the page names the line in words (what, when, process, verdict, rule, reason), shows the
// line as written with the agent's text escaped, the five lines on each side as links, and the same program across
// runs with links to Logs; the scope chips offer the program and its command.
func TestEventDetailsPage(t *testing.T) {
	s, c, contract, _ := detailServer(t)
	w := do(s, "GET", "/runs/"+detailRun+"/lines/2", "127.0.0.1:8484", c)
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", w.Code, body)
	}
	for _, want := range []string{
		"The agent ran", "Program: git", "exec[git]", "pid 42", "Allowed", "2.0 s into the run",
		"&lt;b&gt;x&lt;/b&gt;", `&#34;argv&#34;`, contract,
		`href="/runs/` + detailRun + `/lines/1"`, `href="/runs/` + detailRun + `/lines/7"`, // context: 5 after
		"<strong>3</strong> lines in 2 runs", `href="/logs?q=git"`, `href="/logs?run=` + detailRun2 + `&amp;q=git"`,
		"This program: git", "This command: git push", `action="/logs"`, `/static/event.css`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page lacks %q", want)
		}
	}
	if strings.Contains(body, "<b>x</b>") {
		t.Error("the agent's text is not escaped")
	}
	if strings.Contains(body, `href="/runs/`+detailRun+`/lines/8"`) {
		t.Error("more than five lines after")
	}
	if w := do(s, "GET", "/runs/"+detailRun+"/lines/99", "127.0.0.1:8484", c); w.Code != http.StatusNotFound {
		t.Errorf("a missing line: %d", w.Code)
	}
	if w := do(s, "GET", "/runs/r-nope/lines/1", "127.0.0.1:8484", c); w.Code != http.StatusNotFound {
		t.Errorf("a missing run: %d", w.Code)
	}
	// A file line offers its breadcrumb up to the run's working directory.
	body = do(s, "GET", "/runs/"+detailRun+"/lines/1?level=2", "127.0.0.1:8484", c).Body.String()
	for _, want := range []string{">secret.txt</a>", ">b/</a>", `aria-current="true">a/</a>`, "Every file under "} {
		if !strings.Contains(body, want) {
			t.Errorf("the file breadcrumb lacks %q", want)
		}
	}
	// A connection offers the destination and the whole host.
	body = do(s, "GET", "/runs/"+detailRun+"/lines/4", "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(body, "This destination: api.example.com:443") || !strings.Contains(body, "The whole host: api.example.com") {
		t.Error("the net scopes are missing")
	}
	// A live run's line also offers Block now, posting to the run's own live-block form.
	if strings.Contains(body, "/block\"") {
		t.Error("an ended run offers Block now")
	}
	markLive(t, s.cfg.Ledger, detailRun)
	body = do(s, "GET", "/runs/"+detailRun+"/lines/2", "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(body, `action="/runs/`+detailRun+`/block"`) || !strings.Contains(body, `name="kind" value="exec"`) ||
		!strings.Contains(body, `name="value" value="/usr/bin/git"`) {
		t.Error("a live run's exec line offers no Block now form")
	}
	// The rows link their line numbers here.
	for _, p := range []string{"/runs/" + detailRun, "/logs"} {
		if w := do(s, "GET", p, "127.0.0.1:8484", c); !strings.Contains(w.Body.String(), `href="/runs/`+detailRun+`/lines/2"`) {
			t.Errorf("%s does not link line #2 to its details", p)
		}
	}
}

// TestEventActPreviewAndWrite: a picked action at a scope shows the diff and a Confirm form; the POST without the
// token, from another Origin or with no Origin is refused and writes nothing; with both it writes the contract and
// keeps .bak, for the command scope and an ancestor folder, and returns to the line's page with the saved state.
func TestEventActPreviewAndWrite(t *testing.T) {
	s, c, contract, _ := detailServer(t)
	target := "/runs/" + detailRun + "/lines/2"
	body := do(s, "GET", target+"?a=block&cmd=1", "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(body, "&#43;    - git push") || !strings.Contains(body, `name="cmd" value="1"`) ||
		!strings.Contains(body, `name="csrf" value="`+s.csrf+`"`) || !strings.Contains(body, "tego rule "+detailRun+" 2 --block --command") {
		t.Fatalf("the preview lacks the diff, the scope, the token or the CLI twin:\n%s", body)
	}
	if b, _ := os.ReadFile(contract); string(b) != detailContract {
		t.Fatal("GET wrote the contract")
	}
	base := baseOf(t, body)
	form := url.Values{"a": {"block"}, "cmd": {"1"}, "csrf": {s.csrf}, "base": {base}}
	bad := url.Values{"a": {"block"}, "cmd": {"1"}, "csrf": {"nope"}, "base": {base}}
	own := "http://127.0.0.1:8484"
	for name, w := range map[string]int{
		"no token":     post(s, target, bad, own, "", c).Code,
		"other origin": post(s, target, form, "http://evil.example", "", c).Code,
		"no origin":    post(s, target, form, "", own+target, c).Code,
		"no cookie":    post(s, target, form, own, "", nil).Code,
	} {
		if w != http.StatusForbidden && w != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, w)
		}
	}
	if b, _ := os.ReadFile(contract); string(b) != detailContract {
		t.Fatal("a refused POST wrote the contract")
	}
	// A confirm without the preview's base writes nothing: it would land on text the person did not look at (F7).
	if b := follow(t, s, c, post(s, target, url.Values{"a": {"block"}, "cmd": {"1"}, "csrf": {s.csrf}}, own, "", c)); !strings.Contains(b, "changed since you looked") {
		t.Error("POST without base does not say the contract changed")
	}
	if b, _ := os.ReadFile(contract); string(b) != detailContract {
		t.Fatal("a POST without base wrote the contract")
	}
	if b := follow(t, s, c, post(s, target, form, own, "", c)); !strings.Contains(b, "ev-saved") || !strings.Contains(b, "other git commands still run") {
		t.Fatalf("POST: %s", b)
	}
	got, _ := os.ReadFile(contract)
	if !strings.Contains(string(got), "  deny:\n    - git push # from run "+detailRun+" line #2") {
		t.Errorf("the contract is\n%s", got)
	}
	if old, _ := os.ReadFile(contract + ".bak"); string(old) != detailContract {
		t.Errorf(".bak holds %q", old)
	}
	// An ancestor folder of the read file.
	base = baseOf(t, do(s, "GET", "/runs/"+detailRun+"/lines/1?a=block&level=2", "127.0.0.1:8484", c).Body.String())
	if b := follow(t, s, c, post(s, "/runs/"+detailRun+"/lines/1", url.Values{"a": {"block"}, "level": {"2"}, "csrf": {s.csrf}, "base": {base}}, own, "", c)); !strings.Contains(b, "ev-saved") {
		t.Fatalf("POST level 2: %s", b)
	}
	if got, _ = os.ReadFile(contract); !strings.Contains(string(got), "deny_read:\n    - ./a/ # from run") {
		t.Errorf("the contract is\n%s", got)
	}
	// A pick the rule refuses (allow of an allowed program) says why and writes nothing.
	before, _ := os.ReadFile(contract)
	if b := follow(t, s, c, post(s, target, url.Values{"a": {"allow"}, "csrf": {s.csrf}}, own, "", c)); !strings.Contains(b, "Nothing to save") || !strings.Contains(b, "already allowed") {
		t.Error("POST allow does not say why nothing was saved")
	}
	if after, _ := os.ReadFile(contract); !bytes.Equal(before, after) {
		t.Error("a refused pick wrote the contract")
	}
}
