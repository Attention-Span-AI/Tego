// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"encoding/hex"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// rulesCanary is an env.set value no page may show.
const rulesCanary = "canary-value-7f3a91"

// rulesSource is the rules file a Rules page fixture run names.
const rulesSource = `# the demo agent
version: 0
name: rules-demo
command: [sh]
capture: off
fs:
  write:
    - ./out/
exec:
  allow: [sh, git]
env:
  pass: [PATH]
  set:
    DEMO_TOKEN: ` + rulesCanary + `
    DEMO_NOTE: >-
      ` + rulesCanary + `-block
`

const (
	rulesRunA = "r-aaaaaaaa-0000000000031-rulesa"
	rulesRunB = "r-aaaaaaaa-0000000000032-rulesb"
	rulesRunO = "r-aaaaaaaa-0000000000033-otherc"
)

// rulesFix is a ledger root whose runs name real rules files, and a server that compiles them.
type rulesFix struct {
	root, proj, home, source, other string
	s                               *Server
	c                               *http.Cookie
}

// newRulesFix writes two runs of rulesSource (A ended, B newer and running) and one run of another rules file (the
// newest), each run's copy and hash as tego run writes them, and logs in.
func newRulesFix(t *testing.T) *rulesFix {
	t.Helper()
	base := t.TempDir()
	f := &rulesFix{root: filepath.Join(base, "ledger"), proj: filepath.Join(base, "proj"), home: filepath.Join(base, "home")}
	f.source, f.other = filepath.Join(f.proj, "agent.yaml"), filepath.Join(f.proj, "other.yaml")
	for _, d := range []string{f.root, filepath.Join(f.proj, "out"), f.home} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	otherText := "version: 0\nname: other-agent\ncommand: [sh]\nexec:\n  allow: [sh]\n"
	t0 := time.Now().Add(-time.Hour).UTC().Truncate(time.Millisecond)
	f.run(t, rulesRunA, f.source, rulesSource, t0, false,
		`"kind":"exec","source":"seccomp","rule":"exec[git]","verdict":"allow","authority":"rule","argv":["git","status"],"exec_id":"x/10/2","path":"/usr/bin/git"`,
		`"kind":"run_end","source":"supervisor","reason":"exit","exit_code":0`)
	f.run(t, rulesRunB, f.source, rulesSource, t0.Add(time.Minute), true,
		`"kind":"exec","source":"seccomp","rule":"exec[git]","verdict":"allow","authority":"rule","argv":["git","log"],"exec_id":"x/10/2","path":"/usr/bin/git"`,
		`"kind":"exec","source":"seccomp","rule":"exec[git]","verdict":"allow","authority":"rule","argv":["git","diff"],"exec_id":"x/10/3","path":"/usr/bin/git"`)
	f.run(t, rulesRunO, f.other, otherText, t0.Add(2*time.Minute), false,
		`"kind":"run_end","source":"supervisor","reason":"exit","exit_code":0`)
	s, err := New(Config{Ledger: f.root, Port: port, Token: "tok123", Machine: &config.Machine{Home: f.home},
		Now: func() time.Time { return t0.Add(time.Hour) }})
	if err != nil {
		t.Fatal(err)
	}
	trustPeer(s)
	f.s, f.c = s, login(t, s)
	return f
}

// run writes the rules file, the run's copy and its ledger: run_start at t0, then rest, one line each.
func (f *rulesFix) run(t *testing.T, id, source, text string, t0 time.Time, live bool, rest ...string) {
	t.Helper()
	if err := os.WriteFile(source, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	c, _, err := agent.LoadBytes(source, []byte(text), &agent.ProfileChain{})
	if err != nil {
		t.Fatal(err)
	}
	canon, err := c.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	sum, _ := c.Hash()
	dir := filepath.Join(f.root, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "contract.yaml"), canon, 0o600); err != nil {
		t.Fatal(err)
	}
	lines := append([]string{fmt.Sprintf(`"kind":"run_start","source":"supervisor","tier":"landlock","command":["sh"],"cwd":"%s","contract_hash":"%s","contract_source":{"path":"%s"}`,
		f.proj, hex.EncodeToString(sum[:]), source)}, rest...)
	var b strings.Builder
	for i, l := range lines {
		fmt.Fprintf(&b, `{"v":1,"seq":%d,"id":"%064x","prev":"","ts":"%s","mono_ns":%d,"run":"%s","agent":"%s","pid":10,"tid":10,"cgroup":1,%s}`+"\n",
			i, i+1, t0.Add(time.Duration(i)*time.Millisecond).Format(time.RFC3339Nano), i+1, id, c.Name, l)
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if live {
		if err := os.MkdirAll(filepath.Join(f.root, ".live"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.root, ".live", id), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *rulesFix) get(t *testing.T, target string) (int, string) {
	t.Helper()
	w := do(f.s, "GET", target, "127.0.0.1:8484", f.c)
	return w.Code, w.Body.String()
}

// TestRulesPageInForce: /rules?run= shows that run's Rules in force as sentences in group tables, each rule's hits in
// that run linking to Logs, its source line, a Change rules button (by the contract's ref, or disabled until built), the terminal twin compiling
// the rules file (not the ledger copy, F8), and the raw YAML behind a closed toggle. No env.set value reaches the
// page, not even inside the raw YAML or the compile table.
func TestRulesPageInForce(t *testing.T) {
	f := newRulesFix(t)
	code, body := f.get(t, "/rules?run="+rulesRunB)
	if code != http.StatusOK {
		t.Fatalf("GET: %d %s", code, body)
	}
	hits := logsURL(rulesRunB, "exec[git]")
	for _, want := range []string{
		"Policy · rules-demo", "Basic (Landlock) · run", " · running",
		"Can change", "Can change files in ./out/", "Programs", "Can run git",
		"Settings it gets", "Gets DEMO_TOKEN, set in its rules", "Gets PATH from your shell",
		`href="` + html.EscapeString(hits) + `"`, "2 hits", "No hits",
		"agent.yaml:", "Edit policy",
		"cd " + f.proj + " &amp;&amp; tego compile " + f.source, "tego block --list " + rulesRunB,
		`<details class="panel rules-raw">`, "DEMO_TOKEN: " + rulesview.Hidden, "/static/rules.css",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/rules?run= lacks %q", want)
		}
	}
	if strings.Contains(body, rulesCanary) {
		t.Error("an env.set value is on the page")
	}
	// Change rules links to the form by the contract's ref once it exists; until then the button is disabled with
	// a hint naming today's ways, never a link to a 404.
	changeLink := `href="/rules/change?c=` + contractRef(f.source) + `"`
	if got := strings.Contains(body, changeLink); got != changeBuilt {
		t.Errorf("Change rules link shown=%v, form built=%v", got, changeBuilt)
	}
	if !changeBuilt && (!strings.Contains(body, `disabled aria-describedby="rules-soon"`) || !strings.Contains(body, "tego rule</span>")) {
		t.Error("the unbuilt Change rules button is not disabled with its hint")
	}
	if strings.Contains(body, "tego compile "+filepath.Join(f.root, rulesRunB)) {
		t.Error("the terminal hint compiles the ledger copy")
	}
	if strings.Contains(body, `rules-raw" open`) {
		t.Error("the raw YAML is open by default")
	}
	// The ended run of the same file says when it was in force.
	if _, body := f.get(t, "/rules?run="+rulesRunA); !strings.Contains(body, " · ended") || !strings.Contains(body, "1 hit") {
		t.Error("the ended run's page lacks its tense or its one hit")
	}
}

// TestRulesPageChooser: the default is the newest run; ?c= picks a rules file by its ref and shows its newest run,
// also when the form kept a run of another file; the run list holds only that file's runs; an unknown ref, a path
// in place of a ref and an unknown run are 404s.
func TestRulesPageChooser(t *testing.T) {
	f := newRulesFix(t)
	_, body := f.get(t, "/rules")
	if !strings.Contains(body, "Policy · other-agent") {
		t.Error("/rules does not default to the newest run")
	}
	for _, want := range []string{`<option value="` + contractRef(f.source) + `"`, `<option value="` + contractRef(f.other) + `" selected`} {
		if !strings.Contains(body, want) {
			t.Errorf("/rules chooser lacks %s", want)
		}
	}
	if strings.Contains(body, `value="`+f.source+`"`) {
		t.Error("the chooser carries a path as a value")
	}
	_, body = f.get(t, "/rules?c="+contractRef(f.source)+"&run="+rulesRunO)
	if !strings.Contains(body, "Policy · rules-demo") || !strings.Contains(body, `<option value="`+rulesRunB+`" selected`) {
		t.Error("?c= with another file's run does not show the file's newest run")
	}
	if !strings.Contains(body, `<option value="`+rulesRunA+`"`) || strings.Contains(body, `<option value="`+rulesRunO+`"`) {
		t.Error("the run list is not the chosen file's runs")
	}
	for _, target := range []string{"/rules?c=feed", "/rules?c=" + url.QueryEscape("../../etc/passwd"), "/rules?c=" + url.QueryEscape(f.source),
		"/rules?run=r-aaaaaaaa-0000000000099-nonexx", "/rules?run=" + url.QueryEscape("../../etc")} {
		if code, _ := f.get(t, target); code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", target, code)
		}
	}
}

// TestRulesPagePendingBanner: a journaled change of the rules file after the run started shows the amber banner
// with its sentence; the tables still show what the run enforces, and "for its next run" is no longer claimed.
func TestRulesPagePendingBanner(t *testing.T) {
	f := newRulesFix(t)
	g := rulefile.DefaultGuard(f.root)
	cur, err := rulefile.Read(f.source, g)
	if err != nil {
		t.Fatal(err)
	}
	next := strings.Replace(rulesSource, "  allow: [sh, git]\n", "  allow: [sh]\n", 1)
	if _, err := rulefile.Replace(context.Background(), g, f.source, cur.SHA256, []byte(next), rulefile.Change{
		Via: "dashboard", Run: rulesRunB, Line: 1, Summary: "remove git from the programs",
		Sentences: []string{"Can run git → Cannot run git"}, Direction: "narrows"}); err != nil {
		t.Fatal(err)
	}
	_, body := f.get(t, "/rules?run="+rulesRunB)
	// The run is running, so the banner is the "Changed since this run started" panel (rules_pending.go).
	for _, want := range []string{"Changed since this run started", "Next run", "Can run git → Cannot run git", "from the dashboard",
		"this run keeps its own", "Can run git", "run copy line"} {
		if !strings.Contains(body, html.EscapeString(want)) {
			t.Errorf("pending page lacks %q", want)
		}
	}
	if strings.Contains(body, "and for its next run") {
		t.Error("the page claims the next run gets these rules after a change")
	}
	// A second change, undone: the banner still lists the first alone, and nothing of the undo.
	cur, err = rulefile.Read(f.source, g)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rulefile.Replace(context.Background(), g, f.source, cur.SHA256, append(cur.Text, []byte("# a later change\n")...),
		rulefile.Change{Via: "dashboard", Summary: "fs.write += ./later/", Sentences: []string{"(nothing) → Can change ./later/"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := rulefile.Undo(context.Background(), g, f.source, rulefile.RevertOptions{Change: rulefile.Change{Via: "dashboard"}}); err != nil {
		t.Fatal(err)
	}
	_, body = f.get(t, "/rules?run="+rulesRunB)
	if !strings.Contains(body, html.EscapeString("Can run git → Cannot run git")) || strings.Contains(body, "./later/") ||
		strings.Contains(body, "undid rc-") || strings.Contains(body, "(an undo)") {
		t.Errorf("after an undone second change the banner should list the first change alone:\n%s", body)
	}
}

// TestRulesPageLiveBlocks: a running run's live block is listed first with a Remove form that posts the kind, value
// and token to the run's unblock route. No launcher line confirms it yet, so the group is headed "Blocking live" and
// its footer says it refuses nothing until then, never "Blocked live now".
func TestRulesPageLiveBlocks(t *testing.T) {
	f := newRulesFix(t)
	if _, err := liveblock.Update(context.Background(), filepath.Join(f.root, rulesRunB), rulesRunB, func(o *liveblock.Overlay) (bool, error) {
		_, ok, err := o.Add(liveblock.KindExec, "/usr/bin/curl", "uid:1000 pid:42 dashboard", time.Now())
		return ok, err
	}); err != nil {
		t.Fatal(err)
	}
	_, body := f.get(t, "/rules?run="+rulesRunB)
	for _, want := range []string{"Blocking live", "A block refuses nothing until the run puts it in force", `action="/runs/` + rulesRunB + `/unblock"`, `name="kind" value="exec"`,
		`name="value" value="/usr/bin/curl"`, `name="csrf" value="` + f.s.csrf + `"`, "live, from the dashboard", ">Remove</button>"} {
		if !strings.Contains(body, want) {
			t.Errorf("live page lacks %s", want)
		}
	}
	if strings.Contains(body, "Blocked live now") {
		t.Error("a group of waiting blocks is headed Blocked live now")
	}
	if strings.Index(body, "Blocking live") > strings.Index(body, "Can change files") {
		t.Error("the live blocks are not listed before the rules file's groups")
	}
	if _, body := f.get(t, "/rules?run="+rulesRunA); strings.Contains(body, "/unblock") {
		t.Error("an ended run offers Remove")
	}
}

// TestRulesPageEmptyAndRunLink: an empty ledger teaches tego init and tego run; the run page's "see the rules" opens
// that run's rules (F9).
func TestRulesPageEmptyAndRunLink(t *testing.T) {
	s := newServer(t, t.TempDir())
	c := login(t, s)
	if b := do(s, "GET", "/rules", "127.0.0.1:8484", c).Body.String(); !strings.Contains(b, "No policies yet") || !strings.Contains(b, "tego init") {
		t.Error("the empty Rules page does not teach tego init")
	}
	f := newRulesFix(t)
	if _, body := f.get(t, "/runs/"+rulesRunA); !strings.Contains(body, `href="/rules?run=`+rulesRunA+`"`) {
		t.Error("the run page's rules link does not name the run")
	}
}
