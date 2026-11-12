// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
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

	"github.com/attention-span-ai/tego/internal/control/rules"
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
		markLive(t, f.root, id)
	}
}

func (f *rulesFix) get(t *testing.T, target string) (int, string) {
	t.Helper()
	w := do(f.s, "GET", target, "127.0.0.1:8484", f.c)
	return w.Code, w.Body.String()
}

// svcRef is the ref the rule service lists for the rules file whose newest run recorded path: the ref Change rules
// names the file by, and so the Rules page too.
func (f *rulesFix) svcRef(t *testing.T, path string) string {
	t.Helper()
	cs, err := (&rules.Service{Ledger: f.root, Home: f.home}).Contracts()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Path == path {
			return c.Ref
		}
	}
	t.Fatalf("the rule service lists no %s: %+v", path, cs)
	return ""
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
		"Contract · rules-demo", "Basic (Landlock) · run", " · running",
		"Can change", "Can change files in ./out/", "Programs", "Can run git",
		"Settings it gets", "Gets DEMO_TOKEN, set in its rules", "Gets PATH from your shell",
		`href="` + html.EscapeString(hits) + `"`, "2 hits", "No hits",
		"agent.yaml:", "Edit contract",
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
	// Change rules links to the form by the contract's ref once it exists, the rule service's own, so the form needs
	// no redirect (and Narrow this to its section); until then the button is disabled with a hint naming today's
	// ways, never a link to a 404.
	ref := f.svcRef(t, f.source)
	changeLink := `href="/rules/change?c=` + ref + `"`
	if got := strings.Contains(body, changeLink); got != changeBuilt {
		t.Errorf("Change rules link shown=%v, form built=%v", got, changeBuilt)
	}
	if narrow := `href="/rules/change?c=` + ref + `#rc-net.allow"`; changeBuilt && !strings.Contains(body, narrow) {
		t.Errorf("the open network lacks %s", narrow)
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

// TestRulesPageChooser: the default is the newest run; ?c= picks a rules file by its ref, the rule service's, and
// shows its newest run, also when the form kept a run of another file; the run list holds only that file's runs; an
// old link naming the file by the page's former ref (the sha256 of its recorded path) is sent to its ref with its run
// kept; an unknown ref, a path in place of a ref and an unknown run are 404s.
func TestRulesPageChooser(t *testing.T) {
	f := newRulesFix(t)
	_, body := f.get(t, "/rules")
	if !strings.Contains(body, "Contract · other-agent") {
		t.Error("/rules does not default to the newest run")
	}
	src, oth := f.svcRef(t, f.source), f.svcRef(t, f.other)
	for _, want := range []string{`<option value="` + src + `"`, `<option value="` + oth + `" selected`} {
		if !strings.Contains(body, want) {
			t.Errorf("/rules chooser lacks %s", want)
		}
	}
	if strings.Contains(body, `value="`+f.source+`"`) {
		t.Error("the chooser carries a path as a value")
	}
	_, body = f.get(t, "/rules?c="+src+"&run="+rulesRunO)
	if !strings.Contains(body, "Contract · rules-demo") || !strings.Contains(body, `<option value="`+rulesRunB+`" selected`) {
		t.Error("?c= with another file's run does not show the file's newest run")
	}
	if !strings.Contains(body, `<option value="`+rulesRunA+`"`) || strings.Contains(body, `<option value="`+rulesRunO+`"`) {
		t.Error("the run list is not the chosen file's runs")
	}
	old := do(f.s, "GET", "/rules?c="+legacyRef(f.source)+"&run="+rulesRunA, "127.0.0.1:8484", f.c)
	if loc := old.Header().Get("Location"); old.Code != http.StatusSeeOther || loc != "/rules?c="+src+"&run="+rulesRunA {
		t.Errorf("an old link by the former ref: %d %q, want 303 to the file's ref", old.Code, loc)
	}
	for _, target := range []string{"/rules?c=feed", "/rules?c=" + url.QueryEscape("../../etc/passwd"), "/rules?c=" + url.QueryEscape(f.source),
		"/rules?c=" + legacyRef(filepath.Join(f.proj, "never-ran.yaml")), "/rules?c=" + src[:15],
		"/rules?run=r-aaaaaaaa-0000000000099-nonexx", "/rules?run=" + url.QueryEscape("../../etc")} {
		if code, _ := f.get(t, target); code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", target, code)
		}
	}
}

// TestRulesPageOneFileTwoSpellings: a run that recorded its rules file through a linked folder ran the same file: the
// chooser lists it once, by the ref the rule service names it by, and its run list holds the runs of both spellings.
func TestRulesPageOneFileTwoSpellings(t *testing.T) {
	f := newRulesFix(t)
	link := filepath.Join(filepath.Dir(f.proj), "proj-link")
	if err := os.Symlink(f.proj, link); err != nil {
		t.Fatal(err)
	}
	const viaLink = "r-aaaaaaaa-0000000000034-linked"
	f.run(t, viaLink, filepath.Join(link, "agent.yaml"), rulesSource, time.Now().Add(-30*time.Minute).UTC().Truncate(time.Millisecond), false,
		`"kind":"run_end","source":"supervisor","reason":"exit","exit_code":0`)
	ref := f.svcRef(t, filepath.Join(link, "agent.yaml")) // listed under its newest run's spelling
	code, body := f.get(t, "/rules?c="+ref)
	if code != http.StatusOK {
		t.Fatalf("GET by the file's ref: %d", code)
	}
	if n, m := strings.Count(body, `<option value="`+ref+`"`), strings.Count(body, ">rules-demo · "); n != 1 || m != 1 {
		t.Errorf("the chooser lists the file %d times by its ref and %d by its name, want once", n, m)
	}
	for _, want := range []string{`<option value="` + viaLink + `" selected`, `<option value="` + rulesRunB + `"`, `<option value="` + rulesRunA + `"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the file's run list lacks %s", want)
		}
	}
}

// TestRulesPageChooserMarksAGoneFile: a rules file removed since its runs is still listed, so its runs' rules can be
// read, and its option says "file gone"; a file still at its path does not.
func TestRulesPageChooserMarksAGoneFile(t *testing.T) {
	f := newRulesFix(t)
	if err := os.Remove(f.other); err != nil {
		t.Fatal(err)
	}
	option := func(body, value string) string {
		i := strings.Index(body, `<option value="`+value+`"`)
		if i < 0 {
			return ""
		}
		j := strings.Index(body[i:], "</option>")
		return body[i : i+j]
	}
	_, body := f.get(t, "/rules")
	if o := option(body, rules.Ref(f.other)); !strings.Contains(o, "other-agent") || !strings.Contains(o, " · file gone") {
		t.Errorf("the removed rules file's option reads %q, want it marked gone", o)
	}
	if o := option(body, rules.Ref(f.source)); o == "" || strings.Contains(o, "file gone") {
		t.Errorf("the rules file still in place reads %q, want it listed and not gone", o)
	}
	if code, page := f.get(t, "/rules?c="+rules.Ref(f.other)); code != http.StatusOK || !strings.Contains(page, "Contract · other-agent") {
		t.Errorf("the removed rules file's runs: %d, want its newest run's rules", code)
	}
}

// TestRulesPageRunListHoldsTheRunShown: the run list holds a rules file's newest maxChooserRuns runs and, when the run
// shown is older than those (reached by ?run=), that run too, selected: the list never names another run than the one
// the page shows.
func TestRulesPageRunListHoldsTheRunShown(t *testing.T) {
	f := newRulesFix(t)
	t0 := time.Now().Add(-50 * time.Minute).UTC().Truncate(time.Millisecond)
	var newest string
	for i := range maxChooserRuns {
		newest = fmt.Sprintf("r-aaaaaaaa-%013d-later", 100+i)
		f.run(t, newest, f.source, rulesSource, t0.Add(time.Duration(i)*time.Second), false,
			`"kind":"run_end","source":"supervisor","reason":"exit","exit_code":0`)
	}
	code, body := f.get(t, "/rules?run="+rulesRunA)
	if code != http.StatusOK || !strings.Contains(body, "Contract · rules-demo") {
		t.Fatalf("GET ?run= of an older run: %d", code)
	}
	_, list, _ := strings.Cut(body, `<select class="select" name="run">`)
	list, _, _ = strings.Cut(list, "</select>")
	if !strings.Contains(list, `<option value="`+rulesRunA+`" selected`) {
		t.Error("the run shown, older than its file's newest runs, is not the run list's choice")
	}
	if n := strings.Count(list, "<option "); n != maxChooserRuns+1 || !strings.Contains(list, `<option value="`+newest+`"`) ||
		strings.Contains(list, `<option value="`+rulesRunB+`"`) {
		t.Errorf("the run list holds %d runs, want the file's newest %d and the run shown", n, maxChooserRuns)
	}
	if strings.Index(list, newest) > strings.Index(list, rulesRunA) {
		t.Error("the run shown is not in its place by start, after the newer runs")
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

// TestRulesPagePendingDiffers: the rules file was replaced by other text whose time is before both runs started (a
// copy put back with its own time), so no journal line and no later time dates the change, yet the file loads to
// other rules than the runs ran. The running run's panel and the ended run's banner each say the file differs, with
// no change listed and no edit time.
func TestRulesPagePendingDiffers(t *testing.T) {
	f := newRulesFix(t)
	if err := os.WriteFile(f.source, []byte(strings.Replace(rulesSource, "  allow: [sh, git]\n", "  allow: [sh]\n", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour) // the runs started about an hour ago
	if err := os.Chtimes(f.source, old, old); err != nil {
		t.Fatal(err)
	}
	const differs = "The file's rules differ from what this run ran, and nothing dates the change"
	_, body := f.get(t, "/rules?run="+rulesRunB)
	mustContain(t, "the running run's panel", body, "Rules file differs from this run", "the file's rules as they are now",
		differs, "not live on this run", "Stop this run", "run copy line", "the rules file no longer loads to the rules this run ran")
	// Nothing dates a change after the start, so no heading, lede or note may say one happened since.
	for _, not := range []string{"Changed since this run started", "every change below", "changed since the run started"} {
		if strings.Contains(body, not) {
			t.Errorf("the running run's panel shows %q for a difference nothing dates", not)
		}
	}
	_, body = f.get(t, "/rules?run="+rulesRunA)
	mustContain(t, "the ended run's banner", body, "Rules file differs · from the next run", "the file's rules as they are now.",
		differs, "tables show what this run enforces")
	for _, not := range []string{"edited outside Tego", `class="rp-list`, "Not compared", "Saved · from the next run",
		"the rules below changed", "changed since the run started"} {
		if strings.Contains(body, not) {
			t.Errorf("the ended run's banner shows %q for a difference nothing dates", not)
		}
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

// endedRun writes an ended run of the fixture's rules file whose overlay holds a block on curl, added from the
// dashboard (serial 1), and one on /p/data from the terminal (serial 2): tier is its run_start's tier and fields after
// it, and lines its lines between run_start and run_end.
func endedRun(t *testing.T, f *rulesFix, id, tier string, lines ...string) {
	t.Helper()
	f.run(t, id, f.source, rulesSource, time.Now().Add(-40*time.Minute).UTC().Truncate(time.Millisecond), false,
		append(lines, `"kind":"run_end","source":"supervisor","reason":"exit","exit_code":0`)...)
	events := filepath.Join(f.root, id, "events.jsonl")
	b, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(events, bytes.Replace(b, []byte(`"tier":"landlock"`), []byte(`"tier":`+tier), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := liveblock.Update(context.Background(), filepath.Join(f.root, id), id, func(o *liveblock.Overlay) (bool, error) {
		if _, _, err := o.Add(liveblock.KindExec, "/usr/bin/curl", "uid:1000 pid:42 dashboard", time.Now()); err != nil {
			return false, err
		}
		_, ok, err := o.Add(liveblock.KindPath, "/p/data", "uid:1000 pid:43 cli", time.Now())
		return ok, err
	}); err != nil {
		t.Fatal(err)
	}
}

// curlLine is a line under the live block on curl, with verdict v; curlGap is the launcher's line confirming that the
// block (serial 1) is in force.
func curlLine(v string, n int) string {
	return fmt.Sprintf(`"kind":"exec","source":"seccomp","rule":"live.block[exec:/usr/bin/curl]","verdict":"%s","authority":"rule","argv":["curl"],"exec_id":"x/10/%d","path":"/usr/bin/curl"`, v, n)
}

const curlGap = `"kind":"gap","source":"supervisor","what":"enforce","why":"live-block-added","live_block":{"op":"add","kind":"exec","value":"/usr/bin/curl","rule":"live.block[exec:/usr/bin/curl]","by":"uid:1000 pid:42 dashboard","serial":1,"at":"2026-10-25T12:01:10Z"}`

// TestRulesPageEndedLiveBlocks: an ended run's live blocks refuse nothing, so no live table lists them and none offers
// Remove; the note says they refuse nothing now, and a collapsed row under it says what each did while the run ran,
// with who added it and its hits: the block the run put in force "Was blocked", the one it ended before putting in
// force "Never put in force". Nothing says an ended block refuses, or that the second ever did.
func TestRulesPageEndedLiveBlocks(t *testing.T) {
	f := newRulesFix(t)
	const run = "r-aaaaaaaa-0000000000036-endblk"
	endedRun(t, f, run, `"landlock"`, curlGap, curlLine("refused", 2), curlLine("refused", 3))
	_, body := f.get(t, "/rules?run="+run)
	mustContain(t, "the ended run's page", body, "The run has ended, so its 2 live blocks refuse nothing now.",
		`<details class="r-fold rules-ended"><summary>This run's live blocks <span class="soft">(2)</span>`,
		"<span>Was blocked: cannot run /usr/bin/curl</span>", "live, from the dashboard", "2 hits",
		"<span>Never put in force: cannot open or change /p/data</span>", "live, from the cli")
	if i, j := strings.Index(body, "Was blocked: cannot run /usr/bin/curl"), strings.Index(body, "Can change files in ./out/"); i > j {
		t.Error("the ended run's live blocks are listed after the rules file's groups")
	}
	for _, not := range []string{"/unblock", `rules-ended" open`, "Blocked live now", `id="g-live"`, "no longer refuse", "Was blocked: cannot open or change /p/data"} {
		if strings.Contains(body, not) {
			t.Errorf("the ended run's page shows %q", not)
		}
	}
}

// TestRulesPageEndedWatchedMarks: an ended watched run's marks recorded what they named and refused nothing, so the
// page lists them as marks, never as blocks: "Was marked (recorded, not refused)" under "This run's live marks", with
// the hits of the lines they recorded, and the note says they record nothing now. Nothing on the page says one was
// blocked, or that one refused anything.
func TestRulesPageEndedWatchedMarks(t *testing.T) {
	f := newRulesFix(t)
	const run = "r-aaaaaaaa-0000000000037-endmrk"
	endedRun(t, f, run, `"observe","fs_reads":{"reads":"direct","why":"records-only"},"reads_notified":{"notified":false,"why":"records-only"}`,
		curlGap, curlLine("observed", 2), curlLine("observed", 3))
	_, body := f.get(t, "/rules?run="+run)
	mustContain(t, "the ended watched run's page", body, "Watched only · nothing refused",
		"The run has ended, so its 2 live marks record nothing now.",
		`<summary>This run's live marks <span class="soft">(2)</span>`,
		"<span>Was marked (recorded, not refused): cannot run /usr/bin/curl</span>", "2 hits",
		"<span>Was marked (recorded, not refused): cannot open or change /p/data</span>")
	for _, not := range []string{"Was blocked", "Never put in force", "This run's live blocks", "live blocks refuse", "no longer refuse", "/unblock"} {
		if strings.Contains(body, not) {
			t.Errorf("the ended watched run's page says %q", not)
		}
	}
}

// TestRulesPageUnreadableLiveBlocks: a live-blocks file the page cannot read is said in plain words, the file and what
// is wrong with it, never as Go's error.
func TestRulesPageUnreadableLiveBlocks(t *testing.T) {
	f := newRulesFix(t)
	if err := os.WriteFile(filepath.Join(f.root, rulesRunB, liveblock.FileName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, body := f.get(t, "/rules?run="+rulesRunB)
	mustContain(t, "a damaged live-blocks file", body, "The run's live blocks could not be read: live-block.json is damaged, or a newer Tego wrote it.")
	for _, not := range []string{"liveblock:", "invalid character"} {
		if strings.Contains(body, not) {
			t.Errorf("the page words a damaged live-blocks file with %q", not)
		}
	}
}

// TestRulesPageEmptyAndRunLink: an empty ledger says a policy comes from presets or a finished run, with tego learn
// for the terminal (tego init's starter runs python3 agent.py, not the person's agent) written as tego watch's footer
// and the Quickstart write it: into a file under ~/contracts, outside the project, since tego refuses a contract its
// agent could rewrite and --out makes no folder. The run page's "see the rules" opens that run's rules (F9).
func TestRulesPageEmptyAndRunLink(t *testing.T) {
	s := newServer(t, t.TempDir())
	c := login(t, s)
	const learn = "<code>mkdir -p ~/contracts &amp;&amp; tego learn &lt;run&gt; --out ~/contracts/&lt;name&gt;.yaml</code>"
	if b := do(s, "GET", "/rules", "127.0.0.1:8484", c).Body.String(); !strings.Contains(b, "No contracts yet") || !strings.Contains(b, learn) {
		t.Errorf("the empty Rules page does not give %s", learn)
	}
	f := newRulesFix(t)
	if _, body := f.get(t, "/runs/"+rulesRunA); !strings.Contains(body, `href="/rules?run=`+rulesRunA+`"`) {
		t.Error("the run page's rules link does not name the run")
	}
}

// TestRulesNewFromRunSaysAddresses: New policy's From a run says what tego learn proposes for a watched run, the
// addresses it connected to. Its record holds no host name, so "the hosts it reached" promised names the policy does
// not hold, beside the plan's note (learn's address warning) that it has entries that are addresses, not host names.
func TestRulesNewFromRunSaysAddresses(t *testing.T) {
	f := newRulesFix(t)
	f.withSetup(t)
	code, body := f.get(t, "/rules/new?mode=run")
	if code != http.StatusOK || !strings.Contains(body, "the addresses it connected to (tego learn)") || strings.Contains(body, "hosts it reached") {
		t.Errorf("From a run answered %d and does not say it allows the addresses the run connected to:\n%s", code, body)
	}
}
