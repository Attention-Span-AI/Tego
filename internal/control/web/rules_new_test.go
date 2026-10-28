// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/rulefile"
)

var newBase = regexp.MustCompile(`name="base" value="([0-9a-f]{64})"`)
var newRef = regexp.MustCompile(`href="/rules\?c=([0-9a-f]{16})"`)

// withSetup gives the fixture's server the rule service with a compiler that accepts every contract.
func (f *rulesFix) withSetup(t *testing.T) *rules.Service {
	t.Helper()
	rs := &rules.Service{Ledger: f.root, Home: f.home,
		Compile: func(context.Context, rules.CheckContext, []byte) error { return nil }}
	f.s.cfg.Setup = rs
	return rs
}

// TestRulesNewPreviewAndCreate: the form offers the presets; a preview (a GET) shows the rules in sentences and the
// Create form and writes nothing; Create (a POST) writes agent.yaml and answers 303 to the page of the agent set up,
// with the start line, which a reload shows again; the new rules file is then in the Rules chooser as not run yet,
// and its page shows its rules and the start line. A second Create and a stale base go back to the preview with a
// line saying why, a post without the form token is refused, and the file is never overwritten.
func TestRulesNewPreviewAndCreate(t *testing.T) {
	f := newRulesFix(t)
	f.withSetup(t)
	code, body := f.get(t, "/rules")
	if code != http.StatusOK || !strings.Contains(body, `href="/rules/new"`) {
		t.Fatalf("the Rules page has no Set up a new agent: %d", code)
	}
	code, body = f.get(t, "/rules/new")
	if code != http.StatusOK {
		t.Fatalf("GET /rules/new: %d %s", code, body)
	}
	for _, want := range []string{"New policy", `name="preset" value="no-secrets" checked`, `name="preset" value="no-prod" checked`,
		`name="preset" value="repo-only-writes">`, "From a run", `name="dir"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the form lacks %q", want)
		}
	}
	dir := filepath.Join(filepath.Dir(f.proj), "fresh-proj")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	q := url.Values{"dir": {dir}, "preset": {"no-secrets", "no-prod"}, "hosts": {"api.example.com:443"}, "cmd": {"sh"}, "preview": {"1"}}
	code, body = f.get(t, "/rules/new?"+q.Encode())
	if code != http.StatusOK {
		t.Fatalf("preview: %d %s", code, body)
	}
	for _, want := range []string{"Preview: fresh-proj", "Network", "api.example.com:443", "Create agent.yaml", "Never reads your SSH keys (~/.ssh)",
		"cd " + dir + " &amp;&amp; tego run agent.yaml</code>", "extends: [tego/no-secrets, tego/no-prod]"} {
		if !strings.Contains(body, want) {
			t.Errorf("the preview lacks %q", want)
		}
	}
	file := filepath.Join(dir, "agent.yaml")
	if _, err := os.Stat(file); err == nil {
		t.Fatal("a preview wrote the file")
	}
	m := newBase.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no base in the Create form")
	}
	form := url.Values{"dir": {dir}, "name": {"fresh-proj"}, "preset": {"no-secrets", "no-prod"}, "hosts": {"api.example.com:443"},
		"cmd": {"sh"}, "mode": {"presets"}, "base": {m[1]}}
	if w := post(f.s, "/rules/new", form, own, "", f.c); w.Code != http.StatusForbidden {
		t.Fatalf("a post without the form token: %d", w.Code)
	}
	form.Set("csrf", f.s.csrf)
	stale := url.Values{}
	for k, v := range form {
		stale[k] = v
	}
	stale.Set("base", strings.Repeat("0", 64))
	w := post(f.s, "/rules/new", stale, own, "", f.c)
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/rules/new?") || !strings.Contains(loc, "preview=1") {
		t.Errorf("a stale base went to %q", loc)
	}
	if b := follow(t, f.s, f.c, w); !strings.Contains(b, "Not created: the folder or the presets changed") || !strings.Contains(b, "Create agent.yaml") {
		t.Fatalf("a stale base's page:\n%s", b)
	}
	w = post(f.s, "/rules/new", form, own, "", f.c)
	loc := w.Header().Get("Location")
	body = follow(t, f.s, f.c, w)
	if !strings.HasPrefix(loc, "/rules/new?created=") || !strings.Contains(body, "fresh-proj · policy written") || !strings.Contains(body, "Set up fresh-proj: ") ||
		!strings.Contains(body, "cd "+dir+" &amp;&amp; tego run agent.yaml</code>") {
		t.Fatalf("Create went to %q: %s", loc, body)
	}
	if reload, _, _ := strings.Cut(loc, "&flash="); !strings.Contains(do(f.s, "GET", reload, "127.0.0.1:8484", f.c).Body.String(), "fresh-proj · policy written") {
		t.Error("a reload of the created page does not show it")
	}
	ref := newRef.FindStringSubmatch(body)
	if ref == nil {
		t.Fatal("no link to the new rules")
	}
	written, err := os.ReadFile(file)
	if err != nil || !strings.Contains(string(written), "tego/no-prod") {
		t.Fatalf("file = %q, %v", written, err)
	}
	if b := follow(t, f.s, f.c, post(f.s, "/rules/new", form, own, "", f.c)); !strings.Contains(b, "never written over a") {
		t.Fatalf("a second Create:\n%s", b)
	}
	if again, _ := os.ReadFile(file); string(again) != string(written) {
		t.Fatal("the file was overwritten")
	}

	_, body = f.get(t, "/rules")
	if !strings.Contains(body, `<option value="`+ref[1]+`"`) || !strings.Contains(body, "not run yet") {
		t.Fatalf("the chooser does not offer the new rules file")
	}
	code, body = f.get(t, "/rules?c="+ref[1])
	for _, want := range []string{"Policy · fresh-proj", "not run yet", "cd " + dir + " &amp;&amp; tego run agent.yaml", "Network"} {
		if code != http.StatusOK || !strings.Contains(body, want) {
			t.Errorf("the not-run page lacks %q (%d)", want, code)
		}
	}
}

// TestRulesNewStartLineHoldsNoCommand: a command with shell syntax or quotes goes into the contract as sh -c, and the
// start line names no command, so pasting it never runs part of the typed text outside tego or in place of the
// contract's command.
func TestRulesNewStartLineHoldsNoCommand(t *testing.T) {
	f := newRulesFix(t)
	f.withSetup(t)
	dir := filepath.Join(filepath.Dir(f.proj), "shell proj")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	start := regexp.MustCompile(`<div class="cli"><code>([^<]*)</code>`)
	for _, cmd := range []string{"make test && curl x", `npm run "lint fix"`} {
		q := url.Values{"dir": {dir}, "preset": {"no-secrets"}, "cmd": {cmd}, "preview": {"1"}}
		code, body := f.get(t, "/rules/new?"+q.Encode())
		if code != http.StatusOK {
			t.Fatalf("preview %q: %d", cmd, code)
		}
		m := start.FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("preview %q shows no start line", cmd)
		}
		if got, want := html.UnescapeString(m[1]), "cd '"+dir+"' && tego run agent.yaml"; got != want {
			t.Errorf("start line for %q = %q, want %q", cmd, got, want)
		}
		if !strings.Contains(html.UnescapeString(body), "/bin/sh") {
			t.Errorf("the contract for %q does not run it through sh -c", cmd)
		}
	}
}

// TestRulesNewStatesGrantsBesidePresets: "Only hosts I list" stays the label, and once the command's agent adds a host
// nobody listed, the preview says so beside it. A command that adds nothing leaves the label alone.
func TestRulesNewStatesGrantsBesidePresets(t *testing.T) {
	f := newRulesFix(t)
	f.withSetup(t)
	dir := filepath.Join(filepath.Dir(f.proj), "grant-proj")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	q := url.Values{"dir": {dir}, "preset": {"no-prod"}, "cmd": {"claude"}, "preview": {"1"}}
	code, body := f.get(t, "/rules/new?"+q.Encode())
	if code != http.StatusOK {
		t.Fatalf("preview: %d %s", code, body)
	}
	const want = `<strong>Only hosts I list</strong><span class="soft ut" title="What the command's agent needs to run">Also api.anthropic.com:443</span>`
	if !strings.Contains(body, want) {
		t.Errorf("the label does not state the grant:\n%s", body)
	}
	q.Set("cmd", "sh")
	if _, body = f.get(t, "/rules/new?"+q.Encode()); strings.Contains(body, ">Also ") {
		t.Errorf("a command that needs nothing got a grant beside the label:\n%s", body)
	}
}

// TestRulesNewProblems: a folder that is not one the service writes in is said as a problem, with no Create form.
func TestRulesNewProblems(t *testing.T) {
	f := newRulesFix(t)
	f.withSetup(t)
	for _, tc := range []struct{ dir, want string }{
		{"relative/path", "full path"},
		{filepath.Join(f.root), "tego&#39;s own folder"},
		{filepath.Join(f.proj, "nope"), "does not exist"},
	} {
		_, body := f.get(t, "/rules/new?"+url.Values{"dir": {tc.dir}, "preset": {"no-secrets"}}.Encode())
		if !strings.Contains(body, tc.want) || strings.Contains(body, "Create agent.yaml") {
			t.Errorf("dir %q: want %q and no Create form", tc.dir, tc.want)
		}
	}
	// A folder that already holds agent.yaml.
	_, body := f.get(t, "/rules/new?"+url.Values{"dir": {f.proj}, "preset": {"no-secrets"}}.Encode())
	if !strings.Contains(body, "already holds agent.yaml") || strings.Contains(body, "Create agent.yaml") {
		t.Error("a folder with agent.yaml offers Create")
	}
}

// TestRulesNewNotRunHidesEnv: a rules file set up here and not run yet shows no env.set value on the Rules page.
func TestRulesNewNotRunHidesEnv(t *testing.T) {
	f := newRulesFix(t)
	f.withSetup(t)
	dir := filepath.Join(filepath.Dir(f.proj), "canary-proj")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	g := rulefile.DefaultGuard(f.root)
	if _, err := rulefile.Create(context.Background(), g, filepath.Join(dir, "agent.yaml"), []byte(rulesSource), rulefile.Change{Via: "dashboard"}); err != nil {
		t.Fatal(err)
	}
	_, body := f.get(t, "/rules")
	ref := regexp.MustCompile(`<option value="([0-9a-f]{16})"`).FindStringSubmatch(body)
	if ref == nil {
		t.Fatal("the chooser does not offer the set-up file")
	}
	code, body := f.get(t, "/rules?c="+ref[1])
	if code != http.StatusOK || !strings.Contains(body, "Policy · rules-demo") {
		t.Fatalf("not-run page: %d", code)
	}
	if strings.Contains(body, rulesCanary) || strings.Contains(html.UnescapeString(body), rulesCanary) {
		t.Fatal("an env.set value reached the page")
	}
}

// TestRulesNewOff: without the rule service the page says so and the Rules page offers no setup.
func TestRulesNewOff(t *testing.T) {
	f := newRulesFix(t)
	code, body := f.get(t, "/rules/new")
	if code != http.StatusOK || !strings.Contains(body, "Not available here") {
		t.Fatalf("GET /rules/new without a service: %d", code)
	}
	if _, body := f.get(t, "/rules"); strings.Contains(body, `href="/rules/new"`) {
		t.Error("the Rules page offers setup without a service")
	}
	form := url.Values{"csrf": {f.s.csrf}, "dir": {f.proj}}
	if b := follow(t, f.s, f.c, post(f.s, "/rules/new", form, own, "", f.c)); !strings.Contains(b, "Not created · policy editing is off") {
		t.Errorf("POST without a service:\n%s", b)
	}
}

// TestRulesNewAskReadNote: the form says Ask before reading runs the whole policy at Basic, and a preview that uses it
// says so in a banner, or that Adjustable blocks these reads without asking; a preview without it has no banner.
func TestRulesNewAskReadNote(t *testing.T) {
	f := newRulesFix(t)
	f.withSetup(t)
	if _, body := f.get(t, "/rules/new"); !strings.Contains(body, "Ask before reading runs the whole policy at Basic") {
		t.Error("the form lacks the note")
	}
	dir := filepath.Join(filepath.Dir(f.proj), "ask-proj")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	preview := func(extra url.Values) string {
		t.Helper()
		q := url.Values{"dir": {dir}, "preset": {"no-secrets"}, "cmd": {"sh"}, "preview": {"1"}}
		for k, v := range extra {
			q[k] = v
		}
		code, body := f.get(t, "/rules/new?"+q.Encode())
		if code != http.StatusOK {
			t.Fatalf("preview: %d %s", code, body)
		}
		return html.UnescapeString(body)
	}
	const basic = "Ask before reading runs this whole policy at Basic protection"
	const adjustable = "these reads are blocked without asking you"
	if b := preview(nil); strings.Contains(b, basic) || strings.Contains(b, adjustable) {
		t.Error("a preview with no Ask before reading has the banner")
	}
	if b := preview(url.Values{"askread": {"./notes/"}}); !strings.Contains(b, basic) {
		t.Errorf("the preview lacks the Basic banner:\n%s", b)
	}
	if b := preview(url.Values{"askread": {"./notes/"}, "live": {"adjustable"}}); !strings.Contains(b, adjustable) {
		t.Errorf("the Adjustable preview lacks its banner:\n%s", b)
	}
}
