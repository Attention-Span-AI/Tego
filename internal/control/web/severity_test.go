// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// TestSeverityPage: a rule added on the Severity page is saved to the person's file (owner-only), applies to
// Detections at once, leaves a secret High, and Remove takes it back out. The page says where the rules live.
func TestSeverityPage(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000007-sevpag"
	file := filepath.Join(t.TempDir(), "tego", "severity.json")
	lines := [][2]string{{"refused", `"rule":"fs.deny_read[/w/home/.ssh/]","reason":"read-denied","op":"open","target":"/w/home/.ssh/id_rsa"`}}
	for range ledgerview.NearSecretLines + 1 { // far enough that the connect is not a send after the secret read
		lines = append(lines, [2]string{"fs", `"rule":"fs.read[./]","verdict":"allow","op":"open","path":"/w/proj/main.go"`})
	}
	lines = append(lines, [2]string{"refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"203.0.113.9:443"`})
	s := newServer(t, detectionsRoot(t, run, "landlock", lines...))
	s.cfg.SeverityFile = file
	c := login(t, s)
	if b := get(t, s, c, "/detections"); strings.Count(b, `<td><span class="sev sev-High">`) != 2 {
		t.Fatalf("before any rule, not two High rows:\n%s", b)
	}
	page := get(t, s, c, "/severity")
	if !strings.Contains(page, "not part of the record") || !strings.Contains(page, file) || !strings.Contains(page, `placeholder="/prod-config/"`) {
		t.Errorf("the page does not say where the rules live, or suggests a form that never matches:\n%s", page)
	}
	csrf := csrfOf(t, s, c, "/severity")
	w := post(s, "/severity/add", url.Values{"csrf": {csrf}, "channel": {""}, "match": {"/"}, "severity": {"Low"}},
		"http://127.0.0.1:8484", "", c)
	if w.Code >= 400 {
		t.Fatalf("add: %d %s", w.Code, w.Body)
	}
	if w := post(s, "/severity/add", url.Values{"csrf": {csrf}, "channel": {"Network"}, "match": {"203.0.113"}, "severity": {"Medium"}},
		"http://127.0.0.1:8484", "", c); w.Code >= 400 {
		t.Fatalf("add: %d %s", w.Code, w.Body)
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the rules file: %v %v", info, err)
	}
	after := get(t, s, c, "/detections")
	if strings.Count(after, `<td><span class="sev sev-High">`) != 1 || strings.Count(after, `<td><span class="sev sev-Medium">`) != 1 {
		t.Errorf("want the secret still High and the connect Medium:\n%s", after)
	}
	for _, r := range [][3]string{{"Network", "203.0.113", "Medium"}, {"", "/", "Low"}} {
		f := url.Values{"csrf": {csrf}, "channel": {r[0]}, "match": {r[1]}, "severity": {r[2]}}
		if w := post(s, "/severity/remove", f, "http://127.0.0.1:8484", "", c); w.Code >= 400 {
			t.Fatalf("remove: %d", w.Code)
		}
	}
	if len(s.severityRules()) != 0 {
		t.Error("Remove left a rule in force")
	}
}

// TestSeverityRemoveNamesTheRule: Remove takes out the rule its form names, whatever a second tab did to the list since
// that form was drawn. By place it took out the neighbour, and a stale form for a rule already gone took out another.
func TestSeverityRemoveNamesTheRule(t *testing.T) {
	file := filepath.Join(t.TempDir(), "severity.json")
	s := newServer(t, fixture(t))
	s.cfg.SeverityFile = file
	c := login(t, s)
	csrf := csrfOf(t, s, c, "/severity")
	const origin = "http://127.0.0.1:8484"
	add := func(match, sev string) {
		t.Helper()
		post(s, "/severity/add", url.Values{"csrf": {csrf}, "match": {match}, "severity": {sev}}, origin, "", c)
	}
	add("/keep/", "Low")
	add("/target/", "High")
	// The first tab's page, with the form for /target/ and the form for /keep/.
	page := get(t, s, c, "/severity")
	if !strings.Contains(page, `name="match" value="/target/"`) || !strings.Contains(page, `name="severity" value="High"`) {
		t.Fatalf("the Remove form does not name its rule:\n%s", page)
	}
	target := url.Values{"csrf": {csrf}, "channel": {""}, "match": {"/target/"}, "severity": {"High"}}
	// A second tab adds a rule in front of both.
	add("/new/", "Medium")
	post(s, "/severity/remove", target, origin, "", c)
	got := func() []string {
		var out []string
		for _, r := range s.severityRules() {
			out = append(out, r.Match)
		}
		return out
	}
	if m := got(); len(m) != 2 || m[0] != "/new/" || m[1] != "/keep/" {
		t.Fatalf("after Remove of /target/: %v", m)
	}
	// The same form again, for a rule that is gone: nothing else goes with it.
	post(s, "/severity/remove", target, origin, "", c)
	if m := got(); len(m) != 2 {
		t.Errorf("a stale form took out another rule: %v", m)
	}
	// A rule of the same match at another severity is another rule.
	stale := url.Values{"csrf": {csrf}, "channel": {""}, "match": {"/keep/"}, "severity": {"High"}}
	post(s, "/severity/remove", stale, origin, "", c)
	if m := got(); len(m) != 2 {
		t.Errorf("a form for /keep/ at High took out /keep/ at Low: %v", m)
	}
}

// TestSeverityRuleTakesAHomePath: a path typed with ~ matches, as rules read absolute paths.
func TestSeverityRuleTakesAHomePath(t *testing.T) {
	file := filepath.Join(t.TempDir(), "severity.json")
	s := newServer(t, fixture(t))
	s.cfg.SeverityFile = file
	c := login(t, s)
	csrf := csrfOf(t, s, c, "/severity")
	post(s, "/severity/add", url.Values{"csrf": {csrf}, "match": {"~/work/prod-config/"}, "severity": {"High"}}, "http://127.0.0.1:8484", "", c)
	if rs := s.severityRules(); len(rs) != 1 || rs[0].Match != "/work/prod-config/" {
		t.Errorf("rules %+v", rs)
	}
}

// TestCorruptSeverityFile: a file the dashboard cannot read does not stop it. The pages say so in plain words and run on
// the built-in rules, a change is refused rather than written over the file, and a fixed file counts with no restart.
func TestCorruptSeverityFile(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000008-corrup"
	root := detectionsRoot(t, run, "landlock",
		[2]string{"refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"203.0.113.9:443"`})
	file := filepath.Join(t.TempDir(), "severity.json")
	if err := os.WriteFile(file, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Ledger: root, SeverityFile: file}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("a corrupt rules file stopped the dashboard: %v", err)
	}
	if srv.severityNote() == "" || len(srv.severityRules()) != 0 {
		t.Errorf("note %q, rules %+v", srv.severityNote(), srv.severityRules())
	}

	s := newServer(t, root)
	s.cfg.SeverityFile = file
	s.loadSeverity()
	c := login(t, s)
	const note = "built-in rules in use"
	for _, p := range []string{"/severity", "/detections"} {
		if b := get(t, s, c, p); !strings.Contains(b, note) {
			t.Errorf("%s lacks the notice:\n%s", p, b)
		}
	}
	if b := get(t, s, c, "/detections"); !strings.Contains(b, `<td><span class="sev sev-High">`) {
		t.Error("the built-in rules are not in force")
	}
	csrf := csrfOf(t, s, c, "/severity")
	post(s, "/severity/add", url.Values{"csrf": {csrf}, "match": {"x"}, "severity": {"Low"}}, "http://127.0.0.1:8484", "", c)
	if b, _ := os.ReadFile(file); string(b) != "{not json" {
		t.Errorf("a change was written over the file: %s", b)
	}
	if err := os.WriteFile(file, []byte(`[{"match":"203.0.113","severity":"Low"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if b := get(t, s, c, "/severity"); strings.Contains(b, note) {
		t.Error("the notice stays after the file was fixed")
	}
	if b := get(t, s, c, "/detections"); !strings.Contains(b, `class="sev sev-Low"`) {
		t.Error("the fixed file's rule is not in force")
	}
}

// TestSeverityFilePipe: a named pipe at the rules file's path does not hold the dashboard's start: it is a file that
// cannot be read, with the notice that says so.
func TestSeverityFilePipe(t *testing.T) {
	root := detectionsRoot(t, "r-aaaaaaaa-0000000000017-sevfif", "landlock")
	file := filepath.Join(t.TempDir(), "severity.json")
	if err := syscall.Mkfifo(file, 0o600); err != nil {
		t.Fatal(err)
	}
	type result struct {
		s   *Server
		err error
	}
	done := make(chan result, 1)
	go func() {
		s, err := New(Config{Ledger: root, SeverityFile: file})
		done <- result{s, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("a pipe stopped the dashboard: %v", r.err)
		}
		if r.s.severityNote() == "" {
			t.Error("no notice for a pipe at the rules file")
		}
	case <-time.After(5 * time.Second):
		t.Error("New is still waiting on a pipe at the rules file")
		// The writer's open releases New, which then reads end of file.
		if f, err := os.OpenFile(file, os.O_WRONLY, 0); err == nil {
			_ = f.Close()
		}
		<-done
	}
}

// severityFileOf writes n rules to a new rules file, each with its own match.
func severityFileOf(t *testing.T, n int) string {
	t.Helper()
	rs := make([]sevFileRule, n)
	for i := range rs {
		rs[i] = sevFileRule{Match: fmt.Sprintf("/some/path/number/%d/", i), Severity: "Medium"}
	}
	b, err := json.Marshal(rs)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "severity.json")
	if err := os.WriteFile(file, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return file
}

// TestOversizeSeverityFile: a rules file past maxSeverityFile is a file that cannot be read: the built-in rules apply,
// the pages say so and nothing is written over it. A file of 20,000 rules held Detections for 30 s, with no notice.
func TestOversizeSeverityFile(t *testing.T) {
	const run = "r-aaaaaaaa-0000000000018-sevbig"
	root := detectionsRoot(t, run, "landlock",
		[2]string{"refused", `"rule":"unmatched","reason":"net-not-allowed","op":"net","target":"203.0.113.9:443"`})
	file := severityFileOf(t, 20_000)
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) <= maxSeverityFile {
		t.Fatalf("the file is %d bytes, not over the limit of %d", len(before), maxSeverityFile)
	}
	s := newServer(t, root)
	s.cfg.SeverityFile = file
	s.loadSeverity()
	if s.severityNote() == "" || len(s.severityRules()) != 0 {
		t.Fatalf("note %q, %d rules in force", s.severityNote(), len(s.severityRules()))
	}
	c := login(t, s)
	for _, p := range []string{"/severity", "/detections"} {
		if b := get(t, s, c, p); !strings.Contains(b, "built-in rules in use") {
			t.Errorf("%s lacks the notice:\n%s", p, b)
		}
	}
	csrf := csrfOf(t, s, c, "/severity")
	post(s, "/severity/add", url.Values{"csrf": {csrf}, "match": {"x"}, "severity": {"Low"}}, "http://127.0.0.1:8484", "", c)
	if after, _ := os.ReadFile(file); string(after) != string(before) {
		t.Error("a change was written over the file")
	}
}

// TestSeverityRuleTooMany: the rule that would take the file past what the dashboard reads is not saved, and the rules
// already there stay in force. Saved, it would have turned all of them off.
func TestSeverityRuleTooMany(t *testing.T) {
	file := severityFileOf(t, 1)
	s := newServer(t, fixture(t))
	s.cfg.SeverityFile = file
	s.loadSeverity()
	rs := make([]ledgerview.SevRule, 0, 2_000)
	for i := range cap(rs) {
		rs = append(rs, ledgerview.SevRule{Match: fmt.Sprintf("/%d/", i), Severity: ledgerview.SevMedium})
	}
	if err := writeSeverityFile(file, rs); err == nil {
		t.Fatalf("%d rules were written", len(rs))
	}
	if err := writeSeverityFile(file, rs[:500]); err != nil {
		t.Fatalf("500 rules: %v", err)
	}
	s.loadSeverity()
	if s.severityNote() != "" || len(s.severityRules()) != 500 {
		t.Errorf("note %q, %d rules in force, want 500", s.severityNote(), len(s.severityRules()))
	}
}
