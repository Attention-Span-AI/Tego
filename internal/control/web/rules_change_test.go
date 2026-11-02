// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
	"github.com/attention-span-ai/tego/internal/rulefile"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// changeFix is the Rules page fixture served with the real rule service, which compiles each change as tego does.
type changeFix struct {
	*rulesFix
	svc *rules.Service
}

func newChangeFix(t *testing.T) *changeFix {
	t.Helper()
	f := newRulesFix(t)
	if err := os.MkdirAll(filepath.Join(f.proj, "more"), 0o755); err != nil {
		t.Fatal(err)
	}
	m := &config.Machine{Home: f.home}
	svc := &rules.Service{Ledger: f.root, Home: f.home, Machine: m,
		Now: func() time.Time { return time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC) }}
	s, err := New(Config{Ledger: f.root, Port: port, Token: "tok123", Machine: m, Rules: svc})
	if err != nil {
		t.Fatal(err)
	}
	trustPeer(s)
	f.s, f.c = s, login(t, s)
	return &changeFix{rulesFix: f, svc: svc}
}

// ref is the service's ref of the rules file at path.
func (f *changeFix) ref(t *testing.T, path string) rules.ContractRef {
	t.Helper()
	cs, err := f.svc.Contracts()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cs {
		if c.Path == path {
			return c
		}
	}
	t.Fatalf("no contract %s in %+v", path, cs)
	return rules.ContractRef{}
}

func (f *changeFix) post(t *testing.T, target string, form url.Values) (int, string) {
	t.Helper()
	form.Set("csrf", f.s.csrf)
	w := post(f.s, target, form, own, "", f.c)
	return w.Code, w.Body.String()
}

// save posts an action and follows its 303 (a line in a flash), returning where it went and that page.
func (f *changeFix) save(t *testing.T, target string, form url.Values) (string, string) {
	t.Helper()
	form.Set("csrf", f.s.csrf)
	w := post(f.s, target, form, own, "", f.c)
	return w.Header().Get("Location"), follow(t, f.s, f.c, w)
}

func readText(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// journalLen is how many entries the ledger root's change journal holds.
func journalLen(t *testing.T, root string) int {
	t.Helper()
	es, err := rulefile.ReadJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	return len(es)
}

// TestChangeGroupsCoverEditKeys: the form has one panel for every list a change may touch, and no other.
func TestChangeGroupsCoverEditKeys(t *testing.T) {
	var keys []string
	for _, g := range changeGroups {
		keys = append(keys, g.Key)
		if g.Hint == "" || g.Example == "" || g.Title == "" {
			t.Errorf("%s lacks a title, hint or example", g.Key)
		}
	}
	slices.Sort(keys)
	want := rules.EditKeys()
	slices.Sort(want)
	if !slices.Equal(keys, want) {
		t.Errorf("panels %v, edit keys %v", keys, want)
	}
}

// TestRulesChangeForm: an old link's ref (the sha256 of the recorded path, which the Rules page named a file by
// before) redirects to the service's; the form has a panel per list with Remove on each entry the file spells and Add
// with its hint, every form a GET to the preview carrying the ref and base; a file that sets env values offers the
// YAML editor with every value hidden and never shows one; another file's editor holds its text.
func TestRulesChangeForm(t *testing.T) {
	f := newChangeFix(t)
	w := do(f.s, "GET", "/rules/change?c="+legacyRef(f.source), "127.0.0.1:8484", f.c)
	ref := f.ref(t, f.source)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/rules/change?c="+ref.Ref {
		t.Fatalf("the Rules page's ref: %d %q", w.Code, w.Header().Get("Location"))
	}
	code, body := f.get(t, "/rules/change?c="+ref.Ref)
	if code != http.StatusOK {
		t.Fatalf("GET: %d %s", code, body)
	}
	for _, want := range []string{
		"Change rules for rules-demo", "Programs it may run", "Can change", "Can never read", "Asks you before it reads",
		`<span class="mono rc-entry" title="git">git</span>`, `name="op" value="remove"`, `name="key" value="exec.allow"`, `name="v" value="git"`,
		`name="base" value="` + ref.Base + `"`, `name="c" value="` + ref.Ref + `"`, `action="/rules/change/preview"`,
		html.EscapeString("git, /usr/bin/git, or git status"), `placeholder="e.g. ./out/"`, "History", "No changes yet",
		"Advanced: edit YAML", "DEMO_TOKEN: " + rulesview.Hidden, "saving puts each back", `name="text"`, "/static/rules-change.css",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the form lacks %q", want)
		}
	}
	if strings.Contains(body, rulesCanary) {
		t.Error("a file with env values shows a value")
	}
	// The lists and the history are a live region; the YAML editor is outside it, so a live update never touches
	// what someone types there.
	if !strings.Contains(body, `data-live="r-change"`) || !strings.Contains(body, "data-sig=") {
		t.Error("the form is not a live page with its lists in a live region")
	}
	if w := doRegions(f.s, "/rules/change?c="+ref.Ref, "127.0.0.1:8484", f.c, "r-change:x"); !strings.Contains(w.Body.String(), `<span class="mono rc-entry" title="git">git</span>`) ||
		strings.Contains(w.Body.String(), `name="text"`) {
		t.Errorf("the r-change region lacks the lists or holds the YAML editor: %s", w.Body.String())
	}
	other := f.ref(t, f.other)
	_, body = f.get(t, "/rules/change?c="+other.Ref+"&raw=1")
	if !strings.Contains(body, `<textarea class="input mono rc-text" id="yaml-text" name="text"`) || !strings.Contains(body, "name: other-agent") ||
		!strings.Contains(body, `rc-raw" id="yaml" open`) {
		t.Error("the YAML editor is not open with the file's text")
	}
	for _, target := range []string{"/rules/change?c=feedfeedfeedfeed", "/rules/change?c=" + url.QueryEscape("../../etc/passwd"),
		"/rules/change?c=" + url.QueryEscape(f.source)} {
		if code, _ := f.get(t, target); code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", target, code)
		}
	}
	if code, body := f.get(t, "/rules/change"); code != http.StatusOK || !strings.Contains(body, "Pick a policy file") {
		t.Errorf("the chooser: %d", code)
	}
}

// TestChangePageLinksBackToItsRules: Change rules links back to the Rules page by the file's ref, the one the Rules
// page names it by, both for a file runs ran and for one set up here that no run ran yet, whose Rules page that link
// missed (404) while the two pages named a file by two refs.
func TestChangePageLinksBackToItsRules(t *testing.T) {
	f := newChangeFix(t)
	f.withSetup(t)
	dir := filepath.Join(filepath.Dir(f.proj), "fresh")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := rulefile.Create(context.Background(), rulefile.DefaultGuard(f.root), filepath.Join(dir, "agent.yaml"),
		[]byte(strings.Replace(rulesSource, "name: rules-demo", "name: fresh-agent", 1)), rulefile.Change{Via: "dashboard"}); err != nil {
		t.Fatal(err)
	}
	cs, err := f.svc.Contracts()
	if err != nil {
		t.Fatal(err)
	}
	fresh := slices.IndexFunc(cs, func(c rules.ContractRef) bool { return c.Runs == 0 })
	if fresh < 0 {
		t.Fatalf("the service lists no file set up here: %+v", cs)
	}
	for _, c := range []rules.ContractRef{f.ref(t, f.source), cs[fresh]} {
		code, form := f.get(t, "/rules/change?c="+c.Ref)
		if back := `href="/rules?c=` + c.Ref + `"`; code != http.StatusOK || !strings.Contains(form, back) {
			t.Errorf("%s: Change rules (%d) does not link back to its Rules page by %s", c.Path, code, back)
		}
		want := "Policy · rules-demo"
		if c.Runs == 0 {
			want = "Policy · fresh-agent"
		}
		if code, page := f.get(t, "/rules?c="+c.Ref); code != http.StatusOK || !strings.Contains(page, want) {
			t.Errorf("%s: its Rules page answered %d, want %q", c.Path, code, want)
		}
	}
}

// TestPreviewWritesNothing: the preview of a narrowing says it in sentences with the badge and "Applies from the next
// run", and a widening shows the amber box with a required checkbox and a button that is not primary; neither writes
// the file or the journal.
func TestPreviewWritesNothing(t *testing.T) {
	f := newChangeFix(t)
	ref := f.ref(t, f.source)
	before := readText(t, f.source)
	q := url.Values{"c": {ref.Ref}, "base": {ref.Base}, "op": {"remove"}, "key": {"exec.allow"}, "v": {"git"}}
	code, body := f.get(t, "/rules/change/preview?"+q.Encode())
	if code != http.StatusOK {
		t.Fatalf("preview: %d %s", code, body)
	}
	for _, want := range []string{"Check the change", "Narrows", "From the next run", "May run git", "Cannot run git",
		`action="/rules/change"`, `name="base" value="` + ref.Base + `"`, `name="csrf" value="` + f.s.csrf + `"`, "btn btn-primary",
		"The change in the YAML", "tego compile " + f.source, "exec.allow"} {
		if !strings.Contains(body, want) {
			t.Errorf("the narrowing's preview lacks %q", want)
		}
	}
	if strings.Contains(body, `name="ack"`) || strings.Contains(body, rulesCanary) {
		t.Error("a narrowing asks for the acknowledgement, or the diff shows an env value")
	}
	q = url.Values{"c": {ref.Ref}, "base": {ref.Base}, "op": {"add"}, "key": {"fs.write"}, "v": {"./more/"}}
	_, body = f.get(t, "/rules/change/preview?"+q.Encode())
	for _, want := range []string{"Widens", "This lets the agent do more", "Next run can: ",
		`<input type="checkbox" name="ack" value="`, "Save the wider rules"} {
		if !strings.Contains(body, want) {
			t.Errorf("the widening's preview lacks %q", want)
		}
	}
	if strings.Contains(body, "btn btn-primary") {
		t.Error("the widening's save is a primary button")
	}
	for _, bad := range []url.Values{{"c": {ref.Ref}, "op": {"chmod"}, "key": {"exec.allow"}, "v": {"x"}},
		{"c": {ref.Ref}, "op": {"add"}, "key": {"limits.pids"}, "v": {"9"}}, {"c": {ref.Ref}, "op": {"add"}, "key": {"fs.write"}}} {
		if code, _ := f.get(t, "/rules/change/preview?"+bad.Encode()); code != http.StatusBadRequest {
			t.Errorf("preview %v: %d, want 400", bad, code)
		}
	}
	if readText(t, f.source) != before || journalLen(t, f.root) != 0 {
		t.Error("a preview wrote the file or the journal")
	}
}

// TestRulesChangeRefusesCrossSite: a change or an undo without the token, with a stale one, from another origin or
// site, to another Host, without the cookie or as JSON is refused before any handler runs; the file and the journal
// are unchanged.
func TestRulesChangeRefusesCrossSite(t *testing.T) {
	f := newChangeFix(t)
	ref := f.ref(t, f.source)
	before := readText(t, f.source)
	form := func(tok string) url.Values {
		return url.Values{"csrf": {tok}, "c": {ref.Ref}, "base": {ref.Base}, "op": {"remove"}, "key": {"exec.allow"}, "v": {"git"}, "id": {"x"}}
	}
	send := func(target, host, ct, body string, hdr map[string]string, cookie bool) int {
		r := httptest.NewRequest("POST", target, strings.NewReader(body))
		r.Host = host
		r.Header.Set("Content-Type", ct)
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		if cookie {
			r.AddCookie(f.c)
		}
		w := httptest.NewRecorder()
		f.s.ServeHTTP(w, r)
		return w.Code
	}
	const formCT = "application/x-www-form-urlencoded"
	for _, target := range []string{"/rules/change", "/rules/revert"} {
		for name, c := range map[string]struct {
			got, want int
		}{
			"no csrf":            {send(target, "127.0.0.1:8484", formCT, form("").Encode(), map[string]string{"Origin": own}, true), 403},
			"stale csrf":         {send(target, "127.0.0.1:8484", formCT, form(strings.Repeat("0", 64)).Encode(), map[string]string{"Origin": own}, true), 403},
			"evil Origin":        {send(target, "127.0.0.1:8484", formCT, form(f.s.csrf).Encode(), map[string]string{"Origin": "http://evil.example"}, true), 403},
			"cross-site fetch":   {send(target, "127.0.0.1:8484", formCT, form(f.s.csrf).Encode(), map[string]string{"Origin": own, "Sec-Fetch-Site": "cross-site"}, true), 403},
			"same-site fetch":    {send(target, "127.0.0.1:8484", formCT, form(f.s.csrf).Encode(), map[string]string{"Origin": own, "Sec-Fetch-Site": "same-site"}, true), 403},
			"no Origin, Referer": {send(target, "127.0.0.1:8484", formCT, form(f.s.csrf).Encode(), nil, true), 403},
			"wrong Host":         {send(target, "evil.example:8484", formCT, form(f.s.csrf).Encode(), map[string]string{"Origin": "http://evil.example:8484"}, true), 421},
			"no cookie":          {send(target, "127.0.0.1:8484", formCT, form(f.s.csrf).Encode(), map[string]string{"Origin": own}, false), 401},
			"JSON body":          {send(target, "127.0.0.1:8484", "application/json", `{"csrf":"`+f.s.csrf+`","op":"remove"}`, map[string]string{"Origin": own}, true), 415},
		} {
			if c.got != c.want {
				t.Errorf("POST %s with %s: %d, want %d", target, name, c.got, c.want)
			}
		}
	}
	if readText(t, f.source) != before || journalLen(t, f.root) != 0 {
		t.Error("a refused POST wrote the file or the journal")
	}
}

// TestRulesChangeSaveAndUndo: a narrowing saved answers 303 to the Saved page with its line, its sentence, the .bak
// and Undo, which a reload shows again; the file and the journal have it. Undo needs the acknowledgement (it widens),
// then gives the file its exact old text back. A confirm on a stale base writes nothing and goes back to the change
// on the file now, with a line saying why.
func TestRulesChangeSaveAndUndo(t *testing.T) {
	f := newChangeFix(t)
	ref := f.ref(t, f.source)
	before := readText(t, f.source)
	loc, body := f.save(t, "/rules/change", url.Values{"c": {ref.Ref}, "base": {ref.Base}, "op": {"remove"}, "key": {"exec.allow"}, "v": {"git"}})
	if !strings.HasPrefix(loc, "/rules/change/saved?c="+ref.Ref+"&id=") {
		t.Fatalf("save went to %q", loc)
	}
	if reload, _, _ := strings.Cut(loc, "&flash="); !strings.Contains(do(f.s, "GET", reload, "127.0.0.1:8484", f.c).Body.String(), "Saved · applies from the next run") {
		t.Error("a reload of the Saved page does not show it")
	}
	for _, want := range []string{"Saved: ", "Saved · applies from the next run", "May run git", "Narrows", ".bak", `action="/rules/revert"`,
		"Undo this change", `<input type="checkbox" name="ack" value="`, "History"} {
		if !strings.Contains(body, html.EscapeString(want)) && !strings.Contains(body, want) {
			t.Errorf("the Saved page lacks %q", want)
		}
	}
	if strings.Contains(body, rulesCanary) {
		t.Error("the Saved page shows an env value")
	}
	after := readText(t, f.source)
	if after == before || strings.Contains(after, "git]") || journalLen(t, f.root) != 1 {
		t.Fatalf("the file or the journal lacks the change:\n%s", after)
	}
	id := regexp.MustCompile(`name="id" value="([^"]+)"`).FindStringSubmatch(body)
	base := regexp.MustCompile(`action="/rules/revert"[^>]*>(?:<[^>]+>)*?<input type="hidden" name="base" value="([0-9a-f]+)"`).FindStringSubmatch(body)
	if id == nil || base == nil {
		t.Fatalf("no Undo id or base on the Saved page")
	}
	undo := url.Values{"c": {ref.Ref}, "id": {id[1]}, "base": {base[1]}}
	if _, body := f.save(t, "/rules/revert", undo); !strings.Contains(body, "Next run may do more") {
		t.Error("Undo without the acknowledgement does not ask for it")
	}
	if readText(t, f.source) != after {
		t.Fatal("an unacknowledged Undo wrote the file")
	}
	undo.Set("ack", ackIn(t, body))
	loc, body = f.save(t, "/rules/revert", undo)
	if !strings.HasPrefix(loc, "/rules/change/saved?") || !strings.Contains(body, "Undone") {
		t.Fatalf("Undo went to %q: %s", loc, body)
	}
	// The history says the undo as what it undid, never as the journal's "undid rc-…: <summary>".
	if !strings.Contains(body, "Undid: ") || strings.Contains(body, "undid rc-") || strings.Contains(body, "Undo:</span>") {
		t.Errorf("the history does not say the undo in words:\n%s", body)
	}
	if readText(t, f.source) != before {
		t.Error("Undo did not give the file its old text back")
	}
	// The form's base is the text before the undo: stale now.
	loc, body = f.save(t, "/rules/change", url.Values{"c": {ref.Ref}, "base": {strings.Repeat("ab", 32)}, "op": {"remove"}, "key": {"exec.allow"}, "v": {"git"}})
	if !strings.HasPrefix(loc, "/rules/change/preview?") || !strings.Contains(body, "changed since you looked") || !strings.Contains(body, `name="base" value="`+ref.Base+`"`) {
		t.Errorf("a stale confirm went to %q, or the page lacks the line or the new base", loc)
	}
	if readText(t, f.source) != before {
		t.Error("a stale confirm wrote the file")
	}
}

// TestRulesChangeWidenNeedsAck: a widening confirmed without the acknowledgement writes nothing and asks for it; with
// it, the file is written.
func TestRulesChangeWidenNeedsAck(t *testing.T) {
	f := newChangeFix(t)
	ref := f.ref(t, f.source)
	before := readText(t, f.source)
	widen := url.Values{"c": {ref.Ref}, "base": {ref.Base}, "op": {"add"}, "key": {"fs.write"}, "v": {"./more/"}}
	widen.Set("ackwiden", "1") // the old boolean is no acknowledgement
	_, body := f.save(t, "/rules/change", widen)
	if !strings.Contains(body, "Next run may do more") || !strings.Contains(body, `<input type="checkbox" name="ack" value="`) {
		t.Error("a widening without the acknowledgement does not ask for it on its preview")
	}
	if readText(t, f.source) != before {
		t.Fatal("an unacknowledged widening wrote the file")
	}
	// The Ack of another preview (a narrower entry) on this widening: nothing is written.
	q := url.Values{"c": {ref.Ref}, "base": {ref.Base}, "op": {"add"}, "key": {"fs.write"}, "v": {"./more/x"}}
	_, narrower := f.get(t, "/rules/change/preview?"+q.Encode())
	widen.Set("ack", ackIn(t, narrower))
	if _, b := f.save(t, "/rules/change", widen); !strings.Contains(b, "the preview changed") || readText(t, f.source) != before {
		t.Fatal("a widening confirmed with another preview's Ack wrote, or did not say why not")
	}
	widen.Set("ack", ackIn(t, body))
	if _, body := f.save(t, "/rules/change", widen); !strings.Contains(body, "Widens") {
		t.Fatalf("an acknowledged widening: %s", body)
	}
	if !strings.Contains(readText(t, f.source), "./more/") {
		t.Error("the acknowledged widening is not in the file")
	}
}

// TestRawEditor: Check compiles the posted text and shows the diagnostics with their lines, or the diff when it
// compiles, writing nothing; Save needs the free-edit confirmation and writes the text with LF line ends; a text that
// changes env values is refused; a contract that sets them takes a free edit with each value hidden, which saving
// puts back.
func TestRawEditor(t *testing.T) {
	f := newChangeFix(t)
	ref := f.ref(t, f.other)
	before := readText(t, f.other)
	raw := func(step, text string, ack bool) (int, string) {
		v := url.Values{"mode": {"raw"}, "c": {ref.Ref}, "base": {ref.Base}, "step": {step}, "text": {text}}
		if ack {
			v.Set("ackfree", "1") // the old boolean is no acknowledgement
		}
		return f.post(t, "/rules/change", v)
	}
	code, body := raw("check", "version: 0\nname: other-agent\ncommand: [sh]\nexec:\n  allow: [sh\n", false)
	if code != http.StatusOK || !strings.Contains(body, "This text cannot be saved") || !regexp.MustCompile(`href="#yl-\d+">line \d+</a>`).MatchString(body) ||
		!strings.Contains(body, `class="mono rc-bad" id="yl-`) {
		t.Errorf("a text that does not parse: %d, or no diagnostic with its line", code)
	}
	// "set" inside an ordinary word (assets/) is no env.set: the parse error still reaches its line.
	code, body = raw("check", "version: 0\nname: other-agent\ncommand: [sh]\nfs:\n  write: [./assets/\n", false)
	if code != http.StatusOK || !strings.Contains(body, "This text cannot be saved") || !strings.Contains(body, `class="mono rc-bad" id="yl-`) ||
		strings.Contains(body, "environment values") {
		t.Errorf("a broken text naming assets/: %d, or no diagnostic with its line", code)
	}
	code, body = raw("check", "version: 0\nname: other-agent\ncommand: [sh]\nexec:\n  allow: [sh]\nfs:\n  write: [3]\nbogus_key: 1\n", false)
	if code != http.StatusOK || !strings.Contains(body, "This text cannot be saved") {
		t.Errorf("a text that does not compile: %d", code)
	}
	good := strings.Replace(before, "allow: [sh]", "allow: [sh, git]", 1)
	code, body = raw("check", good, false)
	if code != http.StatusOK || !strings.Contains(body, "It compiles") || !strings.Contains(body, "&#43;  allow: [sh, git]") {
		t.Errorf("a good text's check: %d %s", code, body)
	}
	goodAck := ackIn(t, body)
	if code, _ = raw("save", good, true); code != http.StatusBadRequest || readText(t, f.other) != before {
		t.Errorf("a free edit saved with ackfree=1: %d", code)
	}
	if code, body = f.post(t, "/rules/change", url.Values{"mode": {"raw"}, "c": {ref.Ref}, "base": {ref.Base}, "step": {"save"},
		"text": {good + "# changed after the check\n"}, "ack": {goodAck}}); code != http.StatusBadRequest || !strings.Contains(body, "the text changed") ||
		readText(t, f.other) != before {
		t.Errorf("a text changed after its check saved with the check's Ack: %d", code)
	}
	if readText(t, f.other) != before {
		t.Fatal("Check wrote the file")
	}
	if code, body = raw("save", good, false); code != http.StatusBadRequest || !strings.Contains(body, "tick to confirm") {
		t.Errorf("a free edit without its confirmation: %d", code)
	}
	if code, body = raw("save", good+"env:\n  set:\n    K: "+rulesCanary+"\n", true); code != http.StatusUnprocessableEntity || !strings.Contains(body, "environment values") {
		t.Errorf("a free edit with env values: %d, want 422", code)
	}
	if code, _ = raw("check", good+"env:\n  set:\n    K: "+rulesview.Hidden+"\n", false); code != http.StatusUnprocessableEntity {
		t.Errorf("a free edit adding a hidden env value: %d, want 422", code)
	}
	if readText(t, f.other) != before {
		t.Fatal("a refused free edit wrote the file")
	}
	if _, body = f.save(t, "/rules/change", url.Values{"mode": {"raw"}, "c": {ref.Ref}, "base": {ref.Base}, "step": {"save"},
		"text": {strings.ReplaceAll(good, "\n", "\r\n")}, "ack": {goodAck}}); !strings.Contains(body, "Whole file replaced") {
		t.Fatalf("a confirmed free edit: %s", body)
	}
	if got := readText(t, f.other); got != good {
		t.Errorf("the saved text is %q, want %q", got, good)
	}
	// The demo's case: a rules file that sets env values is edited with each value hidden, and saving puts it back.
	src := f.ref(t, f.source)
	srcBefore := readText(t, f.source)
	shown := rulesview.RedactEnvText(srcBefore)
	edited := strings.Replace(shown, "allow: [sh, git]", "allow: [sh]", 1)
	free := func(step, text string) (int, string) {
		return f.post(t, "/rules/change", url.Values{"mode": {"raw"}, "c": {src.Ref}, "base": {src.Base}, "step": {step}, "text": {text}})
	}
	// The editor's text saved unchanged, as a browser posts it (CR LF), is "Nothing to save", although one value spans
	// lines and putting it back would rewrite it on one; the file keeps its bytes.
	if !strings.Contains(srcBefore, rulesCanary+"-block\n") {
		t.Fatalf("the fixture's rules file has no multi-line env value:\n%s", srcBefore)
	}
	if code, body = free("save", strings.ReplaceAll(shown, "\n", "\r\n")); !strings.Contains(body, "Nothing to save") || readText(t, f.source) != srcBefore {
		t.Errorf("the unchanged editor text saved: %d, file changed %v\n%s", code, readText(t, f.source) != srcBefore, body)
	}
	code, body = free("check", edited)
	if code != http.StatusOK || !strings.Contains(body, "It compiles") || strings.Contains(body, rulesCanary) {
		t.Errorf("a check of a file with env values: %d, or a value on the page:\n%s", code, body)
	}
	editedAck := ackIn(t, body)
	if code, body = free("check", strings.Replace(edited, "DEMO_TOKEN: "+rulesview.Hidden, "DEMO_TOKEN: other", 1)); code != http.StatusUnprocessableEntity ||
		!strings.Contains(body, "environment values") {
		t.Errorf("a changed env value: %d", code)
	}
	if _, body = f.save(t, "/rules/change", url.Values{"mode": {"raw"}, "c": {src.Ref}, "base": {src.Base}, "step": {"save"}, "text": {edited},
		"ack": {editedAck}}); strings.Contains(body, rulesCanary) {
		t.Fatalf("a free edit of a file with env values shows a value:\n%s", body)
	}
	got := readText(t, f.source)
	if !strings.Contains(got, "DEMO_TOKEN: "+rulesCanary+"\n") || !strings.Contains(got, rulesCanary+"-block") || !strings.Contains(got, "allow: [sh]\n") {
		t.Errorf("the saved file lost an env value or the edit:\n%s", got)
	}
}

// TestDiagsOf: a diagnostic names its line in the contract, not in a profile, and YAML's "line N" counts.
func TestDiagsOf(t *testing.T) {
	ds := diagsOf("the new contract does not compile: error: /p/agent.yaml:7:3: bad [code]\n  fix: do this\nerror: /p/base.yaml:4: in a profile [x]\nyaml: line 9: did not find", "/p/agent.yaml")
	var lines []int
	for _, d := range ds {
		lines = append(lines, d.Line)
	}
	if !slices.Equal(lines, []int{7, 0, 0, 9}) {
		t.Errorf("lines %v, want [7 0 0 9]", lines)
	}
	ls := numbered("a\nb\nc\nd\ne\nf\ng\nh\ni\nj\n", []diagLine{{Line: 2}, {Line: 9}})
	var got []string
	for _, l := range ls {
		if l.Gap {
			got = append(got, "…")
			continue
		}
		got = append(got, l.Text)
	}
	if strings.Join(got, "") != "abcd…ghij" {
		t.Errorf("numbered = %q", got)
	}
}

// fakeChange is a ChangeService that answers fixed plans, for the parts of the pages a real ledger cannot reach in a
// unit test: a running run's "Also apply now", and its outcomes.
type fakeChange struct {
	plan    *rules.ChangePlan
	applied *rules.Applied
	req     rules.ChangeReq
}

func (fc *fakeChange) Contracts() ([]rules.ContractRef, error) {
	return []rules.ContractRef{{Ref: "00112233aabbccdd", Path: "/p/agent.yaml", Agent: "demo", Writable: true, Base: "b1", Live: []string{"r-live-1"}}}, nil
}
func (fc *fakeChange) Current(string) (*rules.Current, error) {
	return &rules.Current{ContractRef: rules.ContractRef{Ref: "00112233aabbccdd", Base: "b2"}, Text: []byte("version: 0\n")}, nil
}
func (fc *fakeChange) PlanChange(context.Context, rules.ChangeReq) (*rules.ChangePlan, error) {
	return fc.plan, nil
}
func (fc *fakeChange) ApplyChange(_ context.Context, r rules.ChangeReq) (*rules.Applied, error) {
	fc.req = r
	return fc.applied, nil
}
func (fc *fakeChange) PlanRaw(context.Context, rules.RawReq) (*rules.ChangePlan, error) {
	return fc.plan, nil
}
func (fc *fakeChange) ApplyRaw(context.Context, rules.RawReq) (*rules.Applied, error) {
	return fc.applied, nil
}
func (fc *fakeChange) History(string) ([]rules.HistoryEntry, error) { return nil, nil }
func (fc *fakeChange) Revert(context.Context, rules.RevertReq) (*rules.Reverted, error) {
	return nil, rules.ErrRefused
}

// TestAlsoApplyNow: the preview offers "Also apply now" per running run, ticked, with each live block, and says why a
// block is not offered; the confirm carries the runs ticked; the Saved page says what each live block did and warns
// when the journal line failed (and then offers no Undo).
func TestAlsoApplyNow(t *testing.T) {
	plan := &rules.ChangePlan{Ref: "00112233aabbccdd", Contract: "/p/agent.yaml", Agent: "demo", Base: "b2", Direction: "narrows",
		Summary: "exec.allow -= ls", Diff: "--- agent.yaml\n-  allow: [sh, ls]\n+  allow: [sh]\n",
		Sentences: []rules.Sentence{{Before: "Can run ls", After: "Cannot run ls", Direction: "narrows"}},
		Now: []rules.NowOption{{Run: "r-live-1", Kind: "exec", Value: "/usr/bin/ls", Block: "exec:/usr/bin/ls", OK: true},
			{Run: "r-live-2", Why: "this run reads files directly"}}}
	fc := &fakeChange{plan: plan, applied: &rules.Applied{Plan: plan, ID: "", Bak: "/p/agent.yaml.bak", Warn: "the journal could not be written",
		Live: []rules.LiveResult{{Run: "r-live-1", Block: "exec:/usr/bin/ls", OK: true}, {Run: "r-live-2", Err: "not running"}}}}
	s, err := New(Config{Ledger: t.TempDir(), Port: port, Token: "tok123", Rules: fc})
	if err != nil {
		t.Fatal(err)
	}
	trustPeer(s)
	c := login(t, s)
	w := do(s, "GET", "/rules/change/preview?c=00112233aabbccdd&base=b1&op=remove&key=exec.allow&v=ls", "127.0.0.1:8484", c)
	body := w.Body.String()
	for _, want := range []string{"Also apply now", `name="now" value="r-live-1" checked`, `<span title="exec:/usr/bin/ls">Running /usr/bin/ls</span> · until the run ends`, "this run reads files directly",
		"tego block r-live-1 exec /usr/bin/ls", "<legend>Running now</legend>", `With Also apply now ticked, it is in force on <span class="nb">r-live-1</span> within about a second`} {
		if !strings.Contains(body, want) {
			t.Errorf("the preview lacks %q", want)
		}
	}
	if strings.Contains(body, `value="r-live-2" checked`) {
		t.Error("a run with no live block is ticked")
	}
	body = follow(t, s, c, post(s, "/rules/change", url.Values{"csrf": {s.csrf}, "c": {"00112233aabbccdd"}, "base": {"b2"}, "op": {"remove"},
		"key": {"exec.allow"}, "v": {"ls"}, "now": {"r-live-1"}}, own, "", c))
	if !slices.Equal(fc.req.AlsoNow, []string{"r-live-1"}) {
		t.Fatalf("confirm: AlsoNow %v", fc.req.AlsoNow)
	}
	if !strings.Contains(body, "Saved: Cannot run ls, from the next run. Putting it in force now on 1 running run.") {
		t.Error("the Saved page's line does not say the change and where it is live")
	}
	for _, want := range []string{"Running now", `<span title="exec:/usr/bin/ls">Running /usr/bin/ls</span>`, "its state cannot be read now",
		"Not placed on run", ": not running; it applies from the next run", "this run reads files directly",
		"Written, but: the journal could not be written", "/p/agent.yaml.bak"} {
		if !strings.Contains(body, want) {
			t.Errorf("the Saved page lacks %q", want)
		}
	}
	if strings.Contains(body, `action="/rules/revert"`) {
		t.Error("a change with no journal line offers Undo")
	}
}

// TestChangeWithoutService: a dashboard started without the rule service says so on every Change rules route.
func TestChangeWithoutService(t *testing.T) {
	s := newServer(t, fixture(t))
	c := login(t, s)
	for _, p := range []string{"/rules/change?c=x", "/rules/change/preview?c=x"} {
		if w := do(s, "GET", p, "127.0.0.1:8484", c); w.Code != http.StatusNotFound || !strings.Contains(w.Body.String(), "Policy editing is off") {
			t.Errorf("GET %s: %d", p, w.Code)
		}
	}
	tok := csrfOf(t, s, c, "/runs/"+harmRun+"/stop")
	for _, p := range []string{"/rules/change", "/rules/revert"} {
		if w := post(s, p, url.Values{"csrf": {"nope"}}, own, "", c); w.Code != http.StatusForbidden {
			t.Errorf("POST %s without the token: %d", p, w.Code)
		}
		if w := post(s, p, url.Values{"csrf": {tok}}, own, "", c); w.Code != http.StatusNotFound {
			t.Errorf("POST %s: %d", p, w.Code)
		}
	}
}
