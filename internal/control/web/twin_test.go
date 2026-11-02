// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/shellword"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestTwinJSRules: static/twin.js writes the Block now panel's terminal twin in the browser, so it carries its own
// copies of Go rules, and each must say what the Go one says. BARE leaves a word unquoted exactly when
// shellword.Quote does; word() writes every word as Quote does, read here from its source (in single quotes, each match
// of ESC written as the replacement string says), so a copy that lets a quote out of them fails here, not only in a
// browser; and UNSAFE, which keeps the placeholders in place of a line, matches exactly the characters
// record.Printable escapes for a terminal. The script is served as JavaScript.
func TestTwinJSRules(t *testing.T) {
	js, err := os.ReadFile("static/twin.js")
	if err != nil {
		t.Fatal(err)
	}
	jsRegexp := func(name string) *regexp.Regexp {
		t.Helper()
		m := regexp.MustCompile(`\b` + name + ` = /((?:\\.|[^/\\\n])+)/[gu]*[,;]`).FindSubmatch(js)
		if m == nil {
			t.Fatalf("twin.js has no %s = /…/", name)
		}
		// The one JavaScript spelling RE2 reads differently: a code point \u{…} is \x{…}.
		return regexp.MustCompile(strings.ReplaceAll(string(m[1]), `\u{`, `\x{`))
	}
	bare, esc, unsafe := jsRegexp("BARE"), jsRegexp("ESC"), jsRegexp("UNSAFE")
	m := regexp.MustCompile(`function word\(s\) \{ return BARE\.test\(s\) \? s : "'" \+ s\.replace\(ESC, "((?:\\.|[^"\\])*)"\) \+ "'"; \}`).FindSubmatch(js)
	if m == nil {
		t.Fatal(`twin.js has no function word(s) { return BARE.test(s) ? s : "'" + s.replace(ESC, "…") + "'"; }`)
	}
	// The replacement, a JavaScript string: \\, \' and \" are the only escapes read here, and $& the only pattern.
	var b strings.Builder
	for i := 0; i < len(m[1]); i++ {
		if m[1][i] == '\\' {
			if i++; !strings.ContainsRune(`\'"`, rune(m[1][i])) {
				t.Fatalf("word()'s replacement %s has an escape this test does not read", m[1])
			}
		}
		b.WriteByte(m[1][i])
	}
	repl := b.String()
	if strings.Contains(strings.ReplaceAll(repl, "$&", ""), "$") {
		t.Fatalf("word()'s replacement %q has a $ pattern other than $&, which this test does not read", repl)
	}
	word := func(s string) string {
		if bare.MatchString(s) {
			return s
		}
		return "'" + esc.ReplaceAllStringFunc(s, func(c string) string { return strings.ReplaceAll(repl, "$&", c) }) + "'"
	}
	words := []string{"", "a b", "it's", "café", "\xff", "''", `\\`, `/tmp/x\'; id #`, "a'b\\c d"}
	for c := rune(0); c < utf8.RuneSelf; c++ {
		words = append(words, string(c), "a"+string(c), string(c)+"a")
	}
	for _, w := range words {
		if js, goes := bare.MatchString(w), shellword.Quote(w) == w; js != goes {
			t.Errorf("%q: twin.js leaves it unquoted: %v; shellword.Quote: %v", w, js, goes)
		}
		if js, goes := word(w), shellword.Quote(w); js != goes {
			t.Errorf("%q: twin.js's word() writes %s; shellword.Quote: %s", w, js, goes)
		}
	}
	for r := rune(0); r <= utf8.MaxRune; r++ {
		if !utf8.ValidRune(r) {
			continue
		}
		if s := string(r); unsafe.MatchString(s) != (record.Printable(s) != s) {
			t.Errorf("U+%04X: twin.js calls it unsafe: %v; record.Printable escapes it: %v", r, unsafe.MatchString(s), record.Printable(s) != s)
		}
	}

	s := newServer(t, fixture(t))
	c := login(t, s)
	w := do(s, "GET", "/static/twin.js", "127.0.0.1:8484", c)
	if w.Code != http.StatusOK || !strings.Contains(w.Header().Get("Content-Type"), "javascript") {
		t.Errorf("twin.js: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
}

// twinHarness runs static/twin.js in node against a stand-in for the run page: the Block now form's fields, one twin
// that counts the writes of its text, and a selection that such a write drops, as a browser's does. It reads {src, cmd,
// placeholders, steps} on stdin. A step sets fields; puts the server's placeholders back as a live merge does when
// merge is set; has the twin selected or not as select says; then fires its event. After each step it prints the
// twin's text, the writes so far and whether the twin is still selected.
const twinHarness = `'use strict';
const input = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const fields = { kind: { value: 'exec' }, value: { value: '' }, for: { value: 'run' }, span: { value: '' }, until: { value: '' } };
let text = input.placeholders, writes = 0, selected = false;
const code = {
  dataset: { twin: 'block-form', cmd: input.cmd },
  get textContent() { return text; },
  set textContent(v) { text = String(v); writes++; selected = false; },
  contains: (n) => n === code,
};
const on = {};
globalThis.document = {
  readyState: 'complete',
  querySelectorAll: (q) => (q === 'code[data-twin]' ? [code] : []),
  getElementById: (id) => (id === 'block-form' ? { elements: { namedItem: (n) => fields[n] || null } } : null),
  addEventListener: (k, f) => { (on[k] = on[k] || []).push(f); },
};
globalThis.window = {
  getSelection: () => ({
    isCollapsed: !selected, rangeCount: selected ? 1 : 0,
    getRangeAt: () => ({ commonAncestorContainer: code }),
    selectAllChildren: (n) => { selected = n === code; },
  }),
};
require('vm').runInThisContext(input.src, { filename: 'twin.js' });
const out = [];
for (const s of input.steps) {
  for (const [k, v] of Object.entries(s.set || {})) fields[k].value = v;
  if (s.merge) text = input.placeholders;
  selected = !!s.select;
  for (const f of on[s.fire] || []) f();
  out.push({ text, writes, selected });
}
process.stdout.write(JSON.stringify(out));
`

// twinStep is one step of twinHarness: the form fields it sets, whether a live merge first puts the server's
// placeholders back in the twin (live.js merges no region a selection is in, so a merge comes with no selection),
// whether the twin is selected, and the event fired then.
type twinStep struct {
	Set    map[string]string `json:"set,omitempty"`
	Merge  bool              `json:"merge,omitempty"`
	Select bool              `json:"select,omitempty"`
	Fire   string            `json:"fire"`
}

// twinState is the twin after a step: its text, how many times twin.js has written it, and whether it is selected.
type twinState struct {
	Text     string `json:"text"`
	Writes   int    `json:"writes"`
	Selected bool   `json:"selected"`
}

// runTwin runs steps through the served static/twin.js in node (twinHarness), on a twin whose fixed words are cmd. A
// machine without node skips the test; TestBlockTwinInChrome (-tags chrome) runs the script in a browser.
func runTwin(t *testing.T, cmd string, steps []twinStep) []twinState {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node to run static/twin.js in")
	}
	src, err := assets.ReadFile("static/twin.js")
	if err != nil {
		t.Fatal(err)
	}
	in, err := json.Marshal(map[string]any{"src": string(src), "cmd": cmd, "placeholders": cmd + " <exec|net|path> <value>", "steps": steps})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	run := exec.CommandContext(ctx, node, "-e", twinHarness)
	run.Stdin = bytes.NewReader(in)
	var stderr bytes.Buffer
	run.Stderr = &stderr
	out, err := run.Output()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, stderr.String())
	}
	var got []twinState
	if err := json.Unmarshal(out, &got); err != nil || len(got) != len(steps) {
		t.Fatalf("node printed %q for %d steps (%v)", out, len(steps), err)
	}
	return got
}

// TestTwinJSWritesOnlyChanges: twin.js writes the twin only when its words change. A write drops a selection in it,
// even a write of the same words, and tego:merged follows every live update: on an active run the person's selection
// of the command was gone within about a second, often before the copy, which then took whatever the clipboard held.
// Words that change under a selection (the form's kind changed) are selected in turn.
func TestTwinJSWritesOnlyChanges(t *testing.T) {
	cmd := "tego block " + harmRun
	got := runTwin(t, cmd, []twinStep{
		{Set: map[string]string{"value": "curl"}, Fire: "input"},
		{Select: true, Fire: "tego:merged"}, // a live update that left the panel as it was
		{Select: true, Fire: "tego:enter"},
		{Merge: true, Fire: "tego:merged"}, // one that merged the server's placeholders back in
		{Set: map[string]string{"kind": "net"}, Select: true, Fire: "change"},
		{Set: map[string]string{"value": ""}, Fire: "input"},
	})
	want := []twinState{
		{cmd + " exec curl", 1, false},
		{cmd + " exec curl", 1, true},
		{cmd + " exec curl", 1, true},
		{cmd + " exec curl", 2, false},
		{cmd + " net curl", 3, true},
		{cmd + " <exec|net|path> <value>", 4, false},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("step %d: the twin is %+v, want %+v", i+1, got[i], want[i])
		}
	}
}

// TestTwinJSQuotesAsGo: for each value typed, the twin twin.js writes is the line the server's twins would: tego block
// <run> and changeWords of exec and the value, which is trimmed as the dashboard and tego block trim it and quoted by
// shellword.Quote; or, for a value holding a character record.Printable escapes, the placeholders. The values hold
// every printable ASCII character, alone and between letters, quotes and backslashes together, spaces at either end
// and text past ASCII.
func TestTwinJSQuotesAsGo(t *testing.T) {
	cmd := "tego block " + harmRun
	values := []string{"curl", "/usr/bin/curl", "it's", "x'; id #", `/tmp/x\'; id #`, `back\slash`, "''", `\\`, " fix it ",
		"\tcurl", "café", "\u00a0curl\u00a0", "a\u202eb", "a\u200db", "\ufeffcurl", "=curl", "a=b", "-x"}
	for c := byte(0x20); c < 0x7f; c++ {
		values = append(values, string(c), "a"+string(c)+"b")
	}
	steps := make([]twinStep, len(values))
	for i, v := range values {
		steps[i] = twinStep{Set: map[string]string{"value": v}, Fire: "input"}
	}
	got := runTwin(t, cmd, steps)
	for i, v := range values {
		want := cmd + " <exec|net|path> <value>"
		if strings.TrimSpace(v) != "" && record.Printable(v) == v {
			want = cmd + " " + changeWords("exec", v, "")
		}
		if got[i].Text != want {
			t.Errorf("value %q: the twin reads %s, want %s", v, got[i].Text, want)
		}
	}
}

// TestTwinJSWritesWhatTheFormDoes: pasted, the Block now twin does what the form's button does. A value that starts
// with - goes after --, the time limit before it, as the server's twins write one (changeWords): `tego block <run>
// exec -x` stopped at a usage error, since tego reads a flag anywhere before --, where the form blocks the program
// -x. A path that is not absolute keeps the placeholders: the form refuses one, and tego block would read it
// against the terminal's folder and block a file the form never named.
func TestTwinJSWritesWhatTheFormDoes(t *testing.T) {
	cmd := "tego block " + harmRun
	placeholders := cmd + " <exec|net|path> <value>"
	cases := []struct{ kind, value, limit, span, want string }{
		{"exec", "-x", "run", "", cmd + " exec -- -x"},
		{"exec", " -bash ", "15m", "", cmd + " exec --for 15m -- -bash"},
		{"exec", "--", "for", "1d12h", cmd + " exec --for 1d12h -- --"},
		{"exec", "-a b", "perm", "", cmd + " exec -- '-a b'"},
		{"net", "-x", "run", "", cmd + " net -- -x"},
		{"exec", "curl", "15m", "", cmd + " exec curl --for 15m"},
		{"path", "/tmp/-x", "run", "", cmd + " path /tmp/-x"},
		{"path", " /home/you/.aws/ ", "1h", "", cmd + " path /home/you/.aws/ --for 1h"},
		{"path", "notes.txt", "run", "", placeholders},
		{"path", "~/.aws", "run", "", placeholders},
		{"path", "./-x", "15m", "", placeholders},
		{"path", "-x", "run", "", placeholders},
	}
	steps := make([]twinStep, len(cases))
	for i, c := range cases {
		steps[i] = twinStep{Set: map[string]string{"kind": c.kind, "value": c.value, "for": c.limit, "span": c.span}, Fire: "change"}
	}
	got := runTwin(t, cmd, steps)
	for i, c := range cases {
		if got[i].Text != c.want {
			t.Errorf("%s %q (%s %s): the twin reads %s, want %s", c.kind, c.value, c.limit, c.span, got[i].Text, c.want)
		}
	}
}

// TestChangeWords: a live change's twin ends in its kind, its value and its time limit, a value that starts with - after
// a -- with the time limit before it, so tego reads it as the value and not as a flag.
func TestChangeWords(t *testing.T) {
	for _, c := range []struct{ kind, value, flags, want string }{
		{"exec", "curl", "", "exec curl"},
		{"exec", " /usr/bin/psql ", " --for 45m", "exec /usr/bin/psql --for 45m"},
		{"read", "/srv/my exports", " --until '2026-11-14 17:00'", "read '/srv/my exports' --until '2026-11-14 17:00'"},
		{"exec", "-x", "", "exec -- -x"},
		{"exec", " -bash", " --for 45m", "exec --for 45m -- -bash"},
		{"exec", "-a b", " --for 1d12h", "exec --for 1d12h -- '-a b'"},
		{"net", "--", "", "net -- --"},
		{"exec", "a-x", "", "exec a-x"},
	} {
		if got := changeWords(c.kind, c.value, c.flags); got != c.want {
			t.Errorf("changeWords(%q, %q, %q) = %s, want %s", c.kind, c.value, c.flags, got, c.want)
		}
	}
}
