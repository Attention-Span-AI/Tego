// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestHeldMutationAskWords: each mutation an fs.ask scope holds (ADR 0047) reads as what it changes, in the banner's
// verb, the card's question and the line an answer leaves, never as its record op; an answer line, which carries no
// hold, reads the same.
func TestHeldMutationAskWords(t *testing.T) {
	const rule = "fs.ask[./src/]"
	for _, c := range []struct {
		op, verb, noun, object string
	}{
		{record.FSUnlink, "delete", "deletion of", "this"},
		{record.FSMkdir, "create a folder at", "new folder at", "this path"},
		{record.FSRename, "rename", "rename of", "this"},
		{record.FSSymlink, "make a symbolic link at", "symbolic link at", "this path"},
		{record.FSLink, "make a hard link of", "hard link of", "this file"},
	} {
		for _, hold := range []string{"mutation", ""} {
			if got := askVerb(c.op, rule, hold); got != c.verb {
				t.Errorf("askVerb(%s, hold %q) = %q, want %q", c.op, hold, got, c.verb)
			}
			if got := askNoun(c.op, rule, hold); got != c.noun {
				t.Errorf("askNoun(%s, hold %q) = %q, want %q", c.op, hold, got, c.noun)
			}
			if got := askObject(c.op, rule, hold); got != c.object {
				t.Errorf("askObject(%s, hold %q) = %q, want %q", c.op, hold, got, c.object)
			}
		}
	}
	// The other asks read as they did.
	for _, c := range []struct{ op, rule, verb, object string }{
		{"open", "fs.ask[./held/]", "write to", "this file"},
		{"read", "fs.ask_read[/p/]", "read", "this file"},
		{"connect", "net.ask[example.com]", "connect to", "this address"},
		{"exec", "exec.ask[curl]", "run", "this program"},
	} {
		if v, o := askVerb(c.op, c.rule, ""), askObject(c.op, c.rule, ""); v != c.verb || o != c.object {
			t.Errorf("%s under %s reads %q %q, want %q %q", c.op, c.rule, v, o, c.verb, c.object)
		}
	}
}

const (
	mutRun = "r-aaaaaaaa-0000000000021-mutask"
	mutSrc = "/home/dev/projects/website/src"
)

// mutNow is the time the mutation fixture's server reads its pages at.
var mutNow = time.Date(2026, 10, 27, 12, 5, 0, 0, time.UTC)

// mutAsks are the mutation fixture's pending asks, one for each mutation an fs.ask scope holds, with the names the
// supervisor's pinned walk writes and the question the Approvals card asks.
var mutAsks = []struct{ id, op, target, target2, question string }{
	{"q-1", "unlink", mutSrc + "/components/OldHeader.tsx", "", "Let claude-tego delete this?"},
	{"q-2", "mkdir", mutSrc + "/components/layout", "", "Let claude-tego create a folder at this path?"},
	{"q-3", "rename", mutSrc + "/components/Header.tsx.tmp.4711.1730000000", mutSrc + "/components/Header.tsx", "Let claude-tego rename this?"},
	{"q-4", "symlink", mutSrc + "/current", "../releases/v2", "Let claude-tego make a symbolic link at this path?"},
	{"q-5", "link", mutSrc + "/a.txt", mutSrc + "/b.txt", "Let claude-tego make a hard link of this file?"},
}

// mutationAskFixture is one live Claude Code run in /home/dev/projects/website with mutAsks pending.
func mutationAskFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t0 := mutNow.Add(-time.Minute)
	ls := []string{line(mutRun, "claude-tego", 0, t0, "run_start", `"tier":"landlock","command":["claude"],"cwd":"/home/dev/projects/website","harness":{"name":"claude"}`)}
	for i, a := range mutAsks {
		extra := `"ask_id":"` + a.id + `","ask_rule":"fs.ask[./src/]","hold":"mutation","op":"` + a.op + `","target":"` + a.target + `"`
		if a.target2 != "" {
			extra += `,"target2":"` + a.target2 + `"`
		}
		ls = append(ls, line(mutRun, "claude-tego", i+1, t0.Add(time.Duration(i+1)*time.Second), "ask", extra))
	}
	if err := os.MkdirAll(filepath.Join(root, mutRun), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, mutRun, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
		t.Fatal(err)
	}
	markLive(t, root, mutRun)
	return root
}

// section is the part of page from the first from up to the next end after it, "" when page has no from.
func section(page, from, end string) string {
	i := strings.Index(page, from)
	if i < 0 {
		return ""
	}
	s := page[i:]
	if j := strings.Index(s, end); j >= 0 {
		s = s[:j]
	}
	return s
}

// TestHeldMutationAsksReadInPlainWords: a person deciding on a held mutation reads what it changes, on the Approvals
// card ("Let claude-tego delete this?"), in the banner, under Waiting on you and in the run's Highlights; the record op
// is in the words' title, never in the text.
func TestHeldMutationAsksReadInPlainWords(t *testing.T) {
	s := newServer(t, mutationAskFixture(t))
	s.cfg.Now = func() time.Time { return mutNow }
	c := login(t, s)
	ap := do(s, "GET", "/approvals", "127.0.0.1:8484", c).Body.String()
	for _, a := range mutAsks {
		q := section(ap, `<h2 class="ask-q" id="q-`+a.id+`"`, "</h2>")
		if got := f3Text(q + "</h2>"); got != a.question {
			t.Errorf("the %s card asks %q, want %q", a.op, got, a.question)
		}
		if !strings.Contains(q, ` title="`+a.op+`">`) {
			t.Errorf("the %s card does not keep its op in the words' title: %s", a.op, q)
		}
	}

	banner := section(do(s, "GET", "/runs", "127.0.0.1:8484", c).Body.String(), `id="ask-banner"`, "</section>")
	bt := f3Text(banner)
	for _, want := range []string{"claude-tego wants to delete ", "claude-tego wants to create a folder at ", "claude-tego wants to rename "} {
		if !strings.Contains(bt, want) {
			t.Errorf("the banner lacks %q: %s", want, bt)
		}
	}
	if !strings.Contains(banner, `<span class="op" title="unlink">delete</span>`) {
		t.Errorf("the banner does not keep the op in the title: %s", banner)
	}

	wait := f3Text(section(do(s, "GET", "/", "127.0.0.1:8484", c).Body.String(), `id="h-asks"`, "</section>"))
	for _, want := range []string{"wants to delete", "wants to create a folder at", "wants to rename", "wants to make a symbolic link at", "wants to make a hard link of"} {
		if !strings.Contains(wait, want) {
			t.Errorf("Waiting on you lacks %q: %s", want, wait)
		}
	}

	run := do(s, "GET", "/runs/"+mutRun, "127.0.0.1:8484", c).Body.String()
	for op, verb := range map[string]string{"unlink": "delete", "mkdir": "create a folder at", "rename": "rename", "symlink": "make a symbolic link at", "link": "make a hard link of"} {
		if !strings.Contains(run, `<span class="op" title="`+op+`">`+verb+`</span>`) {
			t.Errorf("the run's Highlights do not read %s as %q", op, verb)
		}
	}

	for name, text := range map[string]string{"Approvals": f3Text(ap), "the banner": bt, "Waiting on you": wait} {
		for _, raw := range []string{"unlink", "mkdir", "symlink", "to link ", "claude-tego link "} {
			if strings.Contains(text, raw) {
				t.Errorf("%s says the record op %q: %s", name, raw, text)
			}
		}
	}
}

// TestHeldMutationAskShowsBothNames: a held rename, link or symbolic link shows both its names, each shortened against
// the run's folder and never cut where one ends: on the Approvals card, in the banner, under Waiting on you and in the
// run's Highlights, and once answered in Answered recently and the answer's own line.
func TestHeldMutationAskShowsBothNames(t *testing.T) {
	root := mutationAskFixture(t)
	t1 := mutNow.Add(-30 * time.Second)
	names := `"op":"rename","target":"` + mutSrc + `/notes.md.tmp","target2":"` + mutSrc + `/notes.md"`
	appendLines(t, root, mutRun,
		line(mutRun, "claude-tego", 6, t1, "ask", `"ask_id":"q-6","ask_rule":"fs.ask[./src/]","hold":"mutation",`+names),
		line(mutRun, "claude-tego", 7, t1.Add(2*time.Second), "answer", `"ask_id":"q-6","ask_rule":"fs.ask[./src/]","approved":true,"by":"uid:4000000000 pid:9 dashboard","after_s":2,`+names))
	s := newServer(t, root)
	s.cfg.Now = func() time.Time { return mutNow }
	c := login(t, s)
	const (
		rename = "./src/components/Header.tsx.tmp.4711.1730000000 → ./src/components/Header.tsx"
		link   = "./src/a.txt → ./src/b.txt"
	)
	ap := do(s, "GET", "/approvals", "127.0.0.1:8484", c).Body.String()
	for id, want := range map[string]string{"q-3": rename, "q-4": "./src/current → ../releases/v2", "q-5": link} {
		card := section(ap, `<section class="ask" id="`+id+`"`, "</section>")
		if got := f3Text(section(card, `<p class="ask-path">`, "</p>")); got != want {
			t.Errorf("the card of %s shows %q, want %q", id, got, want)
		}
	}
	if recent := f3Text(section(ap, "Answered recently", "</section>")); !strings.Contains(recent, "claude-tego asked to rename ./src/notes.md.tmp → ./src/notes.md") {
		t.Errorf("Answered recently does not say where the rename went: %s", recent)
	}

	if bt := f3Text(section(do(s, "GET", "/runs", "127.0.0.1:8484", c).Body.String(), `id="ask-banner"`, "</section>")); !strings.Contains(bt, "claude-tego wants to rename "+rename+" ·") {
		t.Errorf("the banner does not show both of the rename's names: %s", bt)
	}

	wait := section(do(s, "GET", "/", "127.0.0.1:8484", c).Body.String(), `id="h-asks"`, "</section>")
	// Waiting on you reads paths against the run's home only, each name's folder elided, its file name whole.
	row := f3Text(section(wait, `data-k="`+mutRun+`-q-3"`, "</li>"))
	if !strings.Contains(row, "/components/Header.tsx.tmp.4711.1730000000 → /home/") || !strings.Contains(row, "/components/Header.tsxReview") {
		t.Errorf("Waiting on you does not show both of the rename's names: %s", row)
	}

	hl := f3Text(section(do(s, "GET", "/runs/"+mutRun, "127.0.0.1:8484", c).Body.String(), `class="hl-list"`, "</ul>"))
	if !strings.Contains(hl, "rename "+rename+"Waiting") || !strings.Contains(hl, "make a hard link of "+link+"Waiting") {
		t.Errorf("the run's Highlights do not show both names: %s", hl)
	}

	logs := do(s, "GET", "/logs?run="+mutRun+"&q=q-6", "127.0.0.1:8484", c).Body.String()
	if lt := f3Text(section(logs, `data-k="`+mutRun+`-7"`, "</tr>")); !strings.Contains(lt, "/notes.md.tmp → ") || !strings.Contains(lt, "/src/notes.md") {
		t.Errorf("the answer's line in Logs does not name where the rename went: %s", lt)
	}
}
