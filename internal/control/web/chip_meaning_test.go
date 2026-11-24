// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"golang.org/x/net/html"
)

// TestWaitingChipMeaning pins the design's one orange meaning. An ask line is
// history, not evidence that anyone can still answer it; machine work waiting
// for a run and incomplete setup steps are facts, not requests to a person.
func TestWaitingChipMeaning(t *testing.T) {
	css, err := assets.ReadFile("static/app.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, match := range regexp.MustCompile(`(?m)^([^{}]+)\{([^{}]*)\}`).FindAllStringSubmatch(string(css), -1) {
		if strings.Contains(match[2], "background: var(--c-ask);") && strings.Contains(match[1], ".b-") && strings.TrimSpace(match[1]) != ".b-waiting" {
			t.Errorf("orange chip is not reserved for waiting requests: %s", strings.TrimSpace(match[1]))
		}
	}
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"pending", "approved", "denied", "lost", "unanswered"} {
		t.Run(state, func(t *testing.T) {
			var b bytes.Buffer
			data := map[string]any{"Run": harmRun, "R": &ledgerview.Run{}, "Home": "", "V": map[string]any{
				"State": state, "AskID": "ask-1", "TS": time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC),
			}}
			if err := pages["run"].ExecuteTemplate(&b, "hl-ask", withNumbers(data, countScopes{})); err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(b.String(), `class="b b-waiting"`); got != (state == "pending") {
				t.Errorf("state %s: waiting chip = %v, HTML %s", state, got, b.String())
			}
		})
	}
	for _, state := range []string{guide.Done, guide.Todo, guide.Waiting, guide.Blocked, guide.Skipped, guide.NotKnown} {
		if badge := stepBadge(state); badge[0] == "b-waiting" || badge[0] == "b-asked" {
			t.Errorf("setup state %s uses request class %s", state, badge[0])
		}
	}
	s := newServer(t, fixture(t))
	c := login(t, s)
	chipMeaning(t, get(t, s, c, "/runs/"+harmRun+"/lines/5"), "Not answered", "b-waiting", "i-hand")
	lostRoot := fixture(t)
	letGo(filepath.Join(lostRoot, harmRun))
	lost := newServer(t, lostRoot)
	lostCookie := login(t, lost)
	chipMeaning(t, get(t, lost, lostCookie, "/runs/"+harmRun+"/lines/5"), "Not answered", "b-neutral", "i-hand")
	chipMeaning(t, get(t, lost, lostCookie, "/runs/"+harmRun+"/receipt"), "open", "b-neutral", "i-hand")
	block := liveblock.Entry{Kind: liveblock.KindExec, Value: "git"}
	view := liveView{Serial: 2}
	if chip := liveChipOf(block, view); chip.Class != "b-neutral" {
		t.Errorf("waiting for the launcher is not a request to a person: %+v", chip)
	}
	pending := pendingLiveOf(rules.PendingNow{Placed: []string{"exec:git"}}, true, ledgerview.LiveFacts{},
		runact.LiveBlocks{Serials: map[string]uint64{"exec:git": 2}}, shortener{}, time.Now())
	if pending.Class != "b-neutral" {
		t.Errorf("pending block application is not a request to a person: %+v", pending)
	}
}

// TestNonRequestChipsStayQuiet exercises the actual Adjustable run, its
// Contracts page and lift preview, plus both change-direction template states.
func TestNonRequestChipsStayQuiet(t *testing.T) {
	s, c, _ := liveFenceServer(t)
	for _, target := range []string{"/runs/" + adjRun, "/rules?run=" + adjRun, "/runs/" + adjRun + "/lift?kind=read&value=/srv/exports&for=1h"} {
		page := get(t, s, c, target)
		chipMeaning(t, page, "Adjustable", "b-neutral", "i-shield")
		if target == "/rules?run="+adjRun {
			chipMeaning(t, page, "Granted until ", "b-neutral", "i-check")
		}
	}
	f := newRulesFix(t)
	chipMeaning(t, get(t, f.s, f.c, "/rules?run="+rulesRunA), "Open", "b-neutral", "i-triangle-alert")
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"widens", "mixed"} {
		var b bytes.Buffer
		if err := pages["rules"].ExecuteTemplate(&b, "dir", dir); err != nil {
			t.Fatal(err)
		}
		chipMeaning(t, b.String(), capFirst(dir), "b-widens", "i-triangle-alert")
	}
	root := fixture(t)
	if err := os.WriteFile(filepath.Join(root, harmRun, "contract.yaml"), []byte("version: 0\nfs:\n  write: [\"./never-written/\"]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s = newServer(t, root)
	c = login(t, s)
	chipMeaning(t, get(t, s, c, "/runs/"+harmRun+"/unused"), "Granted but never used", "b-neutral", "i-eye")
	s = newServer(t, routesFixture(t))
	s.cfg.Preview = true
	c = login(t, s)
	chipMeaning(t, get(t, s, c, "/routes?run="+harmRun), "Plaintext, this machine", "b-neutral", "i-server")
	chipMeaning(t, get(t, s, c, "/routes/preview?run="+harmRun+"&endpoint="+routesEndpoint+"&route=local"), "Plaintext, this machine", "b-neutral", "i-server")
	s = newServer(t, mcpFixture(t))
	chipMeaning(t, get(t, s, login(t, s), "/mcp?run="+harmRun), "Not relayed:", "b-neutral", "i-eye")
}

// TestProtectedReadAllowedUsesThroughChip goes through the receipt builder,
// view selection and template: an allow is still a protected file getting
// through, so it needs the same red warning chip as an unrefused watched read.
func TestProtectedReadAllowedUsesThroughChip(t *testing.T) {
	root := t.TempDir()
	const run = "r-aaaaaaaa-0000000000060-rcchip"
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	finishRun(t, root, run,
		line(run, "sh", 0, t0, "run_start", `"tier":"landlock","record":"full","command":["sh"]`),
		line(run, "sh", 1, t0.Add(time.Second), "fs", `"verdict":"allow","rule":"fs.read[/home/u/.ssh/]","op":"open","path":"/home/u/.ssh/id_rsa","flags":0`),
		line(run, "sh", 2, t0.Add(2*time.Second), "run_end", `"reason":"exit","exit_code":0`))
	s := newServer(t, root)
	page := get(t, s, login(t, s), "/runs/"+run+"/receipt")
	chipMeaning(t, page, "Read allowed 1", "b-through", "i-triangle-alert")
	v := &receiptView{R: &ledgerview.Receipt{Command: []string{"codex"}}}
	if chips := v.SensChips("/home/u/.codex/auth.json", 0, 1, 0); len(chips) != 1 || chips[0].Class != "b-neutral" {
		t.Errorf("agent's own login should stay routine: %+v", chips)
	}
}

// chipMeaning finds an actual chip, checks its visible word and its icon, and
// rejects colour-only status changes.
func chipMeaning(t *testing.T, page, word, class, icon string) {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(page))
	if err != nil {
		t.Fatal(err)
	}
	var textOf func(*html.Node) string
	textOf = func(n *html.Node) string {
		if n.Type == html.TextNode {
			return n.Data
		}
		var b strings.Builder
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			b.WriteString(textOf(c))
		}
		return b.String()
	}
	found := false
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		classes := ""
		for _, a := range n.Attr {
			if a.Key == "class" {
				classes = " " + a.Val + " "
			}
		}
		if n.Type == html.ElementNode && strings.Contains(classes, " b ") && strings.HasPrefix(strings.TrimSpace(textOf(n)), word) {
			found = true
			var b bytes.Buffer
			if err := html.Render(&b, n); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(classes, " "+class+" ") || !strings.Contains(b.String(), "sprite.svg#"+icon) {
				t.Errorf("%q needs %s and %s: %s", word, class, icon, b.String())
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visit(c)
		}
	}
	visit(doc)
	if !found {
		t.Errorf("no chip beginning %q", word)
	}
}
