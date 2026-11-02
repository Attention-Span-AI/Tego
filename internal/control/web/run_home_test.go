// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/liveblock"
)

// TestRunTextFoldsTheRunsHome: runText writes the run's home as ~ and its working directory as ., whether the text
// names them in full or from the dashboard user's home (a demo's with/home under the user's checkout), and leaves
// other paths alone.
func TestRunTextFoldsTheRunsHome(t *testing.T) {
	home, cwd := "/d/with/home", "/d/with/proj"
	for in, want := range map[string]string{
		"asked by fs.ask_read[/d/with/home/.config/telemetry/]":        "asked by fs.ask_read[~/.config/telemetry/]",
		"Asks you before it reads files in /d/with/proj/confidential/": "Asks you before it reads files in ./confidential/",
		"Cannot read /etc/shadow":                                      "Cannot read /etc/shadow",
		"":                                                             "",
	} {
		if got := runText(in, home, cwd); got != want {
			t.Errorf("runText(%q) = %q, want %q", in, got, want)
		}
	}
	h := homeDir()
	if h == "" {
		t.Skip("no home directory to stand the checkout in")
	}
	home, cwd = h+"/tego-src/examples/supply-chain-demo/with/home", h+"/tego-src/examples/supply-chain-demo/with/proj"
	in := "Asks you before it reads files in ~/tego-src/examples/supply-chain-demo/with/home/.config/telemetry/ and ~/tego-src/examples/supply-chain-demo/with/proj/confidential/"
	if got, want := runText(in, home, cwd), "Asks you before it reads files in ~/.config/telemetry/ and ./confidential/"; got != want {
		t.Errorf("runText of the owner's ~ form = %q, want %q", got, want)
	}
	if got := runText("Cannot read ~/.ssh/", h, ""); got != "Cannot read ~/.ssh/" {
		t.Errorf("a run whose home is the dashboard user's: %q", got)
	}
}

// TestLinePageLeftColumnRunHome: the line page's left column (Decided by, Rule, The question) names the token's
// folder as ~/.config/telemetry/, the run's home, as its headline does; the rule key in full stays in the titles.
func TestLinePageLeftColumnRunHome(t *testing.T) {
	s := newServer(t, videoFixture(t))
	c := login(t, s)
	page := get(t, s, c, "/runs/"+vidRight+"/lines/5")
	i, j := strings.Index(page, `id="h-dec"`), strings.Index(page, `id="h-who"`)
	if i < 0 || j < i {
		t.Fatal("no decision column on the line page")
	}
	col := html.UnescapeString(page[i:j])
	mustContain(t, "the left column", col, "alice, asked by fs.ask_read[~/.config/telemetry/]",
		"Asks you before it reads files in ~/.config/telemetry/", `title="fs.ask_read[/d/with/home/.config/telemetry/]">fs.ask_read[~/.config/telemetry/]<`,
		`<span class="soft">asked by</span> <span class="mono ev-wrap" title="fs.ask_read[/d/with/home/.config/telemetry/]">fs.ask_read[~/.config/telemetry/]<`)
	for _, line := range strings.Split(col, "\n") {
		if strings.Contains(strings.ReplaceAll(line, `title="fs.ask_read[/d/with/home/.config/telemetry/]"`, ""), "/d/with/home") {
			t.Errorf("the left column names the run's home in full outside a title: %s", line)
		}
	}
}

// TestLiftWhatRunHome: the fence row and the lift preview write a read entry's folder as Logs does, from the run's
// home; a run that could not be read falls back to the dashboard user's.
func TestLiftWhatRunHome(t *testing.T) {
	run := &ledgerview.Run{ID: "r-x", Cwd: "/d/with/proj"}
	if got := liftWhat(string(liveblock.KindRead), "/d/with/proj/datasets", run); got != "read ./datasets" {
		t.Errorf("a folder of the project: %q", got)
	}
	if got := liftWhat(string(liveblock.KindNet), "api.stripe.com:443", run); got != "connect to api.stripe.com:443" {
		t.Errorf("a destination: %q", got)
	}
	if h := homeDir(); h != "" {
		if got := liftWhat(string(liveblock.KindRead), h+"/datasets", nil); got != "read ~/datasets" {
			t.Errorf("no run: %q", got)
		}
	}
}

// TestModelRequestRowWords: a Logs row of a model request reads as one ("model request to api.anthropic.com"),
// never as its kind's name, and Logs' Kind facet names the kind in words.
func TestModelRequestRowWords(t *testing.T) {
	req := ledgerview.Event{Kind: "ssl_request", Op: "ssl_request", Raw: `{"endpoint":"anthropic","method":"POST","host":"api.anthropic.com"}`}
	if op, what := shownOp(req), shown(req); op != "model request to" || what != "api.anthropic.com" {
		t.Errorf("request row: %q %q", op, what)
	}
	// A recorded answer (record.SSLResponsePayload) names no server, so its row reads "model answer" alone.
	resp := ledgerview.Event{Kind: "ssl_response", Op: "ssl_response", Raw: `{"status":200,"request_seq":3}`}
	if op, what := shownOp(resp), shown(resp); op != "model answer" || what != "" {
		t.Errorf("answer row: %q %q", op, what)
	}
	bare := ledgerview.Event{Kind: "ssl_request", Op: "ssl_request", Raw: `{}`}
	if op, what := shownOp(bare), shown(bare); op != "model request" || what != "" {
		t.Errorf("a request naming no server: %q %q", op, what)
	}
	if kindWords["ssl_request"] != "Model requests" || kindWords["ssl_response"] != "Model answers" {
		t.Error("Logs' Kind facet names the model kinds by their ledger names")
	}
}

// TestRowActionsLabelledApart: a row's actions say what they do (Block this, Make a rule), so an allowed line's Rule
// column never seems to read "Block".
func TestRowActionsLabelledApart(t *testing.T) {
	s := newServer(t, videoFixture(t))
	var b strings.Builder
	acts := rowActs{E: ledgerview.Event{Run: "r-x", Seq: 4, Kind: "net"}, Block: "/runs/r-x?block=net&value=h%3A443#block", Rule: true}
	if err := s.pages["logs"].ExecuteTemplate(&b, "rulelink", acts); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	mustContain(t, "a row's actions", out, `>Block this</a>`, `>Make a rule</a>`)
	if strings.Contains(out, `>Block</a>`) || strings.Contains(out, `>Rule</a>`) {
		t.Errorf("a row action reads Block or Rule alone: %s", out)
	}
}
