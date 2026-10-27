// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rowActsFixture is fixture plus an allowed exec and an allowed net line on the live run, and the same on the ended
// run.
func rowActsFixture(t *testing.T) string {
	t.Helper()
	root := fixture(t)
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	add := func(run, agent string, seq int, ls ...string) {
		f, err := os.OpenFile(filepath.Join(root, run, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		if _, err := f.WriteString(strings.Join(ls, "")); err != nil {
			t.Fatal(err)
		}
	}
	add(harmRun, "demo-harm", 7,
		line(harmRun, "demo-harm", 7, t0.Add(time.Minute+7), "exec", `"verdict":"allow","rule":"exec[curl]","argv":["curl","-s","http://example.com/x"],"path":"/usr/bin/curl","exec_id":"e1"`),
		line(harmRun, "demo-harm", 8, t0.Add(time.Minute+8), "net", `"verdict":"allow","rule":"net[example.com:443]","proto":"tcp","dst":"93.184.216.34:443","host":"example.com"`))
	return root
}

// A live run's exec and net rows that were allowed offer Block, linking to the run page's Block now panel with the
// program or destination filled in; a refused row, a row of an ended run and an fs row do not; the row's Rule link is
// compact (one row-acts group beside the verdict), never a line of its own.
func TestRowActionsOfferBlockOnLiveRuns(t *testing.T) {
	s := newServer(t, rowActsFixture(t))
	c := login(t, s)
	body := do(s, "GET", "/runs/"+harmRun, "127.0.0.1:8484", c).Body.String()
	for _, want := range []string{
		`href="/runs/` + harmRun + `?block=exec&amp;value=curl#block"`,
		`href="/runs/` + harmRun + `?block=net&amp;value=example.com%3A443#block"`,
		`<span class="row-acts">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("live run page lacks %s", want)
		}
	}
	// The pending ask's net row (verdict ask) and the allowed net row name the same host; the refusals offer none.
	if n := strings.Count(body, `class="link row-act act-block"`); n != 3 {
		t.Errorf("%d Block links on the live run page, want 3 (the exec row, the ask and the allowed net row; not the refusals)", n)
	}
	// The run names no contract file (as a tego watch run), so no row can become a rule: no Rule link at all.
	if strings.Contains(body, `class="link row-act" href="/runs/`+harmRun+`/lines/`) {
		t.Error("a run with no contract file offers Rule links")
	}
	logs := do(s, "GET", "/logs?run="+harmRun, "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(logs, `?block=exec&amp;value=curl#block`) {
		t.Error("a live run's exec row in the logs lacks Block")
	}
	clean := do(s, "GET", "/runs/"+cleanRun, "127.0.0.1:8484", c).Body.String()
	if strings.Contains(clean, "act-block") {
		t.Error("an ended run offers Block")
	}
}

// The Block now panel opens filled in from the Block link's query string, and ignores a kind it does not know. It
// names its terminal twin, tego block, now that a block answers with one line instead of a done page.
func TestBlockPanelPrefill(t *testing.T) {
	s := newServer(t, rowActsFixture(t))
	c := login(t, s)
	body := do(s, "GET", "/runs/"+harmRun+"?block=net&value=example.com%3A443", "127.0.0.1:8484", c).Body.String()
	for _, want := range []string{`<option value="net" selected>`, `value="example.com:443"`,
		"<code>tego block " + harmRun + " &lt;exec|net|path&gt; &lt;value&gt;</code>", "<code>tego block --list " + harmRun + "</code>"} {
		if !strings.Contains(body, want) {
			t.Errorf("prefilled panel lacks %s", want)
		}
	}
	body = do(s, "GET", "/runs/"+harmRun+"?block=bogus&value=x", "127.0.0.1:8484", c).Body.String()
	if strings.Contains(body, ` selected>`) || strings.Contains(body, `value="x"`) {
		t.Error("an unknown kind prefilled the panel")
	}
}

// When the contract could not be recompiled here, a rule the run named is not declared "Not in policy": the page
// says it cannot tell.
func TestUnusedTabDoesNotClaimWhatItCannotKnow(t *testing.T) {
	root := fixture(t)
	if err := os.WriteFile(filepath.Join(root, harmRun, "contract.yaml"), []byte("version: 0\nfs:\n  write: [\"./out/\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	body := do(s, "GET", "/runs/"+harmRun+"/unused", "127.0.0.1:8484", c).Body.String()
	if !strings.Contains(body, "Policy unknown here") || strings.Contains(body, `<span class="muted">Not in policy</span>`) {
		t.Errorf("unused tab of a contract that was not recompiled:\n%s", body)
	}
}

// When the copy cannot be compiled here, the tab still counts the entries the contract text declares: an entry no
// line used reads "Granted but never used", and one line of note says where the counts come from.
func TestUnusedTabCountsFromTextWhenItCannotCompile(t *testing.T) {
	root := fixture(t)
	if err := os.WriteFile(filepath.Join(root, harmRun, "contract.yaml"), []byte("version: 0\nfs:\n  write: [\"./never-written/\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newServer(t, root)
	c := login(t, s)
	body := do(s, "GET", "/runs/"+harmRun+"/unused", "127.0.0.1:8484", c).Body.String()
	for _, want := range []string{"counted from its text", "./never-written/", "Granted but never used", "1 of 1 contract entry granted but never used"} {
		if !strings.Contains(body, want) {
			t.Errorf("unused tab lacks %q:\n%s", want, body)
		}
	}
}
