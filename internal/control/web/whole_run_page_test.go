// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// The whole-run JSONL is the ledger, kind:refused lists the refusal notes, Processes counts them, the facets
// word watched rows as watched, and a live run's Processes tab is laid out once per procsHold.

const (
	noteRun    = "r-aaaaaaaa-0000000000009-notesx"
	r9WatchRun = "r-aaaaaaaa-0000000000010-watchx"
)

// noteFixture is one ended run with one refused read and the kind=refused line that mirrors it (a refusal note), and
// one watched run (tier observe) with a line no rule decided.
func noteFixture(t *testing.T) (root string, lines []string) {
	t.Helper()
	root = t.TempDir()
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	lines = []string{
		line(noteRun, "codex", 0, at(0), "run_start", `"tier":"landlock","command":["codex","exec"],"cwd":"/w/x/proj"`),
		line(noteRun, "codex", 1, at(1), "fs", `"verdict":"refused","rule":"fs.deny_read[~/.ssh]","reason":"read-denied","op":"open","path":"/w/x/home/.ssh/id_rsa","flags":0`),
		line(noteRun, "codex", 2, at(1), "refused", `"rule":"fs.deny_read[~/.ssh]","reason":"read-denied","op":"open","target":"/w/x/home/.ssh/id_rsa"`),
		line(noteRun, "codex", 3, at(2), "exec", `"verdict":"allow","rule":"exec.allow[ls]","path":"/bin/ls","argv":["ls"],"exec_id":"10:1","parent_exec_id":""`),
		line(noteRun, "codex", 4, at(3), "run_end", `"reason":"exit","exit_code":0`),
	}
	write := func(run string, ls ...string) {
		if err := os.MkdirAll(filepath.Join(root, run), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, run, "events.jsonl"), []byte(strings.Join(ls, "")), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(noteRun, lines...)
	write(r9WatchRun,
		line(r9WatchRun, "watch-codex", 0, at(10), "run_start", `"tier":"observe","command":["codex"],"cwd":"/w/x/proj"`),
		line(r9WatchRun, "watch-codex", 1, at(11), "fs", `"rule":"unmatched","verdict":"observed","op":"open","path":"/w/x/home/.config/token","flags":0`),
		line(r9WatchRun, "watch-codex", 2, at(12), "run_end", `"reason":"exit","exit_code":0`))
	return root, lines
}

func TestWholeRunJSONLIsTheLedger(t *testing.T) {
	root, lines := noteFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	if b := do(s, "GET", "/logs.jsonl?run="+noteRun, "127.0.0.1:8484", c).Body.String(); b != strings.Join(lines, "") {
		t.Errorf("the whole run's JSONL is not its events file (the refusal note left out?):\n%s", b)
	}
	if b := do(s, "GET", "/logs.jsonl?where="+url.QueryEscape("run:"+noteRun), "127.0.0.1:8484", c).Body.String(); b != strings.Join(lines, "") {
		t.Errorf("the whole run by the query's run: is not its events file:\n%s", b)
	}
	// Any narrowing gives the lines Logs counts: the refusal note is left out, and the title says so.
	if b := do(s, "GET", "/logs.jsonl?run="+noteRun+"&where=-kind:run", "127.0.0.1:8484", c).Body.String(); b != lines[1]+lines[3] {
		t.Errorf("narrowed JSONL:\n%s", b)
	}
	page := html.UnescapeString(get(t, s, c, "/logs?run="+noteRun))
	if !strings.Contains(page, "This run's whole ledger: all 5 lines of its events file") {
		t.Error("the whole run's JSONL button does not say it is the whole ledger")
	}
	page = html.UnescapeString(get(t, s, c, "/logs?run="+noteRun+"&where=-kind:run"))
	if !strings.Contains(page, "this is not a chain anything can check") {
		t.Error("a narrowed JSONL button does not say mirror lines are left out")
	}
	// where=kind:refused lists the refusal note, as the form's Kind=refused does.
	for _, q := range []string{"where=kind:refused", "kind=refused"} {
		if got := matchedOn(t, get(t, s, c, "/logs?run="+noteRun+"&"+q)); got != 1 {
			t.Errorf("/logs?%s: %d lines, want the 1 refusal note", q, got)
		}
	}
}

func TestProcessesCountsRefusalNotes(t *testing.T) {
	root, _ := noteFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	body := get(t, s, c, "/runs/"+noteRun+"/processes")
	if !strings.Contains(body, "4 actions · <span") || !strings.Contains(body, "1 refusal note</span>") {
		i := strings.Index(body, `id="h-pr"`)
		t.Errorf("the Processes count does not read 4 actions and 1 refusal note: %.300s", body[max(i, 0):])
	}
}

func TestFacetWordsForWatchedRows(t *testing.T) {
	root, _ := noteFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	body := get(t, s, c, "/logs?run="+r9WatchRun)
	if strings.Contains(body, ">Not in policy<") || !strings.Contains(body, ">Watched only<") {
		t.Error("the Rule facet calls a watched run's line Not in policy, not Watched only")
	}
	if strings.Contains(body, "No verdict") || !strings.Contains(body, ">Recorded<") {
		t.Error("the Verdict facet says No verdict, not Recorded")
	}
	// An enforced run's unmatched line keeps its words.
	if got := ruleName("unmatched"); got != "Not in policy" {
		t.Errorf("ruleName(unmatched) = %q", got)
	}
	if l, _ := facetRule("unmatched", false); l != "Not in policy" {
		t.Errorf("an enforced unmatched facet reads %q", l)
	}
	if l, _ := facetRule("fs.read[/etc]", true); l != "Watched only · Read: /etc" {
		t.Errorf("a watched rule facet reads %q", l)
	}
}

// TestProcsHeldOnALiveRun: a live run's tab is the same view (so the same bytes and region hash) for procsHold, then
// laid out again; an ended run is laid out every time.
func TestProcsHeldOnALiveRun(t *testing.T) {
	root, lines := noteFixture(t)
	t0 := time.Date(2026, 10, 25, 12, 5, 0, 0, time.UTC)
	load := func() *ledgerview.Run {
		r, err := ledgerview.LoadRun(root, noteRun)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if a, b := procsFor(root, load(), t0), procsFor(root, load(), t0); a == b {
		t.Error("an ended run's tab was held")
	}
	// Live: no run_end yet, and the live marker.
	if err := os.WriteFile(filepath.Join(root, noteRun, "events.jsonl"), []byte(strings.Join(lines[:4], "")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".live"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".live", noteRun), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	r := load()
	if r.State() != "running" {
		t.Fatalf("the fixture run is %s, want running", r.State())
	}
	first := procsFor(root, r, t0)
	if procsFor(root, load(), t0.Add(procsHold-time.Millisecond)) != first {
		t.Error("a live run's tab was laid out again inside procsHold")
	}
	if procsFor(root, load(), t0.Add(procsHold)) == first {
		t.Error("a live run's tab was still held after procsHold")
	}
	if procsFor(t.TempDir(), r, t0) == first {
		t.Error("another ledger root's run of the same id shared the held tab")
	}
}
