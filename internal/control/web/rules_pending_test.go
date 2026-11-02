// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/shellword"
)

// TestPendingLiveStates: a pending change's chip on the running run, from what the rule service says of it and the
// run's record: Live now since line #N once every placed block is confirmed, Requested before, Recorded only on a
// watched run, and Next run with Apply now (a block to place), with why (none), or saying its block was removed.
func TestPendingLiveStates(t *testing.T) {
	sh := shortener{cwd: "/p", home: "/h"}
	lb := runact.LiveBlocks{Serials: map[string]uint64{"exec:git": 2}, Serial: 2}
	placed := rules.PendingNow{ID: "c1", Placed: []string{"exec:git"}}
	confirmed := ledgerview.LiveFacts{Confirmed: 2, ConfirmedSeq: 9}
	for _, c := range []struct {
		name  string
		pn    rules.PendingNow
		ok    bool
		facts ledgerview.LiveFacts
		state string
		label string
		apply bool
	}{
		{"requested", placed, true, ledgerview.LiveFacts{Confirmed: 1}, "requested", "Requested", false},
		{"recorded", placed, true, ledgerview.LiveFacts{}, "recorded", "Recorded only (watched run)", false},
		{"next with apply", rules.PendingNow{ID: "c1", Options: []rules.NowOption{{OK: true, Block: "write:/p/tmp"}}}, true, confirmed, "next", "Next run", true},
		{"next with why", rules.PendingNow{ID: "c1", Options: []rules.NowOption{{Why: "an ask cannot be added live"}}}, true, confirmed, "next", "Next run", false},
		{"not read", rules.PendingNow{}, false, confirmed, "next", "Next run", false},
		{"placed then removed", rules.PendingNow{ID: "c1", Placed: []string{"read:/p/vault"}}, true, confirmed, "next", "Next run", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.name == "recorded" {
				c.facts.Observe = true
			}
			pl := pendingLiveOf(c.pn, c.ok, c.facts, lb, sh, time.Now())
			if pl.State != c.state || pl.Label != c.label || pl.CanApply != c.apply {
				t.Errorf("%+v, want %s %q apply %v", pl, c.state, c.label, c.apply)
			}
			if c.name == "next with why" && !strings.Contains(pl.Note, "an ask cannot be added live") {
				t.Errorf("note %q", pl.Note)
			}
			if c.name == "next with apply" && (len(pl.Blocks) != 1 || pl.Blocks[0] != (pendingBlock{Words: "Changes to ./tmp (reads still go through)", Key: "write:./tmp"})) {
				t.Errorf("blocks %+v", pl.Blocks)
			}
			if c.name == "placed then removed" && (pl.Note != "Its live block was removed from this run; the next run gets the change." || len(pl.Blocks) != 0) {
				t.Errorf("a removed block: note %q blocks %+v", pl.Note, pl.Blocks)
			}
		})
	}
	// Live now: the confirming line's seq is the Since of the first line confirming serial 2 (a run's own facts carry
	// it; here, the facts of a loaded fixture).
	_, rr := liveFixture(t, "landlock", 2)
	pl := pendingLiveOf(placed, true, ledgerview.LiveFactsOf(rr), lb, sh, time.Now())
	if pl.State != "live" || pl.Label != "Live now since line #1" {
		t.Errorf("live: %+v", pl)
	}
}

// TestRulesPagePendingApplyNow: on a running run whose rules file was narrowed without "Also apply now", the Rules
// page shows "Changed since this run started" with the change as Next run and an Apply now button, and the command
// that starts the next run; Apply now places the live block through the rule service and journals it, and the page
// then says Requested (no launcher confirms it in this test). An ended run keeps the plain banner.
func TestRulesPagePendingApplyNow(t *testing.T) {
	s, c, _, _ := askServer(t)
	svc := s.cfg.Rules.(*rules.Service)
	holdLock(t, filepath.Join(s.cfg.Ledger, actRun))
	refs, err := svc.Contracts()
	if err != nil || len(refs) != 1 {
		t.Fatalf("contracts %+v %v", refs, err)
	}
	a, err := svc.ApplyChange(context.Background(), rules.ChangeReq{Ref: refs[0].Ref, Base: refs[0].Base,
		Edits: []rules.Edit{{Op: "remove", Key: "exec.allow", Entry: "git"}}})
	if err != nil || a.ID == "" {
		t.Fatalf("apply %+v %v", a, err)
	}
	page := do(s, "GET", "/rules?run="+actRun, "127.0.0.1:8484", c).Body.String()
	mustContain(t, "the pending panel", page, "Changed since this run started", "Cannot run git", `data-state="next"`, "Next run",
		`name="do" value="applynow"`, `name="id" value="`+a.ID+`"`, "Apply now", "Stop this run", "tego run ")
	w := post(s, "/rules/change", url.Values{"csrf": {s.csrf}, "do": {"applynow"}, "id": {a.ID}, "run": {actRun}}, own, "", c)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("apply now: %d %s", w.Code, w.Body.String())
	}
	page = follow(t, s, c, w)
	mustContain(t, "after Apply now", page, "Putting it in force on this run now (1 live block).", `data-state="requested"`, "Requested", "Running git", `title="exec:git"`)
	if strings.Contains(page, `name="do" value="applynow"`) {
		t.Error("Apply now is still offered after the block was placed")
	}
	bs, err := runact.Blocks(s.cfg.Ledger, actRun)
	if err != nil || len(bs) != 1 || bs[0].Key() != "exec:git" {
		t.Errorf("live blocks %+v %v", bs, err)
	}
	// A second Apply now places nothing and says why.
	page = follow(t, s, c, post(s, "/rules/change", url.Values{"csrf": {s.csrf}, "do": {"applynow"}, "id": {a.ID}, "run": {actRun}}, own, "", c))
	mustContain(t, "a second Apply now", page, "Nothing was applied")
}

// TestLiveWordsAndRestartWords: a live block key reads as what it covers, its path shortened; a restart line's words
// are quoted exactly (shellword.Quote, which startCommand calls), a leading or trailing space kept.
func TestLiveWordsAndRestartWords(t *testing.T) {
	sh := shortener{cwd: "/p", home: "/h"}
	for key, want := range map[string]string{
		"exec:uname":          "Running uname",
		"exec:/p/bin/":        "Running programs in ./bin/",
		"net:example.com:443": "Connections to example.com:443",
		"path:/h/.ssh":        "Opening or changing ~/.ssh",
		"read:/p/data/x.txt":  "Reads of ./data/x.txt",
		"write:/p":            "Changes to . (reads still go through)",
		"odd":                 "odd",
	} {
		if got := liveWords(key, sh); got != want {
			t.Errorf("liveWords(%q) = %q, want %q", key, got, want)
		}
	}
	for in, want := range map[string]string{"sh": "sh", " fix it ": "' fix it '", "it's": `'it'\''s'`, "": "''"} {
		if got := shellword.Quote(in); got != want {
			t.Errorf("shellword.Quote(%q) = %q, want %q", in, got, want)
		}
	}
}
