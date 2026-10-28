// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/rulefile"
)

var (
	undoForm  = regexp.MustCompile(`(?s)<form class="ev-undo" id="act-undo".*?</form>`)
	undoField = regexp.MustCompile(`name="(undo|base|ack)" value="([^"]*)"`)
)

// undoFields is the event page's Undo form's hidden fields and its ack value, from page.
func undoFields(t *testing.T, page string) (url.Values, string) {
	t.Helper()
	f := undoForm.FindString(page)
	if f == "" {
		t.Fatalf("the page has no Undo form:\n%s", page)
	}
	v := url.Values{}
	for _, m := range undoField.FindAllStringSubmatch(f, -1) {
		v.Set(m[1], html.UnescapeString(m[2]))
	}
	return v, f
}

// savedWithBlock saves "Cannot run git" on the live run's line #4 with Also apply now, returning the Saved page.
func savedWithBlock(t *testing.T) (*Server, string, string) {
	t.Helper()
	s, c, _, _ := askServer(t)
	holdLock(t, filepath.Join(s.cfg.Ledger, actRun))
	line := "/runs/" + actRun + "/lines/4"
	preview := do(s, "GET", line+"?a=block&level=0", "127.0.0.1:8484", c).Body.String()
	saved := follow(t, s, c, post(s, line, url.Values{"csrf": {s.csrf}, "a": {"block"}, "level": {"0"}, "base": {baseOf(t, preview)}, "now": {actRun}}, own, "", c))
	if bs, err := runact.Blocks(s.cfg.Ledger, actRun); err != nil || len(bs) != 1 || bs[0].Key() != "exec:git" {
		t.Fatalf("live blocks after the save: %+v %v", bs, err)
	}
	return s, line, saved
}

// TestUndoLiftsLiveBlockFromEventPage: the Saved panel's Undo of a narrowing applied live offers, ticked, to lift the
// live block it placed on this run; undoing with the box lifts it from the run's overlay, the line says so, and the
// journal records the lift on the revert. Without the box the block stays and the line says that instead.
func TestUndoLiftsLiveBlockFromEventPage(t *testing.T) {
	t.Run("lift", func(t *testing.T) {
		s, line, saved := savedWithBlock(t)
		v, form := undoFields(t, saved)
		mustContain(t, "the Undo form", form, `name="lift" value="1" checked`, "Also lift the live block it placed", "on this run",
			"The run may do that again at once.", `name="ack"`)
		c := login(t, s)
		v.Set("csrf", s.csrf)
		v.Set("lift", "1")
		w := post(s, line, v, own, "", c)
		page := follow(t, s, c, w)
		mustContain(t, "the page after Undo", page, "The live block it placed is being lifted")
		if bs, err := runact.Blocks(s.cfg.Ledger, actRun); err != nil || len(bs) != 0 {
			t.Errorf("live blocks after the Undo with lift: %+v %v", bs, err)
		}
		es, err := rulefile.ReadJournal(s.cfg.Ledger)
		if err != nil || len(es) < 3 {
			t.Fatalf("journal %+v %v", es, err)
		}
		last := es[len(es)-1]
		if last.Op != rulefile.OpLive || last.Of != es[len(es)-2].ID || es[len(es)-2].Op != rulefile.OpRevert ||
			len(last.Live) != 1 || !last.Live[0].Lift || !last.Live[0].OK || last.Live[0].Block != "exec:git" {
			t.Errorf("the journal's lift: %+v", last)
		}
	})
	t.Run("keep", func(t *testing.T) {
		s, line, saved := savedWithBlock(t)
		v, _ := undoFields(t, saved)
		c := login(t, s)
		v.Set("csrf", s.csrf)
		page := follow(t, s, c, post(s, line, v, own, "", c))
		mustContain(t, "the page after Undo", page, "The live block it placed stays on its run until the run ends")
		if bs, err := runact.Blocks(s.cfg.Ledger, actRun); err != nil || len(bs) != 1 {
			t.Errorf("live blocks after the Undo without lift: %+v %v", bs, err)
		}
	})
}

// TestUndoLiveLine: what an Undo answer says of the undone change's live blocks.
func TestUndoLiveLine(t *testing.T) {
	for _, tc := range []struct {
		name string
		rv   rules.Reverted
		want string
	}{
		{"none", rules.Reverted{}, ""},
		{"one lifted", rules.Reverted{Lifted: []rules.LiveResult{{Run: "r", Block: "exec:git", OK: true, Lift: true}}},
			"The live block it placed is being lifted: within about a second its run may do that again."},
		{"two lifted, one failed", rules.Reverted{Lifted: []rules.LiveResult{{OK: true, Lift: true}, {OK: true, Lift: true},
			{Err: "not lifted: the run is not running", Lift: true}}},
			"The 2 live blocks it placed are being lifted: within about a second their runs may do that again. " +
				"A live block it placed was not lifted: the run is not running; remove it on the run's page."},
		{"kept", rules.Reverted{Kept: []rules.LiftOption{{}, {}}},
			"The 2 live blocks it placed stay on their runs until they end or you remove them on the run's page."},
	} {
		if got := undoLiveLine(&tc.rv); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	if strings.Contains(undoneLine(&rules.Reverted{Contract: "/p/agent.yaml"}), "stays until its run ends") {
		t.Error("an Undo with no live block still speaks of one")
	}
}

var histUndo = regexp.MustCompile(`(?s)<form class="rc-undo" method="post" action="/rules/revert">.*?</form>`)

// TestUndoLiftFromHistory: the Change rules page's History offers, on the Undo of the change that placed a live block
// on a running run, a ticked box that also lifts it; POST /rules/revert with it lifts the block and the Undone page
// says so, and the History then reads "lifted on" for the revert.
func TestUndoLiftFromHistory(t *testing.T) {
	s, _, _ := savedWithBlock(t)
	c := login(t, s)
	cs, err := s.cfg.Rules.(*rules.Service).Contracts()
	if err != nil || len(cs) != 1 {
		t.Fatalf("contracts %+v %v", cs, err)
	}
	page := do(s, "GET", "/rules/change?c="+cs[0].Ref, "127.0.0.1:8484", c).Body.String()
	form := histUndo.FindString(page)
	mustContain(t, "the History's Undo", form, `name="lift" value="1" checked`, "also lift its live block now", "Running git on "+shortRun(actRun))
	v := url.Values{}
	for _, m := range regexp.MustCompile(`name="(c|id|base|ack)" value="([^"]*)"`).FindAllStringSubmatch(form, -1) {
		v.Set(m[1], html.UnescapeString(m[2]))
	}
	v.Set("csrf", s.csrf)
	v.Set("lift", "1")
	undone := follow(t, s, c, post(s, "/rules/revert", v, own, "", c))
	mustContain(t, "the Undone page", undone, "Undone", "The live block it placed is being lifted", "lifted on "+shortRun(actRun)+": exec:git")
	if bs, err := runact.Blocks(s.cfg.Ledger, actRun); err != nil || len(bs) != 0 {
		t.Errorf("live blocks after the Undo with lift: %+v %v", bs, err)
	}
}
