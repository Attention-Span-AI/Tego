// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"net/http"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/control/rules"
)

// TestHistoryListIsTheServicesWords (C130): the Change rules page's history lists each journal entry the rule service
// reads in the service's one wording (HistoryEntry.What), and offers Undo on the entries the service says can be undone
// (HistoryEntry.Undoable). `tego rules history` prints the same words and the same Undo rule from the same service, so
// the page and the terminal list one history.
func TestHistoryListIsTheServicesWords(t *testing.T) {
	f := newChangeFix(t)
	for _, e := range []rules.Edit{{Op: "add", Key: "fs.write", Entry: "./more/"}, {Op: "add", Key: "exec.allow", Entry: anyProgram}} {
		c := f.ref(t, f.source)
		req := rules.ChangeReq{Ref: c.Ref, Base: c.Base, Edits: []rules.Edit{e}}
		p, err := f.svc.PlanChange(t.Context(), req)
		if err != nil || p.Err != "" {
			t.Fatalf("plan %+v: %+v %v", e, p, err)
		}
		req.Ack = p.Ack
		if _, err := f.svc.ApplyChange(t.Context(), req); err != nil {
			t.Fatalf("apply %+v: %v", e, err)
		}
	}
	f.historyIsOnThePage(t, f.source, 2, 1)
	// A free edit, its undo and the undo of that undo (a redo) of another rules file: the rows `tego rules history`
	// is held to as well (TestRulesHistoryIsTheDashboardsHistory), each worded by the service alone.
	c := f.ref(t, f.other)
	raw := rules.RawReq{Ref: c.Ref, Base: c.Base, Text: []byte(strings.Replace(readText(t, f.other), "[sh]", "[sh, ls]", 1))}
	pr, err := f.svc.PlanRaw(t.Context(), raw)
	if err != nil || pr.Err != "" {
		t.Fatalf("plan the free edit: %+v %v", pr, err)
	}
	raw.Ack = pr.Ack
	if _, err := f.svc.ApplyRaw(t.Context(), raw); err != nil {
		t.Fatalf("apply the free edit: %v", err)
	}
	for _, what := range []string{"undo", "redo"} {
		hs, err := f.svc.History(c.Ref)
		if err != nil || len(hs) == 0 || !hs[0].Undoable(f.ref(t, f.other).Base) {
			t.Fatalf("before the %s: %+v %v", what, hs, err)
		}
		if _, err := f.svc.Revert(t.Context(), rules.RevertReq{ID: hs[0].ID, Base: f.ref(t, f.other).Base, Ack: hs[0].Ack}); err != nil {
			t.Fatalf("the %s: %v", what, err)
		}
	}
	// After a redo the file holds the text of the free edit again, so the free edit (not undone any more, as the journal
	// folds it: a revert that is itself undone does not undo its target) and the redo both stand, and both are offered.
	f.historyIsOnThePage(t, f.other, 3, 2)
}

// historyIsOnThePage: the page of the rules file at path lists its want journal entries in the service's words and
// offers Undo on the entries the service says can be undone, wantUndo of them.
func (f *changeFix) historyIsOnThePage(t *testing.T, path string, want, wantUndo int) {
	t.Helper()
	ref := f.ref(t, path)
	hs, err := f.svc.History(ref.Ref)
	if err != nil || len(hs) != want {
		t.Fatalf("history of %s: %+v %v", path, hs, err)
	}
	code, page := f.get(t, "/rules/change?c="+ref.Ref)
	if code != http.StatusOK {
		t.Fatalf("the Change rules page: %d", code)
	}
	base := f.ref(t, path).Base
	undo := 0
	for _, h := range hs {
		if !strings.Contains(page, html.EscapeString(h.What())) {
			t.Errorf("the page does not list %q for %s", h.What(), h.ID)
		}
		has := strings.Contains(page, `name="id" value="`+h.ID+`"`)
		if has != h.Undoable(base) {
			t.Errorf("%s: the page offers Undo %t, the service says %t", h.ID, has, h.Undoable(base))
		}
		if h.Undoable(base) {
			undo++
		}
	}
	if undo != wantUndo {
		t.Errorf("%d entries can be undone, want %d: %+v", undo, wantUndo, hs)
	}
}
