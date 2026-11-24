// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/control/agents"
)

// AgentsService supplies private agent evidence. The service opens saved results
// and records and owns remembered discoveries. Load never launches a scan.
type AgentsService interface {
	Load(context.Context, time.Time) agents.View
}

// agentsForgetter is what a service offers to drop one remembered discovery (the default service does). A
// service without it answers the Forget form with a line saying nothing was forgotten.
type agentsForgetter interface {
	Forget(ctx context.Context, id string, now time.Time) error
}

// home keeps Overview available at /overview. Only the guide's completed fact
// makes Agents the home; opening or leaving a page cannot complete the guide.
func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	if s.cfg.Agents != nil {
		v := s.agentsView(r.Context())
		if v.GuideDone {
			s.renderAgents(w, r, v, "")
			return
		}
	} else if s.cfg.Guide != nil {
		// Reuse Overview's bounded guide cache while setup is in progress.
		// Agents itself rechecks its scan when the completed guide selects it.
		snap, ok := s.load(w)
		if !ok {
			return
		}
		if g := s.setupGuide(r.Context(), snap); g != nil && g.Done {
			s.agentsPage(w, r)
			return
		}
	}
	s.overview(w, r)
}

func (s *Server) agentsService() AgentsService {
	if s.cfg.Agents != nil {
		return s.cfg.Agents
	}
	return agents.Service{Inputs: s.cfg.Guide, Ledger: s.cfg.Ledger}
}

func (s *Server) agentsView(ctx context.Context) agents.View {
	return s.agentsService().Load(ctx, s.cfg.Now())
}

// agentsPage and agentPage are the page's two reads: the list at /agents and one identity's detail at
// /agents/<id>. Both are rendered from the same View, so a row and its detail never disagree.
func (s *Server) agentsPage(w http.ResponseWriter, r *http.Request) {
	s.renderAgents(w, r, s.agentsView(r.Context()), "")
}
func (s *Server) agentPage(w http.ResponseWriter, r *http.Request) {
	s.renderAgents(w, r, s.agentsView(r.Context()), strings.TrimPrefix(r.URL.Path, "/agents/"))
}

// agentsData is what the Agents page template reads. V is the data layer's answer untouched; the rest is the
// page's own arrangement of it, never new facts.
type agentsData struct {
	V    agents.View
	Rows []agentRow
	// One is the identity a detail page shows, nil on the list.
	One *agentRow
	// Recorded and Seen count the listed rows by kind: a recorded run, or a program only a scan saw.
	Recorded, Seen int
}

// agentRow is a row as the page lays it out.
type agentRow struct {
	agents.Row
	// Kind is "run" for a recorded run's row, "remembered" for a program seen by an earlier scan and "seen" for one
	// the latest scan lists.
	Kind string
	// Ticks are the five stages. On is set only where the data established the stage for the named run: an
	// observation sets none.
	Ticks []agentTick
	// Where is the row's one sentence of where it was seen or recorded, as the data layer wrote it; the page adds
	// the time (Row.WhereAt) and the folder after it.
	Where string
	// WhereNote is the data layer's closing clause of a recorded run's sentence, shown after the folder.
	WhereNote string
	// RunLinks are the recorded runs the data relates to this row, each linked to its own page.
	RunLinks []string
	// Forget is whether the row can be forgotten: only a remembered discovery, never a recorded run.
	Forget bool
}

type agentTick struct {
	ID, Label                     string
	On                            bool
	Text, Source, CannotTell, Run string
}

func agentRowOf(r agents.Row) agentRow {
	row := agentRow{Row: r, Kind: "seen", Where: r.Membership}
	switch {
	case r.Agent.RunID != "":
		row.Kind = "run"
	case r.Remembered && r.NotSeenLatest, r.Stage == "Previously seen":
		row.Kind = "remembered"
	}
	if r.Agent.RunID != "" {
		row.WhereNote = "The stages below describe that run."
	}
	for _, st := range r.Agent.Stages {
		row.Ticks = append(row.Ticks, agentTick{ID: st.ID, Label: st.Label, On: st.Fact.Established && r.Agent.RunID != "",
			Text: st.Fact.Text, Source: st.Fact.Source, CannotTell: st.Fact.CannotTell, Run: st.Fact.RunID})
	}
	row.RunLinks = r.Agent.RelatedRunIDs
	row.Forget = r.Remembered && r.Agent.RunID == ""
	return row
}

func (s *Server) renderAgents(w http.ResponseWriter, r *http.Request, v agents.View, id string) {
	d := agentsData{V: v}
	for _, row := range v.Rows {
		ar := agentRowOf(row)
		if ar.Kind == "run" {
			d.Recorded++
		} else {
			d.Seen++
		}
		if id != "" {
			if row.ID == id {
				one := ar
				d.One = &one
			}
			continue
		}
		d.Rows = append(d.Rows, ar)
	}
	if id != "" && d.One == nil {
		s.fail(w, http.StatusNotFound, "Agent not found", "This identity is not in the current evidence. Refresh Agents to see the saved result.")
		return
	}
	snap, ok := s.load(w)
	if !ok {
		return
	}
	title := "Agents"
	if d.One != nil {
		title = "Agent " + d.One.Name
	}
	c := s.chromeOf(snap, title, "agents")
	c.PhoneName = "Agents"
	if r.Method == http.MethodHead {
		w = headOnly{w}
	}
	s.render(w, http.StatusOK, "agents", c, d)
}

// headOnly keeps a HEAD answer's headers and drops its body.
type headOnly struct{ http.ResponseWriter }

func (headOnly) Write(p []byte) (int, error) { return len(p), nil }

// Unwrap lets render find the tour's writer beneath.
func (h headOnly) Unwrap() http.ResponseWriter { return h.ResponseWriter }

// agentsForget is the Forget form's POST (routePost has already checked the peer, the session, the origin, the
// token and that the caller is not a governed program). It names one remembered discovery by its row ID; the data
// layer drops that entry under the store's own lock and checks and touches nothing else: never a run record, a
// saved scan or a contract.
func (s *Server) agentsForget(w http.ResponseWriter, r *http.Request) {
	id := r.PostForm.Get("agent")
	back := "/agents"
	f, ok := s.agentsService().(agentsForgetter)
	var err error
	switch {
	case !ok:
		err = agents.ErrForgetUnavailable
	case id == "" || len(id) > 200:
		err = agents.ErrNotRemembered
	default:
		err = f.Forget(r.Context(), id, s.cfg.Now())
	}
	if err == nil {
		s.redirectBack(w, r, back, flash{OK: true, Text: "Forgot this remembered sighting. Recorded runs were not changed. If the latest saved scan still lists the program, the page remembers it again."})
		return
	}
	text := "Nothing was forgotten."
	switch {
	case errors.Is(err, agents.ErrNotRemembered):
		text += " This sighting is not remembered any more; refresh the page."
	case errors.Is(err, agents.ErrForgetBusy):
		text += " The store is busy; try again."
	case errors.Is(err, agents.ErrForgetUnsafe):
		text += " The store could not be read safely; the page shows the repair steps."
	case errors.Is(err, agents.ErrForgetSave):
		text += " The change could not be saved."
	default:
		text += " This dashboard cannot change remembered sightings."
	}
	s.redirectBack(w, r, back, flash{OK: false, Text: text})
}

// agentScanWord names a saved scan's state in a word, the word of its badge.
func agentScanWord(status string) string {
	switch status {
	case "fresh":
		return "Fresh"
	case "stale":
		return "Old"
	case "another-boot":
		return "Another boot"
	case "future":
		return "Future time"
	case "failed":
		return "Failed"
	case "unreadable":
		return "Unreadable"
	case "missing":
		return "Not saved yet"
	case "unavailable":
		return "Not configured"
	}
	return "Cannot be checked"
}

// agentScanClass is the badge class of that word: plain for a usable scan, dashed for one that is only history,
// red for one that cannot be read at all.
func agentScanClass(status string) string {
	switch status {
	case "fresh":
		return "b-neutral"
	case "stale", "another-boot", "future":
		return "b-outside"
	case "failed", "unreadable":
		return "b-broken"
	}
	return "b-outside"
}

// agentTime is a time as the page writes it: local, to the minute, with the zone.
func agentTime(t time.Time) string {
	if t.IsZero() {
		return "time unknown"
	}
	return t.Local().Format("2006-01-02 15:04 MST")
}

// agCopy is an exact-copy control's data: the element id its button copies from, the text, and what the button's
// accessible name says it copies.
func agCopy(id, text, what string) struct{ ID, Text, What string } {
	return struct{ ID, Text, What string }{id, text, what}
}

// agDetail is the detail template's data: the row, and the session's form token for its one form.
func agDetail(r agentRow, csrf string) struct {
	R    agentRow
	CSRF string
} {
	return struct {
		R    agentRow
		CSRF string
	}{r, csrf}
}
