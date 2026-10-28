// SPDX-License-Identifier: Apache-2.0

package web

import (
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"sync"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/mcpact"
)

// The MCP tools page (ADR 0126 §6): per run, each declared MCP server, whether it is behind Tego's relay, and per
// tool Allow / Ask / Deny switches the relay applies to the next call. A tightening applies at once; a loosening goes
// to a preview whose acknowledgement mcpact binds to the overlay it was shown against. The page makes no decision of its
// own: it parses forms and calls internal/control/mcpact, which writes, after ServeHTTP's governed-peer, session and CSRF checks.

// mcpService is the service the page calls; a test replaces it.
var mcpService = mcpact.New

// maxMCPRuns bounds the runs the picker reads a contract of.
const maxMCPRuns = 30

// mcpPageSet parses the MCP pages apart from pageNames, as the event page is: two new templates, the shared layout.
var mcpPageSet = sync.OnceValues(func() (map[string]*template.Template, error) {
	out := map[string]*template.Template{}
	for _, n := range []string{"mcp-tools", "mcp-preview"} {
		t, err := template.New("layout.tmpl").Funcs(funcs).ParseFS(assets, "templates/layout.tmpl", "templates/rulelink.tmpl", "templates/"+n+".tmpl")
		if err != nil {
			return nil, err
		}
		if err := escapeRegions(n, t); err != nil {
			return nil, err
		}
		out[n] = t
	}
	return out, nil
})

// mcpRunOpt is one run in the picker.
type mcpRunOpt struct {
	ID, Label string
	Live      bool
	Selected  bool
}

// mcpData is the MCP tools page's data.
type mcpData struct {
	Runs  []mcpRunOpt
	State *mcpact.State
	Err   string
	CSRF  string
}

// mcpPreviewData is the loosening preview's data.
type mcpPreviewData struct {
	Plan *mcpact.Plan
	Err  string
	CSRF string
	Back string
}

// mcpGet answers the MCP pages' GETs; false for any other path.
func (s *Server) mcpGet(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/mcp":
		s.mcpTools(w, r)
	case "/mcp/preview":
		s.mcpPreview(w, r)
	default:
		return false
	}
	return true
}

// mcpPost answers the MCP pages' POSTs; false for any other path.
func (s *Server) mcpPost(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/mcp/set":
		s.mcpSet(w, r, false)
	case "/mcp/reset":
		s.mcpSet(w, r, true)
	default:
		return false
	}
	return true
}

func (s *Server) renderMCP(w http.ResponseWriter, r *http.Request, snap *ledgerview.Snapshot, name, title string, data any) {
	c := s.chromeOf(snap, title, "mcp")
	c.Host, c.Ledger, c.CSRF, c.Preview = s.host, s.cfg.Ledger, s.csrf, s.cfg.Preview
	// No live regions yet: live.js leaves a page without a signature alone (a reload shows new counts).
	c.Sig, c.Rev = "", ""
	if fw, ok := w.(*flashWriter); ok {
		c.Flash = fw.flash
	}
	set, err := mcpPageSet()
	if err != nil {
		http.Error(w, "tego-control serve: template "+name+": "+err.Error(), http.StatusInternalServerError)
		return
	}
	renderPage(w, http.StatusOK, set[name], name, page{chrome: c, Data: data})
}

func (s *Server) mcpTools(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.load(w)
	if !ok {
		return
	}
	svc := mcpService(s.cfg.Ledger)
	d := mcpData{CSRF: s.csrf}
	want := r.URL.Query().Get("run")
	// Live runs first, then the newest; only runs that declare an MCP server.
	var live, ended []mcpRunOpt
	for i, rr := range snap.Runs {
		if i >= maxMCPRuns {
			break
		}
		if !svc.HasMCP(rr.ID) {
			continue
		}
		o := mcpRunOpt{ID: rr.ID, Label: rr.Agent + " · " + shortRun(rr.ID), Live: rr.Live}
		if rr.Agent == "" {
			o.Label = shortRun(rr.ID)
		}
		if rr.Live {
			live = append(live, o)
		} else {
			ended = append(ended, o)
		}
	}
	live = append(live, ended...)
	d.Runs = live
	if want == "" && len(d.Runs) > 0 {
		want = d.Runs[0].ID
	}
	for i := range d.Runs {
		d.Runs[i].Selected = d.Runs[i].ID == want
	}
	if want != "" {
		st, err := svc.State(want)
		if err != nil {
			d.Err = mcpErrWords(err)
		} else {
			d.State = st
		}
	}
	s.renderMCP(w, r, snap, "mcp-tools", "MCP tools", d)
}

func (s *Server) mcpPreview(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.load(w)
	if !ok {
		return
	}
	q := r.URL.Query()
	run, server, tool, decision := q.Get("run"), q.Get("server"), q.Get("tool"), q.Get("decision")
	svc := mcpService(s.cfg.Ledger)
	d := mcpPreviewData{CSRF: s.csrf, Back: "/mcp?run=" + url.QueryEscape(run)}
	var p *mcpact.Plan
	var err error
	if decision == "reset" {
		p, err = svc.PlanReset(run, server, tool)
	} else {
		p, err = svc.Plan(run, server, tool, decision)
	}
	d.Plan = p
	if err != nil {
		d.Err = mcpErrWords(err)
	}
	s.renderMCP(w, r, snap, "mcp-preview", "Check this change", d)
}

// mcpSet applies a switch (or a reset): a tightening at once, a loosening only with its preview's acknowledgement;
// a loosening without one goes to the preview.
func (s *Server) mcpSet(w http.ResponseWriter, r *http.Request, reset bool) {
	f := r.PostForm
	run, server, tool, decision, ack := f.Get("run"), f.Get("server"), f.Get("tool"), f.Get("decision"), f.Get("ack")
	back := "/mcp?run=" + url.QueryEscape(run)
	svc := mcpService(s.cfg.Ledger)
	var p *mcpact.Plan
	var err error
	if reset {
		p, err = svc.PlanReset(run, server, tool)
	} else {
		p, err = svc.Plan(run, server, tool, decision)
	}
	if err == nil && p.Loosens && ack == "" {
		word := decision
		if reset {
			word = "reset"
		}
		http.Redirect(w, r, "/mcp/preview?"+url.Values{"run": {run}, "server": {server}, "tool": {tool}, "decision": {word}}.Encode(), http.StatusSeeOther)
		return
	}
	if err == nil {
		if reset {
			p, err = svc.Reset(r.Context(), run, server, tool, ack)
		} else {
			p, err = svc.Set(r.Context(), run, server, tool, decision, ack)
		}
	}
	if err != nil {
		s.redirectBack(w, r, back, flash{Text: "Not done: " + mcpErrWords(err)})
		return
	}
	fl := flash{OK: true}
	switch {
	case !p.Changed && reset:
		fl.Text = server + " " + tool + " had no live switch; the contract decides it (" + p.To + ")."
	case !p.Changed:
		fl.Text = server + " " + tool + " was already " + p.To + "."
	case reset:
		fl.Text = server + " " + tool + " is back to the contract's rule: " + p.To + ". The relay applies it to the next call."
	default:
		fl.Text = server + " " + tool + " is now " + p.To + " for the rest of this run. The relay applies it to the next call."
	}
	s.redirectBack(w, r, back, fl)
}

// mcpErrWords is a service error in the page's words.
func mcpErrWords(err error) string {
	switch {
	case errors.Is(err, mcpact.ErrBadRun):
		return "there is no such run in this ledger."
	case errors.Is(err, mcpact.ErrNotRunning):
		return "the run is not running, so a live switch would apply to nothing."
	case errors.Is(err, mcpact.ErrNoServer):
		return "the run declares no such MCP server."
	case errors.Is(err, mcpact.ErrNotRelayed):
		return "this server is not behind Tego's relay: add tools: to it in the contract to get switches."
	case errors.Is(err, mcpact.ErrNoBroker):
		return "this run has no approvals (its contract has no ask: section), so Ask would refuse every call."
	case errors.Is(err, mcpact.ErrGoverned):
		return "a governed agent cannot loosen its own rules."
	case errors.Is(err, mcpact.ErrAck):
		return "the switches changed since the preview, or it was not confirmed. Check the change again."
	case errors.Is(err, mcpact.ErrBadName):
		return "that is not a server or tool name."
	default:
		return plainErr(err) + "."
	}
}
