// SPDX-License-Identifier: Apache-2.0

package web

import (
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"sync"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/routeact"
)

// The Model routes page (ADR 0127): per run, each models[] endpoint, the route its requests go by now, and the
// backends its contract declares, one of which a person may send the next request to, and back. Sending an endpoint
// elsewhere goes to a preview whose acknowledgement routeact binds to the overlay it was shown against; a revert to the
// endpoint itself applies at once. The page makes no decision of its own: it parses forms and calls internal/control/routeact, which writes,
// after ServeHTTP's governed-peer, session and CSRF checks, and it offers only the routes the contract declares.

// routesService is the service the page calls; a test replaces it.
var routesService = routeact.New

// maxRouteRuns bounds the runs the picker reads a contract of.
const maxRouteRuns = 30

// routesPageSet parses the Model routes pages apart from pageNames, as the MCP pages are: two templates, the shared
// layout.
var routesPageSet = sync.OnceValues(func() (map[string]*template.Template, error) {
	out := map[string]*template.Template{}
	for _, n := range []string{"model-routes", "model-routes-preview"} {
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

// routeRunOpt is one run in the picker.
type routeRunOpt struct {
	ID, Label string
	Live      bool
	Selected  bool
}

// routesData is the Model routes page's data.
type routesData struct {
	Runs  []routeRunOpt
	State *routeact.State
	Err   string
	CSRF  string
}

// routesPreviewData is the preview's data.
type routesPreviewData struct {
	Plan *routeact.Plan
	Err  string
	CSRF string
	Back string
}

// routesGet answers the Model routes pages' GETs; false for any other path.
func (s *Server) routesGet(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/routes":
		s.routesPage(w, r)
	case "/routes/preview":
		s.routesPreview(w, r)
	default:
		return false
	}
	return true
}

// routesPost answers the Model routes pages' POSTs; false for any other path.
func (s *Server) routesPost(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case "/routes/set":
		s.routesSet(w, r)
	default:
		return false
	}
	return true
}

func (s *Server) renderRoutes(w http.ResponseWriter, snap *ledgerview.Snapshot, name, title string, data any) {
	c := s.chromeOf(snap, title, "routes")
	c.Host, c.Ledger, c.CSRF, c.Preview = s.host, s.cfg.Ledger, s.csrf, s.cfg.Preview
	// No live regions: live.js leaves a page without a signature alone (a reload shows new counts).
	c.Sig, c.Rev = "", ""
	if fw, ok := w.(*flashWriter); ok {
		c.Flash = fw.flash
	}
	set, err := routesPageSet()
	if err != nil {
		http.Error(w, "tego-control serve: template "+name+": "+err.Error(), http.StatusInternalServerError)
		return
	}
	renderPage(w, http.StatusOK, set[name], name, page{chrome: c, Data: data})
}

func (s *Server) routesPage(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.load(w)
	if !ok {
		return
	}
	svc := routesService(s.cfg.Ledger)
	d := routesData{CSRF: s.csrf}
	want := r.URL.Query().Get("run")
	// Live runs first, then the newest; only runs whose contract declares a route.
	var live, ended []routeRunOpt
	for i, rr := range snap.Runs {
		if i >= maxRouteRuns {
			break
		}
		if !svc.HasRoutes(rr.ID) {
			continue
		}
		o := routeRunOpt{ID: rr.ID, Label: rr.Agent + " · " + shortRun(rr.ID), Live: rr.Live}
		if rr.Agent == "" {
			o.Label = shortRun(rr.ID)
		}
		if rr.Live {
			live = append(live, o)
		} else {
			ended = append(ended, o)
		}
	}
	d.Runs = slices.Concat(live, ended)
	if want == "" && len(d.Runs) > 0 {
		want = d.Runs[0].ID
	}
	for i := range d.Runs {
		d.Runs[i].Selected = d.Runs[i].ID == want
	}
	if want != "" {
		st, err := svc.State(want)
		if err != nil {
			d.Err = routesErrWords(err)
		} else {
			d.State = st
		}
	}
	s.renderRoutes(w, snap, "model-routes", "Model routes", d)
}

func (s *Server) routesPreview(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.load(w)
	if !ok {
		return
	}
	q := r.URL.Query()
	run, endpoint, route := q.Get("run"), q.Get("endpoint"), q.Get("route")
	d := routesPreviewData{CSRF: s.csrf, Back: "/routes?run=" + url.QueryEscape(run)}
	p, err := routesService(s.cfg.Ledger).Plan(run, endpoint, route)
	d.Plan = p
	if err != nil {
		d.Err = routesErrWords(err)
	}
	s.renderRoutes(w, snap, "model-routes-preview", "Check this change", d)
}

// routesSet applies a route change: a revert at once, a widening only with its preview's acknowledgement; a widening
// without one goes to the preview.
func (s *Server) routesSet(w http.ResponseWriter, r *http.Request) {
	f := r.PostForm
	run, endpoint, route, ack := f.Get("run"), f.Get("endpoint"), f.Get("route"), f.Get("ack")
	back := "/routes?run=" + url.QueryEscape(run)
	svc := routesService(s.cfg.Ledger)
	p, err := svc.Plan(run, endpoint, route)
	if err == nil && p.Widens && ack == "" {
		http.Redirect(w, r, "/routes/preview?"+url.Values{"run": {run}, "endpoint": {endpoint}, "route": {route}}.Encode(), http.StatusSeeOther)
		return
	}
	if err == nil {
		p, err = svc.Set(r.Context(), run, endpoint, route, ack)
	}
	if err != nil {
		s.redirectBack(w, r, back, flash{Text: "Not done: " + routesErrWords(err)})
		return
	}
	fl := flash{OK: true}
	switch {
	case !p.Changed:
		fl.Text = endpoint + " already sends to " + p.To.Name + " (" + p.To.Authority + ")."
	case p.To.Name == "direct":
		fl.Text = endpoint + " sends to its own endpoint again, from the next request."
	default:
		fl.Text = endpoint + " now sends to " + p.To.Name + " (" + p.To.Authority + ") from the next request, for the rest of this run."
	}
	s.redirectBack(w, r, back, fl)
}

// routesErrWords is a service error in the page's words.
func routesErrWords(err error) string {
	switch {
	case errors.Is(err, routeact.ErrBadRun):
		return "there is no such run in this ledger."
	case errors.Is(err, routeact.ErrNotRunning):
		return "the run is not running, so a route change would apply to nothing."
	case errors.Is(err, routeact.ErrNoEndpoint):
		return "the run declares no such model endpoint."
	case errors.Is(err, routeact.ErrNoRoute):
		return "the contract declares no such route for this endpoint; only declared routes can be chosen."
	case errors.Is(err, routeact.ErrGoverned):
		return "a governed agent cannot choose its own model route."
	case errors.Is(err, routeact.ErrAck):
		return "the routes changed since the preview, or it was not confirmed. Check the change again."
	default:
		return plainErr(err) + "."
	}
}
