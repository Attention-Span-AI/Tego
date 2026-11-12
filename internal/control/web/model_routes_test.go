// SPDX-License-Identifier: Apache-2.0

package web

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/modelroutes"
)

const routesContract = `version: 0
name: demo-harm
command: [python3, agent.py]
capture: forwarder
models:
  - provider: anthropic
    host: api.anthropic.com
    port: 443
    routes:
      - {name: corp, host: llm-proxy.corp.example, port: 8443}
      - {name: local, host: 127.0.0.1, port: 11434, tls: false}
  - {provider: openai, host: api.openai.com, port: 443}
`

const routesEndpoint = "api.anthropic.com:443"

// routesFixture is the harm fixture's live run with routesContract as its contract copy, made Adjustable (ADR 0125), so
// its endpoints may move off direct; lockedRoutesFixture leaves it Locked.
func routesFixture(t *testing.T) string {
	t.Helper()
	root := lockedRoutesFixture(t)
	adjustableHarm(t, root)
	return root
}

func lockedRoutesFixture(t *testing.T) string {
	t.Helper()
	root := fixture(t)
	if err := os.WriteFile(filepath.Join(root, harmRun, "contract.yaml"), []byte(routesContract), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestRoutesLockedRunRefusesARoute: on a Locked run (ADR 0127 §6) a route other than direct is refused in the words a
// Locked lift gets, on the flash after the POST and on the preview, which offers no acknowledgement; nothing is
// written. Back to direct still applies.
func TestRoutesLockedRunRefusesARoute(t *testing.T) {
	root := lockedRoutesFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	holdLock(t, filepath.Join(root, harmRun))
	post := func(form url.Values) *httptest.ResponseRecorder {
		r := govRequest("POST", "/routes/set", form)
		r.AddCookie(c)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	for _, ack := range []string{"", "forged"} {
		w := post(url.Values{"csrf": {s.csrf}, "run": {harmRun}, "endpoint": {routesEndpoint}, "route": {"corp"}, "ack": {ack}})
		loc := w.Header().Get("Location")
		if w.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/routes?run=") {
			t.Fatalf("a route on a Locked run (ack %q): %d %q", ack, w.Code, loc)
		}
		if body := html.UnescapeString(get(t, s, c, loc)); !strings.Contains(body, "Not done: "+lockedWords) {
			t.Fatalf("the flash lacks the Locked words:\n%s", body)
		}
	}
	// The preview says it as the flash does, offers no acknowledgement and no promise of one, and leads back.
	prev := html.UnescapeString(get(t, s, c, "/routes/preview?"+url.Values{"run": {harmRun}, "endpoint": {routesEndpoint}, "route": {"corp"}}.Encode()))
	if !strings.Contains(prev, "Not done: "+lockedWords) || strings.Contains(prev, `name="ack"`) ||
		strings.Contains(prev, "until you confirm") || !strings.Contains(prev, `href="/routes?run=`+harmRun+`">Back to Model routes</a>`) {
		t.Fatalf("the preview of a Locked run's route:\n%s", prev)
	}
	if _, err := os.Stat(filepath.Join(root, harmRun, modelroutes.FileName)); err == nil {
		t.Fatal("a refused route wrote the overlay")
	}
	if w := post(url.Values{"csrf": {s.csrf}, "run": {harmRun}, "endpoint": {routesEndpoint}, "route": {"direct"}}); w.Code != http.StatusSeeOther ||
		!strings.Contains(html.UnescapeString(get(t, s, c, w.Header().Get("Location"))), "already sends to direct") {
		t.Fatalf("direct on a Locked run: %d %q", w.Code, w.Header().Get("Location"))
	}
}

// TestRoutesPageRenders: the page lists the run's endpoints, the route in force (direct), the declared routes with
// their TLS, a Send here per route not in use, and a plain note for an endpoint without routes; the Preview nav links it.
func TestRoutesPageRenders(t *testing.T) {
	root := routesFixture(t)
	s := newServer(t, root)
	s.cfg.Preview = true
	c := login(t, s)
	holdLock(t, filepath.Join(root, harmRun))
	body := get(t, s, c, "/routes?run="+harmRun)
	for _, want := range []string{"Model routes", routesEndpoint, "llm-proxy.corp.example:8443", "127.0.0.1:11434",
		"Plaintext, this machine", "TLS, certificate checked", "Send here", "In use", "No routes declared",
		`href="/static/routes.css"`, `href="/routes" aria-current="page"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(body, "Back to direct") {
		t.Error("a run on direct offers Back to direct")
	}
}

// routePages are the bodies of the Model routes page and of the check page a widening goes to, unescaped.
func routePages(t *testing.T) map[string]string {
	t.Helper()
	root := routesFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	holdLock(t, filepath.Join(root, harmRun))
	r := govRequest("POST", "/routes/set", url.Values{"csrf": {s.csrf}, "run": {harmRun}, "endpoint": {routesEndpoint}, "route": {"corp"}})
	r.AddCookie(c)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	preview := w.Header().Get("Location")
	if !strings.HasPrefix(preview, "/routes/preview?") {
		t.Fatalf("widening: %d %q", w.Code, preview)
	}
	return map[string]string{"routes": html.UnescapeString(get(t, s, c, "/routes?run="+harmRun)),
		"preview": html.UnescapeString(get(t, s, c, preview))}
}

// TestRoutePagesPromiseWhatTheBuildDoes: both route pages say what a route carries, a key the agent holds itself
// included, and no rule of a layer the build has not got: with no key layer that key goes wherever the route goes, so
// words on an allow list would be false at the moment a person consents. A layer's sentence comes from the layer. The
// test sets the layers itself, so it means the same in a tree that carries one.
func TestRoutePagesPromiseWhatTheBuildDoes(t *testing.T) {
	const note = "The probe layer's sentence."
	if _, err := parsedPages(); err != nil { // once per process, and with the build's own layers
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		layers []layer
		note   bool
	}{{name: "no layer"}, {name: "a layer's sentence", layers: []layer{{RouteNote: note}}, note: true}} {
		t.Run(tc.name, func(t *testing.T) {
			old := layers
			t.Cleanup(func() { layers = old })
			layers = tc.layers
			for page, body := range routePages(t) {
				if !strings.Contains(body, "a key the agent holds itself goes") {
					t.Errorf("%s: does not say a key travels with the request", page)
				}
				if strings.Contains(body, "allow list") || strings.Contains(body, "credential") {
					t.Errorf("%s: promises a rule of a layer", page)
				}
				if strings.Contains(body, note) != tc.note {
					t.Errorf("%s: the layer's sentence on the page: %t, want %t", page, !tc.note, tc.note)
				}
			}
		})
	}
}

// TestRoutesWideningGoesToPreview: a route change without its acknowledgement is sent to the preview, which carries
// one and writes nothing; confirmed with it, the overlay holds the route, by the dashboard; Back to direct applies at
// once.
func TestRoutesWideningGoesToPreview(t *testing.T) {
	root := routesFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	dir := filepath.Join(root, harmRun)
	holdLock(t, dir)
	post := func(form url.Values) *httptest.ResponseRecorder {
		r := govRequest("POST", "/routes/set", form)
		r.AddCookie(c)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	form := url.Values{"csrf": {s.csrf}, "run": {harmRun}, "endpoint": {routesEndpoint}, "route": {"corp"}}
	w := post(form)
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/routes/preview?") {
		t.Fatalf("widening: %d %q", w.Code, w.Header().Get("Location"))
	}
	prev := get(t, s, c, w.Header().Get("Location"))
	if !strings.Contains(prev, "Check this change") || !strings.Contains(prev, `name="ack"`) || !strings.Contains(prev, "llm-proxy.corp.example:8443") {
		t.Fatalf("preview lacks its acknowledgement:\n%s", prev)
	}
	if _, err := modelroutes.Read(dir, harmRun); err == nil {
		t.Fatal("the widening wrote before its confirmation")
	}
	i := strings.Index(prev, `name="ack" value="`)
	ack := prev[i+len(`name="ack" value="`):]
	ack = ack[:strings.IndexByte(ack, '"')]
	form.Set("ack", ack)
	if w = post(form); w.Code != http.StatusSeeOther || strings.HasPrefix(w.Header().Get("Location"), "/routes/preview") {
		t.Fatalf("confirmed: %d %q", w.Code, w.Header().Get("Location"))
	}
	o, err := modelroutes.Read(dir, harmRun)
	if err != nil {
		t.Fatal(err)
	}
	if e, ok := o.Lookup(routesEndpoint); !ok || e.Route != "corp" || !strings.HasSuffix(e.By, "dashboard") {
		t.Fatalf("overlay %+v", o)
	}
	if body := get(t, s, c, "/routes?run="+harmRun); !strings.Contains(body, "Back to direct") || !strings.Contains(body, "Rerouted") {
		t.Fatalf("a rerouted run's page:\n%s", body)
	} else if e, _ := o.Lookup(routesEndpoint); !strings.Contains(html.UnescapeString(body), "set by "+who(e.By)) ||
		strings.Contains(body, "uid:") || !strings.Contains(who(e.By), "from the dashboard") {
		// The card names the person, as live blocks do, never the ledger's "uid:<n> pid:<n> dashboard".
		t.Errorf("the card names who set the route as %q, want %q", e.By, who(e.By))
	}
	w = post(url.Values{"csrf": {s.csrf}, "run": {harmRun}, "endpoint": {routesEndpoint}, "route": {"direct"}})
	if w.Code != http.StatusSeeOther || strings.HasPrefix(w.Header().Get("Location"), "/routes/preview") {
		t.Fatalf("revert: %d %q", w.Code, w.Header().Get("Location"))
	}
	o, _ = modelroutes.Read(dir, harmRun)
	if _, ok := o.Lookup(routesEndpoint); ok {
		t.Fatalf("overlay after revert %+v", o)
	}
	// An undeclared route is never written, whatever the form says.
	form = url.Values{"csrf": {s.csrf}, "run": {harmRun}, "endpoint": {routesEndpoint}, "route": {"evil"}, "ack": {"x"}}
	if w = post(form); w.Code != http.StatusSeeOther {
		t.Fatalf("undeclared: %d", w.Code)
	}
	o, _ = modelroutes.Read(dir, harmRun)
	if len(o.Changes) != 2 {
		t.Fatalf("an undeclared route changed the overlay: %+v", o)
	}
}

// TestRoutesGovernedPeerRefused: a POST from a socket made inside a run is refused before the page sees it.
func TestRoutesGovernedPeerRefused(t *testing.T) {
	root := routesFixture(t)
	s := newServer(t, root)
	c := login(t, s)
	tree := newCgroupTree(t, 1000)
	s.governed = (&governedCheck{cgroupRoot: func() (string, error) { return tree.root, nil },
		socketCgroup: func(netip.AddrPort, netip.AddrPort) (uint64, error) { return inode(t, tree.scope), nil }}).refuse
	for _, route := range []string{"corp", "direct"} {
		r := govRequest("POST", "/routes/set", url.Values{"csrf": {s.csrf}, "run": {harmRun}, "endpoint": {routesEndpoint}, "route": {route}})
		r.AddCookie(c)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("POST route %s from inside a run: %d", route, w.Code)
		}
	}
	if _, err := os.Stat(filepath.Join(root, harmRun, modelroutes.FileName)); err == nil {
		t.Fatal("a governed POST wrote the overlay")
	}
}
