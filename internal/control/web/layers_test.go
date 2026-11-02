// SPDX-License-Identifier: Apache-2.0

package web

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// TestLayerPathsPassTheGates: a layer's handlers run where every other page's do. A request with no session reaches
// neither; a POST without the session's token, or from a socket made inside a run, does not reach Post; a region
// request reaches Get, since a layer's page may have live regions; and the layer's entry is in the Preview nav only.
func TestLayerPathsPassTheGates(t *testing.T) {
	const path = "/layer-probe"
	var gets, posts int
	old := layers
	t.Cleanup(func() { layers = old })
	layers = append(slices.Clone(old), layer{
		Get: func(s *Server, w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path != path {
				return false
			}
			gets++
			w.WriteHeader(http.StatusNoContent)
			return true
		},
		Post: func(s *Server, w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path != path {
				return false
			}
			posts++
			w.WriteHeader(http.StatusNoContent)
			return true
		},
		Nav: []navEntry{{Href: path, Key: "layer-probe", Icon: "i-link", Label: "Layer probe"}},
	})
	s := newServer(t, fixture(t))
	c := login(t, s)

	do(s, "GET", path, "127.0.0.1:8484", nil)
	if gets != 0 {
		t.Fatal("a GET with no session reached the layer")
	}
	if w := do(s, "GET", path, "127.0.0.1:8484", c); w.Code != http.StatusNoContent || gets != 1 {
		t.Fatalf("a signed-in GET: %d, reached %d times", w.Code, gets)
	}
	doRegions(s, path, "127.0.0.1:8484", c, headerOf(map[string]string{"r-nav": "stale"}))
	if gets != 2 {
		t.Fatalf("a region request did not reach the layer: reached %d times", gets)
	}
	if w := do(s, "GET", "/layer-absent", "127.0.0.1:8484", c); w.Code != http.StatusNotFound {
		t.Fatalf("a path no layer answers: %d", w.Code)
	}

	post(s, path, url.Values{}, own, "", c)
	if posts != 0 {
		t.Fatal("a POST without the session's token reached the layer")
	}
	good := url.Values{"csrf": {s.csrf}}
	governed := s.governed
	s.governed = func(*http.Request) error { return errors.New("run r-1") }
	post(s, path, good, own, "", c)
	s.governed = governed
	if posts != 0 {
		t.Fatal("a POST from inside a run reached the layer")
	}
	post(s, path, good, "http://evil.example", "", c)
	if posts != 0 {
		t.Fatal("a POST from another origin reached the layer")
	}
	if w := post(s, path, good, own, "", c); w.Code != http.StatusNoContent || posts != 1 {
		t.Fatalf("a good POST: %d, reached %d times", w.Code, posts)
	}
	if w := post(s, "/layer-absent", good, own, "", c); w.Code != http.StatusNotFound {
		t.Fatalf("a POST to a path no layer answers: %d", w.Code)
	}

	if strings.Contains(do(s, "GET", "/", "127.0.0.1:8484", c).Body.String(), ">Layer probe<") {
		t.Error("a layer's entry is in the nav without Preview")
	}
	s.cfg.Preview = true
	if nav := navHref.FindString(do(s, "GET", "/", "127.0.0.1:8484", c).Body.String()); !strings.Contains(nav, `href="`+path+`"`) {
		t.Error("a layer's entry is not in the Preview nav")
	}
}

// TestLayerNavOrderAndSoon: the Preview nav is one list, the core's entries and each layer's in Order, in the side nav
// and in the More menu, and a Soon entry is a muted label with its tooltip, never a link, in both.
func TestLayerNavOrderAndSoon(t *testing.T) {
	old := layers
	t.Cleanup(func() { layers = old })
	layers = append(slices.Clone(old), layer{Nav: []navEntry{
		{Icon: "i-users", Label: "Late probe", Title: "Late probe tip", Soon: true, Order: 9},
		{Href: "/early-probe", Key: "early-probe", Icon: "i-link", Label: "Early probe", Order: -9},
	}})
	s := newServer(t, fixture(t))
	c := login(t, s)
	s.cfg.Preview = true
	nav := navHref.FindString(do(s, "GET", "/", "127.0.0.1:8484", c).Body.String())
	more := nav[strings.Index(nav, `id="more-menu"`):]
	side := strings.TrimSuffix(nav, more)
	for name, part := range map[string]string{"side nav": side, "More menu": more} {
		early, mcp, routes, late := strings.Index(part, "Early probe"), strings.Index(part, "MCP tools"), strings.Index(part, "Model routes"), strings.Index(part, "Late probe")
		if early < 0 || mcp < early || routes < mcp || late < routes {
			t.Errorf("%s: Early probe %d, MCP tools %d, Model routes %d, Late probe %d, want them in that order", name, early, mcp, routes, late)
		}
		if !strings.Contains(part, `href="/early-probe"`) {
			t.Errorf("%s: the Early probe is not a link", name)
		}
	}
	if !strings.Contains(side, `title="Late probe tip"`) || !strings.Contains(side, `<span class="soon-tag">Soon</span>`) {
		t.Errorf("the side nav's Soon entry lacks its tooltip or tag: %s", side)
	}
	if !strings.Contains(more, `Late probe<span class="soon-tag">Coming soon</span>`) {
		t.Errorf("the More menu's Soon entry lacks its tag: %s", more)
	}
	if strings.Contains(nav, `href=""`) {
		t.Errorf("a Soon entry is drawn as a link: %s", nav)
	}
}
