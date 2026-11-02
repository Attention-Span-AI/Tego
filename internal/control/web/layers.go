// SPDX-License-Identifier: Apache-2.0

package web

import (
	"cmp"
	"net/http"
	"slices"
	"strings"
)

// A layer is a set of dashboard pages kept in files of their own (a handler file, its templates and stylesheet), which
// registers itself from its init and which a build may leave out: the core names none of its paths. Its handlers run
// where every other page's do, inside route and routePost, so Host, peer, session, CSRF, origin and governed checks,
// region requests and the region cache apply to them unchanged.
type layer struct {
	// Pages are the layer's template names, parsed with pageNames.
	Pages []string
	// Get and Post answer a path of the layer and report whether they did; false for any other path.
	Get, Post func(*Server, http.ResponseWriter, *http.Request) bool
	// Nav are the layer's entries of the Preview nav.
	Nav []navEntry
	// RouteNote is a sentence the layer adds to the Model routes page and its check page, after the core's words on
	// what a route carries. What a layer does to a request is the layer's to promise, so a build without it says none.
	RouteNote string
}

// navEntry is one entry of the Preview nav. Key is the page's chrome Nav value.
type navEntry struct {
	Href, Key, Icon, Label string
	// Soon marks a page not built yet: a muted label with Title as its tooltip, not a link.
	Soon  bool
	Title string
	// Order places the entry, lowest first. The core's entries stand at 0.
	Order int
}

// coreNav are the core's own entries of the Preview nav.
var coreNav = []navEntry{
	{Href: "/mcp", Key: "mcp", Icon: "i-terminal", Label: "MCP tools"},
	{Href: "/routes", Key: "routes", Icon: "i-link", Label: "Model routes"},
}

// layers are the layers this build carries. A layer's init appends to it, so it is read only after every registration.
var layers []layer

// allPages are the template names parsedPages parses: the core's and each layer's.
func allPages() []string {
	out := slices.Clone(pageNames)
	for _, l := range layers {
		out = append(out, l.Pages...)
	}
	return out
}

// layerGet answers a GET or HEAD of a layer's path; route falls back to it before its 404.
func (s *Server) layerGet(w http.ResponseWriter, r *http.Request) bool {
	for _, l := range layers {
		if l.Get != nil && l.Get(s, w, r) {
			return true
		}
	}
	return false
}

// layerPost answers a POST of a layer's path; routePost falls back to it before its 404.
func (s *Server) layerPost(w http.ResponseWriter, r *http.Request) bool {
	for _, l := range layers {
		if l.Post != nil && l.Post(s, w, r) {
			return true
		}
	}
	return false
}

// layerRouteNote is what this build's layers add to the Model routes pages (the template function of the same name),
// empty when none does.
func layerRouteNote() string {
	var notes []string
	for _, l := range layers {
		if l.RouteNote != "" {
			notes = append(notes, l.RouteNote)
		}
	}
	return strings.Join(notes, " ")
}

// layerNav is the Preview nav (the template function of the same name): the core's entries and each layer's, in Order.
func layerNav() []navEntry {
	out := slices.Clone(coreNav)
	for _, l := range layers {
		out = append(out, l.Nav...)
	}
	slices.SortStableFunc(out, func(a, b navEntry) int { return cmp.Compare(a.Order, b.Order) })
	return out
}
