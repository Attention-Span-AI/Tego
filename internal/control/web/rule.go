// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/url"
	"strconv"
)

// The old Rule page's address. GET /rule?run=<id>&seq=<n> redirects to the event page's Act on this panel, the one
// rule UI (F11). POST /rule, the Confirm form an older Rule page served, is retired (SEC-1): it wrote a widening with
// no acknowledgement and on no previewed base, so it now answers 410 Gone with a link to the line's page and writes
// nothing. Every rule is made on the event page (event.go) or on Change rules (rules_change.go), through the rule
// service's guards.

// RuleService is the rule service the pages ask (internal/control/rules.Service). Each page asserts the half it
// needs (ActService, ChangeService); a value with neither serves those pages' notices.
type RuleService any

// ruleGone is the data of the 410 page POST /rule answers: the line's page, when the form named one.
type ruleGone struct {
	Line string
}

// lineAct is the event page's Act on this panel for line seq of run.
func lineAct(run string, seq uint64) string {
	return "/runs/" + url.PathEscape(run) + "/lines/" + strconv.FormatUint(seq, 10) + "#act"
}

// rulePage serves GET /rule (a redirect to the event page).
func (s *Server) rulePage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	seq, err := strconv.ParseUint(q.Get("seq"), 10, 64)
	if err != nil || q.Get("run") == "" {
		s.fail(w, http.StatusBadRequest, "No such line", "The address names no line.")
		return
	}
	http.Redirect(w, r, lineAct(q.Get("run"), seq), http.StatusSeeOther)
}

// ruleGonePost serves POST /rule, which postAllowed has passed: 410 Gone, with the line's page to make the rule on.
// It reads the form for the link only and calls no service.
func (s *Server) ruleGonePost(w http.ResponseWriter, r *http.Request) {
	var d ruleGone
	if seq, err := strconv.ParseUint(r.PostForm.Get("seq"), 10, 64); err == nil && runIDShape(r.PostForm.Get("run")) {
		d.Line = lineAct(r.PostForm.Get("run"), seq)
	}
	s.render(w, http.StatusGone, "rule", chrome{Title: "This form is retired", Nav: "runs"}, d)
}

// runIDShape is the shape of a run id a link may carry: r-, then lower-case letters, digits and dashes.
func runIDShape(id string) bool {
	if len(id) < 3 || len(id) > 128 || id[:2] != "r-" {
		return false
	}
	for _, c := range id {
		if c != '-' && (c < '0' || c > '9') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

// sameOrigin is the POST's Origin check: the browser's Origin header names this dashboard's own address (the Host
// check has already held r.Host to it), and a Sec-Fetch-Site header, when sent, says same-origin.
func (s *Server) sameOrigin(r *http.Request) bool {
	if sfs := r.Header.Get("Sec-Fetch-Site"); sfs != "" && sfs != "same-origin" {
		return false
	}
	o := r.Header.Get("Origin")
	return o != "" && o == "http://"+r.Host && s.hosts[r.Host]
}
