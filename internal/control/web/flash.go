// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// After a form changes something (an answer, a stop, a block), the dashboard answers 303 See Other back to the page
// the person was on, with one plain line saying what was done: "Denied: read of ~/.config/telemetry/token". A reload
// then posts nothing, the page is the one they were reading, and no ledger line is shown raw (the line page has it).
// The line is kept in memory under a random id that the redirect's ?flash= names, and shown once: a second GET of
// the same address shows the page alone. It holds no secret and stays a few minutes at most. The line sits in the
// layout's r-banner live region, so the page that shows it is a live page like any other.
//
// With JavaScript on, static/live.js posts these forms in the background with the header X-Tego-Inline (inlineHeader)
// and the action answers the same line as JSON instead of the 303 (inlineAnswer): live.js says it in a toast and
// refreshes the page's live regions in place. The line is said once, as a toast or as the flash line, never both, and
// the page does not load again.
//
// An action whose result is a page of its own names it in the answer for live.js too: Here is the address of the
// page the form is on with the result in its live regions (the event page's Saved panel), which live.js puts in the
// address bar before it refreshes the regions, so the panel changes in place; Go is another page (Change rules'
// Saved, a new agent's Rules), which live.js opens with the toast carried over, as it does after a Stop. The plain
// form's 303 goes to the same address.
//
// A result that shows a panel of its own (a saved change, with its Undo) keeps the panel's data in memory under a
// random id its page's address names (?saved=<id>, keep): unlike a flash it is read, not taken, so the page's live
// regions and a reload show it again, for keptTTL.

// flash is the line an action leaves on the next page.
type flash struct {
	// OK is a change made; otherwise the change was not made and Text says why.
	OK   bool
	Text string
	// Link and LinkText are an optional next step after the line ("Make it permanent: Never allow").
	Link, LinkText string
	// Here and Go are the page that shows the result, for live.js (see above); "" leaves it on the page it is on.
	Here, Go string
}

type flashEntry struct {
	f  flash
	at time.Time
}

// flashTTL is how long a flash waits for its page; maxFlashes bounds the store.
const (
	flashTTL   = 5 * time.Minute
	maxFlashes = 64
)

// putFlash keeps f and returns its id.
func (s *Server) putFlash(f flash) string {
	id := randomHex(8)
	now := time.Now()
	s.flashMu.Lock()
	defer s.flashMu.Unlock()
	if s.flashes == nil {
		s.flashes = map[string]flashEntry{}
	}
	for k, e := range s.flashes {
		if now.Sub(e.at) > flashTTL {
			delete(s.flashes, k)
		}
	}
	for len(s.flashes) >= maxFlashes {
		oldest := ""
		for k, e := range s.flashes {
			if oldest == "" || e.at.Before(s.flashes[oldest].at) {
				oldest = k
			}
		}
		delete(s.flashes, oldest)
	}
	s.flashes[id] = flashEntry{f, now}
	return id
}

// takeFlash returns the flash under id and forgets it; nil when there is none (shown already, or expired).
func (s *Server) takeFlash(id string) *flash {
	s.flashMu.Lock()
	defer s.flashMu.Unlock()
	e, ok := s.flashes[id]
	if !ok {
		return nil
	}
	delete(s.flashes, id)
	if time.Since(e.at) > flashTTL {
		return nil
	}
	return &e.f
}

// flashWriter carries a GET's flash to render, which every page calls.
type flashWriter struct {
	http.ResponseWriter
	flash *flash
}

// Unwrap lets http.ResponseController reach the connection.
func (f *flashWriter) Unwrap() http.ResponseWriter { return f.ResponseWriter }

// inlineHeader marks an action static/live.js posted in the background: it answers its line as JSON, not a 303.
const inlineHeader = "X-Tego-Inline"

// inlineAnswer is an action's line as JSON (live.js's toast): flash's fields, named for JSON.
type inlineAnswer struct {
	OK       bool   `json:"ok"`
	Text     string `json:"text"`
	Link     string `json:"link,omitempty"`
	LinkText string `json:"link_text,omitempty"`
	Here     string `json:"here,omitempty"`
	Go       string `json:"go,omitempty"`
}

// backTo is where an action returns: the form's back field, else the Referer, when it is a page of this dashboard;
// else fallback. A Stop's confirm page returns to its run, and the query keys that only prefill a form (block,
// value) or carried a flash or the token are dropped.
func backTo(r *http.Request, fallback string) string {
	for _, raw := range []string{r.PostForm.Get("back"), r.Header.Get("Referer")} {
		if p := samePage(raw, r.Host); p != "" {
			return p
		}
	}
	return fallback
}

// samePage is raw as a path and query on this dashboard, or "" when it names another origin or no page.
func samePage(raw, host string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" {
		return ""
	}
	if u.Scheme != "" || u.Host != "" {
		if u.Scheme != "http" || u.Host != host {
			return ""
		}
	}
	p := u.Path
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\x00\r\n") {
		return ""
	}
	if strings.HasPrefix(p, "/runs/") && strings.HasSuffix(p, "/stop") {
		p = strings.TrimSuffix(p, "/stop")
	}
	q := u.Query()
	for _, k := range []string{"flash", "t", "block", "value"} {
		q.Del(k)
	}
	if enc := q.Encode(); enc != "" {
		p += "?" + enc
	}
	return p
}

// redirectBack answers an action: 303 to back with f to show there once, or f as JSON to a form live.js posted
// (inlineHeader), which keeps no flash. A #fragment of back stays last in the address.
func (s *Server) redirectBack(w http.ResponseWriter, r *http.Request, back string, f flash) {
	if r.Header.Get(inlineHeader) != "" {
		// live.js puts the text in a toast as text, never markup; an invisible character in a target the line names
		// shows as visibleText writes it, as it does on the page (the flash line is in the page's HTML).
		a := inlineAnswer(f)
		a.Text, a.LinkText = visibleText(a.Text), visibleText(a.LinkText)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(a)
		return
	}
	back, frag, _ := strings.Cut(back, "#")
	sep := "?"
	if strings.Contains(back, "?") {
		sep = "&"
	}
	loc := back + sep + "flash=" + s.putFlash(f)
	if frag != "" {
		loc += "#" + frag
	}
	http.Redirect(w, r, loc, http.StatusSeeOther)
}

// keptTTL is how long a result panel's data stays; maxKept bounds the store.
const (
	keptTTL = 30 * time.Minute
	maxKept = 64
)

type keptEntry struct {
	v  any
	at time.Time
}

// keep holds v for a result page (see above) and returns its id.
func (s *Server) keep(v any) string {
	id := randomHex(8)
	now := time.Now()
	s.keptMu.Lock()
	defer s.keptMu.Unlock()
	if s.kepts == nil {
		s.kepts = map[string]keptEntry{}
	}
	for k, e := range s.kepts {
		if now.Sub(e.at) > keptTTL {
			delete(s.kepts, k)
		}
	}
	for len(s.kepts) >= maxKept {
		oldest := ""
		for k, e := range s.kepts {
			if oldest == "" || e.at.Before(s.kepts[oldest].at) {
				oldest = k
			}
		}
		delete(s.kepts, oldest)
	}
	s.kepts[id] = keptEntry{v, now}
	return id
}

// kept is what keep holds under id, nil when it holds nothing there (expired, or never kept). It is not taken.
func (s *Server) kept(id string) any {
	if id == "" {
		return nil
	}
	s.keptMu.Lock()
	defer s.keptMu.Unlock()
	e, ok := s.kepts[id]
	if !ok || time.Since(e.at) > keptTTL {
		return nil
	}
	return e.v
}
