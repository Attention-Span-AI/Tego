// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
)

// Live regions: the parts of a page that change while runs do, so static/live.js can swap them in place instead of
// reloading the page. Each is a named template of the page's own template set (the layout's r-top, r-nav and
// r-banner, and each page's own, regionsOf), placed inside <div class="lr" data-live="<name>" data-h="<hash>"> (the
// "lr" template, or "lrb" for a table's <tbody>), where hash is a hash of the region's HTML (hashRegion): render
// renders each region first, to hash it, and the page's layout twin (layoutTwin) places that same HTML instead of
// rendering the region a second time. A page asks for its fresh regions by fetching its own address again with the
// header X-Tego-Regions: <name>:<hash>,… (the regions it shows, with the hash each was rendered with); the same
// handler computes the same data, and render answers only the regions whose HTML changed, as
// <template data-live="<name>" data-h="<hash>">…</template>, with no layout around them. The fragments are the
// pages' own templates' output, so escaping and content are the page's; they carry the form token like the page, so
// they are never compressed.
//
// A clock that follows the wall clock rather than the ledger (a running run's duration so far, how long ago an ask
// came) is marked data-ck: live.js rewrites its text every second, and hashRegion leaves its text out, so a region's
// hash moves only when its data does and a live page is not sent a region whose only change is a clock.

// regionHeader is the request header that asks for a page's changed regions instead of the page.
const regionHeader = "X-Tego-Regions"

// layoutRegions are the regions every page's layout has: the topbar's Live word, the side nav with the Approvals
// count, and the waiting-ask banner with the page's notes.
var layoutRegions = []string{"r-top", "r-nav", "r-banner"}

// pageRegions are each page's own regions. "content" is the whole page body, for pages whose every part follows
// the ledger. A page left out has only the layout's.
var pageRegions = map[string][]string{
	// The Overview: its headline, tiles, Running now, Waiting on you, Recent runs and Recent refusals, so a live run's
	// line resends the Running now table and the counts it moved, not the page.
	"overview":  {"r-ov-head", "r-ov-tiles", "r-ov-live", "r-ov-asks", "r-ov-recent", "r-ov-refusals"},
	"approvals": {"content"},
	// Detections and Investigate read the ledger top to bottom; Severity and the Glossary read no line of it.
	"detections":  {"content"},
	"investigate": {"content"},
	// Runs: the counts, the running runs' rows and the other rows of the page (two <tbody> of one table), and the
	// paging links under it.
	"runs": {"r-runs-head", "r-runs-live", "r-runs-table", "r-runs-foot"},
	// The run page: its head and asks, the Block now panel (each block's state moves from waiting to in force as the
	// launcher confirms it), Highlights with the run's details and tabs, then the open tab's parts.
	"run":  {"r-run-top", "r-run-live", "r-run-hl", "r-tl-head", "r-tl-foot", "r-run-tab"},
	"logs": {"r-logs-head", "r-logs-facets", "r-logs-rows"}, // the counts and downloads, the facets, the rows
	// The rules pages: Rules in force (hits, live blocks, the pending banner), the lists and history of Change rules
	// (not its YAML editor), a saved change with its Undo, and "Set up a new agent" with the agent it set up.
	"rules":        {"content"},
	"rules-change": {"r-change"},
	"rules-saved":  {"content"},
	"rules-new":    {"content"},
	// The event page's Act on this panel: its Saved panel (?saved=<id>) and Block now change in place.
	"event": {"r-act"},
}

// topOnly are the regions live.js refreshes only while the person is at the top of the page's first page (Logs'
// rows: new lines arrive at the top, and moving rows under someone reading lower down would lose their place).
var topOnly = map[string]bool{"r-logs-rows": true}

// regionsOf is page name's regions, the layout's first.
func regionsOf(name string) []string {
	return append(append([]string(nil), layoutRegions...), pageRegions[name]...)
}

// liveRegion is one rendered region: its name and hash for the "lr" wrapper, and its HTML for a region answer and
// for the layout twin, which places it in the page.
type liveRegion struct {
	Name string
	Hash string
	Top  bool
	html []byte // html/template's output for the region, in the HTML text context the page places it in
}

// regions renders page name's regions from template set t with p (the ones in want, or all when want is nil).
func regions(t *template.Template, name string, p page, want map[string]string) (map[string]*liveRegion, error) {
	out := map[string]*liveRegion{}
	for _, n := range regionsOf(name) {
		if want != nil {
			if _, ok := want[n]; !ok {
				continue
			}
		}
		var buf bytes.Buffer // its own: the bytes stay the region's (a cached answer shares them)
		if err := t.ExecuteTemplate(&buf, n, p); err != nil {
			return nil, fmt.Errorf("region %s: %w", n, err)
		}
		out[n] = &liveRegion{Name: n, Hash: hashRegion(buf.Bytes()), Top: topOnly[n], html: buf.Bytes()}
	}
	return out, nil
}

// clockMark ends the start tag of a clock that follows the wall clock: <span … data-ck>3 m 12 s</span>. The
// templates write data-ck last in the tag, so the tag's own > follows it, and the clock's text runs to the next <
// (it is a duration or a time in words, never markup).
var clockMark = []byte(" data-ck>")

// hashRegion is a region's hash: the first 8 bytes of the SHA-256 of its HTML with each clock's text left out, so
// two renders a second apart with no new data hash the same.
func hashRegion(b []byte) string {
	h := sha256.New()
	for {
		i := bytes.Index(b, clockMark)
		if i < 0 {
			break
		}
		i += len(clockMark)
		h.Write(b[:i])
		b = b[i:]
		if j := bytes.IndexByte(b, '<'); j >= 0 {
			b = b[j:]
		} else {
			b = nil
		}
	}
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// layoutTwin is template set t (a page's, before it has executed) cloned, with each of page name's regions redefined
// as a placeholder (regionMark and the region's name): the full page executes the layout on the twin and splices in
// the HTML rendered for each region's hash (spliceRegions), so each region renders once per page, not twice. The
// region's bytes are html/template's own output for it in the same HTML text context, placed without changing a
// byte, and no trusted-HTML value is made.
func layoutTwin(name string, t *template.Template) (*template.Template, error) {
	tw, err := t.Clone()
	if err != nil {
		return nil, err
	}
	for _, n := range regionsOf(name) {
		if _, err := tw.New(n).Parse(regionMark + n + "\x00"); err != nil {
			return nil, fmt.Errorf("region %s: %w", n, err)
		}
	}
	// Escape the twin's layout now, as escapeRegions does the regions.
	if err := tw.ExecuteTemplate(io.Discard, "layout", page{}); err != nil {
		var te *template.Error
		if errors.As(err, &te) {
			return nil, err
		}
	}
	return tw, nil
}

// regionMark opens a region's placeholder in the twin's output: it ends with the region's name and a NUL. A NUL
// never comes out of html/template for data (it escapes one in every context), so only the twin's own template text
// makes it.
const regionMark = "\x00tego-region\x00"

// spliceRegions writes page b, the twin's output, to w with each placeholder replaced by its region's HTML from l. A
// placeholder of a region missing from l is an error, never an empty part of the page.
func spliceRegions(w *bytes.Buffer, b []byte, l map[string]*liveRegion) error {
	mark := []byte(regionMark)
	for {
		i := bytes.Index(b, mark)
		if i < 0 {
			w.Write(b)
			return nil
		}
		w.Write(b[:i])
		b = b[i+len(mark):]
		j := bytes.IndexByte(b, 0)
		if j < 0 {
			return errors.New("an unclosed region placeholder")
		}
		r := l[string(b[:j])]
		if r == nil {
			return fmt.Errorf("region %s was not rendered", b[:j])
		}
		w.Write(r.html)
		b = b[j+1:]
	}
}

// fragWriter marks a request for a page's changed regions (ServeHTTP wraps the writer when X-Tego-Regions is sent):
// render answers the regions instead of the page. have is each region the page shows, with its hash.
type fragWriter struct {
	http.ResponseWriter
	have map[string]string
	// hashes and status are what renderRegions answered: every asked region's hash, for runkey.go's memo.
	hashes map[string]string
	status int
	// entry is the render renderRegions answered from, for the shared region cache (regioncache.go); nil when the
	// handler answered something else (an error page, a redirect).
	entry *regionEntry
}

// Unwrap lets http.ResponseController reach the connection.
func (f *fragWriter) Unwrap() http.ResponseWriter { return f.ResponseWriter }

// maxRegionHeader bounds X-Tego-Regions: a page has at most nine regions (the run page's, the Overview's) with
// 16-hex-digit hashes.
const maxRegionHeader = 1 << 10

// parseRegionHeader reads X-Tego-Regions: "<name>:<hash>,…". It reports false for a malformed or oversized header.
func parseRegionHeader(v string) (map[string]string, bool) {
	if v == "" || len(v) > maxRegionHeader {
		return nil, false
	}
	have := map[string]string{}
	for _, part := range strings.Split(v, ",") {
		n, h, _ := strings.Cut(strings.TrimSpace(part), ":")
		if n == "" {
			return nil, false
		}
		have[n] = h
	}
	return have, true
}

// renderRegions answers a region request: the asked regions whose hash changed, each in a <template>. The render
// is kept on fw (entry) for the shared region cache (regioncache.go).
func renderRegions(fw *fragWriter, status int, t *template.Template, name string, p page) {
	regs, err := regions(t, name, p, fw.have)
	if err != nil {
		http.Error(fw, "tego-control serve: render: "+err.Error(), http.StatusInternalServerError)
		return
	}
	fw.entry = &regionEntry{status: status, sig: p.Sig, rev: p.Rev, names: regionsOf(name), regs: regs}
	fw.answer(fw.entry)
}

// answer writes e as the answer to fw's request: the regions whose hash differs from the one the page shows.
func (f *fragWriter) answer(e *regionEntry) {
	var buf bytes.Buffer
	f.hashes, f.status = make(map[string]string, len(e.regs)), e.status
	for _, n := range e.names {
		r := e.regs[n]
		if r == nil {
			continue
		}
		if _, asked := f.have[n]; !asked {
			continue
		}
		f.hashes[n] = r.Hash
		if f.have[n] == r.Hash {
			continue
		}
		// Name is one of regionsOf's constants and Hash is hex: neither needs escaping in the attribute.
		fmt.Fprintf(&buf, `<template data-live="%s" data-h="%s">`, r.Name, r.Hash)
		buf.Write(r.html)
		buf.WriteString("</template>")
	}
	h := f.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Tego-Sig", e.sig)
	h.Set("X-Tego-Rev", e.rev)
	f.WriteHeader(e.status)
	_, _ = f.Write(visibleHTML(buf.Bytes()))
}

// escapeRegions has html/template escape every region of t as its own entry point at start, so a region's first
// request does not escape templates while other requests execute them, and a broken region fails New, not a page.
func escapeRegions(name string, t *template.Template) error {
	for _, n := range append(regionsOf(name), "lr") {
		if t.Lookup(n) == nil {
			return fmt.Errorf("no template %q", n)
		}
		// A zero page executes too: only an escaping error (html/template's *Error) is a broken template.
		if err := t.ExecuteTemplate(io.Discard, n, page{}); err != nil {
			var te *template.Error
			if errors.As(err, &te) {
				return err
			}
		}
	}
	return nil
}
