// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"compress/gzip"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// Logs' rows as fragments, for static/logs.js: GET /logs/rows is the rows of a Logs search after a cursor (the live
// tail: new lines at the top) or before one (older lines, added in place under the page); GET /logs/line is one row
// opened in place, every field of its line in words. Both read only, like the page, and the page works without
// them: its Older lines link and each row's line link are plain addresses.

// logsPage is how many rows Logs shows and each fragment brings.
const logsPage = 100

// rowView is one Logs row with what its cells link to: its program and pid as filters, and the run facts its
// actions need.
type rowView struct {
	ledgerview.Row
	// Home is the run's home, for the path shortener; Live marks a running run (its exec, net and fs rows offer Block)
	// and Contract a run that names a contract file (only its rows can become a rule).
	Home string
	// Cwd is the run's working directory: a file of the project reads ./… (pathWordsIn).
	Cwd            string
	Live, Contract bool
	// ProgURL narrows the search to the row's program and PIDURL to its process; "" when the line names none.
	ProgURL, PIDURL string
	// PID is the line's process (0 when it names none).
	PID int
	// Key is the row's identity on the page (run-seq): logs.js reads the run and line from it.
	Key string
	// Severity is a blocked row's severity (ledgerview.Severity, "Routine" for a background one), "" otherwise.
	Severity string
}

// rowViews labels a page's rows and gives each its links.
func (s *Server) rowViews(lq *logsQuery, rows []ledgerview.Row, snap *ledgerview.Snapshot) []rowView {
	s.labelRows(rows)
	relabelLive(rows, snap.Find)
	watchLabels(rows, snap)
	homes := homesOf(rows, snap)
	sigs := s.signals(snap.Runs)
	out := make([]rowView, len(rows))
	for i, r := range rows {
		v := rowView{Row: r, Home: homes[r.Run], Key: r.Run + "-" + strconv.FormatUint(r.Seq, 10)}
		if run := snap.Find(r.Run); run != nil {
			if sig := sigs.ownOf(run); sig != nil && r.Refused() {
				v.Severity = sig.SeverityOf(&r.Event).String()
			}
			v.Live, v.Contract, v.Cwd = run.State() == "running", run.Contract != "", run.Cwd
		}
		if r.Program != "" {
			toks, _ := lq.toggled(ledgerview.Token{Key: "prog", Value: r.Program})
			v.ProgURL = lq.with("/logs", toks, nil)
		}
		if pid := r.PID(); pid > 0 {
			v.PID = pid
			toks, _ := lq.toggled(ledgerview.Token{Key: "pid", Value: strconv.Itoa(pid)})
			v.PIDURL = lq.with("/logs", toks, nil)
		}
		out[i] = v
	}
	return out
}

// rowsURL is the address logs.js asks for more rows of this search at: /logs/rows with the search's parameters and
// no cursor or grouping.
func (lq *logsQuery) rowsURL() string {
	return lq.with("/logs/rows", nil, map[string]string{"group": "", "after": ""})
}

// logsRows is GET /logs/rows?<search>&after=<cursor> or &before=<cursor>: the rows of the search newer than after
// (newest first, at most a page, a folded refusal group with its whole count and its run and key in data-f, so the
// page drops that run's older row of the group; X-Tego-More says more were left out, so the page loads its first
// page again) or older than before. X-Tego-After is the newest row's cursor (the given one when none is newer),
// X-Tego-Next the cursor of the page after these older rows ("" at the end) and X-Tego-Rows how many rows the whole
// search has.
func (s *Server) logsRows(w http.ResponseWriter, r *http.Request) {
	snap, err := ledgerview.Load(s.cfg.Ledger)
	if err != nil {
		http.Error(w, "tego-control serve: the ledger could not be read", http.StatusInternalServerError)
		return
	}
	q := r.URL.Query()
	lq := readLogsQuery(q, s.cfg.Now()).onPage()
	f := lq.f
	f.PageSize = logsPage
	after, before := q.Get("after"), q.Get("before")
	switch {
	case after != "" && before != "":
		http.Error(w, "tego-control serve: give after or before, not both", http.StatusBadRequest)
		return
	case after != "":
		if !validCursor(after) {
			http.Error(w, "tego-control serve: after is not a row cursor", http.StatusBadRequest)
			return
		}
		// The new rows are the search's first rows down to the cursor, each folded group with its whole count (a
		// new line of a group the page shows moves that group up): the search's own first page, cut there.
		f.PageSize = logsPage + 1
	case before != "":
		if !validCursor(before) {
			http.Error(w, "tego-control serve: before is not a row cursor", http.StatusBadRequest)
			return
		}
		f.Before = before
	}
	pg := snap.Query(f)
	more := false
	if after != "" {
		n := 0
		for n < len(pg.Rows) && pg.Rows[n].NewerThan(after) {
			n++
		}
		more = n > logsPage
		pg.Rows = pg.Rows[:min(n, logsPage)]
	}
	rows := s.rowViews(&lq, pg.Rows, snap)
	var buf bytes.Buffer
	if err := s.pages["logs"].ExecuteTemplate(&buf, "logrows", rows); err != nil {
		http.Error(w, "tego-control serve: render: "+err.Error(), http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	newest := after
	if len(pg.Rows) > 0 && (after != "" || before == "") {
		newest = pg.Rows[0].Cursor()
	}
	h.Set("X-Tego-After", newest)
	if after == "" {
		h.Set("X-Tego-Next", pg.Next)
	}
	if more {
		h.Set("X-Tego-More", "1")
	}
	h.Set("X-Tego-Rows", strconv.Itoa(pg.Groups))
	writeFragment(w, r, buf.Bytes())
}

// validCursor reports whether c reads as a row cursor (ns.run.seq).
func validCursor(c string) bool {
	ns, rest, ok := strings.Cut(c, ".")
	if !ok {
		return false
	}
	run, seq, ok := strings.Cut(rest, ".")
	if _, err := strconv.ParseInt(ns, 10, 64); err != nil || !ok || run == "" {
		return false
	}
	_, err := strconv.ParseUint(seq, 10, 64)
	return err == nil
}

// writeFragment writes an HTML fragment, gzipped when it is worth it and the browser takes it: rows are repetitive
// markup. A fragment carries no secret of the dashboard (no form token), so compressing it beside agent-written
// text gives nothing away.
func writeFragment(w http.ResponseWriter, r *http.Request, b []byte) {
	b = visibleHTML(b)
	h := w.Header()
	h.Add("Vary", "Accept-Encoding")
	if len(b) > 1024 && strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		h.Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		_, _ = zw.Write(b) // the client went away: nothing to tell it
		_ = zw.Close()
		return
	}
	_, _ = w.Write(b)
}

// lineView is one row opened in place: its line explained (ledgerview.Explain), with the row's words beside it.
type lineView struct {
	LV *ledgerview.LineView
	Ev ledgerview.Event
	// Program is the row's program; Into how far into the run the line came; Parents the process's parents in a
	// few words, nearest first.
	Program, Into, Parents string
	// Label is the rule in words.
	Label string
	// Fields is the line's fields after the envelope that say something (the kind and run are on the row).
	Fields []ledgerview.Field
	// Home is the run's home, for the path shortener.
	Home string
}

// logsLine is GET /logs/line?run=<id>&seq=<n>: the inline panel of one row.
func (s *Server) logsLine(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	id := q.Get("run")
	seq, err := strconv.ParseUint(q.Get("seq"), 10, 64)
	if id == "" || err != nil {
		http.Error(w, "tego-control serve: give run and seq", http.StatusBadRequest)
		return
	}
	run, err := ledgerview.LoadRun(s.cfg.Ledger, id)
	if errors.Is(err, os.ErrNotExist) {
		http.Error(w, "tego-control serve: no such run", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "tego-control serve: the run could not be read", http.StatusInternalServerError)
		return
	}
	lv, err := ledgerview.Explain(s.cfg.Ledger, run, seq)
	if errors.Is(err, os.ErrNotExist) {
		http.Error(w, "tego-control serve: no such line", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "tego-control serve: the line could not be read", http.StatusInternalServerError)
		return
	}
	_, at, _, ok := ledgerview.Context(run, seq, 0)
	if !ok {
		http.Error(w, "tego-control serve: no such line", http.StatusNotFound)
		return
	}
	d := lineView{LV: lv, Ev: at, Program: ledgerview.ProgramOf(run, seq), Home: ledgerview.RunHome(run)}
	rows := []ledgerview.Row{{Event: at}}
	s.labelRun(run, rows)
	d.Label = rows[0].Label
	if ledgerview.WatchedLine(run, &at) {
		// The row says it was watched only (watchLabel); opened, it names the rule it would have matched beside that.
		d.Label = watchedRule(at.Rule, d.Label)
	}
	if !run.Start.IsZero() && !at.TS.Before(run.Start) {
		d.Into = human(at.TS.Sub(run.Start).Truncate(time.Millisecond))
	}
	var parents []string
	for _, p := range lv.Chain {
		switch {
		case p.Launcher:
			parents = append(parents, "tego's launcher")
		case p.Name != "":
			parents = append(parents, p.Name+" ("+strconv.Itoa(p.PID)+")")
		default:
			parents = append(parents, "pid "+strconv.Itoa(p.PID))
		}
	}
	d.Parents = strings.Join(parents, " ← ")
	observedFields(lv.Fields, &at)
	for _, f := range lv.Fields {
		switch f.Key {
		case "kind", "run", "agent":
			continue // on the row already
		}
		d.Fields = append(d.Fields, f)
	}
	var buf bytes.Buffer
	if err := s.pages["logs"].ExecuteTemplate(&buf, "logline", &d); err != nil {
		http.Error(w, "tego-control serve: render: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	writeFragment(w, r, buf.Bytes())
}
