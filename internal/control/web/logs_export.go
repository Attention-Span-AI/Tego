// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
)

// The Logs downloads: every line the page's search matches (the page's own filter, unfolded and unpaged), as GET
// requests behind the same Host, peer and cookie checks as the page.
//
//   - GET /logs.jsonl is the exact ledger lines, byte for byte as the events files hold them. They are not masked: it
//     is the person's own ledger, read on their own machine, and the download button says so. For one whole run and
//     no other narrowing it is that run's events file itself, a refused action's mirror line included (Filter.Ledger),
//     so its chain checks; any other search gives the matching lines as Logs counts them, without the mirror lines,
//     which the button's title says is not a chain anything can check.
//   - GET /logs.csv is the page's columns in words, the rule as the row words it (rowLabeler), masked as the page masks
//     them (shown.go), for a spreadsheet. A cell a spreadsheet would read as a formula (it starts with = + - @, a tab
//     or a carriage return) is prefixed with ', and an invisible character (a bidi override in a file name) is written
//     as the page writes it, ⟦U+202E⟧ (visibleText).
//
// Filtered downloads stop at maxExportLines and say so. A whole-run JSONL download streams the
// complete file observed at open, preserving its chain even when the dashboard holds only a window.
// Both orders default to oldest first. Refused lines are download notes, never events:
// JSONL uses tego_export_note rows; CSV uses the existing single-cell # note convention.
// Each note names the run, byte offset and decoder reason.

// maxExportLines bounds filtered downloads and CSV.
const maxExportLines = 1_000_000

// exportNote is the JSONL note row: not a ledger line (it has no seq or kind), only a sentence and the counts.
type exportNote struct {
	Note    string `json:"tego_export_note"`
	Lines   int    `json:"lines"`
	Skipped int    `json:"skipped,omitempty"`
}

func exportOrder(r *http.Request) ledgerview.Order {
	if r.URL.Query().Get("order") == "newest" {
		return ledgerview.NewestFirst
	}
	return ledgerview.OldestFirst
}

func exportName(now time.Time, ext string) string {
	return "tego-logs-" + now.Local().Format("20060102-150405") + "." + ext
}

func (s *Server) logsJSONL(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.load(w)
	if !ok {
		return
	}
	lq := readLogsQuery(r.URL.Query(), s.cfg.Now())
	if refuseUnreadQuery(w, &lq) {
		return
	}
	lq.f.Ledger = true
	_, whole := lq.f.WholeRun()
	h := w.Header()
	h.Set("Content-Type", "application/x-ndjson; charset=utf-8")
	h.Set("Content-Disposition", `attachment; filename="`+exportName(s.cfg.Now(), "jsonl")+`"`)
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	bw := bufio.NewWriterSize(w, 64<<10)
	n, skipped, cut := 0, 0, false
	snap.Each(lq.f, exportOrder(r), func(e *ledgerview.Event, raw func() ([]byte, error)) bool {
		if !whole && n == maxExportLines {
			cut = true
			return false
		}
		b, err := raw()
		if err != nil {
			skipped++
			note := exportNote{Note: exportRefusal(e, err), Lines: n, Skipped: 1}
			if b, marshalErr := json.Marshal(note); marshalErr == nil {
				_, _ = bw.Write(append(b, '\n'))
			}
			return true
		}
		if _, err := bw.Write(b); err != nil {
			return false // the browser went away
		}
		_ = bw.WriteByte('\n') // a failed write fails the next Write too
		n++
		return true
	})
	if cut {
		note := exportNote{Lines: n, Skipped: skipped}
		switch {
		case cut:
			note.Note = "stopped at " + strconv.Itoa(maxExportLines) + " lines: narrow the search to download the rest"
		default:
			note.Note = strconv.Itoa(skipped) + " lines were left out"
		}
		if b, err := json.Marshal(note); err == nil {
			_, _ = bw.Write(append(b, '\n')) // the download is already under way: nothing else to tell
		}
	}
	_ = bw.Flush() // as above
}

// csvHeader is the CSV columns.
var csvHeader = []string{"Time", "Run", "Agent", "Line", "Kind", "Verdict", "Action", "What", "Rule", "Rule in words", "Why", "Host", "PID"}

// csvCell makes a cell safe to open in a spreadsheet: one that would be read as a formula gets a leading '.
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func (s *Server) logsCSV(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.load(w)
	if !ok {
		return
	}
	lq := readLogsQuery(r.URL.Query(), s.cfg.Now())
	if refuseUnreadQuery(w, &lq) {
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/csv; charset=utf-8")
	h.Set("Content-Disposition", `attachment; filename="`+exportName(s.cfg.Now(), "csv")+`"`)
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	cw := csv.NewWriter(w)
	_ = cw.Write(csvHeader) // a failed write shows in cw.Error, checked as rows go
	labels := rowLabeler{ledger: s.cfg.Ledger, snap: snap, runs: map[string]*runLabels{}, sigs: s.signals(snap.Runs)}
	n, cut := 0, false
	row := make([]string, len(csvHeader))
	snap.Each(lq.f, exportOrder(r), func(e *ledgerview.Event, raw func() ([]byte, error)) bool {
		if n == maxExportLines {
			cut = true
			return false
		}
		if _, err := raw(); err != nil {
			return cw.Write([]string{"# " + exportRefusal(e, err)}) == nil
		}
		pid := ""
		if p := e.PID(); p != 0 {
			pid = strconv.Itoa(p)
		}
		w := lineWordsOf(*e, labels.reads(e))
		row = append(row[:0], e.TS.Local().Format("2006-01-02 15:04:05.000 MST"), e.Run, e.Agent,
			strconv.FormatUint(e.Seq, 10), e.Kind, w.Verdict, w.Action, w.What, e.Rule, labels.label(e), w.Why,
			e.Host, pid)
		for i := range row {
			row[i] = csvCell(visibleText(row[i]))
		}
		if cw.Write(row) != nil {
			return false // the browser went away
		}
		n++
		return true
	})
	if cut {
		_ = cw.Write([]string{"# stopped at " + strconv.Itoa(maxExportLines) + " lines: narrow the search to download the rest"}) // as above
	}
	cw.Flush()
}

// rowLabeler words a line's rule as its Logs row does (rowViews: labelRows, then relabelLive, then watchLabels), one
// line at a time for the CSV: a watched run's observed line reads watchedLabel, a live block's refusal who blocked it
// and when (blockLabels), any other line its rule in words (ruleLabel). Each run's contract lists and live blocks are
// read once.
type rowLabeler struct {
	ledger string
	snap   *ledgerview.Snapshot
	runs   map[string]*runLabels
	sigs   *sigMemo
}

// runLabels is what rowLabeler read of one run: blocks is nil until the run's first live-block line.
type runLabels struct {
	run    *ledgerview.Run
	lists  rulesview.Lists
	blocks map[string]string
	reads  *readContext
}

// of is the labels of e's run, read once.
func (l *rowLabeler) of(e *ledgerview.Event) *runLabels {
	r := l.runs[e.Run]
	if r == nil {
		r = &runLabels{run: l.snap.Find(e.Run), lists: rulesview.RunLists(l.ledger, e.Run)}
		if r.run != nil {
			r.reads = readContextOf(r.run, l.sigs.ownOf(r.run))
		}
		l.runs[e.Run] = r
	}
	return r
}

// reads is the run's read context as the page's rows have it (rowViews), nil for a line of a run the read model lacks.
func (l *rowLabeler) reads(e *ledgerview.Event) *readContext { return l.of(e).reads }

func (l *rowLabeler) label(e *ledgerview.Event) string {
	r := l.of(e)
	if strings.HasPrefix(e.Rule, "live.block[") {
		if r.blocks == nil {
			r.blocks = blockLabels(r.run)
		}
		if b, ok := r.blocks[e.Rule]; ok {
			if m := watchedMarkLabel(r.run, e, b); m != b {
				return sameFileLabel(m, e) // a watch-only mark names itself, as the row does
			}
			if !ledgerview.WatchedLine(r.run, e) {
				return sameFileLabel(b, e)
			}
		}
	}
	if ledgerview.WatchedLine(r.run, e) {
		return watchedLabel
	}
	return ruleLabel(*e, r.lists)
}

func exportRefusal(e *ledgerview.Event, err error) string {
	return fmt.Sprintf("left out %s line at byte offset %d: %v", e.Run, e.ByteOffset(), err)
}

// refuseUnreadQuery answers 400 when the query could not be read in full: a download of the lines of a part of it would
// pass for all of what was asked.
func refuseUnreadQuery(w http.ResponseWriter, lq *logsQuery) bool {
	if lq.err == nil {
		return false
	}
	http.Error(w, "tego-control serve: this query could not be read in full, so nothing is downloaded. "+queryErrWords(lq.err), http.StatusBadRequest)
	return true
}
