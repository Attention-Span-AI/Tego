// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
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
//   - GET /logs.csv is the page's columns in words, masked as the page masks them (shown.go), for a spreadsheet. A cell
//     a spreadsheet would read as a formula (it starts with = + - @, a tab or a carriage return) is prefixed with ',
//     and an invisible character (a bidi override in a file name) is written as the page writes it, ⟦U+202E⟧
//     (visibleText).
//
// Both stop at maxExportLines lines and then say so in a last row; both are oldest first unless order=newest.

// maxExportLines bounds one download.
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
	lq.f.Ledger = true
	h := w.Header()
	h.Set("Content-Type", "application/x-ndjson; charset=utf-8")
	h.Set("Content-Disposition", `attachment; filename="`+exportName(s.cfg.Now(), "jsonl")+`"`)
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	bw := bufio.NewWriterSize(w, 64<<10)
	n, skipped, cut := 0, 0, false
	snap.Each(lq.f, exportOrder(r), func(_ *ledgerview.Event, raw func() ([]byte, error)) bool {
		if n == maxExportLines {
			cut = true
			return false
		}
		b, err := raw()
		if err != nil {
			skipped++ // the file changed since the read model took it: the line is no longer where it was
			return true
		}
		if _, err := bw.Write(b); err != nil {
			return false // the browser went away
		}
		_ = bw.WriteByte('\n') // a failed write fails the next Write too
		n++
		return true
	})
	if cut || skipped > 0 {
		note := exportNote{Lines: n, Skipped: skipped}
		switch {
		case cut:
			note.Note = "stopped at " + strconv.Itoa(maxExportLines) + " lines: narrow the search to download the rest"
		default:
			note.Note = strconv.Itoa(skipped) + " lines were left out: their events file changed while this was read"
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
	h := w.Header()
	h.Set("Content-Type", "text/csv; charset=utf-8")
	h.Set("Content-Disposition", `attachment; filename="`+exportName(s.cfg.Now(), "csv")+`"`)
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	cw := csv.NewWriter(w)
	_ = cw.Write(csvHeader) // a failed write shows in cw.Error, checked as rows go
	lists := map[string]rulesview.Lists{}
	n, cut := 0, false
	row := make([]string, len(csvHeader))
	snap.Each(lq.f, exportOrder(r), func(e *ledgerview.Event, _ func() ([]byte, error)) bool {
		if n == maxExportLines {
			cut = true
			return false
		}
		l, ok := lists[e.Run]
		if !ok {
			l = rulesview.RunLists(s.cfg.Ledger, e.Run)
			lists[e.Run] = l
		}
		what := shown(*e)
		if e.Kind == "exec" {
			what = mask(e.Target) // the whole command: the page's row elides a launcher in front of a shell script
		}
		pid := ""
		if p := e.PID(); p != 0 {
			pid = strconv.Itoa(p)
		}
		v := ledgerview.LogsVerdict(e)
		verdict := verdictWords[v]
		if verdict == "" {
			verdict = v
		}
		row = append(row[:0], e.TS.Local().Format("2006-01-02 15:04:05.000 MST"), e.Run, e.Agent,
			strconv.FormatUint(e.Seq, 10), e.Kind, verdict, shownOp(*e), what, e.Rule, ruleLabel(*e, l), reasonWords(*e),
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
