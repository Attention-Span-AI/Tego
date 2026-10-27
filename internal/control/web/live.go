// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
)

// What static/live.js follows, so a page changes only when the ledger did, and only where it did. The live state is
// how many runs are live and asks are waiting, with two short fingerprints, Sig (changes when the set of waiting asks
// does) and Rev (ledgerview's revision: changes when a run writes a line, starts or ends, or an ask comes or goes). GET /events
// pushes it as Server-Sent Events, one "state" event each time it changes and a heartbeat comment when it does not;
// GET /status.json answers it once, the fallback a page polls while it has no stream. On a change the page asks for
// its changed live regions (regions.go). GET /runs/<id>/rows?after=<seq> is a run's timeline rows newer than line
// seq, as HTML, so a live run's page adds its new rows instead of re-rendering the whole timeline. All pass the same
// Host and session checks as every page.

// timelinePage is how many rows the run timeline shows at a time; "Older" pages back by seq.
const timelinePage = 200

// liveState is the body of /status.json, and what a page records at render time to compare against.
type liveState struct {
	Live    int    `json:"live"`
	Pending int    `json:"pending"`
	Sig     string `json:"sig"`
	Rev     string `json:"rev"`
}

// stateOf is the snapshot's live state. Rev is the read model's own revision (ledgerview's Snapshot.Rev, D-CACHE),
// which moves exactly when a run gains lines, starts, ends, changes its live state or leaves the root, so an ask
// coming or going moves it too; Sig hashes the waiting asks so a page can tell an ask change from a new line.
func stateOf(snap *ledgerview.Snapshot) liveState {
	var st liveState
	sig := sha256.New()
	for _, a := range snap.Pending() {
		st.Pending++
		_, _ = fmt.Fprintf(sig, "%s\x00%s\x00", a.Run, a.AskID)
	}
	st.Sig = hex.EncodeToString(sig.Sum(nil))[:12]
	for _, r := range snap.Runs {
		if r.Live {
			st.Live++
		}
	}
	st.Rev = strconv.FormatUint(snap.Rev, 36)
	return st
}

// liveCache is the live state, read at most once per tick however many pages follow it.
type liveCache struct {
	mu sync.Mutex
	at time.Time
	st liveState
}

// liveNow is the live state, at most three quarters of a tick old (fresh when fresh is set): the one place the
// dashboard reads it. The load is the read model's cached snapshot (ledgerview.Load shares one Store per root), so a
// look costs a directory listing and one Lstat per run plus whatever lines were appended.
func (s *Server) liveNow(fresh bool) (liveState, error) {
	s.live.mu.Lock()
	defer s.live.mu.Unlock()
	if !fresh && !s.live.at.IsZero() && time.Since(s.live.at) < s.tick*3/4 {
		return s.live.st, nil
	}
	// LoadNow, not Load: while another request decodes runs (a cold start), the state is the one last published, so
	// /status.json and the streams answer at once and the read's publish moves Rev when it lands.
	snap, err := ledgerview.LoadNow(s.cfg.Ledger)
	if err != nil {
		return liveState{}, err
	}
	s.live.st, s.live.at = stateOf(snap), time.Now()
	return s.live.st, nil
}

func (s *Server) status(w http.ResponseWriter, _ *http.Request) {
	st, err := s.liveNow(true) // one poll per page every 2 s: the cache is for the streams
	if err != nil {
		http.Error(w, "tego-control serve: the ledger could not be read", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(st)
}

const (
	// maxStreams bounds the open /events streams; one more gets 503 and its page polls /status.json instead. A
	// browser opens at most 6 HTTP/1.1 connections to one host and a stream holds one for as long as it lasts, so the
	// bound stays well under 6: past it the streams would take every connection and the dashboard's own fetches,
	// form posts and page loads would hang. live.js also closes a hidden tab's stream.
	maxStreams = 4
	// heartbeatTicks is how many quiet ticks pass before the stream writes a heartbeat comment, so a page notices a
	// dead connection and a proxy does not close an idle one.
	heartbeatTicks = 15
	// maxStream is how long one stream lasts; the page then opens another, so nothing holds a connection for ever.
	maxStream = 10 * time.Minute
	// streamWrite bounds each write to the stream, in place of the server's WriteTimeout, which would cut the stream.
	streamWrite = 10 * time.Second
)

// events is GET /events: the live state as Server-Sent Events. The page's EventSource sends the session cookie like
// every same-origin request, and ServeHTTP has checked it and the Host before this runs.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "text/event-stream")
		return
	}
	if s.streams.Add(1) > maxStreams {
		s.streams.Add(-1)
		http.Error(w, "tego-control serve: too many live streams open; this page polls instead", http.StatusServiceUnavailable)
		return
	}
	defer s.streams.Add(-1)
	rc := http.NewResponseController(w)
	// The server's ReadTimeout would end this request's context mid-stream (net/http reads the idle connection in
	// the background under that deadline and cancels the request when it expires), and its WriteTimeout would cut
	// the stream after 30 s: lift the read deadline and bound each write instead. A writer that cannot set
	// deadlines (a test recorder) has none to lift.
	_ = rc.SetReadDeadline(time.Time{})
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	send := func(msg string) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(streamWrite))
		if _, err := io.WriteString(w, msg); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !send("retry: 2000\n\n") {
		return
	}
	tick := time.NewTicker(s.tick)
	defer tick.Stop()
	end := time.NewTimer(maxStream)
	defer end.Stop()
	last, quiet := "", 0
	for {
		st, err := s.liveNow(false)
		if err != nil {
			// The ledger cannot be read: say so and end, so the page shows "reconnecting" and polls /status.json
			// (which answers 500 for the same reason) instead of showing Live over a stream that never sends a state.
			_ = send("event: lost\ndata: {}\n\n")
			return
		}
		if b, _ := json.Marshal(st); string(b) != last {
			last, quiet = string(b), 0
			if !send("event: state\ndata: " + last + "\n\n") {
				return
			}
		}
		if quiet >= heartbeatTicks {
			quiet = 0
			if !send(": hb\n\n") {
				return
			}
		}
		select {
		case <-r.Context().Done():
			return
		case <-end.C:
			return
		case <-tick.C:
			quiet++
		}
	}
}

// timeline is the run's timeline: newest first, one row per refusal (a refused action's mirror line is left out,
// ledgerview pair.go), identical refusals folded (each group in the place of its newest line), and only refusals
// when verdict is "refused". A gap that says only that the machine has no price table is left out too
// (ledgerview.QuietGap; Logs keeps every line). Rows come in strictly falling Seq order, the order the paging cursors
// (before, after) rely on. The read model builds it once per version of the run; Rows builds only the rows a page
// shows.
func timeline(run *ledgerview.Run, verdict string) *ledgerview.Timeline {
	return ledgerview.TimelineOf(run, verdict == "refused")
}

// lastSeq is the seq of the run's last line read, the cursor a live page polls after.
func lastSeq(run *ledgerview.Run) uint64 {
	if n := len(run.Events); n > 0 {
		return run.Events[n-1].Seq
	}
	return 0
}

// foldKey names a folded refusal group, so the live page can drop a group's older row when a newer line of the same
// group arrives at the top. Other rows have no key.
func foldKey(e ledgerview.Event) string {
	if !e.Refused() {
		return ""
	}
	h := sha256.Sum256([]byte(e.Kind + "\x00" + e.Rule + "\x00" + e.Reason + "\x00" + e.Op + "\x00" + e.Target))
	return hex.EncodeToString(h[:6])
}

func (s *Server) labelRun(run *ledgerview.Run, rows []ledgerview.Row) {
	lists := rulesview.RunLists(s.cfg.Ledger, run.ID)
	for i := range rows {
		rows[i].Label = ruleLabel(rows[i].Event, lists)
	}
	relabelLive(rows, func(string) *ledgerview.Run { return run })
}

// rows is GET /runs/<id>/rows?after=<seq>[&verdict=refused]: the timeline rows whose newest line is after seq, newest
// first, each folded group with its whole count. X-Tego-After is the cursor for the next poll; X-Tego-Live is 0 once
// the run is no longer live, which tells the page to load itself once more and stop polling.
func (s *Server) rows(w http.ResponseWriter, r *http.Request, id string) {
	after, err := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	if err != nil {
		http.Error(w, "tego-control serve: after is a line number", http.StatusBadRequest)
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
	// A watched run's rows carry the verdict's marks (story.go tlMarked), as its page does. The verdict reads the
	// run against its enforced reference run, so it takes the whole snapshot (warm: the page just read it); an
	// enforced run's rows skip it, and only a leak marks rows there.
	var v ledgerview.Verdict
	tl := timeline(run, r.URL.Query().Get("verdict"))
	if run.Tier == "observe" || r.URL.Query().Get("verdict") == "leak" {
		if snap, err := ledgerview.Load(s.cfg.Ledger); err == nil {
			v = ledgerview.RunVerdict(run, s.signalOf(snap.Runs, run))
			if r.URL.Query().Get("verdict") == "leak" {
				tl = ledgerview.MarkedTimeline(run, v)
			}
		}
	}
	n := tl.Len()
	if after < math.MaxUint64 {
		n = tl.Below(after + 1) // the rows whose newest line is after seq
	}
	rows := tl.Rows(0, min(n, timelinePage))
	s.labelRun(run, rows)
	var buf bytes.Buffer
	t := tlMarkedOf(tlOf(rows, run.Live, run.Contract != "", liveChanges(s.feed(), run, rows, after, r.URL.Query().Get("verdict"))),
		v, run.Tier == "observe", ledgerview.RunHome(run))
	if err := s.pages["run"].ExecuteTemplate(&buf, "tlrows", t); err != nil {
		http.Error(w, "tego-control serve: render: "+err.Error(), http.StatusInternalServerError)
		return
	}
	live := "0"
	if run.Live {
		live = "1"
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Tego-After", strconv.FormatUint(max(lastSeq(run), after), 10))
	h.Set("X-Tego-Live", live)
	// The rows are most of what a busy live run sends, and repetitive markup: gzipped (writeFragment), they are a tenth.
	writeFragment(w, r, buf.Bytes())
}
