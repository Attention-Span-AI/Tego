// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// maxCompareRows is how many rows the Compare page shows before "Show all".
const maxCompareRows = 40

func init() {
	funcs["enforcement"] = enforcement
	funcs["cmpForm"] = cmpForm
	funcs["cmpSide"] = cmpSide
	funcs["cmpStats"] = func(a, b ledgerview.CmpSide) []cmpStatView { return []cmpStatView{cmpStat(a, "A"), cmpStat(b, "B")} }
	// cmpUnrec is readGap for a secret row's cell that saw nothing on a run that kept no file read: "not seen" there
	// would claim an absence the run could not record.
	funcs["cmpUnrec"] = func(c ledgerview.CmpCell, class string, r *ledgerview.Run) string {
		if c.Seen || class != "secret" {
			return ""
		}
		return readGap(r)
	}
	funcs["cmpTone"] = func(c ledgerview.CmpCell) string {
		switch c.Tone {
		case ledgerview.ToneBad:
			return "bad"
		case ledgerview.ToneGood:
			return "refused" // Stopped: the stopped tone (tokens.css), green
		case ledgerview.ToneAsk:
			return "asked"
		case ledgerview.ToneMuted:
			return "neutral" // Refused: a refusal the verdict does not count wears no green (tokens.css); grey, as routine is
		}
		return "neutral"
	}
	funcs["cmpIcon"] = func(c ledgerview.CmpCell) string {
		switch c.Word {
		case "Stopped":
			return "i-shield"
		case "Got through":
			return "i-triangle-alert"
		case "Refused":
			return "i-ban"
		case "Allowed":
			return "i-check"
		case "Asked":
			return "i-hand"
		}
		return "i-eye"
	}
}

// cmpStatView is one run's stat block above Compare's sentence (QA QU-11): Label (A or B) and Mode (Watched or
// Enforced) as its kicker, Head the headline ("2 secrets left the machine", "0 left"), Detail the line under it, and
// Tone leak (red), ok (green: Tego stopped something) or neutral.
type cmpStatView struct{ Label, Mode, Head, Detail, Tone string }

// cmpStat is a run's stat block, read from the verdict its banner and chip read (CmpSide.Verdict), so the numbers
// agree: a leak names what left and where, a protected run the attempts Tego stopped (Verdict.Stopped).
func cmpStat(s ledgerview.CmpSide, label string) cmpStatView {
	v := s.Verdict
	st := cmpStatView{Label: label, Mode: "Enforced", Head: "0 left", Tone: "neutral"}
	if s.Run != nil && s.Run.Tier == "observe" {
		st.Mode = "Watched"
	}
	switch v.Kind {
	case ledgerview.VerdictLeak:
		st.Tone, st.Head = "leak", plural4(len(v.Exposed), "secret left the machine", "secrets left the machine")
		st.Detail = baseNames(v.Exposed) + " → " + destWords(v.Dests)
	case ledgerview.VerdictProtected:
		st.Tone, st.Detail = "ok", plural4(v.Stopped(), "attempt stopped", "attempts stopped")
	case ledgerview.VerdictWatched:
		st.Detail = plural4(len(v.Read), "secret read, none sent", "secrets read, none sent")
	default:
		st.Detail = "no attempt on a secret seen"
	}
	if v.Kind != ledgerview.VerdictLeak && v.Kind != ledgerview.VerdictProtected && readGap(s.Run) != "" {
		st.Detail = "file reads not recorded"
	}
	return st
}

// cmpFormData is what the chooser form shows: the runs to pick from and the pair selected.
type cmpFormData struct {
	Runs []*ledgerview.Run
	A, B string
}

// cmpForm builds the chooser; with no pair chosen it starts on cmpPick's. Its lists hold the newest maxPick runs and
// the pair selected: two lists of every run were most of a 2,000-run Runs page (PF-F6).
func cmpForm(runs []*ledgerview.Run, a, b string) cmpFormData {
	if a == "" && b == "" {
		p := cmpPick(runs)
		a, b = p.A, p.B
	}
	if len(runs) > maxPick {
		keep := slices.Clone(runs[:maxPick])
		for _, r := range runs[maxPick:] {
			if r.ID == a || r.ID == b {
				keep = append(keep, r)
			}
		}
		runs = keep
	}
	return cmpFormData{runs, a, b}
}

// maxPick is how many of the newest runs the Compare chooser lists (with the pair selected, when older).
const maxPick = 50

// cmpSideData is one run's header on the Compare page.
type cmpSideData struct {
	ledgerview.CmpSide
	Label string
	Chain ledgerview.Chain
	Now   time.Time
}

func cmpSide(s ledgerview.CmpSide, label string, chain ledgerview.Chain, now time.Time) cmpSideData {
	return cmpSideData{s, label, chain, now}
}

// enforcement says in a word whether the run blocked anything: tier observe records only.
func enforcement(tier string) string {
	switch tier {
	case "observe":
		return "Watched only"
	case "":
		return "—"
	}
	return "Enforced · " + tierWord(tier)
}

// cmpChoice is the pair of runs the chooser starts on.
type cmpChoice struct{ A, B string }

// cmpPick suggests a pair when none is chosen: the newest run that only observed, against the run that enforced the
// same program and started closest to it (the demo starts its two takes together, and a later rehearsal of the
// enforced side is not the watched take's pair), else the newest that enforced.
func cmpPick(runs []*ledgerview.Run) cmpChoice {
	var c cmpChoice
	var watched *ledgerview.Run
	for _, r := range runs { // newest first
		switch {
		case r.Tier == "observe" && c.A == "":
			c.A, watched = r.ID, r
		case r.Tier != "observe" && c.B == "":
			c.B = r.ID
		}
	}
	if watched == nil {
		// No watched run: A is the newest other run, so the two pickers never open on the same run (a page that
		// offers a run against itself only answers "Choose two different runs").
		if c.B != "" {
			c.A = suggestOther(runs, c.B)
		}
		return c
	}
	if best := ledgerview.PairOf(runs, watched); best != nil {
		c.B = best.ID
	}
	return c
}

// suggestOther picks the run to set against id: the newest of the other kind (observed against enforced) that ran the
// same program, as a watched run's reference does (ledgerview.ReferenceRun), else the newest of the other kind, else
// the newest other run.
func suggestOther(runs []*ledgerview.Run, id string) string {
	var self *ledgerview.Run
	for _, r := range runs {
		if r.ID == id {
			self = r
		}
	}
	// The other kind's run of the same program that started closest: the watched take's own pair, as the run
	// page's reference and the Overview's suggested pair name it, not a later rehearsal or Block now take.
	if p := ledgerview.PairOf(runs, self); p != nil {
		return p.ID
	}
	other := ""
	for _, r := range runs {
		if r.ID == id {
			continue
		}
		if self != nil && (r.Tier == "observe") != (self.Tier == "observe") {
			return r.ID
		}
		if other == "" {
			other = r.ID
		}
	}
	return other
}

type compareData struct {
	Runs   []*ledgerview.Run
	A, B   string
	Cmp    *ledgerview.Comparison
	Shown  []ledgerview.CmpRow
	Hidden int
	All    bool
	Err    string
	ChainA ledgerview.Chain
	ChainB ledgerview.Chain
	AllURL string
	Now    time.Time
}

func (s *Server) compare(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.load(w)
	if !ok {
		return
	}
	q := r.URL.Query()
	d := compareData{Runs: snap.Runs, A: q.Get("a"), B: q.Get("b"), All: q.Get("all") == "1", Now: s.cfg.Now()}
	// With nothing chosen the page only offers a pair; with one run it suggests the other and compares.
	chosen := d.A != "" || d.B != ""
	switch {
	case !chosen:
		p := cmpPick(snap.Runs)
		d.A, d.B = p.A, p.B
	case d.B == "":
		d.B = suggestOther(snap.Runs, d.A)
	case d.A == "":
		d.A = suggestOther(snap.Runs, d.B)
	}
	if q.Get("a") == "" || q.Get("b") == "" {
		// One run given (the run page's Compare): the watched run goes on the left, as everywhere in the demo.
		if ra, rb := snap.Find(d.A), snap.Find(d.B); ra != nil && rb != nil && ra.Tier != "observe" && rb.Tier == "observe" {
			d.A, d.B = d.B, d.A
		}
	}
	if chosen {
		ra, rb := snap.Find(d.A), snap.Find(d.B)
		switch {
		case ra == nil:
			d.Err = "No run " + d.A + " is in this ledger root."
		case rb == nil:
			d.Err = "No run " + d.B + " is in this ledger root."
		case ra == rb:
			d.Err = "Choose two different runs to compare."
		default:
			d.Cmp = ledgerview.CompareSignals(ra, rb, s.signalOf(snap.Runs, ra), s.signalOf(snap.Runs, rb), d.All)
			d.Shown = d.Cmp.Rows
			if !d.All && len(d.Shown) > maxCompareRows {
				d.Hidden = len(d.Shown) - maxCompareRows
				d.Shown = d.Shown[:maxCompareRows]
			}
			d.ChainA = ledgerview.VerifyRun(r.Context(), s.cfg.Ledger, ra.ID, s.cfg.Anchor, ra)
			d.ChainB = ledgerview.VerifyRun(r.Context(), s.cfg.Ledger, rb.ID, s.cfg.Anchor, rb)
			d.AllURL = "/compare?" + url.Values{"a": {ra.ID}, "b": {rb.ID}, "all": {"1"}}.Encode()
		}
	}
	s.render(w, http.StatusOK, "compare", s.chromeOf(snap, "Compare runs", "runs"), d)
}
