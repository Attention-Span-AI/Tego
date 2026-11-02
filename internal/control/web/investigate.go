// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// maxLinked is how many other detections What else lists.
const maxLinked = 6

// linkedWindow is how close in time another detection of the same run must come to count as part of the same story.
const linkedWindow = 10 * time.Second

// investigateData is the Investigate page: one detection in four parts, always in the same order (what, how it got
// there, what else, what now), and the next detection at the same severity.
type investigateData struct {
	D      detection
	Kind   string // what the object is, in words (fileKind), "" when unknown
	Policy string // the policy file the run ran under
	LV     *ledgerview.LineView
	Chain  []ledgerview.ProcRef // the launcher first, the acting process last
	Argv   string               // the acting process's command line, credentials masked
	Linked []detection
	Next   *detection
	Pos    int // 1-based place among the detections of its severity
	OfSev  int
}

// investigate answers /runs/<id>/investigate/<seq>: the detection whose first line is seq, which stays its address as
// a live run adds to it, or whose newest line is.
func (s *Server) investigate(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/runs/")
	id, seqS, _ := strings.Cut(rest, "/investigate/")
	seq, err := strconv.ParseUint(seqS, 10, 64)
	if err != nil {
		s.fail(w, http.StatusNotFound, "Not found", "No detection at this address.")
		return
	}
	snap, ok := s.load(w)
	if !ok {
		return
	}
	run := snap.Find(id)
	all, _ := s.detectionList(snap, s.signals(snap.Runs))
	i := -1
	for j := range all {
		if all[j].Run == id && (all[j].Seq == seq || all[j].FirstSeq == seq) {
			i = j
			break
		}
	}
	if run == nil || i < 0 {
		s.fail(w, http.StatusNotFound, "Not found", "No detection at this address.")
		return
	}
	d := investigateData{D: all[i], Kind: fileKind(all[i].Subject)}
	if run.Contract != "" { // path.Base of "" is ".", which the page would show as the policy
		d.Policy = path.Base(run.Contract)
	}
	for j := range all {
		x := &all[j]
		if x.Severity == d.D.Severity {
			d.OfSev++
			if j <= i {
				d.Pos = d.OfSev
			}
			if j > i && d.Next == nil {
				d.Next = x
			}
		}
		if j != i && x.Run == id && x.Severity > ledgerview.SevLow && linked(x, &d.D) && len(d.Linked) < maxLinked {
			d.Linked = append(d.Linked, *x)
		}
	}
	if lv, err := ledgerview.Explain(s.cfg.Ledger, run, d.D.Seq); err == nil {
		d.LV = lv
		for k := len(lv.Chain) - 1; k >= 0; k-- {
			d.Chain = append(d.Chain, lv.Chain[k])
		}
		if lv.Proc != nil {
			d.Chain = append(d.Chain, *lv.Proc)
			d.Argv = lv.Proc.ArgvMasked
		}
	}
	if d.Kind == "" && d.D.Class == "net" {
		d.Kind = urlHost(d.Argv) // a connect to a bare address: the host its command line names
	}
	c := s.chromeOf(snap, d.D.Verb+" "+mask(tilde(d.D.Subject)), "detections")
	s.render(w, http.StatusOK, "investigate", c, d)
}

// linked reports whether two detections came within linkedWindow of each other at any point. A row that holds a scan
// lasts as long as the scan, and a key read in the middle of it is the first thing a person opening it wants to know.
func linked(a, b *detection) bool {
	return !a.First.After(b.Last.Add(linkedWindow)) && !b.First.After(a.Last.Add(linkedWindow))
}

// logsFor is the Logs search for one detection's object in its run. A subject with a credential in it stays out of the
// address, where the body would not show it: the run's blocked lines hold it.
func logsFor(d detection) string {
	v := url.Values{"run": {d.Run}}
	if q := d.Match(); q != "" {
		v.Set("q", q)
	} else {
		v.Set("verdict", "refused")
	}
	return "/logs?" + v.Encode()
}

// logsByTarget is the Logs view of one detection's refused lines gathered by what each names: a scan's ports, and how
// often each was tried.
func logsByTarget(d detection) string {
	v := url.Values{"run": {d.Run}, "group": {ledgerview.GroupTarget}, "verdict": {"refused"}}
	if q := d.Match(); q != "" {
		v.Set("q", q)
	}
	return "/logs?" + v.Encode()
}

// Match is the text that finds a detection, for a link's address; "" when it holds a credential (mask).
func (d detection) Match() string {
	q := d.LogsText()
	if mask(q) != q {
		return ""
	}
	return q
}

// urlHost is the host of the first http(s) URL in a command line, "" when it names none.
func urlHost(argv string) string {
	for _, f := range strings.Fields(argv) {
		if u, err := url.Parse(f); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	return ""
}
