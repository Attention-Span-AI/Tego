// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rulesview"
)

// downloadProposal serves the proposal as a file to save and review beside the contract in use.
func (s *Server) downloadProposal(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		s.fail(w, http.StatusMethodNotAllowed, "Method not allowed", "The proposal is downloaded with GET.")
		return
	}
	p := rulesview.Learn(r.Context(), s.cfg.Ledger, s.cfg.Anchor, id)
	if p.Err != "" {
		s.fail(w, http.StatusNotFound, "No proposal", "No proposal could be made for run "+id+": "+p.Err)
		return
	}
	// The file is the tab's text: a run that leaked never has the address its secrets went to allowed (QA PW-1). The
	// run is read as the run page reads it; one that cannot be read serves nothing rather than an unchecked proposal.
	run, err := ledgerview.LoadRun(s.cfg.Ledger, id)
	if err != nil {
		s.fail(w, http.StatusInternalServerError, "The run could not be read", err.Error())
		return
	}
	snap, ok := s.load(w)
	if !ok {
		return
	}
	text, _ := rulesview.Withhold(p.Text, s.leakDests(snap.Runs, run))
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+id+`.contract.yaml"`) // a run id is [a-z0-9-]
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(text))
}

// leakDests are the destinations a contract made from run r must never allow (ledgerview.Verdict.NeverAllow, QA PW-1):
// where r's secrets went when its verdict is a leak, nil for any other verdict or a nil run.
func (s *Server) leakDests(all []*ledgerview.Run, r *ledgerview.Run) []string {
	if r == nil {
		return nil
	}
	return ledgerview.RunVerdict(r, s.signalOf(all, r)).NeverAllow()
}

// tierFact is one enforcement tier as this machine's runs show it.
type tierFact struct {
	N, Name, Word, Needs string
	// Has is this machine running it (a run here ran at it or above); Missing says what it lacks.
	Has     bool
	Missing string
	// Used is the newest run that ran at this tier, nil when none of the dashboard's runs did.
	Used *ledgerview.Run
}

// machineData is the This machine page: which tiers this machine's runs used, and what the newest run's run_start
// recorded about the machine.
type machineData struct {
	Run          *ledgerview.Run
	Tier, Kernel string
	// Watch: the newest run was watch-only (tier observe), so it says nothing about the tiers; Best is the highest
	// tier any run here used, "" when none was enforced.
	Watch        bool
	Best         *tierFact
	NetAssurance string
	NetGuards    []string
	NetMissing   []string
	Caps         []string
	NoCaps       []string
	BestEffort   []string
	Tiers        []tierFact
	Plane        string
	Err          string
	Now          time.Time
}

func (s *Server) machine(w http.ResponseWriter, _ *http.Request) {
	snap, ok := s.load(w)
	if !ok {
		return
	}
	d := machineData{Now: s.cfg.Now()}
	var newest *ledgerview.Run
	for _, r := range snap.Runs {
		if newest == nil || r.Start.After(newest.Start) {
			newest = r
		}
	}
	d.Run = newest
	d.Tiers = tierFacts(snap.Runs)
	for i := range d.Tiers {
		if d.Tiers[i].Used != nil {
			d.Best = &d.Tiers[i]
		}
	}
	if newest != nil {
		d.Watch = newest.Tier == "observe"
		st, err := rulesview.RunStart(s.cfg.Ledger, newest.ID)
		if err != nil {
			d.Err = err.Error()
		}
		d.Tier, d.Kernel, d.NetAssurance, d.Plane, d.BestEffort = st.Tier, st.Kernel, st.NetAssurance, st.DecisionPlane, st.BestEffort
		for k, ok := range st.NetGuarantees {
			if ok {
				d.NetGuards = append(d.NetGuards, k)
			} else {
				d.NetMissing = append(d.NetMissing, k)
			}
		}
		for k, ok := range st.Capabilities {
			if ok {
				d.Caps = append(d.Caps, k)
			} else {
				d.NoCaps = append(d.NoCaps, k)
			}
		}
		for _, xs := range [][]string{d.NetGuards, d.NetMissing, d.Caps, d.NoCaps} {
			slices.Sort(xs)
		}
	}
	s.render(w, http.StatusOK, "machine", s.chromeOf(snap, "This machine", "machine"), d)
}

// tierFacts is the three enforcement tiers against the runs the dashboard's snapshot holds (no ledger read): each
// names the newest run that ran at it; a tier at or below the highest one used is on this machine, and each one
// above it says what it needs. A watch-only run (tier observe) uses no tier, so a newest run that only watched
// leaves the tiers as the runs before it showed them.
func tierFacts(runs []*ledgerview.Run) []tierFact {
	ts := []tierFact{
		{N: "1", Name: "landlock", Word: "Landlock", Needs: "No admin rights"},
		{N: "2", Name: "cgroup", Word: "cgroup BPF", Needs: "Root"},
		{N: "3", Name: "bpflsm", Word: "BPF LSM", Needs: "Root · BPF LSM at boot"},
	}
	at := 0
	for _, r := range runs {
		n := map[string]int{"landlock": 1, "cgroup": 2, "bpflsm": 3}[strings.ToLower(r.Tier)]
		if n == 0 {
			continue
		}
		at = max(at, n)
		if u := ts[n-1].Used; u == nil || r.Start.After(u.Start) {
			ts[n-1].Used = r
		}
	}
	for i := range ts {
		ts[i].Has = i+1 <= at
		if ts[i].Has {
			continue
		}
		switch ts[i].Name {
		case "landlock":
			ts[i].Missing = "Check with tego doctor"
		case "cgroup":
			ts[i].Missing = "Run with sudo"
		case "bpflsm":
			ts[i].Missing = "Run with sudo · add bpf to the kernel's lsm= list"
		}
	}
	return ts
}
