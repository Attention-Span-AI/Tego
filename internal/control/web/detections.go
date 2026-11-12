// SPDX-License-Identifier: Apache-2.0

package web

import (
	"cmp"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// detection is one row of the Detections page: one refusal group of one run (ledgerview.Group), not routine.
type detection struct {
	ledgerview.Group
	Run, Agent, Project string
	Home                string // the run's home, for the path shortener
	Channel, Verb, Rule string
}

// leakRow is one run whose secrets left (ledgerview.VerdictLeak), in the words of the run page's banner.
type leakRow struct {
	Run, Agent, Project string
	Title, Sub          string
	When                time.Time
}

// detectionsData is the Detections page: the runs whose secrets left, first and whatever the filters say; the rows the
// filters keep, High first; and the counts the filter chips show. Watched says some run read secrets with only a
// recorder in the way: no check mark stands over that, whatever was blocked.
type detectionsData struct {
	Leaks      []leakRow
	Watched    bool
	Sev, Ch    string // the filters: "" (High and Medium, Low folded), high, medium or low; "" or a channel
	Rows, Low  []detection
	SevCount   map[string]int // by severity, within the channel filter
	ChCount    map[string]int // by channel, every severity
	Total      int
	Routine    int // routine refusal lines, folded away (Logs has them)
	Severities []string
	Channels   []string
	Now        time.Time
}

// ruleWord is the rule that blocked a detection (its group's newest line), as a short label. Tego's built-in refusal
// of setsockopt(TCP_ULP) reads as the receipt names it (ledgerview.BuiltInRefusal), not as the default deny it is filed
// under, which no rule could lift.
func ruleWord(e ledgerview.Event) string {
	if kind := ledgerview.BuiltInRefusal(e); kind != "" {
		return kind
	}
	rule := e.Rule
	switch {
	case rule == "" || rule == "unmatched" || rule == "host-sockets" || rule == "held-unsupported":
		return "Not in contract"
	case strings.HasPrefix(rule, "fs.deny_read"):
		return "Never read"
	case strings.HasPrefix(rule, "fs.ask"):
		return "Ask first"
	case strings.HasPrefix(rule, "live.block"):
		return "Blocked live"
	}
	return ruleName(rule)
}

// verb is a refused operation in plain words.
func verb(g *ledgerview.Group) string {
	switch g.Op {
	case "exec":
		return "run"
	case "net", "connect":
		return "connect"
	case "mkdir":
		return "create folder"
	case "unlink", "rmdir":
		return "delete"
	case "rename":
		return "rename"
	case "open":
		if strings.HasPrefix(g.Reason, "read") {
			return "read"
		}
		return "open"
	}
	return g.Op
}

// portSpans is a row's ports as a person reads a scan: in order, neighbours as one span ("22, 80, 19100–19249"), at most
// spans of them, then how many ports are left. A row can hold every port of a host, and its words stay short.
func portSpans(ports []string, spans int) string {
	nums := make([]int, 0, len(ports))
	for _, p := range ports {
		if n, err := strconv.Atoi(p); err == nil {
			nums = append(nums, n)
		}
	}
	slices.Sort(nums)
	var parts []string
	shown := 0
	for i := 0; i < len(nums) && len(parts) < spans; {
		j := i
		for j+1 < len(nums) && nums[j+1] == nums[j]+1 {
			j++
		}
		w := strconv.Itoa(nums[i])
		if j > i {
			w += "–" + strconv.Itoa(nums[j])
		}
		parts = append(parts, w)
		shown += j - i + 1
		i = j + 1
	}
	return moreWords(strings.Join(parts, ", "), len(ports)-shown)
}

// someOf is the first n of xs, for a title: a row can hold 60,000 targets, and every page that shows it would carry them.
func someOf(xs []string, n int) string {
	n = min(n, len(xs))
	return moreWords(strings.Join(xs[:n], ", "), len(xs)-n)
}

// moreWords is shown, and how many are left when any are.
func moreWords(shown string, more int) string {
	if more > 0 {
		return shown + " and " + strconv.Itoa(more) + " more"
	}
	return shown
}

// leaksOf is the runs whose secrets left, newest first: the worst thing the ledger can say, which no refusal group
// holds, because nothing was refused. The verdict is the one the Overview's headline and the run page read. watched
// says some other run's verdict is VerdictWatched.
func leaksOf(snap *ledgerview.Snapshot, sigs *sigMemo) (out []leakRow, watched bool) {
	for _, run := range snap.Runs {
		v := ledgerview.RunVerdict(run, sigs.of(run))
		watched = watched || v.Kind == ledgerview.VerdictWatched
		if v.Kind != ledgerview.VerdictLeak {
			continue
		}
		st := storyOf(v, false)
		out = append(out, leakRow{Run: run.ID, Agent: run.Agent, Project: path.Base(run.Cwd), Title: st.Title, Sub: st.Sub, When: run.Start})
	}
	return out, watched
}

// detectionList is every refusal group of every run that is not routine, High first, then newest; routine counts
// the routine refusal lines left out.
func (s *Server) detectionList(snap *ledgerview.Snapshot, sigs *sigMemo) (all []detection, routine int) {
	for _, run := range snap.Runs {
		sig := sigs.ownOf(run)
		if sig == nil {
			continue
		}
		routine += sig.BackgroundLines
		for _, g := range sig.Groups {
			if g.Background {
				continue
			}
			all = append(all, detection{Group: g, Run: run.ID, Agent: run.Agent, Project: path.Base(run.Cwd), Home: ledgerview.RunHome(run),
				Channel: ledgerview.Channel(g.Class), Verb: verb(&g), Rule: ruleWord(g.Event)})
		}
	}
	slices.SortStableFunc(all, func(a, b detection) int {
		return cmp.Or(cmp.Compare(b.Severity, a.Severity), b.Last.Compare(a.Last))
	})
	return all, routine
}

// detections answers /detections: every refusal group of every run that is not routine, High first, then newest.
func (s *Server) detections(w http.ResponseWriter, r *http.Request) {
	snap, ok := s.load(w)
	if !ok {
		return
	}
	q := r.URL.Query()
	d := detectionsData{Sev: strings.ToLower(q.Get("sev")), Ch: strings.ToLower(q.Get("ch")),
		SevCount: map[string]int{}, ChCount: map[string]int{},
		Severities: []string{"High", "Medium", "Low"}, Channels: []string{"Files", "Programs", "Network"}, Now: s.cfg.Now()}
	sigs := s.signals(snap.Runs)
	d.Leaks, d.Watched = leaksOf(snap, sigs)
	all, routine := s.detectionList(snap, sigs)
	d.Routine = routine
	for _, x := range all {
		d.ChCount[x.Channel]++
		if d.Ch != "" && strings.ToLower(x.Channel) != d.Ch {
			continue
		}
		sev := x.Severity.String()
		d.SevCount[sev]++
		switch {
		case d.Sev != "" && strings.ToLower(sev) != d.Sev:
		case d.Sev == "" && x.Severity == ledgerview.SevLow:
			d.Low = append(d.Low, x) // folded under the list unless asked for
		default:
			d.Rows = append(d.Rows, x)
		}
	}
	d.Total = len(all)
	c := s.chromeOf(snap, "Detections", "detections")
	if n := s.severityNote(); n != "" {
		c.Notes = append(c.Notes, n)
	}
	s.render(w, http.StatusOK, "detections", c, d)
}
