// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Grouping: Logs' matched lines gathered by process, by target or by rule, so 11,000 lines of a watched run read as
// the few dozen things the agent did. A group counts the same lines Page.Matched counts (a refused action's mirror
// is one refusal with its action), so the groups' counts add up to the page's. Each run's groups are kept per run
// version and filter, like the facets' tallies.

// The groupings Snapshot.Group knows.
const (
	// GroupProcess gathers a run's lines by process: the pid and the program it was running (program.go).
	GroupProcess = "process"
	// GroupTarget gathers lines by what they name (a path, an address, a command line), across runs.
	GroupTarget = "target"
	// GroupRule gathers lines by the rule that decided them, across runs. A line nothing decided (verdict observed:
	// recorded only, as every action of a watched run is) is gathered apart, under the rule it names
	// (GroupRow.Observed).
	GroupRule = "rule"
	// GroupSeverity gathers lines by severity (Severity: High, Medium, Low, Routine), then Observed, Asked, Answered,
	// Allowed and Recorded for the lines that were not blocked, across runs. Observed is a watched run's line: nothing
	// allowed it and nothing stopped it, and its key reads and sends are not "allowed". Answered is a person's answer,
	// a no as much as a yes. Recorded is a line nothing decided: a gap note, a run's start and end, a limit.
	GroupSeverity = "severity"
)

// sevOrder is the order GroupSeverity's groups read in.
var sevOrder = []string{"High", "Medium", "Low", "Routine", "Observed", "Asked", "Answered", "Allowed", "Recorded"}

// GroupRow is one group: what it gathers and how many lines.
type GroupRow struct {
	// Key is the group's identity among the page's groups.
	Key string
	// Run and PID are a process group's run and process (Run is also set on a target or rule group whose lines
	// are all of one run); Program is the program it was running, "" when the record does not say.
	Run     string
	PID     int
	Program string
	// Target is a target group's target and Kind its newest line's kind; Rule a rule group's rule: the rule that
	// decided its lines or, on an Observed group, the rule they name ("" for the lines that name no rule: a run's start
	// and end, a gap note, an answer).
	Target, Kind, Rule string
	// Observed marks a rule group of lines that name Rule but that nothing decided (verdict observed); the lines Rule
	// decided are another group. Watched says every one of them is of a watched run (WatchedLine), where Rule is the
	// contract entry they would have matched. Split marks a rule group whose rule has a group of the other kind in the
	// search too, so the verdict names which of the rule's lines are this group's.
	Observed, Watched, Split bool
	// Severity is a severity group's name (sevOrder).
	Severity string
	// Agent is the newest line's agent.
	Agent string
	// Lines and Refused count the group's lines and the refused ones; First and Last are its oldest and newest
	// line's times, and NewestRun and NewestSeq the newest line.
	Lines, Refused int
	First, Last    time.Time
	NewestRun      string
	NewestSeq      uint64
	runs           int
}

// Grouped is a search's groups, most lines first.
type Grouped struct {
	By   string
	Rows []GroupRow
	// Total is how many groups there are (Rows holds at most the limit); Matched the lines they hold; Keyless the
	// matched lines with nothing to group by (a target grouping's lines that name no target).
	Total, Matched, Keyless int
}

// ValidGroup reports whether by is a grouping Group knows.
func ValidGroup(by string) bool {
	return by == GroupProcess || by == GroupTarget || by == GroupRule || by == GroupSeverity
}

// runGroups is one run's groups under one filter.
type runGroups struct {
	rows    map[string]*GroupRow
	keyless int
}

var groupCache = struct {
	sync.Mutex
	m map[tallyKey]*runGroups
}{m: map[tallyKey]*runGroups{}}

// Group gathers the lines f matches by by (GroupProcess, GroupTarget, GroupRule or GroupSeverity), most lines first
// (ties: the newest first; GroupSeverity in sevOrder), at most limit groups (0: all). An unknown by is an empty Grouped.
// sens is what makes a path a secret for each run, as the pages read its Signal, so GroupSeverity's High is Detections'
// and it shares the run's cached Signal; nil is each run's working folder alone.
func (s *Snapshot) Group(f Filter, by string, limit int, sens func(*Run) Sensitive) Grouped {
	out := Grouped{By: by}
	if !ValidGroup(by) {
		return out
	}
	m := newMatcher(&f)
	fk, keep := facetKey(&f)
	all := map[string]*GroupRow{}
	for _, r := range s.Runs {
		if len(r.AllEvents()) == 0 {
			continue
		}
		rm, ok := m.forRun(r)
		if !ok {
			continue
		}
		var k tallyKey
		var g *runGroups
		rs := Sensitive{Cwd: r.Cwd}
		if sens != nil {
			rs = sens(r)
		}
		if keep && cacheable(r) {
			k = tallyKey{store: r.st.store, run: r.ID, rev: r.Rev, filter: fk + "\x00group:" + by}
			if by == GroupSeverity {
				k.filter += "\x00" + sensKey(rs)
			}
			groupCache.Lock()
			g = groupCache.m[k]
			groupCache.Unlock()
		}
		if g == nil {
			g = groupRun(r, rm, by, rs)
			if keep && cacheable(r) {
				groupCache.Lock()
				if len(groupCache.m) >= maxTallies {
					groupCache.m = map[tallyKey]*runGroups{}
				}
				groupCache.m[k] = g
				groupCache.Unlock()
			}
		}
		out.Keyless += g.keyless
		out.Matched += g.keyless
		for key, row := range g.rows {
			out.Matched += row.Lines
			a := all[key]
			if a == nil {
				cp := *row
				all[key] = &cp
				continue
			}
			mergeGroup(a, row)
		}
	}
	out.Rows = make([]GroupRow, 0, len(all))
	for _, row := range all {
		if row.runs > 1 {
			row.Run = ""
		}
		if by == GroupRule && row.Rule != "" {
			_, row.Split = all[ruleGroupKey(row.Rule, !row.Observed)]
		}
		out.Rows = append(out.Rows, *row)
	}
	slices.SortFunc(out.Rows, func(a, b GroupRow) int {
		switch {
		case by == GroupSeverity:
			return slices.Index(sevOrder, a.Severity) - slices.Index(sevOrder, b.Severity)
		case a.Lines != b.Lines:
			return b.Lines - a.Lines
		case !a.Last.Equal(b.Last):
			return b.Last.Compare(a.Last)
		}
		return strings.Compare(a.Key, b.Key)
	})
	out.Total = len(out.Rows)
	if limit > 0 && len(out.Rows) > limit {
		out.Rows = out.Rows[:limit]
	}
	return out
}

// mergeGroup adds b (another run's part of the same group) into a.
func mergeGroup(a, b *GroupRow) {
	a.Lines += b.Lines
	a.Refused += b.Refused
	a.runs += b.runs
	a.Watched = a.Watched && b.Watched
	if b.First.Before(a.First) {
		a.First = b.First
	}
	if b.Last.After(a.Last) || (b.Last.Equal(a.Last) && b.NewestRun > a.NewestRun) {
		a.Last, a.NewestRun, a.NewestSeq, a.Kind, a.Agent = b.Last, b.NewestRun, b.NewestSeq, b.Kind, b.Agent
	}
}

// groupRun is run r's matched lines (rm) gathered by by; sens is the run's, for GroupSeverity.
func groupRun(r *Run, rm *runMatch, by string, sens Sensitive) *runGroups {
	g := &runGroups{rows: map[string]*GroupRow{}}
	evs := r.AllEvents()
	var names []string
	var of []int32
	if by == GroupProcess {
		names, of = r.progs()
	}
	var sig *RunSignal
	if by == GroupSeverity {
		sig = Signal(r, sens)
	}
	for i := range evs {
		e := &evs[i]
		idx := int32(i) //nolint:gosec // a run holds far fewer than 2^31 lines (MaxLines)
		if ok, _ := rm.match(idx, e); !ok {
			continue
		}
		var key string
		observed := false
		switch by {
		case GroupProcess:
			prog := programAt(names, of, idx)
			key = r.ID + "\x00" + strconv.Itoa(e.pid) + "\x00" + prog
		case GroupTarget:
			if e.Target == "" {
				g.keyless++
				continue
			}
			key = e.Target
		case GroupRule:
			// verdict:observed names these lines in a query (verdictOf), so the group is the lines it lists.
			observed = e.Rule != "" && verdictOf(e) == string(record.VerdictObserved)
			key = ruleGroupKey(logsRule(e), observed)
		case GroupSeverity:
			key = lineSeverity(e, sig)
		}
		row := g.rows[key]
		if row == nil {
			row = &GroupRow{Key: key, Run: r.ID, First: e.TS, runs: 1}
			switch by {
			case GroupProcess:
				row.PID, row.Program = e.pid, programAt(names, of, idx)
			case GroupTarget:
				row.Target = e.Target
			case GroupRule:
				// One run's lines of a group are all of its tier: a watched run's observed lines are all watched.
				row.Rule, row.Observed, row.Watched = logsRule(e), observed, observed && WatchedLine(r, e)
			case GroupSeverity:
				row.Severity = key
			}
			g.rows[key] = row
		}
		row.Lines++
		if e.Refused() {
			row.Refused++
		}
		if e.TS.Before(row.First) {
			row.First = e.TS
		}
		if !e.TS.Before(row.Last) {
			row.Last, row.NewestRun, row.NewestSeq, row.Kind, row.Agent = e.TS, r.ID, e.Seq, e.Kind, e.Agent
		}
	}
	return g
}

// ruleGroupKey is the group key of rule's lines: those it decided, or (observed) those that name it but that nothing
// decided.
func ruleGroupKey(rule string, observed bool) string {
	if observed {
		return rule + "\x00observed"
	}
	return rule
}

// lineSeverity is the severity group of line e (sevOrder).
func lineSeverity(e *Event, sig *RunSignal) string {
	switch {
	case e.Refused():
		return sig.SeverityOf(e).String()
	case e.Kind == "ask" || e.Verdict == "ask":
		return "Asked"
	case e.Kind == "answer":
		return "Answered"
	case e.Verdict == "observed":
		return "Observed"
	case e.Verdict == "allow":
		return "Allowed"
	}
	return "Recorded"
}
