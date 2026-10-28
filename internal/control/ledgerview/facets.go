// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"slices"
	"strconv"
	"strings"
	"sync"
)

// Facets: Logs' matched lines counted by kind, verdict, rule, host and run, so a person sees what a search holds and
// narrows it with one click. They are counted in the same walk as the filter (Query), over the lines Page.Matched
// counts, so a facet's count is the number of lines the search plus that value would match.

// FacetTop is how many values each facet lists.
const FacetTop = 10

// FacetValue is one value of a facet and how many matched lines have it.
type FacetValue struct {
	Value string
	Count int
}

// Facet is a facet's FacetTop values with the most lines, most first (ties by value), and how many values it has.
type Facet struct {
	Values   []FacetValue
	Distinct int
}

// Facets is the matched lines counted five ways. Kind is the kind as Logs groups them (Filter.Kind), Verdict is
// verdictOf, Rule the rule key, Host Event.Host and Run the run id; a line with no rule or no host is in neither of
// those two. Kind's "refused" also counts the refusal notes kind:refused lists (countMirror), so Kind's values add up
// to the matched lines plus those.
type Facets struct {
	Kind, Verdict, Rule, Host, Run Facet
	// Program is the program the line's process was running (program.go); a line whose program the record does
	// not say is in none.
	Program Facet
	// WatchedRules is the rule keys among Rule.Values whose every counted line is of a watched run (tier observe):
	// no rule decided those lines, tego watch only recorded them, so Logs words them as watched, not as the rule.
	WatchedRules map[string]bool
}

// runTally is one run's matched lines counted by each facet. Kinds and verdicts are few, so they are counted in
// short lists rather than maps (a facet pass over 350,000 lines must stay inside a page's budget).
type runTally struct {
	n             int
	kinds, verdts []FacetValue
	rules, hosts  map[string]int
	progs         map[string]int
}

func newRunTally() *runTally {
	return &runTally{rules: map[string]int{}, hosts: map[string]int{}, progs: map[string]int{}}
}

func bump(vs []FacetValue, v string) []FacetValue {
	for i := range vs {
		if vs[i].Value == v {
			vs[i].Count++
			return vs
		}
	}
	return append(vs, FacetValue{v, 1})
}

func (t *runTally) count(e *Event, prog string) {
	t.n++
	t.kinds = bump(t.kinds, logsKind(e.Kind))
	t.verdts = bump(t.verdts, verdictOf(e))
	if e.Rule != "" {
		t.rules[e.Rule]++
	}
	if e.Host != "" {
		t.hosts[e.Host]++
	}
	if prog != "" {
		t.progs[prog]++
	}
}

// countMirror counts a refused action's mirror that the search left out (it counts the action) under the Kind
// facet's "refused" alone, when the search would list it by kind: kind:refused lists the mirror lines (Filter.Kind),
// so the facet's count is what a click on it matches. The mirror is in no other facet and not in the run's count, so
// the Kind facet's values add up to the matched lines plus these refusal notes.
func (t *runTally) countMirror(rm *runMatch, i int32, e *Event) {
	if rm.mirrors {
		return // the search lists mirrors, so match already took or refused this one on its own
	}
	rm.mirrors = true
	ok, _ := rm.match(i, e)
	rm.mirrors = false
	if ok {
		t.kinds = bump(t.kinds, "refused")
	}
}

// tallyKey names one run version's tally under one filter: the store and run, the run's revision (a new line is a
// new revision) and the filter's line fields (facetKey).
type tallyKey struct {
	store  *Store
	run    string
	rev    uint64
	filter string
}

// maxTallies bounds the tally cache, dropped wholesale past it (a few filters for each of thousands of runs).
const maxTallies = 1 << 14

var tallies = struct {
	sync.Mutex
	m map[tallyKey]*runTally
}{m: map[tallyKey]*runTally{}}

// facetKey is f's fields that decide which of a run's lines match: everything but the run selection and paging, so
// one run's tally serves every search that differs only in those. ok is false for a filter whose tallies are not
// worth keeping (one that matches nothing).
func facetKey(f *Filter) (string, bool) {
	if f.none {
		return "", false
	}
	var b strings.Builder
	sep := func() { b.WriteByte(0) }
	list := func(xs []string) {
		for _, x := range xs {
			b.WriteString(x)
			b.WriteByte(1)
		}
		sep()
	}
	for _, s := range []string{f.Agent, f.Kind, f.Text, f.PathPrefix, f.Source, f.After} {
		b.WriteString(s)
		sep()
	}
	for _, l := range [][]string{f.Verdicts, f.Kinds, f.Agents, f.Rules, f.Hosts, f.Words, f.Not.Kinds, f.Not.Verdicts,
		f.Not.Rules, f.Not.Hosts, f.Not.Agents, f.Not.Words, f.Programs, f.Not.Programs} {
		list(l)
	}
	b.WriteString(strconv.FormatBool(f.HideSys) + strconv.FormatBool(f.HideNoise) + strconv.FormatBool(f.OnlyRefus) + strconv.Itoa(f.PID))
	if !f.Since.IsZero() {
		b.WriteString("s" + strconv.FormatInt(f.Since.UnixNano(), 10))
	}
	if !f.Until.IsZero() {
		b.WriteString("u" + strconv.FormatInt(f.Until.UnixNano(), 10))
	}
	return b.String(), true
}

// facetCounter sums the runs' tallies into Facets for one Query. A nil counter (no facets asked) does nothing.
type facetCounter struct {
	key                         string
	keepable                    bool
	kinds, verdts, rules, hosts map[string]int
	progs                       map[string]int
	runs                        []FacetValue
	// ruleRuns is, per rule key, which runs its lines came from: ruleWatched, ruleEnforced or both.
	ruleRuns map[string]uint8
}

// The bits of facetCounter.ruleRuns.
const (
	ruleWatched uint8 = 1 << iota
	ruleEnforced
)

func newFacetCounter(f *Filter) *facetCounter {
	k, ok := facetKey(f)
	return &facetCounter{key: k, keepable: ok, kinds: map[string]int{}, verdts: map[string]int{}, rules: map[string]int{},
		hosts: map[string]int{}, progs: map[string]int{}, ruleRuns: map[string]uint8{}}
}

// cacheable reports whether r's tallies can be kept: a run the store published (a test's literal Run, or one rebuilt
// for the line bound, has no revision of its own).
func cacheable(r *Run) bool { return r.st != nil && r.memo != nil }

func tallyGet(k tallyKey) *runTally {
	tallies.Lock()
	defer tallies.Unlock()
	return tallies.m[k]
}

func tallyPut(k tallyKey, t *runTally) {
	tallies.Lock()
	defer tallies.Unlock()
	if len(tallies.m) >= maxTallies {
		tallies.m = map[tallyKey]*runTally{}
	}
	tallies.m[k] = t
}

func (fc *facetCounter) keyOf(r *Run, filter string) tallyKey {
	return tallyKey{store: r.st.store, run: r.ID, rev: r.Rev, filter: filter}
}

// cached is r's tally under this counter's filter: kept from an earlier Query (true), or a fresh one for the walk to
// fill (false). A nil counter answers nil.
func (fc *facetCounter) cached(r *Run) (*runTally, bool) {
	if fc == nil {
		return nil, false
	}
	if fc.keepable && cacheable(r) {
		if t := tallyGet(fc.keyOf(r, fc.key)); t != nil {
			return t, true
		}
	}
	return newRunTally(), false
}

// keep stores a tally the walk filled.
func (fc *facetCounter) keep(r *Run, t *runTally, cached bool) {
	if !cached && fc.keepable && cacheable(r) {
		tallyPut(fc.keyOf(r, fc.key), t)
	}
}

// plainTally is r's tally with no filter: every line but the mirrors, the lines Query's plain path counts.
func (fc *facetCounter) plainTally(r *Run) *runTally {
	var k tallyKey
	if cacheable(r) {
		k = fc.keyOf(r, "\x00plain")
		if t := tallyGet(k); t != nil {
			return t
		}
	}
	t := newRunTally()
	evs := r.AllEvents()
	names, of := r.progs()
	for i := range evs {
		if !evs[i].Mirror {
			t.count(&evs[i], programAt(names, of, int32(i))) //nolint:gosec // a run holds far fewer than 2^31 lines
		} else {
			t.kinds = bump(t.kinds, "refused") // a refusal note kind:refused lists (countMirror)
		}
	}
	if cacheable(r) {
		tallyPut(k, t)
	}
	return t
}

// add sums run r's tally in.
func (fc *facetCounter) add(r *Run, t *runTally) {
	if t == nil || t.n == 0 {
		return
	}
	fc.runs = append(fc.runs, FacetValue{r.ID, t.n})
	for _, v := range t.kinds {
		fc.kinds[v.Value] += v.Count
	}
	for _, v := range t.verdts {
		fc.verdts[v.Value] += v.Count
	}
	from := ruleEnforced
	if r.Tier == "observe" {
		from = ruleWatched
	}
	for k, n := range t.rules {
		fc.rules[k] += n
		fc.ruleRuns[k] |= from
	}
	for k, n := range t.hosts {
		fc.hosts[k] += n
	}
	for k, n := range t.progs {
		fc.progs[k] += n
	}
}

func top(vs []FacetValue) Facet {
	slices.SortFunc(vs, func(a, b FacetValue) int {
		if a.Count != b.Count {
			return b.Count - a.Count
		}
		return strings.Compare(a.Value, b.Value)
	})
	return Facet{Values: vs[:min(len(vs), FacetTop)], Distinct: len(vs)}
}

func topOf(m map[string]int) Facet {
	vs := make([]FacetValue, 0, len(m))
	for k, n := range m {
		vs = append(vs, FacetValue{k, n})
	}
	return top(vs)
}

func (fc *facetCounter) facets() *Facets {
	out := &Facets{Kind: topOf(fc.kinds), Verdict: topOf(fc.verdts), Rule: topOf(fc.rules), Host: topOf(fc.hosts),
		Run: top(fc.runs), Program: topOf(fc.progs)}
	for _, v := range out.Rule.Values {
		if fc.ruleRuns[v.Value] == ruleWatched {
			if out.WatchedRules == nil {
				out.WatchedRules = map[string]bool{}
			}
			out.WatchedRules[v.Value] = true
		}
	}
	return out
}
