// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bytes"
	"sort"
	"strings"
	"sync"
	"time"
)

// runMemo holds the views derived from one published version of a run: computed on first use, shared by every
// request that holds that version, and dropped with it when the run gains a line. Each view is built from the run's
// lines alone, so a view of a version is the same whenever it is built.
type runMemo struct {
	orderOnce sync.Once
	order     []int32 // the lines newest first by (ts, seq), when that is not simply the reverse of file order

	tlOnce [2]sync.Once
	tl     [2]*Timeline // TimelineOf: every action line, refusals only

	refOnce sync.Once
	refused []Row // RunRefusals: the refusals Run.Refusals counts (Event.Refusal), folded, newest first

	frontOnce sync.Once
	front     []Row // Refusals: refused lines without route probes, folded, newest first

	homeOnce sync.Once
	home     string // RunHome

	subjOnce sync.Once
	subjects map[Subject]*[2]int // FindSimilar: lines and refusals per subject, mirrors left out

	ruleOnce sync.Once
	rules    map[string]int // RuleHits: lines per rule key, mirrors left out

	allOnce   sync.Once
	all       folded         // Query with no filter: every line but the mirrors (pair.go) folded, newest first
	allCounts map[string]int // and those lines per verdictOf

	hayOnce sync.Once
	hay     []byte // Query's text search: each line's haystack, lower-cased, each ending in a newline
	hayOff  []int  // where line i's haystack starts in hay; hayOff[n] is len(hay)
	// hitsMu guards hits, the last few searches' results: a page refresh, the next page and a live update repeat
	// the same search.
	hitsMu sync.Mutex
	hits   map[string][]bool

	live liveMemo // LiveFactsOf and the live-block views built on it (live.go)

	// factsOnce builds facts, what Explain reads besides the line itself (proc.go): the processes by exec_id and
	// by pid (the program a pid ran at a line, and its parents), the asks by ask_id with the lines that belong to
	// each, and which action each mirror mirrors.
	factsOnce sync.Once
	facts     *lineIndex
}

// maxHits bounds runMemo.hits per run, dropped wholesale past it.
const maxHits = 8

func (r *Run) memoOf() *runMemo {
	if r.memo == nil {
		// A Run not made by the store (a test's literal): its views are built every time.
		return &runMemo{}
	}
	return r.memo
}

// newestFirst is the run's line indices newest first in the Logs order (less): the reverse of file order unless a
// line's time steps back, then sorted.
func (r *Run) newestFirst() []int32 {
	m := r.memoOf()
	m.orderOnce.Do(func() {
		evs := r.AllEvents()
		for i := 1; i < len(evs); i++ {
			if evs[i].TS.Before(evs[i-1].TS) || (evs[i].TS.Equal(evs[i-1].TS) && evs[i].Seq < evs[i-1].Seq) {
				order := make([]int32, len(evs))
				for k := range order {
					order[k] = int32(len(evs) - 1 - k) //nolint:gosec // a run holds far fewer than 2^31 lines (MaxLines)
				}
				sort.SliceStable(order, func(a, b int) bool { return less(&evs[order[a]], &evs[order[b]]) })
				m.order = order
				return
			}
		}
	})
	return m.order
}

// foldGroup is a folded refusal group's lines after its newest: how many in all, the oldest one's time, every seq.
type foldGroup struct {
	count int
	first time.Time
	seqs  []uint64
}

type foldKey struct{ kind, rule, reason, op, target string }

// folded is one run's lines folded into rows without building them: reps is the index of each row's newest line,
// in row order, and groups the refusal groups by that index.
type folded struct {
	evs    []Event
	reps   []int32
	groups map[int32]*foldGroup
}

// foldRun folds the lines of evs that keep accepts, walking them in the order order gives (nil: the reverse of file
// order): identical refusals (same kind, rule, reason, op and target; a fold never spans runs) go into the row of
// their newest line, whose Count holds them all, First the oldest one's time and Seqs every seq, newest first.
// Nothing is dropped.
func foldRun(evs []Event, order []int32, keep func(int32, *Event) bool) folded {
	f := folded{evs: evs, groups: map[int32]*foldGroup{}}
	idx := map[foldKey]int32{}
	n := len(evs)
	for k := 0; k < n; k++ {
		i := int32(n - 1 - k) //nolint:gosec // a run holds far fewer than 2^31 lines (MaxLines)
		if order != nil {
			i = order[k]
		}
		e := &evs[i]
		if keep != nil && !keep(i, e) {
			continue
		}
		if e.Refused() {
			key := foldKey{e.Kind, e.Rule, e.Reason, e.Op, e.Target}
			if rep, ok := idx[key]; ok {
				g := f.groups[rep]
				g.count++
				g.first = e.TS
				g.seqs = append(g.seqs, e.Seq)
				continue
			}
			idx[key] = i
			f.groups[i] = &foldGroup{count: 1, first: e.TS, seqs: []uint64{e.Seq}}
		}
		f.reps = append(f.reps, i)
	}
	return f
}

// row builds row k.
func (f *folded) row(k int) Row {
	i := f.reps[k]
	e := f.evs[i]
	if g := f.groups[i]; g != nil {
		return Row{Event: e, Count: g.count, First: g.first, Seqs: g.seqs}
	}
	return Row{Event: e, Count: 1, First: e.TS, Seqs: []uint64{e.Seq}}
}

func (f *folded) rows() []Row {
	out := make([]Row, len(f.reps))
	for k := range f.reps {
		out[k] = f.row(k)
	}
	return out
}

// Timeline is a run's timeline: its lines newest first (strictly falling seq), identical refusals folded into the
// place of their newest line. It holds no rows, only where they are, so a run of 200,000 lines pages cheaply; Rows
// builds the rows asked for, fresh, for the caller to label.
type Timeline struct{ f folded }

// TimelineOf is the run's timeline: one row per thing the agent did, so every line but a refused action's mirror
// (pair.go) and a quiet gap (QuietGap), or, with refusedOnly, the refusals (Event.Refusal). It is built once per
// version of the run and shared.
func TimelineOf(r *Run, refusedOnly bool) *Timeline {
	m := r.memoOf()
	k := 0
	if refusedOnly {
		k = 1
	}
	m.tlOnce[k].Do(func() {
		keep := func(_ int32, e *Event) bool { return !e.Mirror && !QuietGap(e) }
		if refusedOnly {
			keep = func(_ int32, e *Event) bool { return e.Refusal() }
		}
		m.tl[k] = &Timeline{foldRun(r.AllEvents(), nil, keep)}
	})
	return m.tl[k]
}

// QuietGap is a gap line the timeline leaves out: "record no-price-table", which only says a cost budget cannot be
// priced on this machine. It is in every run and says nothing about what the agent did; Logs keeps it.
func QuietGap(e *Event) bool {
	return e.Kind == "gap" && strings.HasSuffix(e.Target, " no-price-table")
}

// Len is the number of rows.
func (t *Timeline) Len() int { return len(t.f.reps) }

// Rows is rows i to j (j excluded), built fresh.
func (t *Timeline) Rows(i, j int) []Row {
	i, j = max(i, 0), min(j, len(t.f.reps))
	if i >= j {
		return nil
	}
	out := make([]Row, 0, j-i)
	for k := i; k < j; k++ {
		out = append(out, t.f.row(k))
	}
	return out
}

// Below is the index of the first row whose (newest) line's seq is below seq: the rows before it are those at or
// above seq.
func (t *Timeline) Below(seq uint64) int {
	return sort.Search(len(t.f.reps), func(k int) bool { return t.f.evs[t.f.reps[k]].Seq < seq })
}

// runRefusals is the memoized RunRefusals.
func (r *Run) runRefusals() []Row {
	m := r.memoOf()
	m.refOnce.Do(func() {
		// The same rule as Run.Refusals (Event.Refusal), so the Refusals tab holds as many refusals as the count
		// beside it.
		f := foldRun(r.AllEvents(), r.newestFirst(), func(_ int32, e *Event) bool { return e.Refusal() })
		m.refused = f.rows()
	})
	return m.refused
}

// frontRefusals is the run's part of Snapshot.Refusals: refused lines without route probes, folded, newest first.
func (r *Run) frontRefusals() []Row {
	m := r.memoOf()
	m.frontOnce.Do(func() {
		probes := probeTargets(r)
		f := foldRun(r.AllEvents(), r.newestFirst(), func(_ int32, e *Event) bool { return e.Kind == "refused" && !probes[e.Target] })
		m.front = f.rows()
	})
	return m.front
}

// subjectCounts is the run's lines and refusals per subject (SubjectOf), for FindSimilar; a refused action's mirror
// is left out, as its action counts it.
func (r *Run) subjectCounts() map[Subject]*[2]int {
	m := r.memoOf()
	m.subjOnce.Do(func() {
		m.subjects = map[Subject]*[2]int{}
		evs := r.AllEvents()
		for i := range evs {
			if evs[i].Mirror { // its action's line counts the refusal (pair.go)
				continue
			}
			s := SubjectOf(&evs[i])
			if s.Class == "" {
				continue
			}
			c := m.subjects[s]
			if c == nil {
				c = &[2]int{}
				m.subjects[s] = c
			}
			c[0]++
			if evs[i].Refusal() {
				c[1]++
			}
		}
	})
	return m.subjects
}

// allFolded is every line of the run folded, newest first, and the lines per verdict: what Query with no filter
// takes from each run.
func (r *Run) allFolded() (folded, map[string]int) {
	m := r.memoOf()
	m.allOnce.Do(func() {
		evs := r.AllEvents()
		m.allCounts = map[string]int{}
		for i := range evs {
			if !evs[i].Mirror {
				m.allCounts[verdictOf(&evs[i])]++
			}
		}
		m.all = foldRun(evs, r.newestFirst(), func(_ int32, e *Event) bool { return !e.Mirror })
	})
	return m.all, m.allCounts
}

// textMatches marks the lines (by file index) whose haystack (see haystack) holds needle, which is lower-cased and
// holds no newline. The haystacks are built once per version of the run and searched as one buffer; the result is
// shared and must not be modified.
func (r *Run) textMatches(needle []byte) []bool {
	m := r.memoOf()
	evs := r.AllEvents()
	m.hayOnce.Do(func() {
		m.hayOff = make([]int, len(evs)+1)
		for i := range evs {
			m.hayOff[i] = len(m.hay)
			m.hay = append(haystack(m.hay, &evs[i]), '\n')
		}
		m.hayOff[len(evs)] = len(m.hay)
	})
	m.hitsMu.Lock()
	out, ok := m.hits[string(needle)]
	m.hitsMu.Unlock()
	if ok {
		return out
	}
	out = make([]bool, len(evs))
	defer func() {
		m.hitsMu.Lock()
		if m.hits == nil || len(m.hits) >= maxHits {
			m.hits = map[string][]bool{}
		}
		m.hits[string(needle)] = out
		m.hitsMu.Unlock()
	}()
	for pos := 0; pos < len(m.hay); {
		k := bytes.Index(m.hay[pos:], needle)
		if k < 0 {
			break
		}
		p := pos + k
		i := sort.Search(len(evs), func(i int) bool { return m.hayOff[i+1] > p })
		if i >= len(evs) {
			break
		}
		out[i] = true
		pos = m.hayOff[i+1]
	}
	return out
}

// RuleHits is how many lines of r name each rule key (Event.Rule), a refused action's mirror (pair.go) left out, so a
// refusal counts once, as Logs and Run.Refusals count it: the Rules page's hits per rule. It is built once per
// published version; the map is shared and must not be modified.
func RuleHits(r *Run) map[string]int {
	m := r.memoOf()
	m.ruleOnce.Do(func() {
		m.rules = map[string]int{}
		evs := r.AllEvents()
		for i := range evs {
			if e := &evs[i]; e.Rule != "" && !e.Mirror {
				m.rules[e.Rule]++
			}
		}
	})
	return m.rules
}
