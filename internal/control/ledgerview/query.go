// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bytes"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Filter selects log lines. Empty fields match everything; set fields all apply (AND), and a list field matches a
// line that matches any of its entries (OR). The fields after OnlyRefus are the query language's (querylang.go).
type Filter struct {
	Run   string
	Agent string
	// Kind is one kind as Logs groups them: "run" is run_start and run_end, "ask" is ask and answer. Kind "refused"
	// lists a refused action's mirror too (pair.go), and so does the query's kind:refused (Kinds), as the form's
	// Kind does: asking for refused lines by kind asks for the mirrors themselves.
	Kind      string
	Verdicts  []string // "refused" also matches refused lines; "allow", "ask", "observed", "none"
	Text      string   // a literal substring of the line's haystack, case-insensitive: never parsed
	HideSys   bool
	HideNoise bool   // leave out SystemNoise: allowed reads of /proc, /sys, /dev and system libraries
	Before    string // a Row cursor: rows strictly older than it
	PageSize  int
	OnlyRefus bool

	Kinds  []string // any of, grouped as Kind
	Runs   []string
	Agents []string
	PID    int      // the envelope's process; 0 is any
	Rules  []string // a rule key exactly, or the keys a prefix ending in * starts
	// PathPrefix is a prefix of a path the line names: an fs line's path or second path, a refused line's target, an
	// exec line's program path or argv, an ask's target. A leading ~ is each run's home (RunHome).
	PathPrefix string
	Hosts      []string // Event.Host, case-insensitive
	// Programs is the program the line's process was running (program.go), case-insensitive: curl, bash, codex.
	Programs []string
	Source   string // the envelope's source (supervisor, kernel, ...)
	Since    time.Time
	Until    time.Time // Since inclusive, Until exclusive
	// After is a Row cursor: lines strictly newer than it in the Logs order (time, then run, then seq), so lines at the
	// cursor's very time in other runs are neither lost nor listed twice.
	After string
	Words []string // each a literal substring of the haystack, like Text
	Not   Exclude
	// Facets asks Query for Page.Facets.
	Facets bool
	// Ledger asks Each for the ledger itself when f selects one whole run and nothing else (WholeRun): every line of
	// the run in file order, a refused action's mirror included, so the lines are byte for byte its events file.
	Ledger bool
	// none is set by And when the two filters cannot both match: nothing matches.
	none bool
}

// Exclude is what a Filter leaves out: lines that match any entry (the query's -key:value and -word).
type Exclude struct {
	Kinds, Verdicts, Rules, Hosts, Runs, Agents, Words, Programs []string
}

// Row is a log row: one line, or identical refusals (same run, kind, rule, reason and target) folded into one.
type Row struct {
	Event
	// Label is the rule in words, with the exact list a default decision fell outside of (set by the web layer).
	Label string
	// Program is the program the line's process was running (program.go), "" when the record does not say.
	Program string
	Count   int
	First   time.Time // the oldest folded line's time
	Seqs    []uint64
}

// Cursor is the row's position in the newest-first order.
func (r Row) Cursor() string {
	return strconv.FormatInt(r.TS.UnixNano(), 10) + "." + r.Run + "." + strconv.FormatUint(r.Seq, 10)
}

// Page is a page of rows and what the page counted.
type Page struct {
	Rows      []Row
	Next      string // the cursor of the next page, "" at the end
	Matched   int    // lines that matched, folded or not
	Groups    int    // rows after folding
	SysHidden int    // system lookup lines the filter hid
	// NoiseHidden is those of SysHidden only HideNoise hid: Logs' downloads, which carry no noise filter, hold them.
	NoiseHidden int
	Runs        int // distinct runs among the matched lines
	Counts      map[string]int
	// Facets counts the matched lines by kind, verdict, rule, host and run (facets.go), when Filter.Facets asked.
	Facets *Facets
}

func less(a, b *Event) bool { // newest first
	if !a.TS.Equal(b.TS) {
		return a.TS.After(b.TS)
	}
	if a.Run != b.Run {
		return a.Run > b.Run
	}
	return a.Seq > b.Seq
}

// NewerThan reports whether the row comes before cursor in the newest-first order (a live tail's new rows): a
// folded group comes when its newest line does. An unreadable cursor has nothing newer.
func (r Row) NewerThan(cursor string) bool {
	c, ok := parseCursor(cursor)
	return ok && less(&r.Event, &c)
}

func parseCursor(c string) (Event, bool) {
	parts := strings.SplitN(c, ".", 3)
	if len(parts) != 3 {
		return Event{}, false
	}
	ns, err1 := strconv.ParseInt(parts[0], 10, 64)
	seq, err2 := strconv.ParseUint(parts[2], 10, 64)
	if err1 != nil || err2 != nil {
		return Event{}, false
	}
	return Event{TS: time.Unix(0, ns).UTC(), Run: parts[1], Seq: seq}, true
}

// verdictOf is the verdict a line counts under in Logs. An ask line carries no verdict of its own (the supervisor
// writes the held action's outcome on the answer and the lines after it), but it is the line that says Tego asked a
// person, so it counts as asked: Logs and Approvals then agree on how many asks there were.
func verdictOf(e *Event) string {
	if e.Refused() {
		return "refused"
	}
	if e.Kind == "ask" && e.Verdict == "" {
		return "ask"
	}
	if e.Verdict == "" {
		return "none"
	}
	return e.Verdict
}

// procData reports whether p reads what a process holds rather than its status: /proc/<pid>/environ and its memory
// (a task's too), or a file through /proc/<pid>/root and cwd, where any path of the machine can be named.
func procData(p string) bool {
	rest, ok := strings.CutPrefix(p, "/proc/")
	if !ok {
		return false
	}
	if base := path.Base(rest); base == "environ" || base == "mem" {
		return true
	}
	return strings.Contains(rest+"/", "/root/") || strings.Contains(rest+"/", "/cwd/")
}

// LogsVerdict is the verdict a line counts under in Logs, its counts and its Verdict facet (verdictOf).
func LogsVerdict(e *Event) string { return verdictOf(e) }

// logsKind is a line's kind as Logs groups them (Filter.Kind): run_start and run_end are "run", ask and answer "ask".
func logsKind(k string) string {
	switch k {
	case "run_start", "run_end":
		return "run"
	case "answer":
		return "ask"
	}
	return k
}

// plain reports whether f selects nothing but runs: Query then takes each run's memoized fold (allFolded).
func (f *Filter) plain() bool {
	return f.Agent == "" && f.Kind == "" && len(f.Verdicts) == 0 && f.Text == "" && !f.HideSys && !f.HideNoise && !f.OnlyRefus &&
		!f.lineFilters()
}

// lineFilters reports whether f sets a query-language field that looks at each line (not Runs, Not.Runs, Facets).
func (f *Filter) lineFilters() bool {
	n := &f.Not
	return len(f.Kinds) > 0 || len(f.Agents) > 0 || f.PID != 0 || len(f.Rules) > 0 || f.PathPrefix != "" ||
		len(f.Hosts) > 0 || len(f.Programs) > 0 || len(n.Programs) > 0 || f.Source != "" || !f.Since.IsZero() || !f.Until.IsZero() || f.After != "" ||
		len(f.Words) > 0 || len(n.Kinds) > 0 || len(n.Verdicts) > 0 || len(n.Rules) > 0 || len(n.Hosts) > 0 ||
		len(n.Agents) > 0 || len(n.Words) > 0 || f.none
}

// wantsRun reports whether f can match a line of run r at all (the run fields, and the time range against the run's
// oldest and newest line).
func (f *Filter) wantsRun(r *Run) bool {
	if f.none || (f.Run != "" && r.ID != f.Run) || (len(f.Runs) > 0 && !slices.Contains(f.Runs, r.ID)) ||
		slices.Contains(f.Not.Runs, r.ID) {
		return false
	}
	if f.Since.IsZero() && f.Until.IsZero() {
		return true
	}
	evs := r.AllEvents()
	if len(evs) == 0 {
		return false
	}
	newest, oldest := &evs[len(evs)-1], &evs[0]
	if order := r.newestFirst(); order != nil {
		newest, oldest = &evs[order[0]], &evs[order[len(order)-1]]
	}
	if !f.Since.IsZero() && newest.TS.Before(f.Since) {
		return false
	}
	return f.Until.IsZero() || oldest.TS.Before(f.Until)
}

// ruleMatches reports whether rule is one of rules: exactly, or under an entry ending in * as a prefix.
func ruleMatches(rules []string, rule string) bool {
	for _, w := range rules {
		if p, ok := strings.CutSuffix(w, "*"); ok {
			if strings.HasPrefix(rule, p) {
				return true
			}
		} else if rule == w {
			return true
		}
	}
	return false
}

// pathHas reports whether a path line e names starts with prefix (Filter.PathPrefix, ~ already expanded).
func pathHas(e *Event, prefix string) bool {
	switch e.Kind {
	case "fs":
		p, p2, two := strings.Cut(e.Target, " → ")
		return strings.HasPrefix(p, prefix) || (two && strings.HasPrefix(p2, prefix))
	case "refused", "run_start":
		return strings.HasPrefix(e.Target, prefix)
	case "exec":
		return strings.HasPrefix(e.path, prefix) || strings.HasPrefix(e.Target, prefix)
	case "ask", "answer":
		return strings.HasPrefix(e.askTarget, prefix)
	}
	return false
}

// matcher is a Filter made ready for one Query or Each: its cursor read, its words lower-cased.
type matcher struct {
	f               *Filter
	after           Event
	hasAfter        bool
	text            []byte
	perLine         bool // text holds a newline, which no haystack buffer line can: search line by line
	words, notWords [][]byte
	hosts, notHosts []string
	hay             []byte
}

func newMatcher(f *Filter) *matcher {
	m := &matcher{f: f, text: []byte(strings.ToLower(f.Text))}
	m.perLine = bytes.IndexByte(m.text, '\n') >= 0
	if f.After != "" {
		m.after, m.hasAfter = parseCursor(f.After)
		if !m.hasAfter {
			f.none = true // an unreadable cursor matches nothing rather than everything
		}
	}
	low := func(ws []string) [][]byte {
		var out [][]byte
		for _, w := range ws {
			if w = strings.ToLower(w); w != "" {
				out = append(out, []byte(w))
			}
		}
		return out
	}
	m.words, m.notWords = low(f.Words), low(f.Not.Words)
	for _, h := range f.Hosts {
		m.hosts = append(m.hosts, strings.ToLower(h))
	}
	for _, h := range f.Not.Hosts {
		m.notHosts = append(m.notHosts, strings.ToLower(h))
	}
	return m
}

// runMatch is a matcher made ready for one run: the text searches' hits and the path prefix with ~ expanded.
type runMatch struct {
	*matcher
	hits            []bool
	wordHits        [][]bool
	notHits         [][]bool
	path            string
	mirrors         bool
	progOf          []int32 // the run's program per line, when the filter names programs
	progWant        []int8  // per program name: 1 wanted, -1 left out, 0 neither
	needWordsInLine bool    // a word holds a newline: searched line by line
}

// forRun readies m for run r; false when no line of r can match.
func (m *matcher) forRun(r *Run) (*runMatch, bool) {
	f := m.f
	if !f.wantsRun(r) {
		return nil, false
	}
	rm := &runMatch{matcher: m, path: f.PathPrefix, mirrors: f.Kind == "refused" || f.OnlyRefus ||
		slices.Contains(f.Kinds, "refused")}
	if rest, ok := strings.CutPrefix(rm.path, "~"); ok {
		home := RunHome(r)
		if home == "" {
			return nil, false // a run with no home known has no path under ~
		}
		rm.path = home + rest
	}
	if len(m.text) > 0 && !m.perLine {
		rm.hits = r.textMatches(m.text)
	}
	if len(f.Programs) > 0 || len(f.Not.Programs) > 0 {
		names, of := r.progs()
		rm.progOf, rm.progWant = of, make([]int8, len(names))
		for k, n := range names {
			n = strings.ToLower(n)
			switch {
			case slices.Contains(f.Not.Programs, n):
				rm.progWant[k] = -1
			case slices.Contains(f.Programs, n):
				rm.progWant[k] = 1
			}
		}
	}
	for _, w := range m.words {
		if bytes.IndexByte(w, '\n') >= 0 {
			rm.needWordsInLine = true
			continue
		}
		rm.wordHits = append(rm.wordHits, r.textMatches(w))
	}
	for _, w := range m.notWords {
		if bytes.IndexByte(w, '\n') >= 0 {
			rm.needWordsInLine = true
			continue
		}
		rm.notHits = append(rm.notHits, r.textMatches(w))
	}
	return rm, true
}

// match reports whether line i (e) of the run matches every field and search of the filter, leaving out a mirror
// unless the filter lists them; sys reports a line that matched but is a system lookup the filter hides.
func (rm *runMatch) match(i int32, e *Event) (ok, sys bool) {
	f := rm.f
	if e.Mirror && !rm.mirrors {
		return false, false
	}
	if !f.matchFields(e) || !rm.matchQuery(e) || !rm.matchProgram(i) {
		return false, false
	}
	if len(rm.text) > 0 {
		if rm.hits != nil {
			if !rm.hits[i] {
				return false, false
			}
		} else if !bytes.Contains(rm.haystackOf(e), rm.text) {
			return false, false
		}
	}
	for _, h := range rm.wordHits {
		if !h[i] {
			return false, false
		}
	}
	for _, h := range rm.notHits {
		if h[i] {
			return false, false
		}
	}
	if rm.needWordsInLine {
		hay := rm.haystackOf(e)
		for _, w := range rm.words {
			if bytes.IndexByte(w, '\n') >= 0 && !bytes.Contains(hay, w) {
				return false, false
			}
		}
		for _, w := range rm.notWords {
			if bytes.IndexByte(w, '\n') >= 0 && bytes.Contains(hay, w) {
				return false, false
			}
		}
	}
	if f.HideSys && e.SystemLookup || f.HideNoise && SystemNoise(e) {
		return false, true
	}
	return true, false
}

// matchProgram is the prog: key on line i: a line whose program is not known matches no prog: and is never left out.
func (rm *runMatch) matchProgram(i int32) bool {
	if rm.progOf == nil {
		return true
	}
	want := int8(0)
	if p := rm.progOf[i]; p >= 0 {
		want = rm.progWant[p]
	}
	return want == 1 || (want == 0 && len(rm.f.Programs) == 0)
}

func (rm *runMatch) haystackOf(e *Event) []byte {
	rm.hay = haystack(rm.hay[:0], e)
	return rm.hay
}

// matchQuery is the query language's fields on one line.
func (rm *runMatch) matchQuery(e *Event) bool {
	f := rm.f
	if rm.hasAfter && !less(e, &rm.after) {
		return false
	}
	if !f.Since.IsZero() && e.TS.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && !e.TS.Before(f.Until) {
		return false
	}
	if f.PID != 0 && e.pid != f.PID {
		return false
	}
	if f.Source != "" && e.Source != f.Source {
		return false
	}
	if len(f.Kinds) > 0 || len(f.Not.Kinds) > 0 {
		k := logsKind(e.Kind)
		if (len(f.Kinds) > 0 && !slices.Contains(f.Kinds, k)) || slices.Contains(f.Not.Kinds, k) {
			return false
		}
	}
	if (len(f.Agents) > 0 && !slices.Contains(f.Agents, e.Agent)) || slices.Contains(f.Not.Agents, e.Agent) {
		return false
	}
	if (len(f.Rules) > 0 && !ruleMatches(f.Rules, e.Rule)) || (len(f.Not.Rules) > 0 && ruleMatches(f.Not.Rules, e.Rule)) {
		return false
	}
	if (len(rm.hosts) > 0 && !slices.Contains(rm.hosts, e.Host)) || (e.Host != "" && slices.Contains(rm.notHosts, e.Host)) {
		return false
	}
	if len(f.Not.Verdicts) > 0 && slices.Contains(f.Not.Verdicts, verdictOf(e)) {
		return false
	}
	if rm.path != "" && !pathHas(e, rm.path) {
		return false
	}
	return true
}

// matchFields is the filter's original fields (run, agent, kind, verdict, refused lines only) on one line.
func (f *Filter) matchFields(e *Event) bool {
	if f.Run != "" && e.Run != f.Run {
		return false
	}
	if f.Agent != "" && e.Agent != f.Agent {
		return false
	}
	if f.Kind != "" && logsKind(e.Kind) != f.Kind {
		return false
	}
	if f.OnlyRefus && e.Kind != "refused" {
		return false
	}
	if len(f.Verdicts) > 0 && !slices.Contains(f.Verdicts, verdictOf(e)) {
		return false
	}
	return true
}

// Query filters, folds and pages the snapshot's lines, newest first. Each run's lines are walked once, newest first,
// and folded where they are (a fold never spans runs: its key holds the run), keeping only where each row is; the
// page is then merged across runs from the cursor, so only its own rows are ever built. A refused action's mirror is
// the same refusal as the action (pair.go): Logs shows and counts the action line, except when the person asked for
// refused lines by kind, which are the mirrors themselves. With f.Facets, the matched lines are also counted by kind,
// verdict, rule, host and run in the same walk (facets.go).
func (s *Snapshot) Query(f Filter) Page {
	if f.PageSize <= 0 {
		f.PageSize = 100
	}
	pg := Page{Counts: map[string]int{}}
	m := newMatcher(&f)
	// No filter but the run: each run's lines folded once per version (allFolded).
	plain := f.plain()
	var fc *facetCounter
	if f.Facets {
		fc = newFacetCounter(&f)
	}
	type part struct {
		folded
		pos   int
		run   *Run
		names []string
		of    []int32
	}
	var parts []*part
	for _, r := range s.Runs {
		evs := r.AllEvents()
		if len(evs) == 0 {
			continue
		}
		var fr folded
		if plain {
			if !f.wantsRun(r) {
				continue
			}
			var counts map[string]int
			fr, counts = r.allFolded()
			for k, v := range counts {
				pg.Counts[k] += v
				pg.Matched += v
			}
			if fc != nil {
				fc.add(r, fc.plainTally(r))
			}
		} else {
			rm, ok := m.forRun(r)
			if !ok {
				continue
			}
			t, cached := fc.cached(r)
			var progOf []int32
			var progNames []string
			if t != nil && !cached {
				progNames, progOf = r.progs()
			}
			fr = foldRun(evs, r.newestFirst(), func(i int32, e *Event) bool {
				ok, sys := rm.match(i, e)
				if sys {
					pg.SysHidden++
					if !(f.HideSys && e.SystemLookup) {
						pg.NoiseHidden++
					}
				}
				if !ok {
					if e.Mirror && t != nil && !cached {
						t.countMirror(rm, i, e)
					}
					return false
				}
				pg.Counts[verdictOf(e)]++
				pg.Matched++
				if t != nil && !cached {
					t.count(e, programAt(progNames, progOf, i))
				}
				return true
			})
			if fc != nil {
				fc.keep(r, t, cached)
				fc.add(r, t)
			}
		}
		if len(fr.reps) == 0 {
			continue
		}
		pg.Runs++ // a fold never spans runs, so a run with a row is a run with a matched line
		pg.Groups += len(fr.reps)
		p := &part{folded: fr, run: r}
		if c, ok := parseCursor(f.Before); ok {
			p.pos = sort.Search(len(fr.reps), func(k int) bool {
				e := &fr.evs[fr.reps[k]]
				return !less(e, &c) && !sameKey(e, &c)
			})
		}
		parts = append(parts, p)
	}
	if fc != nil {
		pg.Facets = fc.facets()
	}
	next := func() *part {
		var best *part
		for _, p := range parts {
			if p.pos < len(p.reps) && (best == nil || less(&p.evs[p.reps[p.pos]], &best.evs[best.reps[best.pos]])) {
				best = p
			}
		}
		return best
	}
	for len(pg.Rows) < f.PageSize {
		p := next()
		if p == nil {
			break
		}
		row := p.row(p.pos)
		if p.of == nil {
			p.names, p.of = p.run.progs()
		}
		row.Program = programAt(p.names, p.of, p.reps[p.pos])
		pg.Rows = append(pg.Rows, row)
		p.pos++
	}
	if len(pg.Rows) == f.PageSize && next() != nil {
		pg.Next = pg.Rows[len(pg.Rows)-1].Cursor()
	}
	return pg
}

// haystack appends what the text search looks in (op, target, rule, reason, agent, run, kind, ask id and what an ask
// or answer is about, joined by spaces; an exec line's target is its argv, read from its blob when the writer moved it
// to one) to buf, lower-cased: in place when it is ASCII, through strings.ToLower when it is not, so it matches what
// strings.ToLower of the joined fields would.
func haystack(buf []byte, e *Event) []byte {
	start := len(buf)
	ascii := true
	for i, s := range [...]string{e.Op, e.Target, e.Rule, e.Reason, e.Agent, e.Run, e.Kind, e.AskID, e.askTarget} {
		if i > 0 {
			buf = append(buf, ' ')
		}
		for j := 0; j < len(s); j++ {
			c := s[j]
			if c >= utf8.RuneSelf {
				ascii = false
			} else if 'A' <= c && c <= 'Z' {
				c += 'a' - 'A'
			}
			buf = append(buf, c)
		}
	}
	if ascii {
		return buf
	}
	low := strings.ToLower(strings.Join([]string{e.Op, e.Target, e.Rule, e.Reason, e.Agent, e.Run, e.Kind, e.AskID, e.askTarget}, " "))
	return append(buf[:start], low...)
}

func sameKey(a, b *Event) bool { return a.TS.Equal(b.TS) && a.Run == b.Run && a.Seq == b.Seq }

// Refusals is the snapshot's refused lines (kind refused), newest first, folded, without route probes (RouteProbe):
// the Overview's recent list. Run.Refusals counts each once (a mirror with its action, pair.go), and Logs and the
// run's Refusals tab list a mirrored one by its action line. Each run's part is folded once per version of the run;
// this merges them.
func (s *Snapshot) Refusals(limit int) []Row {
	var rows []Row
	for _, r := range s.Runs {
		rows = append(rows, r.frontRefusals()...)
	}
	sort.Slice(rows, func(i, j int) bool { return less(&rows[i].Event, &rows[j].Event) })
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows
}

// RunRefusals is one run's refusals as Run.Refusals counts them (Event.Refusal: a refused action, or a refused line
// that mirrors no action), newest first, folded. The rows are the caller's to label.
func RunRefusals(r *Run) []Row {
	return slices.Clone(r.runRefusals())
}

// Pending is every ask waiting on a person, oldest first: the open asks of live runs. A lost run (no run_end, not
// live) keeps its open asks in Run.Pending, but nothing holds them, so they are not waiting (Lost lists them).
func (s *Snapshot) Pending() []Ask {
	var out []Ask
	for _, r := range s.Runs {
		if r.Live {
			out = append(out, r.Pending...)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TS.Before(out[j].TS) })
	return out
}

// Lost is the open asks of runs that were lost (no run_end and not live), newest first: asks nobody answered and
// nothing holds any more.
func (s *Snapshot) Lost() []Ask {
	var out []Ask
	for _, r := range s.Runs {
		if r.State() == "lost" {
			out = append(out, r.Pending...)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TS.After(out[j].TS) })
	return out
}

// Agents is the agent names in the snapshot, sorted.
func (s *Snapshot) Agents() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range s.Runs {
		if r.Agent != "" && !seen[r.Agent] {
			seen[r.Agent] = true
			out = append(out, r.Agent)
		}
	}
	sort.Strings(out)
	return out
}

// noisePrefixes are the system folders a program reads on its own all the time: its process status, devices,
// libraries and locale files.
var noisePrefixes = []string{"/proc/", "/sys/", "/dev/", "/usr/lib/", "/usr/lib64/", "/lib/", "/lib64/",
	"/usr/share/locale/", "/usr/share/zoneinfo/", "/etc/ld.so."}

// SystemNoise reports whether e is an allowed plain read under one of noisePrefixes: the Logs page hides these unless
// asked to show them (Filter.HideNoise). A refused line is never noise (a refused action is kind fs too, with its
// verdict), nor a write, nor a secret by its path, nor what another process holds (procData).
func SystemNoise(e *Event) bool {
	if e.Kind != "fs" || e.Op != "read" || (e.Verdict != "allow" && e.Verdict != "observed") {
		return false
	}
	if e.secretPart(0, e.Target) || procData(e.Target) {
		return false
	}
	for _, p := range noisePrefixes {
		if strings.HasPrefix(e.Target, p) {
			return true
		}
	}
	return false
}
