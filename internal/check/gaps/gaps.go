// SPDX-License-Identifier: Apache-2.0

// Package gaps summarises a run's gap events into the one line `tego status` and `tego drift`
// print beside their verdicts (docs/FEATURES.md C8; docs/p0/limits-check-doctor-cli.md
// R34). A view that reports "running" or "no drift" over a run whose producers dropped events, or
// never saw a binary's model traffic, is stating less than it appears to, and the gap line is where
// it says so. A person's live changes to a run (a block, a lift, a pause) are recorded on gap lines too; Split sets
// them apart, so the views print them as "live changes:", not as gaps. Classify says what any gap means for the record
// (the receipt uses it too), and Words says that in a person's words, for tego status.
//
// Imports: pkg/spec/record only. Must not import internal/runtime (docs/REPO-LAYOUT.md: the read
// side never imports the engine).
package gaps

import (
	"cmp"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Unknown is the what and why a gap line carries when its payload does not decode: the event is
// still a gap, and dropping it from the summary would hide exactly the run it was written about.
const Unknown = "unknown"

// SharedTracingSkip and SharedTracingUnavailable carry uncertainty about this run, not known lost events.
const (
	SharedTracingSkip        = "bpf-trampoline-miss/shared-build"
	SharedTracingUnavailable = "bpf-trampoline-counter-unavailable"
)

// maxBinaries bounds how many binaries one entry of the rendered line names; --json carries them
// all. A run with a gap per binary (no-openssl on every helper a build spawns) would otherwise
// print a line as long as its process list.
const maxBinaries = 3

// Count is every gap event of one (what, why): how many were written, how many events their
// producers said they dropped, and which binaries they named.
type Count struct {
	// What and Why are the gap's own fields (spec/record/v1: what capture|record|enforce).
	What, Why string
	// Events is the number of gap events with this what and why.
	Events int
	// Lost is the sum of their count fields: events a producer dropped rather than recorded.
	// Zero when no event of this kind carried a count. A gap that names a binary counts that binary's
	// processes the source could not cover, not dropped events, and adds to Processes instead.
	// Shared tracing skips add to SharedSkipped; unavailable-counter occurrences add to neither.
	Lost int
	// SharedSkipped is the reported sum of skipped executions of shared programs: the recorder's tracing programs
	// (Uncertain) or the programs the run's rules rely on (RulesUncertain). Overlapping runs may report the same
	// execution; these are neither unique skips nor this run's lost events.
	SharedSkipped int
	// Processes is the sum of the count fields of gaps that name a binary.
	Processes int
	// Binaries are the distinct binary fields, sorted; empty when none named one.
	Binaries []string
}

// Tally accumulates gap events in one pass over a ledger. Its memory is one entry per distinct
// (what, why, binary), never one per event, so a view that streams stays O(1) per event
// (limits-check-doctor-cli.md §6 case 10).
type Tally struct {
	counts map[[2]string]*Count
	seen   map[[3]string]bool
}

// Add counts e when it is a gap event and ignores every other kind, so a caller can hand it each
// event of its own pass.
func (t *Tally) Add(e *record.Event) {
	if e == nil || e.Kind != record.KindGap {
		return
	}
	var p record.GapPayload
	if err := e.DecodePayload(&p); err != nil {
		p = record.GapPayload{}
	}
	if p.What == "" {
		p.What = Unknown
	}
	if p.Why == "" {
		p.Why = Unknown
	}
	lost, procs, skipped := 0, 0, 0
	var bins []string
	switch {
	case p.What == record.GapRecord && p.Why == SharedTracingSkip,
		p.What == record.GapEnforce && (p.Why == record.GapDecidingSkip || p.Why == record.GapTrackingSkip):
		skipped = max(p.Count, 0)
	case p.What == record.GapRecord && p.Why == SharedTracingUnavailable,
		p.What == record.GapEnforce && (p.Why == record.GapSkipCounterUnavailable || p.Why == record.GapSkipCounterRestored):
		// Count names counter failures, not lost events.
	case p.Count > 0 && p.Binary != "":
		procs = p.Count
	case p.Count > 0:
		lost = p.Count
	}
	if p.Binary != "" {
		bins = []string{p.Binary}
	}
	t.add(p.What, p.Why, 1, lost, procs, skipped, bins)
}

// add folds events gap events of one (what, why) into the tally.
func (t *Tally) add(what, why string, events, lost, procs, skipped int, binaries []string) {
	if t.counts == nil {
		t.counts, t.seen = map[[2]string]*Count{}, map[[3]string]bool{}
	}
	c := t.counts[[2]string{what, why}]
	if c == nil {
		c = &Count{What: what, Why: why}
		t.counts[[2]string{what, why}] = c
	}
	c.Events = addCount(c.Events, events)
	c.Lost = addCount(c.Lost, lost)
	c.SharedSkipped = addCount(c.SharedSkipped, skipped)
	c.Processes = addCount(c.Processes, procs)
	for _, b := range binaries {
		if !t.seen[[3]string{what, why, b}] {
			t.seen[[3]string{what, why, b}] = true
			c.Binaries = append(c.Binaries, b)
		}
	}
}

// addCount saturates a nonnegative diagnostic counter instead of wrapping and hiding recorded gaps.
func addCount(total, count int) int {
	if count <= 0 {
		return total
	}
	const maximum = int(^uint(0) >> 1)
	if total > maximum-count {
		return maximum
	}
	return total + count
}

// Counts returns the tally sorted by what, then why, with each entry's binaries sorted; nil when
// the run recorded no gap.
func (t *Tally) Counts() []Count {
	if len(t.counts) == 0 {
		return nil
	}
	out := make([]Count, 0, len(t.counts))
	for _, c := range t.counts {
		cc := *c
		cc.Binaries = slices.Clone(c.Binaries)
		slices.Sort(cc.Binaries)
		out = append(out, cc)
	}
	sortCounts(out)
	return out
}

// Merge sums the tallies of several runs by (what, why), for drift's aggregate report: events and
// lost add up and the binaries are the union. SharedSkipped sums reported counts; overlapping runs may
// report the same skipped execution, so this is not a count of unique skips.
func Merge(runs ...[]Count) []Count {
	var t Tally
	for _, cs := range runs {
		for _, c := range cs {
			t.add(c.What, c.Why, c.Events, c.Lost, c.Processes, c.SharedSkipped, c.Binaries)
		}
	}
	return t.Counts()
}

// Line renders the tally as the gap line, without its "gaps: " label: "none" when the run recorded
// no gap — said out loud, so a reader can tell a run with no gaps from a view that does not show
// them — else one "what/why xN" entry per kind, joined by "; ", each followed by the dropped-event
// total and up to three of the binaries it named, e.g.
// "capture/no-openssl x2 (in /usr/bin/curl, /usr/bin/gh); record/channel-full x1 (12 events lost)".
func Line(cs []Count) string {
	if len(cs) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		var b strings.Builder
		fmt.Fprintf(&b, "%s/%s x%d", record.Printable(c.What), record.Printable(c.Why), c.Events)
		var detail []string
		switch Classify(c.What, c.Why) {
		case Uncertain:
			detail = append(detail, SharedTracingWords(c.SharedSkipped, c.Why == SharedTracingUnavailable))
		case RulesUncertain:
			detail = append(detail, skipWordsOf([]Count{c}))
		case Missed, Live, Capture, Price, Restored:
			// no words beyond the counts below
		}
		if c.Lost > 0 {
			detail = append(detail, strconv.Itoa(c.Lost)+" events lost")
		}
		if c.Processes > 0 {
			detail = append(detail, strconv.Itoa(c.Processes)+" processes")
		}
		if n := len(c.Binaries); n > 0 {
			shown := make([]string, 0, min(n, maxBinaries))
			for _, bin := range c.Binaries[:min(n, maxBinaries)] {
				shown = append(shown, record.Printable(bin)) // a binary's path is the agent's to choose
			}
			s := "in " + strings.Join(shown, ", ")
			if n > maxBinaries {
				s += fmt.Sprintf(", +%d more", n-maxBinaries)
			}
			detail = append(detail, s)
		}
		if len(detail) > 0 {
			b.WriteString(" (" + strings.Join(detail, ", ") + ")")
		}
		parts = append(parts, b.String())
	}
	return strings.Join(parts, "; ")
}

// liveChanges are the whys of a gap what=enforce that record a person's live change to a running run, or what became
// of one: a live block added, removed or ended, an Adjustable run's fence entry lifted, restored, ended or refused, a
// pause or a resume (one the launcher could not put in force included), a live MCP tool switch and a model route
// change. The record keeps them on gap lines (spec/record/v1), but they are operator actions, not coverage the run
// lacked, so the views print them on their own "live changes:" line. live-block-unreadable (an overlay the launcher
// could not read) and live-block-lost (changes whose lines are missing) are not here: they are gaps.
var liveChanges = map[string]bool{
	record.GapLiveBlockAdded: true, record.GapLiveBlockRemoved: true, record.GapLiveBlockExpired: true,
	record.GapLiveUnblockExpired: true, record.GapLiveRuleLifted: true, record.GapLiveRuleRestored: true,
	record.GapLiveLiftExpired: true, record.GapLiveLiftRefused: true, record.GapRunPaused: true,
	record.GapRunResumed: true, record.GapPauseFailed: true, record.GapResumeFailed: true,
	record.GapMCPToolChanged: true, record.GapModelRouteChanged: true,
}

// LiveChange reports whether a gap of what and why records a live change (liveChanges) rather than a gap in what the
// run could see or enforce.
func LiveChange(what, why string) bool { return what == record.GapEnforce && liveChanges[why] }

// Split parts cs into the gaps proper and the live changes (LiveChange), each in cs's order; either is nil when it
// holds none. Line renders either half.
func Split(cs []Count) (gaps, live []Count) {
	for _, c := range cs {
		if LiveChange(c.What, c.Why) {
			live = append(live, c)
		} else {
			gaps = append(gaps, c)
		}
	}
	return gaps, live
}

// Class is what a gap means for the run's record: the one reading of a gap the receipt, the dashboard's receipt and
// tego status all use (QA PW-2).
type Class int

const (
	// Missed is a gap that may have lost actions, so the record's counts are a minimum. Anything not named below is
	// one, a gap this binary does not know included: the conservative reading.
	Missed Class = iota
	// Live is a person's live change (LiveChange): no action went unrecorded.
	Live
	// Capture is model traffic tego could not read: only the token counts are short.
	Capture
	// Price is a missing price: only the cost estimate is short.
	Price
	// Restored is tego giving the owner back the rights something took from one of its own files
	// (record.GapOwnStateModeRestored): nothing went unrecorded and nothing is short, so the counts stand.
	Restored
	// Uncertain is shared tracing counter evidence that cannot establish whether this run lost actions.
	Uncertain
	// RulesUncertain is a skip of a shared program the run's rules rely on (ADR 0148): the kernel skipped a program
	// that decides the run's actions or adds its child cgroups to the run set, or the counters could not be read, so
	// the run cannot say every rule held. The skip may have been another run's or an ungoverned task's.
	RulesUncertain
)

// priceWhys are the whys of a gap what=record that leave only the cost unestimated.
var priceWhys = map[string]bool{"no-price-table": true, "price-table-version-mismatch": true, "unpriced-model": true}

// Classify says what a gap of what and why means for the record.
func Classify(what, why string) Class {
	switch {
	case LiveChange(what, why):
		return Live
	case what == record.GapRecord && (why == SharedTracingSkip || why == SharedTracingUnavailable):
		return Uncertain
	case what == record.GapEnforce && (why == record.GapDecidingSkip || why == record.GapTrackingSkip ||
		why == record.GapSkipCounterUnavailable || why == record.GapSkipCounterRestored):
		return RulesUncertain
	case what == record.GapCapture:
		return Capture
	case what == record.GapRecord && priceWhys[why]:
		return Price
	case what == record.GapRecord && why == record.GapOwnStateModeRestored:
		return Restored
	}
	return Missed
}

// SharedTracingWords preserves what these counters measure, including their inability to attribute skips to
// this run. "Reported" also covers merged run windows that may count the same skipped execution more than once.
func SharedTracingWords(skipped int, unavailable bool) string {
	words := "recording coverage is uncertain"
	if skipped > 0 {
		words += fmt.Sprintf(": %d reported skipped executions of shared tracing programs, which may belong to other runs or ungoverned tasks", skipped)
	}
	if unavailable {
		words += "; active shared tracing program counters could not be established or read"
	}
	return words + "; this run may have unrecorded actions"
}

// SkippedProgramWords says what skips of the programs a run's rules rely on mean (RulesUncertain), in the words the
// receipt and tego status use: deciding and tracking are the reported skips of each class, unavailable that a reading
// failed. The programs are shared, so the words never say the skips were this run's.
func SkippedProgramWords(deciding, tracking int, unavailable bool) string {
	var parts []string
	if deciding > 0 {
		parts = append(parts, fmt.Sprintf("the kernel skipped %d executions of shared programs that decide this run's "+
			"actions, so an action the rules refuse may have gone on unrefused", deciding))
	}
	if tracking > 0 {
		parts = append(parts, fmt.Sprintf("the kernel skipped %d executions of the shared program that adds a run's "+
			"child cgroups to the run set, so tasks of a child cgroup may have gone ungoverned and unrecorded", tracking))
	}
	if unavailable {
		parts = append(parts, "the skip counters of the programs the run's rules rely on could not be read")
	}
	if len(parts) == 0 {
		parts = append(parts, "the kernel skipped programs that the run's rules rely on")
	}
	return "the rules may not have held: " + strings.Join(parts, "; ") +
		"; the skips may belong to other runs or ungoverned tasks"
}

// skipWordsOf is SkippedProgramWords over the RulesUncertain entries of cs.
func skipWordsOf(cs []Count) string {
	var deciding, tracking int
	var unavailable bool
	for _, c := range cs {
		switch {
		case c.What != record.GapEnforce:
		case c.Why == record.GapDecidingSkip:
			deciding = addCount(deciding, c.SharedSkipped)
		case c.Why == record.GapTrackingSkip:
			tracking = addCount(tracking, c.SharedSkipped)
		case c.Why == record.GapSkipCounterUnavailable, c.Why == record.GapSkipCounterRestored:
			// A restored line closes an outage: the counters could not be read for a while.
			unavailable = true
		}
	}
	return SkippedProgramWords(deciding, tracking, unavailable)
}

// RestoredWords says how many of tego's own files had their owner's rights given back (Restored), in the words the
// receipt and tego status use.
func RestoredWords(n int) string {
	if n == 1 {
		return "tego restored the mode of one of its own files"
	}
	return fmt.Sprintf("tego restored the modes of %d of its own files", n)
}

// liveWords says what each live change did, in the words the dashboard's glossary gives it (linewords.GapWhy; a test
// there holds the two equal).
var liveWords = map[string]string{
	record.GapLiveBlockAdded:     "a live block was added",
	record.GapLiveBlockRemoved:   "a live block was removed",
	record.GapLiveBlockExpired:   "a live block's time ran out; it no longer refuses",
	record.GapLiveUnblockExpired: "a live block's time off ran out; it refuses again",
	record.GapLiveRuleLifted:     "a rule in the fence was allowed for now",
	record.GapLiveRuleRestored:   "a rule in the fence refuses again",
	record.GapLiveLiftExpired:    "an allowed rule's time ran out; it refuses again",
	record.GapLiveLiftRefused:    "a request to allow a rule was refused; nothing was loosened",
	record.GapRunPaused:          "the run was paused",
	record.GapRunResumed:         "the run was resumed",
	record.GapPauseFailed:        "a pause could not be put in force; the run kept running",
	record.GapResumeFailed:       "a resume could not be put in force; the run stays paused",
	record.GapMCPToolChanged:     "an MCP tool's rule was changed live",
	record.GapModelRouteChanged:  "a model endpoint's requests were sent to another approved backend",
}

// LiveWords is what a live change's why did, in words; false for a why that is not one.
func LiveWords(why string) (string, bool) {
	w, ok := liveWords[why]
	return w, ok
}

// Words says what a run's gaps mean, in the words its receipt and the dashboard use: whether actions may be missing,
// what is short if not, which of its own files tego gave back their owner's rights (Restored), and what a person
// changed. "" when the run recorded no gap and ended: the gap line's "none"
// says that. cutOff says the run stopped with no run_end (status.Lost): its record may stop short of what it did, so
// no count of gap lines can say that nothing is missing.
func Words(cs []Count, cutOff bool) string {
	if len(cs) == 0 && !cutOff {
		return ""
	}
	var missed, lost, capture, price, restored, skipped int
	var uncertain, unavailable bool
	var rules []Count
	var live []string
	for _, c := range cs {
		switch Classify(c.What, c.Why) {
		case Uncertain:
			uncertain = true
			skipped = addCount(skipped, c.SharedSkipped)
			unavailable = unavailable || c.Why == SharedTracingUnavailable
		case RulesUncertain:
			rules = append(rules, c)
		case Missed:
			missed = addCount(missed, c.Events)
			lost = addCount(lost, c.Lost)
		case Capture:
			capture = addCount(capture, c.Events)
		case Price:
			price = addCount(price, c.Events)
		case Restored:
			restored = addCount(restored, c.Events)
		case Live:
			w, ok := liveWords[c.Why]
			if !ok {
				w = record.Printable(c.Why)
			}
			if c.Events > 1 {
				w += fmt.Sprintf(" (%d times)", c.Events)
			}
			live = append(live, w)
		}
	}
	var parts []string
	if len(rules) > 0 {
		// First: it says what the run's rules may not have done, the gravest thing a gap can say.
		parts = append(parts, skipWordsOf(rules))
	}
	switch {
	case missed > 0 && lost > 0:
		parts = append(parts, fmt.Sprintf("%s in the record (counts are a minimum, %d events lost)", plural(missed, "gap"), lost))
	case missed > 0:
		parts = append(parts, plural(missed, "gap")+" in the record (counts are a minimum)")
	case !cutOff && !uncertain && len(rules) == 0:
		// A skipped tracking program leaves a child cgroup's tasks unrecorded too, so with rules uncertain nothing
		// says no action is missing.
		parts = append(parts, "no action known to be missing")
	}
	if uncertain {
		parts = append(parts, SharedTracingWords(skipped, unavailable))
	}
	if cutOff {
		parts = append(parts, "the record has no end, so it may stop short of what the run did")
	}
	if capture > 0 {
		parts = append(parts, fmt.Sprintf("token counts may be low (%s)", plural(capture, "capture gap")))
	}
	if price > 0 {
		parts = append(parts, "the cost is not estimated (no price for a model)")
	}
	if restored > 0 {
		parts = append(parts, RestoredWords(restored))
	}
	return strings.Join(append(parts, live...), "; ")
}

// plural is n and noun, with an s past one.
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// sortCounts orders entries by what, then why: one order in the table, the JSON and the tests.
func sortCounts(cs []Count) {
	slices.SortFunc(cs, func(a, b Count) int {
		if c := cmp.Compare(a.What, b.What); c != 0 {
			return c
		}
		return cmp.Compare(a.Why, b.Why)
	})
}
