// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// receiptClock is the zone the terminal layout prints times in: the reader's own, as the dashboard and tego events
// show them, so a receipt read beside either agrees with it. Tests set it to time.UTC. The JSON keeps the ledger's
// RFC 3339 UTC.
var receiptClock = func() *time.Location { return time.Local }

// timesIn is the suffix a heading over a list of times carries: the zone those times are printed in, the one their
// first time falls in, since a zone's name belongs to an instant (a receipt read after a daylight-saving change said
// EST over the EDT times of a run from before it).
func timesIn(first time.Time, loc *time.Location) string {
	zone, _ := first.In(loc).Zone()
	return " (times in " + zone + ")"
}

// timeIn is the listed time ts under a heading timesIn(first) made, naming its own zone when a run crossed a
// daylight-saving change and ts is on the other side of it.
func timeIn(ts, first time.Time, loc *time.Location) string {
	local := ts.In(loc)
	zone, _ := local.Zone()
	if head, _ := first.In(loc).Zone(); zone != head {
		return local.Format("15:04:05") + " " + zone
	}
	return local.Format("15:04:05")
}

// maxListed is how many paths, refusals and asks the terminal layout lists before "and N more".
const maxListed = 10

// JSON writes the receipt as one indented JSON object (the byte-exact form; strings are not escaped for a
// terminal).
func (rc *Receipt) JSON(w io.Writer) error {
	b, err := json.MarshalIndent(rc, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// Text writes the receipt's short terminal layout: plain sentences, one section per V1 field. Every string that
// came from the ledger goes through record.Printable.
func (rc *Receipt) Text(w io.Writer) error {
	var b strings.Builder
	p := record.Printable
	agent := rc.Agent
	if agent == "" {
		agent = "an agent"
	}
	fmt.Fprintf(&b, "Receipt for run %s (%s)\n", p(rc.Run), p(agent))
	if len(rc.Command) > 0 {
		fmt.Fprintf(&b, "  Command: %s\n", p(cut(strings.Join(rc.Command, " "), 100)))
	}
	fmt.Fprintf(&b, "  Outcome: %s\n", rc.Outcome())

	b.WriteString("\nTime taken\n")
	fmt.Fprintf(&b, "  %s", Duration(rc.Time.Seconds))
	if rc.Time.SoFar {
		b.WriteString(" so far")
	}
	if rc.Time.Note != "" {
		fmt.Fprintf(&b, " (%s)", rc.Time.Note)
	}
	b.WriteString(".\n")

	// "Files written", never "files changed": an allowed write-open is no proof that a byte changed.
	b.WriteString("\nFiles written\n")
	f := rc.Files
	if !f.Recorded {
		fmt.Fprintf(&b, "  %s.\n", capital(f.Note))
	} else {
		fmt.Fprintf(&b, "  %d written, %d created, %d deleted, %d renamed.\n", len(f.Written), len(f.Created), len(f.Deleted), len(f.Renamed))
		rc.listPaths(&b, "Wrote", f.Written)
		rc.listPaths(&b, "Created", f.Created)
		rc.listPaths(&b, "Deleted", f.Deleted)
		for i, r := range f.Renamed {
			if i == maxListed {
				fmt.Fprintf(&b, "    and %d more renames\n", len(f.Renamed)-maxListed)
				break
			}
			fmt.Fprintf(&b, "    Renamed %s to %s\n", p(cutMiddle(rc.shortPath(r.From), 60)), p(cutMiddle(rc.shortPath(r.To), 60)))
		}
		if f.Truncated {
			fmt.Fprintf(&b, "  The lists stop at %d paths each.\n", MaxPaths)
		}
		if f.Note != "" {
			fmt.Fprintf(&b, "  %s.\n", capital(f.Note))
		}
	}

	rc.activityText(&b)

	loc := receiptClock()
	rf := rc.Refusals
	if len(rf.List) > 0 {
		b.WriteString("\nRefused actions" + timesIn(rf.List[0].TS, loc) + "\n")
	} else {
		b.WriteString("\nRefused actions\n")
	}
	if rf.Total == 0 {
		fmt.Fprintf(&b, "  %s\n", rc.RefusedWords())
	} else {
		fmt.Fprintf(&b, "  Tego refused %d %s.\n", rf.Total, plural(rf.Total, "action", "actions"))
		if w := rc.RefusedWords(); w != "" {
			fmt.Fprintf(&b, "  %s\n", w)
		}
		for _, g := range rc.RefusalGroups() {
			fmt.Fprintf(&b, "    %4d  %s (%s)\n", g.Count, p(g.Words), p(g.Reason))
		}
		for _, s := range rc.SameFile() {
			fmt.Fprintf(&b, "    %s: refused, %s (%d %s)\n", p(rc.shortPath(s.Path)), p(s.Note), s.Count, plural(s.Count, "time", "times"))
		}
		for i, r := range rf.List {
			if i == maxListed {
				fmt.Fprintf(&b, "    and %d more; tego events %s --verdict refused lists them all\n", rf.Total-maxListed, p(rc.Run))
				break
			}
			fmt.Fprintf(&b, "    %s  %s %s  %s (%s)\n", timeIn(r.TS, rf.List[0].TS, loc), p(r.Op), p(cutMiddle(rc.shortTarget(r.Target), 70)),
				p(rc.refusalWords(r)), p(r.Reason))
		}
	}

	b.WriteString("\nRefusals over time\n")
	if rf.Total == 0 {
		fmt.Fprintf(&b, "  %s\n", NoneOverTime)
	} else {
		fmt.Fprintf(&b, "  Per minute from the start: %s\n", overTime(rc.OverTime.Counts))
	}

	b.WriteString("\nStall minutes\n")
	st := rc.Stall
	if st.Windows == 0 {
		fmt.Fprintf(&b, "  No quiet stretch of %s or more.\n", Duration(st.ThresholdSeconds))
	} else {
		fmt.Fprintf(&b, "  %s minutes quiet, in %d %s of %s or more.\n", strconv.FormatFloat(st.Minutes, 'f', -1, 64), st.Windows,
			plural(st.Windows, "stretch", "stretches"), Duration(st.ThresholdSeconds))
	}
	if st.EndedByStall {
		b.WriteString("  The stall limit ended the run.\n")
	}
	if st.Note != "" {
		fmt.Fprintf(&b, "  Partial: %s.\n", st.Note)
	}

	b.WriteString("\nTests result\n")
	fmt.Fprintf(&b, "  %s.\n", capital(rc.Tests.Note))

	a := rc.Asks
	if len(a.List) > 0 {
		b.WriteString("\nTimes it asked you" + timesIn(a.List[0].TS, loc) + "\n")
	} else {
		b.WriteString("\nTimes it asked you\n")
	}
	if a.Asked == 0 {
		b.WriteString("  It never asked.\n")
	} else {
		fmt.Fprintf(&b, "  It asked %d %s: %d approved, %d denied, %d timed out, %d answered with another file, %d not answered.\n",
			a.Asked, plural(a.Asked, "time", "times"), a.Approved, a.Denied, a.TimedOut, a.Alternates, a.Unanswered)
		for i, q := range a.List {
			if i == maxListed {
				fmt.Fprintf(&b, "    and %d more\n", len(a.List)-maxListed)
				break
			}
			ans := q.Answer
			if ans == "" {
				ans = "not answered"
			}
			fmt.Fprintf(&b, "    %s  %s %s  %s", timeIn(q.TS, a.List[0].TS, loc), p(q.Op), p(cutMiddle(rc.shortTarget(q.Target), 60)), ans)
			if q.By != "" {
				fmt.Fprintf(&b, " by %s after %ss", p(q.By), strconv.FormatFloat(q.AfterS, 'f', 1, 64))
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("\nTokens and model calls\n")
	t := rc.Tokens
	if !t.Recorded {
		fmt.Fprintf(&b, "  %s.\n", capital(t.Note))
	} else {
		fmt.Fprintf(&b, "  %d model %s; tokens: %d in, %d out, %d cache read, %d cache write.\n", t.ModelCalls,
			plural(t.ModelCalls, "call", "calls"), t.In, t.Out, t.CacheRead, t.CacheWrite)
		if t.Note != "" {
			fmt.Fprintf(&b, "  %s.\n", capital(t.Note))
		}
	}
	switch {
	case t.CostText == "":
	case t.Unpriced == t.Metered:
		fmt.Fprintf(&b, "  Cost: not estimated; no price covered the %d metered %s.\n", t.Metered, plural(t.Metered, "response", "responses"))
	default:
		fmt.Fprintf(&b, "  Cost: %s.\n", t.CostText)
	}

	b.WriteString("\nCoverage\n")
	if rc.Coverage.Complete {
		b.WriteString("  Complete: every field above was read off a ledger that records it.\n")
	} else {
		// A gap whose note its own section already printed is not repeated here (the tokens note was said twice); the
		// JSON's coverage still lists every gap.
		said := map[string]bool{"files": !f.Recorded || f.Note != "", "tokens": !t.Recorded || t.Note != "", "stall": st.Note != ""}
		left := 0
		for _, g := range rc.Coverage.Gaps {
			if said[g.Field] && g.Why != "" && !strings.HasPrefix(g.Why, "each list stops") {
				continue
			}
			fmt.Fprintf(&b, "  %s: %s.\n", g.Field, p(g.Why))
			left++
		}
		if left == 0 {
			b.WriteString("  Partial: the notes in the sections above say what this run's record could not cover.\n")
		}
	}
	if fr := rc.Coverage.FrozenText(); fr != "" {
		fmt.Fprintf(&b, "  %s\n", fr)
	}
	for _, n := range rc.Notes {
		fmt.Fprintf(&b, "\nNote: %s.\n", p(n))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// TimeText is the time taken in words, "so far" for a live run.
func (rc *Receipt) TimeText() string {
	s := Duration(rc.Time.Seconds)
	if rc.Time.SoFar {
		s += " so far"
	}
	if rc.Time.Note != "" {
		s += " (" + rc.Time.Note + ")"
	}
	return s
}

// StallText is the stall minutes in words.
func (rc *Receipt) StallText() string {
	st := rc.Stall
	if st.Windows == 0 {
		return "No quiet stretch of " + Duration(st.ThresholdSeconds) + " or more"
	}
	return fmt.Sprintf("%s minutes quiet, in %d %s of %s or more", strconv.FormatFloat(st.Minutes, 'f', -1, 64), st.Windows,
		plural(st.Windows, "stretch", "stretches"), Duration(st.ThresholdSeconds))
}

// OverTimeText is the refusals per minute, at most 12 numbers.
func (rc *Receipt) OverTimeText() string { return overTime(rc.OverTime.Counts) }

// Outcome is the run's end in a few words.
func (rc *Receipt) Outcome() string {
	switch {
	case !rc.Ended && rc.Time.Note == "":
		return "still running"
	case !rc.Ended:
		return "no end recorded (the run was lost or is still running)"
	case rc.ExitCode != nil:
		return "exited with code " + strconv.Itoa(*rc.ExitCode)
	case rc.EndReason == record.RunEndSignal:
		return "ended by signal " + strconv.Itoa(rc.Signal)
	case rc.EndReason == record.RunEndExecFailed:
		return "the command could not be started"
	case rc.EndReason == record.RunEndLimit:
		return "stopped by a limit in its contract"
	case rc.EndReason == record.RunEndStopped:
		return "stopped by a person"
	case rc.EndReason == record.RunEndOOM:
		return "killed: out of memory"
	case rc.EndReason == record.RunEndPids:
		return "stopped: too many processes"
	}
	return "ended: " + record.Printable(rc.EndReason)
}

// ruleText names the rule that refused an action in words: the default deny, which the ledger records as rule
// "unmatched", reads "not allowed by any rule"; the ledger value is unchanged.
func ruleText(r string) string {
	switch r {
	case "":
		return "no rule named"
	case "unmatched":
		return "not allowed by any rule"
	}
	return r
}

func (rc *Receipt) listPaths(b *strings.Builder, verb string, paths []string) {
	for i, s := range paths {
		if i == maxListed {
			fmt.Fprintf(b, "    and %d more\n", len(paths)-maxListed)
			return
		}
		fmt.Fprintf(b, "    %s %s\n", verb, record.Printable(cutMiddle(rc.shortPath(s), 90)))
	}
}

// The words of tego's built-in refusal of setsockopt(TCP_ULP) (builtInULP): kernel TLS, which OpenSSL tries and falls
// back from (once per HTTPS run of Python on Ubuntu 24.04), and any other name, which is not called kernel TLS (smc
// turns a TCP socket into another family). Each has a long form for the receipt and a short kind for tego run's summary
// and the dashboard. The words say what a TLS library does, not what this caller did: the record holds the name the
// supervisor read after its decision, which the agent can change, and the root tiers' line may be an io_uring call.
const (
	ulpTLSKind  = "built in: kernel TLS"
	ulpTLSWords = `built in, no rule allows it: kernel TLS (TCP_ULP "tls") is refused under a net: section, and a ` +
		`TLS library such as OpenSSL falls back to its own TLS`
	ulpOtherKind  = "built in: TCP upper-layer protocol"
	ulpOtherWords = "built in, no rule allows it: every TCP upper-layer protocol is refused under a net: section, " +
		"since one can turn an allowed socket into another kind"
)

// builtInULP reports whether a refusal is tego's built-in refusal of setsockopt(TCP_ULP), and whether it names kernel
// TLS. Under a net: section tego refuses every upper-layer protocol whatever the contract says (ADR 0018 (7)), and both
// writers, the supervisor and the root tiers' cgroup/setsockopt, spell it alike (record.SocketOption): op setsockopt,
// target TCP_ULP, rule unmatched, reason net-not-allowed. The record's rule is the default deny's, so "not allowed by
// any rule" would read as if a rule could allow it. The record is unchanged: this is for the words only.
func builtInULP(op, target, rule, reason string) (tls, ok bool) {
	if op != "setsockopt" || rule != "unmatched" || reason != string(record.ReasonNetNotAllowed) {
		return false, false
	}
	name, ok := strings.CutPrefix(target, "TCP_ULP ")
	if !ok && target != "TCP_ULP" {
		return false, false
	}
	return name == `"tls"`, true
}

// BuiltInKind is a listed refusal's built-in kind ("built in: kernel TLS", BuiltInRefusal), or "" for any other
// refusal: the dashboard's Receipt tab names it so, as tego run's summary does.
func (rc *Receipt) BuiltInKind(r Refusal) string {
	return BuiltInRefusal(r.Op, r.Target, r.Rule, r.Reason)
}

// BuiltInRefusal is one refused line's built-in kind (builtInULP: "built in: kernel TLS", or "built in: TCP
// upper-layer protocol" for another name), or "" for any other line. It is the one rule every page that names a single
// line's rule reads (the dashboard's Logs, a run's timeline and Refusals tab, Detections), so none of them calls tego's
// built-in refusal "Not in contract" while the receipt calls it built in. op and target are the line's as the receipt
// and the dashboard read them: op setsockopt, target the record's TCP_ULP words.
func BuiltInRefusal(op, target, rule, reason string) string {
	if tls, ok := builtInULP(op, target, rule, reason); ok && tls {
		return ulpTLSKind
	} else if ok {
		return ulpOtherKind
	}
	return ""
}

// BuiltInWords is one refused line's built-in refusal in the receipt's own words (builtInULP: "built in, no rule allows
// it: kernel TLS (TCP_ULP "tls") is refused under a net: section, ..."), or "" for any other line: the sentence tego
// receipt prints for it, which the dashboard's Logs row says under the line in place of the default deny's reason
// ("not on the allowed hosts"), so the two never word one refusal two ways.
func BuiltInWords(op, target, rule, reason string) string {
	if tls, ok := builtInULP(op, target, rule, reason); ok && tls {
		return ulpTLSWords
	} else if ok {
		return ulpOtherWords
	}
	return ""
}

// NoneOverTime is the refusals-over-time part of a receipt that counts no refusal, on `tego receipt` and the
// dashboard's Receipt tab alike: there is nothing to draw, and RefusedWords says what that count leaves out.
const NoneOverTime = "None to show."

// RefusedWords is what a receipt says beside its refusal count, the same sentence on `tego receipt` and the
// dashboard's Receipt tab. With no refusal: "Nothing was refused.", or, when a read this run refused leaves no line
// (RefusedReadsUnrecorded), that no recorded action was refused and why. With refusals: that a refused read is not
// counted, when it leaves no line, else "".
func (rc *Receipt) RefusedWords() string {
	return RefusedSentence(rc.Refusals.Total, rc.RefusedReadsUnrecorded())
}

// RefusedSentence is RefusedWords for a run that refused total lines and whose refused reads leave no line when
// readsUnrecorded (ReadsUnrecordedBy): the one rule for these words, which the dashboard's Refusals tab reads too for a
// run it has not built a receipt of.
func RefusedSentence(total int, readsUnrecorded bool) string {
	switch {
	case total == 0 && readsUnrecorded:
		return "No recorded action was refused; this run does not record refused reads (see Sensitive files read)."
	case total == 0:
		return "Nothing was refused."
	case readsUnrecorded:
		return "This run does not record refused reads, so a read it refused is not counted (see Sensitive files read)."
	}
	return ""
}

// routineWords are the routine calls a receipt counts apart from its places, in words: the system lookups any
// program makes, and the socket calls that name no place (C58). Neither is a place the run connected to.
func (rc *Receipt) routineWords() []string {
	var routine []string
	if rc.SystemLookups > 0 {
		routine = append(routine, fmt.Sprintf("%d %s (the name and user lookups any program makes)", rc.SystemLookups,
			plural(rc.SystemLookups, "routine system lookup", "routine system lookups")))
	}
	if rc.RoutineSockets > 0 {
		routine = append(routine, fmt.Sprintf("%d %s (disconnects with AF_UNSPEC, the kernel's netlink socket)", rc.RoutineSockets,
			plural(rc.RoutineSockets, "routine socket call that names no place", "routine socket calls that name no place")))
	}
	return routine
}

// NoConnectionWords is the Connections part of a receipt that lists no place, the same sentence on `tego receipt` and
// the dashboard's Receipt tab: "None recorded.", or "None, besides" the routine calls it counted apart. It is "" when
// the receipt lists a place (RoutineAlsoWords then says the routine calls).
func (rc *Receipt) NoConnectionWords() string {
	if len(rc.Connections) > 0 {
		return ""
	}
	if routine := rc.routineWords(); len(routine) > 0 {
		return "None, besides " + strings.Join(routine, " and ") + "."
	}
	return "None recorded."
}

// RoutineAlsoWords are the lines under a receipt's places, one per routine count: "Also 3 routine system lookups (...),
// not counted above." None when the receipt lists no place (NoConnectionWords then names them).
func (rc *Receipt) RoutineAlsoWords() []string {
	if len(rc.Connections) == 0 {
		return nil
	}
	var also []string
	for _, r := range rc.routineWords() {
		also = append(also, "Also "+r+", not counted above.")
	}
	return also
}

// refusalWords is a listed refusal's rule in words (RuleWords), or a built-in TCP_ULP refusal's (builtInULP).
func (rc *Receipt) refusalWords(r Refusal) string {
	if w := BuiltInWords(r.Op, r.Target, r.Rule, r.Reason); w != "" {
		return w
	}
	return rc.RuleWords(r.Rule)
}

// RefusalGroup is one line of the refusals by rule as a person reads them: Refusals.ByRule, but with tego's built-in
// TCP_ULP refusals (builtInULP) apart from the default deny that the record names them by. Words is the receipt's
// (RuleWords, or the built-in's sentence) and Kind the short form tego run's summary prints (the rule's name without
// its entry, or the built-in's few words). Rule is the rule the record names (unmatched for a built-in one), and
// BuiltIn says the group is a built-in TCP_ULP refusal, which the dashboard names by its Kind.
type RefusalGroup struct {
	Kind, Words, Rule, Reason string
	Count                     int
	BuiltIn                   bool
}

// RefusalGroups is Refusals.ByRule in words, most first: the counts sum to Refusals.Total as ByRule's do, and only the
// default deny's net-not-allowed line is split, its built-in TCP_ULP refusals named apart.
func (rc *Receipt) RefusalGroups() []RefusalGroup {
	var gs []RefusalGroup
	for _, r := range rc.Refusals.ByRule {
		n := r.Count
		if r.Rule == "unmatched" && r.Reason == string(record.ReasonNetNotAllowed) {
			for _, u := range []struct {
				kind, words string
				n           int
			}{{ulpTLSKind, ulpTLSWords, rc.ulpTLS}, {ulpOtherKind, ulpOtherWords, rc.ulpOther}} {
				if u.n = min(u.n, n); u.n > 0 {
					gs = append(gs, RefusalGroup{Kind: u.kind, Words: u.words, Rule: r.Rule, Reason: r.Reason, Count: u.n, BuiltIn: true})
					n -= u.n
				}
			}
		}
		if n > 0 {
			words := rc.RuleWords(r.Rule)
			kind, _, _ := strings.Cut(words, "[")
			gs = append(gs, RefusalGroup{Kind: kind, Words: words, Rule: r.Rule, Reason: r.Reason, Count: n})
		}
	}
	sort.SliceStable(gs, func(i, j int) bool { return gs[i].Count > gs[j].Count })
	return gs
}

// RuleWords is a refusing rule as the receipt names it (ruleText), with a path inside its brackets shortened as
// ShortPath does: "not allowed by any rule", "fs.deny_read[~/.ssh/]". tego run's end summary uses it.
func (rc *Receipt) RuleWords(r string) string {
	name, rest, ok := strings.Cut(r, "[")
	entry, ok2 := strings.CutSuffix(rest, "]")
	if !ok || !ok2 || !strings.HasPrefix(entry, "/") {
		return ruleText(r)
	}
	slash := strings.HasSuffix(entry, "/") && len(entry) > 1
	short := rc.shortPath(strings.TrimSuffix(entry, "/"))
	if slash {
		short += "/"
	}
	return name + "[" + short + "]"
}

// ShortPath is p as the text layout prints it (shortPath).
func (rc *Receipt) ShortPath(p string) string { return rc.shortPath(p) }

// shortPath is p as a person reads it: relative to the run's working folder when under it, ~/... under Options.Home,
// else whole. A path that only shares a prefix with the folder (/p/proj-old under /p/proj) stays whole.
func (rc *Receipt) shortPath(p string) string {
	if rel, ok := under(p, rc.Cwd); ok {
		if rel == "" {
			return "."
		}
		return rel
	}
	if rel, ok := under(p, rc.home); ok {
		if rel == "" {
			return "~"
		}
		return "~/" + rel
	}
	return p
}

// shortTarget is shortPath over a refusal's or an ask's target: a path, "from -> to" for a rename, or a
// destination (left as it is, since it is not under a folder).
func (rc *Receipt) shortTarget(s string) string {
	if from, to, ok := strings.Cut(s, " -> "); ok {
		return rc.shortPath(from) + " -> " + rc.shortPath(to)
	}
	return rc.shortPath(s)
}

// under reports whether p is dir or inside it, and the rest of p below dir.
func under(p, dir string) (string, bool) {
	dir = strings.TrimRight(dir, "/")
	if dir == "" || !strings.HasPrefix(p, "/") {
		return "", false
	}
	if p == dir {
		return "", true
	}
	rest, ok := strings.CutPrefix(p, dir+"/")
	return rest, ok
}

// activityText writes the Connections, Programs run and Sensitive files read sections.
func (rc *Receipt) activityText(b *strings.Builder) {
	p := record.Printable
	b.WriteString("\nConnections\n")
	// The routine counts are neither a place the run connected to; the dashboard's Receipt tab prints the same words.
	if none := rc.NoConnectionWords(); none != "" {
		fmt.Fprintf(b, "  %s\n", none)
	} else {
		n, total := len(rc.Connections)+rc.ConnectionsMore, rc.ConnectionTries
		fmt.Fprintf(b, "  %d %s to %d %s", total, plural(total, "connection", "connections"), n, plural(n, "place", "places"))
		if rc.ConnectionsMore > 0 {
			fmt.Fprintf(b, "; the %d most used are below", len(rc.Connections))
		}
		b.WriteString(".\n")
		for _, c := range rc.Connections {
			fmt.Fprintf(b, "    %s  %d  %s\n", p(cutMiddle(c.Destination, 60)), c.Count, verdictWords(c.Verdicts))
		}
		if rc.ConnectionsMore > 0 {
			fmt.Fprintf(b, "    and %d more; tego events %s --kind net lists them all\n", rc.ConnectionsMore, p(rc.Run))
		}
		for _, also := range rc.RoutineAlsoWords() {
			fmt.Fprintf(b, "  %s\n", also)
		}
	}
	if rc.ConnectionsNote != "" {
		fmt.Fprintf(b, "  %s.\n", capital(rc.ConnectionsNote))
	}

	b.WriteString("\nPrograms run\n")
	if len(rc.Programs) == 0 {
		b.WriteString("  None recorded.\n")
	} else {
		n, starts := len(rc.Programs)+rc.ProgramsMore, 0
		for _, g := range rc.Programs {
			starts += g.Count
		}
		if rc.ProgramsMore > 0 {
			fmt.Fprintf(b, "  %d programs; the %d most started are below.\n", n, len(rc.Programs))
		} else {
			fmt.Fprintf(b, "  %d %s, started %d %s.\n", n, plural(n, "program", "programs"), starts, plural(starts, "time", "times"))
		}
		for _, g := range rc.Programs {
			fmt.Fprintf(b, "    %s  %d\n", p(cutMiddle(rc.shortPath(g.Path), 70)), g.Count)
		}
		if rc.ProgramsMore > 0 {
			fmt.Fprintf(b, "    and %d more; tego events %s --kind exec lists them all\n", rc.ProgramsMore, p(rc.Run))
		}
	}

	b.WriteString("\nSensitive files read\n")
	switch {
	case len(rc.SensitiveReads) == 0 && rc.SensitiveReadsUnknown:
		b.WriteString("  Not known: this run did not record every read, so a sensitive file may have been read.\n")
	case len(rc.SensitiveReads) == 0:
		b.WriteString("  None: no file that looks like a secret, and none a read rule guards.\n")
	default:
		for i, s := range rc.SensitiveReads {
			if i == maxListed {
				fmt.Fprintf(b, "    and %d more\n", len(rc.SensitiveReads)-maxListed)
				break
			}
			fmt.Fprintf(b, "    %s  %d  %s\n", p(cutMiddle(rc.shortPath(s.Path), 70)), s.Verdicts.Total(), verdictWords(s.Verdicts))
		}
		if rc.SensitiveReadsTruncated {
			fmt.Fprintf(b, "  The list stops at %d files.\n", MaxPaths)
		}
	}
	if rc.SensitiveReadsNote != "" {
		fmt.Fprintf(b, "  %s.\n", capital(rc.SensitiveReadsNote))
	}
}

// verdictWords says what happened to an action's tries in plain words: one word when they all ended the same way,
// else the count of each.
func verdictWords(v Verdicts) string {
	words := []struct {
		n    int
		word string
	}{{v.Observed, "recorded, not blocked"}, {v.Allowed, "allowed"}, {v.Refused, "refused"}}
	var parts []string
	for _, w := range words {
		if w.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", w.n, w.word))
		}
	}
	if len(parts) == 1 {
		for _, w := range words {
			if w.n > 0 {
				return w.word
			}
		}
	}
	return strings.Join(parts, ", ")
}

// overTime renders the per-minute counts, regrouped into at most 12 columns.
func overTime(c []int) string {
	if len(c) == 0 {
		return "none"
	}
	per := 1
	for (len(c)+per-1)/per > 12 {
		per++
	}
	var parts []string
	for i := 0; i < len(c); i += per {
		n := 0
		for j := i; j < min(i+per, len(c)); j++ {
			n += c[j]
		}
		parts = append(parts, strconv.Itoa(n))
	}
	s := strings.Join(parts, " ")
	if per > 1 {
		s += fmt.Sprintf(" (each number is %d minutes)", per)
	}
	return s
}

func cut(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// cutMiddle shortens s to n runes by cutting its middle, never its tail: a path's file name is the part a reader
// needs ("…/teleme…" hid which file was written). It keeps a third of the room for the head.
func cutMiddle(s string, n int) string {
	r := []rune(s)
	if len(r) <= n || n < 5 {
		return s
	}
	head := (n - 1) / 3
	tail := n - 1 - head
	return string(r[:head]) + "…" + string(r[len(r)-tail:])
}

func capital(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
