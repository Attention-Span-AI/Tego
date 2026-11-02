// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"fmt"
	"io"
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
		b.WriteString("  Nothing was refused.\n")
	} else {
		fmt.Fprintf(&b, "  Tego refused %d %s.\n", rf.Total, plural(rf.Total, "action", "actions"))
		for _, r := range rf.ByRule {
			fmt.Fprintf(&b, "    %4d  %s (%s)\n", r.Count, p(rc.RuleWords(r.Rule)), p(r.Reason))
		}
		for i, r := range rf.List {
			if i == maxListed {
				fmt.Fprintf(&b, "    and %d more; tego events %s --verdict refused lists them all\n", rf.Total-maxListed, p(rc.Run))
				break
			}
			fmt.Fprintf(&b, "    %s  %s %s  %s (%s)\n", timeIn(r.TS, rf.List[0].TS, loc), p(r.Op), p(cutMiddle(rc.shortTarget(r.Target), 70)),
				p(rc.RuleWords(r.Rule)), p(r.Reason))
		}
	}

	b.WriteString("\nRefusals over time\n")
	if rf.Total == 0 {
		b.WriteString("  None to show.\n")
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
	lookups := plural(rc.SystemLookups, "routine system lookup", "routine system lookups") // the dashboard's words
	switch {
	case len(rc.Connections) == 0 && rc.SystemLookups == 0:
		b.WriteString("  None recorded.\n")
	case len(rc.Connections) == 0:
		fmt.Fprintf(b, "  None, besides %d %s (the name and user lookups any program makes).\n", rc.SystemLookups, lookups)
	default:
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
		if rc.SystemLookups > 0 {
			fmt.Fprintf(b, "  Also %d %s (the name and user lookups any program makes), not counted above.\n", rc.SystemLookups, lookups)
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
