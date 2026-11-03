// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// receiptView is the Receipt tab's data: the receipt `tego receipt` prints, from the same builder, or why there
// is none. Its methods shape that one receipt for the page (tiles, bars, a sparkline); none computes a number of
// its own, so the page and the terminal cannot disagree.
type receiptView struct {
	R   *ledgerview.Receipt
	Err string
}

// loadReceipt is run id's receipt for the Receipt tab.
func loadReceipt(ctx context.Context, root, id string) *receiptView {
	rc, err := ledgerview.LoadReceipt(ctx, root, id)
	if err != nil {
		return &receiptView{Err: err.Error()}
	}
	return &receiptView{R: rc}
}

// The receipt's page limits: how many files and refusals it lists before pointing at the full views.
const (
	receiptFilesShown = 40
	receiptRefShown   = 12
	sparkCols         = 30
	sparkW, sparkH    = 300, 40
	sparkBar          = 18
)

// LiveSince is the start of a run whose time taken is measured to now (RFC 3339, as the "iso" helper writes it), or
// "" when the time is fixed (an ended run, or one measured to its last line). The tile marks such a time a clock
// (data-since, data-ck): live.js ticks it, and the region's hash leaves its text out, so the Receipt tab is not re-sent
// whenever the seconds change (regions.go).
func (v *receiptView) LiveSince() string {
	if v.R == nil || !v.R.Time.SoFar || v.R.Time.Note != "" || v.R.Started == nil {
		return ""
	}
	return v.R.Started.UTC().Format(time.RFC3339Nano)
}

// Took is the time taken, short ("3m 05s").
// It is the dashboard's one duration formatter (human, "188 ms", "3 m 5 s"), so the Receipt reads like every other
// page (QA QU-16); `tego receipt` keeps its own compact form.
func (v *receiptView) Took() string {
	return human(time.Duration(v.R.Time.Seconds * float64(time.Second)))
}

// ShowStall is whether the Stall minutes block says anything worth a line: a run of at least the stall window (5
// minutes), or one a stall ended. On a 188 ms run "No quiet stretch of 5m 00s or more" only puzzled (QU-16).
func (v *receiptView) ShowStall() bool {
	return v.R.Stall.EndedByStall || v.R.Stall.Windows > 0 || v.R.Time.Seconds >= 300
}

// GapWords is a coverage gap's line in plain words: the receipt's "record" gap ("1 gap line: tego knows it missed
// some actions, so the counts are a floor") reads "1 gap in the record (counts are a minimum)", which says the same
// without alarm (QU-16), and its "tokens.capture" gap ("2 capture gap lines: …") reads "Token counts may be low (2
// capture gaps)"; "" for every other gap, which keeps its own words.
func (v *receiptView) GapWords(field, why string) string {
	if field != "record" && field != "tokens.capture" {
		return ""
	}
	n, _, ok := strings.Cut(why, " ")
	if _, err := strconv.Atoi(n); !ok || err != nil {
		return ""
	}
	gaps := map[bool]string{true: "gap", false: "gaps"}[n == "1"]
	if field == "tokens.capture" {
		return "Token counts may be low (" + n + " capture " + gaps + ")"
	}
	return n + " " + gaps + " in the record (counts are a minimum)"
}

// Command is the run's command line, one string.
func (v *receiptView) Command() string { return strings.Join(v.R.Command, " ") }

// OutcomeClass is the badge class for the run's end, coloured as the run's state badge (layout.tmpl "state") is:
// grey for exit 0, red for a non-zero exit, grey for any other end (stopped, a limit) and while running: amber means
// it needs you and green kept safe (tokens.css), neither of which a run's state is.
func (v *receiptView) OutcomeClass() string {
	rc := v.R
	switch {
	case !rc.Ended:
		return "b-running"
	case rc.ExitCode != nil && *rc.ExitCode == 0:
		return "b-neutral"
	case rc.ExitCode != nil:
		return "b-halted"
	}
	return "b-stopped"
}

// OutcomeWord is the badge text.
func (v *receiptView) OutcomeWord() string {
	rc := v.R
	switch {
	case !rc.Ended && rc.Time.Note == "":
		return "Running"
	case !rc.Ended:
		return "No end recorded"
	case rc.ExitCode != nil && *rc.ExitCode == 0:
		return "Finished"
	case rc.ExitCode != nil:
		return "Failed"
	case rc.EndReason == "limit":
		return "Hit a limit"
	case rc.EndReason == "stopped":
		return "Stopped"
	}
	return "Ended"
}

// ruleBar is one rule's refusals, with its bar's length as a percentage of the largest rule's count.
type ruleBar struct {
	ledgerview.ReceiptRuleCount
	Pct int
}

// Rules is the refusals by rule, most first, each with its bar.
func (v *receiptView) Rules() []ruleBar {
	top := 0
	for _, r := range v.R.Refusals.ByRule {
		top = max(top, r.Count)
	}
	out := make([]ruleBar, 0, len(v.R.Refusals.ByRule))
	for _, r := range v.R.Refusals.ByRule {
		pct := 0
		if top > 0 {
			pct = max(r.Count*100/top, 2)
		}
		out = append(out, ruleBar{ReceiptRuleCount: r, Pct: pct})
	}
	return out
}

// sparkCol is one column of the refusals-over-time sparkline, in the SVG's own units (sparkW by sparkH).
type sparkCol struct {
	X, Y, W, H int
	N          int
	From, To   int // minutes from the start, To exclusive
	Label      string
}

// Spark is the refusals per minute regrouped into at most sparkCols columns, scaled to the busiest one.
func (v *receiptView) Spark() []sparkCol {
	c := v.R.OverTime.Counts
	if len(c) == 0 {
		return nil
	}
	per := (len(c) + sparkCols - 1) / sparkCols
	n := (len(c) + per - 1) / per
	sums := make([]int, n)
	peak := 0
	for i, x := range c {
		sums[i/per] += x
		peak = max(peak, sums[i/per])
	}
	w := sparkW / n
	out := make([]sparkCol, n)
	for i, s := range sums {
		h := 1 // a hairline for an empty minute, so the axis reads as time
		if s > 0 && peak > 0 {
			h = max(s*(sparkH-2)/peak, 3)
		}
		// A bar is at most sparkBar wide, centred in its slot, so a one-minute run draws a bar, not a red block.
		bw := min(max(w-2, 1), sparkBar)
		col := sparkCol{X: i*w + (w-bw)/2, Y: sparkH - h, W: bw, H: h, N: s, From: i * per, To: min((i+1)*per, len(c))}
		col.Label = "minute " + strconv.Itoa(col.From+1)
		if col.To-col.From > 1 {
			col.Label = "minutes " + strconv.Itoa(col.From+1) + " to " + strconv.Itoa(col.To)
		}
		out[i] = col
	}
	return out
}

// SparkBox is the sparkline's viewBox.
func (v *receiptView) SparkBox() string { return "0 0 300 40" }

// fileRow is one line of the files-written list.
type fileRow struct {
	Verb, Path, To string
}

// Files is the files-written list, renames last, at most receiptFilesShown rows.
func (v *receiptView) Files() []fileRow {
	f := v.R.Files
	var out []fileRow
	add := func(verb string, paths []string) {
		for _, p := range paths {
			out = append(out, fileRow{Verb: verb, Path: p})
		}
	}
	add("created", f.Created)
	add("wrote", f.Written)
	add("deleted", f.Deleted)
	for _, r := range f.Renamed {
		out = append(out, fileRow{Verb: "renamed", Path: r.From, To: r.To})
	}
	if len(out) > receiptFilesShown {
		out = out[:receiptFilesShown]
	}
	return out
}

// MoreFiles is how many file rows Files left out.
func (v *receiptView) MoreFiles() int {
	f := v.R.Files
	return max(len(f.Created)+len(f.Written)+len(f.Deleted)+len(f.Renamed)-receiptFilesShown, 0)
}

// Refused is the first refused actions, oldest first, at most receiptRefShown.
func (v *receiptView) Refused() []ledgerview.ReceiptRefusal {
	l := v.R.Refusals.List
	return l[:min(len(l), receiptRefShown)]
}

// MoreRefused is how many refused actions Refused left out.
func (v *receiptView) MoreRefused() int { return max(v.R.Refusals.Total-receiptRefShown, 0) }

// TokensText is TokensTotal with thousands separators ("60,420").
func (v *receiptView) TokensText() string { return thousands(v.TokensTotal()) }

func thousands(n uint64) string {
	s := strconv.FormatUint(n, 10)
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// TokensTotal is input plus output tokens, the quantity a token budget counts (measure R20).
func (v *receiptView) TokensTotal() uint64 {
	if t := v.R.Tokens.In + v.R.Tokens.Out; t >= v.R.Tokens.In {
		return t
	}
	return ^uint64(0) // saturate, as the ledger's sums do
}
