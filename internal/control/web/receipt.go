// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/pricetable"
	receiptspec "github.com/attention-span-ai/tego/pkg/spec/receipt"
)

// receiptView is the Receipt tab's data from the shared builder, or why it
// could not be read. The dashboard adds custom protected paths from the run's
// contract copy to sensitive-read activity. Recorded totals use the same builder
// as the terminal; these methods shape its tiles, bars and sparkline.
type receiptView struct {
	R   *ledgerview.Receipt
	Err string
	// Gap is readGap for the run: on a run that kept no file read it replaces the receipt's own reads note.
	Gap string
}

// loadReceipt is run id's receipt with its contract-sensitive activity for the Receipt tab, priced with the machine's
// price table as `tego receipt` prices it (receiptPricing).
func loadReceipt(ctx context.Context, root, id string, sensitive ledgerview.Sensitive, pricing ledgerview.Pricing) *receiptView {
	rc, err := ledgerview.LoadReceiptPriced(ctx, root, id, sensitive, pricing)
	if err != nil {
		return &receiptView{Err: err.Error()}
	}
	return &receiptView{R: rc}
}

// receiptPricing is what the Receipt tab prices a run's model responses with: the table the machine config names
// (pricetable.FromMachine, the one `tego receipt` and `tego measure` read), loaded when a response first needs a price,
// so a run with no metered response reads no table. The key is the table file's identity (pricetable.Identity: its
// device, inode, size and both times from one stat, and its content while those times are too recent to tell two writes
// apart), so a table the person replaces, even at once, even to the same size, even by a rename that reuses an inode,
// prices the next page view and no view after it is priced by the old one. A machine with no usable table prices
// nothing, and the receipt says so as it does in the terminal.
func (s *Server) receiptPricing() ledgerview.Pricing {
	m := s.cfg.Machine
	key := ""
	if m != nil && m.Prices.Value != "" {
		key = pricetable.Identity(m.Prices.Value)
	}
	return ledgerview.Pricing{Key: key, Prices: pricetable.NewLazy(func() pricetable.Coster {
		if t, _ := pricetable.FromMachine(m); t != nil {
			return t
		}
		return nil
	})}
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
// "" when the time is fixed (an ended run, or one measured to its last line). Each place the tab shows it (the line at
// the top, the tile, the chart's axis) marks such a time a clock (data-since, data-ck): live.js ticks it, and the
// region's hash leaves its text out, so the Receipt tab is not re-sent whenever the seconds change (regions.go).
// With only the tile marked, the other two still moved the hash every second (TestRegionRequest's race-job failures).
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

// GapWords is a coverage gap's line for the two gaps that link to the record's gap lines: the receipt's own sentence,
// the one `tego receipt` and `tego status` say (gaps.MissedWords, gaps.CaptureWords), with its first letter capitalised;
// "" for every other code, which shows its field and its words as the receipt gives them. The page has no sentence of
// its own (C175).
func (v *receiptView) GapWords(code, why string) string {
	if code != receiptspec.CodeMissedActions && code != receiptspec.CodeCaptureGap {
		return ""
	}
	return upperFirst(why)
}

// LevelWords is the one sentence for a coverage level (receiptspec.LevelWords), which the Coverage list shows as the
// chip's title.
func (v *receiptView) LevelWords(level string) string { return receiptspec.LevelWords(level) }

// GapText is the Logs search text a coverage note links to, beside kind=gap: what picks the gap lines the note is about.
// A note about model traffic tego could not read (tokens.capture) lists the lines that say so (what capture), not every
// other note about the record that a run with many gaps would bury them among; any other note keeps the run's every gap
// line (""). The text search reads a line as "<op> <target>" and a gap line's target begins with its what, so the line
// "gap capture no-openssl" is found by "gap capture ".
func (v *receiptView) GapText(field string) string {
	if field == "tokens.capture" {
		return "gap capture "
	}
	return ""
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

// ruleBar is one rule's refusals, with its bar's length as a percentage of the largest rule's count. Label, when set,
// names a built-in refusal the record files under the default deny (tego's refusal of setsockopt(TCP_ULP)).
type ruleBar struct {
	ledgerview.ReceiptRuleCount
	Label string
	Pct   int
}

// Rules is the refusals by rule, most first, each with its bar: the receipt's RefusalGroups, so a built-in TCP_ULP
// refusal has a bar of its own named as tego receipt and tego run's summary name it, and the counts still sum to the
// total.
func (v *receiptView) Rules() []ruleBar {
	gs := v.R.RefusalGroups()
	top := 0
	for _, g := range gs {
		top = max(top, g.Count)
	}
	out := make([]ruleBar, 0, len(gs))
	for _, g := range gs {
		pct := 0
		if top > 0 {
			pct = max(g.Count*100/top, 2)
		}
		bar := ruleBar{ReceiptRuleCount: ledgerview.ReceiptRuleCount{Rule: g.Rule, Reason: g.Reason, Count: g.Count}, Pct: pct}
		if g.BuiltIn {
			bar.Label = g.Kind
		}
		out = append(out, bar)
	}
	return out
}

// BuiltIn is a listed refusal's built-in kind ("built in: kernel TLS"), or "" when its rule names it.
func (v *receiptView) BuiltIn(r ledgerview.ReceiptRefusal) string { return v.R.BuiltInKind(r) }

// NoneOverTime is the refusals-over-time panel's words for a receipt with no refusal: tego receipt's, which say
// nothing of what was not recorded (the "Refused, by rule" panel says that, in RefusedWords).
func (v *receiptView) NoneOverTime() string { return ledgerview.ReceiptNoneOverTime }

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

// FileNumbers qualifies identity counts from the receipt's bounded file lists.
func (v *receiptView) FileNumbers() countScopes {
	n := countScopes{}
	if v.R != nil && v.R.Files.Truncated {
		n.Receipt = countScope{Lower: true, Reason: "The receipt's file lists reached their identity limit. Open the complete record in Logs."}
	}
	return n
}

// SensitiveNumbers qualifies the number of sensitive identities, whose list
// stops at the receipt builder's limit even though it reads the whole record.
func (v *receiptView) SensitiveNumbers() countScopes {
	n := countScopes{}
	if v.R != nil && v.R.SensitiveReadsUnknown {
		n.Receipt = countScope{Lower: true, Reason: "This run did not record every file read. Open the recorded events in Logs."}
	}
	if v.R != nil && v.R.SensitiveReadsTruncated {
		n.Receipt = countScope{Lower: true, Reason: "The receipt's sensitive-file list reached its identity limit. Open the complete record in Logs."}
	}
	return n
}

// ProgramNumbers qualifies the aggregate over the receipt's retained top programs.
func (v *receiptView) ProgramNumbers() countScopes {
	n := countScopes{}
	if v.R != nil && (v.R.ProgramsMore > 0 || v.R.ProgramsOverflowAttempts > 0) {
		n.Receipt = countScope{Lower: true, Reason: "The receipt lists only its most frequent programs. Open the complete record in Logs."}
	}
	return n
}

// TokenNumbers qualifies token and cost totals when some model traffic or
// response statistics were not captured in the complete receipt pass.
func (v *receiptView) TokenNumbers() countScopes {
	n := countScopes{}
	if v.R == nil {
		return n
	}
	if v.R.Tokens.Metered < v.R.Tokens.ModelCalls {
		n.Receipt = countScope{Lower: true, Reason: "Some model responses have no token counts. Open the complete record in Logs."}
	}
	for _, gap := range v.R.Coverage.Gaps {
		if gap.Field == "tokens.capture" {
			n.Receipt = countScope{Lower: true, Reason: "Model traffic capture missed some responses. Open the complete record in Logs."}
		}
	}
	return n
}

// CostNumbers also qualifies an estimated cost when a recorded model response
// has no matching price.
func (v *receiptView) CostNumbers() countScopes {
	n := v.TokenNumbers()
	if v.R != nil && v.R.Tokens.Unpriced > 0 {
		n.Receipt = countScope{Lower: true, Reason: "Some recorded model responses have no price. Open the complete record in Logs."}
	}
	return n
}

// NumberNotes lists each reason for a qualified receipt quantity once, for the quantities the Receipt shows: with no
// sensitive file listed its section already says what is not known, and with no model traffic there is no total.
func (v *receiptView) NumberNotes() []string {
	if v.R == nil {
		return nil
	}
	scopes := []countScopes{v.FileNumbers(), v.ProgramNumbers()}
	if len(v.R.SensitiveReads) > 0 {
		scopes = append(scopes, v.SensitiveNumbers())
	}
	if v.R.Tokens.Recorded {
		scopes = append(scopes, v.TokenNumbers(), v.CostNumbers())
	}
	var notes []string
	seen := map[string]bool{}
	for _, scope := range scopes {
		for _, note := range scope.Notes() {
			if !seen[note] {
				notes = append(notes, note)
				seen[note] = true
			}
		}
	}
	return notes
}
