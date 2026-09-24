// SPDX-License-Identifier: Apache-2.0

package measure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/check/internal/mirror"
	"github.com/attention-span-ai/tego/internal/check/resources"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Prices estimates what one model response cost. It is the one thing this view cannot derive from
// the ledger, and it is an interface rather than a concrete table so the read side never imports
// the engine (REPO-LAYOUT.md): internal/runtime/limits' *PriceTable satisfies it, and the CLI —
// which may import both — hands one over. A nil Prices prices nothing, which is a supported state.
type Prices interface {
	// Cost returns the estimated USD cost of one response's usage and whether it was priced: its model, and
	// every usage counter it reports (R2: 1-hour cache writes, server-tool requests).
	Cost(u ledger.TokenUsage) (float64, bool)
}

// Report is one run's P0 measurements (P0-DESIGN §2.12, R18-R23), recomputed from the ledger alone.
// It never shares state with a live limits.Watcher — the duplicated accumulation is deliberate
// (C1) and is what lets measure work on a still-growing or crashed-mid-record run.
type Report struct {
	// Run and Agent are the run's identity, from any line that carries them.
	Run, Agent string
	// Steps is the highest model step the record attributes or a decision carries (R18).
	Steps int
	// Refused is the number of action events the contract refused (R19); the mirroring refused-kind
	// event is never counted, so one refusal counts once.
	Refused int
	// TokensIn, TokensOut, CacheRead and CacheWrite are the summed ssl_response usage counters (R20).
	TokensIn, TokensOut, CacheRead, CacheWrite uint64
	// EstCostUSD is the summed per-response estimate; every surface renders it with "est." (R20).
	EstCostUSD float64
	// Unpriced is the number of responses no price table covered, so a $0.00 estimate can be told
	// from a genuinely free run (E15).
	Unpriced int
	// Responses is the number of ssl_response events carrying a usage object.
	Responses int
	// Wall is the last event's monotonic distance from run_start (R21).
	Wall time.Duration
	// IdleMax is the largest quiet span between consecutive events, gap windows excluded (R22).
	IdleMax time.Duration
	// Repeats is the longest consecutive same-(tool, input hash) streak anywhere in the run (R23).
	Repeats int
	// Alternates is how many held file opens a person answered with another file (tego alternate), counted from
	// the answer lines, which every record mode keeps (ADR 0057 D1). None is a refusal (the agent's open succeeded,
	// on the person's file) and none an approval (the agent did not get what it asked for), so neither Refused nor
	// any other count holds them.
	Alternates int
	// Events is how many lines the reader decoded, torn tail excluded.
	Events int
	// Ended reports whether the run has its run_end line; when false Wall is "so far".
	Ended bool
	// EndReason is run_end's reason, "" while the run has none.
	EndReason string
	// Live is true when Wall was measured against a caller-supplied clock reading rather than the
	// last recorded event (ComputeAt on a running run).
	Live bool
	// Resources is run_end's resources object (R-res), nil when the run has no run_end yet or its run_end
	// carries none. Each nil field inside it is a key the kernel did not give, unknown and never 0
	// (docs/VERSIONING.md §2). ResourcesRecorded is the same object as the ledger holds it, keys this binary
	// does not know included, for JSON; a string, so a Report stays comparable.
	Resources         *record.Resources
	ResourcesRecorded string
	// ExtraRunEnds is the number of run_end lines after the first, which a healthy writer never produces
	// (§6 case 5): the first by chain order is the run's end, as status reads it, and Anomalies names the rest.
	ExtraRunEnds int
}

// Anomalies are the ledger anomalies the report met (§6 case 5), one line each, for the warning a CLI prints
// and --json's ledger_anomalies. None for a healthy ledger.
func (rep *Report) Anomalies() []string {
	if rep.ExtraRunEnds == 0 {
		return nil
	}
	return []string{fmt.Sprintf("%d run_end lines; the first by chain order is the run's end and the other %d are ignored",
		rep.ExtraRunEnds+1, rep.ExtraRunEnds)}
}

// ctxEvery is how many lines ComputeAt reads between checks of its context.
const ctxEvery = 1024

// ComputeAt measures one run from its ledger (R18-R23). It streams: memory is the report itself,
// whatever the run's size (E10).
//
// p may be nil, in which case every cost is 0 and Unpriced counts the responses. A torn last line
// is ignored as the reader ignores it (E2); a malformed line anywhere else is a hard error naming
// the event it stopped at (E3).
//
// nowMonoNS is the caller's own monotonic clock reading, in nanoseconds on the same
// clock the ledger stamps (0: none). A run with no run_end then measures Wall against nowMonoNS instead of
// its last event (R21), which is what a live `tego measure` wants. A reading that is not plainly
// from this boot — zero, or earlier than the last event — is ignored rather than turned into a
// negative or absurd wall time (E7).
//
// ctx is checked every ctxEvery lines and its error returned as is: a ledger of millions of events takes
// seconds, and the first SIGINT only cancels the context (R29), so a loop that never looked at it ran on
// until a second signal.
func ComputeAt(ctx context.Context, r *ledger.Reader, p Prices, nowMonoNS uint64) (*Report, error) {
	if r == nil {
		return nil, fmt.Errorf("measure: no ledger reader")
	}
	rep := &Report{}
	var (
		startMono, lastMono uint64
		prevMono            uint64
		// the line before, for telling a refused line that mirrors its action from one written on its own
		prev                   mirror.Key
		prevWasGap             = true // no predecessor yet: the first event opens no idle window
		streakTool, streakHash string
		streak                 int
	)
	for e, err := range r.Iter() {
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(r.Dir(), ledger.EventsFile), err)
		}
		rep.Events++
		if rep.Events%ctxEvery == 0 && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if rep.Run == "" {
			rep.Run, rep.Agent = e.Run, e.Agent
		}
		if e.Kind == record.KindRunStart {
			startMono = e.MonoNS
		}
		if startMono == 0 && e.MonoNS > 0 {
			// A run whose run_start was lost still has an origin: its first surviving event.
			startMono = e.MonoNS
		}
		if e.MonoNS > lastMono {
			lastMono = e.MonoNS
		}

		// A window that touches a gap event is unknown, not idle. A window starts at the largest
		// reading so far, never at the line before's: a producer's line keeps its capture-time reading
		// (record-ledger.md §4 Append), so mono_ns can go back along seq, and measuring from the older
		// reading overstated idle by the capture latency. status takes its running maximum the same way.
		if !prevWasGap && e.Kind != record.KindGap && prevMono > 0 && e.MonoNS > prevMono {
			if d := time.Duration(e.MonoNS - prevMono); d > rep.IdleMax {
				rep.IdleMax = d
			}
		}
		prevMono, prevWasGap = max(prevMono, e.MonoNS), e.Kind == record.KindGap

		if e.Attr != nil && e.Attr.Step > rep.Steps {
			rep.Steps = e.Attr.Step // R18
		}
		if e.Kind.IsAction() && e.Verdict == record.VerdictRefused {
			rep.Refused++ // R19
		}
		// A refused line written on its own (keyring, mount family) is a refusal no action line counted; a
		// refused line directly after the refused action it mirrors is that action again (R19).
		if e.Kind == record.KindRefused && !prev.Mirrors(e) {
			rep.Refused++
		}
		prev = mirror.Of(e)

		switch e.Kind {
		case record.KindAnswer:
			var a record.AnswerAlternate
			if e.DecodePayload(&a) == nil && a.Alternate != "" {
				rep.Alternates++
			}
		case record.KindSSLResponse:
			rep.usage(e, p)
		case record.KindDecision:
			var d record.DecisionPayload
			if err := e.DecodePayload(&d); err != nil {
				break
			}
			if d.Step > rep.Steps {
				// The decision's own step is the model's turn counter; a turn with no tool call
				// leaves no action to attribute, so this is the only line that carries it (R18).
				rep.Steps = d.Step
			}
			if d.Tool == "" {
				break
			}
			if streak > 0 && d.Tool == streakTool && d.InputHash == streakHash {
				streak++
			} else {
				streakTool, streakHash, streak = d.Tool, d.InputHash, 1
			}
			if streak > rep.Repeats {
				rep.Repeats = streak // R23: the historical maximum, not the live streak
			}
		case record.KindRunEnd:
			if rep.Ended {
				rep.ExtraRunEnds++ // §6 case 5: the first run_end wins, as in status
				break
			}
			rep.Ended = true
			var end record.RunEndPayload
			if err := e.DecodePayload(&end); err == nil {
				rep.EndReason, rep.Resources = end.Reason, end.Resources
				rep.ResourcesRecorded = string(resources.Recorded(e))
			}
		}
	}

	end := lastMono
	if !rep.Ended && nowMonoNS > lastMono {
		end, rep.Live = nowMonoNS, true // R21
	}
	if startMono > 0 && end > startMono {
		rep.Wall = time.Duration(end - startMono)
	}
	return rep, nil
}

// usage applies R20 to one ssl_response: the same formula as the live watcher's R1/R2, recomputed
// here on purpose (C1) over the one decode both share, ledger.Usage (§4), so the two can never read
// a response differently (I5).
func (rep *Report) usage(e *record.Event, p Prices) {
	u, ok := ledger.Usage(e)
	if !ok {
		return
	}
	rep.Responses++
	rep.TokensIn = ledger.SatAdd(rep.TokensIn, u.In)
	rep.TokensOut = ledger.SatAdd(rep.TokensOut, u.Out)
	rep.CacheRead = ledger.SatAdd(rep.CacheRead, u.CacheRead)
	rep.CacheWrite = ledger.SatAdd(rep.CacheWrite, u.CacheWrite)
	if p == nil {
		rep.Unpriced++
		return
	}
	cost, priced := p.Cost(u)
	if !priced {
		rep.Unpriced++
		return
	}
	rep.EstCostUSD += cost
}

// Tokens is the quantity a token budget is measured against: input plus output, cache excluded,
// the same choice the live watcher makes (R1, R20).
func (rep *Report) Tokens() uint64 { return ledger.SatAdd(rep.TokensIn, rep.TokensOut) }

// Cost renders the estimate the way every surface must: the dollar amount (CostText) and the literal "est."
// suffix (GAPS.md C17). Responses no price table covered are named, so a $0.00 run is never mistaken for
// a free one.
func (rep *Report) Cost() string {
	s := CostText(rep.EstCostUSD) + " est."
	if rep.Unpriced > 0 {
		s += fmt.Sprintf(" (%d unpriced)", rep.Unpriced)
	}
	return s
}

// costDecimals is the most decimals CostText gives a small amount: a micro-dollar, the precision --json's
// est_cost_usd keeps (jsonCost).
const costDecimals = 6

// CostText renders a dollar amount for a person (R20): to the cent from ten cents up, where a fraction of a
// cent is noise, and with two significant digits below that, down to a micro-dollar, so a run that cost
// $0.002127 reads "$0.0021" and not "$0.00", which read as free beside a cost_usd limit event that said
// otherwise. Zero is "$0.00"; an amount above zero that rounds to no micro-dollar is "<$0.000001", never a
// zero; an amount that is not finite keeps fmt's spelling.
//
// The decimals come from the amount rounded to two significant digits by strconv itself ('e', precision 1),
// and the text is strconv's at that many decimals: both round the exact binary value at the same digit, so
// the digit count chosen and the digits printed cannot disagree. A separate math.Round(v*10^d) once chose
// decimals the formatting then rounded differently (5e-7 read "$0.000000", 0.00095 "$0.0009"), and stopped at
// the first d whose rounding carried to two digits (0.0096 read "$0.010", one digit, above the amount).
func CostText(v float64) string {
	if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
		return fmt.Sprintf("$%.2f", v)
	}
	d := 2
	if _, exp, ok := strings.Cut(strconv.FormatFloat(v, 'e', 1, 64), "e"); ok {
		if e, err := strconv.Atoi(exp); err == nil {
			d = min(max(1-e, 2), costDecimals) // the second significant digit sits at 10^(e-1)
		}
	}
	s := strconv.FormatFloat(v, 'f', d, 64)
	if strings.Trim(s, "0.") == "" { // above zero, yet not a micro-dollar survives the rounding
		return "<$" + strconv.FormatFloat(math.Pow10(-costDecimals), 'f', costDecimals, 64)
	}
	return "$" + s
}

// row is one line of the table view: a label and its value.
type row struct{ label, value string }

// rows is the report in the order Table prints it — the P0 column set of P0-DESIGN §2.12, then the run's
// resource peaks from run_end (R-res), each "unknown" where the run recorded none and "unknown until the run
// ends" while it has no run_end. The ask columns (asked, answered, wait, replanned) are not here: the
// receipt reports a run's asks. The one ask figure that is, alternates (ADR 0057 D1), is counted wherever a run held
// a file open for a person.
func (rep *Report) rows() []row {
	wall := rep.Wall.Round(time.Millisecond).String()
	if rep.Live {
		wall += " so far"
	} else if !rep.Ended {
		wall += " to the last event"
	}
	rows := []row{
		{"run", rep.Run},
		{"agent", rep.Agent},
		{"steps", strconv.Itoa(rep.Steps)},
		{"refused", strconv.Itoa(rep.Refused)},
		{"tokens in", strconv.FormatUint(rep.TokensIn, 10)},
		{"tokens out", strconv.FormatUint(rep.TokensOut, 10)},
		{"cache read", strconv.FormatUint(rep.CacheRead, 10)},
		{"cache write", strconv.FormatUint(rep.CacheWrite, 10)},
		// The label is "cost": the value carries the "est." every surface gives it (R2), and a label that
		// said it too printed "est. cost $0.00 est.".
		{"cost", rep.Cost()},
		{"wall", wall},
		{"idle max", rep.IdleMax.Round(time.Millisecond).String()},
		{"repeats", strconv.Itoa(rep.Repeats)},
		{"alternates", strconv.Itoa(rep.Alternates)},
	}
	for _, f := range resources.Fields(rep.Resources) {
		if !rep.Ended {
			f.Value = resources.Pending
		}
		rows = append(rows, row{f.Label, f.Value})
	}
	return rows
}

// Table writes the report as one aligned two-column table (R31). It is the human view; JSON is the
// one to parse.
func (rep *Report) Table(w io.Writer) error {
	rows := rep.rows()
	width := 0
	for _, r := range rows {
		if len(r.label) > width {
			width = len(r.label)
		}
	}
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r.label)
		b.WriteString(strings.Repeat(" ", width-len(r.label)+2))
		// Every value may carry ledger text (the run and agent are not validated on read): escaped, as
		// events, drift and status print theirs.
		b.WriteString(record.Printable(r.value))
		b.WriteByte('\n')
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// jsonReport is the stable wire shape of `measure --json` (R31, E22): one object on one line, the
// same keys in the same order every time, durations as both a number of nanoseconds and the string
// a human reads.
type jsonReport struct {
	Run        string  `json:"run"`
	Agent      string  `json:"agent"`
	Steps      int     `json:"steps"`
	Refused    int     `json:"refused"`
	TokensIn   uint64  `json:"tokens_in"`
	TokensOut  uint64  `json:"tokens_out"`
	CacheRead  uint64  `json:"cache_read"`
	CacheWrite uint64  `json:"cache_write"`
	EstCostUSD float64 `json:"est_cost_usd"`
	CostLabel  string  `json:"est_cost"`
	Unpriced   int     `json:"unpriced_responses"`
	Responses  int     `json:"responses"`
	Wall       string  `json:"wall"`
	WallNS     int64   `json:"wall_ns"`
	IdleMax    string  `json:"idle_max"`
	IdleMaxNS  int64   `json:"idle_max_ns"`
	Repeats    int     `json:"repeats"`
	Alternates int     `json:"alternates"`
	Events     int     `json:"events"`
	Ended      bool    `json:"ended"`
	EndReason  string  `json:"end_reason"`
	Live       bool    `json:"live"`
	// Resources is run_end.resources as recorded, keys this binary does not know included, a key absent
	// wherever the record lacks it, and the whole object absent when run_end carried none or the run has not
	// ended: the JSON view says "unknown" the way the record does, by leaving the key out, where the table
	// says it in words (R-res).
	Resources json.RawMessage `json:"resources,omitempty"`
	// LedgerAnomalies is Report.Anomalies, absent for a healthy ledger (§6 case 5).
	LedgerAnomalies []string `json:"ledger_anomalies,omitempty"`
}

// JSON writes the report as one JSON object on one line (R31).
func (rep *Report) JSON(w io.Writer) error {
	out := jsonReport{
		Run: rep.Run, Agent: rep.Agent, Steps: rep.Steps, Refused: rep.Refused,
		TokensIn: rep.TokensIn, TokensOut: rep.TokensOut,
		CacheRead: rep.CacheRead, CacheWrite: rep.CacheWrite,
		// The estimate is rounded to a millionth of a dollar: binary floating point would otherwise
		// print a sum of per-response costs as 0.27788399999999996, which no reader wants and which
		// says nothing true beyond the cent the label carries.
		EstCostUSD: jsonCost(rep.EstCostUSD), CostLabel: rep.Cost(), Unpriced: rep.Unpriced,
		Responses: rep.Responses,
		Wall:      rep.Wall.Round(time.Millisecond).String(), WallNS: rep.Wall.Nanoseconds(),
		IdleMax: rep.IdleMax.Round(time.Millisecond).String(), IdleMaxNS: rep.IdleMax.Nanoseconds(),
		Repeats: rep.Repeats, Alternates: rep.Alternates, Events: rep.Events, Ended: rep.Ended, EndReason: rep.EndReason,
		Live: rep.Live, Resources: json.RawMessage(rep.ResourcesRecorded),
		LedgerAnomalies: rep.Anomalies(),
	}
	b, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("measure: encode report: %w", err)
	}
	if _, err := w.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("measure: write report: %w", err)
	}
	return nil
}

// jsonCost keeps overflowed estimates representable, as the live limit event does. Large finite values
// already have coarser precision than a millionth: multiplying them before rounding could overflow.
func jsonCost(cost float64) float64 {
	if math.IsInf(cost, 1) {
		return math.MaxFloat64
	}
	if cost > math.MaxFloat64/1e6 {
		return cost
	}
	return math.Round(cost*1e6) / 1e6
}
