// SPDX-License-Identifier: Apache-2.0

package events

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"math"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Filter selects which events a view shows. A zero Filter selects everything. Every field is a conjunct:
// an event must satisfy all of the set ones. Within a field the values are alternatives.
type Filter struct {
	Kinds    []record.Kind    // event kinds to keep
	Sources  []record.Source  // producers to keep
	Verdicts []record.Verdict // allow, ask, refused, observed
	Rules    []string         // the declared entry an action matched, or "unmatched"
	Steps    []int            // model steps, as attributed
	Since    time.Time        // wall-clock lower bound, inclusive
	Until    time.Time        // wall-clock upper bound, exclusive
	Limit    int              // at most this many events; 0 is no limit
}

// Match reports whether e passes the filter. It ignores Limit, which is a property of the stream.
func (f Filter) Match(e *record.Event) bool {
	if len(f.Kinds) > 0 && !slices.Contains(f.Kinds, e.Kind) {
		return false
	}
	if len(f.Sources) > 0 && !slices.Contains(f.Sources, e.Source) {
		return false
	}
	if len(f.Verdicts) > 0 && !slices.Contains(f.Verdicts, effectiveVerdict(e)) {
		return false
	}
	if len(f.Rules) > 0 && !slices.Contains(f.Rules, e.Rule) {
		return false
	}
	if len(f.Steps) > 0 {
		step := -1
		if e.Attr != nil {
			step = e.Attr.Step
		}
		if !slices.Contains(f.Steps, step) {
			return false
		}
	}
	if !f.Since.IsZero() && e.TS.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && !e.TS.Before(f.Until) {
		return false
	}
	return true
}

// effectiveVerdict is the verdict --verdict tests. A refused line is the refusal itself and carries no
// verdict field (the schema forbids one on a non-action line), so it counts as refused: `--last --verdict
// refused` would otherwise be empty, and the standalone refusals (socket family, keyring, signal, topology,
// procscope) would be missed, which drift and measure both count.
func effectiveVerdict(e *record.Event) record.Verdict {
	if e.Kind == record.KindRefused {
		return record.VerdictRefused
	}
	return e.Verdict
}

// ParseFilter builds a Filter from the CLI's repeatable --kind, --source, --verdict, --rule and --step
// values. An unknown kind, source or verdict is an error naming the accepted set, because a typo that
// silently matched nothing would read as "the run did not do that".
func ParseFilter(kinds, sources, verdicts, rules, steps []string, limit int) (Filter, error) {
	f := Filter{Rules: rules, Limit: limit}
	for _, s := range kinds {
		k := record.Kind(s)
		if !k.Valid() {
			return Filter{}, fmt.Errorf("unknown event kind %q: one of %s", s, joinKinds(record.Kinds))
		}
		f.Kinds = append(f.Kinds, k)
	}
	for _, s := range sources {
		src := record.Source(s)
		if !src.Valid() {
			return Filter{}, fmt.Errorf("unknown source %q: one of %s", s, joinSources(record.Sources))
		}
		f.Sources = append(f.Sources, src)
	}
	for _, s := range verdicts {
		v := record.Verdict(s)
		if !v.Valid() {
			return Filter{}, fmt.Errorf("unknown verdict %q: one of allow, ask, refused, observed", s)
		}
		f.Verdicts = append(f.Verdicts, v)
	}
	for _, s := range steps {
		n, err := strconv.Atoi(s)
		if err != nil {
			return Filter{}, fmt.Errorf("step %q is not a number", s)
		}
		f.Steps = append(f.Steps, n)
	}
	return f, nil
}

func joinKinds(ks []record.Kind) string {
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i] = string(k)
	}
	return strings.Join(out, ", ")
}

func joinSources(ss []record.Source) string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = string(s)
	}
	return strings.Join(out, ", ")
}

// JSONOf writes the matching events among entries, which r read (r.Entries() for the whole run, or the one
// entry a caller found, e.g. by ledger.Reader.Backward), as the ledger stored them, one line each, byte for
// byte; r names the file in an error. The bytes are what the chain hashed, so a caller can verify a line it
// copied out of this output; re-encoding the decoded event could differ from the stored line and would break
// that.
//
// A line that does not decode is E3's torn middle line: iteration stops and the error names the file and
// the line's position in it, the `<path>: corrupt ledger at line N` form §7 owes the operator.
func JSONOf(ctx context.Context, w io.Writer, r *ledger.Reader, entries iter.Seq2[ledger.Entry, error], f Filter) (int, error) {
	bw := bufio.NewWriter(w)
	n, err := writeJSON(ctx, bw, r.Dir(), entries, f)
	// Flush what was rendered even when iteration failed, as TableOf does.
	if ferr := bw.Flush(); err == nil {
		err = ferr
	}
	return n, err
}

// writeJSON is JSONOf's loop: one buffered write per line, so a pipe sees full blocks, not a syscall per event.
func writeJSON(ctx context.Context, bw *bufio.Writer, dir string, entries iter.Seq2[ledger.Entry, error], f Filter) (int, error) {
	n, read := 0, 0
	for en, err := range entries {
		if err != nil {
			return n, atPath(dir, err)
		}
		if read++; read%ctxEvery == 0 && ctx.Err() != nil {
			return n, ctx.Err()
		}
		// Entries decodes each line with record.Decode, as the table's reader does, not a bare Unmarshal: the
		// version gate, the kind and the field checks are what make a line the ledger's. A newer version's line
		// is skipped and counted when the caller asked for that (ledger.Reader.SkipNewerVersions), for the table
		// and --json alike; any other line that does not decode stops here with its position in events.jsonl.
		line, e := en.Line, en.Event
		if !f.Match(e) {
			continue
		}
		if _, werr := bw.Write(line); werr != nil {
			return n, werr
		}
		if werr := bw.WriteByte('\n'); werr != nil {
			return n, werr
		}
		n++
		if f.Limit > 0 && n >= f.Limit {
			return n, nil
		}
	}
	return n, nil
}

// ctxEvery is how many lines JSONOf and TableOf read between checks of their context: a ledger of millions of
// events takes seconds per pass, and the first SIGINT only cancels the context (R29), so a loop that never
// looked at it ran on until a second signal.
const ctxEvery = 1024

// atPath names the run's events.jsonl in err. §7 specifies every check command's corrupt-ledger message as
// `<path>: corrupt ledger at line N`; the reader reports the position, only the caller knows the file. An
// error that is not about the file's bytes is returned as it is: a Follower's ErrRunLost and ErrCursorMismatch
// name the run directory themselves (§7 gives their text), and a context's end is no read of the file.
func atPath(dir string, err error) error {
	if errors.Is(err, ledger.ErrRunLost) || errors.Is(err, ledger.ErrCursorMismatch) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return fmt.Errorf("%s: %w", filepath.Join(dir, ledger.EventsFile), err)
}

// widthSample is how many matched rows TableOf measures the column widths over before it starts writing.
// The read side must stream in memory that does not grow with the ledger (E10), and `tego events <run>`
// carries no --limit by default, so a run of millions of events would otherwise be buffered whole; a
// thousand rows is enough for kind, source and verdict (closed sets) and rule (the contract's own names)
// to have settled, and caps what the command retains at a few hundred kilobytes.
const widthSample = 1024

// TableOf writes the matching events among entries, which r read, as aligned columns: seq, time (in the reader's
// zone, named in the header), kind, source, verdict, rule and a kind-specific summary; r names the file in an error. It is the human view;
// JSONOf is the one to parse.
//
// Widths are measured over the first widthSample matching rows and then fixed, and every row after that is
// written as it is read (E10): a later row whose cell is wider than its column overhangs it, keeping the
// two-space separator, which is the price of never holding the whole run in memory.
func TableOf(ctx context.Context, w io.Writer, r *ledger.Reader, entries iter.Seq2[ledger.Entry, error], f Filter) (int, error) {
	bw := bufio.NewWriter(w)
	n, err := writeTable(ctx, newTable(bw), r.Dir(), entries, f)
	// Flush what was rendered even when iteration failed: the rows before a corrupt line were correct, and
	// §7 asks for the position of the bad line, not for the good output to be thrown away.
	if ferr := bw.Flush(); err == nil {
		err = ferr
	}
	return n, err
}

// table is TableOf's state: it holds rows back only until the widths are settled, then streams.
type table struct {
	w         *bufio.Writer
	head      [7]string
	loc       *time.Location
	zone      string // the zone the header names
	width     [7]int
	held      [][7]string
	streaming bool
}

// tableHead is the table's header row; the TIME column is named with its zone (tableClock).
var tableHead = [7]string{"SEQ", "TIME", "KIND", "SOURCE", "VERDICT", "RULE", "DETAIL"}

// tableClock is the zone the table prints times in: the reader's own, as the dashboard shows them, so a time read
// off `tego events` next to the dashboard is the same time. The ledger keeps UTC, and JSONOf prints it as
// recorded. Tests set it.
var tableClock = func() *time.Location { return time.Local }

func newTable(w *bufio.Writer) *table {
	t := &table{w: w, head: tableHead, loc: tableClock(), held: make([][7]string, 0, 64)}
	for i, h := range t.head {
		t.width[i] = utf8.RuneCountInString(h)
	}
	zone, _ := time.Now().In(t.loc).Zone()
	t.nameZone(zone)
	return t
}

// nameZone makes zone the one the header names.
func (t *table) nameZone(zone string) {
	t.zone = zone
	t.head[1] = "TIME (" + zone + ")"
	t.width[1] = utf8.RuneCountInString(t.head[1])
}

// clock is the time cell of an event stamped ts. A zone's name belongs to an instant, not to a place: a run from the
// week before a daylight-saving change is printed in EDT whatever the clock on the wall says now, and the header
// named today's EST over it, an hour off every row. So the first row names the column; a later row on the other side
// of a change says its own zone, since a run can cross one and a table this long streams past its header.
func (t *table) clock(ts time.Time) string {
	local := ts.In(t.loc)
	zone, _ := local.Zone()
	if zone != t.zone && !t.streaming && len(t.held) == 0 {
		t.nameZone(zone)
	}
	cell := local.Format("15:04:05.000")
	if zone != t.zone {
		cell += " " + zone
	}
	return cell
}

// settle writes the header and the held rows with the widths measured so far; after it the table streams. It is
// a no-op once the table streams.
func (t *table) settle() error {
	if t.streaming {
		return nil
	}
	if err := writeRow(t.w, t.head, t.width); err != nil {
		return err
	}
	for _, row := range t.held {
		if err := writeRow(t.w, row, t.width); err != nil {
			return err
		}
	}
	t.held, t.streaming = nil, true
	return nil
}

// add writes row once the table streams, and until then holds it and widens the columns to it, settling at
// widthSample rows.
func (t *table) add(row [7]string) error {
	if t.streaming {
		return writeRow(t.w, row, t.width)
	}
	for i, c := range row {
		if utf8.RuneCountInString(c) > t.width[i] {
			t.width[i] = utf8.RuneCountInString(c)
		}
	}
	t.held = append(t.held, row)
	if len(t.held) == widthSample {
		return t.settle()
	}
	return nil
}

// writeTable is TableOf's loop over entries, which dir's ledger holds.
func writeTable(ctx context.Context, t *table, dir string, entries iter.Seq2[ledger.Entry, error], f Filter) (int, error) {
	// fail writes the header and the rows still held before an iteration error is returned, so the rows before
	// a corrupt line are kept even in a ledger shorter than the sample.
	fail := func(cause error) error {
		if err := t.settle(); err != nil {
			return err
		}
		return cause
	}
	n, read := 0, 0
	for en, err := range entries {
		if err != nil {
			return n, fail(atPath(dir, err))
		}
		e := en.Event
		if read++; read%ctxEvery == 0 && ctx.Err() != nil {
			return n, fail(ctx.Err())
		}
		if !f.Match(e) {
			continue
		}
		// Every cell is escaped for the terminal (record.Printable): the ledger holds text the agent chose,
		// and a control byte in a path or an argv moved the cursor, erased the row above or forged a row.
		row := [7]string{
			strconv.FormatUint(e.Seq, 10),
			t.clock(e.TS),
			record.Printable(string(e.Kind)),
			record.Printable(string(e.Source)),
			record.Printable(verdictCell(e)),
			record.Printable(ruleCell(e)),
			record.Printable(Summary(e)),
		}
		n++
		if err := t.add(row); err != nil {
			return n, err
		}
		if f.Limit > 0 && n >= f.Limit {
			break
		}
	}
	// A run shorter than the sample: widths are exact, nothing has been written yet.
	return n, t.settle()
}

// FollowJSON writes each line fl delivers that f matches, byte for byte as JSONOf writes it, and flushes each
// time fl has delivered every line there is, so a reader of w sees a line as soon as the ledger holds it. It
// returns when the follow ends (ledger.Follower.Lines: run_end with the lock free, a break in the chain, a lost
// run, ctx) or f's limit is reached.
func FollowJSON(ctx context.Context, w io.Writer, fl *ledger.Follower, f Filter) (int, error) {
	bw := bufio.NewWriter(w)
	fl.OnIdle(bw.Flush)
	n, err := writeJSON(ctx, bw, fl.Dir(), followed(ctx, fl), f)
	if ferr := bw.Flush(); err == nil {
		err = ferr
	}
	return n, err
}

// FollowTable is TableOf over what fl delivers: the rows events prints, with the columns measured over the lines
// the ledger held when the follow caught up (at most widthSample of them), then streamed and flushed each time fl
// has delivered every line there is.
func FollowTable(ctx context.Context, w io.Writer, fl *ledger.Follower, f Filter) (int, error) {
	bw := bufio.NewWriter(w)
	t := newTable(bw)
	fl.OnIdle(func() error {
		if err := t.settle(); err != nil {
			return err
		}
		return bw.Flush()
	})
	n, err := writeTable(ctx, t, fl.Dir(), followed(ctx, fl), f)
	if ferr := bw.Flush(); err == nil {
		err = ferr
	}
	return n, err
}

// followed is fl's lines as the entries the renderers read.
func followed(ctx context.Context, fl *ledger.Follower) iter.Seq2[ledger.Entry, error] {
	return func(yield func(ledger.Entry, error) bool) {
		for en, err := range fl.Lines(ctx) {
			if !yield(en.Entry, err) || err != nil {
				return
			}
		}
	}
}

func writeRow(w *bufio.Writer, row [7]string, width [7]int) error {
	for i, c := range row {
		if _, err := w.WriteString(c); err != nil {
			return err
		}
		if i == len(row)-1 { // the last column is never padded
			break
		}
		// A cell wider than its measured column — one that arrived after widthSample rows — keeps the
		// separator instead of a negative pad: the row overhangs, it never runs two columns together.
		if err := writePad(w, max(width[i]-utf8.RuneCountInString(c), 0)+2); err != nil {
			return err
		}
	}
	return w.WriteByte('\n')
}

// blanks is one pad's worth of spaces, sliced rather than allocated: writePad runs six times per row and a
// streamed table is as long as the run (E10).
const blanks = "                                                                "

func writePad(w *bufio.Writer, n int) error {
	for n > len(blanks) {
		if _, err := w.WriteString(blanks); err != nil {
			return err
		}
		n -= len(blanks)
	}
	_, err := w.WriteString(blanks[:n])
	return err
}

func verdictCell(e *record.Event) string {
	switch {
	case e.Verdict != "" && e.Reason != "":
		return string(e.Verdict) + ":" + string(e.Reason)
	case e.Verdict != "":
		return string(e.Verdict)
	case e.Reason != "":
		// A refused event carries its reason in the common field and no verdict of its own; showing the
		// reason here is what makes the row say why the run was stopped from doing something.
		return string(e.Reason)
	}
	return "-"
}

func ruleCell(e *record.Event) string {
	if e.Rule == "" {
		return "-"
	}
	return e.Rule
}

// Summary renders the one-line, kind-specific detail of an event: the path an fs event touched, the
// destination a net event reached, the argv an exec ran. It reads the payload leniently, because a newer
// writer may add fields and a view must not fail on them.
func Summary(e *record.Event) string {
	p := map[string]any{}
	if json.Valid(e.Payload) {
		decoder := json.NewDecoder(bytes.NewReader(e.Payload))
		decoder.UseNumber()
		_ = decoder.Decode(&p)
	}
	str := func(k string) string {
		s, _ := p[k].(string)
		return s
	}
	num := func(k string) string {
		return numberText(p[k])
	}
	switch e.Kind {
	case record.KindRunStart:
		s := "tier=" + str("tier") + " capture=" + str("capture") + " " + str("kernel")
		// The command-line command's grant is not in the contract hash, so the run's first line says it
		// (agent-contract.md R8).
		if g := str("run_command_grant"); g != "" {
			s += " run_command_grant=" + g
		}
		// The gate cells decided on copied syscall facts, never counted as enforced (ADR 0041 D7).
		if cells, _ := p["best_effort"].([]any); len(cells) != 0 {
			names := make([]string, 0, len(cells))
			for _, c := range cells {
				if n, ok := c.(string); ok {
					names = append(names, n)
				}
			}
			s += " best_effort=" + strings.Join(names, ",")
		}
		return s
	case record.KindRunEnd:
		s := "reason=" + str("reason")
		if c := num("exit_code"); c != "" {
			s += " exit=" + c
		}
		return s
	case record.KindExec:
		// argv is a JSON array: read as a string it was always "", and the summary never showed what an exec
		// ran, only the binary.
		s := str("path")
		if argv, ok := p["argv"].([]any); ok && len(argv) > 0 {
			parts := make([]string, 0, len(argv))
			for _, a := range argv {
				s, _ := a.(string)
				parts = append(parts, s)
			}
			s = strings.Join(parts, " ")
		}
		// ADR 0048 (8): an exec a command rule decided names the entry, how it matched and how it was read.
		if rule := str("command_rule"); rule != "" {
			s += " command=" + str("command_list") + ":" + rule
			if m := str("command_match"); m == "ambiguous" {
				s += " (ambiguous)"
			}
			if via := str("command_via"); via != "" && via != "name" {
				s += " via=" + via
			}
		}
		return s
	case record.KindFS:
		s := str("op")
		if s != "" {
			s += " "
		}
		s += str("path")
		if c := num("count"); c != "" && c != "0" {
			s += " x" + c
		}
		// An open a person answered with an alternate names the file delivered and the one it stands for.
		if a := str("alternate_for"); a != "" {
			s += " (alternate for " + a + ")"
		}
		return s
	case record.KindNet:
		s := str("proto") + " " + str("dst")
		if h := str("host"); h != "" {
			s += " (" + h + ")"
		}
		return s
	case record.KindSSLRequest:
		return str("method") + " " + str("host") + str("path")
	case record.KindSSLResponse:
		s := str("model")
		if st := num("status"); st != "" {
			s = st + " " + s
		}
		return strings.TrimSpace(s + " " + usageCell(p))
	case record.KindDecision:
		if t := str("tool"); t != "" {
			return "tool " + t
		}
		return str("why")
	case record.KindGap:
		return str("what") + ": " + str("why")
	case record.KindLimit:
		return str("which") + "=" + num("value") + " ceiling=" + num("ceiling")
	case record.KindRefused:
		// The refusal's target, when the writer recorded one; the reason is already in the verdict column.
		return strings.TrimSpace(str("op") + " " + firstNonEmpty(str("target"), str("path"), str("dst")))
	case record.KindMCP:
		s := strings.TrimSpace(firstNonEmpty(str("server"), str("name")) + " " + str("transport"))
		if tool := str("tool"); tool != "" { // a tools/call (capture-derive.md R41)
			s += " call " + tool
		}
		return s
	case record.KindAsk:
		hold := str("hold")
		if str("op") == "read" { // a held read under fs.ask_read: its hold is the open, its op says it reads
			hold += " read"
		}
		return strings.TrimSpace(hold + " " + firstNonEmpty(str("target"), str("path"), str("dst")))
	case record.KindAnswer:
		// What the answer was, then who gave it (ADR 0057 D1): an answer line has no verdict column of its own, and an
		// alternate is not an approval of what was asked, so it says so. A line older than the approved key (minor 5)
		// says only who answered.
		s := ""
		switch approved, known := p["approved"].(bool); {
		case str("alternate") != "":
			s = "alternate " + str("alternate") + " (not the file asked for)"
		case known && approved:
			s = "approved"
		case str("answer_reason") != "":
			s = "refused " + str("answer_reason")
		case known:
			s = "not approved"
		}
		if by := str("by"); by != "" {
			s += " by " + by
		}
		if a := num("after_s"); a != "" {
			s += " after " + a + "s"
		}
		return strings.TrimSpace(s)
	case record.KindBoundary:
		return strings.TrimSpace(str("dst") + " " + str("propagated"))
	}
	return ""
}

func usageCell(p map[string]any) string {
	u, ok := p["usage"].(map[string]any)
	if !ok {
		return ""
	}
	in, out := numberText(u["input"]), numberText(u["output"])
	if in == "" {
		in = "0"
	}
	if out == "" {
		out = "0"
	}
	if in == "0" && out == "0" {
		return ""
	}
	return "in=" + in + " out=" + out
}

// numberText preserves integral JSON values exactly, including uint64 counters larger than 2^53.
// Fractional and exponential values keep their human-readable decimal rendering.
func numberText(v any) string {
	switch n := v.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return strconv.FormatInt(i, 10)
		}
		if !strings.ContainsAny(n.String(), ".eE") {
			return n.String()
		}
		if f, err := n.Float64(); err == nil {
			return countText(f)
		}
		return n.String()
	case float64:
		return countText(n)
	}
	return ""
}

// countText prints a token count without wrapping: a value at or past 2^63 (a hostile endpoint's
// saturated count) or a fractional one is not converted through int64.
func countText(f float64) string {
	if f != math.Trunc(f) || f >= 1<<63 || f < -(1<<63) {
		return strconv.FormatFloat(f, 'f', -1, 64)
	}
	return strconv.FormatInt(int64(f), 10)
}

// firstNonEmpty returns the first value that is not the empty string.
func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
