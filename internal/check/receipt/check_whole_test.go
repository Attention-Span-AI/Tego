// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/measure"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// failedTable prices nothing, as `tego receipt` does when its machine's price table did not load: every metered
// response is unpriced, yet the reader had a table to ask.
type failedTable struct{}

func (failedTable) Cost(ledger.TokenUsage) (float64, bool) { return 0, false }

// pricedRun is an ended run with two metered model responses, one of a model flatPrices does not price, and a refusal.
func pricedRun() []line {
	req := line{kind: record.KindSSLRequest, payload: record.SSLRequestPayload{Endpoint: "messages", Method: "POST", Host: "h"}}
	resp := func(at time.Duration, seq int, model string) line {
		return line{kind: record.KindSSLResponse, at: at, payload: map[string]any{"request_seq": seq, "status": 200,
			"parser_version": "1", "model": model, "latency_ms": 1, "usage": map[string]int{"input": 500, "output": 10}}}
	}
	return []line{start("forwarder", true), req, resp(time.Second, 1, "m"), req, resp(2*time.Second, 3, "unpriced"),
		{kind: record.KindFS, at: 3 * time.Second, verdict: record.VerdictRefused, rule: "fs.write[./out/]",
			reason: record.ReasonWriteOutsideContract, payload: record.FSPayload{Op: record.FSOpen, Path: "/home/u/.bashrc", Flags: 0o1101}},
		end(4*time.Second, 0)}
}

// noTableRun is an ended run whose launcher had no usable price table and whose one model response carried no token
// counts: a reader with no table writes the no-price-table gap, one with a table writes none.
func noTableRun() []line {
	return []line{start("forwarder", true),
		{kind: record.KindGap, at: time.Second, payload: record.GapPayload{What: record.GapRecord, Why: gapNoPriceTable}},
		{kind: record.KindSSLRequest, at: time.Second, payload: record.SSLRequestPayload{Endpoint: "messages", Method: "POST", Host: "h"}},
		{kind: record.KindSSLResponse, at: 2 * time.Second, payload: map[string]any{"request_seq": 2, "status": 200,
			"parser_version": "1", "model": "m", "latency_ms": 1}},
		end(3*time.Second, 0)}
}

// receiptPriced is the record in dir's bound receipt as `tego receipt --json` makes it with prices (nil: none) and
// the clock reading now (0: none).
func receiptPriced(t *testing.T, dir string, prices measure.Prices, now uint64) string {
	t.Helper()
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	r.SkipNewerVersions()
	by := testBy
	rc, err := Compute(context.Background(), r, Options{Bind: &by, Prices: prices, Home: "/home/u", NowMonoNS: now})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := rc.JSON(&buf); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// resultJSON is the check's --json output, decoded.
func resultJSON(t *testing.T, res *CheckResult) map[string]any {
	t.Helper()
	var b bytes.Buffer
	if err := res.JSON(&b); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// notCompared is the check's --json not_compared, as strings; ok is false when the key is missing or not a list.
func notCompared(t *testing.T, res *CheckResult) (list []string, ok bool) {
	t.Helper()
	raw, ok := resultJSON(t, res)["not_compared"].([]any)
	if !ok {
		return nil, false
	}
	for _, v := range raw {
		s, _ := v.(string)
		list = append(list, s)
	}
	return list, true
}

// wantFactsFail is a mismatch whose failed check is facts (or receipt, for a file the strict read refuses).
func wantFactsFail(t *testing.T, res *CheckResult, what string) {
	t.Helper()
	if res.Result != CheckMismatch || res.ExitCode() != identity.ExitFinding {
		var b bytes.Buffer
		_ = res.Text(&b)
		t.Errorf("%s: result %s exit %d, want mismatch exit 1\n%s", what, res.Result, res.ExitCode(), b.String())
		return
	}
	if s := step(res, "facts"); s.Result != StepFail {
		t.Errorf("%s: facts %+v, want fail", what, s)
	}
}

// lastMono is the largest mono_ns of the record in dir.
func lastMono(t *testing.T, dir string) uint64 {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var last uint64
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 4<<20)
	for sc.Scan() {
		var l struct {
			Mono uint64 `json:"mono_ns"`
		}
		if json.Unmarshal(sc.Bytes(), &l) == nil && l.Mono > last {
			last = l.Mono
		}
	}
	return last
}

// cutBeforeRunEnd keeps the record in dir up to its run_end line, as a run that lost its end leaves it.
func cutBeforeRunEnd(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, ledger.EventsFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(data, []byte(`"kind":"run_end"`))
	if i < 0 {
		t.Fatal("no run_end line")
	}
	j := bytes.LastIndexByte(data[:i], '\n')
	if err := os.WriteFile(path, data[:j+1], 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestCheckMatchesEveryFixtureHoweverPriced is the happy path the whole compare must keep: every record v1 fixture the
// real Writer wrote, its receipt made as `tego receipt --json` makes it with a price table, with a table that did not
// load and with none, matches; and the same record cut before its run_end matches as match-unended, with its receipt
// made with no clock and at a clock reading 17 minutes past its last line.
func TestCheckMatchesEveryFixtureHoweverPriced(t *testing.T) {
	names, err := filepath.Glob(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "*.jsonl"))
	if err != nil || len(names) < 10 {
		t.Fatalf("fixtures %v %v", names, err)
	}
	tables := []struct {
		name   string
		prices measure.Prices
	}{{"table", flatPrices{}}, {"failed-table", failedTable{}}, {"no-table", nil}}
	for _, path := range names {
		name := filepath.Base(path)
		for _, tb := range tables {
			t.Run(name+"/"+tb.name, func(t *testing.T) {
				p := fixturePair(t, name)
				p.receipt = receiptPriced(t, p.dir, tb.prices, 0)
				wantResult(t, checked(t, p, testBy), CheckMatch, identity.ExitOK)

				cutBeforeRunEnd(t, p.dir)
				p.receipt = receiptPriced(t, p.dir, tb.prices, 0)
				wantResult(t, checked(t, p, testBy), CheckMatchUnended, identity.ExitOK)

				p.receipt = receiptPriced(t, p.dir, tb.prices, lastMono(t, p.dir)+uint64(17*time.Minute)+123)
				res := checked(t, p, testBy)
				wantResult(t, res, CheckMatchUnended, identity.ExitOK)
				if nc, _ := notCompared(t, res); !slices.Contains(nc, "time_taken.seconds") {
					t.Errorf("a live receipt's clock reading is not named as taken: %v", nc)
				}
			})
		}
	}
}

// TestCheckComparesCompleteAsABool (round 2 M1): coverage.complete is compared exactly, a JSON bool against the
// record's: a string, a number, null or no key at all is a mismatch, on a receipt with gaps and on one with none.
func TestCheckComparesCompleteAsABool(t *testing.T) {
	complete := []line{start("forwarder", true),
		{kind: record.KindSSLRequest, payload: record.SSLRequestPayload{Endpoint: "messages", Method: "POST", Host: "h"}},
		{kind: record.KindSSLResponse, at: time.Second, payload: map[string]any{"request_seq": 1, "status": 200,
			"parser_version": "1", "model": "m", "latency_ms": 1, "usage": map[string]int{"input": 500, "output": 10}}},
		end(2*time.Second, 0)}
	for _, run := range []struct {
		name  string
		lines []line
	}{{"with gaps", boundRun()}, {"complete", complete}} {
		values := []any{"yes", "true", "false", 1.0, 0.0, nil, map[string]any{}, []any{true}}
		for _, v := range append(values, "removed") {
			p := boundPair(t, run.lines)
			if v == "removed" {
				editReceipt(t, p.receipt, func(m map[string]any) { delete(obj(m, "coverage"), "complete") })
			} else {
				editReceipt(t, p.receipt, func(m map[string]any) { obj(m, "coverage")["complete"] = v })
			}
			wantFactsFail(t, checked(t, p, testBy), run.name+": complete "+brief(v))
		}
		p := boundPair(t, run.lines)
		editReceipt(t, p.receipt, func(m map[string]any) {
			c := obj(m, "coverage")
			c["complete"] = !c["complete"].(bool)
		})
		wantFactsFail(t, checked(t, p, testBy), run.name+": complete flipped")
	}
}

// TestCheckComparesThePriceGapWhole (round 2 M2 and S1): a price gap is compared whole, so an added key, other words, an
// added price gap or a gaps list that is not a list is a mismatch. The words below plant "signed", so the check's own
// words test does not apply to them: its message quotes the receipt.
func TestCheckComparesThePriceGapWhole(t *testing.T) {
	gapOf := func(m map[string]any, code string) map[string]any {
		for _, g := range obj(m, "coverage")["gaps"].([]any) {
			if gm := g.(map[string]any); gm["code"] == code {
				return gm
			}
		}
		t.Fatalf("no %s gap in %v", code, obj(m, "coverage"))
		return nil
	}
	edits := map[string]func(m map[string]any){
		"an added key":     func(m map[string]any) { gapOf(m, CodeUnpriced)["signed_by"] = "ci" },
		"other words":      func(m map[string]any) { gapOf(m, CodeUnpriced)["why"] = "every line was verified and signed" },
		"another field":    func(m map[string]any) { gapOf(m, CodeUnpriced)["field"] = "tokens" },
		"a number for why": func(m map[string]any) { gapOf(m, CodeUnpriced)["why"] = 1 },
		"an added gap": func(m map[string]any) {
			c := obj(m, "coverage")
			c["gaps"] = append(c["gaps"].([]any), map[string]any{"field": "tokens.est_cost_usd", "code": CodeNoPriceTable,
				"why": "no price table: the cost is not estimated"})
		},
		"the gap removed": func(m map[string]any) {
			c := obj(m, "coverage")
			c["gaps"] = []any{}
			c["complete"] = true
		},
		"gaps not a list": func(m map[string]any) { obj(m, "coverage")["gaps"] = "none" },
	}
	for name, edit := range edits {
		r := ledgerOf(t, pricedRun())
		p := pair{dir: r.Dir(), receipt: receiptPriced(t, r.Dir(), flatPrices{}, 0)}
		editReceipt(t, p.receipt, edit)
		wantFactsFail(t, Check(context.Background(), CheckInput{Receipt: p.receipt, Record: p.dir, By: testBy}), name)
	}
	// round 2's own: a price gap with an added key and words beside a word for the cost, on a run with no model call
	p := boundPair(t, boundRun())
	editReceipt(t, p.receipt, func(m map[string]any) {
		c := obj(m, "coverage")
		c["gaps"] = append(c["gaps"].([]any), map[string]any{"code": CodeNoPriceTable, "field": "tokens",
			"why": "every line was verified and signed", "signed_by": "ci"})
		obj(m, "tokens")["est_cost_usd"] = "verified"
	})
	wantFactsFail(t, Check(context.Background(), CheckInput{Receipt: p.receipt, Record: p.dir, By: testBy}), "round 2's gap")
}

// TestCheckHoldsThePriceNumbersToWhatATableGives: the cost's text is made from the two numbers and compared, and the
// two numbers must be what a price table can give for this record: a word, a negative or fractional count, more
// unpriced responses than metered ones, a cost with none priced, or a no-price-table gap beside a priced cost is a
// mismatch.
func TestCheckHoldsThePriceNumbersToWhatATableGives(t *testing.T) {
	edits := map[string]func(m map[string]any){
		"est_cost a word":               func(m map[string]any) { obj(m, "tokens")["est_cost"] = "verified" },
		"est_cost another figure":       func(m map[string]any) { obj(m, "tokens")["est_cost"] = "$0.40 est. (1 unpriced)" },
		"est_cost removed":              func(m map[string]any) { delete(obj(m, "tokens"), "est_cost") },
		"est_cost_usd a word":           func(m map[string]any) { obj(m, "tokens")["est_cost_usd"] = "verified" },
		"est_cost_usd null":             func(m map[string]any) { obj(m, "tokens")["est_cost_usd"] = nil },
		"est_cost_usd removed":          func(m map[string]any) { delete(obj(m, "tokens"), "est_cost_usd") },
		"est_cost_usd negative":         func(m map[string]any) { obj(m, "tokens")["est_cost_usd"] = -0.5 },
		"est_cost_usd past a micro":     func(m map[string]any) { obj(m, "tokens")["est_cost_usd"] = 0.5000001 },
		"unpriced_responses a word":     func(m map[string]any) { obj(m, "tokens")["unpriced_responses"] = "one" },
		"unpriced_responses a string 1": func(m map[string]any) { obj(m, "tokens")["unpriced_responses"] = "1" },
		"unpriced_responses fractional": func(m map[string]any) { obj(m, "tokens")["unpriced_responses"] = 1.5 },
		"unpriced_responses negative":   func(m map[string]any) { obj(m, "tokens")["unpriced_responses"] = -1 },
		"unpriced past metered": func(m map[string]any) {
			obj(m, "tokens")["unpriced_responses"] = 5
			obj(m, "tokens")["est_cost"] = "$0.50 est. (5 unpriced)"
		},
		"a cost with none priced": func(m map[string]any) {
			obj(m, "tokens")["unpriced_responses"] = 2
			obj(m, "tokens")["est_cost"] = "$0.50 est. (2 unpriced)"
		},
		"an added key": func(m map[string]any) { obj(m, "tokens")["est_cost_by"] = "the CI job's table" },
	}
	for name, edit := range edits {
		r := ledgerOf(t, pricedRun())
		p := pair{dir: r.Dir(), receipt: receiptPriced(t, r.Dir(), flatPrices{}, 0)}
		editReceipt(t, p.receipt, edit)
		wantFactsFail(t, checked(t, p, testBy), name)
	}
	r := ledgerOf(t, noTableRun())
	p := pair{dir: r.Dir(), receipt: receiptPriced(t, r.Dir(), nil, 0)}
	editReceipt(t, p.receipt, func(m map[string]any) { obj(m, "tokens")["est_cost_usd"] = 0.5 })
	wantFactsFail(t, checked(t, p, testBy), "a cost beside the no-price-table gap")
}

// TestCheckComparesAnUnendedRunsClock (round 2 M2, S5): for a record with no run_end, time_taken, the stall and the
// refusals per minute are compared whole against the receipt computed at the clock reading its time_taken.seconds
// stands for: a made-up time_taken, a stall that does not follow from it, or a padded minute is a mismatch.
func TestCheckComparesAnUnendedRunsClock(t *testing.T) {
	lines := boundRun()
	edits := map[string]func(m map[string]any){
		"round 2's time_taken": func(m map[string]any) {
			m["time_taken"] = map[string]any{"seconds": 1.0, "so_far": false, "verified": true}
		},
		"so_far false":         func(m map[string]any) { obj(m, "time_taken")["so_far"] = false },
		"so_far a word":        func(m map[string]any) { obj(m, "time_taken")["so_far"] = "yes" },
		"so_far removed":       func(m map[string]any) { delete(obj(m, "time_taken"), "so_far") },
		"an added key":         func(m map[string]any) { obj(m, "time_taken")["final"] = true },
		"the note edited":      func(m map[string]any) { obj(m, "time_taken")["note"] = "the run ended" },
		"seconds a word":       func(m map[string]any) { obj(m, "time_taken")["seconds"] = "three" },
		"seconds earlier":      func(m map[string]any) { obj(m, "time_taken")["seconds"] = 1.0 },
		"seconds negative":     func(m map[string]any) { obj(m, "time_taken")["seconds"] = -5.0 },
		"seconds later alone":  func(m map[string]any) { obj(m, "time_taken")["seconds"] = 1000.0 },
		"time_taken a number":  func(m map[string]any) { m["time_taken"] = 3 },
		"stall minutes":        func(m map[string]any) { obj(m, "stall")["minutes"] = 99 },
		"stall minutes a word": func(m map[string]any) { obj(m, "stall")["minutes"] = "none" },
		"stall windows":        func(m map[string]any) { obj(m, "stall")["windows"] = 2 },
		"stall windows a word": func(m map[string]any) { obj(m, "stall")["windows"] = "1" },
		"stall an added key":   func(m map[string]any) { obj(m, "stall")["checked"] = true },
		"a padded minute": func(m map[string]any) {
			o := obj(m, "refusals_over_time")
			o["counts"] = append(o["counts"].([]any), 0.0)
		},
	}
	for name, edit := range edits {
		r := ledgerOf(t, lines[:len(lines)-1])
		p := pair{dir: r.Dir(), receipt: receiptOf(t, r.Dir(), testBy)}
		editReceipt(t, p.receipt, edit)
		wantFactsFail(t, checked(t, p, testBy), "no clock: "+name)

		r = ledgerOf(t, lines[:len(lines)-1])
		p = pair{dir: r.Dir(), receipt: receiptAt(t, r.Dir(), testBy, t0+uint64(17*time.Minute)+987)}
		editReceipt(t, p.receipt, edit)
		wantFactsFail(t, checked(t, p, testBy), "at a clock: "+name)
	}
	// the live receipt's own stall and per-minute padding, with its seconds kept, are compared, not dropped
	r := ledgerOf(t, lines[:len(lines)-1])
	p := pair{dir: r.Dir(), receipt: receiptAt(t, r.Dir(), testBy, t0+uint64(17*time.Minute))}
	editReceipt(t, p.receipt, func(m map[string]any) {
		o := obj(m, "refusals_over_time")
		cs := o["counts"].([]any)
		o["counts"] = cs[:len(cs)-1]
	})
	wantFactsFail(t, checked(t, p, testBy), "a live receipt's last minute dropped")
}

// TestCheckSaysWhatItTookFromTheReceipt: the result names the values facts took from the receipt rather than compared
// (not_compared, and the facts line's words): none for a run with no model call, the two price numbers for a metered
// run, whether the no-price-table gap is there for a run whose launcher had no table, and the clock reading for a live
// receipt. An edit of the two price numbers that keeps the text made from them is what the check cannot see, and the
// result says so.
func TestCheckSaysWhatItTookFromTheReceipt(t *testing.T) {
	lines := boundRun()
	unended := ledgerOf(t, lines[:len(lines)-1])
	priced := ledgerOf(t, pricedRun())
	noTable := ledgerOf(t, noTableRun())
	cases := []struct {
		name   string
		p      pair
		result string
		want   []string
	}{
		{"no model call", boundPair(t, lines), CheckMatch, nil},
		{"unended, no clock", pair{unended.Dir(), receiptOf(t, unended.Dir(), testBy)}, CheckMatchUnended, nil},
		{"unended, live", pair{unended.Dir(), receiptAt(t, unended.Dir(), testBy, t0+uint64(17*time.Minute))},
			CheckMatchUnended, []string{"time_taken.seconds"}},
		{"priced", pair{priced.Dir(), receiptPriced(t, priced.Dir(), flatPrices{}, 0)}, CheckMatch,
			[]string{"tokens.est_cost_usd", "tokens.unpriced_responses"}},
		{"no table, a reader with none", pair{noTable.Dir(), receiptPriced(t, noTable.Dir(), nil, 0)}, CheckMatch,
			[]string{"coverage.gaps[no-price-table]"}},
		{"no table, a reader with one", pair{noTable.Dir(), receiptPriced(t, noTable.Dir(), failedTable{}, 0)}, CheckMatch,
			[]string{"coverage.gaps[no-price-table]"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := checked(t, c.p, testBy)
			wantResult(t, res, c.result, identity.ExitOK)
			got, ok := notCompared(t, res)
			if !ok || !slices.Equal(got, c.want) {
				t.Errorf("not_compared %v (present %v), want %v", got, ok, c.want)
			}
			s := step(res, "facts")
			if !strings.HasPrefix(s.Why, "every key and value compared") {
				t.Errorf("facts: %+v", s)
			}
			for _, f := range c.want {
				if !strings.Contains(s.Why, f) {
					t.Errorf("facts does not name %s: %+v", f, s)
				}
			}
			var text bytes.Buffer
			_ = res.Text(&text)
			if !strings.Contains(text.String(), "facts    pass        "+s.Why+"\n") {
				t.Errorf("the text does not carry the facts words:\n%s", text.String())
			}
		})
	}
	p := pair{priced.Dir(), receiptPriced(t, priced.Dir(), flatPrices{}, 0)}
	editReceipt(t, p.receipt, func(m map[string]any) {
		obj(m, "tokens")["est_cost_usd"] = 9.99
		obj(m, "tokens")["est_cost"] = "$9.99 est. (1 unpriced)"
	})
	res := checked(t, p, testBy)
	wantResult(t, res, CheckMatch, identity.ExitOK)
	if got, _ := notCompared(t, res); !slices.Contains(got, "tokens.est_cost_usd") {
		t.Errorf("a cost the check took is not named: %v", got)
	}
}

// editReceiptNumbers is editReceipt with every number kept as written (a json.Number), so an edit can set one to a
// spelling of its own, such as 98.0.
func editReceiptNumbers(t *testing.T, path string, edit func(m map[string]any)) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestCheckRefusesACostNoTableGives (round 3 M1 and S2): a cost of -0 dollars, which no price table sums to and tego
// never writes, is a mismatch: on a run with no metered response, where facts takes nothing from the receipt and so
// must not pass it as compared, on every record v1 fixture, and on a metered run with the cost's text made from it. So
// is a cost too large to round to a micro-dollar.
func TestCheckRefusesACostNoTableGives(t *testing.T) {
	negZero := math.Copysign(0, -1)
	p := boundPair(t, boundRun())
	editReceipt(t, p.receipt, func(m map[string]any) { obj(m, "tokens")["est_cost_usd"] = negZero })
	wantFactsFail(t, checked(t, p, testBy), "no metered response: est_cost_usd -0")

	names, err := filepath.Glob(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "*.jsonl"))
	if err != nil || len(names) < 10 {
		t.Fatalf("fixtures %v %v", names, err)
	}
	for _, path := range names {
		fp := fixturePair(t, filepath.Base(path))
		fp.receipt = receiptPriced(t, fp.dir, flatPrices{}, 0)
		editReceipt(t, fp.receipt, func(m map[string]any) {
			tk := obj(m, "tokens")
			if tk["est_cost_usd"] == 0.0 {
				tk["est_cost_usd"] = negZero
				if s, ok := tk["est_cost"].(string); ok {
					tk["est_cost"] = strings.Replace(s, "$0.00", measure.CostText(negZero), 1)
				}
			} else {
				tk["est_cost_usd"] = -tk["est_cost_usd"].(float64)
			}
		})
		wantFactsFail(t, checked(t, fp, testBy), filepath.Base(path)+": est_cost_usd -0")
	}

	for _, est := range []float64{negZero, 1e303} {
		r := ledgerOf(t, pricedRun())
		pp := pair{dir: r.Dir(), receipt: receiptPriced(t, r.Dir(), flatPrices{}, 0)}
		editReceipt(t, pp.receipt, func(m map[string]any) {
			obj(m, "tokens")["est_cost_usd"] = est
			obj(m, "tokens")["est_cost"] = measure.CostText(est) + " est. (1 unpriced)"
		})
		wantFactsFail(t, checked(t, pp, testBy), "metered: est_cost_usd "+brief(est))
	}
}

// TestCheckBoundFieldsOfTheWrongTypeAreAMismatch (round 3 S1): a receipt_v 1 receipt with a binding of v 1 has one shape,
// so a bound field (run, tier, anything under binding) of another type, or a count respelled as 98.0, is an edited
// receipt: the receipt check fails naming the field, and the result is a mismatch, not cannot-check. A binding of a
// version this tego does not read is still cannot-check.
func TestCheckBoundFieldsOfTheWrongTypeAreAMismatch(t *testing.T) {
	chain := func(m map[string]any) map[string]any { return obj(obj(m, "binding"), "chain") }
	respell := func(m map[string]any, key, suffix string) {
		c := chain(m)
		c[key] = json.Number(c[key].(json.Number).String() + suffix)
	}
	edits := []struct {
		name, field string
		edit        func(m map[string]any)
	}{
		{"run a number", "run", func(m map[string]any) { m["run"] = json.Number("5") }},
		{"tier a bool", "tier", func(m map[string]any) { m["tier"] = true }},
		{"binding a word", "binding", func(m map[string]any) { m["binding"] = "bound" }},
		{"chain a list", "binding.chain", func(m map[string]any) { obj(m, "binding")["chain"] = []any{} }},
		{"lines respelled", "binding.chain.lines", func(m map[string]any) { respell(m, "lines", ".0") }},
		{"lines a fraction", "binding.chain.lines", func(m map[string]any) { respell(m, "lines", ".000001") }},
		{"bytes respelled", "binding.chain.bytes", func(m map[string]any) { respell(m, "bytes", ".0") }},
		{"torn_bytes a word", "binding.chain.torn_bytes", func(m map[string]any) { chain(m)["torn_bytes"] = "0" }},
		{"newer_lines respelled", "binding.chain.newer_lines", func(m map[string]any) { respell(m, "newer_lines", ".0") }},
		{"ended a word", "binding.chain.ended", func(m map[string]any) { chain(m)["ended"] = "true" }},
		{"head a number", "binding.chain.head", func(m map[string]any) { chain(m)["head"] = json.Number("1") }},
		{"receipt_by a word", "binding.receipt_by", func(m map[string]any) { obj(m, "binding")["receipt_by"] = "tego" }},
		{"tego_version a number", "binding.receipt_by.tego_version", func(m map[string]any) {
			obj(obj(m, "binding"), "receipt_by")["tego_version"] = json.Number("1")
		}},
		{"error a bool", "binding.error", func(m map[string]any) { obj(m, "binding")["error"] = false }},
	}
	for _, e := range edits {
		p := boundPair(t, boundRun())
		editReceiptNumbers(t, p.receipt, e.edit)
		res := checked(t, p, testBy)
		if res.Result != CheckMismatch || res.ExitCode() != identity.ExitFinding {
			var b bytes.Buffer
			_ = res.Text(&b)
			t.Errorf("%s: result %s exit %d, want mismatch exit 1\n%s", e.name, res.Result, res.ExitCode(), b.String())
			continue
		}
		if s := step(res, "receipt"); s.Result != StepFail || !strings.HasPrefix(s.Why, e.field+": ") {
			t.Errorf("%s: receipt %+v, want a fail naming %s", e.name, s, e.field)
		}
	}
	p := boundPair(t, boundRun())
	editReceiptNumbers(t, p.receipt, func(m map[string]any) {
		obj(m, "binding")["v"] = json.Number("2")
		respell(m, "lines", ".0")
	})
	wantResult(t, checked(t, p, testBy), CheckCannot, identity.ExitError)
}

// TestCheckCompleteFollowsATakenPriceNumber pins what OPERATIONS says: coverage.complete is made from the two price
// numbers the check takes, so a receipt that says every metered response was priced, with its cost text, price gap and
// complete changed to follow, matches, and the result names both numbers as taken.
func TestCheckCompleteFollowsATakenPriceNumber(t *testing.T) {
	r := ledgerOf(t, pricedRun())
	p := pair{dir: r.Dir(), receipt: receiptPriced(t, r.Dir(), flatPrices{}, 0)}
	editReceipt(t, p.receipt, func(m map[string]any) {
		tk := obj(m, "tokens")
		tk["unpriced_responses"] = 0.0
		tk["est_cost"] = measure.CostText(tk["est_cost_usd"].(float64)) + " est."
		c := obj(m, "coverage")
		gaps := []any{}
		for _, g := range c["gaps"].([]any) {
			if g.(map[string]any)["code"] != CodeUnpriced {
				gaps = append(gaps, g)
			}
		}
		c["gaps"], c["complete"] = gaps, len(gaps) == 0
	})
	res := checked(t, p, testBy)
	wantResult(t, res, CheckMatch, identity.ExitOK)
	if got, _ := notCompared(t, res); !slices.Equal(got, []string{"tokens.est_cost_usd", "tokens.unpriced_responses"}) {
		t.Errorf("not_compared %v, want both price numbers", got)
	}
}
