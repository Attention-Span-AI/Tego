// SPDX-License-Identifier: Apache-2.0

package measure

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// update rewrites the golden files instead of comparing against them: `go test ./internal/check/measure
// -update`. Every change it makes belongs in the same commit as the change that caused it.
var update = flag.Bool("update", false, "rewrite the golden files")

// prices is the test price table: the one model the fixture uses, at USD per million tokens.
type prices map[string][4]float64

// Cost implements Prices over the table.
func (p prices) Cost(u ledger.TokenUsage) (float64, bool) {
	row, ok := p[u.Model]
	if !ok {
		return 0, false
	}
	const perM = 1e6
	return float64(u.In)/perM*row[0] + float64(u.Out)/perM*row[1] +
		float64(u.CacheRead)/perM*row[2] + float64(u.CacheWrite)/perM*row[3], true
}

// fixturePrices prices the fixture's model at the same rates internal/runtime/limits' testdata uses.
func fixturePrices() prices {
	return prices{"claude-sonnet-4-5-20250929": {3, 15, 0.30, 3.75}}
}

// fixtureReader opens the frozen v1 fixture ledger as a run directory. The fixture is the contract
// every view is built against (P0-DESIGN §10): measure is written against it before the runtime
// emits a real event.
func fixtureReader(t *testing.T) *ledger.Reader {
	t.Helper()
	src := filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "run-fixture.jsonl")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return readerOf(t, data)
}

// readerOf writes lines as a run directory's ledger and opens a reader over it.
func readerOf(t *testing.T, data []byte) *ledger.Reader {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// TestComputeFixture is the frozen fixture's measurement, every P0 column checked against the
// values a reader can count off the fixture by hand (R18-R23).
func TestComputeFixture(t *testing.T) {
	rep, err := Compute(fixtureReader(t), fixturePrices())
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	want := Report{
		Run:        "r-3f9c2a1b-0dllq06ts7400-k7m2pq",
		Agent:      "retriever",
		Steps:      20,    // the twenty decision events (R18)
		Refused:    1,     // the one fs event with verdict=refused; the refused-kind event is not counted (R19)
		TokensIn:   58000, // 1000..4800 by 200 (R20)
		TokensOut:  2420,  // 102..140 by 2
		CacheRead:  97280,
		CacheWrite: 10240,
		Responses:  20,
		Wall:       25642250000, // last event 837987500000 - run_start 812345250000 (R21)
		IdleMax:    1700250000,  // seq 15 -> 16 (R22)
		Repeats:    1,           // every input hash differs (R23)
		Events:     98,
		Ended:      true,
		EndReason:  record.RunEndLimit,
	}
	got := *rep
	cost := got.EstCostUSD
	got.EstCostUSD = 0
	if got != want {
		t.Errorf("report\n got %+v\nwant %+v", got, want)
	}
	// 58000*3 + 2420*15 + 97280*0.30 + 10240*3.75, per million.
	if wantCost := 0.277884; !nearly(cost, wantCost) {
		t.Errorf("est cost = %.6f, want %.6f", cost, wantCost)
	}
	if label := rep.Cost(); label != "$0.28 est." {
		t.Errorf("cost label = %q, want %q (every surface says est.)", label, "$0.28 est.")
	}
	if rep.Tokens() != 60420 {
		t.Errorf("budget tokens = %d, want 60420 — the value the fixture's limit event records", rep.Tokens())
	}
}

// TestFixtureAgreesWithTheLimitEvent is I5 in the direction this package can check on its own: the
// tokens measure recomputes are the tokens the run's own limit event recorded when it tripped.
func TestFixtureAgreesWithTheLimitEvent(t *testing.T) {
	r := fixtureReader(t)
	rep, err := Compute(r, fixturePrices())
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	var found bool
	for e, err := range r.Iter() {
		if err != nil {
			t.Fatalf("iter: %v", err)
		}
		if e.Kind != record.KindLimit {
			continue
		}
		var p record.LimitPayload
		if err := e.DecodePayload(&p); err != nil {
			t.Fatalf("decode limit: %v", err)
		}
		found = true
		if p.Which != record.LimitTokens {
			t.Fatalf("fixture limit is %q", p.Which)
		}
		if uint64(p.Value) != rep.Tokens() {
			t.Errorf("limit event value %v, measure %d: the two formulas disagree (I5)", p.Value, rep.Tokens())
		}
	}
	if !found {
		t.Fatal("the fixture has no limit event")
	}
}

// TestFixtureGolden freezes the two rendered views (limits-check-doctor-cli.md R31 and E22).
func TestFixtureGolden(t *testing.T) {
	rep, err := Compute(fixtureReader(t), fixturePrices())
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	t.Run("table", func(t *testing.T) {
		var out bytes.Buffer
		if err := rep.Table(&out); err != nil {
			t.Fatalf("Table: %v", err)
		}
		checkGolden(t, "fixture-table.txt", out.Bytes())
	})
	t.Run("json", func(t *testing.T) {
		var out bytes.Buffer
		if err := rep.JSON(&out); err != nil {
			t.Fatalf("JSON: %v", err)
		}
		if n := bytes.Count(out.Bytes(), []byte("\n")); n != 1 {
			t.Errorf("--json wrote %d lines, want exactly one object on one line", n)
		}
		checkGolden(t, "fixture.json", out.Bytes())
	})
}

// checkGolden compares got against testdata/name, or rewrites it under -update.
func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden: %v (run with -update to create it)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("golden %s differs\n got:\n%s\nwant:\n%s", name, got, want)
	}
}

// event builds one synthetic ledger line.
type event struct {
	kind    record.Kind
	mono    uint64
	verdict record.Verdict
	step    int
	tool    string
	hash    string
	model   string
	usage   *record.Usage
	reason  string
	// resources is a run_end's resources object; nil writes none. rawEnd, when set, is the run_end's whole
	// payload as written, for a key this binary's types do not hold.
	resources *record.Resources
	rawEnd    string
	// raw, when set, is the line's whole payload as written (an answer line's, say).
	raw string
}

// ledgerOf marshals a synthetic run into a reader, stamping the common fields a writer would.
func ledgerOf(t *testing.T, events []event) *ledger.Reader {
	t.Helper()
	var buf bytes.Buffer
	prev := ""
	for i, in := range events {
		e := &record.Event{
			V: record.Version, Seq: uint64(i), Prev: prev, MonoNS: in.mono,
			TS:  time.Unix(0, int64(in.mono)).UTC(),
			Run: "r-3f9c2a1b-0dllq06ts7400-k7m2pq", Agent: "synthetic",
			PID: 1, TID: 1, Kind: in.kind, Source: record.SourceSupervisor,
			Verdict: in.verdict,
		}
		switch in.kind {
		case record.KindRunStart:
			if err := e.SetPayload(record.RunStartPayload{Tier: "landlock", Capture: "forwarder"}); err != nil {
				t.Fatal(err)
			}
		case record.KindRunEnd:
			if err := e.SetPayload(record.RunEndPayload{Reason: in.reason, Resources: in.resources}); err != nil {
				t.Fatal(err)
			}
			if in.rawEnd != "" {
				e.Payload = json.RawMessage(in.rawEnd)
			}
		case record.KindSSLResponse:
			if err := e.SetPayload(record.SSLResponsePayload{Model: in.model, Status: 200, ParserVersion: "1", Usage: in.usage}); err != nil {
				t.Fatal(err)
			}
		case record.KindDecision:
			if err := e.SetPayload(record.DecisionPayload{Step: in.step, Tool: in.tool, InputHash: in.hash}); err != nil {
				t.Fatal(err)
			}
		case record.KindGap:
			if err := e.SetPayload(record.GapPayload{What: record.GapRecord, Why: "channel-full"}); err != nil {
				t.Fatal(err)
			}
		case record.KindFS:
			e.Rule, e.Authority = "fs.read[/tmp]", record.AuthorityRule
			e.Attr = record.Unattributed()
			if err := e.SetPayload(record.FSPayload{Op: record.FSOpen, Path: "/tmp/x"}); err != nil {
				t.Fatal(err)
			}
		case record.KindRefused:
			e.Rule, e.Reason = "fs.read[/tmp]", record.ReasonReadDenied
			if err := e.SetPayload(record.RefusedPayload{Op: record.FSOpen, Target: "/tmp/x"}); err != nil {
				t.Fatal(err)
			}
		}
		if in.raw != "" {
			e.Payload = json.RawMessage(in.raw)
		}
		line, err := e.MarshalLine()
		if err != nil {
			t.Fatalf("marshal seq %d: %v", i, err)
		}
		prev = e.ID
		buf.Write(line)
		buf.WriteByte('\n')
	}
	return readerOf(t, buf.Bytes())
}

// TestComputeRules is the table of limits-check-doctor-cli.md R18, R19, R20, R21, R22 and R23 against synthetic runs, one property per case.
func TestComputeRules(t *testing.T) {
	sec := func(n uint64) uint64 { return n * uint64(time.Second) }
	usage := func(in, out int) *record.Usage { return &record.Usage{Input: in, Output: out} }

	tests := []struct {
		name   string
		events []event
		check  func(t *testing.T, rep *Report)
	}{
		{
			name: "R19: an action's own refused verdict counts once, the mirroring refused event never",
			events: []event{
				{kind: record.KindRunStart, mono: sec(1)},
				{kind: record.KindFS, mono: sec(2), verdict: record.VerdictRefused},
				{kind: record.KindRefused, mono: sec(2)},
				{kind: record.KindFS, mono: sec(3), verdict: record.VerdictAllow},
				{kind: record.KindRunEnd, mono: sec(4), reason: record.RunEndExit},
			},
			check: func(t *testing.T, rep *Report) {
				if rep.Refused != 1 {
					t.Errorf("refused = %d, want 1", rep.Refused)
				}
			},
		},
		{
			name: "R22: a window touching a gap event is unknown, not idle",
			events: []event{
				{kind: record.KindRunStart, mono: sec(1)},
				{kind: record.KindFS, mono: sec(2), verdict: record.VerdictAllow},
				{kind: record.KindGap, mono: sec(30)},
				{kind: record.KindFS, mono: sec(60), verdict: record.VerdictAllow},
				{kind: record.KindFS, mono: sec(63), verdict: record.VerdictAllow},
				{kind: record.KindRunEnd, mono: sec(64), reason: record.RunEndExit},
			},
			check: func(t *testing.T, rep *Report) {
				if rep.IdleMax != 3*time.Second {
					t.Errorf("idle max = %s, want 3s (the 28s and 30s windows straddle the gap)", rep.IdleMax)
				}
			},
		},
		{
			// A forwarder line keeps its capture-time reading, so mono_ns can go back along seq. The
			// window after it is measured from the largest reading so far: the quiet spans are 9s and 10s.
			name: "R22: a reading that goes back is not the next window's start",
			events: []event{
				{kind: record.KindRunStart, mono: sec(1)},
				{kind: record.KindFS, mono: sec(10), verdict: record.VerdictAllow},
				{kind: record.KindFS, mono: sec(5), verdict: record.VerdictAllow},
				{kind: record.KindFS, mono: sec(20), verdict: record.VerdictAllow},
				{kind: record.KindRunEnd, mono: sec(20), reason: record.RunEndExit},
			},
			check: func(t *testing.T, rep *Report) {
				if rep.IdleMax != 10*time.Second {
					t.Errorf("idle max = %s, want 10s (measured from the largest reading, not the 5s one)", rep.IdleMax)
				}
			},
		},
		{
			name: "R23: the longest streak anywhere, not the last one",
			events: []event{
				{kind: record.KindRunStart, mono: sec(1)},
				{kind: record.KindDecision, mono: sec(2), step: 1, tool: "bash", hash: "a"},
				{kind: record.KindDecision, mono: sec(3), step: 2, tool: "bash", hash: "a"},
				{kind: record.KindDecision, mono: sec(4), step: 3, tool: "bash", hash: "a"},
				{kind: record.KindDecision, mono: sec(5), step: 4, tool: "bash", hash: "b"},
				{kind: record.KindDecision, mono: sec(6), step: 5, tool: "bash", hash: "b"},
				{kind: record.KindRunEnd, mono: sec(7), reason: record.RunEndExit},
			},
			check: func(t *testing.T, rep *Report) {
				if rep.Repeats != 3 {
					t.Errorf("repeats = %d, want 3", rep.Repeats)
				}
				if rep.Steps != 5 {
					t.Errorf("steps = %d, want 5", rep.Steps)
				}
			},
		},
		{
			name: "E14: a decision with no tool and a response with no usage contribute nothing",
			events: []event{
				{kind: record.KindRunStart, mono: sec(1)},
				{kind: record.KindSSLResponse, mono: sec(2), model: "m"},
				{kind: record.KindDecision, mono: sec(3), step: 1},
				{kind: record.KindRunEnd, mono: sec(4), reason: record.RunEndExit},
			},
			check: func(t *testing.T, rep *Report) {
				if rep.Responses != 0 || rep.Tokens() != 0 || rep.Repeats != 0 {
					t.Errorf("report %+v, want no tokens, no responses and no streak", rep)
				}
				if rep.Steps != 1 {
					t.Errorf("steps = %d, want 1: an unparsed decision still counts as a step", rep.Steps)
				}
			},
		},
		{
			name: "R21: a run with no run_end measures to its last event",
			events: []event{
				{kind: record.KindRunStart, mono: sec(1)},
				{kind: record.KindFS, mono: sec(9), verdict: record.VerdictAllow},
			},
			check: func(t *testing.T, rep *Report) {
				if rep.Ended || rep.Live {
					t.Errorf("ended=%v live=%v, want both false", rep.Ended, rep.Live)
				}
				if rep.Wall != 8*time.Second {
					t.Errorf("wall = %s, want 8s", rep.Wall)
				}
			},
		},
		{
			name: "a run whose run_start was lost still measures from its first event",
			events: []event{
				{kind: record.KindFS, mono: sec(10), verdict: record.VerdictAllow},
				{kind: record.KindFS, mono: sec(14), verdict: record.VerdictAllow},
			},
			check: func(t *testing.T, rep *Report) {
				if rep.Wall != 4*time.Second {
					t.Errorf("wall = %s, want 4s", rep.Wall)
				}
			},
		},
		{
			name: "R20: tokens sum whatever the price table says",
			events: []event{
				{kind: record.KindRunStart, mono: sec(1)},
				{kind: record.KindSSLResponse, mono: sec(2), model: "unpriced", usage: usage(10, 5)},
				{kind: record.KindSSLResponse, mono: sec(3), model: "unpriced", usage: usage(20, 5)},
				{kind: record.KindRunEnd, mono: sec(4), reason: record.RunEndExit},
			},
			check: func(t *testing.T, rep *Report) {
				if rep.TokensIn != 30 || rep.TokensOut != 10 {
					t.Errorf("tokens = %d/%d, want 30/10", rep.TokensIn, rep.TokensOut)
				}
				if rep.EstCostUSD != 0 || rep.Unpriced != 2 {
					t.Errorf("cost %.2f over %d unpriced responses, want 0 over 2", rep.EstCostUSD, rep.Unpriced)
				}
				if got := rep.Cost(); !strings.Contains(got, "unpriced") {
					t.Errorf("cost label %q does not say the responses were unpriced", got)
				}
			},
		},
		{
			name:   "an empty ledger measures to zero, never an error",
			events: nil,
			check: func(t *testing.T, rep *Report) {
				if rep.Events != 0 || rep.Wall != 0 {
					t.Errorf("report %+v, want an empty one", rep)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := Compute(ledgerOf(t, tc.events), fixturePrices())
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			tc.check(t, rep)
		})
	}
}

// TestComputeAtLive covers R21's live half: a running run measures against the caller's clock, and
// a reading that cannot be from this boot is ignored rather than believed.
func TestComputeAtLive(t *testing.T) {
	events := []event{
		{kind: record.KindRunStart, mono: uint64(time.Second)},
		{kind: record.KindFS, mono: uint64(5 * time.Second), verdict: record.VerdictAllow},
	}
	t.Run("now is later than the last event", func(t *testing.T) {
		rep, err := ComputeAt(t.Context(), ledgerOf(t, events), nil, uint64(30*time.Second))
		if err != nil {
			t.Fatalf("ComputeAt: %v", err)
		}
		if !rep.Live || rep.Wall != 29*time.Second {
			t.Errorf("live=%v wall=%s, want true and 29s", rep.Live, rep.Wall)
		}
	})
	t.Run("a reading from another boot is ignored", func(t *testing.T) {
		rep, err := ComputeAt(t.Context(), ledgerOf(t, events), nil, 1)
		if err != nil {
			t.Fatalf("ComputeAt: %v", err)
		}
		if rep.Live || rep.Wall != 4*time.Second {
			t.Errorf("live=%v wall=%s, want false and 4s", rep.Live, rep.Wall)
		}
	})
	t.Run("a finished run ignores the clock", func(t *testing.T) {
		done := append(append([]event{}, events...), event{kind: record.KindRunEnd, mono: uint64(6 * time.Second), reason: record.RunEndExit})
		rep, err := ComputeAt(t.Context(), ledgerOf(t, done), nil, uint64(time.Hour))
		if err != nil {
			t.Fatalf("ComputeAt: %v", err)
		}
		if rep.Live || rep.Wall != 5*time.Second {
			t.Errorf("live=%v wall=%s, want false and 5s", rep.Live, rep.Wall)
		}
	})
}

// TestTornLines covers E2 and E3: a torn last line is what a live run looks like and is ignored; a
// malformed line anywhere else is a hard, named error.
// (limits-check-doctor-cli.md E2 and E3.)
func TestTornLines(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "run-fixture.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimRight(src, "\n"), []byte("\n"))

	t.Run("torn last line", func(t *testing.T) {
		var buf bytes.Buffer
		for _, l := range lines[:len(lines)-1] {
			buf.Write(l)
			buf.WriteByte('\n')
		}
		buf.Write(lines[len(lines)-1][:40]) // a half-written line, no newline
		rep, err := Compute(readerOf(t, buf.Bytes()), fixturePrices())
		if err != nil {
			t.Fatalf("Compute over a torn tail: %v", err)
		}
		if rep.Events != len(lines)-1 {
			t.Errorf("events = %d, want %d", rep.Events, len(lines)-1)
		}
		if rep.Ended {
			t.Error("the torn line was run_end; the run must not read as ended")
		}
	})

	t.Run("torn middle line", func(t *testing.T) {
		var buf bytes.Buffer
		for i, l := range lines {
			if i == 10 {
				buf.WriteString("{\"v\":1,\"seq\":10,\n")
				continue
			}
			buf.Write(l)
			buf.WriteByte('\n')
		}
		_, err := Compute(readerOf(t, buf.Bytes()), fixturePrices())
		if err == nil {
			t.Fatal("a malformed middle line must be a hard error")
		}
		if !errors.Is(err, ledger.ErrCorruptLedger) {
			t.Errorf("error %v does not wrap ledger.ErrCorruptLedger", err)
		}
		if !strings.Contains(err.Error(), "events.jsonl: ledger: corrupt line") || strings.Contains(err.Error(), "at event") {
			t.Errorf("error %q must name the file and the reader's line only", err)
		}
	})
}

// TestComputeNilReader covers the quality bar: no panic on input a caller can hand over.
func TestComputeNilReader(t *testing.T) {
	if _, err := Compute(nil, nil); err == nil {
		t.Fatal("Compute(nil) must report an error, not panic")
	}
}

// BenchmarkCompute guards E10's streaming invariant over a run of fixture-shaped events: memory
// must not grow with the ledger.
func BenchmarkCompute(b *testing.B) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "fixtures", "run-fixture.jsonl"))
	if err != nil {
		b.Fatal(err)
	}
	var big bytes.Buffer
	for range 300 { // ~29k events
		big.Write(src)
	}
	dir := b.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), big.Bytes(), 0o600); err != nil {
		b.Fatal(err)
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = r.Close() })
	p := fixturePrices()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Compute(r, p); err != nil {
			b.Fatal(err)
		}
	}
}

// nearly compares two estimates to well under a cent.
func nearly(a, b float64) bool {
	d := a - b
	return d < 1e-9 && d > -1e-9
}

// TestResourcesFromRunEnd is R-res: measure reads run_end.resources and shows what the run's cgroup said it
// used. A key the record lacks is "unknown" in the table and absent in --json, never 0, and a 0 the record
// carries is shown as the kernel's 0 (docs/VERSIONING.md §2).
func TestResourcesFromRunEnd(t *testing.T) {
	sec := func(n uint64) uint64 { return n * uint64(time.Second) }
	u := func(v uint64) *uint64 { return &v }
	res := &record.Resources{PidsPeak: u(20), MemoryPeak: u(64 << 20), CPUNrThrottled: u(0),
		MemoryEvents: &record.MemoryEvents{OOMKill: u(0)}}
	render := func(t *testing.T, rep *Report) (table, js string) {
		t.Helper()
		var tb, jb bytes.Buffer
		if err := rep.Table(&tb); err != nil {
			t.Fatal(err)
		}
		if err := rep.JSON(&jb); err != nil {
			t.Fatal(err)
		}
		return tb.String(), jb.String()
	}
	row := func(table, label string) string {
		for _, line := range strings.Split(table, "\n") {
			if strings.HasPrefix(line, label+"  ") {
				return strings.TrimSpace(strings.TrimPrefix(line, label))
			}
		}
		return "<no row>"
	}

	rep, err := Compute(ledgerOf(t, []event{
		{kind: record.KindRunStart, mono: sec(1)},
		{kind: record.KindRunEnd, mono: sec(2), reason: record.RunEndExit, resources: res},
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Resources == nil || *rep.Resources.PidsPeak != 20 {
		t.Fatalf("Resources = %+v, want run_end's", rep.Resources)
	}
	table, js := render(t, rep)
	for label, want := range map[string]string{
		"memory peak":   "64.0 MiB (67108864 B)",
		"pids peak":     "20",
		"cpu":           "unknown (user unknown, system unknown)",
		"cpu throttled": "0 times for unknown",
		"memory events": "high unknown, max unknown, oom unknown, oom_kill 0",
	} {
		if got := row(table, label); got != want {
			t.Errorf("table row %q = %q, want %q\n%s", label, got, want, table)
		}
	}
	if !strings.Contains(js, `"resources":{"memory_peak":67108864,"pids_peak":20,"cpu_nr_throttled":0,"memory_events":{"oom_kill":0}}`) {
		t.Errorf("--json does not carry run_end.resources as recorded: %s", js)
	}

	// A run_end with no resources object (an older binary, a run whose cgroup never existed): every row
	// unknown, since the kernel told nothing. A run that has not ended: every row says it has none until it
	// ends, since the runtime reads them once, at shutdown, and a bare unknown would read as a kernel that told
	// nothing. Neither has a resources key in --json rather than a block of zeros.
	for _, tc := range []struct {
		name   string
		events []event
		want   string
	}{
		{"run_end without resources", []event{
			{kind: record.KindRunStart, mono: sec(1)},
			{kind: record.KindRunEnd, mono: sec(2), reason: record.RunEndExit},
		}, "unknown"},
		{"no run_end yet", []event{{kind: record.KindRunStart, mono: sec(1)}}, "unknown until the run ends"},
	} {
		rep, err := Compute(ledgerOf(t, tc.events), nil)
		if err != nil {
			t.Fatal(err)
		}
		table, js := render(t, rep)
		for _, label := range []string{"memory peak", "pids peak", "cpu throttled", "memory events"} {
			if got := row(table, label); got != tc.want {
				t.Errorf("%s: table row %q = %q, want %q", tc.name, label, got, tc.want)
			}
		}
		if tc.want != "unknown" {
			if got := row(table, "cpu"); got != tc.want {
				t.Errorf("%s: table row cpu = %q, want %q", tc.name, got, tc.want)
			}
		}
		if strings.Contains(js, `"resources"`) {
			t.Errorf("%s: --json carries a resources key the record does not have: %s", tc.name, js)
		}
	}
}

// TestResourcesJSONIsTheRecordedObject is R-res's --json half: run_end.resources is given as the ledger holds
// it, so a key a newer binary adds (additive, docs/VERSIONING.md §2) reaches a jq filter rather than being
// dropped by this binary's record.Resources, while the table shows the keys it knows.
func TestResourcesJSONIsTheRecordedObject(t *testing.T) {
	sec := func(n uint64) uint64 { return n * uint64(time.Second) }
	const recorded = `{"memory_peak":1024,"io_bytes_read":77,"memory_events":{"oom_kill":0,"sock_throttled":3}}`
	rep, err := Compute(ledgerOf(t, []event{
		{kind: record.KindRunStart, mono: sec(1)},
		{kind: record.KindRunEnd, mono: sec(2), rawEnd: `{"reason":"exit","exit_code":0,"resources":` + recorded + `}`},
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	var jb, tb bytes.Buffer
	if err := rep.JSON(&jb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jb.String(), `"resources":`+recorded) {
		t.Errorf("--json does not give run_end.resources as recorded:\n got %s\nwant %s inside", jb.String(), recorded)
	}
	if err := rep.Table(&tb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tb.String(), "1.0 KiB (1024 B)") {
		t.Errorf("the table lost the known key:\n%s", tb.String())
	}
}

// TestTableEscapesLedgerText: the table prints every ledger-derived cell through record.Printable, as
// events, drift and status do. The run and agent strings are not validated on read, and a tampered or
// foreign ledger's escape sequence reached the terminal raw through this one view.
func TestTableEscapesLedgerText(t *testing.T) {
	sec := func(n uint64) uint64 { return n * uint64(time.Second) }
	rep, err := Compute(ledgerOf(t, []event{
		{kind: record.KindRunStart, mono: sec(1)},
		{kind: record.KindRunEnd, mono: sec(2), rawEnd: `{"reason":"exit","exit_code":0,"resources":{"memory_events":{"o\u001b[2J":1}}}`},
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	rep.Run, rep.Agent = "r\x1b[2Jx", "a\x1b]0;t\a"
	var tb bytes.Buffer
	if err := rep.Table(&tb); err != nil {
		t.Fatal(err)
	}
	for _, c := range tb.String() {
		if c < 0x20 && c != '\n' || c == 0x7f {
			t.Fatalf("the table carries control byte %#x:\n%q", c, tb.String())
		}
	}
	if !strings.Contains(tb.String(), `r\x1b[2Jx`) {
		t.Errorf("the run is not shown escaped:\n%s", tb.String())
	}
}

// ADR 0057 D1: a held open a person answered with another file is counted from its answer line, as an alternate:
// neither a refusal nor an approval. An approval, a denial and an answer line older than the approved key are not.
func TestAlternatesAreCountedFromTheAnswerLines(t *testing.T) {
	rep, err := Compute(ledgerOf(t, []event{
		{kind: record.KindRunStart, mono: 1},
		{kind: record.KindAnswer, mono: 2, raw: `{"ask_id":"q-1","by":"uid:1000 pid:7","after_s":1,"approved":false,"alternate":"/home/u/fake","alternate_dev":2049,"alternate_ino":7}`},
		{kind: record.KindAnswer, mono: 3, raw: `{"ask_id":"q-2","by":"standing:q-1","after_s":0,"approved":false,"alternate":"/home/u/fake"}`},
		{kind: record.KindAnswer, mono: 4, raw: `{"ask_id":"q-3","by":"uid:1000 pid:7","after_s":1,"approved":true}`},
		{kind: record.KindAnswer, mono: 5, raw: `{"ask_id":"q-4","by":"uid:1000 pid:7","after_s":1,"approved":false,"answer_reason":"ask-denied"}`},
		{kind: record.KindAnswer, mono: 6, raw: `{"ask_id":"q-5","by":"human","after_s":1}`},
	}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Alternates != 2 || rep.Refused != 0 {
		t.Fatalf("alternates %d refused %d, want 2 and 0", rep.Alternates, rep.Refused)
	}
	var tbl, js bytes.Buffer
	if err := rep.Table(&tbl); err != nil {
		t.Fatal(err)
	}
	if err := rep.JSON(&js); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^alternates +2$`).MatchString(tbl.String()) || !strings.Contains(js.String(), `"alternates":2,`) {
		t.Fatalf("table:\n%s\njson: %s", tbl.String(), js.String())
	}
}
