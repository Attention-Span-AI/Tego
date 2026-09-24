// SPDX-License-Identifier: Apache-2.0

package measure

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// buildReader chains events into a ledger the way a writer would (seq gapless, prev naming the prior
// id) and opens a Reader over it. Unlike measure_test.go's ledgerOf/event helpers this takes raw
// *record.Event values, so a case here can set fields ledgerOf never touches — Attr with a non-zero
// Step in particular (§ TestComputeStepsFromAttribution).
func buildReader(t *testing.T, events []*record.Event) *ledger.Reader {
	t.Helper()
	var buf bytes.Buffer
	prev := ""
	for i, e := range events {
		e.V = record.Version
		e.Seq = uint64(i)
		e.Prev = prev
		if e.Run == "" {
			e.Run = "r-3f9c2a1b-0dllq06ts7400-k7m2pq"
		}
		if e.Agent == "" {
			e.Agent = "synthetic"
		}
		if e.PID == 0 {
			e.PID = 1
		}
		if e.TID == 0 {
			e.TID = 1
		}
		if e.Source == "" {
			e.Source = record.SourceSupervisor
		}
		if e.TS.IsZero() {
			e.TS = time.Unix(0, int64(e.MonoNS)).UTC()
		}
		line, err := e.MarshalLine()
		if err != nil {
			t.Fatalf("marshal seq %d (%s): %v", i, e.Kind, err)
		}
		prev = e.ID
		buf.Write(line)
		buf.WriteByte('\n')
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// fsAction builds a minimal, valid exec/fs/net/mcp-shaped fs event carrying the given attribution —
// the shape validateAction requires (rule, verdict, authority, attribution).
func fsAction(mono uint64, attr *record.Attribution) *record.Event {
	e := &record.Event{
		MonoNS: mono, Kind: record.KindFS, Rule: "fs.read[/tmp]",
		Verdict: record.VerdictAllow, Authority: record.AuthorityRule, Attr: attr,
	}
	if err := e.SetPayload(record.FSPayload{Op: record.FSOpen, Path: "/tmp/x"}); err != nil {
		panic(err) // constant payload; a marshal error here is a test-helper bug, not a case result
	}
	return e
}

func runStart(mono uint64) *record.Event {
	e := &record.Event{MonoNS: mono, Kind: record.KindRunStart}
	if err := e.SetPayload(record.RunStartPayload{Tier: "landlock", Capture: "forwarder"}); err != nil {
		panic(err)
	}
	return e
}

func runEnd(mono uint64, reason string) *record.Event {
	e := &record.Event{MonoNS: mono, Kind: record.KindRunEnd}
	if err := e.SetPayload(record.RunEndPayload{Reason: reason}); err != nil {
		panic(err)
	}
	return e
}

func decision(mono uint64, step int, tool, hash string) *record.Event {
	e := &record.Event{MonoNS: mono, Kind: record.KindDecision}
	if err := e.SetPayload(record.DecisionPayload{Step: step, Tool: tool, InputHash: hash}); err != nil {
		panic(err)
	}
	return e
}

// TestComputeStepsFromAttribution pins R18's actual formula: "Steps = max(attribution.step)". P0
// writers do not populate Attr.Step yet (measure.go's own doc comment: "Attribution carries it only
// from M2 on, so in P0 this is the only [decision.Step] source R18's column can have") — but the read
// side already implements the general formula (measure.go lines checking `e.Attr != nil && e.Attr.Step
// > rep.Steps`), and every other test in this package drives Steps through decision.Step alone. A
// hand-built or future-writer ledger that does carry attribution must still be measured correctly, and
// nothing else here would notice if that branch were ever deleted as apparently-dead code.
// limits-check-doctor-cli.md R18 is the rule this pins: Steps is the maximum attribution.step.
func TestComputeStepsFromAttribution(t *testing.T) {
	events := []*record.Event{
		runStart(1e9),
		decision(2e9, 3, "bash", "a"),                    // decision.Step=3: the smaller, P0-realistic source
		fsAction(3e9, record.AttributedByTime("t1", 7)),  // attribution.Step=7: must win, it's larger
		fsAction(4e9, record.AttributedByTime("t1", 4)),  // smaller than the running max: must not lower it
		fsAction(5e9, record.AttributedByTime("t1", 10)), // new max: running max, not first-wins
		runEnd(6e9, record.RunEndExit),
	}
	rep, err := Compute(buildReader(t, events), nil)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if rep.Steps != 10 {
		t.Errorf("Steps = %d, want 10 (R18: max(attribution.step) across the run, not the last decision.Step seen)", rep.Steps)
	}
}

// TestComputeCostNilPrices pins the p==nil half of R20/E15 with actual usage on the ledger. Compute's
// own doc comment states the contract: "p may be nil, in which case every cost is 0 and Unpriced
// counts the responses." E15 adds that "tokens (R1) are unaffected either way" — a missing price table
// must not also blind the token count. TestComputeRules' "R20: tokens sum whatever the price table
// says" case exercises a *non-nil* table with one *unpriced model* in it (the partial-table half of
// E15); it never calls Compute with p itself nil, so the whole-table-missing half of E15 — the literal
// words in Compute's doc comment — had no test pinning it against a ledger that actually carries usage.
func TestComputeCostNilPrices(t *testing.T) {
	usage := &record.Usage{Input: 10, Output: 5, CacheRead: 2, CacheWrite: 1}
	e := &record.Event{MonoNS: 2e9, Kind: record.KindSSLResponse}
	if err := e.SetPayload(record.SSLResponsePayload{Model: "claude-sonnet-4-5-20250929", Status: 200, ParserVersion: "1", Usage: usage}); err != nil {
		t.Fatal(err)
	}
	events := []*record.Event{runStart(1e9), e, runEnd(3e9, record.RunEndExit)}

	rep, err := Compute(buildReader(t, events), nil)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if rep.EstCostUSD != 0 {
		t.Errorf("EstCostUSD = %v, want 0 with a nil Prices (R20/E15)", rep.EstCostUSD)
	}
	if rep.Responses != 1 || rep.Unpriced != 1 {
		t.Errorf("Responses=%d Unpriced=%d, want 1/1: a nil price table must still count the response as unpriced (E15)", rep.Responses, rep.Unpriced)
	}
	if rep.TokensIn != 10 || rep.TokensOut != 5 {
		t.Errorf("tokens = %d/%d, want 10/5: a missing price table must not blind the token count (E15, \"tokens are unaffected either way\")", rep.TokensIn, rep.TokensOut)
	}
	if label := rep.Cost(); label != "$0.00 est. (1 unpriced)" {
		t.Errorf("cost label = %q, want %q", label, "$0.00 est. (1 unpriced)")
	}
}

// TestComputeWallUsesLastEventNotRunEnd pins R21's literal formula: "Wall = last_event.MonoNS -
// run_start.MonoNS if run_end present" — last_event, not run_end itself. Every existing test where
// run_end is present has it double as the chronologically last line, so "last_event.MonoNS" and
// "run_end.MonoNS" have never been made to disagree: a regression that measured Wall to run_end's own
// timestamp instead of the true last event would pass every other case in this package. §6 E5 records
// that a duplicate or out-of-order run_end is a real (if abnormal) ledger shape ("should never happen;
// a bug elsewhere could append twice"); R21 must still report the true span.
func TestComputeWallUsesLastEventNotRunEnd(t *testing.T) {
	events := []*record.Event{
		runStart(1e9),
		fsAction(2e9, record.Unattributed()),
		runEnd(3e9, record.RunEndExit),
		fsAction(9e9, record.Unattributed()), // anomalous: an event stamped after run_end
	}
	rep, err := Compute(buildReader(t, events), nil)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if !rep.Ended {
		t.Fatal("Ended = false, want true: the run_end line was read")
	}
	if rep.Wall != 8*time.Second {
		t.Errorf("Wall = %s, want 8s (9s last event - 1s run_start; run_end's own 3s must not cap it, R21)", rep.Wall)
	}
}
