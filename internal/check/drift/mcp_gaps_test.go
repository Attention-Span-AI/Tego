// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/gaps"
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// nopAnchor keeps these tests out of the host-wide chain.log.
type nopAnchor struct{}

func (nopAnchor) Append(string, string) error       { return nil }
func (nopAnchor) Head(string) (string, bool, error) { return "", false, nil }

// mcpTable declares two MCP servers and nothing else, so only R15 can make a report drift.
func mcpTable() *agent.RuleTable {
	return &agent.RuleTable{Contract: &agent.Contract{
		Name: "tester",
		MCP:  []agent.MCPServer{{Name: "fs"}, {Name: "postgres"}},
	}}
}

// mcpRun writes one run whose run_start carries parsers and whose body is the given events, and
// computes its drift report against mcpTable.
func mcpRun(t *testing.T, parsers map[string]string, body ...*record.Event) *Report {
	t.Helper()
	return mcpRunWith(t, mcpTable(), parsers, body...)
}

// mcpRunWith is mcpRun against the given table.
func mcpRunWith(t *testing.T, rt *agent.RuleTable, parsers map[string]string, body ...*record.Event) *Report {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "r-00000000-000000000000a-aaaaaa")
	w, err := ledger.Open(dir, record.RunRef{ID: filepath.Base(dir), Agent: "tester"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"/bin/true"}, Tier: "landlock", Parsers: parsers}); err != nil {
		t.Fatalf("run_start: %v", err)
	}
	for _, e := range body {
		if err := w.Append(e); err != nil {
			t.Fatalf("append %s: %v", e.Kind, err)
		}
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatalf("close: %v", err)
	}
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	rep, err := Compute(r, rt)
	if err != nil {
		t.Fatalf("compute: %v", err)
	}
	return rep
}

// mcpEvent is one mcp event naming a declared server.
func mcpEvent(t *testing.T, name string) *record.Event {
	t.Helper()
	e := &record.Event{
		Kind: record.KindMCP, Source: record.SourceSupervisor, PID: 1, TID: 1,
		Rule: "mcp[" + name + "]", Verdict: record.VerdictAllow, Authority: record.AuthorityRule,
		Attr: &record.Attribution{Confidence: "unattributed", Method: "none"},
	}
	if err := e.SetPayload(record.MCPPayload{Name: name, Transport: "stdio"}); err != nil {
		t.Fatal(err)
	}
	return e
}

// gapEvent is one gap event.
func gapEvent(t *testing.T, p record.GapPayload) *record.Event {
	t.Helper()
	e := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor, PID: 1, TID: 1}
	if err := e.SetPayload(p); err != nil {
		t.Fatal(err)
	}
	return e
}

// TestMCPWithoutProducerIsUnobservable: a run whose record names no MCP producer and
// holds no mcp event cannot say whether a declared server started, so its servers are reported as
// unobservable and the report is not drift. Before the fix both servers read as unused and every
// real run that declared mcp[] exited 1.
func TestMCPWithoutProducerIsUnobservable(t *testing.T) {
	for _, parsers := range []map[string]string{nil, {"anthropic": "1"}, {"mcp": "0"}, {"mcp": ""}} {
		rep := mcpRun(t, parsers)
		if len(rep.UnusedMCP) != 0 {
			t.Errorf("parsers %v: UnusedMCP = %v, want none: nothing could have recorded a server start", parsers, rep.UnusedMCP)
		}
		if want := []string{"mcp[fs]", "mcp[postgres]"}; !slices.Equal(rep.UnobservableMCP, want) {
			t.Errorf("parsers %v: UnobservableMCP = %v, want %v", parsers, rep.UnobservableMCP, want)
		}
		if rep.Drifted() {
			t.Errorf("parsers %v: a report whose only finding is an unobservable server must not drift", parsers)
		}
	}
}

// TestMCPWithProducerIsUnused: once run_start names an MCP producer, a declared server with no mcp
// event is unused (R15) and the report drifts.
func TestMCPWithProducerIsUnused(t *testing.T) {
	rep := mcpRun(t, map[string]string{"mcp": "1"})
	if want := []string{"mcp[fs]", "mcp[postgres]"}; !slices.Equal(rep.UnusedMCP, want) {
		t.Fatalf("UnusedMCP = %v, want %v", rep.UnusedMCP, want)
	}
	if len(rep.UnobservableMCP) != 0 || !rep.Drifted() {
		t.Fatalf("unobservable %v, drifted %v", rep.UnobservableMCP, rep.Drifted())
	}
}

// TestMCPEventProvesAProducer: an mcp event is itself proof a producer ran, so a sibling server
// with none is unused even when run_start names no producer.
func TestMCPEventProvesAProducer(t *testing.T) {
	rep := mcpRun(t, nil, mcpEvent(t, "fs"))
	if want := []string{"mcp[postgres]"}; !slices.Equal(rep.UnusedMCP, want) {
		t.Fatalf("UnusedMCP = %v, want %v", rep.UnusedMCP, want)
	}
	if len(rep.UnobservableMCP) != 0 {
		t.Fatalf("UnobservableMCP = %v, want none", rep.UnobservableMCP)
	}
}

// TestAggregateKeepsOneBlindRunOpen is R17 with R15's third state: a server one run could not
// observe and another left unused is unobservable for the agent, not unused, and a server some run
// used is neither.
func TestAggregateKeepsOneBlindRunOpen(t *testing.T) {
	blind := mcpRun(t, nil)
	seen := mcpRun(t, map[string]string{"mcp": "1"}, mcpEvent(t, "fs"))
	agg, err := Aggregate([]*Report{blind, seen})
	if err != nil {
		t.Fatal(err)
	}
	if len(agg.UnusedMCP) != 0 {
		t.Errorf("UnusedMCP = %v, want none: the blind run may have used postgres", agg.UnusedMCP)
	}
	if want := []string{"mcp[postgres]"}; !slices.Equal(agg.UnobservableMCP, want) {
		t.Errorf("UnobservableMCP = %v, want %v", agg.UnobservableMCP, want)
	}
	both := mcpRun(t, map[string]string{"mcp": "1"})
	agg, err = Aggregate([]*Report{both, mcpRun(t, map[string]string{"mcp": "1"})})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"mcp[fs]", "mcp[postgres]"}; !slices.Equal(agg.UnusedMCP, want) || len(agg.UnobservableMCP) != 0 {
		t.Errorf("two observing runs: unused %v, unobservable %v", agg.UnusedMCP, agg.UnobservableMCP)
	}
}

// TestComputeCarriesTheGapLine is R34 for drift: the run's gap events reach the report, and an
// aggregated report sums them.
// (limits-check-doctor-cli.md R34.)
func TestComputeCarriesTheGapLine(t *testing.T) {
	one := mcpRun(t, map[string]string{"mcp": "1"},
		gapEvent(t, record.GapPayload{What: "record", Why: "channel-full", Count: 4}))
	two := mcpRun(t, map[string]string{"mcp": "1"},
		gapEvent(t, record.GapPayload{What: "record", Why: "channel-full", Count: 6}),
		gapEvent(t, record.GapPayload{What: "capture", Why: "no-openssl", Binary: "/usr/bin/gh"}))
	if want := []gaps.Count{{What: "record", Why: "channel-full", Events: 1, Lost: 4}}; !reflect.DeepEqual(one.Gaps, want) {
		t.Fatalf("gaps = %+v, want %+v", one.Gaps, want)
	}
	agg, err := Aggregate([]*Report{one, two})
	if err != nil {
		t.Fatal(err)
	}
	want := []gaps.Count{
		{What: "capture", Why: "no-openssl", Events: 1, Binaries: []string{"/usr/bin/gh"}},
		{What: "record", Why: "channel-full", Events: 2, Lost: 10},
	}
	if !reflect.DeepEqual(agg.Gaps, want) {
		t.Fatalf("aggregate gaps = %+v\nwant %+v", agg.Gaps, want)
	}
}
