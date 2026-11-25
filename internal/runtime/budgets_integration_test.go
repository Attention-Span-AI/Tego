// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// loopCalls is how many calls the model-agent is told to make in the budget tests: far more than any
// ceiling here allows, so a run that ends with 124 was stopped by the budget and did not simply finish.
const loopCalls = 200

// writeMachineConfigWith is writeMachineConfig plus extra top-level YAML lines.
func writeMachineConfigWith(t *testing.T, f *fixture, extra string) string {
	t.Helper()
	path := writeMachineConfig(t, f)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(b, []byte(extra)...), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// runModelAgent drives the real CLI over the model-agent against the upstream, as a user would, and
// returns tego's exit code, its combined output and the run's events.
func runModelAgent(t *testing.T, f *fixture, cfg, agentBin, caFile string) (int, string, []*record.Event, string) {
	t.Helper()
	bin := tegoBinary(t)
	run := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"), "--", agentBin)
	run.Dir = f.dir
	run.Env = append(os.Environ(), "TEGO_CONFIG="+cfg, "SSL_CERT_FILE="+caFile,
		"MODEL_CALLS="+strconv.Itoa(loopCalls))
	out, err := run.CombinedOutput()
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v, want one\n%s", dirs, out)
	}
	return exitCodeOf(t, err), string(out), events(t, dirs[0]), filepath.Base(dirs[0])
}

// assertStoppedBy checks: exit 124, one limit event naming the ceiling, run_end reason=limit, and that the limit line
// follows model traffic the run captured (every budget here is counted from it). It does not bound the calls the
// agent made altogether: the stop is a kill that lands after the limit line, and a stand-in agent that answers
// instantly can make every call it was told to in that time (seen once under load, 200 of 200). That the budget
// stopped the run at the right place is each caller's assertion, from the limit payload and the lines before the
// limit line, which do not depend on how fast the agent loops.
func assertStoppedBy(t *testing.T, code int, out string, evs []*record.Event, which string) record.LimitPayload {
	t.Helper()
	if code != identity.ExitLimit {
		t.Fatalf("tego run exited %d, want %d\n%s", code, identity.ExitLimit, out)
	}
	lim := limitEvent(t, evs)
	if lim.Which != which {
		t.Fatalf("limit payload %+v, want %s", lim, which)
	}
	var end record.RunEndPayload
	if err := evs[len(evs)-1].DecodePayload(&end); err != nil {
		t.Fatal(err)
	}
	if end.Reason != record.RunEndLimit || end.ExitCode != identity.ExitLimit {
		t.Fatalf("run_end %+v, want limit/124", end)
	}
	if n := responsesBeforeLimit(evs); n < 1 {
		t.Fatalf("the limit line stands before any captured response: %v", kinds(evs))
	}
	return lim
}

// TestIntegrationRepeatsStopALoopingAgent is the repeat detector on real model traffic: the
// model answers every call with the same tool_use, the forwarder captures each exchange, derive turns
// each response into a decision with the tool and the hash of its input, and limits.repeats: 3 stops the
// run on the third identical decision, with exit 124 and a limit event.
//
// The tool_use ids differ call to call, as a real model's do; R5 compares the tool and the input bytes,
// never the id, so that is no escape from the detector.
func TestIntegrationRepeatsStopALoopingAgent(t *testing.T) {
	agentBin := modelAgentBinary(t)
	host, port, caFile := modelUpstreamAnswering(t,
		`[{"type":"tool_use","id":"toolu_01","name":"read_file","input":{"path":"notes.txt"}}]`, "tool_use")
	f := newFixture(t, modelContract("irepeats", agentBin, host, port, "\n  repeats: 3"))
	// A price table path that does not exist, so the run records exactly one price gap whatever the
	// invoking user has installed in ~/.tego, and the assertion below can count it.
	missing := filepath.Join(t.TempDir(), "no-prices.yaml")
	cfg := writeMachineConfigWith(t, f, "prices: "+missing+"\n")

	code, out, evs, _ := runModelAgent(t, f, cfg, agentBin, caFile)
	lim := assertStoppedBy(t, code, out, evs, record.LimitRepeats)
	if lim.Value != 3 || lim.Ceiling != 3 {
		t.Fatalf("limit payload %+v, want repeats 3 at a ceiling of 3", lim)
	}
	// The watcher trips on the decision that crosses and the limit line follows that decision's own line, so exactly
	// three decisions stand before it. That is the product's meaning of repeats: 3, whatever the agent does while the
	// kill lands.
	if n := decisionsBeforeLimit(evs); n != 3 {
		t.Fatalf("%d decisions before the limit line, want 3: the third identical one crossed the ceiling", n)
	}
	var decisions int
	for _, e := range evs {
		if e.Kind != record.KindDecision {
			continue
		}
		var p record.DecisionPayload
		if err := e.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.Tool != "read_file" || p.InputHash == "" {
			t.Fatalf("decision %+v, want the looping read_file call with its input hash", p)
		}
		decisions++
	}
	if decisions < 3 {
		t.Fatalf("%d decisions in the ledger, want at least the 3 that crossed the ceiling", decisions)
	}
	// E15 with R32: no table is one gap for the run, not one from the CLI and another from the watcher.
	if n := priceTableGaps(t, evs); n != 1 {
		t.Fatalf("%d price-table gaps, want exactly one", n)
	}
}

// TestIntegrationACostBudgetStopsTheRun: a $25 budget stops a run with exit 124
// and a limit event. The price table makes each captured response cost $14 (40 input tokens at
// $100,000/MTok, 20 output at $500,000/MTok — prices chosen so the arithmetic is exact, not realistic),
// so the second response crosses cost_usd: 25 (R2).
//
// It also checks the own log: the runtime's "budget crossed" line reaches tego.log tagged with the run id,
// which is Deps.Logger wired end to end through the CLI.
func TestIntegrationACostBudgetStopsTheRun(t *testing.T) {
	agentBin := modelAgentBinary(t)
	host, port, caFile := modelUpstream(t)
	f := newFixture(t, modelContract("icost", agentBin, host, port, "\n  cost_usd: 25"))
	pricesDir := t.TempDir()
	// The price table follows the machine config's trust rule: no group-writable directory (umask 002).
	if err := os.Chmod(pricesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	prices := filepath.Join(pricesDir, "prices.yaml")
	table := "version: 1\nmodels:\n  claude-test-1:\n    input_per_mtok: 100000\n    output_per_mtok: 500000\n"
	if err := os.WriteFile(prices, []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := writeMachineConfigWith(t, f, "prices: "+prices+"\n")

	code, out, evs, runID := runModelAgent(t, f, cfg, agentBin, caFile)
	lim := assertStoppedBy(t, code, out, evs, record.LimitCostUSD)
	if lim.Ceiling != 25 || lim.Value < 27.99 || lim.Value > 28.01 {
		t.Fatalf("limit payload %+v, want $28 (two responses) over a ceiling of $25", lim)
	}
	if n := priceTableGaps(t, evs); n != 0 {
		t.Fatalf("%d price-table gaps in a run whose table loaded", n)
	}
	assertOwnLogNames(t, f, runID, "run: budget crossed")
}

// priceTableGaps counts the gaps saying the run has no usable price table.
func priceTableGaps(t *testing.T, evs []*record.Event) int {
	t.Helper()
	n := 0
	for _, e := range evs {
		if e.Kind != record.KindGap {
			continue
		}
		var p record.GapPayload
		if err := e.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.Why == "no-price-table" || p.Why == "price-table-version-mismatch" {
			n++
		}
	}
	return n
}

// assertOwnLogNames finds a line carrying run=<runID> and msg in the own log of the binary the fixture ran,
// rotated or not: <f.logHome>/.tego/tego.log, where writeMachineConfig points the tegotesthooks build. It
// read the invoking user's real ~/.tego/tego.log once, which every run of this test appended to.
func assertOwnLogNames(t *testing.T, f *fixture, runID, msg string) {
	t.Helper()
	if f.logHome == "" {
		t.Fatal("the fixture has no own-log home: writeMachineConfig was not called")
	}
	var seen []string
	for _, suffix := range []string{"", ".1"} {
		b, err := os.ReadFile(filepath.Join(f.logHome, ".tego", "tego.log"+suffix))
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(b), "\n") {
			if strings.Contains(l, "run="+runID) {
				seen = append(seen, l)
				if strings.Contains(l, msg) {
					return
				}
			}
		}
	}
	t.Fatalf("no %q line for run %s in %s/.tego/tego.log; the run's lines there: %q", msg, runID, f.logHome, seen)
}

// TestIntegrationABudgetWindowCarriesAcrossRuns is the restart row (AO-7) on the real CLI and a real kernel: the model-agent answers 60 tokens
// a call, `tokens: 150, window: 24h`. The first run makes two calls (120 tokens, under the ceiling) and ends 0. A
// restart of the same contract, which without a window would make three calls before it crossed 150, is ended at its
// first response (120 + 60 = 180), exit 124, with the gap that says it counted an earlier run; a third start while no run
// is live reads both and is ended at its first response again.
func TestIntegrationABudgetWindowCarriesAcrossRuns(t *testing.T) {
	agentBin := modelAgentBinary(t)
	host, port, caFile := modelUpstream(t)
	f := newFixture(t, modelContract("iwindow", agentBin, host, port, "\n  tokens: 150\n  window: 24h"))
	missing := filepath.Join(t.TempDir(), "no-prices.yaml")
	cfg := writeMachineConfigWith(t, f, "prices: "+missing+"\n")
	start := func(calls int) (int, string, []*record.Event) {
		t.Helper()
		run := exec.Command(tegoBinary(t), "run", filepath.Join(f.dir, "agent.yaml"), "--", agentBin)
		run.Dir = f.dir
		run.Env = append(os.Environ(), "TEGO_CONFIG="+cfg, "SSL_CERT_FILE="+caFile, "MODEL_CALLS="+strconv.Itoa(calls))
		out, err := run.CombinedOutput()
		dirs := runDirs(t, f.root)
		if len(dirs) == 0 {
			t.Fatalf("no run directory\n%s", out)
		}
		return exitCodeOf(t, err), string(out), events(t, dirs[len(dirs)-1])
	}
	code, out, evs := start(2)
	if code != 0 {
		t.Fatalf("the first run exited %d, want 0 (120 tokens under 150)\n%s", code, out)
	}
	if n := windowGaps(t, evs); n != 0 {
		t.Fatalf("the first run, with nothing before it, wrote %d window-carried gaps", n)
	}
	for i := 2; i <= 3; i++ {
		code, out, evs = start(loopCalls)
		lim := assertStoppedBy(t, code, out, evs, record.LimitTokens)
		if lim.Ceiling != 150 || lim.Value < 180 {
			t.Fatalf("run %d: limit %+v, want tokens at 180 or more over 150: the earlier runs were not counted", i, lim)
		}
		if n := responsesBeforeLimit(evs); n > 2 {
			t.Fatalf("run %d: %d responses were recorded before the limit: without the carried spend it would have taken three to cross", i, n)
		}
		if n := windowGaps(t, evs); n != 1 {
			t.Fatalf("run %d wrote %d window-carried gaps, want 1", i, n)
		}
	}
}

// responsesBeforeLimit counts the ssl_response lines that stand before the first limit line in a run's ledger. The
// limit line follows the response that crossed (the watcher trips on that response, on the pipeline's own goroutine), so
// this is the number of responses it took to cross. It is not the number of calls the agent made: the stop is a kill,
// and an agent that loops makes more calls in the time that takes, which the ledger records after the limit line. Counting
// every response would fail a run that was stopped at the right one (seen once in five on a host).
func responsesBeforeLimit(evs []*record.Event) int {
	n := 0
	for _, e := range evs {
		switch e.Kind {
		case record.KindSSLResponse:
			n++
		case record.KindLimit:
			return n
		}
	}
	return n
}

// decisionsBeforeLimit counts the decision lines that stand before the first limit line in a run's ledger.
func decisionsBeforeLimit(evs []*record.Event) int {
	n := 0
	for _, e := range evs {
		switch e.Kind {
		case record.KindDecision:
			n++
		case record.KindLimit:
			return n
		}
	}
	return n
}

// windowGaps counts the gaps what=limits why=window-carried in a run's ledger.
func windowGaps(t *testing.T, evs []*record.Event) int {
	t.Helper()
	n := 0
	for _, e := range evs {
		if e.Kind != record.KindGap {
			continue
		}
		var p record.GapPayload
		if err := e.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if p.What == record.GapLimits && p.Why == GapWindowCarried {
			n++
		}
	}
	return n
}

// TestResponsesBeforeLimitCountsToTheLimitLine: the responses that stand after the limit line are an agent's calls
// while the kill landed, not the ones it took to cross.
func TestResponsesBeforeLimitCountsToTheLimitLine(t *testing.T) {
	ev := func(k record.Kind) *record.Event { return &record.Event{Kind: k} }
	for _, c := range []struct {
		name string
		evs  []*record.Event
		want int
	}{
		{"crossed at the first, two more calls while the kill landed",
			[]*record.Event{ev(record.KindSSLRequest), ev(record.KindSSLResponse), ev(record.KindLimit), ev(record.KindSSLRequest),
				ev(record.KindSSLResponse), ev(record.KindSSLResponse)}, 1},
		{"crossed at the third", []*record.Event{ev(record.KindSSLResponse), ev(record.KindSSLResponse), ev(record.KindSSLResponse),
			ev(record.KindLimit)}, 3},
		{"no limit line: every response", []*record.Event{ev(record.KindSSLResponse), ev(record.KindSSLResponse)}, 2},
	} {
		if got := responsesBeforeLimit(c.evs); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}

// TestDecisionsBeforeLimitCountsToTheLimitLine: decisions that stand after the limit line are the agent's calls while
// the kill landed.
func TestDecisionsBeforeLimitCountsToTheLimitLine(t *testing.T) {
	ev := func(k record.Kind) *record.Event { return &record.Event{Kind: k} }
	d, l := ev(record.KindDecision), ev(record.KindLimit)
	if got := decisionsBeforeLimit([]*record.Event{d, d, d, l, d, d}); got != 3 {
		t.Errorf("%d, want 3", got)
	}
	if got := decisionsBeforeLimit([]*record.Event{d, d, d, d, l}); got != 4 {
		t.Errorf("%d, want 4", got)
	}
}
