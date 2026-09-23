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

// assertStoppedBy checks the three things P0-DESIGN §12.4 names: exit 124, one limit event naming the
// ceiling, and run_end reason=limit; and that the agent was stopped short of the calls it wanted.
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
	if _, resps := sslPairs(t, evs); len(resps) >= loopCalls {
		t.Fatalf("the agent made all %d calls: the budget did not stop it", len(resps))
	}
	return lim
}

// TestIntegrationRepeatsStopALoopingAgent is P0-DESIGN §12.4's first half on real model traffic: the
// model answers every call with the same tool_use, the forwarder captures each exchange, derive turns
// each response into a decision with the tool and the hash of its input, and limits.repeats: 3 stops the
// run on the third identical decision (limits-check-doctor-cli.md R5), with exit 124 and a limit event.
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

// TestIntegrationACostBudgetStopsTheRun is §12.4's second half: "a $25 budget stops a run with exit 124
// and a limit event". The price table makes each captured response cost $14 (40 input tokens at
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
