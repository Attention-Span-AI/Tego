// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/cli"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestCustomAgentExampleMetersEveryBudget pins what makes examples/agents/custom-agent.yaml a contract for a run nobody
// watches (test/poc/custom-agent, docs/OPERATIONS.md, "Unattended runs"): every budget dimension has a value, the model's traffic
// goes through the forwarder, so that the budgets that read it (tokens, cost_usd, repeats) have something to count, and
// no way around the forwarder is left open. A budget with nothing to count is reported [budget-unmetered] at compile
// and refused at launch, exit 125, but compile reports it as a warning and still exits 0, so a copy that loses its
// `models:` entry would still compile; this test is what notices.
func TestCustomAgentExampleMetersEveryBudget(t *testing.T) {
	path := place(t, "custom-agent.yaml")
	var out, errb bytes.Buffer
	if code := cli.Main([]string{"tego", "compile", path, "--offline", "--json"}, &out, &errb); code != identity.ExitOK {
		t.Fatalf("tego compile custom-agent.yaml: exit %d:\n%s", code, errb.String())
	}
	var c struct {
		Capture string         `json:"capture"`
		Record  string         `json:"record"`
		Limits  map[string]any `json:"limits"`
	}
	if err := json.Unmarshal(out.Bytes(), &c); err != nil {
		t.Fatalf("compile --json: %v\n%s", err, out.String())
	}
	if c.Capture != "forwarder" {
		t.Errorf("capture %q, want forwarder: the model's traffic is what tokens, cost_usd and repeats count", c.Capture)
	}
	if c.Record != "full" {
		t.Errorf("record %q, want full: under summary a quiet reader is silent, and stall_after ends it", c.Record)
	}
	for _, k := range []string{"wall", "stall_after", "repeats", "tokens", "cost_usd", "memory", "pids", "cpu"} {
		if c.Limits[k] == nil {
			t.Errorf("limits.%s is not set: a night without it has nothing to stop that failure", k)
		}
	}
	// cost_usd needs the machine's price table, which this stand-in machine has not (its own warning, which the other
	// examples draw too); a budget with no model traffic to count is another, and one the example must not draw.
	for _, never := range []string{"no models: endpoint is declared", "no model traffic is metered"} {
		if strings.Contains(errb.String(), never) {
			t.Errorf("compile warns that a budget counts nothing (%q):\n%s", never, errb.String())
		}
	}
	requireDirectConnectRefused(t, "custom-agent.yaml")
}
