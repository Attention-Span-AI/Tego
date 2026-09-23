// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestMeasureRendersAFixtureRun is the P0 column set over the frozen fixture (R18-R23, R31).
func TestMeasureRendersAFixtureRun(t *testing.T) {
	dir := fixtureRun(t)
	code, out, errs := run(t, "measure", dir)
	if code != identity.ExitOK {
		t.Fatalf("exit %d (stderr %q)", code, errs)
	}
	for _, want := range []string{
		"steps", "refused", "tokens in", "tokens out", "cache read", "cache write",
		"cost", "wall", "idle max", "repeats",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the table has no %q column:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "est.") {
		t.Error("the cost is not labelled est.")
	}
	// Once: the value says est., and a label that said it too read "est. cost $0.28 est."
	if n := strings.Count(out, "est."); n != 1 {
		t.Errorf("est. appears %d times:\n%s", n, out)
	}
	if !strings.Contains(out, "58000") || !strings.Contains(out, "2420") {
		t.Errorf("the fixture's token totals are missing:\n%s", out)
	}
}

// TestMeasureJSONIsOneObject covers R31 and E22: one object, one line, the documented keys.
func TestMeasureJSONIsOneObject(t *testing.T) {
	dir := fixtureRun(t)
	code, out, errs := run(t, "measure", dir, "--json")
	if code != identity.ExitOK {
		t.Fatalf("exit %d (stderr %q)", code, errs)
	}
	if n := strings.Count(strings.TrimRight(out, "\n"), "\n"); n != 0 {
		t.Fatalf("--json wrote %d extra lines, want one object on one line", n)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("--json is not one JSON object: %v", err)
	}
	for _, key := range []string{
		"run", "steps", "refused", "tokens_in", "tokens_out", "cache_read", "cache_write",
		"est_cost_usd", "est_cost", "wall_ns", "idle_max_ns", "repeats",
	} {
		if _, ok := got[key]; !ok {
			t.Errorf("--json has no %q key: %s", key, out)
		}
	}
	if got["steps"] != float64(20) || got["refused"] != float64(1) {
		t.Errorf("steps/refused = %v/%v, want 20/1", got["steps"], got["refused"])
	}
	// Repeated invocations must be byte-stable, which is what a jq pipeline depends on.
	_, again, _ := run(t, "measure", dir, "--json")
	if again != out {
		t.Errorf("--json is not deterministic:\n%s\n%s", out, again)
	}
}

// TestMeasureUsage covers R25: the wrong number of arguments is a usage error, exit 2.
func TestMeasureUsage(t *testing.T) {
	for _, args := range [][]string{{"measure"}, {"measure", "a", "b"}} {
		code, _, errs := run(t, args...)
		if code != identity.ExitUsage {
			t.Errorf("%v exited %d, want %d (stderr %q)", args, code, identity.ExitUsage, errs)
		}
	}
}

// TestMeasureMissingRun reports a run directory that is not there as the caller's mistake, a usage error, never as
// an empty report that would read as "this run did nothing".
func TestMeasureMissingRun(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "no-such-run")
	code, _, errs := run(t, "measure", dir)
	if code != identity.ExitUsage {
		t.Fatalf("exit %d, want %d (stderr %q)", code, identity.ExitUsage, errs)
	}
	if !strings.Contains(errs, "measure") {
		t.Errorf("stderr %q does not name the command", errs)
	}
}
