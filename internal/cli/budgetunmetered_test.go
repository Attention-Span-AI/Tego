// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// updateGolden rewrites the golden files this package keeps under testdata.
var updateGolden = flag.Bool("update", false, "rewrite the golden files under testdata")

// unmeteredLines is each "never trip(s)" diagnostic in stderr with the fix line under it.
func unmeteredLines(stderr string) string {
	var b strings.Builder
	lines := strings.Split(stderr, "\n")
	for i, l := range lines {
		if !strings.Contains(l, "never trip") {
			continue
		}
		b.WriteString(l + "\n")
		if i+1 < len(lines) && strings.HasPrefix(lines[i+1], "  fix:") {
			b.WriteString(lines[i+1] + "\n")
		}
	}
	return b.String()
}

// TestCompileWarnsUnmeteredBudgets: a tokens, cost_usd or repeats budget with capture: off, or with no models:
// endpoint where the run captures with the forwarder alone, never trips, and compile said nothing. It warned
// [unenforced] at the budget's line while the run went ahead with a limit that did nothing; such a run is now
// refused at launch, and compile reports it [budget-unmetered], saying the run is refused (as it reports a pinned
// tier the build lacks [tier-unavailable]). The golden file holds the lines. A contract that declares its model
// endpoint is not warned, under record: off too unless it pins capture: uprobe, since the forwarder that runs
// beside the probes records under record: off; an auto contract under record: off with no
// models: is told what the run says, the missing endpoint, at any tier.
func TestCompileWarnsUnmeteredBudgets(t *testing.T) {
	t.Setenv("TEGO_CONFIG", "")
	t.Chdir(filepath.Join("testdata", "budget-unmetered"))
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup) // the released build: make build
	var got strings.Builder
	for _, f := range []string{"capture-off.yaml", "no-models.yaml", "no-models-landlock.yaml", "with-models.yaml",
		"record-off-cgroup.yaml", "record-off-auto.yaml", "record-off-models.yaml", "record-off-uprobe.yaml"} {
		code, _, errs := run(t, "compile", f, "--offline")
		if code != identity.ExitOK {
			t.Fatalf("%s: exit %d\n%s", f, code, errs)
		}
		got.WriteString(unmeteredLines(errs))
	}
	golden := filepath.Join("..", "budget-unmetered.golden")
	if *updateGolden {
		if err := os.WriteFile(golden, []byte(got.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got.String() != string(want) {
		t.Errorf("diagnostics drifted from %s:\ngot:\n%s\nwant:\n%s", golden, got.String(), want)
	}
	for _, l := range strings.Split(strings.TrimSpace(got.String()), "\n") {
		if !strings.HasPrefix(l, "  fix:") && (!strings.HasSuffix(l, "is refused [budget-unmetered]") || !strings.HasPrefix(l, "warning: ")) {
			t.Errorf("%q is not a warning saying the run is refused, tagged [budget-unmetered]", l)
		}
	}
}

// TestCompileWarnsABudgetUnderACaptureCeilingOfOff is M1's machine half: a machine config whose capture
// ceiling is off lowers an auto contract to no capture, and its tokens budget never trips. compile names the
// ceiling's line and says a run on this machine is refused.
func TestCompileWarnsABudgetUnderACaptureCeilingOfOff(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("capture: off\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEGO_CONFIG", cfg)
	contract := filepath.Join("testdata", "budget-unmetered", "with-models.yaml")
	code, _, errs := run(t, "compile", contract, "--offline")
	want := contract + ":8:11: limits.tokens budget never trips: the machine's capture ceiling is off (" + cfg +
		":1), so no model traffic is metered, and every run of this contract on this machine is refused [budget-unmetered]"
	if code != identity.ExitOK || !strings.Contains(errs, want) {
		t.Errorf("compile exit %d, stderr lacks %q:\n%s", code, want, errs)
	}
}
