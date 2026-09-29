// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"os"
	"regexp"
	"testing"
)

// TestKT4HarnessMeasuresWhatRuntimeLaunchR24Says pins docs/p0/runtime-launch.md R24 (kill test 4)
// to the harness that measures it: test/e2e/kt4-ordinary.sh runs the pip, npm and go kinds by default, twenty
// runs each under a contract that extends base/python-dev, passes at nineteen of twenty, times the baseline as
// the median of five runs outside tego and calls a run broken past twice that median, and reads a run's
// `refused` events for a declared target. A harness that drifted from these numbers would report a pass the
// spec does not give. (The measured result, and the tier cgroup condition, are the nightly matrix's:
// test/vm/README.md.)
func TestKT4HarnessMeasuresWhatRuntimeLaunchR24Says(t *testing.T) {
	b, err := os.ReadFile("kt4-ordinary.sh")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for name, re := range map[string]string{
		"twenty runs":          `KT4_RUNS="\$\{KT4_RUNS:-20\}"`,
		"median of five":       `KT4_BASE_RUNS=5\b`,
		"nineteen of twenty":   `KT4_THRESHOLD=\$\(\(\(KT4_RUNS \* 19 \+ 19\) / 20\)\)`,
		"twice the median":     `budget_ms="\$\(\(base_median \* 2\)\)"`,
		"over the budget":      `\[ "\$wall" -gt "\$budget_ms" \]`,
		"the three kinds":      `kinds="\$\{KT4_KINDS:-pip npm go\}"`,
		"base/python-dev":      `extends: base/python-dev`,
		"refused declared":     `select\(\.kind == "refused"\)`,
		"tier landlock by def": `tiers="\$\{KT4_TIERS:-landlock\}"`,
	} {
		if !regexp.MustCompile(re).MatchString(src) {
			t.Errorf("kt4-ordinary.sh no longer has %s (%s)", name, re)
		}
	}
	if _, err := os.Stat("../../examples/profiles/base/python-dev.yaml"); err != nil {
		t.Errorf("the profile R24 names is gone: %v", err)
	}
}
