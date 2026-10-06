// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestKT5HarnessMeasuresWhatFeaturesR7Says pins docs/FEATURES.md's "Kill test 5 (R7)" (docs/p0/supervisor.md
// §10 "E2E") to the harness that measures it: test/e2e/kt5-ask.sh declares one fs.ask and one net.ask entry the
// workload never touches, compares the run with the same contract without them on the 20-step agent and on the
// build workload (kill test 2's agent and kill test 4's pip kind), judges the median of ten runs of each against
// the larger of 1% of the base run's wall time and one second, reads run_end's supervisor block, and prints a miss as
// TARGET-MISS, not as a number moved. A harness that drifted from these would report a pass the requirement does not give.
// (The measured result, per tier, is the matrix's: test/vm/README.md.)
func TestKT5HarnessMeasuresWhatFeaturesR7Says(t *testing.T) {
	spec, err := os.ReadFile("../../docs/FEATURES.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"**Kill test 5 (R7)**",
		"one `fs.ask` and one `net.ask` entry the workload never touches",
		"under 1% of wall time or 1 s, whichever is larger",
		"on the 20-step agent and on the build workload, in every tier",
		"`supervisor{notifications, held_ms}`",
	} {
		if !strings.Contains(string(spec), want) {
			t.Errorf("docs/FEATURES.md no longer says %q, which kt5-ask.sh measures", want)
		}
	}
	b, err := os.ReadFile("kt5-ask.sh")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for name, re := range map[string]string{
		"median of ten":           `KT5_RUNS="\$\{KT5_RUNS:-10\}"`,
		"1% rounded up":           `one_percent=\$\(\(\(\$1 \+ 99\) / 100\)\)`,
		"or a second, the larger": `echo \$\(\(one_percent > 1000 \? one_percent : 1000\)\)`,
		"not under the budget":    `\[ "\$delta" -ge "\$budget" \]`,
		"a miss is TARGET-MISS":   `FAIL "TARGET-MISS `,
		"the 20-step agent":       `kinds="\$\{KT5_KINDS:-agent20 pip\}"`,
		"kill test 2's agent":     `test/workloads/python-steps/agent\.py`,
		"kill test 4's pip":       `test/workloads/build/python/run\.sh`,
		"one fs.ask entry":        `\[ "\$variant" != ask \] \|\| echo "  ask: \[\\"\$never/\\"\]"`,
		"one net.ask entry":       `\[ "\$variant" != ask \] \|\| echo "  ask: \[\\"\$ASK_NET\\"\]"`,
		"the supervisor block":    `\$e\.supervisor\.notifications`,
		"held_ms":                 `\$e\.supervisor\.held_ms`,
		"untouched entries":       `select\(\.kind == "ask" or \.kind == "answer"\)`,
		"the ask machinery live":  `\$s\.capabilities\.ask`,
		"every tier":              `tiers="landlock cgroup"`,
		"tier bpflsm":             `tiers="\$tiers bpflsm"`,
	} {
		if !regexp.MustCompile(re).MatchString(src) {
			t.Errorf("kt5-ask.sh no longer has %s (%s)", name, re)
		}
	}
	for _, f := range []string{
		"../workloads/python-steps/agent.py", "../workloads/build/python/run.sh", "../workloads/model-stub/server.py",
	} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("a workload kill test 5 runs is gone: %v", err)
		}
	}
}
