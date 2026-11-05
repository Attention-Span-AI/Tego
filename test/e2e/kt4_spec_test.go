// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/internal/testutil/contracttest"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
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

// The review's ancestor/exchange counterexample needs a new scope at a/target. After the
// rollback, that future name is uncovered at both places: declaring the write must not
// introduce a new protection promise which the ancestor move silently removes.
func TestCoverageRollbackAncestorCounterexample(t *testing.T) {
	f := contracttest.Build(t, "version: 0\nname: ancestor\ncommand: [fixture]\nfs:\n  write: [work/, work/a/target/]\n", contracttest.Tree{
		"work/a/target/": "", "work/b/target/": "",
	})
	names := decide.NewNameIndex(f.Rules)
	for _, rel := range []string{"work/a/target/.env", "work/b/target/.env"} {
		if _, covered := names.Match(f.Path(rel), false); covered {
			t.Errorf("write declaration introduced coverage in review counterexample: %s", rel)
		}
	}
	for _, ends := range [][2]string{{"work/a", "work/b"}, {"work/b", "work/a"}} {
		if m, refused := names.MoveRefused(f.Path(ends[0]), f.Path(ends[1])); refused {
			t.Errorf("unchanged outer coverage should permit ancestor/exchange arm: %+v", m)
		}
	}
}

// Keep the exact future declared-pattern example honest. Root name entries refuse the
// directory move. Landlock held reads refuse the original name, but do not track an as-yet
// unpinned future object moved outside the pattern: this is the pre-existing A11 limit,
// not a guarantee supplied by the reverted built-in-only directory guard.
func TestCoverageRollbackDeclaredPatternCounterexample(t *testing.T) {
	f := contracttest.Build(t, "version: 0\nname: declared\ncommand: [fixture]\nfs:\n  write: [work/]\n  reads: held\n  deny_read: [work/private/*/token.key]\n", contracttest.Tree{
		"work/private/pkg/": "", "work/public/": "",
	})
	from, to := f.Path("work/private/pkg"), f.Path("work/public/pkg")
	held := decide.NewHeldReadIndex(f.Rules)
	if _, refused := held.Refusal(nil, filepath.Join(from, "token.key"), false); !refused {
		t.Fatal("declared future name lost its held-read check")
	}
	if _, refused := held.Refusal(nil, filepath.Join(to, "token.key"), false); refused {
		t.Fatal("fixture no longer isolates the unpinned out-of-pattern residual")
	}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		a := agent.Action{Kind: agent.ActionFSRename, Path: from, DestPath: to, Dir: true}
		got := decide.Evaluate(f.Rules, a, tier)
		want := agent.VerdictRefused
		if tier == backend.TierLandlock {
			want = agent.VerdictAllow
		}
		if indexed := decide.NewEvaluator(f.Rules).Evaluate(a, tier); got.Verdict != want || indexed != got {
			t.Errorf("%s: reference %+v indexed %+v; want %s", tier, got, indexed, want)
		}
	}
}

// Pip moves its scripts directory from a temporary install into its destination. Both places must keep
// the built-in name protections: ADR 0043 D5 correctly refuses a move that loses .env coverage, even if
// pip recovers by copying. R18 counts that refusal as broken work.
func TestKT4PipRenamePreservesNameCoverage(t *testing.T) {
	b, err := os.ReadFile("kt4-ordinary.sh")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	start := strings.Index(src, "prepare_pip() {")
	if start < 0 {
		t.Fatal("no pip preparation in the harness")
	}
	end := strings.Index(src[start:], "\n}\n")
	if end < 0 {
		t.Fatal("unterminated pip preparation")
	}
	work := t.TempDir()
	for _, dir := range []string{"write", "deps/pip-bootstrap", "deps/wheelhouse"} {
		if err := os.MkdirAll(filepath.Join(work, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	prepare := `set -eu
work="$1"; W="$work/write"; repo="$2"; fixture="$work/deps"
kt_pydeps() { echo "$fixture"; }
` + src[start:start+end+3] + `
prepare_pip
printf '%s\n' "${cmd[4]}" "${cmd[5]}"
`
	cmd := exec.Command("bash", "-c", prepare, "pip-prepare", work, "../..")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("prepare pip: %v: %s", err, out)
	}
	paths := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(paths) != 2 {
		t.Fatalf("pip target and temporary directory: %q", out)
	}
	if filepath.Base(paths[0]) != "target" {
		t.Fatalf("limit fixture no longer tests --target ./target: %s", paths[0])
	}
	from, to := filepath.Join(paths[1], "pip-target-random", "bin"), filepath.Join(paths[0], "bin")
	contract := fmt.Sprintf("version: 0\nname: pip\ncommand: [fixture]\nfs:\n  write: [%q, %q, %q]\n", filepath.Join(work, "write"), paths[1], paths[0])
	// Declaring both ends alone is not a remedy on master: keep this limit explicit.
	f := contracttest.BuildAt(t, work, contract, nil)
	if _, refused := decide.NewNameIndex(f.Rules).MoveRefused(from, to); !refused {
		t.Fatal("original --target ./target limit disappeared from the broad-parent/cwd contract")
	}
	// The tested remedy also launches from the pre-created target. The contract stays outside W.
	f = contracttest.BuildAt(t, work, contract, nil, agent.WithCwd(paths[0]))
	names := decide.NewNameIndex(f.Rules)
	if m, refused := names.MoveRefused(from, to); refused {
		t.Errorf("target-cwd remedy loses name protection: %+v", m)
	}
	for _, dir := range []string{from, to} {
		if _, covered := names.Match(filepath.Join(dir, ".env"), false); !covered {
			t.Errorf("remedy's directory %s escapes built-in .env protection", dir)
		}
	}
	for _, check := range []string{"check_pip_limit", "last-refusal.json", `fs.write: ["./tmp/", "./target/"]`, "name-move-$tier", `cwd="$W/target"`, "prep=(site-packages)", `[ "$tier" = landlock ] || check_pip_limit`} {
		if !strings.Contains(src, check) {
			t.Errorf("KT4 no longer checks the limit and working remedy: %s", check)
		}
	}
}
