// SPDX-License-Identifier: Apache-2.0

package perf

import (
	"math"
	"strings"
	"testing"
)

func TestEvaluateFailsOverTheLimitAndOnlyReportsATargetMiss(t *testing.T) {
	t.Parallel()
	bs := []Budget{
		{Name: "a", Limit: 100, Target: 50, Unit: "ms"},
		{Name: "b", Limit: 100, Unit: "ms"},
	}
	rs := Evaluate(bs, map[string]float64{"a": 80, "b": 100})
	text, failed := Report(rs)
	if failed {
		t.Fatalf("a value at or under its limit failed:\n%s", text)
	}
	if !strings.Contains(text, "TARGET-MISS") {
		t.Fatalf("a value over its target did not say so:\n%s", text)
	}
	rs = Evaluate(bs, map[string]float64{"a": 80, "b": 100.5})
	if text, failed = Report(rs); !failed || !strings.Contains(text, "OVER") {
		t.Fatalf("a value over its limit passed:\n%s", text)
	}
}

func TestEvaluateFailsACheckThatProducedNoValue(t *testing.T) {
	t.Parallel()
	rs := Evaluate([]Budget{{Name: "a", Limit: 1, Unit: "ms"}}, map[string]float64{})
	if text, failed := Report(rs); !failed || !strings.Contains(text, "MISSING") {
		t.Fatalf("a budget with no measurement passed:\n%s", text)
	}
}

func TestOverrideLowersALimitAndRefusesAnUnknownName(t *testing.T) {
	t.Parallel()
	name := Defaults()[0].Name
	bs, err := Override(Defaults(), []string{name + "=1"})
	if err != nil {
		t.Fatalf("Override: %v", err)
	}
	if bs[0].Limit != 1 {
		t.Fatalf("limit = %v after the override, want 1", bs[0].Limit)
	}
	if _, err := Override(Defaults(), []string{"no.such=1"}); err == nil {
		t.Fatal("an override naming no budget was accepted")
	}
	if _, err := Override(Defaults(), []string{name}); err == nil {
		t.Fatal("an override without a value was accepted")
	}
}

func TestOverrideRefusesNonfiniteLimits(t *testing.T) {
	t.Parallel()
	bs := []Budget{{Name: "elapsed", Limit: 10}}
	for _, value := range []string{"NaN", "Inf", "+Inf", "-Inf", "Infinity", "+Infinity", "-Infinity"} {
		t.Run(value, func(t *testing.T) {
			if _, err := Override(bs, []string{"elapsed=" + value}); err == nil || !strings.Contains(err.Error(), "finite") {
				t.Fatalf("nonfinite limit %q accepted or misreported: %v", value, err)
			}
			if bs[0].Limit != 10 {
				t.Fatal("rejected override mutated the input budget")
			}
		})
	}
}

func TestNonfiniteNumbersCannotPassBudgetReport(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"value", "limit", "target"} {
		for _, number := range []struct {
			name  string
			value float64
		}{{"NaN", math.NaN()}, {"positive_infinity", math.Inf(1)}, {"negative_infinity", math.Inf(-1)}} {
			t.Run(field+"/"+number.name, func(t *testing.T) {
				b, value := Budget{Name: "excess", Limit: 10, Target: 5}, 1.0
				switch field {
				case "value":
					value = number.value
				case "limit":
					b.Limit = number.value
				case "target":
					b.Target = number.value
				}
				rs := Evaluate([]Budget{b}, map[string]float64{b.Name: value})
				text, failed := Report(rs)
				if !failed || !strings.Contains(text, "INVALID") {
					t.Errorf("nonfinite %s did not fail explicitly: failed=%v\n%s", field, failed, text)
				}
				if !rs[0].Present || !rs[0].Over() || rs[0].TargetMiss() {
					t.Errorf("invalid sample must be present, failing, and never a soft miss: %+v", rs[0])
				}
			})
		}
	}
}

func TestFiniteNegativeLimitsAndExcessRemainValid(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		limit, name string
		measurement float64
		wantFail    bool
	}{{"-1", "negative dry-failure control", 0, true}, {"0", "negative measured excess", -1, false}, {"-2", "finite negative budget and measurement", -3, false}} {
		t.Run(tc.name, func(t *testing.T) {
			bs, err := Override([]Budget{{Name: "excess", Limit: 10}}, []string{"excess=" + tc.limit})
			if err != nil {
				t.Fatalf("finite override refused: %v", err)
			}
			text, failed := Report(Evaluate(bs, map[string]float64{"excess": tc.measurement}))
			if failed != tc.wantFail || strings.Contains(text, "INVALID") {
				t.Fatalf("finite verdict=%v want=%v: %s", failed, tc.wantFail, text)
			}
		})
	}
}

func TestDefaultBudgetsAreUniqueAndComplete(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, b := range Defaults() {
		if seen[b.Name] {
			t.Fatalf("budget %s twice", b.Name)
		}
		seen[b.Name] = true
		if (b.Limit <= 0 && !b.Report) || (b.Report && (b.Limit != 0 || b.Target <= 0)) || b.Unit == "" || b.Doc == "" {
			t.Fatalf("budget %+v: want a positive limit, or a report row with a target and no limit, a unit and a doc", b)
		}
	}
}

// TestAReportRowIsNeverOverButMissesItsTarget (ADR 0043 C10): a figure the spec states as "report" fails no run
// whatever its value, prints TARGET-MISS over its target, and still fails when it is missing or not finite; an
// override gives it a limit.
func TestAReportRowIsNeverOverButMissesItsTarget(t *testing.T) {
	t.Parallel()
	bs := []Budget{{Name: "deep", Target: 1000, Report: true, Unit: "ns", Doc: "d"}}
	text, failed := Report(Evaluate(bs, map[string]float64{"deep": 5000}))
	if failed || !strings.Contains(text, "TARGET-MISS") || !strings.Contains(text, "(report target 1000)") {
		t.Fatalf("over its target: failed %v\n%s", failed, text)
	}
	if text, failed = Report(Evaluate(bs, map[string]float64{"deep": 900})); failed || !strings.Contains(text, "BUDGET ok") {
		t.Fatalf("under its target: failed %v\n%s", failed, text)
	}
	for name, got := range map[string]map[string]float64{"missing": {}, "nan": {"deep": math.NaN()}} {
		if text, failed = Report(Evaluate(bs, got)); !failed {
			t.Errorf("%s: a report row passed\n%s", name, text)
		}
	}
	over, err := Override(bs, []string{"deep=10"})
	if err != nil {
		t.Fatal(err)
	}
	if text, failed = Report(Evaluate(over, map[string]float64{"deep": 900})); !failed || !strings.Contains(text, "OVER") {
		t.Fatalf("an overridden report row did not fail over its new limit: failed %v\n%s", failed, text)
	}
}

func TestABootWithoutBPFHasNoLSMModeAndNoBudgetForOne(t *testing.T) {
	t.Parallel()
	ms := ModesFor("lockdown,capability,landlock,yama,apparmor")
	if len(ms) != 2 || ms[1].Plane != "fmod_ret" {
		t.Fatalf("modes without bpf = %+v, want landlock and the fmod_ret plane", ms)
	}
	if got := ModesFor("lockdown,landlock,bpf"); len(got) != len(Modes) {
		t.Fatalf("modes with bpf = %+v", got)
	}
	for _, b := range ForModes(Defaults(), ms) {
		if strings.Contains(b.Name, "bpflsm") || strings.Contains(b.Name, "cgroup-lsm") {
			t.Fatalf("budget %s kept on a boot with no BPF LSM", b.Name)
		}
	}
	if len(ForModes(Defaults(), Modes)) != len(Defaults()) {
		t.Fatal("a boot with every mode dropped a budget")
	}
}

func TestMin(t *testing.T) {
	t.Parallel()
	if got := Min([]float64{5, 2, 9}); got != 2 {
		t.Fatalf("min = %v", got)
	}
	if got := Min(nil); got != 0 {
		t.Fatalf("empty min = %v", got)
	}
}

func TestMedianAndPercentile(t *testing.T) {
	t.Parallel()
	if got := Median([]float64{5, 1, 3}); got != 3 {
		t.Fatalf("median = %v", got)
	}
	if got := Median([]float64{4, 1, 3, 2}); got != 2.5 {
		t.Fatalf("even median = %v", got)
	}
	if got := Percentile([]float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 90); got != 9 {
		t.Fatalf("p90 = %v", got)
	}
	if got := Median(nil); got != 0 {
		t.Fatalf("empty median = %v", got)
	}
}
