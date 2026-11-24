// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

func TestBaselineAppliedModeMatrix(t *testing.T) {
	type input struct {
		name, contractTier, machineTier string
		observe                         bool
		flag                            backend.Tier
		record                          RecordMode
	}
	var cases []input
	for _, tier := range []string{"auto", "landlock", "cgroup", "bpflsm"} {
		for _, observe := range []bool{false, true} {
			cases = append(cases, input{name: fmt.Sprintf("contract %s observe %t", tier, observe), contractTier: tier, observe: observe})
		}
	}
	for _, tier := range []string{"landlock", "cgroup", "bpflsm"} {
		for _, observe := range []bool{false, true} {
			cases = append(cases, input{name: fmt.Sprintf("machine %s observe %t", tier, observe), machineTier: tier, observe: observe})
		}
		cases = append(cases, input{name: "launcher tier " + tier, flag: backend.Tier(tier)})
	}
	for _, record := range []RecordMode{RecordFull, RecordSummary, RecordOff} {
		cases = append(cases, input{name: "record " + string(record), record: record})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			withBaselineEnv(t, f, "TOKEN")
			if tc.machineTier != "" {
				f.machine.Tier.Bounded = true
				f.machine.Tier.Value.Auto, f.machine.Tier.Value.Tier = false, tc.machineTier
			}
			body := "version: 0\nname: baseline-mode\ncommand: [" + filepath.Join(f.bin, "python") + "]\n"
			if tc.contractTier != "" {
				body += "tier: " + tc.contractTier + "\n"
			}
			var opts []CompileOption
			if tc.observe {
				opts = append(opts, WithObserve())
			}
			if tc.flag != "" {
				opts = append(opts, WithTierFlag(tc.flag))
			}
			if tc.record != "" {
				opts = append(opts, WithRecord(tc.record))
			}
			rt, ds, err := Compile(f.load(body), f.machine, f.opts(opts...)...)
			if err != nil {
				t.Fatalf("ordinary mode failed compile: %v %s", err, render(ds))
			}
			if rt.Baseline == nil || rt.Baseline.Applied == tc.observe || len(rt.Baseline.Entries) != 1 {
				t.Fatalf("mode changed baseline application: observe=%t baseline=%+v", tc.observe, rt.Baseline)
			}
		})
	}
	t.Logf("%d ordinary mode inputs: only explicit observation leaves the baseline not applied", len(cases))
}
