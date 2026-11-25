// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// limits.window makes tokens and cost_usd a total across restarts (ADR 0165). The compile reads it as a duration from a
// minute to 30 days, keeps it only where a token or cost budget is there to count, and says so where it is not.
func TestLimitsWindow(t *testing.T) {
	const base = "version: 0\nname: windowed\ncommand: [\"/bin/sh\"]\ntier: landlock\n"
	for _, tc := range []struct {
		name, limits string
		window       time.Duration
		errContains  string
		errCode      string
		warnNothing  bool
	}{
		{"a day of tokens", "limits: {tokens: 1000, window: 24h}\n", 24 * time.Hour, "", "", false},
		{"a week of cost", "limits: {cost_usd: 5, window: 7d}\n", 7 * 24 * time.Hour, "", "", false},
		{"the shortest", "limits: {tokens: 1, window: 1m}\n", time.Minute, "", "", false},
		{"the longest", "limits: {tokens: 1, window: 30d}\n", 30 * 24 * time.Hour, "", "", false},
		{"no window", "limits: {tokens: 1000}\n", 0, "", "", false},
		{"under a minute", "limits: {tokens: 1000, window: 30s}\n", 0, "outside 1m to 30d", CodeLimitWindowRange, false},
		{"over the retention default", "limits: {tokens: 1000, window: 31d}\n", 0, "outside", CodeLimitWindowRange, false},
		{"nothing to count", "limits: {wall: 1h, window: 24h}\n", 0, "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			if tc.warnNothing {
				// The machine's own ceilings would bound tokens and cost for a contract that sets neither.
				f.machine.Limits.Tokens.Bounded, f.machine.Limits.CostUSD.Bounded = false, false
			}
			if tc.errContains != "" {
				path := filepath.Join(f.project, "agent.yaml")
				f.file(path, base+tc.limits, 0o644)
				_, ds, err := Load(path, f.profiles())
				found := false
				for _, d := range ds {
					found = found || (d.IsError() && d.Code == tc.errCode && strings.Contains(d.Message, tc.errContains))
				}
				if err == nil || !found {
					t.Fatalf("err %v; no error %s naming %q:\n%s", err, tc.errCode, tc.errContains, render(ds))
				}
				return
			}
			rt, ds := f.compile(f.load(base + tc.limits))
			if rt == nil {
				t.Fatalf("no table:\n%s", render(ds))
			}
			if got := rt.Limits.Window; got != tc.window {
				t.Fatalf("window = %v, want %v", got, tc.window)
			}
			nothing := false
			for _, d := range ds {
				nothing = nothing || (d.Code == CodeRedundantRule && strings.Contains(d.Message, "limits.window"))
			}
			if nothing != tc.warnNothing {
				t.Fatalf("nothing-to-count warning = %v, want %v:\n%s", nothing, tc.warnNothing, render(ds))
			}
		})
	}
}
