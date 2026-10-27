// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRecorderAttributesAnAbsentRowsRefusalToTego: at tiers cgroup and
// bpflsm the inherited Landlock ruleset leaves an absent built-in row's name ungranted (ADR 0067 D3), so a read of a
// token made there during the run comes back -EACCES from the chain. The model answers that refusal, so the line is
// refused, read_denied, named by the row, never observed by: other as if another LSM had refused what Tego's own
// ruleset did; a sample without a chain return is inferred refused the same way, not counted as an allowed read.
func TestRecorderAttributesAnAbsentRowsRefusalToTego(t *testing.T) {
	f := newFixture(t)
	home := filepath.Join(f.dir, "home")
	row := filepath.Join(home, ".codex", "auth.json")
	// A wire-fixture counterfactual: the row compile would record for a home with no ~/.codex.
	f.rules.Tier = backend.TierCgroup
	f.rules.AbsentDenyRead = []agent.AbsentRow{{Path: row, Resolved: row, At: filepath.Join(home, ".codex")}}
	other := filepath.Join(home, ".codex", "config.toml")
	eacces := -int32(unix.EACCES)
	lines := fsLines(t, f,
		fsSample(sample{Kind: KindOpen, PID: 50, TID: 50, MonoNS: 1, Ret: eacces, RetOK: true}, 0, 1, 2049, row, ""),
		fsSample(sample{Kind: KindOpen, PID: 50, TID: 50, MonoNS: 2}, 0, 2, 2049, other, ""),
	)
	rule := "fs.deny_read[" + row + "]"
	for _, c := range []struct{ path, from string }{{row, record.FSVerdictChain}, {other, record.FSVerdictModel}} {
		ev := lines[c.path]
		if ev == nil {
			t.Errorf("%s: no line", c.path)
			continue
		}
		p := payload[record.FSPayload](t, ev)
		if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonReadDenied || ev.Rule != rule || p.By != "" || p.VerdictFrom != c.from {
			t.Errorf("%s: %s %q rule %s by %q from %q, want refused read_denied %s from %q", c.path, ev.Verdict, ev.Reason, ev.Rule, p.By, p.VerdictFrom, rule, c.from)
		}
	}
}
