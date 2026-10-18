// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestRunStallWarningFollowsRecordAndObserve: the stall-reads-unseen warning `tego run`
// holds for its tier is derived from the record the run makes, so `--record full` over a record: summary contract is
// not warned and `--record summary` over a record: full contract is; and an `--observe` run, which installs tier
// landlock's filter, is warned at TierObserve, the tier it prints held findings for. A run at a root tier under
// record: off is not: each allowed open of a stall-bounded run stamps its activity in the kernel there
// (it was warned while an allowed open made no sample).
func TestRunStallWarningFollowsRecordAndObserve(t *testing.T) {
	const base = "version: 0\nname: stallrun\ncommand: [/usr/bin/true]\nlimits: {stall_after: 2s}\n"
	for _, tc := range []struct {
		name, record, flag string
		observe            bool
		tier               backend.Tier
		want               bool
		recordIs           agent.RecordMode
		pin                backend.Tier // the contract's tier, landlock when empty
	}{
		{"summary contract, --record full", "summary", "full", false, backend.TierLandlock, false, agent.RecordFull, ""},
		{"full contract, --record summary", "full", "summary", false, backend.TierLandlock, true, agent.RecordSummary, ""},
		{"summary contract, no --record", "summary", "", false, backend.TierLandlock, true, agent.RecordSummary, ""},
		{"summary contract, --observe", "summary", "", true, backend.TierObserve, true, agent.RecordSummary, ""},
		{"full contract, --observe", "full", "", true, backend.TierObserve, false, agent.RecordFull, ""},
		{"off contract at cgroup", "off", "", false, backend.TierCgroup, false, agent.RecordOff, backend.TierCgroup},
		{"full contract at cgroup, --record off", "full", "off", false, backend.TierCgroup, false, agent.RecordOff, backend.TierCgroup},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "agent.yaml")
			pin := tc.pin
			if pin == "" {
				pin = backend.TierLandlock
			}
			if err := os.WriteFile(path, []byte(base+"tier: "+string(pin)+"\nrecord: "+tc.record+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			var errs bytes.Buffer
			rt, held, _, code := compileForRun(t.Context(), runOptions{contract: path, record: tc.flag, observe: tc.observe, offline: true}, config.Builtin(), &errs)
			if code != identity.ExitOK || rt == nil {
				t.Fatalf("compileForRun = %d\n%s", code, errs.String())
			}
			if rt.Record != tc.recordIs {
				t.Fatalf("the run records %s, want %s", rt.Record, tc.recordIs)
			}
			var out bytes.Buffer
			_ = agent.WriteDiagnostics(&out, agent.ForTier(held, tc.tier))
			if got := strings.Contains(out.String(), "[stall-reads-unseen]"); got != tc.want {
				t.Fatalf("at tier %s the run printed:\n%s\nwant the stall warning %v", tc.tier, out.String(), tc.want)
			}
			if tc.want && tc.flag != "" && !strings.Contains(out.String(), "--record "+tc.flag) {
				t.Fatalf("the warning %q does not name the run's --record %s", out.String(), tc.flag)
			}
		})
	}
}

// TestRunStallWarningUnderTierLandlockOffersNoConflictingPin: `tego run --tier landlock`
// pins the run to tier landlock in the selection, after Compile, so the landlock stall warning's root tier, offered as
// "pin a root tier" in the contract, got that run refused as a --tier conflict when followed with the flag still
// given. compileForRun hands --tier to Compile (WithTierFlag), and the clause says to drop the flag.
func TestRunStallWarningUnderTierLandlockOffersNoConflictingPin(t *testing.T) {
	buildsTiers(t, backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM)
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte("version: 0\nname: stallrun\ncommand: [/usr/bin/true]\nlimits: {stall_after: 2s}\nrecord: summary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"landlock", ""} {
		var errs bytes.Buffer
		_, held, _, code := compileForRun(t.Context(), runOptions{contract: path, tier: flag, offline: true}, config.Builtin(), &errs)
		if code != identity.ExitOK {
			t.Fatalf("--tier %q: compileForRun = %d\n%s", flag, code, errs.String())
		}
		var out bytes.Buffer
		_ = agent.WriteDiagnostics(&out, agent.ForTier(held, backend.TierLandlock))
		said := out.String()
		if !strings.Contains(said, "[stall-reads-unseen]") || !strings.Contains(said, "pin a root tier (cgroup or bpflsm)") {
			t.Fatalf("--tier %q: the run printed:\n%s\nwant the stall warning offering a root tier", flag, said)
		}
		if without := strings.Contains(said, "without --tier landlock, pin a root tier"); without != (flag == "landlock") {
			t.Fatalf("--tier %q: the fix says to drop --tier landlock: %v, want %v:\n%s", flag, without, flag == "landlock", said)
		}
	}
}
