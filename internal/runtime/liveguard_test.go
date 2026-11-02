// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"testing"

	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// adjustableTable is a table compiled from live.mode: adjustable, whose fence the kernel layers hold open.
func adjustableTable() *agent.RuleTable {
	return &agent.RuleTable{Contract: &agent.Contract{Name: "a"}, Tier: backend.TierCgroup,
		Live: &agent.LiveTable{Mode: agent.LiveAdjustable, Entries: []agent.LiveEntry{{Kind: agent.LiveKindRead, Value: "/srv/secrets", Source: agent.LiveSourceDeny}}}}
}

// TestRefuseAdjustableOnlyAdoptions: since the launcher seeds the fence's refusals, a run of an Adjustable
// table is not refused by the guard (checkAdjustable decides whether it may start); an adoption is (ADR 0125 decision
// 6); a Locked table never is.
func TestRefuseAdjustableOnlyAdoptions(t *testing.T) {
	if err := refuseAdjustable(adjustableTable(), false); err != nil {
		t.Fatalf("a run of an Adjustable table is refused by the guard: %v", err)
	}
	if err := refuseAdjustable(adjustableTable(), true); !errors.Is(err, ErrLiveUnavailable) {
		t.Fatalf("an adoption of an Adjustable table: %v, want ErrLiveUnavailable", err)
	}
	if err := refuseAdjustable(&agent.RuleTable{Contract: &agent.Contract{Name: "a"}}, true); err != nil {
		t.Fatalf("a Locked table is refused: %v", err)
	}
	if err := refuseAdjustable(&agent.RuleTable{Contract: &agent.Contract{Name: "a"}, Live: &agent.LiveTable{Mode: agent.LiveLocked}}, true); err != nil {
		t.Fatalf("a table with a Locked live table is refused: %v", err)
	}
}

// TestAdoptRefusesAdjustable: an adopted run cannot have its fence refused from its first instruction (ADR 0125
// decision 6), so the adoption is refused before anything moves.
func TestAdoptRefusesAdjustable(t *testing.T) {
	root := adopt.Process{Identity: adopt.Identity{PID: 4242, Start: 1}, Cgroup: "/user.slice/x.scope"}
	res, err := Adopt(context.Background(), adjustableTable(), AdoptSpec{Root: root, Recheck: admitAll},
		AdoptDeps{Config: config.Builtin(), Enforce: &adoptBackend{}})
	if !errors.Is(err, ErrLiveUnavailable) {
		t.Fatalf("err %v, want ErrLiveUnavailable", err)
	}
	if res.ExitCode != identity.ExitLauncher {
		t.Fatalf("result %+v, want 125", res)
	}
}
