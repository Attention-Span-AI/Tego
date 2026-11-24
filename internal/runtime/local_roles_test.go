// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"path/filepath"
	"testing"
)

func TestLocalRolesLaunchQualification(t *testing.T) {
	if localEnforcing(true) == nil || localEnforcing(false) != nil {
		t.Fatal("records-only activation was admitted")
	}
	for _, tc := range []struct {
		name   string
		uid    int
		ns     uint64
		mode   agent.RecordMode
		tier   backend.Tier
		setuid bool
		bad    bool
	}{
		{"qualified", 0, record.InitialUserNamespace, agent.RecordFull, backend.TierLandlock, false, false},
		{"summary", 0, record.InitialUserNamespace, agent.RecordSummary, backend.TierCgroup, false, false},
		{"unprivileged launcher", 1001, record.InitialUserNamespace, agent.RecordFull, backend.TierLandlock, false, true},
		{"private namespace", 0, record.InitialUserNamespace + 1, agent.RecordFull, backend.TierLandlock, false, true},
		{"missing diagnostics", 0, 0, agent.RecordFull, backend.TierLandlock, false, true},
		{"record off", 0, record.InitialUserNamespace, agent.RecordOff, backend.TierLandlock, false, true},
		{"record unknown", 0, record.InitialUserNamespace, "", backend.TierLandlock, false, true},
		{"observe", 0, record.InitialUserNamespace, agent.RecordFull, backend.TierObserve, false, true},
		{"setuid", 0, record.InitialUserNamespace, agent.RecordFull, backend.TierCgroup, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := localLaunch(tc.uid, tc.ns, tc.mode, tc.tier, tc.setuid); (err != nil) != tc.bad {
				t.Fatalf("qualification: %v", err)
			}
		})
	}
}

func TestLocalRolesChildCredentials(t *testing.T) {
	for _, tc := range []struct {
		priv        bool
		uid         int
		setuid, bad bool
	}{{true, 1001, false, false}, {false, 1001, false, true}, {true, 0, false, true}, {true, -1, false, true}, {true, 1001, true, true}, {true, 4294967295, false, true}} {
		if err := localDrop(tc.priv, tc.uid, tc.setuid); (err != nil) != tc.bad {
			t.Fatalf("%+v: %v", tc, err)
		}
	}
}

func TestLocalRolesFinalStoredAttributionRequired(t *testing.T) {
	const id = "r-00000000-000000000000a-localx"
	w, err := ledger.Open(filepath.Join(t.TempDir(), id), record.RunRef{ID: id, Agent: "roles"}, ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w.Abandon() }()
	if err := w.WriteRunStart(record.RunStartPayload{RecordMinor: record.MinorLocalRoles, Tier: "landlock"}); err != nil {
		t.Fatal(err)
	}
	r := &runner{writer: w}
	e := &record.Event{Kind: record.KindAnswer, Source: record.SourceSupervisor}
	if err := e.SetPayload(map[string]any{"ask_id": "q-local", "approved": true, "by": "uid:0 pid:42"}); err != nil {
		t.Fatal(err)
	}
	if err := r.appendLocalAnswer(e); err == nil {
		t.Fatal("stripped actor reached durable approval")
	}
	if w.Seq() != 1 {
		t.Fatal("stripped authority consumed record sequence")
	}
}

// Every launch writes revision 41 (ADR 0157), a superset of 37, so a run under the floor carries 41 and the roles
// fields validate there: the roles writer rule gives 41 for the launch revision the product writes.
func TestLocalRolesPayloadIsRevision41ForEveryLaunch(t *testing.T) {
	if got := localRolesMinor(launchMinor); got != record.MinorEveryLaunch || record.MinorEveryLaunch != 41 {
		t.Fatalf("a launch writing revision %d: roles payload revision %d, want 41", launchMinor, got)
	}
	// The line the roles payload sits on must validate at that revision and be supported by the reader.
	if !record.SupportsMinor(41) || !record.SupportsMinor(record.MinorLocalRoles) {
		t.Fatal("the reader must support both 37 and 41")
	}
	for _, minor := range []int{36, 38} {
		if record.SupportsMinor(minor) {
			t.Errorf("revision %d is reserved and must stay unsupported", minor)
		}
	}
}

func TestLocalRolesPayloadNeverLowersTheLaunchRevision(t *testing.T) {
	for launch, want := range map[int]int{record.MinorLearn: record.MinorLocalRoles, record.MinorLocalRoles: record.MinorLocalRoles, record.MinorBaseline: record.MinorBaseline, record.Minor: record.Minor, record.Minor + 1: record.Minor + 1} {
		if got := localRolesMinor(launch); got != want {
			t.Errorf("launch revision %d: roles payload revision %d, want %d", launch, got, want)
		}
	}
}
