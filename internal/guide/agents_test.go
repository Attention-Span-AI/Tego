// SPDX-License-Identifier: Apache-2.0

package guide_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/agentid"
	"github.com/attention-span-ai/tego/internal/guide"
	"github.com/attention-span-ai/tego/internal/guide/guidetest"
	"github.com/attention-span-ai/tego/internal/scan/result"
)

func TestAgentIdentityReadsTheSameSetupFacts(t *testing.T) {
	for _, name := range []string{guidetest.Fresh, guidetest.HalfDone, guidetest.ContractMade, guidetest.Finished, guidetest.Tampered} {
		t.Run(name, func(t *testing.T) {
			f := guidetest.Make(t, name)
			s := guide.Compute(t.Context(), f.Inputs(t))
			if name == guidetest.Fresh {
				if len(s.Agents) != 0 {
					t.Fatal("invented agent")
				}
				return
			}
			if len(s.Agents) == 0 {
				t.Fatal("recorded run identity missing")
			}
			verified, contracted := false, false
			for _, a := range s.Agents {
				if !a.Stages[1].Fact.Established {
					t.Fatal("run_start missing recorded fact")
				}
				for _, stage := range a.Stages {
					if stage.ID == agentid.ContractStage && stage.Fact.Established {
						contracted = true
						if stage.Fact.RunID != f.Runs[len(f.Runs)-1] || !strings.Contains(stage.Fact.Text, "in that run's context") {
							t.Fatalf("contract compile lost its exact run context: %+v", stage.Fact)
						}
					}
					if stage.ID == agentid.VerifiedStage && stage.Fact.Established {
						verified = true
					}
				}
			}
			if verified != (name == guidetest.Finished) {
				t.Fatalf("verified %v for %s", verified, name)
			}
			if contracted != (name == guidetest.Finished) {
				t.Fatalf("contracted %v for %s", contracted, name)
			}
			b, err := json.Marshal(s.Agents)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), "--loop") {
				t.Fatal("identity serialized private arguments")
			}
		})
	}
}

func TestScanAgentsKeepsCommandAndFolderUnknowns(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	f.PutScan(t, "a")
	r, err := guide.ReadScan(f.Home, f.Inputs(t).UID, guidetest.BootID, guidetest.CheckTime).ScanResult()
	if err != nil {
		t.Fatal(err)
	}
	found := guide.ScanAgents(r.Snapshot, r.Snapshot.As.UID, "last.json")
	if len(found) != 1 || found[0].Folder != "" || !strings.Contains(found[0].Fact, "claude-native: exe-name (source-1)") {
		t.Fatalf("lost typed evidence: %+v", found)
	}
	if got := guide.ScanAgents(r.Snapshot, r.Snapshot.As.UID+1, "last.json"); len(got) != 0 {
		t.Fatal("foreign user evidence admitted")
	}
	for _, kind := range []string{"settings", "project", "mcp_server", "user_unit", "timer", "other_program"} {
		s := r.Snapshot
		s.Items = []result.Item{{Kind: kind}}
		if got := guide.ScanAgents(s, s.As.UID, "last.json"); len(got) != 0 {
			t.Fatalf("%s became a found agent", kind)
		}
	}
}

func TestScanAgentsRetainsIdentityCaveats(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	f.PutScan(t, "a")
	r, err := guide.ReadScan(f.Home, f.Inputs(t).UID, guidetest.BootID, guidetest.CheckTime).ScanResult()
	if err != nil {
		t.Fatal(err)
	}
	r.Snapshot.Items[0].Caveats = []string{"identity-unknown", "user-rule"}
	a := guide.ScanAgents(r.Snapshot, r.Snapshot.As.UID, "last.json")[0]
	if !a.IdentityUnknown || !strings.Contains(a.Fact, "identity-unknown, user-rule") {
		t.Fatalf("qualification dropped: %+v", a)
	}
}

func TestScanAgentsInsideRunAddsNoObservation(t *testing.T) {
	f := guidetest.Make(t, guidetest.Fresh)
	f.PutScan(t, "a")
	r, err := guide.ReadScan(f.Home, f.Inputs(t).UID, guidetest.BootID, guidetest.CheckTime).ScanResult()
	if err != nil {
		t.Fatal(err)
	}
	p := r.Snapshot.Items[0].Process()
	p.Membership = "in-run"
	r.Snapshot.Items[0].Detail = result.Detail(p)
	if rows := guide.ScanAgents(r.Snapshot, r.Snapshot.As.UID, "last.json"); len(rows) != 0 {
		t.Fatalf("inside-run scan added rows: %+v", rows)
	}
}
