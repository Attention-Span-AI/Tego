// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil/jsonschema"
)

const metadataRunID = "r-3f9c2a1b-0dllq06ts7400-k7m2pq"

func TestContractsHostileRecordedHashIsOmitted(t *testing.T) {
	f, o := fixture(t)
	// Metadata discovery decodes old and forged records without attesting them.
	// Put the oversized value in an actual run_start, below the ledger line cap.
	raw, err := os.ReadFile("../../spec/record/v1/fixtures/run-fixture.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var start map[string]any
	if err := json.Unmarshal(bytes.SplitN(raw, []byte{'\n'}, 2)[0], &start); err != nil {
		t.Fatal(err)
	}
	start["contract_hash"] = strings.Repeat("a", 1<<20)
	start["tier"] = "invented-tier"
	start["cwd"] = f.Root
	start["launcher_uid"] = os.Getuid()
	start["contract_source"] = map[string]any{"path": f.Path("contract.yaml")}
	raw, err = json.Marshal(start)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(o.Machine.LedgerRoot.Value, metadataRunID, "events.jsonl"), string(raw)+"\n")
	o.Snapshot = nil
	c := Discover(context.Background(), o)
	e, err := c.Select(f.Path("contract.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if e.State != "compiles" || e.LastRun == nil {
		t.Fatalf("record fixture was not read and checked: state %s, last run present %t", e.State, e.LastRun != nil)
	}
	if e.LastRun.ContractHash != "" || e.LastRun.Tier != "unknown" || e.LastRun.SameContract != "unknown" {
		t.Fatalf("untrusted metadata survived: hash length %d, tier %q, same %q", len(e.LastRun.ContractHash), e.LastRun.Tier, e.LastRun.SameContract)
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > 16<<10 {
		t.Fatalf("record hash inflated catalog to %d bytes", len(encoded))
	}
	jsonschema.Validate(t, "../../spec/contracts/v1/contracts.schema.json", c)
}

func TestContractsRecordedIdentifiersAreValidated(t *testing.T) {
	f, o := fixture(t)
	for _, tc := range []struct {
		name, id, agent, tier, hash, wantID, wantName, wantTier, wantHash string
	}{
		{"known", metadataRunID, "known-agent", "landlock", strings.Repeat("a", 64), metadataRunID, "known-agent", "landlock", strings.Repeat("a", 64)},
		{"cgroup", metadataRunID, "known-agent", "cgroup", "", metadataRunID, "known-agent", "cgroup", ""},
		{"bpflsm", metadataRunID, "known-agent", "bpflsm", "", metadataRunID, "known-agent", "bpflsm", ""},
		{"observe", metadataRunID, "known-agent", "observe", "", metadataRunID, "known-agent", "observe", ""},
		{"auto", metadataRunID, "known-agent", "auto", "", metadataRunID, "known-agent", "unknown", ""},
		{"oversized", strings.Repeat("r", 1<<20), strings.Repeat("a", 1<<20), strings.Repeat("t", 1<<20), "", "unknown", "unknown", "unknown", ""},
		{"controls", "r-\x1b[31m\n", "name\x1b[31m\n", "landlock\n", "broken", "unknown", "unknown", "unknown", ""},
		{"uppercase-hash", metadataRunID, "known-agent", "landlock", strings.Repeat("A", 64), metadataRunID, "known-agent", "landlock", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := run(f.Path(tc.name+"-missing.yaml"), f.Root, tc.agent, tc.hash, tc.tier, tc.id)
			o.Snapshot.Runs = append(o.Snapshot.Runs[:0], r)
			c := Discover(context.Background(), o)
			e, err := c.Select(r.Contract)
			if err != nil {
				t.Fatal(err)
			}
			if e.LastRun == nil {
				t.Fatal("record-only entry lost its last run")
			}
			if e.LastRun.ID != tc.wantID || e.Name != tc.wantName || e.LastRun.Tier != tc.wantTier || e.LastRun.ContractHash != tc.wantHash {
				t.Fatalf("metadata mismatch: id length %d, name length %d, tier length %d, hash length %d", len(e.LastRun.ID), len(e.Name), len(e.LastRun.Tier), len(e.LastRun.ContractHash))
			}
			if tc.tier == "observe" && e.LastRun.SameContract != "not-enforced" {
				t.Fatalf("observed run acquired an enforcement comparison: %+v", e.LastRun)
			}
			jsonschema.Validate(t, "../../spec/contracts/v1/contracts.schema.json", c)
		})
	}
}

func TestContractsSchemaRejectsMalformedRecordedHash(t *testing.T) {
	_, o := fixture(t)
	c := Discover(context.Background(), o)
	c.Contracts = []Entry{{Name: "fixture", Path: "/missing.yaml", Cwd: "/", FoundIn: []string{"run"}, State: "missing", Diagnostics: []Diagnostic{},
		LastRun: &LastRun{ID: metadataRunID, At: time.Unix(1700000000, 0).UTC(), Tier: "landlock", ContractHash: strings.Repeat("x", 1<<20), SameContract: "unknown"}}}
	if jsonschema.Check("../../spec/contracts/v1/contracts.schema.json", c) == nil {
		t.Fatal("schema accepted a malformed recorded contract hash")
	}
}
