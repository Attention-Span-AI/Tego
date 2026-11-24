// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger/runstart"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestSharedRunStartMetadata(t *testing.T) {
	for _, payload := range []string{
		`{"tier":"landlock","cwd":"/project","contract_source":{"path":"/project/agent.yaml"},"contract_hash":"hash"}`,
		`{"tier":"cgroup","cwd":"/project","contract_source":{"path":"/project/agent.yaml"},"launcher_uid":0}`,
		`{"tier":"observe","cwd":"/project","launcher_uid":1001}`,
	} {
		e := &record.Event{Kind: record.KindRunStart, Agent: "fixture", TS: time.Unix(1, 0).UTC(), Payload: []byte(payload)}
		r := &Run{ID: "r-fixture", Kinds: map[string]int{}}
		r.add(fromRecord(e))
		metadata, err := runstart.Project(e.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if r.Tier != metadata.Tier || r.Cwd != metadata.Cwd || r.Contract != metadata.Contract || r.ContractHash != metadata.ContractHash || r.UID != metadata.UID || r.Start != e.TS || r.Agent != e.Agent {
			t.Fatalf("dashboard metadata %+v differs from shared projection %+v", r, metadata)
		}
	}
}
