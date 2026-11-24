// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/rulesview"
)

func TestContractChooserCarriesNewestStartAtScale(t *testing.T) {
	s := newServer(t, t.TempDir())
	const n = 100000
	ran := make([]rulesview.ContractRun, n)
	refs := refMemo{}
	t0 := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	for i := range ran {
		path := fmt.Sprintf("/contracts/%d/agent.yaml", i)
		refs[path] = fmt.Sprintf("%016x", i)
		ran[i] = rulesview.ContractRun{Path: path, NewestStart: t0.Add(time.Duration(i) * time.Second), Runs: 1}
	}
	// Different recorded spellings can resolve to the same contract ref.
	ran = append(ran, rulesview.ContractRun{Path: "/alias/agent.yaml", NewestStart: t0.Add(48 * time.Hour), Runs: 2, Live: 1})
	refs["/alias/agent.yaml"] = refs[ran[0].Path]
	got := s.chooserContracts(ran, refs, context.Background())
	if len(got) != n {
		t.Fatalf("got %d contracts, want %d", len(got), n)
	}
	for i, c := range got {
		want := ran[i].NewestStart
		if i == 0 {
			want = t0.Add(48 * time.Hour)
		}
		if !c.Last.Equal(want) {
			t.Fatalf("contract %d latest start %s, want %s", i, c.Last, want)
		}
	}
	if got[0].Runs != 3 || got[0].Live != 1 {
		t.Fatalf("alias totals %+v", got[0])
	}
}
