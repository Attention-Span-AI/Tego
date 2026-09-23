// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"testing"

	"golang.org/x/net/bpf"

	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// plainHandle is an enforcing tier's handle: it has no Verdict of its own.
type plainHandle struct{}

func (plainHandle) LandlockRuleset() (int, bool)                { return -1, false }
func (plainHandle) SeccompFilter() ([]bpf.RawInstruction, bool) { return nil, false }
func (plainHandle) Attach(uint64) error                         { return nil }
func (plainHandle) Detach() error                               { return nil }
func (plainHandle) Close() error                                { return nil }

// verdictOnly is a handle that fixes some other verdict; only observed makes a run record-only.
type verdictOnly struct {
	plainHandle
	v record.Verdict
}

func (h verdictOnly) Verdict() record.Verdict { return h.v }

// TestRecordsOnlyFollowsTheHandle is the runtime's half: the supervisor of an --observe run is
// put in record-only mode because the observe handle says its verdicts are observed, and a run on any
// other handle keeps deciding.
func TestRecordsOnlyFollowsTheHandle(t *testing.T) {
	h, err := enforce.Observe().Prepare(context.Background(), &agent.RuleTable{}, enforce.RunRef{})
	if err != nil {
		t.Fatal(err)
	}
	if !recordsOnly(h) {
		t.Errorf("the observe handle did not make the run record-only: its supervisor would refuse")
	}
	for name, h := range map[string]api.Handle{
		"enforcing handle":     plainHandle{},
		"a non-observed fixed": verdictOnly{v: record.VerdictAllow},
		"no handle":            nil,
	} {
		if recordsOnly(h) {
			t.Errorf("%s made the run record-only", name)
		}
	}
}
