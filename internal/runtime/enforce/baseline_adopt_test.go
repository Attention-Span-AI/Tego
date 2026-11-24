// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestAdoptionRecorderUsesObservedPredicate(t *testing.T) {
	h := adoptionObservedHandle{Handle: new(cgroupenforce.Handle)}
	if h.Verdict() != record.VerdictObserved {
		t.Fatal("record-only adoption did not use observed predicate")
	}
	var _ api.Handle = h
	var _ api.Listener = h
	var _ api.Armer = h
	var _ KernelRecorder = h
	var _ Reporter = h
	var _ DecisionPlaneReporter = h
	var _ PlaneKeyedReporter = h
}
