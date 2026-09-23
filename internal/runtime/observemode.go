// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// verdictHandle is the optional method of a handle that fixes the verdict of every action its run
// records, rather than leaving each one to be decided. Only the observe backend has it (P0-DESIGN §2.6:
// "a handle ... whose verdicts are observed").
type verdictHandle interface {
	Verdict() record.Verdict
}

// recordsOnly reports whether the run's handle is an observe run's, which is what puts the supervisor in
// record-only mode (docs/p0/supervisor.md R30). The handle is asked rather than the backend's tier so that
// the component that promised the verdict is the one that decides it; a handle without the method is an
// enforcing tier, and its run decides every action as usual.
func recordsOnly(h api.Handle) bool {
	v, ok := h.(verdictHandle)
	return ok && v.Verdict() == record.VerdictObserved
}
