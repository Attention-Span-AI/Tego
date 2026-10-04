// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

func (r *runner) runNetworkCounters() *backend.NetworkCounters {
	reporter, ok := r.handle.(enforce.NetworkCounterReporter)
	if !ok {
		return nil
	}
	counts, err := reporter.NetworkCountersSnapshot()
	if err != nil {
		r.log.Warn("run: final network accounting unavailable", "err", err)
		r.noteDetail("network accounting unavailable: " + err.Error())
		return nil
	}
	for _, available := range counts.Available {
		if available {
			return &counts
		}
	}
	return nil
}
