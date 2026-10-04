// SPDX-License-Identifier: Apache-2.0

package enforce

import "github.com/attention-span-ai/tego/pkg/spec/backend"

// NetworkCounterReporter is optional: a missing reporter provides no network
// accounting. Snapshot errors must not be replaced with a zero measurement.
type NetworkCounterReporter interface {
	NetworkCountersSnapshot() (backend.NetworkCounters, error)
}
