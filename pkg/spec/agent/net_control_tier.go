// SPDX-License-Identifier: Apache-2.0

package agent

import "github.com/attention-span-ai/tego/pkg/spec/backend"

// Packet admission and socket resource budgets require a kernel network plane.
// A listener bind alone can retain the explicitly weaker supervisor guarantee.
func (k *compiler) networkControlTier() {
	l := k.rt.NetLimits
	if k.rt.Ingress == nil && l.Bytes == nil && l.DatagramsPerSecond == nil && l.Connections == nil && l.PendingConnects == nil {
		return
	}
	if k.rt.Tier == backend.TierLandlock || k.rt.Tier == backend.TierObserve {
		k.ds.errorf(k.pos("net"), CodeUnenforced, "net.ingress and net.limits require tier cgroup or bpflsm with their kernel network attachments")
	}
}
