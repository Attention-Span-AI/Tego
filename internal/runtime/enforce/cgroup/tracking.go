// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"

	"github.com/attention-span-ai/tego/internal/bpf"
)

// TrackingFailures is the run's durable enforcement status. It is independent of the record ring,
// so a full or unavailable ring cannot hide failed descendant materialization from the runtime.
// Runtime workers stop before Detach/Close, which own the slot and map lifetime.
func (h *Handle) TrackingFailures() (uint64, error) {
	if h.kern == nil || !h.hasSlot || h.closed || h.detached {
		return 0, errors.New("cgroup: tracking counter is not available for this run")
	}
	return h.kern.trackingFailures(h.slot)
}

func (k *bpfKernel) trackingFailures(slot uint32) (uint64, error) {
	m := k.maps[bpf.MapTrackingFailed]
	if m == nil {
		return 0, errors.New("cgroup: missing durable tracking-failure counter")
	}
	return bpf.SlotCount(m, slot)
}
