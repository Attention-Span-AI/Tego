// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"testing"
)

func TestTrackingFailuresRemainEnforcementState(t *testing.T) {
	k := &fakeKernel{trackingCount: 3}
	h := &Handle{kern: k, slot: 7, hasSlot: true}
	if n, err := h.TrackingFailures(); n != 3 || err != nil {
		t.Fatalf("count=%d err=%v", n, err)
	}
	k.trackingErr = errors.New("unreadable")
	if _, err := h.TrackingFailures(); !errors.Is(err, k.trackingErr) {
		t.Fatal("counter read error was suppressed")
	}
	h.detached = true
	if _, err := h.TrackingFailures(); err == nil {
		t.Fatal("detached slot was read as healthy")
	}
	if _, err := (&bpfKernel{}).trackingFailures(0); err == nil {
		t.Fatal("missing counter was read as healthy")
	}
}
