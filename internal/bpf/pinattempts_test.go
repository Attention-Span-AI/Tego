// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"testing"

	"github.com/cilium/ebpf"
)

// TestPinAttemptsIsOneMoreThanThePinnedMaps: each EEXIST a pinned load can meet pins one more of the object's
// pinned names for good, so a load needs at most one attempt more than it has pinned maps; maps it does not pin
// cannot race.
func TestPinAttemptsIsOneMoreThanThePinnedMaps(t *testing.T) {
	spec := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		"a":    {Pinning: ebpf.PinByName},
		"b":    {Pinning: ebpf.PinByName},
		".bss": {Pinning: ebpf.PinNone},
	}}
	if got := PinAttempts(spec); got != 3 {
		t.Errorf("PinAttempts = %d, want 3", got)
	}
	if got := PinAttempts(&ebpf.CollectionSpec{}); got != 1 {
		t.Errorf("PinAttempts of an object with no pinned map = %d, want 1", got)
	}
}
