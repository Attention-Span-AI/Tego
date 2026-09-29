// SPDX-License-Identifier: Apache-2.0

package bpf

import "testing"

// TestRingFootprintIsNeverBelowTheRingsData: a kernel that reports no memlock for a ring is charged this instead,
// so the ring budget cannot be passed by rings that read as free. It stays within 32 KiB of the kernel's own
// figure for an 8 MiB ring (8,433,944 B, ADR 0026) and above the ring's bytes.
func TestRingFootprintIsNeverBelowTheRingsData(t *testing.T) {
	for _, size := range []uint32{64 << 10, 1 << 20, 8 << 20} {
		if got := ringFootprint(size, 4096); got <= uint64(size) || got > uint64(size)+uint64(size)/4096*8+4*4096 {
			t.Errorf("ringFootprint(%d) = %d", size, got)
		}
	}
	const kernel = 8433944
	if got := ringFootprint(8<<20, 4096); got+32<<10 < kernel || got > kernel+32<<10 {
		t.Errorf("ringFootprint(8 MiB) = %d, the kernel charges %d", got, kernel)
	}
}
