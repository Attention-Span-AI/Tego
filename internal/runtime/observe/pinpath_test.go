// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
)

// TestPinnedMapPathIsTheLoadersPinPath is the reader half of one path two packages compute. The tier-2
// loader hands cilium/ebpf MapOptions{PinPath: <bpffs>/tego/<hash>/maps} and every map is
// LIBBPF_PIN_BY_NAME, so a map is pinned at filepath.Join(PinPath, <its ELF name>) — and the ELF names are
// internal/bpf's Map* constants (bpf/include/maps.h). The recorder once opened maps/events and maps/lost,
// paths no loader creates, so every tier-2 run recorded kernel-record-unavailable while the ring buffer it
// should have drained was being written.
func TestPinnedMapPathIsTheLoadersPinPath(t *testing.T) {
	const hash = "0123456789abcdef"
	loaderMaps := filepath.Join("/sys/fs/bpf", "tego", hash, "maps")
	for _, tc := range []struct {
		reader string
		elf    string
	}{
		{EventsMapName, bpf.MapEvents},
		{LostMapName, bpf.MapLost},
	} {
		want := filepath.Join(loaderMaps, tc.elf)
		if got := pinnedMapPath("", hash, tc.reader); got != want {
			t.Errorf("the recorder opens %s, the loader pins %s", got, want)
		}
	}
	if got, want := pinnedMapPath("/mnt/bpf/tego", hash, EventsMapName),
		filepath.Join("/mnt/bpf/tego", hash, "maps", bpf.MapEvents); got != want {
		t.Errorf("an overridden pin root opens %s, want %s", got, want)
	}
}
