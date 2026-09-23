// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf

package observe

import (
	"testing"

	"github.com/cilium/ebpf"

	"github.com/attention-span-ai/tego/internal/bpf"
)

// TestRecorderMapsArePinnedByTheirReaderNames checks the other half against the compiled objects
// themselves, with no kernel: each tier-2 object the loader pins from must declare the ring buffer and the
// lost counter under the names this recorder opens, and pin them by name, or the pin path the loader
// derives (PinPath/<spec name>) is not the one pinnedMapPath builds.
func TestRecorderMapsArePinnedByTheirReaderNames(t *testing.T) {
	for _, obj := range []bpf.Object{bpf.ObjectCgroupNet, bpf.ObjectCgroupTrack, bpf.ObjectTraceProc} {
		spec, err := bpf.Load(obj)
		if err != nil {
			t.Fatalf("load %s: %v", obj, err)
		}
		for _, name := range []string{EventsMapName, LostMapName} {
			m, ok := spec.Maps[name]
			if !ok {
				t.Errorf("%s declares no map %q; the recorder would open a pin nothing creates", obj, name)
				continue
			}
			if m.Pinning != ebpf.PinByName {
				t.Errorf("%s: %s is not pinned by name (pinning %v)", obj, name, m.Pinning)
			}
			if m.Name != name {
				t.Errorf("%s: map %q carries spec name %q, which is what the pin path is built from", obj, name, m.Name)
			}
		}
	}
}
