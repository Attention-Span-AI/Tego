// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf

package bpf

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

// TestEveryUnpinnedMapIsKernelOnly: a build's later runs adopt its pinned programs instead of loading the object
// again only when every map the object holds is pinned by name, a global-variable section, or named in
// KernelOnlyMaps (cgroup adoptObjectIn). A map that is none of them makes every later run of the build load and
// verify the whole object again and leave it unattached: 400 to 900 ms of a warm start at tier bpflsm
// (enforce-plane §10, the perf suite's plane.objects.new phase), with nothing failing. tego_plane_path_buf was
// added unpinned and unlisted and did exactly that.
func TestEveryUnpinnedMapIsKernelOnly(t *testing.T) {
	// The fill objects are not adopted through adoptObjectIn: adoptPlaneFiller opens their pins one by one.
	objs := append([]Object{ObjectCgroupNet, ObjectCgroupTrack, ObjectTraceProc}, PlaneObjects()...)
	seen := map[string]bool{}
	for _, o := range objs {
		spec, err := Load(o)
		if err != nil {
			t.Fatalf("Load(%s): %v", o, err)
		}
		for name, ms := range spec.Maps {
			if ms.Pinning == ebpf.PinByName || strings.HasPrefix(name, ".") {
				continue
			}
			if !KernelOnlyMaps[name] {
				t.Errorf("%s: map %s is neither pinned by name, a section, nor in KernelOnlyMaps: a run would not adopt the object", o, name)
			}
			seen[name] = true
		}
	}
	for name := range KernelOnlyMaps {
		if !seen[name] {
			t.Errorf("KernelOnlyMaps names %s, which no object holds unpinned", name)
		}
	}
}
