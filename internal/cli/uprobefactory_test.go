// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestUprobeFactory is E20's wiring at the composition root. A binary with the compiled capture object
// gives Select a uprobe source at tier cgroup, and that source follows the kernel record
// (source.KernelFollower), which is how the run hands it the pinned build and the exec stream that drives
// its attaches. A binary without the object has no factory, and Select says so with a gap. Before this the
// factory was missing in every build, so every run recorded mechanism-unavailable binary=uprobe.
func TestUprobeFactory(t *testing.T) {
	m := config.Builtin()
	rt := captureTable(agent.CaptureUprobe, []agent.ModelEndpoint{{Provider: "anthropic", Host: "api.anthropic.com", Port: 443}})
	f := uprobeFactory(rt, m)
	if !bpf.Available() {
		if f != nil {
			t.Fatal("a binary without the capture object offered a uprobe factory")
		}
		return
	}
	if f == nil {
		t.Fatal("a binary with the capture object offered no uprobe factory")
	}
	sources, gaps := selectCapture(rt, m, fakeBackend{tier: backend.TierCgroup, caps: backend.Set{backend.CapCaptureModel: true}})
	defer stopAll(t, sources)
	if len(gaps) != 0 {
		t.Fatalf("gaps %+v, want none from a build that carries both mechanisms", gaps)
	}
	var up source.Source
	for _, s := range sources {
		if s.Name() == string(agent.CaptureUprobe) {
			up = s
		}
	}
	if up == nil {
		t.Fatalf("sources %v, want a uprobe source", sources)
	}
	if _, ok := up.(source.KernelFollower); !ok {
		t.Fatal("the uprobe source does not follow the kernel record, so nothing would ever drive its attaches")
	}
}

// TestUprobeBodiesCanBeSynced pins the store the factory hands the uprobe source to one its Stop can sync.
// The source syncs whatever store has a Sync and cannot sync one without, so a store that lost the method
// would leave every captured body outside record-ledger R6's barrier with nothing failing.
func TestUprobeBodiesCanBeSynced(t *testing.T) {
	store := uprobeBlobs(t.TempDir())
	s, ok := store.(interface{ Sync() error })
	if !ok {
		t.Fatalf("%T has no Sync, so the uprobe source's bodies would never be made durable before run_end", store)
	}
	if err := s.Sync(); err != nil {
		t.Fatalf("Sync of an empty store: %v", err)
	}
}
