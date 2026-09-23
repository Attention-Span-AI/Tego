// SPDX-License-Identifier: Apache-2.0

package runtime_test

import (
	"context"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/runtime/capture/uprobe"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// forwarderStandin is a started forwarder as run_start sees one: a capture source by that name with no gap.
type forwarderStandin struct{}

func (forwarderStandin) Name() string                                            { return "forwarder" }
func (forwarderStandin) Start(context.Context, source.RunRef, source.Sink) error { return nil }
func (forwarderStandin) Stop() error                                             { return nil }
func (forwarderStandin) Gaps() []source.Gap                                      { return nil }

// TestAnInertUprobeIsNotCapture is the real uprobe source on the path the tier-2 build takes when its capture
// object cannot be loaded: Kernel mode with no kernel record to follow. Start returns nil there — a mechanism
// that cannot run is a gap, never a failed run (capture-derive.md §4) — so run_start.capture has to learn
// from the source that nothing runs, or it records uprobe for a run no uprobe saw. The runtime unit tests
// pin the rule with a stand-in; this pins that the real source says what the rule reads.
func TestAnInertUprobeIsNotCapture(t *testing.T) {
	u, err := uprobe.New(uprobe.Options{Kernel: true, PinRoot: t.TempDir()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	q := runtime.NewQueue(8)
	if err := u.Start(context.Background(), source.RunRef{ID: "r-inert", Agent: "a"}, q); err != nil {
		t.Fatalf("Start = %v; this is the path where the source starts and captures nothing", err)
	}
	defer func() {
		if err := u.Stop(); err != nil {
			t.Errorf("Stop: %v", err)
		}
	}()
	if got := runtime.CaptureModeOf(agent.CaptureUprobe, []source.Source{u, forwarderStandin{}}); got != "forwarder" {
		t.Errorf("run_start.capture = %q with an inert uprobe beside the forwarder, want forwarder", got)
	}
	if got := runtime.CaptureModeOf(agent.CaptureUprobe, []source.Source{u}); got != "off" {
		t.Errorf("run_start.capture = %q with only an inert uprobe, want off", got)
	}
}
