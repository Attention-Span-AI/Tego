// SPDX-License-Identifier: Apache-2.0

package capture

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// fakeSource is a capture source under test control.
type fakeSource struct {
	name string
	gaps []Gap
}

func (s *fakeSource) Name() string { return s.name }
func (s *fakeSource) Start(context.Context, RunRef, Sink) error {
	return nil
}
func (s *fakeSource) Stop() error { return nil }
func (s *fakeSource) Gaps() []Gap { return s.gaps }

// factory returns a Factory that hands back one source.
func factory(name string) Factory {
	return func() (Source, error) { return &fakeSource{name: name}, nil }
}

// TestSelect covers §4's mode selection and the concurrency the 2026-09-22 resolution settled: under
// auto both mechanisms run, and so they do for uprobe reached through auto; under forwarder only one does,
// and off starts nothing and gaps nothing. A contract that pins uprobe itself is TestSelectPinnedUprobe.
func TestSelect(t *testing.T) {
	t.Parallel()
	full := backend.Set{backend.CapCaptureModel: true}
	cases := []struct {
		name     string
		capture  agent.CaptureMode
		tier     backend.Tier
		caps     backend.Set
		deps     Deps
		wantSrc  []string
		wantGaps []string
	}{
		{
			name: "auto at tier 2 runs both", capture: agent.CaptureAuto, tier: backend.TierCgroup, caps: full,
			deps:    Deps{Uprobe: factory("uprobe"), Forwarder: factory("forwarder")},
			wantSrc: []string{"uprobe", "forwarder"},
		},
		{
			name: "uprobe resolved from auto runs both", capture: agent.CaptureUprobe, tier: backend.TierBPFLSM, caps: full,
			deps:    Deps{Uprobe: factory("uprobe"), Forwarder: factory("forwarder")},
			wantSrc: []string{"uprobe", "forwarder"},
		},
		{
			name: "forwarder pinned runs only the forwarder", capture: agent.CaptureForwarder,
			tier: backend.TierCgroup, caps: full,
			deps:    Deps{Uprobe: factory("uprobe"), Forwarder: factory("forwarder")},
			wantSrc: []string{"forwarder"},
		},
		{
			name: "tier 1 cannot run uprobes", capture: agent.CaptureAuto, tier: backend.TierLandlock, caps: full,
			deps:    Deps{Uprobe: factory("uprobe"), Forwarder: factory("forwarder")},
			wantSrc: []string{"forwarder"},
		},
		{
			name: "a machine without the capability cannot run uprobes", capture: agent.CaptureUprobe,
			tier: backend.TierCgroup, caps: backend.Set{},
			deps:    Deps{Uprobe: factory("uprobe"), Forwarder: factory("forwarder")},
			wantSrc: []string{"forwarder"},
		},
		{
			name: "off starts nothing and gaps nothing", capture: agent.CaptureOff, tier: backend.TierCgroup,
			caps: full, deps: Deps{Uprobe: factory("uprobe"), Forwarder: factory("forwarder")},
		},
		{
			name:    "a mechanism this binary does not carry is a gap, never a silence",
			capture: agent.CaptureAuto, tier: backend.TierCgroup, caps: full,
			deps:     Deps{Uprobe: factory("uprobe")},
			wantSrc:  []string{"uprobe"},
			wantGaps: []string{"forwarder"},
		},
		{
			name: "a constructor that fails is a gap", capture: agent.CaptureForwarder,
			tier: backend.TierCgroup, caps: full,
			deps:     Deps{Forwarder: func() (Source, error) { return nil, errors.New("bind: address in use") }},
			wantGaps: []string{"forwarder"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &agent.RuleTable{Capture: tc.capture}
			srcs, gaps := Select(rt, tc.tier, tc.caps, tc.deps)
			var names []string
			for _, s := range srcs {
				names = append(names, s.Name())
			}
			if len(names) != len(tc.wantSrc) {
				t.Fatalf("sources = %v, want %v", names, tc.wantSrc)
			}
			for i := range names {
				if names[i] != tc.wantSrc[i] {
					t.Fatalf("sources = %v, want %v", names, tc.wantSrc)
				}
			}
			if len(gaps) != len(tc.wantGaps) {
				t.Fatalf("gaps = %v, want %v", gaps, tc.wantGaps)
			}
			for i, g := range gaps {
				if g.What != record.GapCapture || g.Why != GapMechanismUnavailable || g.Binary != tc.wantGaps[i] {
					t.Errorf("gap %d = %+v, want %s", i, g, tc.wantGaps[i])
				}
			}
		})
	}
}

// TestSelectPinnedUprobe is FEATURES kill test 7 (b), "one open-source Python agent on system Python + the
// Anthropic SDK with capture: uprobe", read by the probes on the system OpenSSL. Select used to start the
// forwarder beside the uprobes for a contract that pinned uprobe, and the forwarder's ANTHROPIC_BASE_URL sent
// every request of the SDK to its loopback listener, whose upstream TLS no probe sees: the run recorded every
// request as source=forwarder and the uprobes never read one. A pinned uprobe runs no forwarder where the tier
// can run uprobes; where it cannot, it tops out at the forwarder as Compile and AtTier lower it. The same
// table without the pin, uprobe reached through auto, still runs both.
func TestSelectPinnedUprobe(t *testing.T) {
	t.Parallel()
	full := backend.Set{backend.CapCaptureModel: true}
	models := []agent.ModelEndpoint{{Provider: "anthropic", Host: "api.anthropic.com", Port: 443}}
	deps := Deps{Uprobe: factory("uprobe"), Forwarder: factory("forwarder")}
	cases := []struct {
		name     string
		pin      agent.CaptureMode
		mode     agent.CaptureMode
		tier     backend.Tier
		caps     backend.Set
		models   []agent.ModelEndpoint
		deps     Deps
		wantSrc  []string
		wantGaps []Gap
	}{
		{name: "pinned uprobe at tier 2 runs the uprobes alone", pin: agent.CaptureUprobe, mode: agent.CaptureUprobe,
			tier: backend.TierCgroup, caps: full, models: models, deps: deps, wantSrc: []string{"uprobe"}},
		{name: "pinned uprobe with no models[] is no forwarder gap either", pin: agent.CaptureUprobe,
			mode: agent.CaptureUprobe, tier: backend.TierCgroup, caps: full, deps: deps, wantSrc: []string{"uprobe"}},
		{name: "pinned uprobe in a build with no uprobe source is its gap, and no forwarder", pin: agent.CaptureUprobe,
			mode: agent.CaptureUprobe, tier: backend.TierCgroup, caps: full, models: models,
			deps:     Deps{Forwarder: factory("forwarder")},
			wantGaps: []Gap{{What: record.GapCapture, Why: GapMechanismUnavailable, Binary: "uprobe"}}},
		{name: "pinned uprobe lowered to the forwarder at tier 1", pin: agent.CaptureUprobe, mode: agent.CaptureForwarder,
			tier: backend.TierLandlock, caps: full, models: models, deps: deps, wantSrc: []string{"forwarder"}},
		{name: "pinned uprobe on a tier 1 run of a tier 2 table tops out at the forwarder", pin: agent.CaptureUprobe,
			mode: agent.CaptureUprobe, tier: backend.TierLandlock, caps: full, models: models, deps: deps,
			wantSrc: []string{"forwarder"}},
		{name: "uprobe through auto runs both", pin: agent.CaptureAuto, mode: agent.CaptureUprobe,
			tier: backend.TierCgroup, caps: full, models: models, deps: deps, wantSrc: []string{"uprobe", "forwarder"}},
		{name: "uprobe with capture unset runs both", mode: agent.CaptureUprobe,
			tier: backend.TierCgroup, caps: full, models: models, deps: deps, wantSrc: []string{"uprobe", "forwarder"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &agent.RuleTable{Capture: tc.mode, Contract: &agent.Contract{Name: "a", Capture: tc.pin, Models: tc.models}}
			srcs, gaps := Select(rt, tc.tier, tc.caps, tc.deps)
			var names []string
			for _, s := range srcs {
				names = append(names, s.Name())
			}
			if !slices.Equal(names, tc.wantSrc) {
				t.Errorf("sources = %v, want %v", names, tc.wantSrc)
			}
			if !slices.Equal(gaps, tc.wantGaps) {
				t.Errorf("gaps = %+v, want %+v", gaps, tc.wantGaps)
			}
		})
	}
}

// TestSelectWithoutARuleTable covers the nil contract: a caller with nothing compiled captures nothing and
// is not told it is missing anything.
func TestSelectWithoutARuleTable(t *testing.T) {
	t.Parallel()
	srcs, gaps := Select(nil, backend.TierCgroup, nil, Deps{Uprobe: factory("uprobe")})
	if srcs != nil || gaps != nil {
		t.Fatalf("Select(nil) = %v, %v", srcs, gaps)
	}
}

// TestAliasesSatisfyTheRuntimeContract is the point of the aliases: a capture source is a runtime source,
// with no adapter in between.
// These assertions are the point of the aliases: a capture source must be usable wherever the runtime
// expects one, and Gap and RunRef must be the runtime's own types rather than look-alikes. They are
// compile-time checks, so a divergence fails the build rather than a test run.
var (
	_ source.Source = (*fakeSource)(nil)
	_ source.Gap    = Gap{}
	_ source.RunRef = RunRef{}
)

func TestAliasesSatisfyTheRuntimeContract(t *testing.T) {
	t.Parallel()
	var s Source = &fakeSource{name: "uprobe"}
	//nolint:staticcheck // the explicit type is the assertion: capture.Source must satisfy source.Source
	var rs source.Source = s
	if rs.Name() != "uprobe" {
		t.Errorf("name = %q", rs.Name())
	}
}
