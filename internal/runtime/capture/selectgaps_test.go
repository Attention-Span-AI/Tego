// SPDX-License-Identifier: Apache-2.0

package capture

import (
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/capture/forwarder"
	"github.com/attention-span-ai/tego/internal/runtime/capture/uprobe"
	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestSelectNamesWhyAMechanismDidNotRun is R37 as amended: a mechanism that never ran is a gap whose why says
// which of two facts is true, and neither is no-openssl, which is R4's finding about a process's libraries.
// A contract with no models[] is the ordinary case of the first (a build script, a Go tool) and must not
// read as a binary with no OpenSSL; the forwarder factory is not even consulted, because there is nothing
// for a listener to be bound to.
func TestSelectNamesWhyAMechanismDidNotRun(t *testing.T) {
	t.Parallel()
	full := backend.Set{backend.CapCaptureModel: true}
	consulted := false
	fwd := func() (Source, error) { consulted = true; return &fakeSource{name: "forwarder"}, nil }
	cases := []struct {
		name     string
		contract *agent.Contract
		tier     backend.Tier
		deps     Deps
		wantSrc  []string
		wantGaps []Gap
		consult  bool
	}{
		{
			name: "no models[] is no-models on the forwarder", contract: &agent.Contract{Name: "tool"},
			tier: backend.TierLandlock, deps: Deps{Forwarder: fwd},
			wantGaps: []Gap{{What: record.GapCapture, Why: GapNoModels, Binary: "forwarder"}},
		},
		{
			name: "declared models run the forwarder",
			contract: &agent.Contract{Name: "agent",
				Models: []agent.ModelEndpoint{{Provider: "anthropic", Host: "api.anthropic.com"}}},
			tier: backend.TierLandlock, deps: Deps{Forwarder: fwd},
			wantSrc: []string{"forwarder"}, consult: true,
		},
		{
			name: "a build with no uprobe source says the mechanism is unavailable",
			contract: &agent.Contract{Name: "agent",
				Models: []agent.ModelEndpoint{{Provider: "anthropic", Host: "api.anthropic.com"}}},
			tier: backend.TierCgroup, deps: Deps{Forwarder: fwd},
			wantSrc:  []string{"forwarder"},
			wantGaps: []Gap{{What: record.GapCapture, Why: GapMechanismUnavailable, Binary: "uprobe"}},
			consult:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			consulted = false
			rt := &agent.RuleTable{Capture: agent.CaptureAuto, Contract: tc.contract}
			srcs, gaps := Select(rt, tc.tier, full, tc.deps)
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
			if consulted != tc.consult {
				t.Errorf("forwarder factory consulted = %v, want %v", consulted, tc.consult)
			}
			for _, g := range gaps {
				if g.Why == GapNoOpenSSL {
					t.Errorf("a mechanism that never ran was filed as no-openssl: %+v", g)
				}
			}
		})
	}
}

// TestMechanismNamesAgree pins the three spellings of one mechanism: the source's own Name, the binary a
// selection gap names, and the capture mode run_start.capture is read as. A forwarder renamed on one side only
// would leave run_start saying off for a run the forwarder captured.
func TestMechanismNamesAgree(t *testing.T) {
	t.Parallel()
	// mechanismForwarder and mechanismUprobe are defined as the capture modes' own strings, so one
	// comparison each covers all three spellings.
	if forwarder.Name != mechanismForwarder {
		t.Errorf("forwarder source %q, selection and mode %q", forwarder.Name, mechanismForwarder)
	}
	if uprobe.Name != mechanismUprobe {
		t.Errorf("uprobe source %q, selection and mode %q", uprobe.Name, mechanismUprobe)
	}
}

// TestCaptureWhysAreOneSet pins that the reasons this package writes are R37's closed set as internal/runtime/
// derive holds it, so a gap Select writes is never one Coverage would refile as malformed.
func TestCaptureWhysAreOneSet(t *testing.T) {
	t.Parallel()
	mine := []string{GapNoOpenSSL, GapStaticTLSNoSymbols, GapH2, GapMalformed, GapRingBufferDrop, GapSizeCap, derive.GapEmitQueueFull,
		GapNoModels, GapMechanismUnavailable}
	if !slices.Equal(mine, derive.CaptureWhys) {
		t.Fatalf("capture's set %v differs from derive's %v", mine, derive.CaptureWhys)
	}
}
