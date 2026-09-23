// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// fakeBackend is a selected tier under test control: capture.Select reads nothing of a backend but its
// tier and its capability set.
type fakeBackend struct {
	tier backend.Tier
	caps backend.Set
}

func (b fakeBackend) Tier() backend.Tier        { return b.tier }
func (b fakeBackend) Capabilities() backend.Set { return b.caps }
func (b fakeBackend) Prepare(context.Context, *agent.RuleTable, enforce.RunRef) (api.Handle, error) {
	return nil, errors.New("cli: the capture tests never prepare enforcement")
}

// captureTable is a compiled table the selection can be run against: only the fields selectCapture and
// capture.Select read.
func captureTable(mode agent.CaptureMode, models []agent.ModelEndpoint) *agent.RuleTable {
	return &agent.RuleTable{
		Capture:  mode,
		Record:   agent.RecordSummary,
		Contract: &agent.Contract{Name: "capture-test", Models: models},
	}
}

// stopAll releases the loopback sockets a selection bound, so a test never leaves a listener behind.
func stopAll(t *testing.T, sources []source.Source) {
	t.Helper()
	for _, s := range sources {
		if err := s.Stop(); err != nil {
			t.Fatalf("stop %s: %v", s.Name(), err)
		}
	}
}

// TestSelectCaptureBindsTheForwarder is the wire `tego run` now carries: a contract with models[] gets a
// forwarder whose listeners are already bound, with a base-URL variable per declared provider and an
// endpoint the run can admit — all before runtime.Run is called (capture-derive.md §3, R19).
func TestSelectCaptureBindsTheForwarder(t *testing.T) {
	t.Parallel()
	m := config.Builtin()
	rt := captureTable(agent.CaptureForwarder, []agent.ModelEndpoint{
		{Provider: "anthropic", Host: "api.anthropic.com", Port: 443},
	})
	sources, gaps := selectCapture(rt, m, enforce.Observe())
	defer stopAll(t, sources)

	if len(sources) != 1 || sources[0].Name() != "forwarder" {
		t.Fatalf("sources %v, want one forwarder", sources)
	}
	// capture: forwarder never asks for the uprobe mechanism, so its absence is not a shortfall.
	if len(gaps) != 0 {
		t.Fatalf("gaps %v, want none", gaps)
	}
	loop, ok := sources[0].(source.LoopbackSource)
	if !ok {
		t.Fatal("the forwarder is not a LoopbackSource: the run cannot reach its ports")
	}
	vars := loop.Vars()
	base := vars[identity.EnvAnthropicBaseURL]
	if !strings.HasPrefix(base, "http://127.0.0.1:") {
		t.Fatalf("%s = %q, want a loopback base URL", identity.EnvAnthropicBaseURL, base)
	}
	eps := loop.Endpoints()
	if len(eps) != 1 || !eps[0].Addr().IsLoopback() || eps[0].Port() == 0 {
		t.Fatalf("endpoints %v, want one bound loopback address", eps)
	}
	if !strings.HasSuffix(base, eps[0].String()) {
		t.Fatalf("the base URL %q and the admitted endpoint %v are different ports", base, eps[0])
	}
}

// TestSelectCaptureGapsWhatThisBinaryCannotBuild covers the two shortfalls this build has: no uprobe
// mechanism at all, and a contract that declared no models[] for a forwarder to bind to. Both are gap
// events rather than silences (§8 I4).
func TestSelectCaptureGapsWhatThisBinaryCannotBuild(t *testing.T) {
	t.Parallel()
	m := config.Builtin()
	tests := []struct {
		name    string
		rt      *agent.RuleTable
		tier    backend.Tier
		caps    backend.Set
		wantSrc int
		want    []string // gap binaries, in order
		// untagged marks a case that is only true of a binary without the compiled BPF objects;
		// TestUprobeFactory covers the other build.
		untagged bool
	}{
		{
			name: "no models leaves the forwarder unbuildable",
			rt:   captureTable(agent.CaptureForwarder, nil),
			want: []string{"forwarder"},
		},
		{
			name: "uprobe is not in this build",
			rt:   captureTable(agent.CaptureUprobe, []agent.ModelEndpoint{{Provider: "anthropic", Host: "h", Port: 443}}),
			tier: backend.TierBPFLSM, caps: backend.Set{backend.CapCaptureModel: true},
			wantSrc: 1, want: []string{"uprobe"}, untagged: true,
		},
		{
			name: "capture off selects and gaps nothing",
			rt:   captureTable(agent.CaptureOff, []agent.ModelEndpoint{{Provider: "anthropic", Host: "h", Port: 443}}),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.untagged && bpf.Available() {
				t.Skip("this binary carries the capture object; TestUprobeFactory covers it")
			}
			sources, gaps := selectCapture(tc.rt, m, fakeBackend{tier: tc.tier, caps: tc.caps})
			defer stopAll(t, sources)
			if len(sources) != tc.wantSrc {
				t.Fatalf("sources %v, want %d", sources, tc.wantSrc)
			}
			if len(gaps) != len(tc.want) {
				t.Fatalf("gaps %v, want %v", gaps, tc.want)
			}
			for i, want := range tc.want {
				if gaps[i].What != record.GapCapture || gaps[i].Binary != want {
					t.Fatalf("gap %d is %+v, want what=capture binary=%s", i, gaps[i], want)
				}
			}
		})
	}
}

// TestPinnedUprobeRunsNoForwarder is kill test 7 (b)'s wiring through `tego run`: examples/agents/
// anthropic-sdk-python.yaml pins capture: uprobe so that the SDK's requests are read by the probes on the system
// OpenSSL, and no forwarder is bound, so no base-URL variable reroutes them (capture.Select, PinsUprobe). In a
// build with the capture object the uprobe source is the one source; in one without, the uprobe's gap is the
// whole of capture, and still no forwarder.
func TestPinnedUprobeRunsNoForwarder(t *testing.T) {
	t.Parallel()
	m := config.Builtin()
	rt := captureTable(agent.CaptureUprobe, []agent.ModelEndpoint{{Provider: "anthropic", Host: "api.anthropic.com", Port: 443}})
	rt.Contract.Capture = agent.CaptureUprobe
	sources, gaps := selectCapture(rt, m, fakeBackend{tier: backend.TierCgroup, caps: backend.Set{backend.CapCaptureModel: true}})
	defer stopAll(t, sources)
	for _, s := range sources {
		if _, ok := s.(source.LoopbackSource); ok || s.Name() != "uprobe" {
			t.Errorf("source %s under a pinned capture: uprobe, want the uprobe source alone", s.Name())
		}
	}
	for _, g := range gaps {
		if g.Binary != "uprobe" {
			t.Errorf("gap %+v: a pinned uprobe asks nothing of the forwarder", g)
		}
	}
	wantSrc, wantGaps := 0, 1
	if bpf.Available() {
		wantSrc, wantGaps = 1, 0
	}
	if len(sources) != wantSrc || len(gaps) != wantGaps {
		t.Errorf("sources %v and gaps %v, want %d and %d (capture object in this build: %v)", sources, gaps,
			wantSrc, wantGaps, bpf.Available())
	}
}

// TestHostsForClaimsDeclaredHosts is R25's host half: a models[] entry pointing a provider at some other
// host lets the parser claim it, so dispatch still finds it when no provider name reached the dispatcher.
func TestHostsForClaimsDeclaredHosts(t *testing.T) {
	t.Parallel()
	models := []agent.ModelEndpoint{
		{Provider: "Anthropic", Host: "proxy.internal"},
		{Provider: "openai", Host: "api.openai.com"},
		{Provider: "anthropic", Host: ""},
	}
	got := hostsFor(models, "anthropic")
	if len(got) != 1 || got[0] != "proxy.internal" {
		t.Fatalf("hosts %v, want [proxy.internal]", got)
	}
}
