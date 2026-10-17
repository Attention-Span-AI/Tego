// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRecordOffAutoCapturesWithTheForwarder: under record: off the uprobe source places no
// probe, so a contract that reaches uprobe through auto captures with the forwarder alone, and the table says
// so: its capture is forwarder at every tier, and its models[] endpoints are guarded, so a direct connection to
// the model host is refused rather than neither captured nor refused. Compiled as uprobe, the table guarded
// nothing (GuardedModels guards under forwarder alone), and a tokens budget was spent past by any agent that
// ignored the forwarder's base URL. The record mode is the run's, so `tego run --record off` does the same; a
// pinned capture: uprobe keeps its mode (its run is refused for a declared budget instead), and record: summary
// keeps uprobe, whose probes read a direct connection's TLS.
func TestRecordOffAutoCapturesWithTheForwarder(t *testing.T) {
	const head = "version: 0\nname: offauto\ncommand: [\"python\", \"agent.py\"]\n"
	const models = "models:\n  - { provider: anthropic, host: api.anthropic.com, port: 443 }\n"
	direct := Action{Kind: ActionNetConnect, Host: "api.anthropic.com", Port: 443}
	refused := EvalResult{Verdict: VerdictRefused, Rule: "models[api.anthropic.com:443]", Reason: record.ReasonNetNotAllowed}
	for _, tc := range []struct {
		name, body string
		opts       []CompileOption
		want       CaptureMode
		guarded    bool
	}{
		{"auto, record: off, a token budget", "record: off\n" + models + "limits: {tokens: 1000}\n", nil, CaptureForwarder, true},
		{"auto, record: off, no budget", "record: off\n" + models, nil, CaptureForwarder, true},
		{"auto, record: off, net.allow names the model host", "record: off\nnet:\n  allow: [\"api.anthropic.com:443\"]\n" + models +
			"limits: {tokens: 1000}\n", nil, CaptureForwarder, true},
		{"auto, --record off", models + "limits: {tokens: 1000}\n", []CompileOption{WithRecord(RecordOff)}, CaptureForwarder, true},
		{"auto, record: off, tier: cgroup", "tier: cgroup\nrecord: off\n" + models + "limits: {tokens: 1000}\n", nil, CaptureForwarder, true},
		{"auto, record: off, no models:", "record: off\nlimits: {tokens: 1000}\n", nil, CaptureForwarder, false},
		{"pinned uprobe, record: off", "record: off\ncapture: uprobe\n" + models + "limits: {tokens: 1000}\n", nil, CaptureUprobe, false},
		{"auto, record: summary", "record: summary\n" + models + "limits: {tokens: 1000}\n", nil, CaptureUprobe, false},
		{"auto, record: full", "record: full\n" + models + "limits: {tokens: 1000}\n", nil, CaptureUprobe, false},
		{"capture: off, record: off", "record: off\ncapture: off\n" + models, nil, CaptureOff, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			opts := append([]CompileOption{WithTiers(backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM)}, tc.opts...)
			rt, ds := f.compile(f.load(head+tc.body), opts...)
			if rt.Capture != tc.want {
				t.Fatalf("compiled capture %s at tier %s, want %s:\n%s", rt.Capture, rt.Tier, tc.want, render(ds))
			}
			for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
				at := rt.AtTier(tier)
				got := at.Evaluate(direct, tier)
				if tc.guarded && got != refused {
					t.Errorf("tier %s: a direct connection to the model host = %+v, want %+v", tier, got, refused)
				}
				if !tc.guarded && tier != backend.TierLandlock && len(at.GuardedModels()) != 0 {
					t.Errorf("tier %s: guarded %+v, want nothing", tier, at.GuardedModels())
				}
			}
		})
	}
}
