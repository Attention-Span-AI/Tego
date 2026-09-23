// SPDX-License-Identifier: Apache-2.0

package capture

import (
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The producer contract, spelled here as docs/p0/capture-derive.md §2 spells it. They are aliases rather
// than new types: internal/runtime owns the contract every source of a run satisfies (the eBPF recorder,
// this component's two sources), and a second definition of the same four shapes would mean a capture
// Source could not be handed to runtime.Deps.Capture at all.
type (
	// Source is one long-running producer of events owned by the run. §2 calls its gap accessor
	// Coverage(); the interface calls it Gaps(), and the run emits every source's gaps at run_end
	// (runner.emitSourceGaps).
	Source = source.Source
	// Sink receives events without returning an error. The run's capture lane waits a bounded time
	// for queue space, then counts dropped events; lost metering can end a budgeted run.
	Sink = source.Sink
	// RunRef identifies the run a source is producing for.
	RunRef = source.RunRef
	// Gap is one uncovered capture path. Capture only ever produces what=capture gaps.
	Gap = source.Gap
)

// Gap reasons, the closed set of R37. A capture shortfall is always one of the nine of derive.CaptureWhys (the forwarder's emit-queue-full is the ninth) and never a silence
// (§8 I4). The first six are what a running mechanism failed to see; the last two are Select's own, a
// mechanism that never ran at all.
const (
	// GapNoOpenSSL is R4 finding nothing to attach to, and the generic bucket §7 assigns every
	// attach failure whose real cause the closed why set cannot express.
	GapNoOpenSSL = "no-openssl"
	// GapStaticTLSNoSymbols is a TLS implementation with no OpenSSL symbols: Bun's BoringSSL, rustls.
	GapStaticTLSNoSymbols = "static-tls-no-symbols"
	// GapH2 is an h2 connection preface on a traced connection (R17).
	GapH2 = "h2"
	// GapMalformed is HTTP/1.1 reassembly could not follow (R18).
	GapMalformed = "malformed"
	// GapRingBufferDrop is the kernel's own lost-sample counter.
	GapRingBufferDrop = "ring-buffer-drop"
	// GapSizeCap is a bound this component imposes: R5's scratch map, R6's chunk split, R13's
	// header cap, R11's pipeline depth.
	GapSizeCap = "size-cap"
	// GapNoModels is a contract with capture on and no models[] entry: the forwarder has no endpoint to
	// bind a listener for (R19), so it is not started. The gap names the forwarder as its binary.
	GapNoModels = "no-models"
	// GapMechanismUnavailable is a mechanism the run wanted that this binary does not carry (a nil
	// Factory) or could not construct for this run (a Factory that failed); binary names which.
	GapMechanismUnavailable = "mechanism-unavailable"
)

// Factory builds one capture source. A caller supplies the constructors for the mechanisms its binary
// carries; Select decides which of them the compiled contract and the tier actually want.
type Factory func() (Source, error)

// The two mechanisms, named as their sources name themselves (Source.Name) and as the capture mode each
// provides. A gap's binary field uses the same name, and the run reads run_start.capture off the names of
// the sources that actually started, so the three spellings must never drift apart.
const (
	mechanismUprobe    = string(agent.CaptureUprobe)
	mechanismForwarder = string(agent.CaptureForwarder)
)

// Deps are the source constructors Select chooses between. A nil member means that mechanism is not part
// of this binary: Select reports a mechanism-unavailable gap for it rather than leaving a silence, because
// a run that captured nothing and said nothing is exactly what I4 forbids.
type Deps struct {
	// Uprobe builds the OpenSSL uprobe source (internal/runtime/capture/uprobe).
	Uprobe Factory
	// Forwarder builds the loopback forwarder source (internal/runtime/capture/forwarder).
	Forwarder Factory
}

// Select returns the capture sources a run should start and the gaps its choice already implies. It never
// fails a run: a mechanism that cannot be built is a Coverage gap, not an error (§4).
//
// capture: off returns nothing and no gap — a run that asked for no capture is not missing anything.
// capture: forwarder runs the forwarder alone. The uprobe source runs at capture: uprobe, and at auto, which
// Compile resolves to uprobe where the tier allows it, once the tier and the machine admit it (wantsUprobe).
// Beside it the forwarder runs too, except when the contract itself pinned capture: uprobe
// (agent.RuleTable.PinsUprobe): that contract asks for the agent's own TLS to be read by the probes, and a
// forwarder would take the agent's model traffic away from them by setting its base-URL variable (FEATURES
// kill test 7 (b)). Where the tier cannot run uprobes, a pinned uprobe tops out at the forwarder, as Compile
// and agent.AtTier lower it, and `tego run` warns for each of the contract's variables the forwarder's then
// override (agent-contract R12). When both run they never see the same request: the forwarder only sees loopback
// traffic its own base-URL variable routed to it, uprobe only real upstream TLS (P0-DESIGN §2.9, amended
// 2026-09-23 for the pinned case).
//
// A mechanism that cannot run is one gap naming it in binary, and the why says which of two things is
// true. no-models: the contract declares no models[] endpoint, so the forwarder has nothing to listen for
// and is never constructed. mechanism-unavailable: this binary does not carry the mechanism, or its
// constructor failed. Both used to be filed under no-openssl, which is R4's finding about a process's
// libraries and is false of a forwarder and of a uprobe source that never started (R37, amended).
//
// A table with no contract attached (a caller that compiled nothing it could name) is not judged on
// models[]: the forwarder factory decides for itself whether it can be built.
func Select(rt *agent.RuleTable, tier backend.Tier, caps backend.Set, deps Deps) ([]Source, []Gap) {
	if rt == nil || rt.Capture == agent.CaptureOff {
		return nil, nil
	}
	var sources []Source
	var gaps []Gap
	// A selection gap carries no count: count is the number of events a gap lost (spec/record/v1), and a
	// mechanism that never ran lost no event it had — it had none.
	unavailable := func(name, why string) {
		gaps = append(gaps, Gap{What: record.GapCapture, Why: why, Binary: name})
	}
	add := func(name string, f Factory) {
		if f == nil {
			unavailable(name, GapMechanismUnavailable)
			return
		}
		s, err := f()
		if err != nil || s == nil {
			unavailable(name, GapMechanismUnavailable)
			return
		}
		sources = append(sources, s)
	}
	uprobe := wantsUprobe(rt, tier, caps)
	if uprobe {
		add(mechanismUprobe, deps.Uprobe)
	}
	if uprobe && rt.PinsUprobe() {
		return sources, gaps // no forwarder: see above
	}
	if rt.Contract != nil && len(rt.Contract.Models) == 0 {
		unavailable(mechanismForwarder, GapNoModels)
	} else {
		add(mechanismForwarder, deps.Forwarder)
	}
	return sources, gaps
}

// wantsUprobe reports whether the compiled contract and the tier admit the uprobe source. The compiler
// has already lowered capture to the tier's ceiling (agent.Compile's tierAndCapture), so this is a
// re-check rather than a decision: a tier below cgroup, or a machine whose probe found the capability
// missing, cannot run uprobes however the contract reads.
func wantsUprobe(rt *agent.RuleTable, tier backend.Tier, caps backend.Set) bool {
	if rt.Capture != agent.CaptureUprobe && rt.Capture != agent.CaptureAuto {
		return false
	}
	if tier != "" && !backend.TierCgroup.AtOrBelow(tier) {
		return false
	}
	if caps != nil && !caps[backend.CapCaptureModel] {
		return false
	}
	return true
}
