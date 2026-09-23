// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationRunStartSaysWhatTheRunHad is one real tier-1 run read back from its ledger, for the three
// things run_start and the gaps after it must say about the run rather than about the contract or the tier:
//
//   - capture is what started. No capture source is wired here, so run_start.capture is off although the
//     contract compiled to forwarder, and the shortfall is a gap in R37's closed set.
//   - limits carry a zero budget. The machine's tokens: 0 is the tightest budget (E16) and the watcher
//     enforces it, so run_start.limits must show it rather than no budget at all.
//   - the capability line is the run's own: every row, with capture and read recording absent, and a
//     deny_read entry under record: summary is a gap what=record why=unprivileged-tier (E56).
func TestIntegrationRunStartSaysWhatTheRunHad(t *testing.T) {
	zeroTokens := func(m *config.Machine) { m.Limits.Tokens = config.Ceiling[int64]{Bounded: true} }
	f := newFixtureWithMachine(t, `version: 0
name: irunstart
command: ["/bin/true"]
tier: landlock
fs:
  write: ["./out/"]
  deny_read: ["./agent.yaml"]
exec:
  allow: ["/bin/true"]
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 128
record: summary
`, zeroTokens)
	res, err := Run(context.Background(), f.rt, []string{"/bin/true"}, f.deps(t, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 || res.Reason != record.RunEndExit {
		t.Fatalf("result %+v, want exit 0", res)
	}
	evs := events(t, runDirs(t, f.root)[0])
	if evs[0].Kind != record.KindRunStart {
		t.Fatalf("first event %s, want run_start", evs[0].Kind)
	}
	var start record.RunStartPayload
	if err := evs[0].DecodePayload(&start); err != nil {
		t.Fatal(err)
	}
	if string(f.rt.Capture) == "off" {
		t.Fatalf("the fixture must compile to a capture mode for this test to mean anything")
	}
	if start.Capture != "off" {
		t.Errorf("run_start.capture = %q with no capture source started, want off", start.Capture)
	}

	var raw struct {
		Limits map[string]any `json:"limits"`
	}
	if err := json.Unmarshal(evs[0].Payload, &raw); err != nil {
		t.Fatal(err)
	}
	if v, ok := raw.Limits["tokens"]; !ok || v != 0.0 {
		t.Errorf("run_start.limits = %v, want tokens: 0 (E16)", raw.Limits)
	}

	if len(start.Capabilities) != len(backend.AllCapabilities()) {
		t.Fatalf("capability line has %d rows, want every one: %v", len(start.Capabilities), start.Capabilities)
	}
	for row, want := range map[backend.Capability]bool{
		backend.CapFileWriteDeny: true, backend.CapExecDeny: true,
		backend.CapCaptureModel: false, backend.CapRecordReads: false,
		backend.CapAdoptedContainers: false,
		// ADR 0041 D7: tier 1's supervisor relays a net gate's IP connects; it completes no fs or exec gate
		// decision and no kernel plane protects the built-in write targets.
		backend.CapGateNetCompletion: true, backend.CapGateFSOpenCompletion: false,
		backend.CapGateFSMutationCompletion: false, backend.CapGateExecCompletion: false,
		backend.CapProtectedWriteTargets: false,
	} {
		if got := start.Capabilities[string(row)]; got != want {
			t.Errorf("capabilities[%s] = %v, want %v", row, got, want)
		}
	}

	gaps := map[string]int{}
	for _, e := range evs {
		if e.Kind != record.KindGap {
			continue
		}
		var p record.GapPayload
		if err := e.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		gaps[p.What+"/"+p.Why]++
	}
	if gaps["record/"+GapUnprivilegedTier] != 1 {
		t.Errorf("gaps %v, want exactly one record/%s", gaps, GapUnprivilegedTier)
	}
	if gaps["capture/mechanism-unavailable"] != 1 {
		t.Errorf("gaps %v, want the capture shortfall as capture/mechanism-unavailable", gaps)
	}
}

// TestIntegrationObserveCapabilityLineIsTrue is one real --observe run read back from its ledger. An observe
// run enforces nothing, so its tier row is empty, but it records through tier 1's filter and captures through
// whatever source started: its line used to be all false, which put capture.model_traffic=false beside
// capture=forwarder and record.exec_open_connect=false above the run's own observed exec event.
func TestIntegrationObserveCapabilityLineIsTrue(t *testing.T) {
	f := newFixture(t, contractFor("iobscaps", []string{"/bin/true"}, []string{"/bin/true"}))
	f.backend = enforce.Observe()
	deps := f.deps(t, nil)
	deps.Capture = []source.Source{&plainSource{name: "forwarder"}}
	res, err := Run(context.Background(), f.rt, []string{"/bin/true"}, deps)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("result %+v, want exit 0", res)
	}
	evs := events(t, runDirs(t, f.root)[0])
	var start record.RunStartPayload
	if err := evs[0].DecodePayload(&start); err != nil {
		t.Fatal(err)
	}
	if start.Tier != string(backend.TierObserve) || start.Capture != "forwarder" {
		t.Fatalf("run_start tier=%q capture=%q, want observe and forwarder", start.Tier, start.Capture)
	}
	observedExec := false
	for _, e := range evs {
		if e.Kind == record.KindExec && e.Verdict == record.VerdictObserved {
			observedExec = true
		}
	}
	if !observedExec {
		t.Fatalf("no exec event with verdict observed: the run did not record what the line is checked against")
	}
	for row, want := range map[backend.Capability]bool{
		backend.CapCaptureModel: true, backend.CapRecordExecOpenNet: true, backend.CapLogAllowed: true,
		backend.CapRecordReads:   f.rt.Record == agent.RecordFull,
		backend.CapFileWriteDeny: false, backend.CapExecDeny: false, backend.CapAsk: false,
	} {
		if got := start.Capabilities[string(row)]; got != want {
			t.Errorf("capabilities[%s] = %v, want %v", row, got, want)
		}
	}
}

// TestIntegrationRunStartNamesTheStdioKinds: on a real run, the agent keeps the
// caller's fds 0-2 whatever they are, and run_start says what each was, here a socket on stdin.
func TestIntegrationRunStartNamesTheStdioKinds(t *testing.T) {
	f := newFixture(t, contractFor("istdio", []string{"/bin/true"}, []string{"/bin/true"}))
	deps := f.deps(t, nil)
	deps.Stdio.In = socketFile(t)
	if _, err := Run(context.Background(), f.rt, []string{"/bin/true"}, deps); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var start record.RunStartPayload
	if err := events(t, runDirs(t, f.root)[0])[0].DecodePayload(&start); err != nil {
		t.Fatal(err)
	}
	if start.Stdio == nil || start.Stdio.Stdin != record.StdioSocket {
		t.Fatalf("run_start.stdio = %+v, want stdin socket", start.Stdio)
	}
}
