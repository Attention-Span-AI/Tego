// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIntegrationZeroTokenCeilingEndsTheRun is the acceptance, end to end through the facade.
//
// An operator writes `limits: {tokens: 0}` in the machine config. That is the tightest budget the
// configuration language can express, and E16 says it is a hard one: the run must end on its first
// response. What it used to get instead was a run with no token budget at all — the ceiling
// resolved to the number 0, every consumer downstream read 0 as "nobody set this", and the
// limit-above-machine warning told the operator the ceiling had been kept while it was in fact the
// only ceiling that could not be.
//
// The omitted half runs the same agent and the same producer with no machine ceiling at all, so the
// two cases differ in exactly one thing: whether the ceiling was written.
func TestIntegrationZeroTokenCeilingEndsTheRun(t *testing.T) {
	zeroCeiling := func(m *config.Machine) {
		m.Limits.Tokens = config.Ceiling[int64]{Bounded: true}
	}
	f := newFixtureWithMachine(t, contractFor("izerotok", []string{"/bin/sleep"}, []string{"/bin/sleep"}), zeroCeiling)
	if !f.rt.Limits.Bounded(agent.BudgetTokens) || f.rt.Limits.Tokens != 0 {
		t.Fatalf("the compiled table lost the zero ceiling: %+v", f.rt.Limits)
	}

	deps := f.deps(t, nil)
	deps.Capture = []source.Source{&usageSource{every: 50 * time.Millisecond, tokens: 60}}
	res, err := Run(context.Background(), f.rt, []string{"/bin/sleep", "30"}, deps)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Reason != record.RunEndLimit || res.ExitCode != identity.ExitLimit {
		t.Fatalf("result %+v, want limit/124", res)
	}
	evs := events(t, runDirs(t, f.root)[0])
	lim := limitEvent(t, evs)
	if lim.Which != record.LimitTokens || lim.Ceiling != 0 || lim.Value <= 0 {
		t.Fatalf("limit payload %+v, want tokens over a ceiling of 0", lim)
	}
	// The first response is the one that crosses it: 60 tokens, one tick, nothing accumulated.
	if lim.Value != 60 {
		t.Errorf("limit fired at %v tokens, want the first response's 60 (E16)", lim.Value)
	}
	var end record.RunEndPayload
	if err := evs[len(evs)-1].DecodePayload(&end); err != nil {
		t.Fatal(err)
	}
	if end.Reason != record.RunEndLimit || end.ExitCode != identity.ExitLimit {
		t.Fatalf("run_end %+v, want limit/124", end)
	}
}

// TestIntegrationOmittedTokenCeilingIsUnbounded is the other half, and the reason the fix is a
// presence bit rather than a comparison change: with no ceiling written anywhere the same producer
// spends tokens freely and the agent runs to its own end.
func TestIntegrationOmittedTokenCeilingIsUnbounded(t *testing.T) {
	f := newFixture(t, contractFor("iopentok", []string{"/bin/sleep"}, []string{"/bin/sleep"}))
	if f.rt.Limits.Bounded(agent.BudgetTokens) {
		t.Fatalf("an omitted tokens came out bounded: %+v", f.rt.Limits)
	}

	deps := f.deps(t, nil)
	deps.Capture = []source.Source{&usageSource{every: 50 * time.Millisecond, tokens: 60}}
	res, err := Run(context.Background(), f.rt, []string{"/bin/sleep", "2"}, deps)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Reason != record.RunEndExit || res.ExitCode != 0 {
		t.Fatalf("result %+v, want a clean exit: an omitted ceiling is not a budget", res)
	}
	if evs := events(t, runDirs(t, f.root)[0]); has(evs, record.KindLimit) {
		t.Fatalf("a limit event with no ceiling set: %v", kinds(evs))
	}
}
