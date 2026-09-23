// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// tier2Standin is a tier-2 backend as the facade sees one, built on a real tier-1 backend so it runs
// unprivileged: it reports tier cgroup, holds the table to cgroup.Prepare's precondition (the table must
// say cgroup), names a ring buffer, and owns a listener that refuses one open through the run's sink the
// way tier 2's fanotify listener does. It stands in only for the kernel half nothing unprivileged can load.
type tier2Standin struct{ inner enforce.Backend }

const standinHash = "0123456789abcdef"

func (b tier2Standin) Tier() backend.Tier        { return backend.TierCgroup }
func (b tier2Standin) Capabilities() backend.Set { return backend.Matrix(backend.TierCgroup) }
func (b tier2Standin) Prepare(ctx context.Context, rt *agent.RuleTable, run enforce.RunRef) (api.Handle, error) {
	if rt.Tier != backend.TierCgroup {
		return nil, fmt.Errorf("stand-in for cgroup.Prepare: table says %q, want cgroup", rt.Tier)
	}
	h, err := b.inner.Prepare(ctx, rt, run)
	if err != nil {
		return nil, err
	}
	return &standinHandle{Handle: h, run: run}, nil
}

type standinHandle struct {
	api.Handle
	run enforce.RunRef
}

func (h *standinHandle) BPFHash() string { return standinHash }

// RunListener refuses one read the way fanotify.go's emitRefusal reports it, then answers until the run
// ends, as the real listener does.
func (h *standinHandle) RunListener(ctx context.Context) error {
	if h.run.Events == nil {
		return errors.New("stand-in listener: prepared with no event sink")
	}
	ev := &record.Event{V: record.Version, TS: time.Now(), Run: h.run.ID, Agent: h.run.Agent, Cgroup: h.run.CgroupID,
		Kind: record.KindFS, Source: record.SourceFanotify, Rule: "fs.deny_read[0]",
		Verdict: record.VerdictRefused, Authority: record.AuthorityRule, Reason: record.ReasonReadDenied}
	if err := ev.SetPayload(record.FSPayload{Op: record.FSOpen, Path: "/secret/key.pem"}); err != nil {
		return err
	}
	h.run.Events.Emit(ev)
	<-ctx.Done()
	return nil
}

// TestIntegrationTierTwoRefusalReachesTheLedger: an auto contract (compiled for the machine's ceiling, bpflsm) runs
// on a tier-2
// backend, which is handed a table stamped cgroup, and the refusal its listener emits through RunRef.Events
// is a line of the run's ledger. run_start names the tier and the handle's bpf_hash. Before, the table
// kept its compiled tier and cgroup.Prepare refused it, and the listener had no sink, so its refusal was
// only a dropped-counter increment.
func TestIntegrationTierTwoRefusalReachesTheLedger(t *testing.T) {
	f := newFixture(t, `version: 0
name: itier2
command: ["/bin/true"]
fs:
  write: ["./out/"]
exec:
  allow: ["/bin/true"]
env:
  pass: ["PATH", "HOME"]
record: summary
`)
	if f.rt.Tier != backend.TierBPFLSM {
		t.Fatalf("an auto contract compiled to %s on an unbounded machine; this test assumes bpflsm", f.rt.Tier)
	}
	deps := f.deps(t, nil)
	deps.Enforce = tier2Standin{inner: f.backend}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := Run(ctx, f.rt, []string{"/bin/true"}, deps)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("result %+v", res)
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v", dirs)
	}
	evs := events(t, dirs[0])
	var start record.RunStartPayload
	if err := evs[0].DecodePayload(&start); err != nil {
		t.Fatal(err)
	}
	if start.Tier != string(backend.TierCgroup) || start.BPFHash != standinHash {
		t.Errorf("run_start tier %q bpf_hash %q, want cgroup and the handle's %s", start.Tier, start.BPFHash, standinHash)
	}
	var refused *record.Event
	for _, e := range evs {
		if e.Source == record.SourceFanotify && e.Verdict == record.VerdictRefused {
			refused = e
		}
	}
	if refused == nil {
		t.Fatalf("the tier's refusal never reached the ledger: %v", kinds(evs))
	}
	var fs record.FSPayload
	if err := refused.DecodePayload(&fs); err != nil || fs.Path != "/secret/key.pem" {
		t.Errorf("refusal payload %+v, %v", fs, err)
	}
	if refused.Run == "" || refused.Run != evs[0].Run {
		t.Errorf("the refusal is not stamped with this run's id: %q, run_start %q", refused.Run, evs[0].Run)
	}
}

// lingeringHandle is a tier-2 handle whose listener returns when the run ends while one of its workers is
// still answering an event it held: the line that worker records reaches the sink only in WaitListener,
// after the run group's Wait, as a real fanotify worker's can (enforce-cgroup-observe §6 E35).
type lingeringHandle struct {
	api.Handle
	run    enforce.RunRef
	waited bool
}

func (h *lingeringHandle) RunListener(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func (h *lingeringHandle) WaitListener(ctx context.Context) error {
	h.waited = true
	ev := &record.Event{V: record.Version, TS: time.Now(), Run: h.run.ID, Agent: h.run.Agent, Cgroup: h.run.CgroupID,
		Kind: record.KindFS, Source: record.SourceFanotify, Rule: "fs.deny_read[0]",
		Verdict: record.VerdictRefused, Authority: record.AuthorityRule, Reason: record.ReasonReadDenied}
	if err := ev.SetPayload(record.FSPayload{Op: record.FSOpen, Path: "/secret/late.pem"}); err != nil {
		return err
	}
	h.run.Events.Emit(ev)
	return nil
}

type lingeringStandin struct {
	inner enforce.Backend
	h     *lingeringHandle
}

func (b *lingeringStandin) Tier() backend.Tier        { return backend.TierCgroup }
func (b *lingeringStandin) Capabilities() backend.Set { return backend.Matrix(backend.TierCgroup) }
func (b *lingeringStandin) Prepare(ctx context.Context, rt *agent.RuleTable, run enforce.RunRef) (api.Handle, error) {
	h, err := b.inner.Prepare(ctx, rt, run)
	if err != nil {
		return nil, err
	}
	b.h = &lingeringHandle{Handle: h, run: run}
	return b.h, nil
}

// TestIntegrationListenerWorkersAreWaitedForBeforeTheDrain pins the shutdown order E35 depends on: a
// refusal a listener's worker records after the listener itself returned is still a line of the ledger,
// because shutdown waits for the workers (api.ListenerWaiter) before its final drain. Without the wait
// the line is recorded after run_end, into a closed pipeline, and the ledger never shows the refusal.
func TestIntegrationListenerWorkersAreWaitedForBeforeTheDrain(t *testing.T) {
	f := newFixture(t, `version: 0
name: ilinger
command: ["/bin/true"]
fs:
  write: ["./out/"]
exec:
  allow: ["/bin/true"]
env:
  pass: ["PATH", "HOME"]
record: summary
`)
	deps := f.deps(t, nil)
	sb := &lingeringStandin{inner: f.backend}
	deps.Enforce = sb
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if _, err := Run(ctx, f.rt, []string{"/bin/true"}, deps); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if sb.h == nil || !sb.h.waited {
		t.Fatal("shutdown never waited for the listener's workers")
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v", dirs)
	}
	evs := events(t, dirs[0])
	var found bool
	for _, e := range evs {
		var fs record.FSPayload
		if e.Source == record.SourceFanotify && e.Verdict == record.VerdictRefused && e.DecodePayload(&fs) == nil && fs.Path == "/secret/late.pem" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the late worker's refusal never reached the ledger: %v", kinds(evs))
	}
	if last := evs[len(evs)-1]; last.Kind != record.KindRunEnd {
		t.Fatalf("the ledger does not end with run_end: %v", kinds(evs))
	}
}
