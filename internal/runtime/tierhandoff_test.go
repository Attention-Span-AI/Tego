// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// handoffBackend records what the facade hands a tier at Prepare and answers with a fixed handle.
type handoffBackend struct {
	tier   backend.Tier
	handle api.Handle
	gotRT  *agent.RuleTable
	gotRun enforce.RunRef
}

func (b *handoffBackend) Tier() backend.Tier        { return b.tier }
func (b *handoffBackend) Capabilities() backend.Set { return backend.Matrix(b.tier) }
func (b *handoffBackend) Prepare(_ context.Context, rt *agent.RuleTable, run enforce.RunRef) (api.Handle, error) {
	b.gotRT, b.gotRun = rt, run
	return b.handle, nil
}

// handoffRunner is a runner at the point prepareEnforcement runs: a run id, a cgroup and a table.
func handoffRunner(b *handoffBackend, build Build) *runner {
	r := newTestRunner(Deps{Enforce: b, Build: build})
	r.id, r.agentID, r.dir = "01JTESTRUN", "a", "/nonexistent/run"
	r.cg = cgroup.Cgroup{Path: "/sys/fs/cgroup/tego.slice/run.scope", ID: 42}
	r.rt = &agent.RuleTable{Tier: b.tier, Contract: &agent.Contract{Name: "a"}}
	return r
}

// TestPrepareHandsTheTierTheRunsQueue is the facade half of docs/p0/enforce-cgroup-observe.md §7: the
// tier is prepared with a live event sink, and it is the queue the pipeline drains. The queue used to be
// made in startWorkers, after Prepare, so every tier-2 backend was built with Events nil and its fanotify
// listener's refusals and gaps went to a counter nothing reads.
func TestPrepareHandsTheTierTheRunsQueue(t *testing.T) {
	b := &handoffBackend{tier: backend.TierCgroup, handle: tier2Handle{hash: "0123456789abcdef"}}
	r := handoffRunner(b, Build{})
	if err := r.prepareEnforcement(context.Background()); err != nil {
		t.Fatal(err)
	}
	if b.gotRun.Events == nil {
		t.Fatal("the tier was prepared with no event sink: its refusals and §7 gaps would never reach the ledger")
	}
	// The listener's own lane of the run's queue.
	l, ok := b.gotRun.Events.(laneSink)
	if !ok || l.q != r.runQueue() || l.l != LaneListener {
		t.Fatalf("Events = %#v, want the listener's lane of the run's own queue", b.gotRun.Events)
	}
	// What the listener emits is waiting in the queue the pipeline will read.
	ev := &record.Event{Kind: record.KindFS, Source: record.SourceFanotify, Verdict: record.VerdictRefused}
	b.gotRun.Events.Emit(ev)
	select {
	case got := <-r.queue.lanes[LaneListener]:
		if got != ev {
			t.Errorf("queue gave %+v, want the tier's event", got)
		}
	default:
		t.Error("the tier's event is not in the run's queue")
	}
	if b.gotRun.CgroupID != 42 || b.gotRun.CgroupMount != "/sys/fs/cgroup" || b.gotRun.CgroupPath != "/tego.slice/run.scope" {
		t.Errorf("RunRef %+v does not place the run's cgroup", b.gotRun)
	}
}

// TestRunStartBPFHashIsThePreparedTiers: run_start.bpf_hash names the pins the run's programs live in,
// which only a tier with a ring buffer has; tier 1 records it empty whatever the build carries (record
// v1: "empty in tier 1"). Before, the CLI's hard-coded "none" reached every run_start as "", so a tier-2
// run said nothing about which build's programs enforced it.
func TestRunStartBPFHashIsThePreparedTiers(t *testing.T) {
	b := &handoffBackend{tier: backend.TierCgroup, handle: tier2Handle{hash: "0123456789abcdef"}}
	r := handoffRunner(b, Build{BPFHash: "fedcba9876543210"})
	if err := r.prepareEnforcement(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.deps.Build.BPFHash; got != "0123456789abcdef" {
		t.Errorf("tier 2 bpf_hash %q, want the handle's own", got)
	}

	b = &handoffBackend{tier: backend.TierLandlock, handle: tier1Handle{}}
	r = handoffRunner(b, Build{BPFHash: "fedcba9876543210"})
	if err := r.prepareEnforcement(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := r.deps.Build.BPFHash; got != "" {
		t.Errorf("tier 1 bpf_hash %q, want empty: no BPF program enforces a landlock run", got)
	}
}

// TestRunEnforcesTheTableAtTheSelectedTier is the handoff R14 leaves to the runtime: an auto contract
// compiles to the machine's ceiling, the CLI selects what the machine really offers, and the backend must
// be handed a table that says so — the tier-2 backend refuses any other (ErrTier, exit 125).
func TestRunEnforcesTheTableAtTheSelectedTier(t *testing.T) {
	compiled := &agent.RuleTable{Tier: backend.TierBPFLSM, Capture: agent.CaptureUprobe, Record: agent.RecordSummary,
		Contract: &agent.Contract{Name: "a"}}
	cases := []struct {
		selected    backend.Tier
		wantTier    backend.Tier
		wantCapture agent.CaptureMode
	}{
		{backend.TierCgroup, backend.TierCgroup, agent.CaptureUprobe},
		{backend.TierLandlock, backend.TierLandlock, agent.CaptureForwarder},
		// An observe run enforces nothing; its table stays as compiled.
		{backend.TierObserve, backend.TierBPFLSM, agent.CaptureUprobe},
	}
	for _, tc := range cases {
		t.Run(string(tc.selected), func(t *testing.T) {
			b := &handoffBackend{tier: tc.selected, handle: tier1Handle{}}
			r, err := newRunner(compiled, []string{"/bin/true"}, Deps{Config: config.Builtin(), Enforce: b})
			if err != nil {
				t.Fatal(err)
			}
			if r.rt.Tier != tc.wantTier || r.rt.Capture != tc.wantCapture {
				t.Errorf("the run enforces tier %s capture %s, want %s %s", r.rt.Tier, r.rt.Capture, tc.wantTier, tc.wantCapture)
			}
			r.id, r.cg = "01JTESTRUN", cgroup.Cgroup{ID: 1}
			if err := r.prepareEnforcement(context.Background()); err != nil {
				t.Fatal(err)
			}
			if b.gotRT != r.rt {
				t.Error("the backend was prepared with a table other than the one the run enforces")
			}
		})
	}
	if compiled.Tier != backend.TierBPFLSM || compiled.Capture != agent.CaptureUprobe {
		t.Error("the compiled table was modified (agent.RuleTable I4)")
	}
}

// listeningHandle is a tier-2 shaped handle whose Attach, like any open on a marked mount, cannot
// complete until the listener answers.
type listeningHandle struct {
	tier2Handle
	listening chan struct{}
	attached  bool
}

func (h *listeningHandle) RunListener(ctx context.Context) error {
	close(h.listening)
	<-ctx.Done()
	return nil
}

func (h *listeningHandle) Attach(uint64) error {
	select {
	case <-h.listening:
		h.attached = true
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("Attach waited on a listener that was never started")
	}
}

// TestTheListenerAnswersBeforeTheLauncherOpensAnything: tier 2's fanotify marks are live when Prepare
// returns and cover whole mounts, so whatever the launcher does next that opens a file on one of them —
// the kernel recorder's factory, Attach, the own log's lazily opened file — waits for the listener.
// The facade started the listener last, after both, and a root `tego run --tier cgroup` in the KVM guest
// stalled with the launcher's own thread in fanotify_get_response and every other opener on / behind it.
func TestTheListenerAnswersBeforeTheLauncherOpensAnything(t *testing.T) {
	h := &listeningHandle{tier2Handle: tier2Handle{hash: "0123456789abcdef"}, listening: make(chan struct{})}
	b := &handoffBackend{tier: backend.TierCgroup, handle: h}
	r := handoffRunner(b, Build{})
	factoryWaited := make(chan error, 1)
	r.deps.ObserveFactory = func(string) (source.Source, error) {
		select {
		case <-h.listening:
			factoryWaited <- nil
		case <-time.After(5 * time.Second):
			factoryWaited <- errors.New("the kernel recorder was built before the listener started")
		}
		return &plainSource{name: "observe"}, nil
	}
	group, gctx := newGroup(context.Background())
	r.group = group
	defer func() {
		group.Cancel()
		_ = group.Wait()
	}()
	if err := r.prepareEnforcement(gctx); err != nil {
		t.Fatal(err)
	}
	if err := <-factoryWaited; err != nil {
		t.Error(err)
	}
	if !h.attached {
		t.Error("Attach did not complete")
	}
}
