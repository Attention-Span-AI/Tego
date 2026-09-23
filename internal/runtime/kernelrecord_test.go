// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"log/slog"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/net/bpf"
)

// tier1Handle is an enforcement handle with no ring buffer of its own, the tier-1 shape.
type tier1Handle struct{}

func (tier1Handle) LandlockRuleset() (int, bool)                { return -1, false }
func (tier1Handle) SeccompFilter() ([]bpf.RawInstruction, bool) { return nil, false }
func (tier1Handle) Attach(uint64) error                         { return nil }
func (tier1Handle) Detach() error                               { return nil }
func (tier1Handle) Close() error                                { return nil }

// tier2Handle also names a ring buffer, the tier-2 shape (enforce.KernelRecorder).
type tier2Handle struct {
	tier1Handle
	hash string
}

func (h tier2Handle) BPFHash() string { return h.hash }

func newTestRunner(deps Deps) *runner {
	return &runner{deps: deps, log: slog.New(slog.DiscardHandler)}
}

// TestKernelRecordTier1StartsNothing pins the tier-1 case: the supervisor is the only producer and
// writes events directly, so there is no ring buffer to drain and no gap to report either.
func TestKernelRecordTier1StartsNothing(t *testing.T) {
	called := false
	r := newTestRunner(Deps{ObserveFactory: func(string) (source.Source, error) {
		called = true
		return &plainSource{name: "observe"}, nil
	}})
	r.startKernelRecord(tier1Handle{})
	if called {
		t.Error("the factory ran for a tier with no ring buffer")
	}
	if r.kernelRecord != nil {
		t.Error("a recorder was started for tier 1")
	}
	if len(r.deps.CaptureGaps) != 0 {
		t.Errorf("tier 1 reported a gap for a record it never had: %+v", r.deps.CaptureGaps)
	}
}

// TestKernelRecordTier2StartsTheRecorder is the wiring: a tier that writes a ring
// buffer gets a recorder built from the hash its handle names, and that recorder joins the run's
// sources so it is started and stopped with everything else.
func TestKernelRecordTier2StartsTheRecorder(t *testing.T) {
	var gotHash string
	src := &plainSource{name: "observe"}
	r := newTestRunner(Deps{ObserveFactory: func(hash string) (source.Source, error) {
		gotHash = hash
		return src, nil
	}})
	r.startKernelRecord(tier2Handle{hash: "deadbeef"})
	t.Cleanup(r.closeHookQueues)
	if gotHash != "deadbeef" {
		t.Errorf("the factory was given %q, want the handle's own hash", gotHash)
	}
	if r.kernelRecord != src {
		t.Fatalf("kernelRecord = %v, want the built source", r.kernelRecord)
	}
	var found bool
	for _, s := range r.allSources() {
		if rf, ok := s.(recorderFirst); ok {
			s = rf.Source // started through the wrapper that withdraws its followers when it reads nothing
		}
		if s == src {
			found = true
		}
	}
	if !found {
		t.Error("the recorder is not in the run's sources, so nothing would start or stop it")
	}
	if len(r.deps.CaptureGaps) != 0 {
		t.Errorf("a working recorder reported a gap: %+v", r.deps.CaptureGaps)
	}
}

// TestKernelRecordGapsWhenItCannotRun covers both ways the recorder can be absent on a tier that has
// one. Either way the run must say so: a kernel record that was never drained reads exactly like a run
// where nothing happened, and P0-DESIGN §6 forbids that silence.
func TestKernelRecordGapsWhenItCannotRun(t *testing.T) {
	cases := []struct {
		name string
		deps Deps
	}{
		{"no factory in this build", Deps{}},
		{"the factory failed", Deps{ObserveFactory: func(string) (source.Source, error) {
			return nil, errors.New("no pinned ring buffer")
		}}},
		{"the factory returned nothing", Deps{ObserveFactory: func(string) (source.Source, error) {
			return nil, nil
		}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTestRunner(tc.deps)
			r.startKernelRecord(tier2Handle{hash: "deadbeef"})
			t.Cleanup(r.closeHookQueues)
			if r.kernelRecord != nil {
				t.Error("a recorder was started although the factory produced none")
			}
			if len(r.deps.CaptureGaps) != 1 {
				t.Fatalf("gaps %+v, want exactly one", r.deps.CaptureGaps)
			}
			g := r.deps.CaptureGaps[0]
			if g.What != record.GapRecord || g.Why != GapKernelRecordUnavailable || g.Count != 1 {
				t.Errorf("gap %+v, want what=%s why=%s count=1", g, record.GapRecord, GapKernelRecordUnavailable)
			}
		})
	}
}

// compile-time proof that the tier-2 shape really satisfies the optional interface the runtime asserts.
var _ enforce.KernelRecorder = tier2Handle{}

// activitySource is a kernel recorder that reports activity (ActivityReporter).
type activitySource struct {
	plainSource
	activity func(uint64)
}

func (s *activitySource) SetActivity(fn func(uint64)) { s.activity = fn }

// TestKernelRecordActivityUnderRecordOff: under record: off the recorder keeps no line for allowed work, so the
// budget watcher saw a busy tier-2 agent as idle. The run hands the recorder a way to tell the watcher of each
// sample, under record: off only.
func TestKernelRecordActivityUnderRecordOff(t *testing.T) {
	for _, mode := range []agent.RecordMode{agent.RecordOff, agent.RecordSummary} {
		t.Run(string(mode), func(t *testing.T) {
			src := &activitySource{plainSource: plainSource{name: "observe"}}
			r := newTestRunner(Deps{ObserveFactory: func(string) (source.Source, error) { return src, nil }})
			r.rt, r.queue = &agent.RuleTable{Record: mode}, NewQueue(4)
			r.startKernelRecord(tier2Handle{hash: "deadbeef"})
			t.Cleanup(r.closeHookQueues)
			if (src.activity != nil) != (mode == agent.RecordOff) {
				t.Fatalf("activity set %v under record: %s", src.activity != nil, mode)
			}
			if src.activity == nil {
				return
			}
			src.activity(5) // before the budget exists: nothing to tell, and no panic
			r.newBudget()
			src.activity(7_000_000_000)
			if got := r.budget.Snapshot().LastEventMonoNS; got != 7_000_000_000 {
				t.Errorf("the watcher's last activity is %d, want the sample's", got)
			}
		})
	}
}
