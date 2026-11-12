// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"context"
	"testing"

	"golang.org/x/net/bpf"

	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	cgroupenforce "github.com/attention-span-ai/tego/internal/runtime/enforce/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// fakeInherited is composed tier-1 state that records its release.
type fakeInherited struct{ closed *int }

func (fakeInherited) LandlockRuleset() (int, bool)                { return -1, false }
func (fakeInherited) SeccompFilter() ([]bpf.RawInstruction, bool) { return nil, false }
func (f fakeInherited) Close() error                              { *f.closed++; return nil }

// TestTierOneIsComposedBeforeTierTwoPrepares: cgroup.Prepare installs its fanotify marks before its own
// Inherit step, and the marks answer nothing until the facade starts the listener after Prepare returns.
// Composing tier 1 opens each exec entry O_RDONLY to read its PT_INTERP, so composed in place it waited
// on the launcher's own listener: a root `tego run --tier cgroup` in the KVM guest stalled in
// agent.ReadInterp under cgroup.Prepare, and every open on the marked mounts stalled with it. The adapter
// now composes first and hands tier 2 the result, and releases it when tier 2's Prepare fails.
func TestTierOneIsComposedBeforeTierTwoPrepares(t *testing.T) {
	if _, err := landlock.ProbeABI(); err != nil {
		t.Skipf("no Landlock on this kernel: %v", err)
	}
	withObjects(t, true)
	b, ds := Select(machine(""), table(backend.TierCgroup, "cgroup"), probeRootNoBPF)
	cb, ok := b.(cgroupBackend)
	if !ok {
		t.Fatalf("Select = %T, %v", b, ds)
	}
	var order []string
	closed := 0
	cb.opts.Inherit = func(context.Context, *agent.RuleTable, cgroupenforce.Run) (cgroupenforce.Inherited, error) {
		order = append(order, "compose tier 1")
		return fakeInherited{closed: &closed}, nil
	}
	var handed func(context.Context, *agent.RuleTable, cgroupenforce.Run) (cgroupenforce.Inherited, error)
	cb.newRun = func(o cgroupenforce.Options) *cgroupenforce.Backend {
		order = append(order, "prepare tier 2")
		handed = o.Inherit
		// Hash names a build so Prepare gets past the build identity whatever this test binary embeds;
		// it then fails for want of privilege or of the pinned objects, which is the failure path.
		o.Hash, o.StateDir, o.BPFFS = "0123456789abcdef", t.TempDir(), t.TempDir()
		return cgroupenforce.New(o)
	}
	rt := &agent.RuleTable{Tier: backend.TierCgroup, Contract: &agent.Contract{}}
	h, err := cb.Prepare(context.Background(), rt, RunRef{ID: "r", Agent: "a"})
	if len(order) < 2 || order[0] != "compose tier 1" || order[1] != "prepare tier 2" {
		t.Fatalf("order %v: tier 1 must be composed before tier 2's Prepare installs its marks", order)
	}
	if handed == nil {
		t.Fatal("tier 2 was not handed the composed state")
	}
	if inh, err := handed(context.Background(), rt, cgroupenforce.Run{}); err != nil || inh == nil || len(order) != 2 {
		t.Errorf("tier 2's Inherit composed again (%v) or handed back %v, %v", order, inh, err)
	}
	if err == nil {
		// A privileged box may get this far; the handle then owns the composed state.
		if cerr := h.Close(); cerr != nil {
			t.Logf("close: %v", cerr)
		}
	}
	if closed != 1 {
		t.Errorf("the composed tier-1 state was released %d times, want once (err=%v)", closed, err)
	}
}

// TestTierOneIsNotComposedForARefusedTable: a table tier 2 refuses is answered by cgroup.Prepare's own
// precondition, with nothing composed and nothing to release.
func TestTierOneIsNotComposedForARefusedTable(t *testing.T) {
	composed := 0
	opts := cgroupenforce.Options{Inherit: func(context.Context, *agent.RuleTable, cgroupenforce.Run) (cgroupenforce.Inherited, error) {
		composed++
		return nil, nil
	}}
	closer, err := composeFirst(context.Background(), &agent.RuleTable{Tier: backend.TierLandlock}, cgroupenforce.Run{}, &opts)
	if err != nil || closer != nil || composed != 0 {
		t.Errorf("composeFirst on a landlock table: %v, %v, composed %d times", closer, err, composed)
	}
}

// TestTheTierTwoHandleReleasesWhatItInherited: cgroup.Handle reads the inherited ruleset and filter and
// never closed them, so the Landlock ruleset fd and the O_PATH fds held for the run outlived it.
func TestTheTierTwoHandleReleasesWhatItInherited(t *testing.T) {
	closed := 0
	h := cgroupHandle{Handle: new(cgroupenforce.Handle), inherited: fakeInherited{closed: &closed}}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	if closed != 1 {
		t.Errorf("inherited state released %d times, want once", closed)
	}
	var _ api.Listener = h
	var _ KernelRecorder = h
	var _ Reporter = h
}

// frozenInherited is composed tier-1 state whose ruleset listed dirs for its deny_read entries.
type frozenInherited struct {
	fakeInherited
	dirs []string
}

func (f frozenInherited) DenyReadFrozen() []string { return f.dirs }

// TestTheTierTwoHandleNamesWhatItsRulesetFroze (GAPS A12): a root tier installs the tier-1 ruleset it composed, the
// same enumeration, so its handle names the directories that ruleset listed once at launch, for run_start's
// deny_read_frozen; inherited state that lists none names none.
func TestTheTierTwoHandleNamesWhatItsRulesetFroze(t *testing.T) {
	closed := 0
	h := cgroupHandle{Handle: new(cgroupenforce.Handle), inherited: frozenInherited{fakeInherited{&closed}, []string{"/", "/home"}}}
	if got := h.DenyReadFrozen(); len(got) != 2 || got[0] != "/" || got[1] != "/home" {
		t.Errorf("DenyReadFrozen() = %q, want the inherited ruleset's [/ /home]", got)
	}
	if got := (cgroupHandle{Handle: new(cgroupenforce.Handle), inherited: fakeInherited{&closed}}).DenyReadFrozen(); got != nil {
		t.Errorf("inherited state that lists nothing: %q", got)
	}
	var _ interface{ DenyReadFrozen() []string } = (*landlock.Handle)(nil)
}
