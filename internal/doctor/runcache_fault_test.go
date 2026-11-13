// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"os"
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
)

// TestRunCacheNeverKeepsAFaultedPlaneProbe: a mode whose probe could not finish (fixtures, scratch cgroup, a
// timeout) is no deterministic answer, and its cause is not in the key, so the plane answer is not kept and one an
// earlier run left is replaced; D7's tier-2 rows and D8's answer, which do not depend on it, stay readable. A mode
// that ran and failed, or was ruled out by a precondition, is kept.
func TestRunCacheNeverKeepsAFaultedPlaneProbe(t *testing.T) {
	c, path := testCache(t)
	k := testKey()
	p, rows, fan, fs := vouchingAnswer()
	c.record(k, p, rows, passingPlane(""), nil, fan, fs)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("a passing plane answer was not kept: %v", err)
	}

	faulted := passingPlane("")
	faulted.Modes[0] = PlaneModeResult{Mode: bpfobj.PlaneLSM, Tested: true, Faulted: true, Detail: "fixtures: no space"}
	c.record(k, p, rows, faulted, passingPlaneRows(), fan, fs)
	switch e, ok := c.load(k); {
	case !ok:
		t.Error("a faulted plane probe dropped the tier-2 half of the entry")
	case e.Plane != nil || e.PlaneRows != nil:
		t.Errorf("a faulted plane probe was kept: %+v", e.Plane)
	case !vouches(e.Programs, e.Hooks, e.Fanotify, e.FanotifyState):
		t.Error("the tier-2 half no longer vouches")
	}
	if err := c.store(runCacheEntry{Key: k, Programs: p, Hooks: rows, PlaneRows: passingPlaneRows(), Fanotify: fan,
		FanotifyState: fs}); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.load(k); ok {
		t.Error("an entry holding plane rows without a plane answer was read")
	}
	if err := c.store(runCacheEntry{Key: k, Programs: p, Hooks: rows, Plane: faulted, Fanotify: fan, FanotifyState: fs}); err != nil {
		t.Fatal(err)
	}
	if _, ok := c.load(k); ok {
		t.Error("an entry holding a faulted plane probe was read")
	}

	ruledOut := passingPlane("")
	ruledOut.Modes[0] = PlaneModeResult{Mode: bpfobj.PlaneLSM, Detail: "bpf is not in the active LSM list"}
	c.record(k, p, rows, ruledOut, nil, fan, fs)
	if _, ok := c.load(k); !ok {
		t.Error("a mode ruled out by a precondition was not kept")
	}
}

// TestMemfdNoexecIsAPrecondition: vm.memfd_noexec=2 rules both modes out before any load.
func TestMemfdNoexecIsAPrecondition(t *testing.T) {
	env := PlaneEnv{MemfdNoexec: 2}
	if d, fix := modePrecondition(bpfobj.PlaneLSM, env, LSMState{BPFActive: true}); d == "" || fix == "" {
		t.Errorf("vm.memfd_noexec=2 is no precondition: %q %q", d, fix)
	}
	if d, _ := modePrecondition(bpfobj.PlaneFmodRet, env, LSMState{BPFActive: true}); d == "" {
		t.Error("vm.memfd_noexec=2 leaves fmod_ret mode probeable")
	}
	if d, _ := modePrecondition(bpfobj.PlaneLSM, PlaneEnv{MemfdNoexec: 1, LSMRecursionExempt: true}, LSMState{BPFActive: true}); d != "" {
		t.Errorf("vm.memfd_noexec=1 rules the mode out: %q", d)
	}
}

// TestRunCacheKeyHoldsMemfdNoexec: the sysctl changes what the plane probe can do, so the key holds it.
func TestRunCacheKeyHoldsMemfdNoexec(t *testing.T) {
	if _, err := os.Stat(memfdNoexecPath); err != nil {
		t.Skip("no vm.memfd_noexec on this kernel")
	}
	rel, _ := os.ReadFile("/proc/sys/kernel/osrelease")
	k, ok := machineRunCacheKey(string(rel[:len(rel)-1]), os.Getuid())
	if ok && k.MemfdNoexec == "" {
		t.Errorf("key %+v holds no memfd_noexec", k)
	}
}
