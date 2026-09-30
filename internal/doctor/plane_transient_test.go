// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"os"
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"golang.org/x/sys/unix"
)

// TestPlaneSyscallErrnoFaultsTheProbe: a probe syscall that answered neither passed nor refused (ENOSPC on the
// fixtures directory, EAGAIN from fork, EMFILE, no answer from the child) is a probe that could not finish, not a
// mode that ran and failed: the verdict is not OK and Faulted, so the run-probe cache does not keep it. An errno
// the kernel answers the same way every time (ENOSYS, EOPNOTSUPP) is a failed mode, not a fault.
func TestPlaneSyscallErrnoFaultsTheProbe(t *testing.T) {
	scoped := planeScope{Inside: 1}
	cases := []struct {
		name    string
		edit    func(*HookResult)
		faulted bool
	}{
		{"outside ENOSPC", func(r *HookResult) { r.Outside = planeOutcome(unix.ENOSPC) }, true},
		{"inside EAGAIN", func(r *HookResult) { r.Inside = planeOutcome(unix.EAGAIN) }, true},
		{"outside EMFILE", func(r *HookResult) { r.Outside = planeOutcome(unix.EMFILE) }, true},
		{"no answer from the child", func(r *HookResult) { r.Inside = "no answer from the probe child" }, true},
		{"inside ENOSYS", func(r *HookResult) { r.Inside = planeOutcome(unix.ENOSYS) }, false},
		{"outside EOPNOTSUPP", func(r *HookResult) { r.Outside = planeOutcome(unix.EOPNOTSUPP) }, false},
		{"a body that does not refuse", func(r *HookResult) { r.Inside = planePassed; r.Decides = true }, false},
	}
	for _, tc := range cases {
		rows := passingPlaneRows()[:len(bpfobj.PlaneHooks)]
		tc.edit(&rows[0])
		v := planeModeVerdict(bpfobj.PlaneLSM, rows, scoped, passingKnown())
		if v.OK || v.Faulted != tc.faulted || v.Fix == "" {
			t.Errorf("%s: %+v, want not OK, Faulted %v, a fix", tc.name, v, tc.faulted)
		}
	}

	c, path := testCache(t)
	k := testKey()
	p, hooks, fan, fs := vouchingAnswer()
	rows := passingPlaneRows()[:len(bpfobj.PlaneHooks)]
	rows[0].Outside = planeOutcome(unix.ENOSPC)
	st := passingPlane("")
	st.Modes[0] = planeModeVerdict(bpfobj.PlaneLSM, rows, scoped, passingKnown())
	c.record(k, p, hooks, st, nil, fan, fs)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("a plane probe whose syscall hit ENOSPC dropped the tier-2 entry: %v", err)
	}
	if e, ok := c.load(k); !ok || e.Plane != nil {
		t.Errorf("a probe whose syscall hit ENOSPC left a plane answer in the cache (read %v, %+v)", ok, e.Plane)
	}
}
