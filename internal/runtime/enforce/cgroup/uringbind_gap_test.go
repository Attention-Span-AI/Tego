// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"fmt"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// uringBindGap reads what test/workloads/uringbind printed in place of its steps: result is its "RESULT uring" value,
// empty when every step ran. Only a kernel below 6.11 may lack IORING_OP_BIND, which is what the skip list allows
// (test/vm/root-skips.txt). A ring refused to the agent is never that: the caller has ruled out
// kernel.io_uring_disabled, and the contract says `io_uring: true`, so the refusal is the run's own, such as the
// filter's ENOSYS still in force, and the skip would hide it behind the list on every kernel.
func uringBindGap(result string, kernel sys.KernelVersion) (skip bool, err error) {
	switch {
	case result == "":
		return false, nil
	case result != "unsupported":
		return false, fmt.Errorf("io_uring refused to an agent whose contract admits it: %s", result)
	case kernel.Major > 6 || kernel.Major == 6 && kernel.Minor >= 11:
		return false, fmt.Errorf("kernel %s completed IORING_OP_BIND with EINVAL, and it has had the op since 6.11", kernel)
	}
	return true, nil
}

// TestUringBindGap holds the skip of TestPlaneRunIOUringListenerOutcomes to the kernel it was listed for. That test
// needs root and the BPF objects, and root-skips.txt is its only skip gate, so a skip it takes wrongly fails nothing.
func TestUringBindGap(t *testing.T) {
	old := sys.KernelVersion{Major: 6, Minor: 10, Extra: "-rc1"}
	oldMajor := sys.KernelVersion{Major: 5, Minor: 14}
	first := sys.KernelVersion{Major: 6, Minor: 11}
	current := sys.KernelVersion{Major: 6, Minor: 17, Extra: "-41-generic"}
	nextMajor := sys.KernelVersion{Major: 7, Minor: 0}
	const refused = "unavailable uring: io_uring is not available: io_uring_setup: function not implemented"
	for _, c := range []struct {
		name     string
		result   string
		kernel   sys.KernelVersion
		skip     bool
		wantFail bool
	}{
		{name: "every step ran", kernel: current},
		{name: "every step ran on an old kernel", kernel: old},
		{name: "no op on 6.10", result: "unsupported", kernel: old, skip: true},
		{name: "no op on 5.14", result: "unsupported", kernel: oldMajor, skip: true},
		{name: "no op on 6.11", result: "unsupported", kernel: first, wantFail: true},
		{name: "no op on a current kernel", result: "unsupported", kernel: current, wantFail: true},
		{name: "no op on a next major", result: "unsupported", kernel: nextMajor, wantFail: true},
		{name: "ring refused on a current kernel", result: refused, kernel: current, wantFail: true},
		{name: "ring refused on an old kernel", result: refused, kernel: old, wantFail: true},
		{name: "a line the test does not know", result: "something else", kernel: old, wantFail: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			skip, err := uringBindGap(c.result, c.kernel)
			if skip != c.skip || (err != nil) != c.wantFail {
				t.Fatalf("uringBindGap(%q, %s) = %v, %v; want skip %v, fail %v", c.result, c.kernel, skip, err, c.skip, c.wantFail)
			}
		})
	}
}
