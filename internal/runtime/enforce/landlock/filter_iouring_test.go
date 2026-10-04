// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"testing"

	"golang.org/x/net/bpf"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestFilterIOUringArm is R10 as ADR 0018 (5) amends it (TIER3-PLAN T13): the three io_uring syscalls answer ENOSYS
// in every filter but one whose run declares io_uring: true where the kernel decision plane decides every submission
// (filterOpts.ioUring, from Run.IOUring), which allows them without a notification; openat2, clone3 and
// open_by_handle_at stay ENOSYS in both, and nothing else changes.
func TestFilterIOUringArm(t *testing.T) {
	for _, arch := range []Arch{ArchX86_64, ArchARM64} {
		tab, err := tableFor(arch)
		if err != nil {
			t.Fatal(err)
		}
		run := func(admit bool, nr uint32) uint32 {
			t.Helper()
			insts, err := buildFilter(arch, filterOpts{abi: 7, ioUring: admit, procScope: true, rootTier: true})
			if err != nil {
				t.Fatal(err)
			}
			vm, err := bpf.NewVM(insts)
			if err != nil {
				t.Fatal(err)
			}
			ret, err := vm.Run(seccompData(arch, nr))
			if err != nil {
				t.Fatal(err)
			}
			return uint32(ret)
		}
		for _, s := range tab.ENOSYS {
			want := uint32(retENOSYS)
			if isIOUring(s) {
				want = retAllow
			}
			if got := run(false, s.NR); got != retENOSYS {
				t.Errorf("%s %s without the admission: %#x, want ENOSYS", arch, s.Name, got)
			}
			if got := run(true, s.NR); got != want {
				t.Errorf("%s %s with io_uring admitted: %#x, want %#x", arch, s.Name, got, want)
			}
		}
		n := 0
		for _, s := range tab.ENOSYS {
			if isIOUring(s) {
				n++
			}
		}
		if n != 3 {
			t.Errorf("%s: %d io_uring syscalls in the ENOSYS set, want setup, enter and register", arch, n)
		}
		for _, s := range tab.Notify {
			if run(true, s.NR) != run(false, s.NR) {
				t.Errorf("%s %s: the io_uring admission changed another arm", arch, s.Name)
			}
		}
	}
}

// TestPrepareAdmitsIOUringOnlyWithThePlane is ADR 0018 (5) through Prepare: the filter leaves io_uring_* out of its
// ENOSYS arm only when the contract declares io_uring: true and the run's tier decides every submission in the
// kernel (Run.IOUring, set by tier cgroup with a plane mode); either alone keeps the arm.
func TestPrepareAdmitsIOUringOnlyWithThePlane(t *testing.T) {
	arch := NativeArch()
	tab, err := tableFor(arch)
	if err != nil {
		t.Fatal(err)
	}
	var setup uint32
	for _, s := range tab.ENOSYS {
		if s.Name == "io_uring_setup" {
			setup = s.NR
		}
	}
	answer := func(declared, decided bool) uint32 {
		t.Helper()
		rt := &agent.RuleTable{Contract: &agent.Contract{IOUring: declared, Net: &agent.NetSection{}}}
		h, err := New(Options{syscalls: &fakeSyscalls{abi: 7}}).Prepare(context.Background(), rt, Run{IOUring: decided})
		if err != nil {
			t.Fatalf("Prepare: %v", err)
		}
		defer func() { _ = h.Close() }()
		raw, ok := h.SeccompFilter()
		if !ok {
			t.Fatal("no filter")
		}
		insts := make([]bpf.Instruction, len(raw))
		for i, r := range raw {
			insts[i] = r.Disassemble()
		}
		vm, err := bpf.NewVM(insts)
		if err != nil {
			t.Fatal(err)
		}
		ret, err := vm.Run(seccompData(arch, setup))
		if err != nil {
			t.Fatal(err)
		}
		return uint32(ret)
	}
	for _, tc := range []struct {
		declared, decided bool
		want              uint32
	}{{false, false, retENOSYS}, {true, false, retENOSYS}, {false, true, retENOSYS}, {true, true, retAllow}} {
		if got := answer(tc.declared, tc.decided); got != tc.want {
			t.Errorf("io_uring: %v, the tier decides submissions: %v: io_uring_setup answered %#x, want %#x",
				tc.declared, tc.decided, got, tc.want)
		}
	}
}
