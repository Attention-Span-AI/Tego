// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"testing"

	"golang.org/x/net/bpf"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestFilterProcScopeArm is enforce-landlock R7's process scope (supervisor R35): no Landlock ABI governs
// prlimit64, setpriority, the sched_set* calls or ioprio_set, and at tier 1 the agent shares its launcher's uid,
// so prlimit64(launcher, RLIMIT_CPU, {1, 1}) had the kernel SIGKILL the launcher even inside an ABI-6 signal scope.
// The arm hands a call on another task to the supervisor and allows one on the caller itself (and a prlimit64
// read) without a notification.
func TestFilterProcScopeArm(t *testing.T) {
	for _, arch := range []Arch{ArchX86_64, ArchARM64} {
		tab, err := tableFor(arch)
		if err != nil {
			t.Fatal(err)
		}
		run := func(on bool, data []byte) uint32 {
			t.Helper()
			insts, err := buildFilter(arch, filterOpts{abi: 7, procScope: on})
			if err != nil {
				t.Fatal(err)
			}
			vm, err := bpf.NewVM(insts)
			if err != nil {
				t.Fatal(err)
			}
			ret, err := vm.Run(data)
			if err != nil {
				t.Fatal(err)
			}
			return uint32(ret)
		}
		cases := []struct {
			name string
			data []byte
			want uint32
		}{
			{"prlimit64 of another pid", seccompData(arch, tab.Prlimit, 50, 0, 0x1000), retNotify},
			{"prlimit64 with a pointer above 4 GiB", seccompData(arch, tab.Prlimit, 50, 0, 1<<32), retNotify},
			{"prlimit64 of itself", seccompData(arch, tab.Prlimit, 0, 0, 0x1000), retAllow},
			{"prlimit64 read of another pid", seccompData(arch, tab.Prlimit, 50, 0, 0, 0x1000), retAllow},
			{"setpriority of another process", seccompData(arch, tab.Setpriority, prioProcess, 50, 19), retNotify},
			{"setpriority of itself", seccompData(arch, tab.Setpriority, prioProcess, 0, 19), retAllow},
			{"setpriority of its group", seccompData(arch, tab.Setpriority, 1, 0, 19), retNotify},
			{"setpriority of its uid", seccompData(arch, tab.Setpriority, 2, 0, 19), retNotify},
			{"ioprio_set of another process", seccompData(arch, tab.IoprioSet, ioprioWhoProcess, 50, 0), retNotify},
			{"ioprio_set of itself", seccompData(arch, tab.IoprioSet, ioprioWhoProcess, 0, 0), retAllow},
			{"ioprio_set of its uid", seccompData(arch, tab.IoprioSet, 3, 0, 0), retNotify},
		}
		for _, s := range tab.TaskArg0 {
			cases = append(cases,
				struct {
					name string
					data []byte
					want uint32
				}{s.Name + " of another task", seccompData(arch, s.NR, 50, 8, 0x1000), retNotify},
				struct {
					name string
					data []byte
					want uint32
				}{s.Name + " of itself", seccompData(arch, s.NR, 0, 8, 0x1000), retAllow})
		}
		for _, tc := range cases {
			if got := run(true, tc.data); got != tc.want {
				t.Errorf("%s %s: %#x, want %#x", arch, tc.name, got, tc.want)
			}
			if got := run(false, tc.data); got != retAllow {
				t.Errorf("%s %s without the arm: %#x, want allow", arch, tc.name, got)
			}
		}
	}
}

// TestPrepareInstallsTheProcScopeArm: every enforcing run carries the process-scope arm, at every ABI (Landlock's
// signal scope from ABI 6 does not cover these calls) and every tier.
func TestPrepareInstallsTheProcScopeArm(t *testing.T) {
	tab, err := tableFor(NativeArch())
	if err != nil {
		t.Fatal(err)
	}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup} {
		for _, abi := range []int{1, 5, 6, 7} {
			h, _ := prepare(t, abi, &agent.RuleTable{Contract: &agent.Contract{}, Tier: tier})
			raw, ok := h.SeccompFilter()
			if !ok {
				t.Fatal("no seccomp filter")
			}
			vm, err := bpf.NewVM(disassemble(t, raw))
			if err != nil {
				t.Fatal(err)
			}
			ret, err := vm.Run(seccompData(NativeArch(), tab.Prlimit, 50, 0, 0x1000))
			if err != nil {
				t.Fatal(err)
			}
			if uint32(ret) != retNotify {
				t.Errorf("tier %s ABI %d: prlimit64 of another pid answered %#x, want notify", tier, abi, uint32(ret))
			}
		}
	}
}

// disassemble turns an installed filter back into instructions for bpf.NewVM.
func disassemble(t *testing.T, raw []bpf.RawInstruction) []bpf.Instruction {
	t.Helper()
	insts, ok := bpf.Disassemble(raw)
	if !ok {
		t.Fatal("the installed filter does not disassemble")
	}
	return insts
}
