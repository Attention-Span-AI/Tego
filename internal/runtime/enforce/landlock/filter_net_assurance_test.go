// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"context"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

func TestStrictClientFilterClosesSocketImportsAndListeners(t *testing.T) {
	for _, arch := range []Arch{ArchX86_64, ArchARM64} {
		tab, _ := tableFor(arch)
		if len(tab.ClientDeny) != 6 {
			t.Fatalf("%s: client syscall list %+v", arch, tab.ClientDeny)
		}
		for _, strict := range []bool{false, true} {
			insts, err := buildFilter(arch, filterOpts{abi: 10, strictNet: strict})
			if err != nil {
				t.Fatal(err)
			}
			vm, err := bpf.NewVM(insts)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range tab.ClientDeny {
				ret, err := vm.Run(seccompData(arch, s.NR))
				if err != nil {
					t.Fatal(err)
				}
				want := uint32(retAllow)
				if strict {
					want = retENOSYS
				}
				if uint32(ret) != want {
					t.Errorf("%s strict=%v %s: %#x want %#x", arch, strict, s.Name, ret, want)
				}
			}
		}
	}
	// Preparation and its plane-filter variant must retain the guards, rather
	// than only the standalone filter builder used by the VM checks above.
	rt := &agent.RuleTable{Contract: contractWith(true, true), NetAssurance: agent.NetAssuranceKernel}
	h, err := New(Options{syscalls: &fakeSyscalls{abi: 10}}).Prepare(context.Background(), rt, Run{})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if g := h.NetworkGuarantees(); !g.SocketImportsDenied || !g.ListenersDenied || g.TCPDestination || g.UDPDestination || g.UnixDestination {
		t.Fatalf("Landlock guarantees: %+v", g)
	}
	if _, _, err := h.PlaneFilter(map[string]bool{HookFileOpen: true}); err != nil {
		t.Fatal(err)
	}
	if !h.filterOpts.strictNet {
		t.Fatal("plane relaxation dropped client guard")
	}
}

// TestSocketFamiliesFollowTheSocketArm is ADR 0018's guarantee at tier 1: under a net: section every socket(2) and
// socketpair(2) the run makes is decided by the filter's socket arm in the kernel, on its scalar arguments, and
// io_uring, the one other way to make a socket, is ENOSYS. With no net: section nothing is refused (SEMANTICS §1),
// and with io_uring admitted (a root tier's plane, Run.IOUring) an IORING_OP_SOCKET never meets the filter, so this
// tier alone guarantees nothing: the plane's socket_create is what does then (enforce/cgroup).
func TestSocketFamiliesFollowTheSocketArm(t *testing.T) {
	for _, tc := range []struct {
		name    string
		network bool
		uring   bool
		want    bool
	}{
		{"a net: section", true, false, true},
		{"no net: section", false, false, false},
		{"io_uring admitted", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := contractWith(true, tc.network)
			c.IOUring = tc.uring
			rt := &agent.RuleTable{Contract: c, Tier: backend.TierCgroup}
			h, err := New(Options{syscalls: &fakeSyscalls{abi: 10}}).Prepare(context.Background(), rt, Run{IOUring: tc.uring})
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			if got := h.NetworkGuarantees().SocketFamilies; got != tc.want {
				t.Fatalf("SocketFamilies = %v, want %v", got, tc.want)
			}
			// The bound also covers a socket turned into another family after it is made: wherever it is reported,
			// the installed filter notifies setsockopt(SOL_TCP, TCP_ULP) (ADR 0018 (7)).
			raw, ok := h.SeccompFilter()
			if !ok {
				t.Fatal("no filter installed")
			}
			insts, ok := bpf.Disassemble(raw)
			if !ok {
				t.Fatal("the installed filter does not disassemble")
			}
			vm, err := bpf.NewVM(insts)
			if err != nil {
				t.Fatal(err)
			}
			tab, err := tableFor(NativeArch())
			if err != nil {
				t.Fatal(err)
			}
			ret, err := vm.Run(seccompData(NativeArch(), tab.Setsockopt, 3, unix.SOL_TCP, unix.TCP_ULP, 0x9876, 4))
			if err != nil {
				t.Fatal(err)
			}
			if notified := uint32(ret) == retNotify; tc.want && !notified || !tc.network && notified {
				t.Errorf("setsockopt(SOL_TCP, TCP_ULP) answered %#x with SocketFamilies %v", ret, tc.want)
			}
		})
	}
}
