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

// clientVerdicts runs a strict client filter over the six syscalls of the client list.
func clientVerdicts(t *testing.T, arch Arch, o filterOpts) map[string]uint32 {
	t.Helper()
	tab, _ := tableFor(arch)
	out := map[string]uint32{}
	for _, s := range tab.ClientDeny {
		out[s.Name] = planeVerdict(t, arch, o, s.NR)
	}
	return out
}

// TestStrictFilterKeepsRecvmsgWithoutPlaneHook (ADR 0128, amended): with no plane hook attached the strict client
// filter answers recvmsg ENOSYS, as it always did; a plane without socket_recvmsg, an empty set, and a run that is
// not strict (where the plane hook alone changes nothing) leave it exactly so, in the plane filters too.
func TestStrictFilterKeepsRecvmsgWithoutPlaneHook(t *testing.T) {
	rt := &agent.RuleTable{Contract: contractWith(true, true), NetAssurance: agent.NetAssuranceKernel}
	h, err := New(Options{syscalls: &fakeSyscalls{abi: 10}}).Prepare(context.Background(), rt, Run{})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	for name, hooks := range map[string]map[string]bool{"no hooks": nil, "the fs hooks": hookSet(stepAHooks...), "every hook but recvmsg": hookSet(append(append([]string(nil), stepAHooks...), stepBHooks...)...)} {
		t.Run(name, func(t *testing.T) {
			if _, left, err := h.PlaneImportsFilter(hooks); err != nil || left {
				t.Fatalf("PlaneImportsFilter = left %v, %v; want the filter's own recvmsg answer", left, err)
			}
			prog, _, err := h.PlaneFilter(hooks)
			if err != nil {
				t.Fatal(err)
			}
			if prog == nil {
				prog = h.filter
			}
			insts, ok := bpf.Disassemble(prog)
			if !ok {
				t.Fatal("the plane filter does not disassemble")
			}
			vm, err := bpf.NewVM(insts)
			if err != nil {
				t.Fatal(err)
			}
			tab, _ := tableFor(NativeArch())
			for _, s := range tab.ClientDeny {
				if s.Name != "recvmsg" {
					continue
				}
				if ret, err := vm.Run(seccompData(NativeArch(), s.NR)); err != nil || uint32(ret) != retENOSYS {
					t.Errorf("recvmsg answered %#x, %v; want ENOSYS", ret, err)
				}
			}
		})
	}
	// The hook alone, with no strict assurance, changes nothing: the filter never denied recvmsg.
	plain, err := New(Options{syscalls: &fakeSyscalls{abi: 10}}).Prepare(context.Background(), &agent.RuleTable{Contract: contractWith(true, true)}, Run{})
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if _, left, err := plain.PlaneImportsFilter(hookSet(HookSocketRecvmsg)); err != nil || left {
		t.Fatalf("a run without strict assurance: left %v, %v", left, err)
	}
	for _, arch := range []Arch{ArchX86_64, ArchARM64} {
		if got := clientVerdicts(t, arch, filterOpts{abi: 10, strictNet: true})["recvmsg"]; got != retENOSYS {
			t.Errorf("%s: a strict filter with no plane skip answers recvmsg %#x", arch, got)
		}
	}
}

// TestStrictFilterLeavesRecvmsgToThePlaneForTheOpenDeputy: a strict run that starts the open deputy (fs.reads: held)
// leaves recvmsg to the plane as a run with no deputy does (ADR 0128, amended 2026-11-21): the hook passes the deputy by
// the identity the launcher writes into the run's slot before Arm, and refuses every other task's control receive.
// Before, such a run kept the filter's ENOSYS, and with it the interface-list limit. PlaneImportsFilter and PlaneFilter
// leave recvmsg to the plane for both.
func TestStrictFilterLeavesRecvmsgToThePlaneForTheOpenDeputy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reads  agent.HeldReads
		deputy bool
	}{{"held reads", agent.HeldReads{Mode: agent.ReadsHeld}, true}, {"no deputy", agent.HeldReads{}, false}} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &agent.RuleTable{Contract: contractWith(true, true), Tier: backend.TierLandlock, NetAssurance: agent.NetAssuranceKernel, Reads: tc.reads}
			if rt.NeedsOpenDeputy() != tc.deputy {
				t.Fatalf("NeedsOpenDeputy = %v, want %v", rt.NeedsOpenDeputy(), tc.deputy)
			}
			h, err := New(Options{syscalls: &fakeSyscalls{abi: 10}}).Prepare(context.Background(), rt, Run{})
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			hooks := hookSet(HookSocketRecvmsg)
			prog, left, err := h.PlaneImportsFilter(hooks)
			if err != nil || !left {
				t.Fatalf("PlaneImportsFilter = left %v, %v; want left true", left, err)
			}
			pprog, _, err := h.PlaneFilter(hooks)
			if err != nil {
				t.Fatal(err)
			}
			tab, _ := tableFor(NativeArch())
			for label, raw := range map[string][]bpf.RawInstruction{"imports filter": prog, "plane filter": pprog} {
				insts, ok := bpf.Disassemble(raw)
				if !ok {
					t.Fatalf("%s does not disassemble", label)
				}
				vm, err := bpf.NewVM(insts)
				if err != nil {
					t.Fatal(err)
				}
				for _, s := range tab.ClientDeny {
					if s.Name != "recvmsg" {
						continue
					}
					want := uint32(retAllow)
					if ret, err := vm.Run(seccompData(NativeArch(), s.NR)); err != nil || uint32(ret) != want {
						t.Errorf("%s: recvmsg answered %#x, %v; want %#x", label, ret, err, want)
					}
				}
			}
		})
	}
}

// TestStrictFilterOmitsRecvmsgWithPlaneHook: with socket_recvmsg attached the strict client filter no longer answers
// recvmsg ENOSYS (the plane refuses a control-bearing receive in the kernel), and still answers recvmmsg,
// pidfd_getfd, listen, accept and accept4 ENOSYS; PlaneImportsFilter says so, PlaneFilter's program leaves it out
// too, and its dropped list stays fs-only, so an fs-ignorant plane filter is not taken for an fs decision.
func TestStrictFilterOmitsRecvmsgWithPlaneHook(t *testing.T) {
	for _, arch := range []Arch{ArchX86_64, ArchARM64} {
		for name, v := range clientVerdicts(t, arch, filterOpts{abi: 10, strictNet: true, plane: planeSkip{recvmsg: true}}) {
			want := uint32(retENOSYS)
			if name == "recvmsg" {
				want = retAllow
			}
			if v != want {
				t.Errorf("%s: %s answers %#x, want %#x", arch, name, v, want)
			}
		}
	}
	rt := &agent.RuleTable{Contract: contractWith(true, true), NetAssurance: agent.NetAssuranceKernel}
	h, err := New(Options{syscalls: &fakeSyscalls{abi: 10}}).Prepare(context.Background(), rt, Run{})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	hooks := hookSet(HookSocketRecvmsg)
	prog, left, err := h.PlaneImportsFilter(hooks)
	if err != nil || !left {
		t.Fatalf("PlaneImportsFilter = left %v, %v", left, err)
	}
	pprog, dropped, err := h.PlaneFilter(hooks)
	if err != nil || len(dropped) != 0 {
		t.Fatalf("PlaneFilter with only the receive hook: dropped %v, %v; the dropped list names fs notifications only", dropped, err)
	}
	tab, _ := tableFor(NativeArch())
	for label, raw := range map[string][]bpf.RawInstruction{"imports filter": prog, "plane filter": pprog} {
		insts, ok := bpf.Disassemble(raw)
		if !ok {
			t.Fatalf("%s does not disassemble", label)
		}
		vm, err := bpf.NewVM(insts)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range tab.ClientDeny {
			ret, err := vm.Run(seccompData(NativeArch(), s.NR))
			if err != nil {
				t.Fatal(err)
			}
			want := uint32(retENOSYS)
			if s.Name == "recvmsg" {
				want = retAllow
			}
			if uint32(ret) != want {
				t.Errorf("%s: %s answers %#x, want %#x", label, s.Name, ret, want)
			}
		}
	}
}
