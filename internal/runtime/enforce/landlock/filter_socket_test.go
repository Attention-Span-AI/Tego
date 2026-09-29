// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/net/bpf"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

func runSocketFilter(t *testing.T, arch Arch, sa SocketArm, data []byte) uint32 {
	t.Helper()
	insts, err := buildFilter(arch, filterOpts{abi: minTruncateABI, socket: sa})
	if err != nil {
		t.Fatal(err)
	}
	vm, err := bpf.NewVM(insts)
	if err != nil {
		t.Fatalf("NewVM: %v", err)
	}
	ret, err := vm.Run(data)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return uint32(ret)
}

// The netlink protocols the socket arm's tables name beside NETLINK_ROUTE, which the filter's own netlinkRoute spells.
const netlinkSockDiag, netlinkAudit, netlinkGeneric = 4, 9, 16

// TestFilterSocketAllowlist is ADR 0018's decision table on both arches. Under a net: section socket(2) and
// socketpair(2) are admitted only as what the network rules govern, and every other triple is notified to a
// supervisor handler that can only refuse it: SCTP reached any address through SCTP_SOCKOPT_CONNECTX and a peerless
// send() with no ledger line. Without a net: section nothing changes.
//
// Spec: docs/p0/enforce-landlock.md E30.
func TestFilterSocketAllowlist(t *testing.T) {
	const (
		nonblockCloexec = 0x800 | 0x80000
		sockRaw         = 3
		sockSeqpacket   = 5
		ipprotoSCTP     = 132
		ipprotoUDPLite  = 136
		afPacket        = 17
		afTIPC          = 30
		afVsock         = 40
	)
	restricted, withICMP, open := SocketArm{Restricted: true}, SocketArm{Restricted: true, ICMP: true}, SocketArm{}
	for _, arch := range []Arch{ArchX86_64, ArchARM64} {
		tab, err := tableFor(arch)
		if err != nil {
			t.Fatal(err)
		}
		sock := func(fam, typ, proto uint64) []byte { return seccompData(arch, tab.Socket, fam, typ, proto) }
		pair := func(fam uint64) []byte { return seccompData(arch, tab.Pair, fam, 1, 0, 0) }
		for _, tc := range []struct {
			name string
			sa   SocketArm
			data []byte
			want uint32
		}{
			{"tcp", restricted, sock(afInet, sockStream|nonblockCloexec, 0), retAllow},
			{"tcp6 by number", restricted, sock(afInet6, sockStream, ipprotoTCP), retAllow},
			{"udp", restricted, sock(afInet, sockDgram, 0), retAllow},
			{"udp6 by number", restricted, sock(afInet6, sockDgram|nonblockCloexec, ipprotoUDP), retAllow},
			{"unix, any type", restricted, sock(afUnix, sockSeqpacket, 0), retAllow},
			{"netlink route", restricted, sock(afNetlink, sockRaw, 0), retAllow},
			{"netlink route, datagram and nonblocking", restricted, sock(afNetlink, sockDgram|nonblockCloexec, 0), retAllow},
			{"netlink generic", restricted, sock(afNetlink, sockRaw, netlinkGeneric), retNotify},
			{"netlink sock_diag", restricted, sock(afNetlink, sockDgram, netlinkSockDiag), retNotify},
			{"netlink audit", restricted, sock(afNetlink, sockRaw, netlinkAudit), retNotify},
			{"the netlink protocol is the low 32 bits, as the kernel's int", restricted, sock(afNetlink, sockRaw, 1<<32|netlinkGeneric), retNotify},
			{"no net: section admits netlink generic", open, sock(afNetlink, sockRaw, netlinkGeneric), retAllow},
			{"sctp stream", restricted, sock(afInet, sockStream, ipprotoSCTP), retNotify},
			{"sctp one-to-many", restricted, sock(afInet6, sockSeqpacket, ipprotoSCTP), retNotify},
			{"udp-lite", restricted, sock(afInet, sockDgram, ipprotoUDPLite), retNotify},
			{"raw inet", restricted, sock(afInet, sockRaw, ipprotoICMP), retNotify},
			{"ping without an icmp entry", restricted, sock(afInet, sockDgram, ipprotoICMP), retNotify},
			{"ping with an icmp entry", withICMP, sock(afInet, sockDgram, ipprotoICMP), retAllow},
			{"ping6 with an icmp entry", withICMP, sock(afInet6, sockDgram, ipprotoICMPv6), retAllow},
			{"vsock", restricted, sock(afVsock, sockStream, 0), retNotify},
			{"tipc", restricted, sock(afTIPC, sockSeqpacket, 0), retNotify},
			{"packet", restricted, sock(afPacket, sockRaw, 0), retNotify},
			{"unspec", restricted, sock(0, sockStream, 0), retNotify},
			{"the family is the low 32 bits, as the kernel's int", restricted, sock(1<<32|afInet, sockStream, 0), retAllow},
			{"mptcp stays the silent errno", restricted, sock(afInet, sockStream, ipprotoMPTCP), retEPROTONOSUPPORT},
			{"socketpair unix", restricted, pair(afUnix), retAllow},
			{"socketpair tipc", restricted, pair(afTIPC), retNotify},
			{"socketpair inet", restricted, pair(afInet), retNotify},
			{"no net: section admits sctp", open, sock(afInet, sockStream, ipprotoSCTP), retAllow},
			{"no net: section admits socketpair tipc", open, pair(afTIPC), retAllow},
			{"connect is still notified", restricted, seccompData(arch, tab.Notify[0].NR), retNotify},
		} {
			if got := runSocketFilter(t, arch, tc.sa, tc.data); got != tc.want {
				t.Errorf("%s %s: %#x, want %#x", arch, tc.name, got, tc.want)
			}
		}
	}
}

// TestFilterSocketArmIsTheKernelAllowlist is ADR 0018 PR 2's parity table on the seccomp side: over every family ×
// type × protocol × ICMP cell, the restricted socket arm admits (SECCOMP_RET_ALLOW) exactly the triples
// internal/bpf SocketAllowed admits, the Go spelling of bpf/include/socket_allow.h, which the plane's socket_create
// and cgroup/sock_create run in the kernel. Every other triple is refused: notified to the supervisor's handler, or
// MPTCP's silent EPROTONOSUPPORT. So no socket the filter admits is refused by a kernel layer behind it, and no
// socket a kernel layer would refuse gets past the filter on socket(2) (enforce-landlock E30, enforce-cgroup-observe
// §5 R4).
//
// The one cell where they differ is the MPTCP arm, which stays first and silent (ADR 0018's PR 1 condition): protocol
// 262 is answered EPROTONOSUPPORT in every family, AF_UNIX included, which the allowlist admits with any protocol. The
// filter is stricter there and never looser, and the kernel answers it the same way itself (unix_create refuses a
// protocol but 0 and PF_UNIX).
func TestFilterSocketArmIsTheKernelAllowlist(t *testing.T) {
	const (
		afPacket, afTIPC, afVsock, afSMC                    = 17, 30, 40, 43
		sockRaw, sockSeqpacket, nonblockCloexec             = 3, 5, 0x800 | 0x80000
		ipprotoSCTP, ipprotoUDPLite, ipprotoSMC, ipprotoRaw = 132, 136, 256, 255
	)
	families := []uint64{0, afUnix, afInet, afInet6, afNetlink, afPacket, afTIPC, afVsock, afSMC}
	types := []uint64{sockStream, sockDgram, sockRaw, sockSeqpacket, sockStream | nonblockCloexec, sockDgram | nonblockCloexec}
	protos := []uint64{0, ipprotoTCP, ipprotoUDP, ipprotoICMP, ipprotoICMPv6, ipprotoSCTP, ipprotoUDPLite, ipprotoMPTCP,
		ipprotoSMC, ipprotoRaw, ipprotoSMC + ipprotoTCP, netlinkSockDiag, netlinkAudit, netlinkGeneric}
	for _, arch := range []Arch{ArchX86_64, ArchARM64} {
		tab, err := tableFor(arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, icmp := range []bool{false, true} {
			insts, err := buildFilter(arch, filterOpts{abi: minTruncateABI, socket: SocketArm{Restricted: true, ICMP: icmp}})
			if err != nil {
				t.Fatal(err)
			}
			vm, err := bpf.NewVM(insts)
			if err != nil {
				t.Fatalf("NewVM: %v", err)
			}
			for _, fam := range families {
				for _, typ := range types {
					for _, proto := range protos {
						ret, err := vm.Run(seccompData(arch, tab.Socket, fam, typ, proto))
						if err != nil {
							t.Fatalf("Run: %v", err)
						}
						kernel := ebpfbindings.SocketAllowed(int32(fam), int32(typ), int32(proto), icmp)
						switch got := uint32(ret); {
						case proto == ipprotoMPTCP:
							if got != retEPROTONOSUPPORT {
								t.Errorf("%s icmp=%v socket(%d, %#x, MPTCP): filter %#x, want the silent EPROTONOSUPPORT",
									arch, icmp, fam, typ, got)
							}
						case kernel && got != retAllow:
							t.Errorf("%s icmp=%v socket(%d, %#x, %d): filter %#x, the kernel allowlist admits it",
								arch, icmp, fam, typ, proto, got)
						case !kernel && got != retNotify && got != retEPROTONOSUPPORT:
							t.Errorf("%s icmp=%v socket(%d, %#x, %d): filter %#x, the kernel allowlist refuses it",
								arch, icmp, fam, typ, proto, got)
						}
					}
				}
			}
		}
	}
}

// TestSocketArmFor: the arm follows the compiled net section: none without one, the allowlist with one, ping
// sockets only when an entry names an ICMP destination (port 0).
func TestSocketArmFor(t *testing.T) {
	for _, tc := range []struct {
		name string
		rt   *agent.RuleTable
		want SocketArm
	}{
		{"no net: section", &agent.RuleTable{Contract: &agent.Contract{}}, SocketArm{}},
		{"net: {}", &agent.RuleTable{Contract: &agent.Contract{Net: &agent.NetSection{}}}, SocketArm{Restricted: true}},
		{"a tcp entry", &agent.RuleTable{Contract: &agent.Contract{Net: &agent.NetSection{}},
			Net: []agent.NetRule{{Proto: agent.ProtoInet, Port: 443}}}, SocketArm{Restricted: true}},
		{"an icmp entry", &agent.RuleTable{Contract: &agent.Contract{Net: &agent.NetSection{}},
			Net: []agent.NetRule{{Proto: agent.ProtoInet, Port: 0}}}, SocketArm{Restricted: true, ICMP: true}},
		{"a unix entry is no icmp entry", &agent.RuleTable{Contract: &agent.Contract{Net: &agent.NetSection{}},
			Net: []agent.NetRule{{Proto: agent.ProtoUnix}}}, SocketArm{Restricted: true}},
	} {
		if got := SocketArmFor(tc.rt); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

// TestFilterSocketGolden pins the restricted filter's instruction stream, as TestFilterGolden does the others.
func TestFilterSocketGolden(t *testing.T) {
	for _, tc := range []struct {
		file string
		arch Arch
		sa   SocketArm
	}{
		{"filter_x86_64_net.txt", ArchX86_64, SocketArm{Restricted: true}},
		{"filter_arm64_net_icmp.txt", ArchARM64, SocketArm{Restricted: true, ICMP: true}},
	} {
		t.Run(tc.file, func(t *testing.T) {
			insts, err := buildFilter(tc.arch, filterOpts{abi: minTruncateABI, socket: tc.sa, listenControl: true})
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			for i, ins := range insts {
				fmt.Fprintf(&buf, "%3d %-16T %v\n", i, ins, ins)
			}
			path := filepath.Join("testdata", tc.file)
			if *update {
				if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update to create)", err)
			}
			if !bytes.Equal(want, buf.Bytes()) {
				t.Errorf("filter differs from %s:\n%s", path, buf.String())
			}
		})
	}
}

// TestFilterSignalScopeArm: below Landlock ABI 6 an enforcing run's filter hands the kill family and fcntl's F_SETOWN
// to the supervisor and answers pidfd_send_signal ENOSYS; every other fcntl is allowed, and without the arm (ABI 6
// and later, or an observe run) nothing of it is decided here.
func TestFilterSignalScopeArm(t *testing.T) {
	for _, arch := range []Arch{ArchX86_64, ArchARM64} {
		tab, err := tableFor(arch)
		if err != nil {
			t.Fatal(err)
		}
		run := func(signals bool, data []byte) uint32 {
			t.Helper()
			insts, err := buildFilter(arch, filterOpts{abi: 4, signals: signals})
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
		for _, s := range tab.Signal {
			if got := run(true, seccompData(arch, s.NR, 50, 9)); got != retNotify {
				t.Errorf("%s %s: %#x, want notify", arch, s.Name, got)
			}
			if got := run(false, seccompData(arch, s.NR, 50, 9)); got != retAllow {
				t.Errorf("%s %s without the arm: %#x, want allow", arch, s.Name, got)
			}
		}
		for _, tc := range []struct {
			name string
			data []byte
			want uint32
		}{
			{"pidfd_send_signal", seccompData(arch, tab.PidfdSignal, 3, 9), retENOSYS},
			{"F_SETOWN", seccompData(arch, tab.Fcntl, 3, fSetown, 50), retNotify},
			{"F_SETOWN_EX", seccompData(arch, tab.Fcntl, 3, fSetownEx, 0x1000), retNotify},
			{"F_GETFL", seccompData(arch, tab.Fcntl, 3, 3), retAllow},
			{"tgkill SIGURG, Go's preemption", seccompData(arch, tab.Signal[2].NR, 50, 51, 23), retAllow},
			{"tkill SIGURG", seccompData(arch, tab.Signal[1].NR, 51, 23), retAllow},
			{"tgkill SIGKILL", seccompData(arch, tab.Signal[2].NR, 50, 51, 9), retNotify},
			{"tgkill signal 33, Go's all-threads syscall", seccompData(arch, tab.Signal[2].NR, 50, 51, 33), retNotify},
			{"F_SETSIG", seccompData(arch, tab.Fcntl, 3, 10, 9), retAllow},
		} {
			if got := run(true, tc.data); got != tc.want {
				t.Errorf("%s %s: %#x, want %#x", arch, tc.name, got, tc.want)
			}
		}
	}
}

// TestPrepareInstallsTheSignalArmBelowABI6: Prepare hands the kill family to the supervisor exactly when the
// ruleset it builds has no signal scope.
func TestPrepareInstallsTheSignalArmBelowABI6(t *testing.T) {
	rt := &agent.RuleTable{Contract: &agent.Contract{}}
	for _, abi := range []int{4, 5, 6, 7} {
		h, _ := prepare(t, abi, rt)
		got, ok := h.SeccompFilter()
		if !ok {
			t.Fatal("no seccomp filter")
		}
		// No net: section: the unix-only state notifies bind(2), so the supervisor records the run's sockets (ADR 0070).
		want, err := assembleFilter(NativeArch(), filterOpts{abi: abi, memfd: memfdArmFor(rt.Contract, MemfdNoexecSealSupported, false),
			signals: abi < minSignalScopeABI, procScope: true, unixBinds: true})
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, want) {
			t.Errorf("ABI %d: the installed filter's signal arm is not %v", abi, abi < minSignalScopeABI)
		}
	}
}

// TestFilterRootTierArm is ADR 0033 (3): at tiers 2 and 3 the filter answers bpf, the module calls and kexec
// EPERM whatever the contract says, so even a root agent under setuid: true cannot open a pinned map to
// silence its run or load kernel code. Tier 1 needs no arm: its agent can never be root.
func TestFilterRootTierArm(t *testing.T) {
	for _, arch := range []Arch{ArchX86_64, ArchARM64} {
		tab, err := tableFor(arch)
		if err != nil {
			t.Fatal(err)
		}
		if len(tab.RootDeny) != 6 {
			t.Fatalf("%s: %d root-tier numbers, want 6", arch, len(tab.RootDeny))
		}
		for _, rootTier := range []bool{false, true} {
			insts, err := buildFilter(arch, filterOpts{abi: 7, rootTier: rootTier})
			if err != nil {
				t.Fatal(err)
			}
			vm, err := bpf.NewVM(insts)
			if err != nil {
				t.Fatal(err)
			}
			want := uint32(retAllow)
			if rootTier {
				want = retEPERM
			}
			for _, s := range tab.RootDeny {
				got, err := vm.Run(seccompData(arch, s.NR))
				if err != nil {
					t.Fatal(err)
				}
				if uint32(got) != want {
					t.Errorf("%s rootTier=%v %s: %#x, want %#x", arch, rootTier, s.Name, got, want)
				}
			}
		}
	}
}
