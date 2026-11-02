// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"testing"

	"golang.org/x/net/bpf"

	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
)

// TestEveryNotifiedSyscallHasAHandler walks every variant of the filter on both arches over every syscall
// number, with arguments that take each conditional arm, and requires the supervisor to have a dispatch entry
// for every number that can come back USER_NOTIF. The supervisor answers an undispatched notification ENOSYS
// (ADR 0018), so a missing or misnumbered entry fails closed; this makes it fail loud, before a release, instead
// of refusing a syscall every agent needs.
//
// Spec: docs/p0/enforce-landlock.md R11.
func TestEveryNotifiedSyscallHasAHandler(t *testing.T) {
	argShapes := [][]uint64{
		{},
		{0, WriteFlagMask, WriteFlagMask},  // open/openat with every write bit
		{0, 0, 0, 0, 1},                    // sendto with a destination
		{2, 1, 132},                        // an SCTP socket
		{40, 1, 0},                         // an AF_VSOCK socket
		{30, 5, 0},                         // an AF_TIPC socket / socketpair
		{0, mfdNoexecSeal | mfdHugetlb, 0}, // memfd_create flags the sealing arm refuses
		{0, ioctlTIOCSTI, 0},               // ioctl request
		// The signals arm's owner-setting calls (below ABI 6): fcntl F_SETOWN and F_SETOWN_EX, ioctl FIOSETOWN
		// and SIOCSPGRP. Without them the arm's fcntl and ioctl branches never notify here, and a misnumbered
		// archTable.Fcntl or Ioctl, which no other unit test pins against the supervisor's numbers, went unseen.
		{3, 8, 0}, {3, 15, 0}, {3, 0x8901, 0}, {3, 0x8902, 0},
		{50, 1, 0x1000},         // the process-scope arm: prlimit64 with a new limit, setpriority of a group
		{3, 6, 31},              // setsockopt(SOL_TCP, TCP_ULP), the socket arm's ULP refusal (ADR 0018 (7))
		{3, 17, 1}, {3, 136, 1}, // setsockopt(UDP_CORK) at SOL_UDP and SOL_UDPLITE, R11d's pending-frame arm
		{3, 0, 0, 0x8000, 0, 0},                // a sendto with no address and MSG_MORE, R11d's
		{0xffffffff, 0xffffffff, 0xffffffffff}, // everything set
	}
	for _, arch := range []Arch{ArchX86_64, ArchARM64} {
		for _, full := range []bool{false, true} {
			for _, abi := range []int{1, minTruncateABI} {
				for _, m := range []MemfdArm{MemfdOpen, MemfdSealed, MemfdRefused} {
					for _, o := range []filterOpts{{}, {socket: SocketArm{Restricted: true}},
						{socket: SocketArm{Restricted: true, ICMP: true}, signals: true, procScope: true}, {signals: true}, {procScope: true},
						{gateWrite: true}, {gateRead: true}, {frames: true}, {socket: SocketArm{Restricted: true}, frames: true},
						{watches: true}} {
						o.full, o.abi, o.memfd = full, abi, m
						sa := o.socket
						insts, err := buildFilter(arch, o)
						if err != nil {
							t.Fatal(err)
						}
						vm, err := bpf.NewVM(insts)
						if err != nil {
							t.Fatal(err)
						}
						for nr := uint32(0); nr < 1024; nr++ {
							for _, args := range argShapes {
								ret, err := vm.Run(seccompData(arch, nr, args...))
								if err != nil {
									t.Fatal(err)
								}
								if uint32(ret) == retNotify && !supervisor.Dispatches(uint32(arch), int32(nr)) {
									t.Errorf("%s full=%v abi=%d memfd=%s socket=%+v signals=%v: syscall %d is notified and the supervisor has no handler for it",
										arch, full, abi, m, sa, o.signals, nr)
								}
							}
						}
					}
				}
			}
		}
	}
}
