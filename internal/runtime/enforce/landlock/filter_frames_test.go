// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// TestFilterNotifiesWhatCouldStartAPendingFrame is R11d (supervisor R13's pending frames): in a run that decides
// datagrams the filter notifies every syscall that can leave a UDP frame pending on a socket, so the supervisor can
// refuse it on the socket's own kind: a sendto with no address whose flags carry MSG_MORE (an addressed one is
// notified anyway, and sendmsg and sendmmsg always are), setsockopt(UDP_CORK) at SOL_UDP or SOL_UDPLITE, and every
// sendfile and splice. The scalars are ints, so only their low 32 bits count, as the kernel reads them. Without the
// arms (a run that decides no datagrams) none of these is notified, and other calls are left as they were on both
// architectures: the arms reload the syscall number on every path that does not return.
func TestFilterNotifiesWhatCouldStartAPendingFrame(t *testing.T) {
	frames := filterOpts{abi: minTruncateABI, frames: true}
	none := filterOpts{abi: minTruncateABI}
	for _, arch := range []Arch{ArchX86_64, ArchARM64} {
		tab, err := tableFor(arch)
		if err != nil {
			t.Fatal(err)
		}
		if len(tab.Frames) != 2 {
			t.Fatalf("%s: Frames = %v, want sendfile and splice", arch, tab.Frames)
		}
		sendfile, splice := tab.Frames[0].NR, tab.Frames[1].NR
		for _, tc := range []struct {
			name          string
			nr            uint32
			args          []uint64
			framed, plain uint32
		}{
			{"send with MSG_MORE", tab.SendTo, []uint64{3, 0x1000, 4, unix.MSG_MORE, 0, 0}, retNotify, retAllow},
			{"send with MSG_MORE and MSG_DONTWAIT", tab.SendTo, []uint64{3, 0x1000, 4, unix.MSG_MORE | unix.MSG_DONTWAIT, 0, 0}, retNotify, retAllow},
			{"send with MSG_MORE, int truncation", tab.SendTo, []uint64{3, 0x1000, 4, uint64(5)<<32 | unix.MSG_MORE, 0, 0}, retNotify, retAllow},
			{"send with MSG_MORE only in the high bits", tab.SendTo, []uint64{3, 0x1000, 4, uint64(unix.MSG_MORE) << 32, 0, 0}, retAllow, retAllow},
			{"send", tab.SendTo, []uint64{3, 0x1000, 4, unix.MSG_DONTWAIT, 0, 0}, retAllow, retAllow},
			{"addressed sendto", tab.SendTo, []uint64{3, 0x1000, 4, 0, 0x2000, 16}, retNotify, retNotify},
			{"addressed sendto, high half", tab.SendTo, []uint64{3, 0x1000, 4, 0, uint64(1) << 32, 16}, retNotify, retNotify},
			{"UDP_CORK", tab.Setsockopt, []uint64{3, unix.SOL_UDP, unix.UDP_CORK, 0x9000, 4}, retNotify, retAllow},
			{"UDP_CORK at SOL_UDPLITE", tab.Setsockopt, []uint64{3, unix.IPPROTO_UDPLITE, unix.UDP_CORK, 0x9000, 4}, retNotify, retAllow},
			{"UDP_CORK, int truncation", tab.Setsockopt, []uint64{3, uint64(7)<<32 | unix.SOL_UDP, uint64(9)<<32 | unix.UDP_CORK, 0x9000, 4}, retNotify, retAllow},
			{"UDP_SEGMENT", tab.Setsockopt, []uint64{3, unix.SOL_UDP, unix.UDP_SEGMENT, 0x9000, 4}, retAllow, retAllow},
			{"UDP_CORK's number at SOL_SOCKET", tab.Setsockopt, []uint64{3, unix.SOL_SOCKET, unix.UDP_CORK, 0x9000, 4}, retAllow, retAllow},
			{"UDP_CORK's number at SOL_TCP", tab.Setsockopt, []uint64{3, unix.SOL_TCP, unix.UDP_CORK, 0x9000, 4}, retAllow, retAllow},
			{"sendfile", sendfile, []uint64{4, 5, 0, 1 << 20}, retNotify, retAllow},
			{"splice", splice, []uint64{4, 0, 5, 0, 1 << 20, 0}, retNotify, retAllow},
			{"splice with SPLICE_F_MORE", splice, []uint64{4, 0, 5, 0, 1 << 20, unix.SPLICE_F_MORE}, retNotify, retAllow},
			{"the notify set after the arms", tab.Notify[0].NR, []uint64{3, unix.SOL_UDP, unix.UDP_CORK}, retNotify, retNotify},
			{"socket after the arms", tab.Socket, []uint64{unix.AF_INET, unix.SOCK_DGRAM, 0}, retAllow, retAllow},
		} {
			if got := planeVerdict(t, arch, frames, tc.nr, tc.args...); got != tc.framed {
				t.Errorf("%s, a run that decides datagrams: %s = %#x, want %#x", arch, tc.name, got, tc.framed)
			}
			if got := planeVerdict(t, arch, none, tc.nr, tc.args...); got != tc.plain {
				t.Errorf("%s, a run that decides none: %s = %#x, want %#x", arch, tc.name, got, tc.plain)
			}
		}
	}
}

// TestObserveFilterCarriesThePendingFrameArms is R11d for an observe run: BuildFilter, the observe
// run's filter, installs the pending-frame arms when asked (enforce.Observe asks where the contract decides datagrams),
// so the observe run's supervisor, which applies its pending-frame decisions on the same predicate and continues them,
// sees and records every operation an enforcing run would refuse datagram-corked; without frames it notifies none.
func TestObserveFilterCarriesThePendingFrameArms(t *testing.T) {
	for _, arch := range []Arch{ArchX86_64, ArchARM64} {
		tab, err := tableFor(arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name string
			nr   uint32
			args []uint64
		}{
			{"send with MSG_MORE", tab.SendTo, []uint64{3, 0x1000, 4, unix.MSG_MORE, 0, 0}},
			{"UDP_CORK", tab.Setsockopt, []uint64{3, unix.SOL_UDP, unix.UDP_CORK, 0x9000, 4}},
			{"sendfile", tab.Frames[0].NR, []uint64{4, 5, 0, 1 << 20}},
			{"splice", tab.Frames[1].NR, []uint64{4, 0, 5, 0, 1 << 20, 0}},
		} {
			for _, frames := range []bool{true, false} {
				insts, err := BuildFilter(arch, false, frames)
				if err != nil {
					t.Fatal(err)
				}
				vm, err := bpf.NewVM(insts)
				if err != nil {
					t.Fatal(err)
				}
				got, err := vm.Run(seccompData(arch, tc.nr, tc.args...))
				if err != nil {
					t.Fatal(err)
				}
				want := uint32(retAllow)
				if frames {
					want = retNotify
				}
				if uint32(got) != want {
					t.Errorf("%s observe filter, frames=%v: %s = %#x, want %#x", arch, frames, tc.name, got, want)
				}
			}
		}
	}
}
