// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestFilterNotifiesTCPULPUnderANetSection is ADR 0018 (7): setsockopt(SOL_TCP, TCP_ULP) turned an
// admitted TCP socket into an AF_SMC one in place ("smc", the smc module's ULP), a socket no socket(2) arm, no
// cgroup/sock_create and no plane socket_create sees, so every tier reported a socket-family bound that did not hold.
// Under a net: section the socket arm now notifies that one option, on its scalar level and name, on both
// architectures, and the supervisor refuses it; the int's high bits are ignored, as the kernel ignores them. Every other
// option, TCP_ULP's number at another level, and a contract with no net: section are left alone. The arm reloads the
// syscall number, so a later arm still sees its own syscall.
func TestFilterNotifiesTCPULPUnderANetSection(t *testing.T) {
	restricted := filterOpts{abi: minTruncateABI, socket: SocketArm{Restricted: true}}
	open := filterOpts{abi: minTruncateABI}
	for _, arch := range []Arch{ArchX86_64, ArchARM64} {
		tab, err := tableFor(arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			name          string
			level, option uint64
			want          uint32
		}{
			{"TCP_ULP", unix.SOL_TCP, unix.TCP_ULP, retNotify},
			{"TCP_ULP, int truncation", uint64(7)<<32 | unix.SOL_TCP, uint64(9)<<32 | unix.TCP_ULP, retNotify},
			{"TCP_NODELAY", unix.SOL_TCP, unix.TCP_NODELAY, retAllow},
			{"TCP_CONGESTION", unix.SOL_TCP, unix.TCP_CONGESTION, retAllow},
			{"TCP_ULP's number at SOL_SOCKET", unix.SOL_SOCKET, unix.TCP_ULP, retAllow},
			{"TCP_ULP's number at SOL_IP", unix.SOL_IP, unix.TCP_ULP, retAllow},
			{"SO_KEEPALIVE", unix.SOL_SOCKET, unix.SO_KEEPALIVE, retAllow},
		} {
			if got := planeVerdict(t, arch, restricted, tab.Setsockopt, 3, tc.level, tc.option, 0x9876, 4); got != tc.want {
				t.Errorf("%s net: setsockopt(%s) = %#x, want %#x", arch, tc.name, got, tc.want)
			}
			if got := planeVerdict(t, arch, open, tab.Setsockopt, 3, tc.level, tc.option, 0x9876, 4); got != retAllow {
				t.Errorf("%s no net: section setsockopt(%s) = %#x, want allow", arch, tc.name, got)
			}
		}
		if got := planeVerdict(t, arch, restricted, tab.Socket, unix.AF_INET, unix.SOCK_STREAM, 132); got != retNotify {
			t.Errorf("%s socket(SCTP) after the arm = %#x, want notify", arch, got)
		}
		if got := planeVerdict(t, arch, restricted, tab.Notify[0].NR, 3, unix.SOL_TCP, unix.TCP_ULP); got != retNotify {
			t.Errorf("%s %s after the arm = %#x, want notify", arch, tab.Notify[0].Name, got)
		}
	}
}
