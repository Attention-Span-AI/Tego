// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestFilterRefusesMPTCPSocket is E30: Landlock's network hooks check LANDLOCK_ACCESS_NET_* only for
// sk_is_tcp()/sk_is_udp() sockets and `else return 0` for everything else (security/landlock/net.c), so
// an IPPROTO_MPTCP socket is outside the domain's net rules entirely. R6 grants BIND_TCP only on a port
// net.listen declares, and with no net.listen the supervisor continues a bind for Landlock to decide, so for
// MPTCP that bind would be nobody's to refuse. go-landlock hit this (issue #50) when Go 1.24 made MPTCP the
// default for net.Listen.
//
// The refusal is EPROTONOSUPPORT, what a kernel built without CONFIG_MPTCP returns, so a runtime that
// probes for MPTCP falls back to a classic TCP socket — which Landlock and the supervisor do see.
//
// Spec: docs/p0/enforce-landlock.md E30.
func TestFilterRefusesMPTCPSocket(t *testing.T) {
	const (
		x86Socket = 41
		armSocket = 198
	)
	cases := []struct {
		name string
		arch Arch
		data []byte
		want uint32
	}{
		{"x86 MPTCP -> EPROTONOSUPPORT", ArchX86_64, seccompData(ArchX86_64, x86Socket, unix.AF_INET, unix.SOCK_STREAM, ipprotoMPTCP), retEPROTONOSUPPORT},
		{"x86 MPTCP inet6 -> EPROTONOSUPPORT", ArchX86_64, seccompData(ArchX86_64, x86Socket, unix.AF_INET6, unix.SOCK_STREAM, ipprotoMPTCP), retEPROTONOSUPPORT},
		{"arm64 MPTCP -> EPROTONOSUPPORT", ArchARM64, seccompData(ArchARM64, armSocket, unix.AF_INET, unix.SOCK_STREAM, ipprotoMPTCP), retEPROTONOSUPPORT},
		// Everything Landlock can actually see must be untouched: the guard is not a socket() ban.
		{"x86 default TCP -> allow", ArchX86_64, seccompData(ArchX86_64, x86Socket, unix.AF_INET, unix.SOCK_STREAM, 0), retAllow},
		{"x86 explicit IPPROTO_TCP -> allow", ArchX86_64, seccompData(ArchX86_64, x86Socket, unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_TCP), retAllow},
		{"x86 UDP -> allow", ArchX86_64, seccompData(ArchX86_64, x86Socket, unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP), retAllow},
		{"x86 unix -> allow", ArchX86_64, seccompData(ArchX86_64, x86Socket, unix.AF_UNIX, unix.SOCK_STREAM, 0), retAllow},
		{"arm64 default TCP -> allow", ArchARM64, seccompData(ArchARM64, armSocket, unix.AF_INET, unix.SOCK_STREAM, 0), retAllow},
		// The x86 socket number must not meet the MPTCP arm on arm64. There 41 is pivot_root, which the
		// mount-family arm notifies (R11, landlock-topology), so the answer is a notification, never
		// EPROTONOSUPPORT.
		{"x86 socket number on arm64 -> not the MPTCP arm", ArchARM64, seccompData(ArchARM64, x86Socket, unix.AF_INET, unix.SOCK_STREAM, ipprotoMPTCP), retNotify},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runFilter(t, tc.arch, false, tc.data); got != tc.want {
				t.Errorf("filter = %#x, want %#x", got, tc.want)
			}
			// The arm is ABI-independent: Landlock's net hooks have had this shape since ABI 4.
			if got := runFilterABI(t, tc.arch, true, 2, tc.data); got != tc.want {
				t.Errorf("abi 2, record full: filter = %#x, want %#x", got, tc.want)
			}
		})
	}
}
