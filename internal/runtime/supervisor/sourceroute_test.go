// SPDX-License-Identifier: Apache-2.0
//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSysKernelSourceRouted is the real kernel's half of TestGateRelayRefusesSourceRoute (ADR 0041 D6): a socket
// can carry a loose source route in IP_OPTIONS, or a type 2 routing header in IPV6_RTHDR, and SourceRouted must
// see both on the socket a relay would use; a socket without one, or with only NOOP options, is not routed.
//
// The IPv4 route takes no privilege before "ipv4: restrict IPOPT_SSRR and IPOPT_LSRR options" (Linux 7.1, and the
// stable kernels it went back to, 7.0.13 among them). A kernel with it sets an LSRR or SSRR option only for a task
// with CAP_NET_RAW over the socket's network namespace and refuses any other EPERM, so there a task without the
// capability cannot route its socket that way: the LSRR case then holds that refusal, and a socket left with no
// route. With the capability, or on an older kernel, it holds that SourceRouted sees the route.
func TestSysKernelSourceRouted(t *testing.T) {
	k := sysKernel{}
	socket := func(t *testing.T, domain int) int {
		t.Helper()
		fd, err := unix.Socket(domain, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Skipf("socket(%d): %v", domain, err)
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		return fd
	}
	check := func(t *testing.T, fd, domain int, want bool) {
		t.Helper()
		got, err := k.SourceRouted(fd, domain)
		if err != nil || got != want {
			t.Fatalf("SourceRouted = %t, %v; want %t", got, err, want)
		}
	}

	t.Run("inet plain", func(t *testing.T) {
		check(t, socket(t, unix.AF_INET), unix.AF_INET, false)
	})
	t.Run("inet NOOP options", func(t *testing.T) {
		fd := socket(t, unix.AF_INET)
		if err := unix.SetsockoptString(fd, unix.IPPROTO_IP, unix.IP_OPTIONS, string([]byte{1, 1, 1, 0})); err != nil {
			t.Fatal(err)
		}
		check(t, fd, unix.AF_INET, false)
	})
	t.Run("inet LSRR", func(t *testing.T) {
		fd := socket(t, unix.AF_INET)
		lsrr := []byte{0x83, 7, 4, 10, 0, 0, 1, 0} // LSRR via 10.0.0.1, then END
		err := unix.SetsockoptString(fd, unix.IPPROTO_IP, unix.IP_OPTIONS, string(lsrr))
		if errors.Is(err, unix.EPERM) && !netRaw(t) {
			check(t, fd, unix.AF_INET, false) // the kernel's own refusal: no route reached the socket
			return
		}
		if err != nil {
			t.Fatalf("setsockopt(IP_OPTIONS, LSRR): %v", err)
		}
		check(t, fd, unix.AF_INET, true)
	})
	t.Run("inet6 plain", func(t *testing.T) {
		check(t, socket(t, unix.AF_INET6), unix.AF_INET6, false)
	})
	t.Run("inet6 RTHDR", func(t *testing.T) {
		fd := socket(t, unix.AF_INET6)
		rthdr := make([]byte, 24) // type 2: next header, hdrlen 2, type 2, segments left 1, reserved, one address
		rthdr[1], rthdr[2], rthdr[3] = 2, 2, 1
		rthdr[8], rthdr[9], rthdr[23] = 0x20, 0x01, 1
		if err := unix.SetsockoptString(fd, unix.IPPROTO_IPV6, unix.IPV6_RTHDR, string(rthdr)); err != nil {
			t.Skipf("IPV6_RTHDR: %v", err)
		}
		check(t, fd, unix.AF_INET6, true)
	})
}

// netRaw reports whether this process holds CAP_NET_RAW over its network namespace as the kernel judges it: a raw
// IPv4 socket's create makes the same ns_capable(net->user_ns, CAP_NET_RAW) test a restricted source route's
// setsockopt does, and refuses EPERM without it.
func netRaw(t *testing.T) bool {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if errors.Is(err, unix.EPERM) {
		return false
	}
	if err != nil {
		t.Fatalf("socket(AF_INET, SOCK_RAW): %v", err)
	}
	_ = unix.Close(fd)
	return true
}

// TestIPv4SourceRouteParse is ipv4SourceRoute's walk of an RFC 791 options block: LSRR and SSRR anywhere are
// routes, END stops the walk, NOOP is skipped, and a block that cannot be walked to its end counts as a route.
func TestIPv4SourceRouteParse(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []byte
		want bool
	}{
		{"empty", nil, false},
		{"end", []byte{0, 0x83, 7}, false},
		{"noop then lsrr", []byte{1, 0x83, 7, 4, 10, 0, 0, 1}, true},
		{"ssrr", []byte{0x89, 7, 4, 10, 0, 0, 1, 0}, true},
		{"record route then end", []byte{7, 7, 4, 0, 0, 0, 0, 0}, false},
		{"timestamp then lsrr", []byte{0x44, 4, 5, 0, 0x83, 3, 4, 0}, true},
		{"zero length", []byte{7, 0}, true},
		{"truncated", []byte{7}, true},
	} {
		if got := ipv4SourceRoute(tc.opts); got != tc.want {
			t.Errorf("%s: ipv4SourceRoute(%x) = %t, want %t", tc.name, tc.opts, got, tc.want)
		}
	}
}
