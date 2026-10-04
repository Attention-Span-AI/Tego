// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"net/netip"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"golang.org/x/sys/unix"
)

func TestConnectApprovalKeyIsExactAndTransportScoped(t *testing.T) {
	dst := netip.MustParseAddrPort("192.0.2.4:443")
	base, err := connectApprovalKey(1, 2, 3, dst, agent.ProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		slot, gen uint32
		cookie    uint64
		dst       netip.AddrPort
		proto     string
		invalid   bool
	}{
		{"different slot", 2, 2, 3, dst, agent.ProtoTCP, false},
		{"different generation", 1, 3, 3, dst, agent.ProtoTCP, false},
		{"different socket", 1, 2, 4, dst, agent.ProtoTCP, false},
		{"different address", 1, 2, 3, netip.MustParseAddrPort("192.0.2.5:443"), agent.ProtoTCP, false},
		{"different port", 1, 2, 3, netip.MustParseAddrPort("192.0.2.4:444"), agent.ProtoTCP, false},
		{"mapped address family", 1, 2, 3, netip.MustParseAddrPort("[::ffff:192.0.2.4]:443"), agent.ProtoTCP, false},
		// A UDP approval (supervisor R13d) is keyed by its own transport: a TCP credit never admits a UDP send.
		{"UDP keyed apart from TCP", 1, 2, 3, dst, agent.ProtoUDP, false},
		{"unix cannot use approval", 1, 2, 3, dst, agent.ProtoUnix, true},
		{"undeclared transport cannot use approval", 1, 2, 3, dst, agent.ProtoInet, true},
		{"no socket identity", 1, 2, 0, dst, agent.ProtoTCP, true},
		{"no generation", 1, 0, 3, dst, agent.ProtoTCP, true},
		{"invalid slot", bpf.MaxSlots, 2, 3, dst, agent.ProtoTCP, true},
		{"unspecified address", 1, 2, 3, netip.MustParseAddrPort("0.0.0.0:443"), agent.ProtoTCP, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := connectApprovalKey(tc.slot, tc.gen, tc.cookie, tc.dst, tc.proto)
			if tc.invalid {
				if err == nil {
					t.Fatalf("invalid identity admitted: %+v", got)
				}
				return
			}
			if err != nil || got == base {
				t.Fatalf("identity aliased baseline: %+v %v", got, err)
			}
		})
	}
}

func TestSocketApprovalCookieSurvivesDupAndNotReuse(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	first, err := socketCookie(fd)
	if err != nil {
		t.Fatal(err)
	}
	dup, err := unix.Dup(fd)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(dup)
	same, err := socketCookie(dup)
	if err != nil || first != same {
		t.Fatalf("duplicate cookie=%d original=%d err=%v", same, first, err)
	}
	other, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(other)
	different, err := socketCookie(other)
	if err != nil || first == different {
		t.Fatalf("independent socket cookie=%d original=%d err=%v", different, first, err)
	}
}
