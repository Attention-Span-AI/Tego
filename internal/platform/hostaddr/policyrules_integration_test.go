// SPDX-License-Identifier: Apache-2.0

//go:build integration

package hostaddr

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// netlinkAdd sends one RTM_NEW* request on a fresh NETLINK_ROUTE socket of the calling thread's network namespace and
// waits for its acknowledgement.
func netlinkAdd(t *testing.T, typ uint16, body []byte) {
	t.Helper()
	fd, err := sys.Own(unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fd.Close() }()
	ne := binary.NativeEndian
	err = fd.Borrow(func(n int) error {
		if err := unix.SetsockoptTimeval(n, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5}); err != nil {
			return err
		}
		if err := unix.Bind(n, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
			return err
		}
		msg := make([]byte, unix.NLMSG_HDRLEN, unix.NLMSG_HDRLEN+len(body))
		ne.PutUint32(msg[0:], uint32(unix.NLMSG_HDRLEN+len(body)))
		ne.PutUint16(msg[4:], typ)
		ne.PutUint16(msg[6:], unix.NLM_F_REQUEST|unix.NLM_F_ACK|unix.NLM_F_CREATE|unix.NLM_F_EXCL)
		ne.PutUint32(msg[8:], 1)
		msg = append(msg, body...)
		if err := unix.Sendto(n, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
			return err
		}
		buf := make([]byte, 4096)
		got, _, err := unix.Recvfrom(n, buf, 0)
		if err != nil {
			return fmt.Errorf("no acknowledgement: %w", err)
		}
		if got < unix.NLMSG_HDRLEN+4 || ne.Uint16(buf[4:]) != unix.NLMSG_ERROR {
			return fmt.Errorf("answer %x", buf[:got])
		}
		if e := int32(ne.Uint32(buf[unix.NLMSG_HDRLEN:])); e != 0 {
			return fmt.Errorf("request type %d: %w", typ, unix.Errno(-e))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// ipRule is `ip [-6] rule add [attrs] lookup table` with the priority left to the kernel's own choice (a fixed one).
func ipRule(t *testing.T, family uint8, table uint32, flags uint32, attrs ...[]byte) {
	t.Helper()
	body := make([]byte, sizeofFibRuleHdr)
	body[0], body[7] = family, unix.FR_ACT_TO_TBL
	binary.NativeEndian.PutUint32(body[8:], flags)
	body = append(body, rtAttr(unix.FRA_TABLE, u32(table))...)
	for _, a := range attrs {
		body = append(body, a...)
	}
	netlinkAdd(t, unix.RTM_NEWRULE, body)
}

// ipRouteLocal is `ip [-6] route add local PREFIX dev lo table N`, the default route when prefix has no bits.
func ipRouteLocal(t *testing.T, prefix string, table uint32) {
	t.Helper()
	p := netip.MustParsePrefix(prefix)
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	body := make([]byte, unix.SizeofRtMsg)
	body[0] = unix.AF_INET6
	if p.Addr().Is4() {
		body[0] = unix.AF_INET
	}
	body[1], body[5], body[6], body[7] = uint8(p.Bits()), unix.RTPROT_BOOT, unix.RT_SCOPE_HOST, unix.RTN_LOCAL
	body = append(body, rtAttr(unix.RTA_TABLE, u32(table))...)
	if p.Bits() != 0 {
		body = append(body, rtAttr(unix.RTA_DST, p.Addr().AsSlice())...)
	}
	body = append(body, rtAttr(unix.RTA_OIF, u32(uint32(lo.Index)))...)
	netlinkAdd(t, unix.RTM_NEWROUTE, body)
}

// inNewNetns runs f on a locked thread in a network namespace of its own, with its loopback up, so the rules and routes
// it adds are the test's alone.
func inNewNetns(t *testing.T, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runtime.LockOSThread() // the thread is left locked and ends with the goroutine: it never returns to the pool in a namespace of its own
		if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
			t.Errorf("unshare(CLONE_NEWNET): %v", err)
			return
		}
		fd, err := sys.Own(unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0))
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = fd.Close() }()
		err = fd.Borrow(func(n int) error {
			ifr, err := unix.NewIfreq("lo")
			if err != nil {
				return err
			}
			ifr.SetUint16(unix.IFF_UP)
			return unix.IoctlIfreq(n, unix.SIOCSIFFLAGS, ifr)
		})
		if err != nil {
			t.Errorf("lo up: %v", err)
			return
		}
		f()
	}()
	<-done
}

// TestIntegrationPolicyRuleTables is D30 on a real kernel, as root in a network namespace of its own (the guest proof): the policy rules decide which non-standard tables' routes are this host's.
//   - `ip rule add from all lookup 100` with `ip route add local 192.0.2.0/24 dev lo table 100`: 192.0.2.5 is this host.
//   - Cilium's shape, `fwmark 0x200/0xf00 lookup 2004` with `local default dev lo table 2004`: the world is not this host,
//     and table 2004 is named.
//   - `oif lo lookup 400` (the agent can SO_BINDTODEVICE since Linux 5.7) and `fwmark 0x100/0xff lookup 700` (unmarked
//     traffic matches it): read. A table no rule leads to: named, not read. `not fwmark 0x1 lookup 500`: unmarked traffic
//     matches it, so it is read. A `uidrange` rule is read here, since root cannot know the user its agent runs as.
//   - The same for IPv6.
func TestIntegrationPolicyRuleTables(t *testing.T) {
	if unix.Geteuid() != 0 {
		t.Skip("needs root: adding a policy rule is CAP_NET_ADMIN")
	}
	inNewNetns(t, func() {
		fwmark := append(attr(unix.FRA_FWMARK, u32(0x200)...), attr(unix.FRA_FWMASK, u32(0xf00)...)...)
		ipRule(t, unix.AF_INET, 100, 0)
		ipRouteLocal(t, "192.0.2.0/24", 100)
		ipRule(t, unix.AF_INET, 2004, 0, fwmark)
		ipRouteLocal(t, "0.0.0.0/0", 2004)
		ipRule(t, unix.AF_INET, 400, 0, attr(unix.FRA_OIFNAME, append([]byte("lo"), 0)...))
		ipRouteLocal(t, "198.51.100.0/24", 400)
		ipRouteLocal(t, "203.0.113.0/24", 77) // no rule leads to table 77
		ipRule(t, unix.AF_INET, 700, 0, append(attr(unix.FRA_FWMARK, u32(0x100)...), attr(unix.FRA_FWMASK, u32(0xff)...)...))
		ipRouteLocal(t, "100.66.0.0/16", 700)
		ipRule(t, unix.AF_INET, 500, unix.FIB_RULE_INVERT, attr(unix.FRA_FWMARK, u32(1)...))
		ipRouteLocal(t, "100.64.0.0/16", 500)
		ipRule(t, unix.AF_INET, 600, 0, uidRange(5000, 6000))
		ipRouteLocal(t, "100.65.0.0/16", 600)
		ipRule(t, unix.AF_INET6, 100, 0)
		ipRouteLocal(t, "2001:db8:100::/48", 100)
		ipRule(t, unix.AF_INET6, 2004, 0, fwmark)
		ipRouteLocal(t, "::/0", 2004)

		tab, err := ReadLocalTable()
		if err != nil {
			t.Fatalf("ReadLocalTable: %v", err)
		}
		t.Logf("local %v unread %v", tab.Local, tab.Unread)
		for _, in := range []string{"192.0.2.0/24", "198.51.100.0/24", "100.64.0.0/16", "100.65.0.0/16", "100.66.0.0/16", "2001:db8:100::/48"} {
			if !slices.Contains(tab.Local, netip.MustParsePrefix(in)) {
				t.Errorf("%s is not read as this host's: %v", in, tab.Local)
			}
		}
		for _, out := range []string{"0.0.0.0/0", "::/0", "203.0.113.0/24"} {
			if slices.Contains(tab.Local, netip.MustParsePrefix(out)) {
				t.Errorf("%s is read as this host's: %v", out, tab.Local)
			}
		}
		if want := []uint32{77, 2004}; !slices.Equal(tab.Unread, want) {
			t.Errorf("unread tables %v, want %v", tab.Unread, want)
		}
		if w := tab.UnreadWords(); w == "" {
			t.Error("no words for the tables left out")
		} else {
			t.Log(w)
		}

		h := NewWithLocalTable(net.InterfaceAddrs, ReadLocalTable, time.Now, time.Second)
		for addr, want := range map[string]bool{"192.0.2.5": true, "198.51.100.5": true, "100.64.9.9": true, "2001:db8:100::5": true, "8.8.8.8": false, "203.0.113.5": false, "2001:4860::1": false} {
			if got, known := h.Has(netip.MustParseAddr(addr)); got != want || !known {
				t.Errorf("Has(%s) = %v, %v, want %v", addr, got, known, want)
			}
		}
		if w := h.UnreadWords(); w == "" {
			t.Error("the snapshot has no words for the tables left out")
		}
	})
}
