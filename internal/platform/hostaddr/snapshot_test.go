// SPDX-License-Identifier: Apache-2.0

package hostaddr

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

func ipNet(cidr string) *net.IPNet {
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return &net.IPNet{IP: ip, Mask: n.Mask}
}

// TestHasBroadcast: an IPv4 subnet's broadcast address is its mask's host bits all set, read unmapped and with no zone.
// A /31 and a /32 have none, IPv6 has no broadcast, and a broadcast address is not one of the host's own.
func TestHasBroadcast(t *testing.T) {
	addrs := []net.Addr{ipNet("127.0.0.1/8"), ipNet("192.168.2.108/24"), ipNet("10.1.2.3/15"), ipNet("10.9.0.0/31"),
		ipNet("10.9.1.1/32"), ipNet("fd00::1/64"), &net.UDPAddr{IP: net.ParseIP("10.8.0.1")}}
	h := New(func() ([]net.Addr, error) { return addrs, nil }, time.Now, time.Hour)
	for a, want := range map[string]bool{
		"192.168.2.255": true, "::ffff:192.168.2.255": true, "127.255.255.255": true, "10.1.255.255": true,
		"192.168.2.108": false, "192.168.2.0": false, "192.168.3.255": false, "10.9.0.1": false, "10.9.1.1": false,
		"fd00::ffff:ffff:ffff:ffff": false, "10.8.0.255": false,
	} {
		got, known := h.HasBroadcast(netip.MustParseAddr(a))
		if got != want || !known {
			t.Errorf("HasBroadcast(%s) = %v, %v, want %v, true", a, got, known, want)
		}
	}
	if local, known := h.Has(netip.MustParseAddr("192.168.2.255")); local || !known {
		t.Errorf("a broadcast address reads as the host's own: %v, %v", local, known)
	}
}

// TestHasBroadcastUnknown: no snapshot ever taken is unknown, and a failed refresh keeps the last one, as Has does.
func TestHasBroadcastUnknown(t *testing.T) {
	now := time.Now()
	fail := true
	list := func() ([]net.Addr, error) {
		if fail {
			return nil, errors.New("no netlink")
		}
		return []net.Addr{ipNet("192.0.2.10/24")}, nil
	}
	a := netip.MustParseAddr("192.0.2.255")
	h := New(list, func() time.Time { return now }, time.Second)
	if got, known := h.HasBroadcast(a); got || known {
		t.Fatalf("first failed snapshot = %v, %v, want unknown", got, known)
	}
	fail, now = false, now.Add(time.Second)
	if got, known := h.HasBroadcast(a); !got || !known {
		t.Fatalf("after a good snapshot = %v, %v", got, known)
	}
	fail, now = true, now.Add(time.Second)
	if got, known := h.HasBroadcast(a); !got || !known {
		t.Fatalf("a failed refresh dropped the last snapshot: %v, %v", got, known)
	}
}
