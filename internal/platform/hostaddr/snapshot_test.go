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

// TestSnapshotReadsTheLocalTable: a snapshot that reads the local table takes a range a `local` route sends here (AnyIP)
// as the host's own, an address a `broadcast` route names (one set by hand) as a broadcast address, and one an
// `anycast` route names as an anycast address the host joined, each read unmapped and with no zone. Has is the one
// reading of the host's own the resolved-address check, a live block, a net gate and the models[] guard all take. Until
// the table is read the addresses answer, and a failed read keeps the last table, as a failed refresh keeps the last
// addresses.
func TestSnapshotReadsTheLocalTable(t *testing.T) {
	now := time.Now()
	tableErr := errors.New("no netlink")
	table := func() (LocalTable, error) {
		if tableErr != nil {
			return LocalTable{}, tableErr
		}
		return LocalTable{
			Local:     prefixes("192.0.2.10/32", "198.51.100.0/24"),
			Broadcast: prefixes("192.0.2.100/32", "192.0.2.255/32"),
			Anycast:   prefixes("2001:db8:1::/128"),
		}, nil
	}
	list := func() ([]net.Addr, error) { return []net.Addr{ipNet("192.0.2.10/24")}, nil }
	h := NewWithLocalTable(list, table, func() time.Time { return now }, time.Second)
	type ask func(netip.Addr) (bool, bool)
	check := func(stage string, cases map[string]bool, f ask, name string) {
		t.Helper()
		for a, want := range cases {
			if got, known := f(netip.MustParseAddr(a)); got != want || !known {
				t.Errorf("%s: %s(%s) = %v, %v, want %v, true", stage, name, a, got, known, want)
			}
		}
	}

	check("no table yet", map[string]bool{"192.0.2.10": true, "198.51.100.7": false}, h.Has, "Has")
	check("no table yet", map[string]bool{"192.0.2.255": true, "192.0.2.100": false}, h.HasBroadcast, "HasBroadcast")
	check("no table yet", map[string]bool{"2001:db8:1::": false}, h.HasAnycast, "HasAnycast")

	for _, step := range []struct {
		stage string
		err   error
	}{{"read", nil}, {"a failed read keeps the last table", errors.New("no netlink")}} {
		stage := step.stage
		tableErr, now = step.err, now.Add(time.Second)
		check(stage, map[string]bool{
			"192.0.2.10": true, "198.51.100.0": true, "198.51.100.7": true, "::ffff:198.51.100.7": true, "198.51.100.255": true,
			"198.51.101.1": false, "203.0.113.7": false, "192.0.2.100": false, "2001:db8:1::": false,
		}, h.Has, "Has")
		check(stage, map[string]bool{
			"192.0.2.100": true, "::ffff:192.0.2.100": true, "192.0.2.255": true, "192.0.2.101": false, "198.51.100.7": false,
		}, h.HasBroadcast, "HasBroadcast")
		check(stage, map[string]bool{
			"2001:db8:1::": true, "2001:db8:1::%eth0": true, "2001:db8:1::1": false, "192.0.2.100": false,
		}, h.HasAnycast, "HasAnycast")
	}

	// The addresses never read: unknown, whatever the table says, so the caller fails closed.
	tableErr = nil
	h = NewWithLocalTable(func() ([]net.Addr, error) { return nil, errors.New("no netlink") }, table, time.Now, time.Second)
	for name, f := range map[string]ask{"Has": h.Has, "HasBroadcast": h.HasBroadcast, "HasAnycast": h.HasAnycast} {
		if got, known := f(netip.MustParseAddr("198.51.100.7")); got || known {
			t.Errorf("%s with no addresses = %v, %v, want unknown", name, got, known)
		}
	}
}

// TestFreshReadsTheLocalTable: Fresh, which the models[] guard decides by, reads the host's own addresses as Has does,
// each time it is called: an address in a range a `local` route sends here (AnyIP) is the host's own, unmapped
// and with no zone, as soon as the route is there. A table it cannot read is unknown even after a good read, as
// addresses it cannot read are, since a route may have come meanwhile; a snapshot made by New reads no table.
func TestFreshReadsTheLocalTable(t *testing.T) {
	var tableErr error
	local := prefixes("192.0.2.10/32")
	table := func() (LocalTable, error) { return LocalTable{Local: local}, tableErr }
	list := func() ([]net.Addr, error) { return []net.Addr{ipNet("192.0.2.10/24")}, nil }
	h := NewWithLocalTable(list, table, time.Now, time.Hour)
	if v := h.Fresh(); func() bool { got, known := v.Has(netip.MustParseAddr("198.51.100.7")); return got || !known }() {
		t.Fatal("before the AnyIP route, 198.51.100.7 reads as this host's or unknown")
	}
	local = prefixes("192.0.2.10/32", "198.51.100.0/24")
	v := h.Fresh()
	for a, want := range map[string]bool{
		"192.0.2.10": true, "198.51.100.7": true, "::ffff:198.51.100.7": true, "198.51.100.255": true,
		"198.51.101.7": false, "192.0.2.255": false,
	} {
		if got, known := v.Has(netip.MustParseAddr(a)); got != want || !known {
			t.Errorf("Fresh().Has(%s) = %v, %v, want %v, true", a, got, known, want)
		}
	}
	if got, known := v.Has(netip.MustParseAddr("2001:db8::1%eth0")); got || !known {
		t.Errorf("Fresh().Has(2001:db8::1%%eth0) = %v, %v", got, known)
	}
	tableErr = errors.New("no netlink")
	if got, known := h.Fresh().Has(netip.MustParseAddr("203.0.113.7")); got || known {
		t.Errorf("an unreadable table = %v, %v, want unknown", got, known)
	}
	if got, known := New(list, time.Now, time.Hour).Fresh().Has(netip.MustParseAddr("198.51.100.7")); got || !known {
		t.Errorf("a snapshot with no table = %v, %v, want the addresses alone", got, known)
	}
}
