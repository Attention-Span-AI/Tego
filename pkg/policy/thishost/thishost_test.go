// SPDX-License-Identifier: Apache-2.0

package thishost

import (
	"net/netip"
	"testing"
)

// lan is a host on 192.0.2.10/24.
type lan struct{}

func (lan) Own(a netip.Addr) bool       { return a == netip.MustParseAddr("192.0.2.10") }
func (lan) Broadcast(a netip.Addr) bool { return a == netip.MustParseAddr("192.0.2.255") }

// TestNamesAndReaches: an address that spells this host names it and reaches it; a group or broadcast address reaches
// it and names nothing, so a block or a rule on one is no block or rule on this host.
func TestNamesAndReaches(t *testing.T) {
	for _, c := range []struct {
		addr             string
		h                Addrs
		names, reaches   bool
		withoutTheHostOK bool // the answer holds with no snapshot too
	}{
		{"127.0.0.1", lan{}, true, true, true},
		{"127.255.0.9", lan{}, true, true, true},
		{"::1", lan{}, true, true, true},
		{"::1%1", lan{}, true, true, true},
		{"::ffff:127.0.0.2", lan{}, true, true, true},
		{"0.0.0.0", lan{}, true, true, true},
		{"::", lan{}, true, true, true},
		{"::ffff:0.0.0.0", lan{}, true, true, true},
		{"192.0.2.10", lan{}, true, true, false},
		{"::ffff:192.0.2.10", lan{}, true, true, false},
		{"224.0.0.1", lan{}, false, true, true},
		{"::ffff:224.0.0.1", lan{}, false, true, true},
		{"239.255.255.250", lan{}, false, true, true},
		{"ff02::1", lan{}, false, true, true},
		{"ff02::1%2", lan{}, false, true, true},
		{"ff01::1", lan{}, false, true, true},
		{"255.255.255.255", lan{}, false, true, true},
		{"::ffff:255.255.255.255", lan{}, false, true, true},
		{"192.0.2.255", lan{}, false, true, false},
		{"::ffff:192.0.2.255", lan{}, false, true, false},
		{"192.0.2.11", lan{}, false, false, true},
		{"203.0.113.7", lan{}, false, false, true},
		{"2001:db8::1", lan{}, false, false, true},
	} {
		a := netip.MustParseAddr(c.addr)
		if got := Names(a, c.h); got != c.names {
			t.Errorf("Names(%s) = %v, want %v", c.addr, got, c.names)
		}
		if got := Reaches(a, c.h); got != c.reaches {
			t.Errorf("Reaches(%s) = %v, want %v", c.addr, got, c.reaches)
		}
		if !c.withoutTheHostOK {
			if Names(a, nil) || Reaches(a, nil) {
				t.Errorf("%s reads as this host with no snapshot", c.addr)
			}
			continue
		}
		if Names(a, nil) != c.names || Reaches(a, nil) != c.reaches {
			t.Errorf("%s answers differently with no snapshot", c.addr)
		}
	}
}

func TestName(t *testing.T) {
	for host, want := range map[string]bool{
		"localhost": true, "LOCALHOST.": true, "db.localhost": true, "a.b.localhost.": true,
		"": false, "localhost.example": false, "notlocalhost": false, "127.0.0.1": false,
	} {
		if got := Name(host); got != want {
			t.Errorf("Name(%q) = %v, want %v", host, got, want)
		}
	}
}
