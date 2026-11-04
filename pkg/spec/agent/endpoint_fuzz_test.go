// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

// FuzzParseEndpoint holds ParseEndpoint to a round trip: an accepted host or CIDR entry, written back as
// host:port, [v6]:port or cidr:port, parses to the same endpoint; its port is 0..65535; an address host is an
// address with no zone; and a unix entry has a path.
func FuzzParseEndpoint(f *testing.F) {
	for _, s := range []string{
		"example.com:443", "EXAMPLE.com.:443", "10.0.0.0/8:443", "[::1]:80", "unix:/run/x", "unix:@bus", "1.2.3.4:0",
		"::/0:1", "[fe80::1%eth0]:1", "::ffff:10.0.0.0/104:443", "[::ffff:1.2.3.4]:80", "127.1:80", "host:08",
		"tcp://example.com:443", "udp://[::1]:53", "tcp://unix:443", "unix.:0",
		"uniX:0", "TcP://host:443", "uDp://host:53", "hTtP://host:80", "hTtPs://host:443",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		e, err := ParseEndpoint(raw)
		if err != nil {
			return
		}
		// The v0 selectors are lowercase. Check this independently of rendering a DNS host named unix,
		// so disambiguating that host below cannot hide the mixed-case selector regression.
		s := strings.TrimSpace(raw)
		for _, selector := range []string{"unix:", "tcp://", "udp://"} {
			if len(s) >= len(selector) && s[:len(selector)] != selector && strings.ToLower(s[:len(selector)]) == selector {
				t.Fatalf("%q: accepted non-canonical selector %q", raw, s[:len(selector)])
			}
		}
		if e.Kind == EndpointUnix {
			if e.UnixPath == "" {
				t.Fatalf("%q: unix entry without a path", raw)
			}
			return
		}
		if e.Port < 0 || e.Port > 65535 {
			t.Fatalf("%q: port %d", raw, e.Port)
		}
		var back string
		switch {
		case e.Kind == EndpointCIDR:
			back = e.CIDR.String() + ":" + strconv.Itoa(e.Port)
		case strings.Contains(e.Host, ":"):
			back = "[" + e.Host + "]:" + strconv.Itoa(e.Port)
		default:
			host := e.Host
			if host == ProtoUnix {
				// A DNS host named unix needs its trailing dot to stay distinct from the socket selector.
				host += "."
			}
			back = host + ":" + strconv.Itoa(e.Port)
		}
		if e.Proto == ProtoTCP || e.Proto == ProtoUDP {
			back = e.Proto + "://" + back
		}
		e2, err := ParseEndpoint(back)
		if err != nil {
			t.Fatalf("%q was written back as %q, which does not parse: %v", raw, back, err)
		}
		if e2.Host != e.Host || e2.Port != e.Port || e2.Kind != e.Kind || e2.Proto != e.Proto || e2.CIDR != e.CIDR || e2.IP != e.IP {
			t.Fatalf("%q -> %q is not stable: %+v vs %+v", raw, back, e, e2)
		}
		if e.IP.IsValid() {
			if e.IP.Zone() != "" {
				t.Fatalf("%q: accepted a zoned address %s", raw, e.IP)
			}
			if a, err := netip.ParseAddr(e.Host); err != nil || a != e.IP {
				t.Fatalf("%q: host %q is not its address %s", raw, e.Host, e.IP)
			}
		}
	})
}
