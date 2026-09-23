// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

// TestParseSockaddr covers every family this tier understands and the malformed shapes it must survive
// (R4, E4, E5).
func TestParseSockaddr(t *testing.T) {
	tests := []struct {
		name     string
		in       []byte
		wantOK   bool
		wantFam  uint16
		wantAP   string
		wantPath string
		wantAbs  string
		unnamed  bool
		wantStr  string
	}{
		{
			name: "ipv4", in: sockaddrIn4("93.184.216.34", 443), wantOK: true, wantFam: unix.AF_INET,
			wantAP: "93.184.216.34:443", wantStr: "93.184.216.34:443",
		},
		{
			name: "ipv4 port 0", in: sockaddrIn4("127.0.0.1", 0), wantOK: true, wantFam: unix.AF_INET,
			wantAP: "127.0.0.1:0", wantStr: "127.0.0.1:0",
		},
		{
			name: "ipv6", in: sockaddrIn6("2001:db8::1", 8443), wantOK: true, wantFam: unix.AF_INET6,
			wantAP: "[2001:db8::1]:8443", wantStr: "[2001:db8::1]:8443",
		},
		{
			name: "ipv4-mapped ipv6 is unmapped", in: sockaddrIn6("::ffff:10.0.0.1", 80), wantOK: true,
			wantFam: unix.AF_INET6, wantAP: "10.0.0.1:80", wantStr: "10.0.0.1:80",
		},
		{
			name: "unix pathname", in: sockaddrUn("/run/pg.sock"), wantOK: true, wantFam: unix.AF_UNIX,
			wantPath: "/run/pg.sock", wantStr: "unix:/run/pg.sock",
		},
		{
			name: "unix abstract", in: sockaddrUn("@bus"), wantOK: true, wantFam: unix.AF_UNIX,
			wantAbs: "bus", wantStr: "unix:@bus",
		},
		{
			name: "unix abstract with an embedded NUL", in: append([]byte{unix.AF_UNIX, 0, 0}, []byte("a\x00b")...),
			wantOK: true, wantFam: unix.AF_UNIX, wantAbs: "a\x00b", wantStr: "unix:@a?b",
		},
		{
			name: "unix unnamed", in: []byte{unix.AF_UNIX, 0}, wantOK: true, wantFam: unix.AF_UNIX,
			unnamed: true, wantStr: "unix:",
		},
		{
			name: "truncated ipv4", in: sockaddrIn4("10.0.0.1", 80)[:6], wantFam: unix.AF_INET,
			wantStr: "family(2)",
		},
		{
			name: "truncated ipv6", in: sockaddrIn6("2001:db8::1", 80)[:20], wantFam: unix.AF_INET6,
			wantStr: "family(10)",
		},
		{name: "empty", in: nil, wantStr: "family(0)"},
		{name: "one byte", in: []byte{2}, wantStr: "family(0)"},
		{
			name: "unknown family", in: []byte{0x10, 0x00, 1, 2, 3, 4}, wantFam: unix.AF_NETLINK,
			wantStr: "family(16)",
		},
		{
			name: "oversized buffer is clamped", in: append(sockaddrIn4("10.0.0.1", 80), make([]byte, 400)...),
			wantOK: true, wantFam: unix.AF_INET, wantAP: "10.0.0.1:80", wantStr: "10.0.0.1:80",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := parseSockaddr(tc.in)
			if d.ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", d.ok, tc.wantOK)
			}
			if d.family != tc.wantFam {
				t.Errorf("family = %d, want %d", d.family, tc.wantFam)
			}
			if tc.wantAP != "" {
				if got := d.ap.String(); got != tc.wantAP {
					t.Errorf("addr = %s, want %s", got, tc.wantAP)
				}
			}
			if d.unixPath != tc.wantPath {
				t.Errorf("unixPath = %q, want %q", d.unixPath, tc.wantPath)
			}
			if string(d.abstract) != tc.wantAbs {
				t.Errorf("abstract = %q, want %q", d.abstract, tc.wantAbs)
			}
			if d.unnamed != tc.unnamed {
				t.Errorf("unnamed = %v, want %v", d.unnamed, tc.unnamed)
			}
			if got := d.String(); got != tc.wantStr {
				t.Errorf("String = %q, want %q", got, tc.wantStr)
			}
		})
	}
}

// TestParseSockaddrScopedIPv6 keeps the scope id on the parsed address, and unzoned drops it for the line
// that stands for the kernel's copy, which carries none. Matching ignores it (decide).
func TestParseSockaddrScopedIPv6(t *testing.T) {
	b := sockaddrIn6("fe80::1", 443)
	putU32(b[sin6ScopeOff:], 3)
	d := parseSockaddr(b)
	if !d.ok || d.ap.Addr().Zone() != "3" {
		t.Fatalf("addr = %v, want the zone kept", d.ap)
	}
	if u := d.unzoned(); u.ap != netip.MustParseAddrPort("[fe80::1]:443") {
		t.Errorf("unzoned = %v, want the zone dropped", u.ap)
	}
}

// FuzzParseSockaddr asserts the parser never panics and never reports an address it did not decode
// (docs/p0/supervisor.md §9 "Fuzzing").
func FuzzParseSockaddr(f *testing.F) {
	f.Add(sockaddrIn4("10.0.0.1", 80))
	f.Add(sockaddrIn6("2001:db8::1", 443))
	f.Add(sockaddrUn("/run/x.sock"))
	f.Add(sockaddrUn("@abs"))
	f.Add([]byte{})
	f.Add([]byte{1, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		d := parseSockaddr(b)
		if len(d.abstract) > sunPathMax || len(d.unixPath) > sunPathMax {
			t.Fatalf("unix name longer than sun_path: %d/%d", len(d.abstract), len(d.unixPath))
		}
		if d.ok && d.isInet() && !d.ap.IsValid() {
			t.Fatal("an inet address reported ok without a valid address")
		}
		if s := d.String(); s == "" {
			t.Fatal("String returned nothing")
		}
	})
}
