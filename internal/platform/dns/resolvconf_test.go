// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseResolvConf covers the shapes /etc/resolv.conf takes on a developer box and the malformed ones
// a run must survive (E32).
func TestParseResolvConf(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "systemd-resolved stub",
			in:   "# generated\nnameserver 127.0.0.53\noptions edns0 trust-ad\nsearch lan\n",
			want: []string{"127.0.0.53:53"},
		},
		{
			name: "two servers and a comment",
			in:   "nameserver 8.8.8.8 ; primary\nnameserver 1.1.1.1\n",
			want: []string{"8.8.8.8:53", "1.1.1.1:53"},
		},
		{name: "ipv6", in: "nameserver fd00::1\n", want: []string{"[fd00::1]:53"}},
		{name: "ipv6 with a zone", in: "nameserver fe80::1%eth0\n", want: []string{"[fe80::1]:53"}},
		{
			name: "more than MAXNS",
			in:   "nameserver 1.1.1.1\nnameserver 2.2.2.2\nnameserver 3.3.3.3\nnameserver 4.4.4.4\n",
			want: []string{"1.1.1.1:53", "2.2.2.2:53", "3.3.3.3:53"},
		},
		{name: "duplicates collapse", in: "nameserver 1.1.1.1\nnameserver 1.1.1.1\n", want: []string{"1.1.1.1:53"}},
		{name: "not an address", in: "nameserver dns.example.com\n", want: nil},
		{name: "no nameserver line", in: "search lan\noptions ndots:1\n", want: nil},
		{name: "empty", in: "", want: nil},
		{name: "nameserver without an argument", in: "nameserver\n", want: nil},
		{name: "commented out", in: "#nameserver 8.8.8.8\n", want: nil},
		{name: "mapped ipv4 is unmapped", in: "nameserver ::ffff:8.8.4.4\n", want: []string{"8.8.4.4:53"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseResolvConf(strings.NewReader(tc.in))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i, w := range tc.want {
				if got[i] != netip.MustParseAddrPort(w) {
					t.Errorf("[%d] = %v, want %v", i, got[i], w)
				}
			}
		})
	}
}

// TestReadResolvConfFile reads a real file and reports a missing one as an error.
func TestReadResolvConfFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(path, []byte("nameserver 10.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadResolvConf(path)
	if err != nil || len(got) != 1 || got[0] != netip.MustParseAddrPort("10.0.0.1:53") {
		t.Fatalf("ReadResolvConf = %v, %v", got, err)
	}
	if _, err := ReadResolvConf(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing file reported no error")
	}
}

// TestSystemResolversNeverFails is E32: an unreadable resolv.conf is an empty list, not a run failure.
func TestSystemResolversNeverFails(t *testing.T) {
	got := SystemResolvers()
	for _, a := range got {
		if a.Port() != ResolverPort {
			t.Errorf("%v is not on port %d", a, ResolverPort)
		}
	}
}

// FuzzParseResolvConf asserts the parser never panics and never returns more than MAXNS endpoints.
func FuzzParseResolvConf(f *testing.F) {
	f.Add("nameserver 1.1.1.1\n")
	f.Add("nameserver\n#x\n;y\n")
	f.Add(strings.Repeat("nameserver 1.1.1.1\n", 100))
	f.Fuzz(func(t *testing.T, in string) {
		got, err := parseResolvConf(strings.NewReader(in))
		if err != nil {
			return
		}
		if len(got) > maxNameservers {
			t.Fatalf("%d endpoints, want at most %d", len(got), maxNameservers)
		}
		for _, a := range got {
			if a.Port() != ResolverPort || !a.Addr().IsValid() {
				t.Fatalf("bad endpoint %v", a)
			}
		}
	})
}
