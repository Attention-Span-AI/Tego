// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"strings"
	"testing"
)

func TestParseEndpoint(t *testing.T) {
	tests := []struct {
		in      string
		kind    EndpointKind
		host    string
		port    int
		static  bool
		wantErr bool
	}{
		{in: "api.anthropic.com:443", kind: EndpointHost, host: "api.anthropic.com", port: 443},
		{in: "API.Example.COM.:8080", kind: EndpointHost, host: "api.example.com", port: 8080},
		{in: "10.1.2.3:53", kind: EndpointHost, host: "10.1.2.3", port: 53, static: true},
		{in: "[::1]:9000", kind: EndpointHost, host: "::1", port: 9000, static: true},
		{in: "[::ffff:1.2.3.4]:80", kind: EndpointHost, host: "1.2.3.4", port: 80, static: true},
		{in: "10.0.0.0/8:443", kind: EndpointCIDR, port: 443, static: true},
		{in: "fd00::/8:443", kind: EndpointCIDR, port: 443, static: true},
		{in: "localhost:0", kind: EndpointHost, host: "localhost", port: 0},
		{in: "unix:/run/pg.sock", kind: EndpointUnix, static: true},
		{in: "unix:~/.local/x.sock", kind: EndpointUnix, static: true},
		{in: "unix:@bus", kind: EndpointUnix, static: true},
		{in: "", wantErr: true},
		{in: "host", wantErr: true},
		{in: "host:", wantErr: true},
		{in: ":443", wantErr: true},
		{in: "host:70000", wantErr: true},
		{in: "host:-1", wantErr: true},
		{in: "host:https", wantErr: true},
		{in: "10.0.0.0/33:443", wantErr: true},
		{in: "10.0.0.256/24:443", wantErr: true},
		{in: "10.0.0.1/8:443", wantErr: true},
		{in: "::1:443", wantErr: true},
		{in: "[::1:443", wantErr: true},
		{in: "-bad.example:1", wantErr: true},
		{in: "unix:", wantErr: true},
		{in: "unix:@", wantErr: true},
		{in: "unix:rel/x.sock", wantErr: true},
		{in: "unix:/" + string(make([]byte, 120)), wantErr: true},
		// An address that does not parse is not a host name to resolve, and a mapped prefix matches no connect.
		{in: "1.2.3.4.5:80", wantErr: true},
		{in: "10.0.0.256:80", wantErr: true},
		{in: "127.1:80", wantErr: true},
		{in: "123:80", wantErr: true},
		{in: "::ffff:1.2.3.4/128:80", wantErr: true},
		{in: "::ffff:10.0.0.0/104:443", wantErr: true},
		{in: "::ffff:0.0.0.0/80:443", wantErr: true},
		// A zone names an interface, which no tier matches; Evaluate matched the spelling alone.
		{in: "[fe80::1%eth0]:443", wantErr: true},
		{in: "[::1%lo]:80", wantErr: true},
		{in: "fe80::/10%eth0:443", wantErr: true},
		{in: "host1.example:80", kind: EndpointHost, host: "host1.example", port: 80},
		{in: "1password.com:443", kind: EndpointHost, host: "1password.com", port: 443},
	}
	for _, tc := range tests {
		e, err := ParseEndpoint(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseEndpoint(%q): want error, got %+v", tc.in, e)
			} else if !errors.Is(err, ErrEndpoint) {
				t.Errorf("ParseEndpoint(%q): error %v does not wrap ErrEndpoint", tc.in, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseEndpoint(%q): %v", tc.in, err)
			continue
		}
		if e.Kind != tc.kind || e.Host != tc.host || e.Port != tc.port || e.Static() != tc.static || e.Raw != tc.in {
			t.Errorf("ParseEndpoint(%q)=%+v", tc.in, e)
		}
	}
}

// TestEndpointRefusalsSayWhatToWrite: the mapped prefix's refusal names the IPv4 form to write.
func TestEndpointRefusalsSayWhatToWrite(t *testing.T) {
	_, err := ParseEndpoint("::ffff:10.0.0.0/104:443")
	if err == nil || !strings.Contains(err.Error(), "write 10.0.0.0/8") {
		t.Errorf("err %v", err)
	}
	_, err = ParseEndpoint("[fe80::1%eth0]:443")
	if err == nil || !strings.Contains(err.Error(), "IPv6 zone (%eth0)") || !strings.Contains(err.Error(), "write [fe80::1]:443") {
		t.Errorf("err %v", err)
	}
	_, err = ParseEndpoint("1.2.3.4.5:80")
	if err == nil || !strings.Contains(err.Error(), "not an IP address") {
		t.Errorf("err %v", err)
	}
}

// v0's endpoint and net.ask grammar uses lowercase unix:, tcp:// and udp://. HTTP and other URL schemes
// are not destination selectors. None may fall through to the case-folding of a bare DNS host.
func TestEndpointSchemeCase(t *testing.T) {
	for _, tc := range []struct {
		in      string
		wantErr bool
	}{
		{"unix:/run/x", false},
		{"uniX:/run/x", true},
		{"UNIX:@bus", true},
		{"unix:0", true},
		{"uniX:0", true},
		{"unix:rel/x", true},
		{"UniX:rel/x", true},
		{"unix:@", true},
		{"Unix:@", true},
		{"tcp://example.com:443", false},
		{"TcP://example.com:443", true},
		{"TCP://example.com:0", true},
		{"udp://[::1]:53", false},
		{"uDp://[::1]:53", true},
		{"UDP://example.com:0", true},
		{"http://example.com:80", true},
		{"hTtP://example.com:80", true},
		{"https://example.com:443", true},
		{"hTtPs://example.com:443", true},
		{"inet://example.com:443", true},
		{"iNeT://example.com:443", true},
		{"file:///run/x", true},
		{"FiLe:///run/x", true},
		{"sctp://example.com:443", true},
		{"ScTp://example.com:443", true},
		// Without a selector delimiter these remain ordinary, case-insensitive DNS hosts.
		{"TcP:443", false},
		{"uDp:53", false},
		{"hTtP:80", false},
		{"hTtPs:443", false},
	} {
		t.Run(tc.in, func(t *testing.T) {
			e, err := ParseEndpoint(tc.in)
			if tc.wantErr {
				if !errors.Is(err, ErrEndpoint) {
					t.Fatalf("ParseEndpoint = %+v, %v; want ErrEndpoint", e, err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}
