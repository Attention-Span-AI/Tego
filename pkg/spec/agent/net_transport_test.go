// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"bytes"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestTransportEndpointGrammar(t *testing.T) {
	for _, tc := range []struct {
		raw, proto, host string
		kind             EndpointKind
		port             int
	}{
		{"api.example:443", ProtoInet, "api.example", EndpointHost, 443},
		{"tcp://API.Example.:443", ProtoTCP, "api.example", EndpointHost, 443},
		{"udp://[2001:db8::1]:53", ProtoUDP, "2001:db8::1", EndpointHost, 53},
		{"tcp://[::ffff:192.0.2.1]:80", ProtoTCP, "192.0.2.1", EndpointHost, 80},
		{"udp://10.0.0.0/8:53", ProtoUDP, "", EndpointCIDR, 53},
		{"tcp://2001:db8::/32:443", ProtoTCP, "", EndpointCIDR, 443},
		{"unix:@bus", ProtoUnix, "", EndpointUnix, 0},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			e, err := ParseEndpoint(tc.raw)
			if err != nil || e.Proto != tc.proto || e.Kind != tc.kind || e.Host != tc.host || e.Port != tc.port || e.Raw != tc.raw {
				t.Fatalf("%+v, %v", e, err)
			}
		})
	}
	for _, raw := range []string{"https://host:443", "TCP://host:443", "udp://host:0", "tcp://host:0", "tcp://host:65536", "udp://user@host:53", "tcp://host:443/path", "tcp://host/path:443", "udp://host:53?x=1", "tcp://host:443#frag", "udp://::1:53", "tcp://[::1%lo]:80", "udp://::ffff:0.0.0.0/96:53", "tcp://"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := ParseEndpoint(raw); !errors.Is(err, ErrEndpoint) {
				t.Fatalf("want ErrEndpoint: %v", err)
			}
		})
	}
}

func TestCompileTransportDNSAndAssurance(t *testing.T) {
	f := newFixture(t)
	f.resolver.table["service.example"] = []netip.Addr{netip.MustParseAddr("198.51.100.10"), netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("::ffff:127.0.0.1")}
	c := f.load("version: 0\nname: transports\ncommand: [static-tool]\nnet:\n  assurance: kernel\n  allow: [tcp://service.example:443, udp://service.example:443, 'udp://[::ffff:192.0.2.1]:443', 'tcp://10.0.0.0/8:443']\n")
	rt, _ := f.compile(c)
	if f.resolver.calls.Load() != 1 {
		t.Fatalf("lookups %d, want one shared hostname lookup", f.resolver.calls.Load())
	}
	if rt.NetAssurance != NetAssuranceKernel {
		t.Fatalf("assurance %q", rt.NetAssurance)
	}
	var printed bytes.Buffer
	if err := PrintRuleTable(&printed, rt); err != nil || !strings.Contains(printed.String(), "assurance kernel") || !strings.Contains(printed.String(), "tcp://service.example:443") {
		t.Fatalf("transport/assurance report: %s %v", printed.String(), err)
	}
	for i, proto := range []string{ProtoTCP, ProtoUDP, ProtoUDP, ProtoTCP} {
		r := rt.Net[i]
		if r.Proto != proto || r.Raw != c.Net.Allow[i] || !strings.Contains(r.RuleName(), c.Net.Allow[i]) {
			t.Fatalf("rule %d: %+v", i, r)
		}
		if i < 2 && (!r.FiltersResolved() || len(r.IPs) != 1 || len(r.Denied) != 2 || !r.PublicAnswer) {
			t.Fatalf("selected DNS rule bypassed filtering: %+v", r)
		}
	}
	if rt.Net[2].FiltersResolved() || rt.Net[2].IPs[0] != netip.MustParseAddr("192.0.2.1") {
		t.Fatalf("literal normalization: %+v", rt.Net[2])
	}
	best := f.load("version: 0\nname: transports\ncommand: [static-tool]\nnet: {allow: [tcp://service.example:443]}\n")
	rtBest, _ := f.compile(best)
	if rtBest.NetAssurance != NetAssuranceBestEffort || rtBest.Hash == rt.Hash {
		t.Fatal("default assurance or contract hashing lost policy distinction")
	}
}

func TestModelHostsDoNotAcceptTransportEndpointSyntax(t *testing.T) {
	for _, host := range []string{"tcp://api.example", "udp://api.example", "unix:@socket", "192.0.2.0/24"} {
		if msg, _ := checkHost(host); msg == "" {
			t.Fatalf("model host accepted endpoint %q", host)
		}
	}
	for _, host := range []string{"api.example", "192.0.2.1", "[2001:db8::1]"} {
		if msg, _ := checkHost(host); msg != "" {
			t.Fatalf("model host %q: %s", host, msg)
		}
	}
}

func TestTransportTestTableInferenceAndContradictions(t *testing.T) {
	for _, tc := range []struct {
		fields, proto string
		bad           bool
	}{
		{"action: net.connect\n    host_port: 'udp://[2001:db8::1]:443'", ProtoUDP, false},
		{"action: net.connect\n    proto: tcp\n    host_port: 'tcp://api.example:443'", ProtoTCP, false},
		{"action: net.connect\n    proto: tcp\n    host_port: 'udp://api.example:443'", "", true},
		{"action: net.connect\n    host_port: 'tcp://api.example:443'\n    proto: udp", "", true},
		{"action: net.http\n    host_port: 'udp://api.example:443'\n    method: POST\n    path: /v1/messages", "", true},
	} {
		table, ds, err := LoadTestTableBytes("transport-tests.yaml", []byte("version: 0\ntests:\n  - "+tc.fields+"\n    expect: allow\n"))
		if tc.bad {
			if err == nil {
				t.Fatalf("bad row accepted: %+v", table)
			}
			continue
		}
		if err != nil || len(table.Rows) != 1 || table.Rows[0].Proto != tc.proto {
			t.Fatalf("table %+v ds %v err %v", table, ds, err)
		}
	}
}

func TestNetAssuranceProfileMergeAndValidation(t *testing.T) {
	p := mapSource{"base": "net: {assurance: kernel, allow: [tcp://service.example:443]}\n"}
	for _, tc := range []struct{ value, want string }{{"", "kernel"}, {"best-effort", "best-effort"}, {"kernel", "kernel"}} {
		data := "version: 0\nname: child\ncommand: [true]\nextends: base\nnet:\n  allow: [udp://service.example:443]\n"
		if tc.value != "" {
			data += "  assurance: " + tc.value + "\n"
		}
		c, ds, err := LoadBytes("child.yaml", []byte(data), p)
		if err != nil || string(c.Net.Assurance) != tc.want || len(c.Net.Allow) != 2 {
			t.Fatalf("%s: contract %+v err %v diagnostics %v", tc.value, c, err, ds)
		}
	}
	_, ds, err := LoadBytes("bad.yaml", []byte("version: 0\nname: bad\ncommand: [true]\nnet: {assurance: packet-firewall}\n"), nil)
	if err == nil || !strings.Contains(render(ds), "net.assurance") {
		t.Fatalf("unknown assurance accepted: %v %v", err, ds)
	}
}
