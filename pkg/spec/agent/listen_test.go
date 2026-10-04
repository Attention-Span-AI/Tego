// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"net/netip"
	"testing"
)

func TestListenerControlTriStateAndImmutableLimits(t *testing.T) {
	for _, absent := range []*Contract{nil, {}, {Net: &NetSection{}}} {
		listen, ingress, _, err := CompileListenerControl(absent, nil)
		if err != nil || listen != nil || ingress != nil {
			t.Fatalf("absent policy: %v %v %v", listen, ingress, err)
		}
	}
	zero := uint64(0)
	bytes := ByteSize(123)
	c := &Contract{Net: &NetSection{Listen: []string{}, Ingress: []IngressRule{}, Limits: &NetworkLimits{Connections: &zero, PendingConnects: &zero, DatagramsPerSecond: &zero, Bytes: &bytes}}}
	listen, ingress, limits, err := CompileListenerControl(c, nil)
	if err != nil || listen == nil || ingress == nil {
		t.Fatalf("explicit empty lost: %v %v %v", listen, ingress, err)
	}
	zero, bytes = 9, 999
	if *limits.Connections != 0 || *limits.PendingConnects != 0 || *limits.DatagramsPerSecond != 0 || *limits.Bytes != 123 {
		t.Fatalf("compiled ceilings alias contract: %+v", limits)
	}
}

func TestListenerControlReferencesAndFamilies(t *testing.T) {
	for _, tc := range []struct {
		name, to, from string
		valid          bool
	}{
		{"ipv4", "tcp://127.0.0.1:8080", "127.0.0.0/8", true},
		{"dualstack", "tcp://[::]:8080", "127.0.0.0/8", true},
		{"wrong-family", "tcp://127.0.0.1:8080", "::1", false},
		{"v6-fixed-v4-source", "tcp://[::1]:8080", "127.0.0.1", false},
		{"host-source", "tcp://127.0.0.1:8080", "localhost", false},
		{"hostbits", "tcp://127.0.0.1:8080", "127.0.0.1/8", false},
		{"mapped-prefix", "tcp://127.0.0.1:8080", "::ffff:127.0.0.0/104", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Contract{Net: &NetSection{Listen: []string{tc.to}, Ingress: []IngressRule{{From: tc.from, To: tc.to}}}}
			_, _, _, err := CompileListenerControl(c, nil)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
	for _, c := range []*Contract{
		{Net: &NetSection{Ingress: []IngressRule{}}},
		{Net: &NetSection{Listen: []string{"tcp://127.0.0.1:8080"}, Ingress: []IngressRule{{From: "127.0.0.1", To: "udp://127.0.0.1:8080"}}}},
	} {
		if _, _, _, err := CompileListenerControl(c, nil); err == nil {
			t.Fatal("missing listener reference accepted")
		}
	}
}

func TestMatchBindZeroMappedAndWildcard(t *testing.T) {
	c := &Contract{Net: &NetSection{Listen: []string{"tcp://0.0.0.0:0", "tcp://[::]:8080", "udp://127.0.0.1:8080"}}}
	listen, _, _, err := CompileListenerControl(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		address, proto string
		allowed        bool
	}{
		{"127.0.0.1:0", ProtoTCP, true}, {"127.0.0.1:8080", ProtoTCP, false},
		{"[::ffff:127.0.0.1]:0", ProtoTCP, true}, {"[::ffff:127.0.0.1]:8080", ProtoTCP, false},
		{"[::1]:8080", ProtoTCP, true}, {"127.0.0.1:8080", ProtoUDP, true}, {"127.0.0.2:8080", ProtoUDP, false},
	} {
		if _, ok := MatchBind(listen, netip.MustParseAddrPort(tc.address), tc.proto); ok != tc.allowed {
			t.Errorf("%s %s allowed=%v", tc.proto, tc.address, ok)
		}
	}
}
