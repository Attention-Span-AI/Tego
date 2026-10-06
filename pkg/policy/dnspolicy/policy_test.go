// SPDX-License-Identifier: Apache-2.0

package dnspolicy

import (
	"strings"
	"testing"
)

func TestQueryAdmissionNameBoundariesTypesAndOwnedDeclarations(t *testing.T) {
	names, types := []string{"*.example.com", "api.example.com", "."}, []string{"A", "TYPE257"}
	p, err := Compile(names, types)
	if err != nil {
		t.Fatal(err)
	}
	names[0], types[0] = "*.attacker.test", "TXT"
	for _, tc := range []struct {
		name string
		typ  uint16
		rule string
		ok   bool
	}{
		{"API.Example.COM.", 1, "net.dns.allow[0]", true},
		{"deep.api.example.com", 257, "net.dns.allow[0]", true},
		{"example.com", 1, "unmatched", false},
		{"otherexample.com", 1, "unmatched", false},
		{"api.example.com.attacker.test", 1, "unmatched", false},
		{"api.example.com", 16, "unmatched", false},
		{"api..example.com", 1, "unmatched", false},
		{"api.example.com..", 1, "unmatched", false},
		{"a\x00.example.com", 1, "unmatched", false},
		{".", 1, "net.dns.allow[2]", true},
	} {
		rule, ok := p.Match(tc.name, tc.typ)
		if rule != tc.rule || ok != tc.ok {
			t.Fatalf("%q TYPE%d = %s/%v, want %s/%v", tc.name, tc.typ, rule, ok, tc.rule, tc.ok)
		}
	}
}

func TestQueryAdmissionAbsentAndEmptyRemainDistinct(t *testing.T) {
	for _, tc := range []struct {
		names, types []string
		want         bool
	}{
		{nil, nil, true}, {[]string{}, nil, false}, {nil, []string{}, false},
	} {
		p, err := Compile(tc.names, tc.types)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := p.Match("any.example", 1); ok != tc.want {
			t.Fatalf("nil/empty semantics %v %v", tc.names, tc.types)
		}
	}
	for _, tc := range []struct{ names, types []string }{
		{[]string{"API.example", "api.example."}, nil},
		{[]string{"*."}, nil}, {[]string{strings.Repeat("a", 64) + ".example"}, nil},
		{nil, []string{"A", "TYPE1"}}, {nil, []string{"TYPE0"}}, {nil, []string{"TYPE65536"}},
	} {
		if _, err := Compile(tc.names, tc.types); err == nil {
			t.Fatalf("invalid declaration accepted: %v %v", tc.names, tc.types)
		}
	}
}
