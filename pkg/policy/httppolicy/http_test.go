// SPDX-License-Identifier: Apache-2.0

package httppolicy

import (
	"strings"
	"testing"
)

func TestHTTPUnionSegmentsMethodsAndImmutability(t *testing.T) {
	rules := []Rule{{Host: "api.example.com", Port: 8443, Allow: []string{"/v1/messages"}, Methods: []string{"POST"}}, {Host: "api.example.com", Port: 8443, Allow: []string{"/status/"}}}
	p, err := Compile(rules)
	if err != nil {
		t.Fatal(err)
	}
	rules[0].Allow[0], rules[0].Methods[0] = "/", "GET"
	for _, tc := range []struct {
		method, path, rule string
		allow              bool
	}{
		{"POST", "/v1/messages", "net.http[0]", true}, {"POST", "/v1/messages/count_tokens", "net.http[0]", true},
		{"POST", "/v1/messages-extra", "unmatched", false}, {"GET", "/v1/messages", "unmatched", false}, {"post", "/v1/messages", "unmatched", false},
		{"PATCH", "/status", "net.http[1]", true}, {"GET", "/status/health", "net.http[1]", true},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			rule, allow, err := p.Match("api.example.com:8443", tc.method, tc.path)
			if err != nil || rule != tc.rule || allow != tc.allow {
				t.Fatalf("got %q,%v,%v", rule, allow, err)
			}
		})
	}
	if _, allow, _ := p.Match("api.example.com:443", "POST", "/v1/messages"); allow {
		t.Fatal("cross-port grant")
	}
	if _, allow, _ := p.Match("evil.example:8443", "POST", "/v1/messages"); allow {
		t.Fatal("cross-authority grant")
	}
}

func TestHTTPAmbiguityIsRefusedEvenUnderRootGrant(t *testing.T) {
	p, err := Compile([]Rule{{Host: "h", Port: 443, Allow: []string{"/"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", "*", "//v1", "/a/../b", "/./v1", "/v1?x=1", "/v1#f", "/v1\\x", "/v1/%", "/%2fsecret", "/%5csecret", "/%2e%2e/secret", "/%252fsecret", "/%00", "/%0a", "/%ff"} {
		t.Run(path, func(t *testing.T) {
			if _, allow, err := p.Match("h:443", "GET", path); err == nil || allow {
				t.Fatalf("ambiguous %q: allow=%v err=%v", path, allow, err)
			}
		})
	}
	for _, method := range []string{"", "CONNECT", "PRI", "GET POST", strings.Repeat("A", 65)} {
		if _, allow, err := p.Match("h:443", method, "/"); err == nil || allow {
			t.Fatalf("invalid method %q", method)
		}
	}
	if _, allow, err := p.Match("h:443", "GET", "/caf%C3%A9"); err != nil || !allow {
		t.Fatalf("unambiguous UTF-8 escape: %v %v", allow, err)
	}
}

// TestHTTPServerResolvedDotSegmentsAreRefused pins SEMANTICS §5's refusal of ambiguous paths against
// the spellings a server resolves as a dot segment although the bytes are not "." or "..": Tomcat, Jetty
// and Spring cut a segment's ;parameters before resolving it, so /v1/allowed/..;/admin is served as
// /v1/admin, and Windows servers trim a segment's trailing dots and spaces. Each is refused under a
// narrow prefix, beside the escaped, double-encoded and plain forms; a ;parameter on an ordinary segment
// stays under the prefix whatever the server makes of it, and is matched as written.
func TestHTTPServerResolvedDotSegmentsAreRefused(t *testing.T) {
	p, err := Compile([]Rule{{Host: "h", Port: 443, Allow: []string{"/v1/allowed"}, Methods: []string{"GET"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		// path parameters on a dot segment, raw and escaped
		"/v1/allowed/..;/admin", "/v1/allowed/..;x=1/admin", "/v1/allowed/..;", "/v1/allowed/.;/x", "/v1/allowed/.;x/admin",
		"/v1/allowed/..;/..;/etc", "/v1/allowed/..%3B/admin", "/v1/allowed/..%3b/admin", "/v1/allowed/.%3B/admin",
		"/v1/allowed/%2e%2e;/admin", "/v1/allowed/%2e%2e%3B/admin",
		// segments a trimming server reads as a dot segment
		"/v1/allowed/.../admin", "/v1/allowed/..%20/admin", "/v1/allowed/.%20/admin", "/v1/allowed/..%20;x/admin",
		// escaped and double-encoded dots and separators
		"/v1/allowed/%2e%2e/admin", "/v1/allowed/.%2e/admin", "/v1/allowed/%2E/admin", "/v1/allowed%2f..%2fadmin",
		"/v1/allowed/%252e%252e/admin", "/v1/allowed/%252fadmin", "/v1/allowed/%253b/admin",
		// plain dot segments
		"/v1/allowed/../admin", "/v1/allowed/./x", "/v1/allowed/..",
	} {
		t.Run(path, func(t *testing.T) {
			if rule, allow, err := p.Match("h:443", "GET", path); err == nil || allow {
				t.Fatalf("server-resolved dot segment %q: rule=%s allow=%v err=%v", path, rule, allow, err)
			}
			if _, err := Compile([]Rule{{Host: "h", Port: 443, Allow: []string{path}}}); err == nil {
				t.Fatalf("declared prefix %q accepted", path)
			}
		})
	}
	for _, tc := range []struct {
		path  string
		allow bool
	}{
		{"/v1/allowed", true}, {"/v1/allowed/x;y=1", true}, {"/v1/allowed/x;/y", true}, {"/v1/allowed/..x", true},
		{"/v1/allowed/x..", true}, {"/v1/allowed/.well-known", true}, {"/v1/allowed;x/y", false}, {"/v1/allowedx", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			if _, allow, err := p.Match("h:443", "GET", tc.path); err != nil || allow != tc.allow {
				t.Fatalf("%q: allow=%v err=%v", tc.path, allow, err)
			}
		})
	}
}

func TestHTTPBoundsAndDenyAll(t *testing.T) {
	for _, rules := range [][]Rule{
		make([]Rule, MaxRules+1), {{Host: "h", Port: 443, Allow: []string{strings.Repeat("/", MaxPathBytes+1)}}},
		{{Host: "h", Port: 443, Methods: []string{"CONNECT"}}}, {{Host: "h", Port: 443, Methods: []string{"GET POST"}}},
		{{Host: "h", Port: 443, Allow: make([]string, MaxPaths+1)}},
	} {
		if _, err := Compile(rules); err == nil {
			t.Fatal("unbounded/unsupported declaration accepted")
		}
	}
	p, err := Compile([]Rule{{Host: "h", Port: 443}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Covers("h:443") {
		t.Fatal("deny-all declaration lost listener scope")
	}
	if _, allow, err := p.Match("h:443", "POST", "/v1/messages"); err != nil || allow {
		t.Fatal("empty allow grants")
	}
}
