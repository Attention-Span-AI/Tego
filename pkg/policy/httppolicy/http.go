// SPDX-License-Identifier: Apache-2.0

// Package httppolicy compiles the forwarder's bounded HTTP request policy.
// It performs no I/O and its compiled policy is immutable.
package httppolicy

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Compile limits bound the immutable policy and each request lookup.
const (
	MaxRules       = 256
	MaxPaths       = 4096
	MaxPathBytes   = 4096
	MaxMethodBytes = 64
)

// Rule is one declared allow-union entry. Host is already canonicalized by
// the contract's endpoint parser; Port is the declared listener's TLS port.
type Rule struct {
	Host           string
	Port           int
	Allow, Methods []string
}
type entry struct {
	authority, name string
	paths, methods  []string
}

// Policy owns copies of all declaration data; callers cannot change a live matcher.
type Policy struct{ entries []entry }

// Authority is the stable fixed upstream spelling, including its TLS port.
func Authority(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }

// Compile validates and copies every entry. An empty allow list grants nothing.
func Compile(rules []Rule) (*Policy, error) {
	if len(rules) > MaxRules {
		return nil, fmt.Errorf("net.http exceeds %d rules", MaxRules)
	}
	p := &Policy{}
	paths := 0
	for i, r := range rules {
		if r.Host == "" || len(r.Host) > 253 || r.Port < 1 || r.Port > 65535 {
			return nil, fmt.Errorf("net.http[%d] has invalid upstream authority", i)
		}
		e := entry{authority: Authority(r.Host, r.Port), name: "net.http[" + strconv.Itoa(i) + "]"}
		paths += len(r.Allow)
		if paths > MaxPaths || len(r.Methods) > 64 {
			return nil, fmt.Errorf("net.http exceeds path or method bound")
		}
		for _, raw := range r.Allow {
			path, err := CanonicalPath(raw)
			if err != nil {
				return nil, fmt.Errorf("net.http[%d] path: %w", i, err)
			}
			e.paths = append(e.paths, strings.TrimSuffix(path, "/"))
		}
		for _, method := range r.Methods {
			if !ValidMethod(method) || method == "CONNECT" || method == "PRI" {
				return nil, fmt.Errorf("net.http[%d] has an invalid or unsupported HTTP method", i)
			}
			e.methods = append(e.methods, method)
		}
		p.entries = append(p.entries, e)
	}
	return p, nil
}

// ValidMethod accepts a bounded HTTP token, preserving case for exact matching.
func ValidMethod(method string) bool {
	if method == "" || len(method) > MaxMethodBytes {
		return false
	}
	for i := range method {
		c := method[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}

// CanonicalPath validates an origin-form escaped path, excluding any query.
// Separators, dot segments and further escapes cannot be hidden by decoding.
// It never rewrites the bytes that the forwarder sends upstream.
func CanonicalPath(raw string) (string, error) {
	if raw == "" || len(raw) > MaxPathBytes || raw[0] != '/' || strings.ContainsAny(raw, "?#\\") {
		return "", fmt.Errorf("invalid HTTP path")
	}
	path, err := url.PathUnescape(raw)
	if err != nil || !utf8.ValidString(path) {
		return "", fmt.Errorf("invalid HTTP path escape")
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] != '%' {
			continue
		}
		decoded, _ := url.PathUnescape(raw[i : i+3])
		if strings.ContainsAny(decoded, "/\\.%") {
			return "", fmt.Errorf("ambiguous HTTP path escape")
		}
		i += 2
	}
	if strings.Contains(path, "//") {
		return "", fmt.Errorf("ambiguous HTTP path separator")
	}
	for _, part := range strings.Split(path, "/") {
		if dotSegment(part) {
			return "", fmt.Errorf("ambiguous HTTP dot segment")
		}
	}
	for _, c := range path {
		if c < 0x20 || c == 0x7f || c == '\\' {
			return "", fmt.Errorf("invalid HTTP path character")
		}
	}
	return path, nil
}

// dotSegment reports a decoded segment that some upstream resolves as "." or "..", which can climb
// out of a declared prefix the matcher compared it under (SEMANTICS §5). Servers differ in what they
// resolve: Tomcat, Jetty and Spring cut a segment's ;parameters first, so "..;" and "..;x" (or "..%3B",
// for one that decodes first) are "..", and Windows servers trim trailing dots and spaces, so "..." and
// ".. " are too. Rather than guess the upstream's reading, any segment that is only dots once a
// ;parameter and trailing spaces are cut is refused. A ;parameter on any other segment cannot climb:
// it stays under the prefix whatever the server makes of it.
func dotSegment(part string) bool {
	base, _, _ := strings.Cut(part, ";")
	base = strings.TrimRight(base, " ")
	return base != "" && strings.Trim(base, ".") == ""
}

// Match evaluates one request against its fixed upstream. A malformed path or
// unsupported method is refused independently of any broad declaration.
func (p *Policy) Match(authority, method, escapedPath string) (rule string, allowed bool, err error) {
	path, err := CanonicalPath(escapedPath)
	if err != nil || !ValidMethod(method) || method == "CONNECT" || method == "PRI" {
		if err == nil {
			err = fmt.Errorf("unsupported HTTP method")
		}
		return "invalid-action", false, err
	}
	if p != nil {
		for _, e := range p.entries {
			if e.authority != authority || (len(e.methods) != 0 && !contains(e.methods, method)) {
				continue
			}
			for _, prefix := range e.paths {
				if prefix == "" || path == prefix || strings.HasPrefix(path, prefix+"/") {
					return e.name, true, nil
				}
			}
		}
	}
	return "unmatched", false, nil
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

// Covers reports whether this immutable policy contains a declaration for a listener.
func (p *Policy) Covers(authority string) bool {
	if p != nil {
		for _, e := range p.entries {
			if e.authority == authority {
				return true
			}
		}
	}
	return false
}

// RuleNames are the declared rule identities for drift accounting.
func (p *Policy) RuleNames() []string {
	if p == nil {
		return nil
	}
	out := make([]string, len(p.entries))
	for i, e := range p.entries {
		out[i] = e.name
	}
	return out
}

// Authorities is a copied, unique list of the listeners this policy requires.
func (p *Policy) Authorities() []string {
	var out []string
	if p != nil {
		for _, e := range p.entries {
			if !contains(out, e.authority) {
				out = append(out, e.authority)
			}
		}
	}
	return out
}
