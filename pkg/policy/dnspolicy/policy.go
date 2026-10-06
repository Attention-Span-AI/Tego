// SPDX-License-Identifier: Apache-2.0

// Package dnspolicy holds the broker's immutable, bounded query admission model.
package dnspolicy

import (
	"fmt"
	"strconv"
	"strings"
)

const MaxNames = 256

// Policy owns every declaration. A nil name list is unrestricted; an explicit
// empty list denies all. Omitted types default to A and AAAA.
type Policy struct {
	unrestricted  bool
	exact, suffix map[string]int
	types         map[uint16]bool
}

func Compile(names, types []string) (*Policy, error) {
	if len(names) > MaxNames || len(types) > 64 {
		return nil, fmt.Errorf("DNS policy exceeds name/type bounds")
	}
	p := &Policy{unrestricted: names == nil, exact: map[string]int{}, suffix: map[string]int{}, types: map[uint16]bool{}}
	for i, raw := range names {
		wild := strings.HasPrefix(raw, "*.")
		if wild {
			raw = raw[2:]
		}
		name, err := CanonicalName(raw)
		if err != nil || name == "." && wild {
			return nil, fmt.Errorf("invalid DNS allow name at entry %d", i)
		}
		index := p.exact
		if wild {
			index = p.suffix
		}
		if _, exists := index[name]; exists {
			return nil, fmt.Errorf("duplicate DNS allow name at entry %d", i)
		}
		index[name] = i
	}
	if types == nil {
		types = []string{"A", "AAAA"}
	}
	for _, raw := range types {
		typ, ok := Type(raw)
		if !ok || p.types[typ] {
			return nil, fmt.Errorf("invalid or duplicate DNS type")
		}
		p.types[typ] = true
	}
	return p, nil
}

// CanonicalName rejects binary/ambiguous names and preserves label boundaries.
func CanonicalName(raw string) (string, error) {
	if raw == "." {
		return raw, nil
	}
	name := strings.ToLower(strings.TrimSuffix(raw, "."))
	if len(name) == 0 || len(name) > 253 {
		return "", fmt.Errorf("invalid DNS name length")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 {
			return "", fmt.Errorf("invalid DNS label length")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", fmt.Errorf("invalid DNS label character")
			}
		}
	}
	return name, nil
}

// Match names the first declared matching name and also enforces query type.
func (p *Policy) Match(raw string, typ uint16) (string, bool) {
	name, err := CanonicalName(raw)
	if p == nil || err != nil || !p.types[typ] {
		return "unmatched", false
	}
	if p.unrestricted {
		return "net.dns", true
	}
	first := MaxNames
	if i, ok := p.exact[name]; ok {
		first = i
	}
	for suffix := name; ; {
		_, next, found := strings.Cut(suffix, ".")
		if !found {
			break
		}
		suffix = next
		if i, ok := p.suffix[suffix]; ok && i < first {
			first = i
		}
	}
	if first == MaxNames {
		return "unmatched", false
	}
	return "net.dns.allow[" + strconv.Itoa(first) + "]", true
}

var typeNames = map[string]uint16{
	"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16,
	"AAAA": 28, "SRV": 33, "DS": 43, "RRSIG": 46, "DNSKEY": 48, "TLSA": 52,
	"SVCB": 64, "HTTPS": 65, "CAA": 257,
}

// Type accepts supported named types and explicit RFC3597 TYPE<number> values.
func Type(raw string) (uint16, bool) {
	if typ, ok := typeNames[strings.ToUpper(raw)]; ok {
		return typ, true
	}
	if strings.HasPrefix(strings.ToUpper(raw), "TYPE") {
		n, err := strconv.ParseUint(raw[4:], 10, 16)
		return uint16(n), err == nil && n != 0
	}
	return 0, false
}
