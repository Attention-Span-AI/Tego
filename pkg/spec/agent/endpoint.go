// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// EndpointKind classifies a net.allow entry.
type EndpointKind string

// Endpoint kinds.
const (
	EndpointHost EndpointKind = "host"
	EndpointCIDR EndpointKind = "cidr"
	EndpointUnix EndpointKind = "unix"
)

// Endpoint is a parsed net.allow destination. Bare IP endpoints admit both TCP
// and UDP; tcp:// and udp:// select one transport. These are destinations, not URLs.
type Endpoint struct {
	Kind  EndpointKind
	Proto string // ProtoInet, ProtoTCP, ProtoUDP or ProtoUnix
	Host  string // host name or literal IP for EndpointHost
	Port  int    // 1..65535; 0 means "any port" and is only valid for ICMP/raw (port 0 spelled explicitly)
	CIDR  netip.Prefix
	IP    netip.Addr // set when Host is a literal address
	// Unix socket entries.
	UnixPath string
	Abstract bool
	Raw      string // the original scalar, for diagnostics and the RuleTable print
}

// Static reports whether the entry never needs DNS: a literal IP, a CIDR or a unix socket.
func (e Endpoint) Static() bool { return e.Kind != EndpointHost || e.IP.IsValid() }

// ErrEndpoint is wrapped by every ParseEndpoint failure.
var ErrEndpoint = errors.New("invalid endpoint")

// hostRE accepts a DNS name: labels of letters, digits and hyphens, dot-separated.
var hostRE = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$`)

// ParseEndpoint parses one net.allow scalar. Malformed CIDRs (/33, a bad
// dotted quad) and ports outside 0..65535 are rejected here, at Load time (E20).
func ParseEndpoint(raw string) (Endpoint, error) {
	e := Endpoint{Raw: raw, Proto: ProtoInet}
	s := strings.TrimSpace(raw)
	if s == "" {
		return e, fmt.Errorf("%w: empty entry", ErrEndpoint)
	}
	if scheme, rest, ok := strings.Cut(s, ":"); ok && strings.EqualFold(scheme, ProtoUnix) {
		// v0 spells selectors in lowercase, as for tcp:// and udp://. Letting a mixed-case unix:
		// fall through as a DNS host bypassed the socket-path checks and changed kind on a round trip.
		if scheme != ProtoUnix {
			return e, fmt.Errorf("%w: unix selector must be lowercase: write %q", ErrEndpoint, "unix:"+rest)
		}
		return parseUnixEndpoint(e, rest)
	}
	if scheme, rest, ok := strings.Cut(s, "://"); ok {
		switch scheme {
		case ProtoTCP, ProtoUDP:
			e.Proto, s = scheme, rest
		default:
			return e, fmt.Errorf("%w: unsupported transport %q: want tcp:// or udp://", ErrEndpoint, scheme)
		}
	}
	host, portStr, err := splitHostPort(s)
	if err != nil {
		return e, err
	}
	port, err := parsePort(portStr)
	if err != nil {
		return e, err
	}
	e.Port = port
	if port == 0 && e.Proto != ProtoInet {
		return e, fmt.Errorf("%w: %s destinations need a port in 1..65535", ErrEndpoint, e.Proto)
	}
	if strings.Contains(host, "/") {
		p, err := netip.ParsePrefix(host)
		if err != nil {
			return e, fmt.Errorf("%w: bad cidr %q: want address/prefix-length such as 10.0.0.0/8", ErrEndpoint, host)
		}
		if p.Addr() != p.Masked().Addr() {
			return e, fmt.Errorf("%w: cidr %q has host bits set; write %s", ErrEndpoint, host, p.Masked())
		}
		// An IPv4-mapped IPv6 prefix matches no connect: every address is compared in its IPv4 form
		// (Evaluate, the supervisor), so such an entry allowed nothing while it read as an allow. The machine
		// config refuses the same spelling in denied_resolved_addresses (E20).
		if p.Addr().Is4In6() {
			if p.Bits() >= 96 {
				return e, fmt.Errorf("%w: cidr %q is an IPv4-mapped IPv6 prefix, which no connect matches; write %s",
					ErrEndpoint, host, netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96))
			}
			return e, fmt.Errorf("%w: cidr %q is an IPv4-mapped IPv6 prefix, which no connect matches; write the IPv4 range", ErrEndpoint, host)
		}
		e.Kind, e.CIDR = EndpointCIDR, p
		return e, nil
	}
	e.Kind, e.Host = EndpointHost, host
	if ip, err := netip.ParseAddr(host); err == nil {
		// A zone names an interface, which no tier matches: Evaluate compared "fe80::1%eth0" as a string, so
		// the entry allowed that spelling alone, while a kernel tier sees the address without it. Refused, as
		// an IPv4-mapped prefix is, rather than read one way here and another in the kernel.
		if ip.Zone() != "" {
			return e, fmt.Errorf("%w: %q has an IPv6 zone (%%%s), which no tier matches on; write [%s]:%s",
				ErrEndpoint, host, ip.Zone(), ip.WithZone(""), portStr)
		}
		e.IP = ip.Unmap()
		e.Host = e.IP.String()
		return e, nil
	}
	if !hostRE.MatchString(host) || len(host) > 253 {
		return e, fmt.Errorf("%w: bad host name %q", ErrEndpoint, host)
	}
	// A name whose last label is all digits is no host name (RFC 3696 §2: no top-level domain is all-numeric);
	// it is an address that did not parse, "1.2.3.4.5" or "1.2.3.256", or one of inet_aton's short forms,
	// "127.1", which the resolver reads as 127.0.0.1. Taken as a host name, it went to DNS (E20).
	name := strings.TrimSuffix(host, ".")
	if last := name[strings.LastIndexByte(name, '.')+1:]; strings.Trim(last, "0123456789") == "" {
		return e, fmt.Errorf("%w: %q is not an IP address, and a host name's last label is never all digits", ErrEndpoint, host)
	}
	e.Host = strings.ToLower(strings.TrimSuffix(host, "."))
	return e, nil
}

func parseUnixEndpoint(e Endpoint, rest string) (Endpoint, error) {
	e.Kind, e.Proto = EndpointUnix, ProtoUnix
	switch {
	case rest == "":
		return e, fmt.Errorf("%w: unix: needs a socket path or @name", ErrEndpoint)
	case strings.HasPrefix(rest, "@"):
		e.Abstract = true
		e.UnixPath = rest[1:]
		if e.UnixPath == "" {
			return e, fmt.Errorf("%w: abstract unix name is empty", ErrEndpoint)
		}
	case strings.HasPrefix(rest, "/") || strings.HasPrefix(rest, "~/"):
		e.UnixPath = rest
	default:
		return e, fmt.Errorf("%w: unix socket path %q must be absolute, ~/-relative or @abstract", ErrEndpoint, rest)
	}
	if len(e.UnixPath) >= 108 {
		return e, fmt.Errorf("%w: unix socket path longer than sun_path (107 bytes)", ErrEndpoint)
	}
	if strings.ContainsRune(e.UnixPath, 0) {
		return e, fmt.Errorf("%w: unix socket path contains NUL", ErrEndpoint)
	}
	return e, nil
}

// splitHostPort splits "host:port", "[v6]:port" and "cidr:port" on the last colon.
func splitHostPort(s string) (host, port string, err error) {
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 || end+1 >= len(s) || s[end+1] != ':' {
			return "", "", fmt.Errorf("%w: %q: want [ipv6]:port", ErrEndpoint, s)
		}
		return s[1:end], s[end+2:], nil
	}
	i := strings.LastIndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return "", "", fmt.Errorf("%w: %q: want host:port, cidr:port or unix:<path>", ErrEndpoint, s)
	}
	host, port = s[:i], s[i+1:]
	if strings.Count(host, ":") > 0 && !strings.Contains(host, "/") {
		return "", "", fmt.Errorf("%w: %q: an IPv6 address must be bracketed, [addr]:port", ErrEndpoint, s)
	}
	return host, port, nil
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n > 65535 {
		return 0, fmt.Errorf("%w: bad port %q: want 0..65535", ErrEndpoint, s)
	}
	return n, nil
}
