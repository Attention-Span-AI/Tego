// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"net/netip"
	"strings"
)

// ParseListenEndpoint parses a bind grant. IP listeners require an explicit
// TCP/UDP selector and a literal address: a DNS name cannot identify a local
// interface, and a CIDR is not a bind address. Port 0 grants the kernel's
// ephemeral allocation, never every fixed port. Unix names retain the ordinary
// endpoint spelling and are interpreted by the filesystem/Unix bind policy.
func ParseListenEndpoint(raw string) (Endpoint, error) {
	s := strings.TrimSpace(raw)
	if strings.HasPrefix(s, "unix:") {
		return ParseEndpoint(raw)
	}
	e := Endpoint{Raw: raw, Kind: EndpointHost}
	proto, rest, ok := strings.Cut(s, "://")
	if !ok || (proto != ProtoTCP && proto != ProtoUDP) {
		return e, fmt.Errorf("%w: listener needs a tcp://, udp:// or Unix endpoint", ErrEndpoint)
	}
	e.Proto = proto
	host, port, err := splitHostPort(rest)
	if err != nil {
		return e, err
	}
	e.Port, err = parsePort(port)
	if err != nil {
		return e, err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return e, fmt.Errorf("%w: listener needs a literal IP address without an interface zone", ErrEndpoint)
	}
	e.IP = ip.Unmap()
	e.Host = e.IP.String()
	return e, nil
}
