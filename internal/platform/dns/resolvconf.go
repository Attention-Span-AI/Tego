// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
)

// ResolverPort is the port the resolver exception covers on UDP and TCP (SEMANTICS §5).
const ResolverPort = 53

// ResolvConfPath is the file a run snapshots its resolvers from at start.
const ResolvConfPath = "/etc/resolv.conf"

// maxNameservers is glibc's MAXNS: resolv.conf entries past the third are ignored by the resolver itself,
// so allowing them here would widen the exception beyond what the machine can actually use.
const maxNameservers = 3

// maxResolvConfSize bounds the read: resolv.conf is a handful of lines, and a file this large is either
// corrupt or hostile. Reading stops there rather than growing the buffer.
const maxResolvConfSize = 64 << 10

// ReadResolvConf parses the nameserver lines of a resolv.conf-shaped file into endpoints on ResolverPort,
// in file order, at most maxNameservers of them and without duplicates. Comment lines (# or ;), options,
// search, domain and sortlist lines are ignored, as is a nameserver line whose argument is not a literal
// address; an IPv6 address may carry a %zone suffix. It returns an error only when the file cannot be read.
func ReadResolvConf(path string) ([]netip.AddrPort, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("resolv.conf %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck // read-only fd
	addrs, err := parseResolvConf(io.LimitReader(f, maxResolvConfSize))
	if err != nil {
		return nil, fmt.Errorf("resolv.conf %s: %w", path, err)
	}
	return addrs, nil
}

// SystemResolvers is ReadResolvConf(ResolvConfPath) with every failure flattened to an empty list: an
// unreadable or resolver-less file is not an error for a run, it only means the port-53 exception matches
// nothing and DNS falls through to ordinary rule matching (E32).
func SystemResolvers() []netip.AddrPort {
	addrs, err := ReadResolvConf(ResolvConfPath)
	if err != nil {
		return nil
	}
	return addrs
}

// parseResolvConf scans nameserver lines out of r.
func parseResolvConf(r io.Reader) ([]netip.AddrPort, error) {
	var out []netip.AddrPort
	seen := make(map[netip.Addr]bool, maxNameservers)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() && len(out) < maxNameservers {
		line := sc.Text()
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "nameserver" {
			continue
		}
		addr, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue // not a literal address: the C resolver ignores it too
		}
		addr = addr.Unmap().WithZone("")
		if seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, netip.AddrPortFrom(addr, ResolverPort))
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// MachineResolvers is the resolver list a run takes from the machine config's `resolver` setting: /etc/resolv.conf's
// nameservers, read now, under `resolver: auto`, else servers as configured (an explicit list replaces the file, and
// an empty one is a machine with no resolver exception, E32). The run snapshots it once at start
// (runtime runResolvers), and compile --test reads it the same way to answer a resolver row as the run would.
func MachineResolvers(auto bool, servers []netip.AddrPort) []netip.AddrPort {
	if auto {
		return SystemResolvers()
	}
	return append([]netip.AddrPort(nil), servers...)
}
