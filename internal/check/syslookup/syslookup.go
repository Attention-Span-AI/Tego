// SPDX-License-Identifier: Apache-2.0

package syslookup

import "strings"

// ResolverRule is the rule a net line carries on a query to a resolver the run has, in every tier, a watched one too:
// the engine's own word for it (agent.ResolverRule, which this package does not import).
const ResolverRule = "net.resolver"

// Sockets are the unix sockets the C library and system services open on their own for name, user and host lookups
// (nscd, systemd's userdb and resolved, the D-Bus system bus). An entry ending in "/" is a directory.
var Sockets = []string{
	"/run/nscd/socket", "/var/run/nscd/socket",
	"/run/systemd/userdb/", "/var/run/systemd/userdb/",
	"/run/systemd/resolve/", "/var/run/systemd/resolve/",
	"/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket",
}

// IsSocket reports whether target (a dst or refused target, "unix:<path>" or a bare path) names one of Sockets, or a
// user's D-Bus session bus (/run/user/<uid>/bus), which desktop libraries open on their own in the same way.
func IsSocket(target string) bool {
	p := strings.TrimPrefix(target, "unix:")
	if uid, ok := strings.CutPrefix(p, "/run/user/"); ok {
		if n, ok := strings.CutSuffix(uid, "/bus"); ok && n != "" && strings.Trim(n, "0123456789") == "" {
			return true
		}
	}
	for _, s := range Sockets {
		if strings.HasSuffix(s, "/") {
			if strings.HasPrefix(p, s) {
				return true
			}
		} else if p == s {
			return true
		}
	}
	return false
}

// Resolver reports whether a line to dst under rule is a DNS lookup: the engine named it a query to a resolver
// (ResolverRule), or it goes to port 53 on this machine, a local stub resolver, which a run under net.dns.mode off or
// broker is refused. Port 53 of any other address is a connect like any other: any server can listen there, and read
// from the port alone an attacker's would be routine, on every try, right after a key read. A unix socket and a bare
// IPv6 address have no port.
func Resolver(dst, rule string) bool {
	if rule == ResolverRule {
		return true
	}
	if strings.HasPrefix(dst, "unix:") {
		return false
	}
	i := strings.LastIndexByte(dst, ':')
	if i <= 0 || dst[i+1:] != "53" {
		return false
	}
	host := dst[:i]
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return false // a bare IPv6 address with no port
	}
	return thisMachine(host)
}

// thisMachine reports whether host is a loopback address or localhost. Only digits and dots after 127: a name that
// starts the same way is someone else's machine.
func thisMachine(host string) bool {
	h := strings.TrimPrefix(strings.Trim(host, "[]"), "::ffff:")
	if h == "localhost" || h == "::1" {
		return true
	}
	return strings.HasPrefix(h, "127.") && strings.Trim(h, "0123456789.") == ""
}

// Routine reports whether a line to dst under rule is a routine system lookup: a system lookup socket (IsSocket) or a
// DNS lookup (Resolver).
func Routine(dst, rule string) bool { return IsSocket(dst) || Resolver(dst, rule) }
