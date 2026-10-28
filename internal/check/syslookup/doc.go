// SPDX-License-Identifier: Apache-2.0

// Package syslookup says whether a connection's destination is a routine system lookup: a unix socket the C library
// and system services open on their own for name, user and host lookups (nscd, systemd's userdb and resolved, the
// D-Bus system and session buses), or a DNS lookup: a query the engine named net.resolver, or port 53 on this machine.
// Such a connection carries none of the run's own data. Port 53 of any other address is no lookup: the line's rule, not
// the port, says what the run's resolvers are.
//
// One classifier serves both sides: the engine-side receipt (internal/check/receipt, its Connections section and
// tego watch's "seen:" line) and the dashboard's verdict (internal/control/ledgerview wraps it), so the terminal and
// the page never disagree about whether nscd is a place the run sent something to. It is a pure function over
// strings: no I/O, no clock.
//
// Imports: the standard library only (strings)
// Must not import: anything under internal/ or pkg/
package syslookup
