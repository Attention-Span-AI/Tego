// SPDX-License-Identifier: Apache-2.0

// Package winpeer is the Windows counterpart of the dashboard's peer check (internal/control/web/peer.go), for the
// relay that carries a Windows browser to the dashboard (docs/adr/0123-dashboard-threat-model.md, "A browser on
// Windows"). For a connection the relay accepted on [::1], it names the process that owns the client's end from
// Windows' own TCP table (GetExtendedTcpTable, AF_INET6, TCP_TABLE_OWNER_PID_CONNECTIONS), matched on the exact
// four-tuple: the row whose local address and port are the client's and whose remote address and port are the
// listener's, established. That process's token user SID must be the relay's own. Anything it cannot show (no row,
// two rows, an owner of pid 0 or 4, a process or token it may not open) refuses: it fails closed.
//
// The table parser (ParseTCP6) and the decision (Decide) are portable pure functions over bytes, so they are tested
// and fuzzed on Linux with fake tables; only the reads of the live table and of a process token are Windows code.
// It is a platform package: no goroutines, no state, no clock.
//
// Imports: standard library, golang.org/x/sys/windows (Windows files only)
// Must not import: any other package of this module
package winpeer
