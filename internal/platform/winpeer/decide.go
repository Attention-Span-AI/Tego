// SPDX-License-Identifier: Apache-2.0

package winpeer

import (
	"errors"
	"fmt"
	"net/netip"
)

// ErrRefused marks every refusal: the connection's owner could not be shown to be the relay's own Windows user.
var ErrRefused = errors.New("the connection's owner could not be shown to be you")

// Owner is what the table and the token said about a connection's client end.
type Owner struct {
	PID uint32
	SID string
}

// ClientPID is the pid that owns the client end of the connection from client to server: the one established row
// whose local end is client and whose remote end is server. No such row, or more than one, is a refusal; so is an
// owner of pid 0 (the idle process) or 4 (the kernel), which no browser is.
func ClientPID(rows []Row, client, server netip.AddrPort) (uint32, error) {
	var found []Row
	for _, r := range rows {
		if r.State == StateEstablished && r.Local == client && r.Remote == server {
			found = append(found, r)
		}
	}
	switch {
	case len(found) == 0:
		return 0, fmt.Errorf("%w: no established socket from %s to %s in the TCP table", ErrRefused, client, server)
	case len(found) > 1:
		return 0, fmt.Errorf("%w: %d sockets from %s to %s in the TCP table", ErrRefused, len(found), client, server)
	case found[0].PID == 0 || found[0].PID == 4:
		return 0, fmt.Errorf("%w: the socket from %s belongs to system pid %d", ErrRefused, client, found[0].PID)
	}
	return found[0].PID, nil
}

// Decide is the relay's admission rule (R2): the client end's owner, read from table (a MIB_TCP6TABLE_OWNER_PID),
// must run as self, the relay's own user SID. sidOf reads a process's token user SID. Every error, an unreadable
// table, an owner that cannot be named or opened, or another SID, refuses; the Owner names what was found, for the
// relay's log.
func Decide(table []byte, client, server netip.AddrPort, self string, sidOf func(pid uint32) (string, error)) (Owner, error) {
	if self == "" {
		return Owner{}, fmt.Errorf("%w: the relay's own user is unknown", ErrRefused)
	}
	rows, err := ParseTCP6(table)
	if err != nil {
		return Owner{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	pid, err := ClientPID(rows, client, server)
	if err != nil {
		return Owner{}, err
	}
	sid, err := sidOf(pid)
	if err != nil {
		return Owner{PID: pid}, fmt.Errorf("%w: the user of pid %d: %w", ErrRefused, pid, err)
	}
	o := Owner{PID: pid, SID: sid}
	if sid != self {
		return o, fmt.Errorf("%w: pid %d runs as %s, not as %s", ErrRefused, pid, sid, self)
	}
	return o, nil
}
