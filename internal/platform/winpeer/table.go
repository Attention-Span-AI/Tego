// SPDX-License-Identifier: Apache-2.0

package winpeer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
)

// Row is one row of MIB_TCP6TABLE_OWNER_PID: a socket's two ends, its TCP state and the pid of the process that
// owns it.
type Row struct {
	Local, Remote netip.AddrPort
	State         uint32
	PID           uint32
}

// Windows' MIB_TCP_STATE values this package names.
const (
	StateListen      = 2
	StateEstablished = 5
)

// rowSize is sizeof(MIB_TCP6ROW_OWNER_PID): ucLocalAddr[16], dwLocalScopeId, dwLocalPort, ucRemoteAddr[16],
// dwRemoteScopeId, dwRemotePort, dwState, dwOwningPid.
const rowSize = 56

// MaxTable bounds one table read; a box with more sockets than this is refused rather than read without limit (the
// dashboard's own peer check bounds /proc/net/tcp6 the same way).
const MaxTable = 32 << 20

// ParseTCP6 reads a MIB_TCP6TABLE_OWNER_PID as GetExtendedTcpTable returns it: a DWORD row count, then that many
// rows. Addresses are network order; each port is a DWORD whose low 16 bits are the port in network order. A buffer
// shorter than its count claims, or longer than MaxTable, is an error, never a partial table.
func ParseTCP6(b []byte) ([]Row, error) {
	if len(b) > MaxTable {
		return nil, fmt.Errorf("TCP table of %d bytes is over the %d byte limit", len(b), MaxTable)
	}
	if len(b) < 4 {
		return nil, errors.New("TCP table shorter than its row count")
	}
	n := binary.LittleEndian.Uint32(b)
	if uint64(n)*rowSize > uint64(len(b)-4) {
		return nil, fmt.Errorf("TCP table claims %d rows in %d bytes", n, len(b))
	}
	rows := make([]Row, 0, n)
	for i := range uint64(n) {
		r := b[4+i*rowSize : 4+(i+1)*rowSize]
		rows = append(rows, Row{
			Local:  endpoint(r[0:16], binary.LittleEndian.Uint32(r[16:20]), r[20:24]),
			Remote: endpoint(r[24:40], binary.LittleEndian.Uint32(r[40:44]), r[44:48]),
			State:  binary.LittleEndian.Uint32(r[48:52]),
			PID:    binary.LittleEndian.Uint32(r[52:56]),
		})
	}
	return rows, nil
}

// endpoint is an address, its scope id as the zone when nonzero, and the port from the low 16 bits (network order)
// of its port DWORD.
func endpoint(addr []byte, scope uint32, port []byte) netip.AddrPort {
	a := netip.AddrFrom16([16]byte(addr))
	if scope != 0 {
		a = a.WithZone(strconv.FormatUint(uint64(scope), 10))
	}
	return netip.AddrPortFrom(a, binary.BigEndian.Uint16(port[0:2]))
}
