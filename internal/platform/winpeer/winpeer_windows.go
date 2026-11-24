// SPDX-License-Identifier: Apache-2.0

package winpeer

import (
	"errors"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// GetExtendedTcpTable's table classes this package asks for (TCP_TABLE_CLASS).
const (
	tableOwnerPIDListener    = 3
	tableOwnerPIDConnections = 4
)

var getExtendedTCPTable = windows.NewLazySystemDLL("iphlpapi.dll").NewProc("GetExtendedTcpTable")

// table reads one AF_INET6 table of class, growing the buffer as Windows asks, up to MaxTable.
func table(class uintptr) ([]byte, error) {
	if err := getExtendedTCPTable.Find(); err != nil {
		return nil, err
	}
	size := uint32(64 << 10)
	for range 8 {
		if size > MaxTable {
			return nil, fmt.Errorf("TCP table of %d bytes is over the %d byte limit", size, MaxTable)
		}
		b := make([]byte, size)
		need := size
		r, _, _ := getExtendedTCPTable.Call(uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&need)), 0,
			windows.AF_INET6, class, 0)
		switch windows.Errno(r) {
		case 0:
			return b[:min(need, size)], nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			size = max(need, size*2)
		default:
			return nil, fmt.Errorf("GetExtendedTcpTable: %w", windows.Errno(r))
		}
	}
	return nil, errors.New("GetExtendedTcpTable: the table kept growing")
}

// Connections is the live AF_INET6 connection table with owning pids.
func Connections() ([]byte, error) { return table(tableOwnerPIDConnections) }

// Listeners is the live AF_INET6 listener table with owning pids.
func Listeners() ([]Row, error) {
	b, err := table(tableOwnerPIDListener)
	if err != nil {
		return nil, err
	}
	return ParseTCP6(b)
}

// ProcessUser is the token user SID of process pid. A process it may not open, or whose token it may not query,
// is an error; the caller refuses.
func ProcessUser(pid uint32) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", fmt.Errorf("open process: %w", err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return "", fmt.Errorf("open process token: %w", err)
	}
	defer func() { _ = tok.Close() }()
	u, err := tok.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("token user: %w", err)
	}
	return u.User.Sid.String(), nil
}

// SelfUser is this process's token user SID.
func SelfUser() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

// Check applies Decide to the live table, for a connection the relay accepted: client is its RemoteAddr, server
// its LocalAddr. It returns nil only when the client end is owned by a process of the relay's own user.
func Check(client, server netip.AddrPort, self string) (Owner, error) {
	b, err := Connections()
	if err != nil {
		return Owner{}, fmt.Errorf("%w: %w", ErrRefused, err)
	}
	return Decide(b, client, server, self, ProcessUser)
}
