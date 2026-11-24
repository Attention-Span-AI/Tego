// SPDX-License-Identifier: Apache-2.0

package proc

import "golang.org/x/sys/windows"

// On Windows StartBootNS holds the process creation FILETIME, in 100 ns ticks
// since 1601. It is an opaque start identity, never a Linux boot timestamp.
func processIdentity(pid int) (Identity, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return Identity{}, err
	}
	defer func() { _ = windows.CloseHandle(h) }()
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return Identity{}, err
	}
	return Identity{PID: pid, StartBootNS: uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)}, nil
}
