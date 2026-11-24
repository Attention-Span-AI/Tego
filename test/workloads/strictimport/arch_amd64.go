// SPDX-License-Identifier: Apache-2.0

package main

import "golang.org/x/sys/unix"

// sysRecvmmsg is the native recvmmsg number.
const sysRecvmmsg = unix.SYS_RECVMMSG

// int80 makes a system call through the 32-bit entry (int 0x80) with eax = 20 (getpid, in the i386 table) and reports
// what came back: "ENOSYS" where the seccomp filter's arch guard answers it, the raw return otherwise. A filter that
// kills the process for it ends the workload before this returns.
func int80() string {
	r := int80Call(20)
	if r == -int32(unix.ENOSYS) {
		return "ENOSYS"
	}
	return "returned " + itoa(int(r))
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func int80Call(nr int32) int32
