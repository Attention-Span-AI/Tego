// SPDX-License-Identifier: Apache-2.0

//go:build !amd64

package main

import "golang.org/x/sys/unix"

// sysRecvmmsg is the native recvmmsg number.
const sysRecvmmsg = unix.SYS_RECVMMSG

// int80 has no 32-bit entry to try on this architecture.
func int80() string { return "not applicable" }
