// SPDX-License-Identifier: Apache-2.0

//go:build amd64

package main

import (
	"syscall"
	"unsafe"
)

// creat is the legacy creat(2) syscall itself, not syscall.Creat (an openat): x86-64 still carries it, the seccomp
// filter notifies it under its own number, and the supervisor decides it in a handler of its own (handleCreat).
func creat(path string) (int, error) {
	p, err := syscall.BytePtrFromString(path)
	if err != nil {
		return -1, err
	}
	fd, _, errno := syscall.Syscall(syscall.SYS_CREAT, uintptr(unsafe.Pointer(p)), 0o644, 0)
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}
