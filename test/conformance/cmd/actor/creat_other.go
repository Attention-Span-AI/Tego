// SPDX-License-Identifier: Apache-2.0

//go:build !amd64

package main

import "syscall"

// creat is creat(2)'s flags on an openat: arm64's generic syscall table has no creat.
func creat(path string) (int, error) {
	return syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_TRUNC|syscall.O_CLOEXEC, 0o644)
}
