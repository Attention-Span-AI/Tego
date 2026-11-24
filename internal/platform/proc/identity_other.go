// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package proc

func processIdentity(pid int) (Identity, error) { return New().Identity(pid) }
