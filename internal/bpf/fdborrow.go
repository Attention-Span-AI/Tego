// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"errors"
	"runtime"

	"github.com/cilium/ebpf"
)

// errNoObject is a nil Program or Map handed to the borrows below.
var errNoObject = errors.New("bpf: no program or map to borrow a descriptor from")

// cilium's Program and Map close their descriptors from a runtime cleanup once unreachable (v0.22.0), so
// p.FD() and m.FD() hand out a number with no lease, the same shape as (*os.File).Fd (ADR
// 0023 A4). The two borrows below are the only places outside this file's tests that may call them: fn runs
// with the number, and the object is kept reachable until fn has returned, so its cleanup cannot close the
// number under fn. fn must cover every use of the number, a program load that bakes a map's number into its
// instructions included, and must not keep it.

// ProgramFD runs fn with p's descriptor number while p is kept reachable.
func ProgramFD(p *ebpf.Program, fn func(fd int) error) error {
	if p == nil {
		return errNoObject
	}
	defer runtime.KeepAlive(p)
	return fn(p.FD())
}

// MapFD runs fn with m's descriptor number while m is kept reachable.
func MapFD(m *ebpf.Map, fn func(fd int) error) error {
	if m == nil {
		return errNoObject
	}
	defer runtime.KeepAlive(m)
	return fn(m.FD())
}
