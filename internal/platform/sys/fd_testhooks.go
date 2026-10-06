// SPDX-License-Identifier: Apache-2.0

//go:build tegotesthooks

package sys

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// The tegotesthooks build's second line behind ADR 0023's static rules (the 2026-10-05 note, A8): a binary
// built with the tag, which the KVM suites run, counts owners that leaked an open number, refuses a fresh
// number without FD_CLOEXEC, names who holds a leased FD, and records each deferred close. A product build
// does not contain this file, and none of it closes anything.

func init() { testHooks = &traceHooks{} }

var (
	leaked      atomic.Int64
	outstanding atomic.Int64

	deferredMu  sync.Mutex
	deferredLog []string
)

// maxDeferredLog bounds the deferred-close report; a process that defers more than this many keeps its latest.
const maxDeferredLog = 256

// LeakedForTest is the number of owners that became unreachable while they still owned an open number. The
// count never closes the number: an owner's number is closed by its owner or not at all.
func LeakedForTest() int64 { return leaked.Load() }

// OutstandingLeasesForTest is the number of Holds not yet returned, process-wide. A run's teardown reads it
// at run start and run end, and fails its testhook check when it grew (A8; the KVM suites run runs serially).
// Borrow's leases are not counted: they cannot outlive their call.
func OutstandingLeasesForTest() int64 { return outstanding.Load() }

// DeferredClosesForTest lists the closes a lease deferred, each with its closer and its holders, for the KVM
// suites' teardown report.
func DeferredClosesForTest() []string {
	deferredMu.Lock()
	defer deferredMu.Unlock()
	return append([]string(nil), deferredLog...)
}

// fdTrace is one owner's trace.
type fdTrace struct {
	// open is set while the owner holds an open number it will close: an owner that becomes unreachable
	// with it set has leaked its number. The cleanup that reads it holds this cell, never the FD.
	open atomic.Bool

	mu sync.Mutex
	// holders maps each lease out, by address, to its Hold's caller. The address keeps nothing reachable.
	holders map[uintptr]uintptr
}

func (t *fdTrace) gone() { t.open.Store(false) }

type traceHooks struct{}

func (*traceHooks) born(f *FD, cloexecFresh bool) error {
	if cloexecFresh {
		fl, err := unix.FcntlInt(uintptr(f.num), unix.F_GETFD, 0)
		if err == nil && fl&unix.FD_CLOEXEC == 0 {
			_ = closeNumber(int(f.num)) // fresh from its producer: no one else has it
			return fmt.Errorf("fd %d: %w", f.num, ErrNotCloexec)
		}
	}
	tr := &fdTrace{holders: map[uintptr]uintptr{}}
	tr.open.Store(true)
	f.ensureSlow().trace = tr // before f is shared: no lock needed
	runtime.AddCleanup(f, func(c *fdTrace) {
		if c.open.Load() {
			leaked.Add(1)
		}
	}, tr)
	return nil
}

func (*traceHooks) held(l *Lease) {
	outstanding.Add(1)
	tr := traceOf(l.fd)
	if tr == nil {
		return
	}
	var pc [1]uintptr
	runtime.Callers(3, pc[:]) // held, Hold, Hold's caller
	tr.mu.Lock()
	tr.holders[uintptr(unsafe.Pointer(l))] = pc[0]
	tr.mu.Unlock()
}

func (*traceHooks) returned(l *Lease) {
	outstanding.Add(-1)
	if tr := traceOf(l.fd); tr != nil {
		tr.mu.Lock()
		delete(tr.holders, uintptr(unsafe.Pointer(l)))
		tr.mu.Unlock()
	}
}

func (*traceHooks) leased(f *FD) error {
	return fmt.Errorf("%w: %s held by %s", ErrLeased, f, holdersOf(f))
}

func (*traceHooks) deferred(f *FD) {
	var pc [1]uintptr
	runtime.Callers(3, pc[:]) // deferred, Close, Close's caller
	line := fmt.Sprintf("%s: Close by %s deferred, held by %s", f, funcName(pc[0]), holdersOf(f))
	deferredMu.Lock()
	if len(deferredLog) == maxDeferredLog {
		deferredLog = append(deferredLog[:0], deferredLog[1:]...)
	}
	deferredLog = append(deferredLog, line)
	deferredMu.Unlock()
}

func (*traceHooks) numAfterReturn() {
	panic("sys: Lease.Num after Return: the number may name any file by now")
}

// holdersOf names the callers of the Holds out on f; a Borrow's lease has no entry.
func holdersOf(f *FD) string {
	tr := traceOf(f)
	if tr == nil {
		return "a lease"
	}
	tr.mu.Lock()
	var names []string
	for _, pc := range tr.holders {
		names = append(names, funcName(pc))
	}
	tr.mu.Unlock()
	if len(names) == 0 {
		return "a Borrow"
	}
	return strings.Join(names, ", ")
}

// traceOf is f's trace: nil for an owner made before the hooks were installed, or by InertForTest or Stdio.
func traceOf(f *FD) *fdTrace {
	if s := f.slow.Load(); s != nil {
		tr, _ := s.trace.(*fdTrace)
		return tr
	}
	return nil
}

func funcName(pc uintptr) string {
	fn := runtime.FuncForPC(pc - 1)
	if fn == nil {
		return "unknown"
	}
	file, line := fn.FileLine(pc - 1)
	return fmt.Sprintf("%s (%s:%d)", fn.Name(), file, line)
}
