// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// insertKeep keeps the strings insertChild's vector points at alive: the vector holds their addresses as integers.
var insertKeep [3]*byte

// insertRace runs the gate-only insertion race when args name it, and reports whether they did:
//
//	execracer -insert <target> <attempts> <report> <word> <extra>
//
// It starts itself <attempts> times as a child that execs <target> as [<target>, <word>] while a thread puts <extra>
// in front of <word> in the vector's pointer array and takes it out again, so the vector the supervisor copies and
// the one the kernel copies after the CONTINUE may differ in length. Each child's fate is tallied as the first form
// does ("attempts=N eacces=N ran=N other=N"; a killed child is other).
func insertRace(args []string) bool {
	if len(args) != 6 || args[0] != "-insert" {
		return false
	}
	n, err := strconv.Atoi(args[2])
	if err != nil || n <= 0 {
		fmt.Fprintln(os.Stderr, "execracer: attempts must be a positive number")
		os.Exit(2)
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "execracer:", err)
		os.Exit(1)
	}
	var eacces, ran, other int
	for range n {
		pid, err := syscall.ForkExec(self, []string{"execracer", "-insertchild", args[1], args[4], args[5]},
			&syscall.ProcAttr{Env: os.Environ(), Files: []uintptr{0, 1, 2}})
		if err != nil {
			other++
			continue
		}
		var ws syscall.WaitStatus
		if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
			other++
			continue
		}
		switch {
		case ws.Exited() && ws.ExitStatus() == exitEACCES:
			eacces++
		case ws.Exited() && ws.ExitStatus() == 0:
			ran++
		default:
			other++
		}
	}
	report := fmt.Sprintf("attempts=%d eacces=%d ran=%d other=%d\n", n, eacces, ran, other)
	if err := os.WriteFile(args[3], []byte(report), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "execracer:", err)
		os.Exit(1)
	}
	return true
}

// insertChild execs target as [target, word] while a thread moves the vector between that and [target, extra, word]:
// it sets the third slot first and clears it last, so every vector a reader can find is NULL-terminated. It returns
// only when execve failed.
func insertChild(target, word, extra string) {
	runtime.GOMAXPROCS(2)
	for i, s := range []string{target, word, extra} {
		p, err := syscall.BytePtrFromString(s)
		if err != nil {
			os.Exit(exitOther)
		}
		insertKeep[i] = p
	}
	at := func(i int) uintptr { return uintptr(unsafe.Pointer(insertKeep[i])) }
	argv := make([]uintptr, 4)
	argv[0], argv[1] = at(0), at(1)
	started := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		close(started)
		for {
			atomic.StoreUintptr(&argv[2], at(1))
			atomic.StoreUintptr(&argv[1], at(2))
			atomic.StoreUintptr(&argv[1], at(1))
			atomic.StoreUintptr(&argv[2], 0)
		}
	}()
	<-started
	env := []uintptr{0}
	_, _, e := syscall.RawSyscall(syscall.SYS_EXECVE, at(0), uintptr(unsafe.Pointer(&argv[0])), uintptr(unsafe.Pointer(&env[0])))
	if e == syscall.EACCES {
		os.Exit(exitEACCES)
	}
	os.Exit(exitOther)
}
