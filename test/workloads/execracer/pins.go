// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// pinRace runs the races of ADR 0048 P2's K6 cells when args name one, and reports whether they did. It execs
// <target> as ["git", <word>] <attempts> times while a thread changes what that exec will find, and writes the tally
// as the first form does (an exec refused with EACCES, one that ran and exited 0, and any other end), and busy: an exec
// that failed ETXTBSY because the racer held the file open for writing:
//
//	execracer -flip <target> <offset> <s1> <s2> <attempts> <report> <word>
//	execracer -swap <target> <link> <to1> <to2> <attempts> <report> <word>
//
// -flip writes <s1>, then <s2>, at <offset> of the file <target> itself, so the script the supervisor read is not the
// one binfmt_script reads (TestPlaneRunExecPinScriptRewrite); a write that fails (ETXTBSY while an exec holds the file)
// is tried again. -swap makes <link> a symlink to <to1> and <link>.2 one to <to2>, and exchanges the two names while an
// exec is in flight, so the image (or the #! interpreter) the supervisor's walk found is not the one the kernel's walk
// opens (TestPlaneRunExecPinSymlinkSwap, TestPlaneRunExecPinInterpreterSwap).
func pinRace(args []string) bool {
	if len(args) != 8 || args[0] != "-flip" && args[0] != "-swap" {
		return false
	}
	n, err := strconv.Atoi(args[5])
	if err != nil || n <= 0 {
		fmt.Fprintln(os.Stderr, "execracer: attempts must be a positive number")
		os.Exit(2)
	}
	target, report, word := args[1], args[6], args[7]
	runtime.GOMAXPROCS(max(runtime.GOMAXPROCS(0), 2))
	var inFlight atomic.Bool
	if args[0] == "-swap" {
		for _, l := range [][2]string{{args[3], args[2]}, {args[4], args[2] + ".2"}} {
			if err := os.Symlink(l[0], l[1]); err != nil {
				fmt.Fprintln(os.Stderr, "execracer:", err)
				os.Exit(2)
			}
		}
		go swapLinks(args[2], args[2]+".2", &inFlight)
	} else {
		off, err := strconv.ParseInt(args[2], 10, 64)
		if err != nil || len(args[3]) != len(args[4]) {
			fmt.Fprintln(os.Stderr, "execracer: -flip needs an offset and two strings of one length")
			os.Exit(2)
		}
		go flipBytes(target, off, args[3], args[4])
	}
	var eacces, ran, other, busy int
	for range n {
		inFlight.Store(true)
		pid, err := syscall.ForkExec(target, []string{"git", word}, &syscall.ProcAttr{Env: os.Environ(), Files: []uintptr{0, 1, 2}})
		inFlight.Store(false)
		if err != nil {
			switch {
			case errors.Is(err, syscall.EACCES):
				eacces++
			case errors.Is(err, syscall.ETXTBSY):
				busy++
			default:
				other++
				fmt.Fprintln(os.Stderr, "execracer: exec:", err)
			}
			continue
		}
		var ws syscall.WaitStatus
		if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil || !ws.Exited() || ws.ExitStatus() != 0 {
			other++
			if !ws.Signaled() {
				fmt.Fprintln(os.Stderr, "execracer: wait:", err, ws.ExitStatus())
			}
			continue
		}
		ran++
	}
	out := fmt.Sprintf("attempts=%d eacces=%d ran=%d other=%d busy=%d\n", n, eacces, ran, other, busy)
	if err := os.WriteFile(report, []byte(out), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "execracer:", err)
		os.Exit(1)
	}
	return true
}

// flipBytes writes s1, then s2, at off of the file path, forever. Between two writes the file is closed for a few
// microseconds, or nearly every exec of it would fail ETXTBSY on the racer's open descriptor.
func flipBytes(path string, off int64, s1, s2 string) {
	runtime.LockOSThread()
	words := [2][]byte{[]byte(s1), []byte(s2)}
	for i := 0; ; i++ {
		if fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CLOEXEC, 0); err == nil {
			_, _ = syscall.Pwrite(fd, words[i&1], off)
			_ = syscall.Close(fd)
		}
		for t0 := time.Now(); time.Since(t0) < flipPause; {
		}
	}
}

// flipPause is how long flipBytes leaves the file closed between two writes.
const flipPause = 20 * time.Microsecond

// swapLinks exchanges the names a and b (renameat2 RENAME_EXCHANGE, one atomic rename) every flipPause while an exec
// is in flight, forever: a always names one of the two links, and which one can change between any two walks of it.
// It rests between execs, so the run's record holds a few renames per exec rather than a flood that would overrun
// the ring and hide the lines the cell counts.
func swapLinks(a, b string, inFlight *atomic.Bool) {
	runtime.LockOSThread()
	for {
		if !inFlight.Load() {
			continue
		}
		_ = unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE)
		for t0 := time.Now(); time.Since(t0) < flipPause; {
		}
	}
}
