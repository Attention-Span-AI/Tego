// SPDX-License-Identifier: Apache-2.0

// Command execracer is ADR 0048's tier-1 TOCTOU workload (TestIntegrationExecRuleRaceTier1). Run as
//
//	execracer <git> <attempts> <report>
//
// it starts itself <attempts> times as a child that starts a thread flipping a five-byte buffer between "diff\0"
// and "push\0" (both git built-ins) while its main thread calls execve(<git>, ["git", buf]); with -tail first, the
// child execs ["git", "add", f0..f39, buf] instead, the flipping word past the 32 elements a decision made on the
// prefix reads (`allow: [git add]`). Run as `execracer <seconds>` (any argv[0]), it sleeps that long and exits 0. The supervisor decides
// on its own copy of argv; the kernel copies argv again after a CONTINUE. Each child's fate is tallied: refused with
// EACCES, or ran. The report is "attempts=N eacces=N ran=N other=N". What the exec'd program saw is the fixture's to
// record.
//
// Run as
//
//	execracer -link <git> <dir> <attempts> <report>
//
// it races the walk instead (TestIntegrationExecRuleLinkRaceTier1): a thread makes <dir>/l a symlink to <git> and
// removes it again, over and over, while the main thread execs <dir>/l as ["git", "push"] <attempts> times. A walk
// that finds no link and is continued lets the kernel's own lookup find one. The report has the same fields; an
// exec that failed with any errno but EACCES (ENOENT, the link not there) counts as other.
//
// pins.go adds K6's script rewrite race of ADR 0048 P2 (-flip), and insert.go the gate-only insertion race
// (-insert); each tallies the same report.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"
	"unsafe"
)

// childExit codes.
const (
	exitEACCES = 77
	exitOther  = 78
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "-child" {
		child(os.Args[2], nil)
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "-tailchild" {
		lead := []string{"add"}
		for i := range 40 {
			lead = append(lead, "f"+strconv.Itoa(i))
		}
		child(os.Args[2], lead)
		return
	}
	if len(os.Args) == 2 {
		if s, err := strconv.Atoi(os.Args[1]); err == nil && s >= 0 {
			// The sleeper K6's peer cells exec under any argv[0]: a coreutils copy may be a multi-call binary that
			// dispatches on argv[0] (uutils on Ubuntu 25.10) and exits 1 for a name it does not know.
			time.Sleep(time.Duration(s) * time.Second)
			return
		}
	}
	if len(os.Args) == 5 && os.Args[1] == "-insertchild" {
		insertChild(os.Args[2], os.Args[3], os.Args[4])
		return
	}
	if pinRace(os.Args[1:]) || insertRace(os.Args[1:]) {
		return
	}
	if len(os.Args) == 6 && os.Args[1] == "-link" {
		linkRace(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
		return
	}
	mode, args := "-child", os.Args[1:]
	if len(args) == 4 && args[0] == "-tail" {
		mode, args = "-tailchild", args[1:]
	}
	if len(args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: execracer [-tail] <git> <attempts> <report>")
		os.Exit(2)
	}
	n, err := strconv.Atoi(args[1])
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
	for i := 0; i < n; i++ {
		pid, err := syscall.ForkExec(self, []string{"execracer", mode, args[0]}, &syscall.ProcAttr{
			Env: os.Environ(), Files: []uintptr{0, 1, 2},
		})
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
	if err := os.WriteFile(args[2], []byte(report), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "execracer:", err)
		os.Exit(1)
	}
}

// child flips buf on another thread and execs git with it after the words lead (["git", lead..., buf]); it returns
// only when execve failed.
func child(git string, lead []string) {
	runtime.GOMAXPROCS(2)
	buf := []byte("diff\x00")
	words := [2][5]byte{{'d', 'i', 'f', 'f', 0}, {'p', 'u', 's', 'h', 0}}
	started := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		close(started)
		for i := 0; ; i++ {
			w := &words[i&1]
			for j := 0; j < 4; j++ {
				buf[j] = w[j]
			}
		}
	}()
	<-started
	path, err := syscall.BytePtrFromString(git)
	if err != nil {
		os.Exit(exitOther)
	}
	argv0, _ := syscall.BytePtrFromString("git")
	argv := []*byte{argv0}
	for _, w := range lead {
		p, _ := syscall.BytePtrFromString(w)
		argv = append(argv, p)
	}
	argv = append(argv, &buf[0], nil)
	env := []*byte{nil}
	_, _, e := syscall.RawSyscall(syscall.SYS_EXECVE, uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&argv[0])), uintptr(unsafe.Pointer(&env[0])))
	if e == syscall.EACCES {
		os.Exit(exitEACCES)
	}
	os.Exit(exitOther)
}

// linkRace flips <dir>/l between a symlink to git and nothing on one thread while the main thread execs it as `git
// push`, and writes the tally to report.
func linkRace(git, dir, attempts, report string) {
	n, err := strconv.Atoi(attempts)
	if err != nil || n <= 0 {
		fmt.Fprintln(os.Stderr, "execracer: attempts must be a positive number")
		os.Exit(2)
	}
	runtime.GOMAXPROCS(max(runtime.GOMAXPROCS(0), 2))
	link, tmp := filepath.Join(dir, "l"), filepath.Join(dir, "l.tmp")
	go func() {
		runtime.LockOSThread()
		for {
			_ = os.Symlink(git, tmp)
			_ = os.Rename(tmp, link)
			_ = os.Remove(link)
		}
	}()
	var eacces, ran, other int
	for i := 0; i < n; i++ {
		pid, err := syscall.ForkExec(link, []string{"git", "push"}, &syscall.ProcAttr{Env: os.Environ(), Files: []uintptr{0, 1, 2}})
		if err != nil {
			if errors.Is(err, syscall.EACCES) {
				eacces++
			} else {
				other++
			}
			continue
		}
		var ws syscall.WaitStatus
		if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
			other++
			continue
		}
		if ws.Exited() && ws.ExitStatus() == 0 {
			ran++
		} else {
			other++
		}
	}
	out := fmt.Sprintf("attempts=%d eacces=%d ran=%d other=%d\n", n, eacces, ran, other)
	if err := os.WriteFile(report, []byte(out), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "execracer:", err)
		os.Exit(1)
	}
}
