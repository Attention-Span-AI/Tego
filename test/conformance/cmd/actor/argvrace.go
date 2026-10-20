// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ADR 0048's disclosed argv race (R5): the supervisor decides a command rule on the argv it copied, and a thread
// of the agent's may change the argv between that copy and the kernel's own. The op race-argv-exec measures it
// and holds its closed direction (test/conformance cells.go OpRaceArgvExec).

const (
	// argvStage is `actor argv-race <path> <word>`: one attempt, a raw execve of path as [tool, word] whose word
	// another thread flips with argvBenign; it exits argvRefused on EACCES and argvOther on any other failure.
	argvStage = "argv-race"
	// argvBenign is test/conformance's RaceArgvBenign.
	argvBenign = "diff"
	// argvFDEnv names the descriptor a noop copy writes the argv[1] it ran with to.
	argvFDEnv = "TEGO_ACTOR_ARGV_FD"
	// argvRefused and argvOther are an attempt's exit when its exec failed.
	argvRefused, argvOther = 77, 78
	// argvAttempts and argvBudget bound the race: so many attempts, or so long.
	argvAttempts = 500
	argvBudget   = 2 * time.Second
)

func init() { observers["race-argv-exec"] = raceArgvExec }

// raceArgvExec runs the attempts and reports "attempts=N refused=R ran=<word>:W,<benign>:B other=O" as its value.
// It is refused (EACCES) when an attempt was refused, and succeeds when none was: the rule never caught the word.
func raceArgvExec(a Action) (string, error) {
	if len(a.Argv) != 2 || len(a.Argv[1]) != len(argvBenign) {
		return "", fmt.Errorf("race-argv-exec: argv %q is not [tool, a %d-letter word]: %w", a.Argv, len(argvBenign), unix.EINVAL)
	}
	r, w, err := os.Pipe()
	if err != nil {
		return "", err
	}
	ran := map[string]int{}
	done := make(chan struct{})
	go func() { // every copy that ran says its word, one line each
		defer close(done)
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			ran[sc.Text()]++
		}
	}()
	n, refused, other := 0, 0, 0
	for start := time.Now(); n < argvAttempts && time.Since(start) < argvBudget; n++ {
		cmd := exec.Command("/proc/self/exe", argvStage, a.Path, a.Argv[1])
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr
		cmd.ExtraFiles = []*os.File{w}
		cmd.Env = append(os.Environ(), argvFDEnv+"=3")
		err := cmd.Run()
		switch code := cmd.ProcessState.ExitCode(); {
		case err == nil:
		case code == argvRefused:
			refused++
		default:
			other++
		}
	}
	_ = w.Close()
	<-done
	_ = r.Close()
	value := fmt.Sprintf("attempts=%d refused=%d ran=%s:%d,%s:%d other=%d", n, refused, a.Argv[1], ran[a.Argv[1]], argvBenign, ran[argvBenign], other)
	if refused > 0 {
		return value, syscall.EACCES
	}
	return value, nil
}

// argvAttempt is one attempt: a raw execve that replaces the stage, so the argv the kernel copies is the buffer
// the other thread is flipping.
func argvAttempt(path, word string) {
	runtime.GOMAXPROCS(max(runtime.GOMAXPROCS(0), 2))
	buf := []byte(argvBenign + "\x00")
	words := [2]string{argvBenign, word}
	started := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		close(started)
		for i := 0; ; i++ {
			copy(buf, words[i&1])
		}
	}()
	<-started
	p, err := unix.BytePtrFromString(path)
	if err != nil {
		os.Exit(argvOther)
	}
	tool, _ := unix.BytePtrFromString(filepath.Base(path))
	argv := []*byte{tool, &buf[0], nil}
	var envp []*byte
	for _, kv := range os.Environ() {
		b, err := unix.BytePtrFromString(kv)
		if err != nil {
			os.Exit(argvOther)
		}
		envp = append(envp, b)
	}
	noop, _ := unix.BytePtrFromString(noopEnv + "=1") // the copy reports its word and exits
	envp = append(envp, noop, nil)
	_, _, en := unix.RawSyscall(unix.SYS_EXECVE, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&argv[0])), uintptr(unsafe.Pointer(&envp[0])))
	if en == unix.EACCES {
		os.Exit(argvRefused)
	}
	os.Exit(argvOther)
}

// reportArgv is a noop copy's report of the word it ran with, where the race asked for one (argvFDEnv).
func reportArgv() {
	if os.Getenv(argvFDEnv) != "3" || len(os.Args) < 2 {
		return
	}
	f := os.NewFile(3, "argv")
	_, _ = fmt.Fprintln(f, os.Args[1])
}
