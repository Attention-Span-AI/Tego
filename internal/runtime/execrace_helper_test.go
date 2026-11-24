// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// The exec-race helper (GAPS C30, ADR 0041's amendment of 2026-11-22). The test binary run as
// `<binary> exec-race <attempts> <granted> <other> <report>` is the agent: for each attempt it starts a child of
// itself, `<binary> exec-race-child <granted> <other>`, which runs the exec race the supervisor's walk cannot close.
// The child opens both images O_PATH and keeps descriptor raceFD on one of them while a second thread of the same
// process points it at the other and back as fast as it can; the main thread runs /proc/self/fd/<raceFD>. The walk
// reads the descriptor once, the kernel opens it again, and the two can differ. The images are copies of true(1) and
// false(1), so the exit status says which one ran: 0 the granted one, 1 the other. The parent counts the outcomes and
// writes them to the report file.
const (
	execRaceArg      = "exec-race"
	execRaceChildArg = "exec-race-child"
	// execRacePlainArg runs one exec of a path with no race, in a child: `<binary> exec-race-plain <path>`.
	execRacePlainArg = "exec-race-plain"
	// raceFD is the descriptor the race flips; it sits above the descriptors a Go program opens for itself.
	raceFD = 100
	// exitRaceRefused is the child's status when its exec was refused EACCES, as a shell's is 126.
	exitRaceRefused = 126
)

// execRaceHelper returns at once when the binary was not started as the helper, and never returns when it was.
func execRaceHelper() {
	switch {
	case len(os.Args) == 6 && os.Args[1] == execRaceArg:
		execRaceParent(os.Args[2], os.Args[3], os.Args[4], os.Args[5])
	case len(os.Args) == 4 && os.Args[1] == execRaceChildArg:
		execRaceChild(os.Args[2], os.Args[3])
	case len(os.Args) == 3 && os.Args[1] == execRacePlainArg:
		err := unix.Exec(os.Args[2], []string{"image"}, os.Environ())
		if errors.Is(err, unix.EACCES) {
			os.Exit(exitRaceRefused)
		}
		fmt.Fprintf(os.Stderr, "exec: %v\n", err)
		os.Exit(9)
	}
}

func execRaceParent(attempts, granted, other, report string) {
	n, err := strconv.Atoi(attempts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "attempts %q: %v\n", attempts, err)
		os.Exit(9)
	}
	counts := map[int]int{}
	var perAttempt strings.Builder
	// First each file once with no race: what the contract says of each, which the raced execs are measured against.
	for _, f := range []struct{ name, path string }{{"granted", granted}, {"other", other}} {
		code := -1
		err := exec.Command(os.Args[0], execRacePlainArg, f.path).Run()
		var ee *exec.ExitError
		switch {
		case err == nil:
			code = 0
		case errors.As(err, &ee):
			code = ee.ExitCode()
		}
		fmt.Fprintf(&perAttempt, "plain %s %d\n", f.name, code)
	}
	firstFailure := ""
	for range n {
		var stderr strings.Builder
		cmd := exec.Command(os.Args[0], execRaceChildArg, granted, other)
		cmd.Stderr = &stderr
		err := cmd.Start()
		pid := 0
		if err == nil {
			pid = cmd.Process.Pid
			err = cmd.Wait()
		}
		if ee := (*exec.ExitError)(nil); firstFailure == "" && err != nil && !(errors.As(err, &ee) && (ee.ExitCode() == 1 || ee.ExitCode() == exitRaceRefused)) {
			firstFailure = strings.TrimSpace(stderr.String()) + " (" + err.Error() + ")"
		}
		var ee *exec.ExitError
		code := -1
		switch {
		case err == nil:
			code = 0
		case errors.As(err, &ee):
			code = ee.ExitCode()
		}
		counts[code]++
		fmt.Fprintf(&perAttempt, "attempt %d %d\n", pid, code)
	}
	text := fmt.Sprintf("granted=%d other=%d refused=%d failed=%d\n", counts[0], counts[1], counts[exitRaceRefused], n-counts[0]-counts[1]-counts[exitRaceRefused])
	text += perAttempt.String()
	if firstFailure != "" {
		text += "first failure: " + firstFailure + "\n"
	}
	if err := os.WriteFile(report, []byte(text), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "report: %v\n", err)
		os.Exit(9)
	}
	os.Exit(0)
}

func execRaceChild(granted, other string) {
	fail := func(what string, err error) {
		fmt.Fprintf(os.Stderr, "%s: %v\n", what, err)
		os.Exit(9)
	}
	g, err := unix.Open(granted, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		fail("open granted", err)
	}
	o, err := unix.Open(other, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		fail("open other", err)
	}
	if err := unix.Dup3(g, raceFD, 0); err != nil {
		fail("dup3", err)
	}
	var stop atomic.Bool
	var flips atomic.Int64
	go func() {
		runtime.LockOSThread()
		for !stop.Load() {
			_ = unix.Dup3(o, raceFD, 0)
			_ = unix.Dup3(g, raceFD, 0)
			flips.Add(1)
		}
	}()
	// The exec starts once the second thread is flipping, so the descriptor changes while the supervisor reads it and
	// while the kernel opens it.
	for flips.Load() < 1000 {
		runtime.Gosched()
	}
	runtime.LockOSThread()
	err = unix.Exec("/proc/self/fd/"+strconv.Itoa(raceFD), []string{"image"}, os.Environ())
	stop.Store(true)
	if errors.Is(err, unix.EACCES) {
		os.Exit(exitRaceRefused)
	}
	fail("exec", err)
}
