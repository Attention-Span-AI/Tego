// SPDX-License-Identifier: Apache-2.0

// Command procscope is a workload for the process scope (supervisor R35): it rewrites, to the values they already
// hold, the RLIMIT_NOFILE and nice value of the process argv[2] names (outside the run) and of a child it starts
// from argv[1] with "30" (inside it), and prints one word per call: "ok" or the errno. Writing a value back
// unchanged is the permission check without the harm, so a filter that let it through changes nothing.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"golang.org/x/sys/unix"
)

func word(err error) string {
	var errno unix.Errno
	switch {
	case err == nil:
		return "ok"
	case errors.As(err, &errno):
		return unix.ErrnoName(errno)
	}
	return err.Error()
}

// touch writes pid's RLIMIT_NOFILE and nice value back as they are.
func touch(pid int) (string, string) {
	var lim unix.Rlimit
	if err := unix.Prlimit(pid, unix.RLIMIT_NOFILE, nil, &lim); err != nil {
		return "read:" + word(err), "-"
	}
	pl := word(unix.Prlimit(pid, unix.RLIMIT_NOFILE, &lim, nil))
	prio, err := unix.Getpriority(unix.PRIO_PROCESS, pid)
	if err != nil {
		return pl, "read:" + word(err)
	}
	// The raw syscall answers 20 - nice.
	return pl, word(unix.Setpriority(unix.PRIO_PROCESS, pid, 20-prio))
}

func main() {
	victim, _ := strconv.Atoi(os.Args[2])
	cmd := exec.Command(os.Args[1], "30")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stderr, os.Stderr // no /dev/null: it is not writable here
	if err := cmd.Start(); err != nil {
		fmt.Println("start:", err)
		os.Exit(1)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	vl, vp := touch(victim)
	cl, cp := touch(cmd.Process.Pid)
	fmt.Printf("outside=%s,%s inside=%s,%s\n", vl, vp, cl, cp)
}
