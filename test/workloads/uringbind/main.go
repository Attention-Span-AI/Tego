// SPDX-License-Identifier: Apache-2.0

// Command uringbind is a workload for the decision plane's listener hooks on io_uring (enforce-plane §2.20):
// IORING_OP_BIND and IORING_OP_LISTEN (6.11+) reach security_socket_bind and security_socket_listen with no bind or
// listen syscall, so no syscall-exit producer sees them. On one OS thread, as one task, it binds an undeclared
// abstract name and an undeclared pathname, makes a socket node with a plain mknod(2) (a filesystem operation, not a
// bind), listens on an unbound socket, then binds and listens on the declared abstract name <name>, each through
// io_uring, and prints "RESULT <step> <errno>" for each (0 on success), or "RESULT uring unavailable <why>" when
// this process has no io_uring, or "RESULT uring unsupported" when the kernel completes IORING_OP_BIND with EINVAL.
package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/attention-span-ai/tego/internal/testutil/uring"
	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: uringbind <declared abstract name>")
		os.Exit(2)
	}
	// The plane's listener marker lives in the submitting task's storage; every step runs on this one thread.
	runtime.LockOSThread()
	name := os.Args[1]
	socket := func() int {
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, "uringbind: socket:", err)
			os.Exit(2)
		}
		return fd
	}
	report := func(step string, res int32, err error) {
		switch {
		case errors.Is(err, uring.ErrUnavailable):
			fmt.Printf("RESULT uring unavailable %v\n", err)
			os.Exit(0)
		case err != nil:
			fmt.Fprintf(os.Stderr, "uringbind: %s: %v\n", step, err)
			os.Exit(2)
		case res == -int32(unix.EINVAL) && step == "uring-bind-undeclared-abstract":
			fmt.Println("RESULT uring unsupported")
			os.Exit(0)
		}
		fmt.Printf("RESULT %s %d\n", step, -res)
	}
	abstract := func(n string) []byte { return append([]byte{byte(unix.AF_UNIX), 0, 0}, n...) }
	pathname := func(p string) []byte { return append(append([]byte{byte(unix.AF_UNIX), 0}, p...), 0) }

	res, err := uring.Bind(socket(), abstract(name+"-undeclared"))
	report("uring-bind-undeclared-abstract", res, err)
	res, err = uring.Bind(socket(), pathname("out/uring-undeclared.sock"))
	report("uring-bind-undeclared-path", res, err)
	// A plain socket node by the same task after the refused binds: no bind is in progress, so the listener
	// policy has nothing to say about it, and it must never take a bind line.
	errno := 0
	if err := unix.Mknod("out/uring-standalone.sock", unix.S_IFSOCK|0o600, 0); err != nil {
		errno = int(err.(unix.Errno))
	}
	fmt.Printf("RESULT standalone-mknod %d\n", errno)
	res, err = uring.Listen(socket(), 4)
	report("uring-listen-unbound", res, err)
	declared := socket()
	res, err = uring.Bind(declared, abstract(name))
	report("uring-bind-declared", res, err)
	res, err = uring.Listen(declared, 4)
	report("uring-listen-declared", res, err)
}
