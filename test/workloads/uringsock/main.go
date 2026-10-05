// SPDX-License-Identifier: Apache-2.0

// Command uringsock is a workload for the decision plane's socket_create (ADR 0018 (5), TIER3-PLAN T13) and for
// cgroup/sock_create (ADR 0018 PR 2): it makes one socket through io_uring's IORING_OP_SOCKET, which no seccomp filter
// sees, for the family, type and protocol its arguments name, and prints "RESULT <name> ok", "RESULT <name> refused
// errno=<n>", or "RESULT <name> unavailable <why>" when this process has no io_uring (the filter's ENOSYS, or a kernel
// without it). An optional fifth argument names the submission mode: inline (the default), async (IOSQE_ASYNC, an
// io-wq worker) or sqpoll (IORING_SETUP_SQPOLL, the SQ thread).
//
// "uringsock <name> ulp <ulp> [mode]" is cgroup/setsockopt's (ADR 0018 (7)): it makes a TCP socket with socket(2) and
// sets its upper-layer protocol through io_uring's SOCKET_URING_OP_SETSOCKOPT, which no seccomp filter sees either,
// and prints the same RESULT line, "ok domain=<family>" naming the family the socket ended with (the smc module's
// "smc" makes it AF_SMC, 43).
package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil/uring"
)

func main() {
	if len(os.Args) >= 4 && os.Args[2] == "ulp" {
		os.Exit(ulp())
	}
	if len(os.Args) != 5 && len(os.Args) != 6 {
		fmt.Fprintln(os.Stderr, "usage: uringsock <name> <family> <type> <protocol> [inline|async|sqpoll]\n"+
			"       uringsock <name> ulp <ulp> [inline|async|sqpoll]")
		os.Exit(2)
	}
	mode, ok := modeArg(5)
	if !ok {
		os.Exit(2)
	}
	var n [3]int
	for i := range n {
		v, err := strconv.Atoi(os.Args[2+i])
		if err != nil {
			fmt.Fprintln(os.Stderr, "uringsock:", err)
			os.Exit(2)
		}
		n[i] = v
	}
	res, err := uring.SocketMode(mode, n[0], n[1], n[2])
	report(res, err, "")
}

// modeArg is the submission mode named by argument i, inline when there is none.
func modeArg(i int) (uring.Mode, bool) {
	if len(os.Args) <= i {
		return uring.Inline, true
	}
	m, err := uring.ParseMode(os.Args[i])
	if err != nil {
		fmt.Fprintln(os.Stderr, "uringsock:", err)
		return uring.Inline, false
	}
	return m, true
}

// ulp sets os.Args[3] as a TCP socket's upper-layer protocol through io_uring.
func ulp() int {
	if len(os.Args) > 5 {
		fmt.Fprintln(os.Stderr, "usage: uringsock <name> ulp <ulp> [inline|async|sqpoll]")
		return 2
	}
	mode, ok := modeArg(4)
	if !ok {
		return 2
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		fmt.Printf("RESULT %s failed socket: %v\n", os.Args[1], err)
		return 0
	}
	defer func() { _ = unix.Close(fd) }()
	name := append([]byte(os.Args[3]), 0)
	res, err := uring.Setsockopt(mode, fd, unix.SOL_TCP, unix.TCP_ULP, name, len(name))
	domain := ""
	if d, derr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN); derr == nil {
		domain = " domain=" + strconv.Itoa(d)
	}
	report(res, err, domain)
	return 0
}

func report(res int32, err error, suffix string) {
	switch {
	case errors.Is(err, uring.ErrUnavailable):
		fmt.Printf("RESULT %s unavailable %v\n", os.Args[1], err)
	case err != nil:
		fmt.Printf("RESULT %s failed %v\n", os.Args[1], err)
	case res < 0:
		fmt.Printf("RESULT %s refused errno=%d\n", os.Args[1], -res)
	default:
		fmt.Printf("RESULT %s ok%s\n", os.Args[1], suffix)
	}
}
