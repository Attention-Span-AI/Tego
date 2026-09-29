// SPDX-License-Identifier: Apache-2.0

// Command sigio sets a socket's SIGIO owner to argv[2] with ioctl(argv[1]: FIOSETOWN or fcntl) and signal
// SIGTERM, then makes the socket readable so the kernel sends it.
package main

import (
	"fmt"
	"os"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func main() {
	pid, _ := strconv.Atoi(os.Args[2])
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		fmt.Println("socketpair", err)
		os.Exit(1)
	}
	var e error
	if os.Args[1] == "ioctl" {
		p := int32(pid)
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fds[0]), 0x8901, uintptr(unsafe.Pointer(&p)))
		if errno != 0 {
			e = errno
		}
	} else {
		_, e = unix.FcntlInt(uintptr(fds[0]), unix.F_SETOWN, pid)
	}
	if e != nil {
		fmt.Println("setown refused:", e)
		os.Exit(3)
	}
	_, _ = unix.FcntlInt(uintptr(fds[0]), unix.F_SETSIG, int(unix.SIGTERM))
	fl, _ := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFL, 0)
	_, _ = unix.FcntlInt(uintptr(fds[0]), unix.F_SETFL, fl|unix.O_ASYNC|unix.O_NONBLOCK)
	_, _ = unix.Write(fds[1], []byte("x"))
	time.Sleep(200 * time.Millisecond)
	fmt.Println("sent")
}
