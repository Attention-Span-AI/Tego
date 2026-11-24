// SPDX-License-Identifier: Apache-2.0

// Command strictimport is a workload for ADR 0128's descriptor-import guard under net.assurance: kernel. It connects a
// SOCK_SEQPACKET socket to the unix socket its first argument names, which an outside process (the test) listens on and
// feeds with messages that carry a descriptor each, and then makes every kind of receive the guard has to answer. After
// each attempt it counts /proc/self/fd, so an import shows as a new entry. It writes what each came to to the file its
// second argument names, as JSON, before its last attempt (int 0x80, which a kernel with the filter's arch guard answers
// ENOSYS and which may end the process instead) and again after it.
//
// The attempts, in order, on messages m1..m4 the outside process sent, m1 to m3 each carrying a descriptor:
//
//	ctl:      recvmsg with a control buffer room for SCM_RIGHTS and SCM_PIDFD: EACCES, no data taken, no new descriptor
//	ctl_peek: the same with MSG_PEEK: EACCES
//	nocontrol_peek: recvmsg with no control buffer and MSG_PEEK: m1, MSG_CTRUNC, no new descriptor
//	nocontrol: the same without MSG_PEEK takes m1: MSG_CTRUNC, no new descriptor (the kernel drops the passed files)
//	read: read(2) takes m2: no new descriptor
//	recvfrom: recvfrom(2) takes m3: no new descriptor
//	udp_ctl_empty: recvmsg with a control buffer on a UDP socket with nothing queued, MSG_DONTWAIT: EAGAIN (the guard
//	    refuses control receives of AF_UNIX sockets only; any other family reaches its protocol's own receive)
//	udp_ctl: a datagram the workload sent itself on loopback, taken with a control buffer and SO_TIMESTAMP: ok with
//	    the timestamp delivered ("skipped" when the run may not send it)
//	recvmmsg: ENOSYS
//	pidfd_getfd: ENOSYS
//	int80: the 32-bit entry, which the filter's arch guard answers ENOSYS (amd64 only)
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// soPassPidfd is SO_PASSPIDFD (Linux 6.5): the receiver then gets an SCM_PIDFD with each message that has a control
// buffer, which installs a pidfd.
const soPassPidfd = 76

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: strictimport <socket> <out.json>")
		os.Exit(2)
	}
	res := map[string]string{}
	write := func() {
		b, _ := json.Marshal(res)
		if err := os.WriteFile(os.Args[2], b, 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "socket:", err)
		os.Exit(1)
	}
	if err := unix.Connect(fd, &unix.SockaddrUnix{Name: os.Args[1]}); err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		os.Exit(1)
	}
	res["pidfd_option"] = errName(unix.SetsockoptInt(fd, unix.SOL_SOCKET, soPassPidfd, 1))
	buf := make([]byte, 64)
	room := make([]byte, unix.CmsgSpace(4)*2)

	// recv runs one recvmsg and records its errno, the data taken, whether the control data was truncated away, and
	// whether the descriptor table grew.
	recv := func(name string, oob []byte, flags int) {
		before := fds()
		n, oobn, rflags, _, err := unix.Recvmsg(fd, buf, oob, flags)
		res[name] = errName(err)
		if err == nil {
			res[name+"_data"] = string(buf[:n])
			if rflags&unix.MSG_CTRUNC != 0 {
				res[name+"_ctrunc"] = "yes"
			} else {
				res[name+"_ctrunc"] = "no"
			}
			if oobn != 0 {
				res[name+"_control"] = "delivered"
			}
		}
		res[name+"_fds"] = fmt.Sprint(fds() - before)
	}
	recv("ctl", room, 0)
	recv("ctl_peek", room, unix.MSG_PEEK)
	recv("nocontrol_peek", nil, unix.MSG_PEEK)
	recv("nocontrol", nil, 0)

	before := fds()
	n, err := unix.Read(fd, buf)
	res["read"] = errName(err)
	if err == nil {
		res["read_data"] = string(buf[:n])
	}
	res["read_fds"] = fmt.Sprint(fds() - before)

	before = fds()
	n, _, err = unix.Recvfrom(fd, buf, 0)
	res["recvfrom"] = errName(err)
	if err == nil {
		res["recvfrom_data"] = string(buf[:n])
	}
	res["recvfrom_fds"] = fmt.Sprint(fds() - before)

	udpControl(res)

	var mm [64]byte
	_, _, e := unix.Syscall6(sysRecvmmsg, uintptr(fd), uintptr(unsafe.Pointer(&mm[0])), 1, unix.MSG_DONTWAIT, 0, 0)
	res["recvmmsg"] = errName(e)
	_, _, e = unix.Syscall(unix.SYS_PIDFD_GETFD, ^uintptr(0), 0, 0)
	res["pidfd_getfd"] = errName(e)

	res["int80"] = "not returned"
	write()
	res["int80"] = int80()
	write()
}

// udpControl makes control-bearing receives on a UDP socket (IP_PKTINFO and SO_TIMESTAMP), which carry no descriptor
// and which the guard must leave alone (ADR 0128, amended: AF_UNIX alone has SCM_RIGHTS and SCM_PIDFD). The first
// receive has nothing to take, so a kernel that gets as far as the protocol answers EAGAIN, and the guard's
// refusal would answer EACCES. The second takes a datagram sent on loopback; a run whose net: section does not allow
// that send reads "skipped" there.
func udpControl(res map[string]string) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		res["udp_ctl_empty"], res["udp_ctl"] = "socket: "+errName(err), "socket: "+errName(err)
		return
	}
	defer func() { _ = unix.Close(fd) }()
	res["udp_opts"] = errName(unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_PKTINFO, 1)) + "/" +
		errName(unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TIMESTAMP, 1))
	buf := make([]byte, 64)
	room := make([]byte, 256)
	_, _, _, _, err = unix.Recvmsg(fd, buf, room, unix.MSG_DONTWAIT)
	res["udp_ctl_empty"] = errName(err)
	res["udp_ctl"] = "skipped"
	lo := &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}
	if unix.Bind(fd, lo) != nil {
		return
	}
	bound, err := unix.Getsockname(fd)
	if err != nil {
		return
	}
	if unix.Sendto(fd, []byte("udp"), 0, bound) != nil {
		return
	}
	_ = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5})
	n, oobn, _, _, err := unix.Recvmsg(fd, buf, room, 0)
	res["udp_ctl"] = errName(err)
	if err == nil {
		res["udp_ctl_data"] = string(buf[:n])
		if oobn != 0 {
			res["udp_ctl_control"] = "delivered"
		}
	}
}

// fds is the number of entries in this process's descriptor table, as /proc/self/fd lists them (the listing's own
// descriptor included, the same each time).
func fds() int {
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	return len(ents)
}

// errName names an errno, "ok" for none.
func errName(err error) string {
	if err == nil {
		return "ok"
	}
	if e, ok := err.(unix.Errno); ok {
		if e == 0 {
			return "ok"
		}
		return unix.ErrnoName(e)
	}
	if e, ok := err.(*os.SyscallError); ok {
		return errName(e.Err)
	}
	return err.Error()
}
