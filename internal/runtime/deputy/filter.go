// SPDX-License-Identifier: Apache-2.0

package deputy

import (
	"fmt"
	"runtime"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// FilterSpec is what the deputy's allowlist filter is built for: its own thread group, whose signals the Go runtime
// raises (tgkill for preemption, kill for a crash), and the runtime's poller, whose eventfd it reads and writes.
type FilterSpec struct {
	// TGID is the deputy's pid: kill and tgkill are allowed for it alone.
	TGID int
	// EventFD is the Go runtime poller's eventfd, which netpollBreak writes and netpoll reads; -1 when the poller
	// has none, and then no read is allowed and write only to standard error.
	EventFD int
}

// seccomp_data offsets (include/uapi/linux/seccomp.h): nr, arch, instruction_pointer, then six 64-bit args.
const (
	offNr   = 0
	offArch = 4
	offArg0 = 16 // low word of args[0] on a little-endian architecture
	offArg1 = 24
)

const (
	retAllow = unix.SECCOMP_RET_ALLOW
	retKill  = unix.SECCOMP_RET_KILL_PROCESS
	// retENOSYS answers clone3, whose flags sit in a structure the filter cannot read: libc's pthread_create falls back
	// to clone(2), whose CLONE_THREAD the filter checks, as it does under a container runtime's default profile.
	retENOSYS = unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)
	// retEINVAL answers prctl(PR_SET_VMA): the Go runtime names its mappings with it (decoratemappings) and stops
	// once the kernel answers EINVAL, so the deputy gains no prctl and the runtime never retries.
	retEINVAL = unix.SECCOMP_RET_ERRNO | uint32(unix.EINVAL)
	// retEPERM answers a read of any descriptor but the poller's eventfd: the read is refused, and the deputy, which
	// reads no file, lives on. A cgo build's libc reads one on its own: glibc's malloc counts the CPUs the first time
	// a thread needs a ninth arena (arena_get2's __get_nprocs), opening /sys/devices/system/cpu/online and then
	// /proc/stat, and falls back to sched_getaffinity, which is allowed, when neither can be read. Killed there, the
	// deputy died as its tenth thread started, under the load that makes it start one, and every held open after it
	// was refused held-unavailable.
	retEPERM = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	// x32Bit is the x32 personality bit in nr on x86_64, which no syscall of this process sets.
	x32Bit = 0x40000000
	// prSetVMA is PR_SET_VMA (include/uapi/linux/prctl.h).
	prSetVMA = 0x53564d41
)

// plainAllowed are the syscalls the deputy makes with any arguments: its walk and opens (openat, the stats, readlinkat,
// dup, close, umask), the protocol (recvmsg, sendmsg), and what the Go runtime needs to schedule its threads, collect
// garbage and exit. Anything not here, nor among the argument-checked ones in Filter, kills the process: execve, any
// socket, connect, ptrace, process_vm_*, ioctl, mount, unshare, setns, bpf, io_uring, memfd_create, fork and the
// rest.
var plainAllowed = []uint32{
	unix.SYS_OPENAT, unix.SYS_OPENAT2, unix.SYS_CLOSE, unix.SYS_FSTAT, unix.SYS_NEWFSTATAT, unix.SYS_STATX, unix.SYS_FSTATFS,
	unix.SYS_READLINKAT, unix.SYS_DUP, unix.SYS_UMASK, unix.SYS_RECVMSG, unix.SYS_SENDMSG,
	unix.SYS_FUTEX, unix.SYS_MMAP, unix.SYS_MUNMAP, unix.SYS_MADVISE, unix.SYS_RT_SIGACTION, unix.SYS_RT_SIGPROCMASK,
	unix.SYS_RT_SIGRETURN, unix.SYS_SIGALTSTACK, unix.SYS_SCHED_YIELD, unix.SYS_NANOSLEEP, unix.SYS_CLOCK_NANOSLEEP,
	unix.SYS_CLOCK_GETTIME, unix.SYS_GETPID, unix.SYS_GETTID, unix.SYS_EXIT, unix.SYS_EXIT_GROUP,
	unix.SYS_RESTART_SYSCALL, unix.SYS_EPOLL_PWAIT, unix.SYS_GETRANDOM, unix.SYS_SCHED_GETAFFINITY,
	// A cgo build's threads are libc's (pthread_create): their stacks' guard pages, robust futex lists, restartable
	// sequences and malloc's heap. Each acts on the deputy's own memory or thread state only. The shipped binary is
	// CGO_ENABLED=0 and makes none of them at steady state. (The CPU count glibc's malloc reads on a new thread is
	// answered EPERM: retEPERM.)
	unix.SYS_MPROTECT, unix.SYS_SET_ROBUST_LIST, unix.SYS_RSEQ, unix.SYS_BRK,
}

// fcntlAllowed are the fcntl commands the deputy makes: an opened descriptor's status flags (O_NONBLOCK as the agent
// asked) and close-on-exec. No lock, lease, owner or pipe size.
var fcntlAllowed = []uint32{unix.F_GETFD, unix.F_SETFD, unix.F_GETFL, unix.F_SETFL}

// nativeArch is the AUDIT_ARCH_* value of the running binary.
func nativeArch() (uint32, error) {
	switch runtime.GOARCH {
	case "amd64":
		return unix.AUDIT_ARCH_X86_64, nil
	case "arm64":
		return unix.AUDIT_ARCH_AARCH64, nil
	}
	return 0, fmt.Errorf("deputy: no filter for GOARCH %s", runtime.GOARCH)
}

// Filter assembles the deputy's allowlist (ADR 0041 D2): any other architecture, the x32 personality, and every
// syscall not allowed below kill the process. Argument-checked: clone only with CLONE_THREAD (the runtime's own
// threads; no new process), kill and tgkill only for the deputy's own thread group, read only of the poller's
// eventfd (any other read answered EPERM, retEPERM), write only to it and to standard error, fcntl only for the
// commands above, and prctl(PR_SET_VMA) answered EINVAL.
func Filter(s FilterSpec) ([]bpf.RawInstruction, error) {
	arch, err := nativeArch()
	if err != nil {
		return nil, err
	}
	var p []bpf.Instruction
	ret := func(v uint32) { p = append(p, bpf.RetConstant{Val: v}) }
	// allowIf: when the accumulator equals v, allow; otherwise fall through past the return.
	allowIf := func(v uint32) {
		p = append(p, bpf.JumpIf{Cond: bpf.JumpEqual, Val: v, SkipFalse: 1})
		ret(retAllow)
	}
	p = append(p, bpf.LoadAbsolute{Off: offArch, Size: 4})
	p = append(p, bpf.JumpIf{Cond: bpf.JumpEqual, Val: arch, SkipTrue: 1})
	ret(retKill)
	p = append(p, bpf.LoadAbsolute{Off: offNr, Size: 4})
	if arch == unix.AUDIT_ARCH_X86_64 {
		p = append(p, bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: x32Bit, SkipFalse: 1})
		ret(retKill)
	}
	for _, nr := range plainAllowed {
		allowIf(nr)
	}
	// Each argument-checked syscall: when nr matches, load an argument, decide, and return; otherwise skip the whole
	// block. body is built first so its length gives the skip.
	checked := func(nr uint32, body []bpf.Instruction) {
		p = append(p, bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipFalse: uint8(len(body))})
		p = append(p, body...)
	}
	allow, kill := bpf.RetConstant{Val: retAllow}, bpf.RetConstant{Val: retKill}
	p = append(p, bpf.JumpIf{Cond: bpf.JumpEqual, Val: sysClone3, SkipFalse: 1})
	ret(retENOSYS)
	checked(sysClone, []bpf.Instruction{
		bpf.LoadAbsolute{Off: offArg0, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: unix.CLONE_THREAD, SkipFalse: 1},
		allow, kill,
	})
	own := uint32(s.TGID)
	for _, nr := range []uint32{unix.SYS_KILL, unix.SYS_TGKILL} {
		checked(nr, []bpf.Instruction{
			bpf.LoadAbsolute{Off: offArg0, Size: 4},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: own, SkipFalse: 1},
			allow, kill,
		})
	}
	efd := uint32(0xffffffff)
	if s.EventFD >= 0 {
		efd = uint32(s.EventFD)
	}
	checked(unix.SYS_READ, []bpf.Instruction{
		bpf.LoadAbsolute{Off: offArg0, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: efd, SkipFalse: 1},
		allow, bpf.RetConstant{Val: retEPERM},
	})
	checked(unix.SYS_WRITE, []bpf.Instruction{
		bpf.LoadAbsolute{Off: offArg0, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: efd, SkipTrue: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 2, SkipFalse: 1},
		allow, kill,
	})
	fcntl := []bpf.Instruction{bpf.LoadAbsolute{Off: offArg1, Size: 4}}
	for i, cmd := range fcntlAllowed {
		// Each equal jumps over the remaining tests to the allow; the last unequal falls into the kill.
		fcntl = append(fcntl, bpf.JumpIf{Cond: bpf.JumpEqual, Val: cmd, SkipTrue: uint8(len(fcntlAllowed) - 1 - i + 1)})
	}
	fcntl = append(fcntl, kill, allow)
	checked(unix.SYS_FCNTL, fcntl)
	checked(unix.SYS_PRCTL, []bpf.Instruction{
		bpf.LoadAbsolute{Off: offArg0, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: prSetVMA, SkipFalse: 1},
		bpf.RetConstant{Val: retEINVAL}, kill,
	})
	ret(retKill)
	return bpf.Assemble(p)
}
