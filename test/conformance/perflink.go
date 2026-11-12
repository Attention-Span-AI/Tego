// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// perfLinkProbe is the program bpfPerfLink loads, r0 = 0 then exit (struct bpf_insn, little-endian), and its license.
// They are package variables so the addresses the bpf(2) attribute holds stay valid for the call: a stack copy
// can move.
var (
	perfLinkProbe        = [2]uint64{0xb7, 0x95}
	perfLinkProbeLicense = [4]byte{'G', 'P', 'L', 0}
)

// bpfPerfLink reports whether this kernel makes BPF perf links (BPF_LINK_CREATE with BPF_PERF_EVENT: upstream 5.15,
// and RHEL 9.8's 5.14 by backport). The decision plane's exec outcome tracepoints attach and pin only as such links
// (internal/runtime/enforce/cgroup attachShared); where they do, the kernel writes an exec's terminal line. It is
// cilium/ebpf's own probe (link haveBPFLinkPerfEvent), made here with x/sys alone: load a kprobe program that returns
// 0 and ask for a perf link to descriptor 0, which is no perf event, so a kernel that knows the attach type answers
// EBADF and one that does not EINVAL. A process that may not load a program (not root) gets false.
func bpfPerfLink() bool {
	var load [128]byte // union bpf_attr, BPF_PROG_LOAD: prog_type, insn_cnt, insns, license, the rest zero
	*(*uint32)(unsafe.Pointer(&load[0])) = unix.BPF_PROG_TYPE_KPROBE
	*(*uint32)(unsafe.Pointer(&load[4])) = uint32(len(perfLinkProbe))
	*(*uint64)(unsafe.Pointer(&load[8])) = uint64(uintptr(unsafe.Pointer(&perfLinkProbe[0])))
	*(*uint64)(unsafe.Pointer(&load[16])) = uint64(uintptr(unsafe.Pointer(&perfLinkProbeLicense[0])))
	fd, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_PROG_LOAD, uintptr(unsafe.Pointer(&load[0])), unsafe.Sizeof(load))
	if errno != 0 {
		return false
	}
	defer func() { _ = unix.Close(int(fd)) }()
	var create [128]byte // BPF_LINK_CREATE: prog_fd, target_fd 0, attach_type
	*(*uint32)(unsafe.Pointer(&create[0])) = uint32(fd)
	*(*uint32)(unsafe.Pointer(&create[8])) = unix.BPF_PERF_EVENT
	link, _, errno := unix.Syscall(unix.SYS_BPF, unix.BPF_LINK_CREATE, uintptr(unsafe.Pointer(&create[0])), unsafe.Sizeof(create))
	if errno == 0 {
		_ = unix.Close(int(link)) // descriptor 0 was a perf event after all; the attach type is known
		return true
	}
	return errno == unix.EBADF
}
