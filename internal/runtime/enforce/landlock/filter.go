// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"fmt"
	"runtime"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// Arch is the AUDIT_ARCH_* value a filter is built for (R9).
type Arch uint32

// Supported architectures.
const (
	ArchX86_64 Arch = unix.AUDIT_ARCH_X86_64
	ArchARM64  Arch = unix.AUDIT_ARCH_AARCH64
)

// String names the architecture.
func (a Arch) String() string {
	switch a {
	case ArchX86_64:
		return "x86_64"
	case ArchARM64:
		return "arm64"
	}
	return fmt.Sprintf("arch(%#x)", uint32(a))
}

// NativeArch is the build's own architecture; the filter must match the ABI the child speaks.
func NativeArch() Arch {
	if runtime.GOARCH == "arm64" {
		return ArchARM64
	}
	return ArchX86_64
}

// seccomp_data layout (R12): nr@0 (4B), arch@4 (4B), instruction_pointer@8 (8B), args[0..5]@16+8i.
// Both supported arches are little-endian, so the low half of a 64-bit argument sits at the field
// offset and the high half four bytes later.
const (
	offNR   = 0
	offArch = 4
	offArg0 = 16
	argSize = 8

	// WriteFlagMask is O_WRONLY|O_RDWR|O_CREAT|O_TRUNC: an open that can modify (R12). O_TMPFILE
	// needs O_WRONLY/O_RDWR to be linkable and is already caught.
	WriteFlagMask = 0x243
	// x32Bit is the x32 personality bit in nr on x86_64 (R9).
	x32Bit = 0x40000000

	// TIOCSTI pushes a byte into the controlling terminal's input queue, and TIOCLINUX subcommand 2
	// pastes the terminal's selection buffer into it. Either lets a process write a command the user's
	// own shell then runs, with the user's privileges and outside the sandbox entirely: CVE-2017-5226
	// against bubblewrap, and the reason flatpak, firejail and snap all refuse them. Landlock cannot
	// see an ioctl, so the filter is the only place in tier 1 that can.
	//
	// Both numbers are the asm-generic values, which x86-64 and arm64 share.
	ioctlTIOCSTI   = 0x5412
	ioctlTIOCLINUX = 0x541C

	// minTruncateABI is the first Landlock ABI with LANDLOCK_ACCESS_FS_TRUNCATE (ABI 3 / kernel 6.2).
	// Below it the kernel has no path_truncate hook at all: "File truncation could not be denied before
	// the third Landlock ABI, so it is always allowed when using a kernel that only supports the first
	// or second ABI" (Documentation/userspace-api/landlock.rst, "Truncating files"). R2's degrade row.
	minTruncateABI = 3
	// minSignalScopeABI is the first Landlock ABI with LANDLOCK_SCOPE_SIGNAL (ABI 6 / kernel 6.12): from it
	// the ruleset refuses a signal to a process outside the domain; below it the filter hands the signalling
	// syscalls to the supervisor (signalScopeTest).
	minSignalScopeABI = 6
	// fSetown and fSetownEx are fcntl's F_SETOWN and F_SETOWN_EX (asm-generic, both arches): they name the
	// process a descriptor's SIGIO (or F_SETSIG's signal) goes to, which is a signal like kill's.
	fSetown, fSetownEx = 8, 15
	// fNotify is fcntl's F_NOTIFY (F_LINUX_SPECIFIC_BASE + 2, both arches): dnotify, the third watch API beside
	// inotify and fanotify, which places a watch on the directory a descriptor holds (R11e).
	fNotify = 1026
	// ioctlFIOSETOWN and ioctlSIOCSPGRP set a socket's signal owner through ioctl(2), the same owner record
	// fcntl's F_SETOWN sets (sock_ioctl -> f_setown).
	ioctlFIOSETOWN, ioctlSIOCSPGRP = 0x8901, 0x8902
	// sigURG is SIGURG, 23 on both arches: default action ignore, and the Go runtime's preemption signal.
	sigURG = 23
	// oTruncFlag is O_TRUNC, oAccMode is O_ACCMODE, oWrOnly and oRdWr its two write modes; x86-64 and
	// arm64 agree on all four, like WriteFlagMask.
	oTruncFlag = 0x200
	oAccMode   = 0x3
	oWrOnly    = 0x1
	oRdWr      = 0x2

	// ipprotoMPTCP is IPPROTO_MPTCP (linux/in.h). Landlock's network hooks dispatch on sk_is_tcp()/
	// sk_is_udp() and fall through to a bare `else return 0` (security/landlock/net.c), so an MPTCP
	// socket carries no LANDLOCK_ACCESS_NET_* check whatsoever — R6's bind/listen denial is real for
	// IPPROTO_TCP only (E30).
	ipprotoMPTCP = 262

	// The socket-family allowlist's constants (ADR 0018), the asm-generic values both arches share:
	// address families (linux/socket.h), socket types (linux/net.h, masked with SOCK_TYPE_MASK because the
	// type argument also carries SOCK_NONBLOCK and SOCK_CLOEXEC) and protocols (linux/in.h, linux/in6.h).
	afUnix, afInet, afNetlink, afInet6  = 1, 2, 16, 10
	netlinkRoute                        = 0
	sockTypeMask, sockStream, sockDgram = 0xf, 1, 2
	ipprotoTCP, ipprotoUDP              = 6, 17
	ipprotoICMP, ipprotoICMPv6          = 1, 58

	// mfdNoexecSeal is MFD_NOEXEC_SEAL (linux/memfd.h): a memfd_create flag that clears the new file's
	// execute bits and seals them (F_SEAL_EXEC), so the kernel refuses to exec it (verified on 6.17: a
	// memfd created with this flag cannot be run, one created without it — or with MFD_EXEC — runs). It is
	// the register argument the memfd arm filters on to close the anonymous-image exec vector at creation
	// (SEMANTICS §4): Landlock's file_open allows a memfd outright (is_nouser_or_private on its
	// SB_NOUSER superblock) and tier 2's FAN_OPEN_EXEC_PERM sees no open a fexecve makes, so before this
	// arm the only closure was the supervisor's post-hoc walk, which a descriptor-table race can beat.
	// The flag arrived upstream in 6.3 and some older distribution kernels backport it (RHEL 9.8's 5.14
	// does), so the sealing arm is installed only when a probe finds the kernel honours it
	// (MemfdNoexecSealSupported), never by version. On a kernel without it no flag distinguishes an
	// executable memfd from a data one: every memfd is exec-capable by the kernel's semantics, so the arm
	// there refuses memfd_create outright (MemfdRefused), which is as race-free at creation as the sealing
	// arm.
	mfdNoexecSeal = 0x0008
	// mfdHugetlb is MFD_HUGETLB (linux/memfd.h): a memfd on hugetlbfs instead of shmem. memfd_create applies
	// MFD_NOEXEC_SEAL to it (the execute bits cleared, F_SEAL_EXEC set), but only shmem_setattr enforces
	// F_SEAL_EXEC; hugetlbfs_setattr does not, so an fchmod gives a sealed hugetlb memfd its execute bits
	// back (verified on 6.17: fchmod 0755 succeeded on it and failed EPERM on a sealed shmem memfd). The
	// sealing arm therefore refuses the flag too: a hugetlb memfd is never a non-executable one.
	mfdHugetlb = 0x0004

	retAllow           = unix.SECCOMP_RET_ALLOW
	retNotify          = unix.SECCOMP_RET_USER_NOTIF
	retENOSYS          = unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)
	retEPERM           = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)
	retEACCES          = unix.SECCOMP_RET_ERRNO | uint32(unix.EACCES)
	retEPROTONOSUPPORT = unix.SECCOMP_RET_ERRNO | uint32(unix.EPROTONOSUPPORT)
)

// MemfdArm is what the filter does with memfd_create(2) (SEMANTICS §4, R11a): the creation-time closure of the
// anonymous-image exec vector, chosen per run by Prepare (memfdArmFor).
type MemfdArm int

const (
	// MemfdOpen installs no arm: every memfd_create is allowed. A run with no exec: section (deny nothing,
	// SEMANTICS §1), one that opted into exec.anonymous, and an observe run get it.
	MemfdOpen MemfdArm = iota
	// MemfdSealed refuses (EACCES) a memfd_create that does not set MFD_NOEXEC_SEAL or that sets MFD_HUGETLB,
	// so every memfd the run can create is non-executable. It needs a kernel that honours the flag
	// (MemfdNoexecSealSupported).
	MemfdSealed
	// MemfdRefused refuses every memfd_create (ENOSYS): the arm for a kernel without MFD_NOEXEC_SEAL,
	// where any memfd can be made executable, so the only creation-time closure is no memfd at all.
	MemfdRefused
)

// String names the arm for diagnostics and golden files.
func (m MemfdArm) String() string {
	switch m {
	case MemfdSealed:
		return "sealed"
	case MemfdRefused:
		return "refused"
	}
	return "open"
}

// SocketArm is what the filter does with socket(2) and socketpair(2) (ADR 0018), chosen per run from the
// compiled net section (SocketArmFor).
type SocketArm struct {
	// Restricted installs the allowlist: the contract has a net: section. Without one nothing is refused
	// (SEMANTICS §1) and only the MPTCP arm applies.
	Restricted bool
	// ICMP admits ping sockets (SOCK_DGRAM with IPPROTO_ICMP or IPPROTO_ICMPV6): the net section holds a
	// port-0 entry, SEMANTICS §5's spelling of an ICMP destination.
	ICMP bool
}

// SocketArmFor is the socket arm a run's table asks for: agent.RuleTable.NetSocketPolicy, the predicate the
// decision plane's slot header reads too (ADR 0018 (5)). The conversion ties SocketArm's fields to it.
func SocketArmFor(rt *agent.RuleTable) SocketArm {
	return SocketArm(rt.NetSocketPolicy())
}

// noSyscall marks a syscall the architecture does not have (arm64 has no open/creat/unlink/...).
const noSyscall = ^uint32(0)

func offArg(i int) uint32 { return offArg0 + uint32(i)*argSize }

// sysNR is one syscall of a table, named for diagnostics and golden tests.
type sysNR struct {
	Name string
	NR   uint32
}

// archTable is the syscall-number table of one architecture. io_uring_* and openat2 are identical on
// both (R10); everything else, open_by_handle_at included, differs.
type archTable struct {
	Arch Arch
	X32  bool // emit the x32 personality check (x86_64 only, R9)

	ENOSYS   []sysNR // io_uring_setup/enter/register, openat2, open_by_handle_at (R10)
	Ioctl    uint32  // the ioctl syscall, for the terminal-injection guard
	Notify   []sysNR // unconditionally notified (R11)
	SendTo   uint32  // notified when args[4] (dest_addr) != NULL (R11/R12)
	Open     uint32  // flags in args[1]; noSyscall on arm64
	OpenAt   uint32  // flags in args[2]
	Truncate uint32  // path-based truncate(2): refused below ABI 3 (R2), notified from ABI 3 (R11)
	// Chmod is the mode-change family, notified under record: full so the supervisor records it (R16), and
	// under an fs.write gate so the supervisor scores it (R11): no Landlock ABI governs chmod, and no other
	// tier-1 or tier-2 mechanism sees one.
	Chmod []sysNR
	// Attr is the attribute-change families beside chmod: the extended-attribute calls that set or remove one
	// (setxattr(2), removexattr(2), their l- and f- forms and the *at forms of 6.13) and the chown family. A POSIX
	// ACL is the extended attribute system.posix_acl_access, and setting one rewrites the mode bits as chmod does;
	// a chown gives the group bits to another group. They are notified under an fs.write gate only, so the
	// supervisor scores each as a write (R11): no Landlock ABI governs either, and no other tier-1 or tier-2
	// mechanism sees one. record: full does not notify them (its promise is reads, mmap and chmod).
	Attr                     []sysNR
	Socket                   uint32 // socket(2), for the IPPROTO_MPTCP guard (E30) and the family allowlist (ADR 0018)
	Pair                     uint32 // socketpair(2), for the family allowlist (ADR 0018)
	Bind, Listen, Setsockopt uint32
	// Frames is sendfile(2) and splice(2), which R11d notifies in a run that decides datagrams: either can leave a
	// UDP frame pending on a socket it writes into.
	Frames []sysNR
	// Watch is inotify_add_watch(2) and fanotify_mark(2), which R11e notifies in every enforcing run, with fcntl(2)'s
	// F_NOTIFY (dnotify, on Fcntl), so the supervisor refuses a watch whose object the run withholds a read of
	// (supervisor R36): a watch opens nothing, so neither the Landlock ruleset, which has no hook for it, nor a decision
	// plane, which hooks no security_path_notify, refuses one, and a watch on a deny_read directory reported which of
	// its files were opened and changed (GAPS A10).
	Watch []sysNR
	// Signal is the kill(2) family the signal-scope arm notifies below Landlock ABI 6, PidfdSignal the
	// pidfd_send_signal(2) it answers ENOSYS, and Fcntl the fcntl(2) whose F_SETOWN it notifies, and whose
	// F_NOTIFY the watch arm notifies.
	Signal      []sysNR
	PidfdSignal uint32
	Fcntl       uint32
	// RootDeny is what the root-tier arm answers EPERM (ADR 0033): loading BPF or kernel code.
	RootDeny []sysNR
	// ClientDeny closes connected-socket import and listener creation for strict
	// destination assurance; these syscalls need architecture-specific numbers.
	ClientDeny []sysNR
	// The process-scope arm's (procScopeTest): Prlimit is prlimit64(2); TaskArg0 the scheduling calls that
	// name one task in args[0] (sched_setparam, sched_setscheduler, sched_setaffinity, sched_setattr);
	// Setpriority and IoprioSet the two that take (which, who) in args[0] and args[1].
	Prlimit                uint32
	TaskArg0               []sysNR
	Setpriority, IoprioSet uint32
	// Unshare, Clone and Setns are the namespace arm's (namespaceTest): unshare(2) and clone(2) take their
	// flags in args[0] on both architectures.
	Unshare, Clone, Setns uint32
	Memfd                 uint32 // memfd_create(2), for the memfd arm (SEMANTICS §4); flags in args[1]
}

// enosysSet is the part of R10's set that is the same on both architectures. clone3 is in it because its
// flags are in user memory the filter cannot read, and CLONE_INTO_CGROUP is checked by the kernel with
// inode_permission, which Landlock does not hook: allowed, it let a process of the run start a child in any
// cgroup its uid may write, at tier 1 every leaf of user@<uid>.service, outside the run's pids.max,
// memory.max and kill, alive past run_end (R10). glibc and Go fall back to clone(2), which
// has no cgroup argument, as they do under Docker's default profile.
var enosysSet = []sysNR{{"io_uring_setup", 425}, {"io_uring_enter", 426}, {"io_uring_register", 427}, {"openat2", 437},
	{"clone3", 435}}

// landlockSet is the Landlock syscalls, at the same numbers on both architectures: a run whose held opens the open
// deputy completes answers them ENOSYS (filterOpts.heldOpens), so no process of the run makes a Landlock domain of its
// own beneath the run's, which the deputy, a process of the run's domain, does not share (ADR 0041 D2).
var landlockSet = []sysNR{{"landlock_create_ruleset", 444}, {"landlock_add_rule", 445}, {"landlock_restrict_self", 446}}

// isIOUring reports whether s is one of the three io_uring syscalls of enosysSet.
func isIOUring(s sysNR) bool {
	switch s.Name {
	case "io_uring_setup", "io_uring_enter", "io_uring_register":
		return true
	}
	return false
}

// uselibX86 is uselib(2), x86_64's only: it opens a file by a pathname the kernel reads itself, with no open-family
// number, so no arm of this filter sees it and the supervisor could neither record nor hold the read it makes (a
// held read's floor, ADR 0069 D2). ENOSYS at every tier, as openat2 and open_by_handle_at are answered (R10); arm64
// has no such syscall, and kernels built without CONFIG_USELIB answer it ENOSYS already.
var uselibX86 = sysNR{"uselib", 134}

// withOpenByHandle is enosysSet plus open_by_handle_at, whose number differs per architecture. It opens a
// file from a struct file_handle in user memory rather than from a path, so no arm of this filter can
// see its flags and the supervisor has no path to record: a write-open through it, or any open under
// record: full, left no line in any tier. Linux 6.12 lets an unprivileged caller use it for some
// handles, and below that it takes CAP_DAC_READ_SEARCH, which a tier-2 agent can reach through a
// set-uid binary (runtime-launch R4 skips no_new_privs there). ENOSYS, like openat2, keeps R10's promise
// that no open reaches the kernel through a number the supervisor has no entry for; name_to_handle_at
// opens nothing and stays allowed.
func withOpenByHandle(nr uint32) []sysNR {
	return append(append([]sysNR(nil), enosysSet...), sysNR{"open_by_handle_at", nr})
}

var (
	x86Table = archTable{
		Arch:   ArchX86_64,
		X32:    true,
		ENOSYS: append(withOpenByHandle(304), uselibX86),
		Notify: []sysNR{
			{"connect", 42}, {"sendmsg", 46}, {"sendmmsg", 307}, {"execve", 59}, {"execveat", 322},
			{"creat", 85}, {"unlink", 87}, {"unlinkat", 263}, {"rename", 82}, {"renameat", 264},
			{"renameat2", 316}, {"mkdir", 83}, {"mkdirat", 258}, {"rmdir", 84}, {"symlink", 88}, {"symlinkat", 266},
			{"link", 86}, {"linkat", 265}, {"mknod", 133}, {"mknodat", 259}, {"mount", 165}, {"umount2", 166}, {"pivot_root", 155},
			{"move_mount", 429},
			// The kernel keyring: a non-namespaced, same-uid credential store no fs or net rule can see
			// and no tier's hooks reach (SEMANTICS §1). Notified so the supervisor decides them, as Docker's and
			// firejail's default seccomp profiles block them.
			{"add_key", 248}, {"request_key", 249}, {"keyctl", 250},
			// System V IPC: a namespace the host shares, reached by guessable ids, which no fs or net rule
			// can see (R11). Notified so the supervisor decides them, as the keyring is;
			// shmdt is not, since it takes an address, and an exec leaves no segment attached.
			{"shmget", 29}, {"shmat", 30}, {"shmctl", 31}, {"semget", 64}, {"semop", 65}, {"semctl", 66},
			{"msgget", 68}, {"msgsnd", 69}, {"msgrcv", 70}, {"msgctl", 71}, {"semtimedop", 220},
		},
		SendTo:   44,
		Open:     2,
		OpenAt:   257,
		Ioctl:    16,
		Truncate: 76,
		Chmod:    []sysNR{{"chmod", 90}, {"fchmod", 91}, {"fchmodat", 268}, {"fchmodat2", 452}},
		Attr: []sysNR{{"setxattr", 188}, {"lsetxattr", 189}, {"fsetxattr", 190}, {"removexattr", 197},
			{"lremovexattr", 198}, {"fremovexattr", 199}, {"setxattrat", 463}, {"removexattrat", 466},
			{"chown", 92}, {"fchown", 93}, {"lchown", 94}, {"fchownat", 260}},
		Socket: 41,
		Pair:   53,
		Bind:   49, Listen: 50, Setsockopt: 54,
		Frames:     []sysNR{{"sendfile", 40}, {"splice", 275}},
		Watch:      []sysNR{{"inotify_add_watch", 254}, {"fanotify_mark", 301}},
		ClientDeny: []sysNR{{"recvmsg", 47}, {"recvmmsg", 299}, {"pidfd_getfd", 438}, {"listen", 50}, {"accept", 43}, {"accept4", 288}},
		Memfd:      319,
		Signal: []sysNR{{"kill", 62}, {"tkill", 200}, {"tgkill", 234}, {"rt_sigqueueinfo", 129},
			{"rt_tgsigqueueinfo", 297}},
		PidfdSignal: 424,
		Fcntl:       72,
		Unshare:     272, Clone: 56, Setns: 308,
		RootDeny: []sysNR{{"bpf", 321}, {"init_module", 175}, {"finit_module", 313}, {"delete_module", 176},
			{"kexec_load", 246}, {"kexec_file_load", 320}},
		Prlimit: 302,
		TaskArg0: []sysNR{{"sched_setparam", 142}, {"sched_setscheduler", 144}, {"sched_setaffinity", 203},
			{"sched_setattr", 314}},
		Setpriority: 141, IoprioSet: 251,
	}
	arm64Table = archTable{
		Arch:   ArchARM64,
		X32:    false,
		ENOSYS: withOpenByHandle(265),
		Notify: []sysNR{
			{"connect", 203}, {"sendmsg", 211}, {"sendmmsg", 269}, {"execve", 221}, {"execveat", 281},
			{"unlinkat", 35}, {"renameat", 38}, {"renameat2", 276}, {"mkdirat", 34}, {"symlinkat", 36},
			{"linkat", 37}, {"mknodat", 33}, {"mount", 40}, {"umount2", 39}, {"pivot_root", 41}, {"move_mount", 429},
			// The kernel keyring (SEMANTICS §1), the same three syscalls as x86-64 at the arm64 generic numbers.
			{"add_key", 217}, {"request_key", 218}, {"keyctl", 219},
			// System V IPC (R11), at the arm64 generic numbers.
			{"msgget", 186}, {"msgctl", 187}, {"msgrcv", 188}, {"msgsnd", 189}, {"semget", 190}, {"semctl", 191},
			{"semtimedop", 192}, {"semop", 193}, {"shmget", 194}, {"shmctl", 195}, {"shmat", 196},
		},
		SendTo:   206,
		Open:     noSyscall,
		OpenAt:   56,
		Ioctl:    29,
		Truncate: 45,
		Chmod:    []sysNR{{"fchmod", 52}, {"fchmodat", 53}, {"fchmodat2", 452}},
		Attr: []sysNR{{"setxattr", 5}, {"lsetxattr", 6}, {"fsetxattr", 7}, {"removexattr", 14},
			{"lremovexattr", 15}, {"fremovexattr", 16}, {"setxattrat", 463}, {"removexattrat", 466},
			{"fchownat", 54}, {"fchown", 55}},
		Socket: 198,
		Pair:   199,
		Bind:   200, Listen: 201, Setsockopt: 208,
		Frames:     []sysNR{{"sendfile", 71}, {"splice", 76}},
		Watch:      []sysNR{{"inotify_add_watch", 27}, {"fanotify_mark", 263}},
		ClientDeny: []sysNR{{"recvmsg", 212}, {"recvmmsg", 243}, {"pidfd_getfd", 438}, {"listen", 201}, {"accept", 202}, {"accept4", 242}},
		Memfd:      279,
		Signal: []sysNR{{"kill", 129}, {"tkill", 130}, {"tgkill", 131}, {"rt_sigqueueinfo", 138},
			{"rt_tgsigqueueinfo", 240}},
		PidfdSignal: 424,
		Fcntl:       25,
		Unshare:     97, Clone: 220, Setns: 268,
		RootDeny: []sysNR{{"bpf", 280}, {"init_module", 105}, {"finit_module", 273}, {"delete_module", 106},
			{"kexec_load", 104}, {"kexec_file_load", 294}},
		Prlimit: 261,
		TaskArg0: []sysNR{{"sched_setparam", 118}, {"sched_setscheduler", 119}, {"sched_setaffinity", 122},
			{"sched_setattr", 274}},
		Setpriority: 140, IoprioSet: 30,
	}
)

// tableFor returns the syscall table of arch.
func tableFor(arch Arch) (archTable, error) {
	switch arch {
	case ArchX86_64:
		return x86Table, nil
	case ArchARM64:
		return arm64Table, nil
	}
	return archTable{}, fmt.Errorf("%w: no seccomp table for %s", ErrRulesetBuild, arch)
}

// BuildFilter is buildFilter for a kernel whose Landlock can deny truncation itself (ABI ≥ 3), with no
// memfd, socket, signal, process-scope or root-tier arm. The one production caller is enforce.Observe, which
// wants exactly this form: an observe run applies no Landlock ruleset and refuses nothing, so the truncation
// arms have nothing to stand in for and the memfd arm — a creation-time refusal — has nothing it may refuse.
// It carries R11c's bind arm, so that an observe run's lines name the run's own unix sockets as an enforcing
// run would decide them (supervisor R11a) rather than as foreign; the supervisor continues every bind there. frames
// installs R11d's pending-frame arms, which the caller sets where the run's contract decides datagrams
// (agent.RuleTable.DecidesDatagrams), as Prepare does: the observe run's supervisor applies its pending-frame
// decisions there (supervisor R13, R30), so without the arms its record would hold the addressed sends with MSG_MORE
// an enforcing run refuses and miss the unaddressed ones, the cork, sendfile and splice.
// An enforcing run goes through Prepare, which assembles the filterOpts its contract and probed kernel ask for.
func BuildFilter(arch Arch, full, frames bool) ([]bpf.Instruction, error) {
	return buildFilter(arch, filterOpts{full: full, abi: minTruncateABI, unixBinds: true, frames: frames})
}

// filterOpts is everything a run's filter varies by.
type filterOpts struct {
	builtin bool // ADR 0113: terminal relay, immutable socket boundary

	full     bool // record: full notifies every open (R16)
	gateRead bool // a read gate needs notifications even under summary/off
	// askRead notifies every open, as record: full does: fs.ask_read holds a read-open for a person, and a classic BPF
	// filter sees the path as a pointer, so the supervisor has to be told of every read to find the ones it holds
	// (POC 2026-10-06, SEMANTICS §6). A run that holds its reads (fs.reads, ADR 0069 D2) sets it for the same reason:
	// the open deputy completes every read-capable open. The supervisor writes no line for a read it neither holds nor
	// refuses, or holds only as a read, unless the record mode keeps reads.
	askRead   bool
	gateWrite bool // a write gate scores a mode or attribute change: the chmod and Attr families are notified under summary/off (R11)
	// watches installs the watch arm (R11e): inotify_add_watch, fanotify_mark and fcntl's F_NOTIFY are notified, for
	// the supervisor to refuse a watch whose object the run withholds a read of (supervisor R36). Every enforcing run
	// sets it (Prepare); an observe run's filter (BuildFilter) does not, since its supervisor would continue every watch.
	watches bool
	// sourceRoute installs the source-route arm (sourceRouteTest, R11b): a run whose contract has a net: section or
	// whose gate scores net actions (ADR 0041 D6, GAPS C34).
	sourceRoute bool
	// frames installs R11d's pending-frame arms (frameTests): a run whose contract decides datagrams
	// (agent.RuleTable.DecidesDatagrams), where a UDP frame left pending would carry a later datagram's bytes to
	// another destination than its line names (supervisor R13).
	frames bool
	abi    int       // the probed Landlock ABI (R2's truncation rows)
	memfd  MemfdArm  // SEMANTICS §4
	socket SocketArm // ADR 0018
	// signals installs the signal-scope arm (signalScopeTest): an enforcing run below minSignalScopeABI.
	signals bool
	// rootTier installs the root-tier arm (rootTierDenyTest): a run at tier cgroup or bpflsm.
	rootTier  bool
	strictNet bool
	// listenControl notifies bind(2) and listen(2): every run with a net: section, a listener policy or none. With
	// none, a listen() with no bind takes an ephemeral port through the kernel's autobind, which never reaches
	// security_socket_bind, so the BIND_TCP such a contract withholds cannot refuse it and the supervisor does (R6).
	listenControl, listenersAllowed, ingress bool
	// unixBinds notifies bind(2) in the unix-only state too, where listenControl is off (R11c): the supervisor records
	// the socket each pathname unix bind of the run names, which is what its implicit admit of a socket under a write
	// entry is held to (supervisor R11a), and continues the bind. listenControl notifies bind already.
	unixBinds bool
	// ioUring leaves io_uring_setup, io_uring_enter and io_uring_register out of the ENOSYS arm (R10): a contract
	// that declares io_uring: true, run where the kernel decision plane decides every submission (Run.IOUring;
	// ADR 0018 (5)). They are then allowed, never notified: the supervisor has nothing to read of a ring.
	ioUring bool
	// procScope installs the process-scope arm (procScopeTest): every enforcing run, at every ABI, since no
	// Landlock scope covers these calls.
	procScope bool
	// heldOpens answers the Landlock syscalls ENOSYS (landlockSet): a run whose contract has the open deputy complete
	// its held opens (gate.completion: held, RuleTable.NeedsOpenDeputy). The deputy makes every held open in the run's
	// own domain; a process that made one of its own beneath it would not be held to it for those opens.
	heldOpens bool
	// plane is what the run's decision plane decides in place of a notification (planeSkips): the syscalls, by
	// their table names, the filter no longer notifies, and writeOpens and truncate for the open family's write
	// arm and truncate(2)'s notification (enforce-plane R22, R27; TIER3-PLAN T16). The zero value notifies all.
	plane planeSkip
}

// planeSkip is the part of the notify set a loaded decision plane decides in the kernel (planeSkips).
type planeSkip struct {
	names      map[string]bool // Notify entries by sysNR.Name
	writeOpens bool            // the open family's write arm (writeFlagTest) and creat
	truncate   bool            // truncate(2)'s notification from ABI 3
}

// any reports whether the skip leaves out anything.
func (p planeSkip) any() bool { return len(p.names) > 0 || p.writeOpens || p.truncate }

// Plane hook names, as bpf.PlaneHook.Name spells them (internal/bpf plane.go): this package does not import the
// objects' bindings, so the names are the contract between the two.
const (
	HookFileOpen     = "file_open"
	HookPathUnlink   = "path_unlink"
	HookPathRmdir    = "path_rmdir"
	HookPathRename   = "path_rename"
	HookPathLink     = "path_link"
	HookPathMknod    = "path_mknod"
	HookPathMkdir    = "path_mkdir"
	HookPathSymlink  = "path_symlink"
	HookPathTruncate = "path_truncate"
)

// planeDecided maps each fs mutation of the notify tables to the plane hooks that decide every form of it
// (TIER3-PLAN §2). unlinkat removes a directory under AT_REMOVEDIR, so it needs path_rmdir too; linkat's
// AT_EMPTY_PATH form (an O_TMPFILE linked in by descriptor) goes through security_path_link like any link.
var planeDecided = map[string][]string{
	"unlink": {HookPathUnlink}, "unlinkat": {HookPathUnlink, HookPathRmdir}, "rmdir": {HookPathRmdir},
	"rename": {HookPathRename}, "renameat": {HookPathRename}, "renameat2": {HookPathRename},
	"link": {HookPathLink}, "linkat": {HookPathLink},
	"mkdir": {HookPathMkdir}, "mkdirat": {HookPathMkdir},
	"mknod": {HookPathMknod}, "mknodat": {HookPathMknod},
	"symlink": {HookPathSymlink}, "symlinkat": {HookPathSymlink},
	// creat is open(O_CREAT|O_WRONLY|O_TRUNC): a write-open, below.
	"creat": {HookFileOpen, HookPathMknod},
}

// planeWriteOpenHooks decide a write-open: file_open decides write, deny_write and O_TRUNC on the object the open
// resolved, and path_mknod decides an O_CREAT create before the file exists (may_o_create), so a refused create
// leaves no file behind (TIER3-PLAN T13's acceptance). Without path_mknod a refused create would be refused at
// file_open only after the file was made, so the write arm stays notified.
var planeWriteOpenHooks = []string{HookFileOpen, HookPathMknod}

// planeSkips is the notification set a run's loaded plane hooks decide in the kernel (enforce-plane R27): each
// fs mutation whose every form a loaded hook decides, the open family's write arm when file_open and path_mknod
// are loaded, and truncate(2) when path_truncate is. Under record: full the open family stays whole (its
// notifications are the record of reads too, and a full filter notifies every open), so creat and the write arm
// are kept and only the other mutations are left out: the kernel recorder names each by its path on its own
// (enforce-plane §2.15). It is empty — every notification kept, fail closed — for a contract with fs ask entries
// (P1: an ask is answered by the supervisor, ADR 0024 (14)). hooks is the set the plane loaded and attached for
// this run's mode, never what a mode could load: file_truncate, absent below 6.2, and the step B hooks before they
// are built are simply not in it.
func planeSkips(hooks map[string]bool, full, ask bool) planeSkip {
	if len(hooks) == 0 || ask {
		return planeSkip{}
	}
	all := func(names []string) bool {
		for _, n := range names {
			if !hooks[n] {
				return false
			}
		}
		return true
	}
	var p planeSkip
	for name, need := range planeDecided {
		if full && name == "creat" {
			continue // an open: under record: full the open family stays whole
		}
		if all(need) {
			if p.names == nil {
				p.names = map[string]bool{}
			}
			p.names[name] = true
		}
	}
	p.writeOpens = !full && all(planeWriteOpenHooks)
	p.truncate = hooks[HookPathTruncate]
	return p
}

// buildFilter assembles the tier-1 seccomp program for arch (R9–R13, R16) as x/net/bpf instructions:
// arch guard, then (x86_64 only) the x32 bit check, then ENOSYS for io_uring_*, openat2 and
// open_by_handle_at, then the
// notify set — connect, sendmsg, sendmmsg, execve, execveat, creat, unlink*, rename*, mkdir*, x86-64's
// rmdir (arm64 removes a directory through unlinkat alone), symlink*, link*, mknod*, and the mount family the
// domain refuses (mount, umount2, pivot_root, move_mount, which the supervisor refuses and records as
// landlock-topology, R11) unconditionally; sendto when its address is non-NULL (both halves of the
// pointer tested);
// open/openat when flags & WriteFlagMask != 0 via BPF_JSET, or unconditionally under record: full —
// and ALLOW for everything else. The guards precede every syscall-number comparison (I6). A run whose decision
// plane decides some of those fs notifications in the kernel leaves them out (filterOpts.plane, planeSkips).
//
// Two arms are errno returns rather than notifications: the terminal-injection ioctls (retEPERM) and
// socket(2) with IPPROTO_MPTCP (E30). The decision needs only the scalar registers the filter already sees,
// so it is race-free with no round trip; it holds under an observe run, whose supervisor continues every
// notification (supervisor R30); and it holds when no listener or supervisor is left to answer. (A notification the
// supervisor has no handler for is answered ENOSYS, ADR 0018 (3), which TestEveryNotifiedSyscallHasAHandler
// checks — so that is not the reason.) A third, the truncation pair, is emitted only when abi cannot handle
// LANDLOCK_ACCESS_FS_TRUNCATE (R2's ABI-3 row).
//
// The memfd_create arm (filterOpts.memfd) is an errno return for the same reasons as the ioctl and MPTCP
// arms: its flags are a scalar argument, and an executable anonymous image is exactly what tiers 1 and 2
// cannot govern after the fact without losing a descriptor-table race (SEMANTICS §4). Either closing form refuses the *creation*
// of an exec-capable memfd, so no such image ever exists inside the run: MemfdSealed where the kernel honours
// MFD_NOEXEC_SEAL, a flag to filter on, and MemfdRefused on a kernel without it.
//
// The socket arm (filterOpts.socket, ADR 0018): under a net: section socket(2) and
// socketpair(2) are admitted by an allowlist decided on their scalar arguments, and every other triple is
// notified to a supervisor handler that can only refuse.
//
// The watch arm (filterOpts.watches, R11e) notifies inotify_add_watch(2), fanotify_mark(2) and fcntl(2)'s F_NOTIFY
// (dnotify) in every enforcing run: none is a hook of Landlock or of a decision plane, so the supervisor refuses a
// watch whose object the run withholds a read of itself (supervisor R36; GAPS A10).
//
// A build with -tags tegotesthooks can leave named syscalls out of the notify arm and the root-tier arm
// (filterTestOmit, TEGO_TEST_FILTER_OMIT), so that a root test reaches what those arms answer first in a product
// run: the decision plane's bpf and key_permission hooks (enforce-plane §2.20). A product build omits nothing.
func buildFilter(arch Arch, o filterOpts) ([]bpf.Instruction, error) {
	builtin := o.builtin
	full, gateRead, gateWrite, abi, m, sa, plane := o.full, o.gateRead || o.askRead, o.gateWrite, o.abi, o.memfd, o.socket, o.plane
	t, err := tableFor(arch)
	if err != nil {
		return nil, err
	}
	prog := []bpf.Instruction{
		bpf.LoadAbsolute{Off: offArch, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(t.Arch), SkipTrue: 1},
		bpf.RetConstant{Val: retENOSYS},
		bpf.LoadAbsolute{Off: offNR, Size: 4},
	}
	if t.X32 {
		prog = append(prog,
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: x32Bit, SkipFalse: 1},
			bpf.RetConstant{Val: retENOSYS},
		)
	}
	for _, s := range t.ENOSYS {
		if o.ioUring && isIOUring(s) {
			continue
		}
		prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: s.NR, SkipFalse: 1}, bpf.RetConstant{Val: retENOSYS})
	}
	if o.heldOpens {
		// ENOSYS, as R10 answers openat2: Landlock is not available to a process of this run, which a library that
		// probes it (landlock_create_ruleset's version query) reads as a kernel without it.
		for _, s := range landlockSet {
			prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: s.NR, SkipFalse: 1}, bpf.RetConstant{Val: retENOSYS})
		}
	}
	if o.strictNet {
		for _, s := range t.ClientDeny {
			if o.listenersAllowed && (s.Name == "listen" || s.Name == "accept" || s.Name == "accept4") {
				continue
			}
			prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: s.NR, SkipFalse: 1}, bpf.RetConstant{Val: retENOSYS})
		}
	}
	if o.listenControl || o.unixBinds || o.builtin {
		prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: t.Bind, SkipFalse: 1}, bpf.RetConstant{Val: retNotify})
	}
	if o.listenControl {
		prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: t.Listen, SkipFalse: 1}, bpf.RetConstant{Val: retNotify})
	}
	if o.ingress {
		prog = append(prog, noPortBindTest(t.Setsockopt)...)
	}
	if o.sourceRoute {
		prog = append(prog, sourceRouteTest(t.Setsockopt)...)
	}
	if o.frames {
		prog = append(prog, frameTests(t)...)
	}
	for _, s := range t.Notify {
		if o.plane.names[s.Name] {
			continue // decided by the run's plane in the kernel, and recorded there (planeSkips)
		}
		if filterTestOmit(s.Name) {
			continue // a test build's seam (filter_hooks.go); a product build omits nothing
		}
		prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: s.NR, SkipFalse: 1}, bpf.RetConstant{Val: retNotify})
	}
	if o.builtin {
		prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: 438, SkipFalse: 1}, bpf.RetConstant{Val: retNotify})
		prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: t.Ioctl, SkipFalse: 4}, bpf.LoadAbsolute{Off: offArg0 + argSize, Size: 4}, bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.TIOCGPTPEER, SkipFalse: 1}, bpf.RetConstant{Val: retNotify}, bpf.LoadAbsolute{Off: offNR, Size: 4})
	}
	prog = append(prog, terminalInjectionTest(t.Ioctl)...)
	prog = append(prog, mptcpSocketTest(t.Socket)...)
	if sa.Restricted {
		prog = append(prog, socketAllowTest(t.Socket, t.Pair, sa.ICMP)...)
		prog = append(prog, tcpULPTest(t.Setsockopt)...)
	}
	if o.signals {
		prog = append(prog, signalScopeTest(t)...)
	}
	if o.procScope {
		prog = append(prog, procScopeTest(t)...)
	}
	// Every filter: an observe run's supervisor continues what it notifies (R30), so the arm refuses only where
	// something is enforced.
	prog = append(prog, namespaceTest(t)...)
	if o.rootTier {
		for _, s := range t.RootDeny {
			if filterTestOmit(s.Name) {
				continue // a test build's seam, as in the notify arm above
			}
			prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: s.NR, SkipFalse: 1}, bpf.RetConstant{Val: retEPERM})
		}
	}
	switch m {
	case MemfdSealed:
		prog = append(prog, memfdSealTest(t.Memfd)...)
	case MemfdRefused:
		prog = append(prog, memfdRefuseTest(t.Memfd)...)
	}
	if abi < minTruncateABI {
		prog = append(prog, truncateTest(t.Truncate)...)
	} else if t.Truncate != noSyscall && !o.plane.truncate {
		// From ABI 3 Landlock's TRUNCATE right decides truncate(2); it is notified so the supervisor records
		// it (and refuses one that reaches a deny_write target, supervisor R15c), as an O_TRUNC open is.
		prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: t.Truncate, SkipFalse: 1}, bpf.RetConstant{Val: retNotify})
	}
	if full || gateWrite {
		// record: full records a mode change (CAPABILITIES "record reads, mmap, chmod"); no fs rule below tier
		// 3 refuses one. An fs.write gate scores one as a write and refuses it above its threshold (supervisor
		// gateFS), so it keeps the notification under summary/off too: gate.md's enabled action kinds retain
		// their notifications, and the verdict does not depend on the record level.
		for _, s := range t.Chmod {
			prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: s.NR, SkipFalse: 1}, bpf.RetConstant{Val: retNotify})
		}
	}
	if gateWrite {
		// An ACL set through setxattr rewrites the mode bits a chmod would, and a chown hands the group bits to
		// another group: the write gate scores both families as writes too (supervisor recordAttr), or a gate that
		// refused `chmod 755 ../outside/f` let `setfacl -m u::rwx,g::r-x,o::r-x ../outside/f` make the same change
		// with no score and no line. Every attribute name is scored, never just the ACL ones: the supervisor's copy
		// of the name is one a sibling thread can rewrite before the kernel reads it.
		for _, s := range t.Attr {
			prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: s.NR, SkipFalse: 1}, bpf.RetConstant{Val: retNotify})
		}
	}
	if o.watches {
		// R11e: a watch names its object by a pathname in the agent's memory (or, for fanotify_mark and dnotify, by a
		// descriptor), so the filter cannot decide it and notifies every call; the supervisor refuses one whose object
		// the run withholds a read of and continues the rest (supervisor R36).
		for _, s := range t.Watch {
			prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: s.NR, SkipFalse: 1}, bpf.RetConstant{Val: retNotify})
		}
		prog = append(prog, dnotifyTest(t.Fcntl)...)
	}
	prog = append(prog, sendToTest(t.SendTo, o.frames)...)
	for _, o := range []struct {
		nr  uint32
		arg int
	}{{t.Open, 1}, {t.OpenAt, 2}} {
		if o.nr == noSyscall {
			continue
		}
		// Before the notify arm, so it wins under record: full too — a notified open is answered
		// CONTINUE by the supervisor's record-only handler and would truncate anyway (R2, E31).
		if abi < minTruncateABI {
			prog = append(prog, readOnlyTruncateTest(o.nr, o.arg)...)
		}
		if builtin {
			prog = append(prog, flagNotifyTest(o.nr, o.arg, unix.O_NOCTTY)...)
		}
		if full || gateRead {
			prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: o.nr, SkipFalse: 1}, bpf.RetConstant{Val: retNotify})
			continue
		}
		if plane.writeOpens {
			continue // file_open and path_mknod decide it (planeWriteOpenHooks)
		}
		prog = append(prog, writeFlagTest(o.nr, o.arg)...)
	}
	return append(prog, bpf.RetConstant{Val: retAllow}), nil
}

// terminalInjectionTest refuses ioctl(TIOCSTI) and ioctl(TIOCLINUX) with EPERM.
//
// An agent inherits the launcher's stdio, which on an interactive run is the user's own terminal. Either
// ioctl writes into that terminal's input queue, and the shell reading it runs whatever was written, as
// the user, outside every boundary this process installs. Landlock has no view of ioctl and the
// supervisor's filesystem answers are advisory, so this filter is tier 1's only opportunity to stop it.
//
// The request number is a scalar in args[1], so classic BPF can compare it exactly — unlike a pointer
// argument, where the target could change the memory after the check (R11's reason for notifying rather
// than deciding). EPERM rather than ENOSYS because ioctl plainly exists; a program that probes for this
// should learn it is refused, not that the syscall is missing.
//
// Linux 6.2 added dev.tty.legacy_tiocsti, default 0, which disables TIOCSTI kernel-wide. This does not
// rely on it: the floor is 5.14, the sysctl is writable, and TIOCLINUX is not covered by it at all.
func terminalInjectionTest(nr uint32) []bpf.Instruction {
	if nr == noSyscall {
		return nil
	}
	return []bpf.Instruction{
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipFalse: 5},
		bpf.LoadAbsolute{Off: offArg(1), Size: 4}, // the request is an unsigned long; both values fit 32 bits
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ioctlTIOCSTI, SkipTrue: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ioctlTIOCLINUX, SkipFalse: 1},
		bpf.RetConstant{Val: retEPERM},
		bpf.LoadAbsolute{Off: offNR, Size: 4},
	}
}

// IP_BIND_ADDRESS_NO_PORT defers port allocation past the post-bind hook. The
// option's register values are immutable, so refuse it before an ingress run
// can create a socket without its verified listener attribution.
func noPortBindTest(nr uint32) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipFalse: 6},
		bpf.LoadAbsolute{Off: offArg(1), Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipFalse: 3},
		bpf.LoadAbsolute{Off: offArg(2), Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 24, SkipFalse: 1},
		bpf.RetConstant{Val: retEPERM},
		bpf.LoadAbsolute{Off: offNR, Size: 4},
	}
}

// Socket options that give an IP socket a source route: IPv4's IP_OPTIONS (an LSRR or SSRR option, which an
// unprivileged task may set before Linux 7.1 and its stable backports, and a task with CAP_NET_RAW on any kernel),
// and IPv6's sticky routing header, set as IPV6_RTHDR or inside an
// IPV6_2292PKTOPTIONS block. IPV6_2292RTHDR is the RFC 2292 name of the same header; Linux reads it as a request
// to receive one, but the arm refuses it with the others rather than rest on that reading.
const (
	solIP              = 0  // SOL_IP, IPPROTO_IP
	solIPv6            = 41 // SOL_IPV6, IPPROTO_IPV6
	ipOptions          = 4  // IP_OPTIONS
	ipv6RTHdr          = 57 // IPV6_RTHDR
	ipv62292RTHdr      = 5  // IPV6_2292RTHDR
	ipv62292PktOptions = 6  // IPV6_2292PKTOPTIONS
)

// sourceRouteTest refuses, with EPERM, a setsockopt(2) that would give a socket a source route, in a run whose
// contract has a net: section or whose gate scores net actions (R11b; ADR 0041 D6; GAPS C34; supervisor R9, R13b). A
// source route sends a connect's or a datagram's first hop to an address in the route, not to the destination the
// contract admitted or the gate scored, and no decision sees it: the supervisor and the root tiers' connect4/6 and
// sendmsg4/6 programs read the destination alone. The supervisor performs an admitted IP connect, Fast-Open send or
// relayed datagram on a duplicate of the agent's own socket and reads the socket's options first (sourceRouted, rule
// relay-source-routed), but that read is a snapshot: the socket is shared with every thread of the agent, and a
// sibling's setsockopt between the read and the relayed call would route it elsewhere; and a datagram the supervisor
// continues is sent by the kernel with whatever options the socket holds by then. Refusing the setsockopt itself
// closes both. The level and option are scalars in args[1] and args[2], so the decision is race-free, as
// noPortBindTest's is; both are ints, so the low 32 bits are what the kernel reads. The refusal leaves no ledger
// line, like the ioctl and MPTCP arms. A gated run has no io_uring (gate_config: a gate requires io_uring disabled);
// a run under io_uring: true can set an option through a ring (SOCKET_URING_OP_SETSOCKOPT), which no seccomp filter
// sees (SEMANTICS §5).
func sourceRouteTest(nr uint32) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipFalse: 11},
		bpf.LoadAbsolute{Off: offArg(1), Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: solIP, SkipFalse: 3},
		bpf.LoadAbsolute{Off: offArg(2), Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ipOptions, SkipTrue: 6},
		bpf.Jump{Skip: 6},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: solIPv6, SkipFalse: 5},
		bpf.LoadAbsolute{Off: offArg(2), Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ipv6RTHdr, SkipTrue: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ipv62292RTHdr, SkipTrue: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ipv62292PktOptions, SkipFalse: 1},
		bpf.RetConstant{Val: retEPERM},
		bpf.LoadAbsolute{Off: offNR, Size: 4},
	}
}

// cloneNamespaceFlags are the namespace flags the namespace arm refuses: a new mount namespace, and a new user
// namespace, which is what gives an unprivileged process the CAP_SYS_ADMIN a new mount namespace needs.
const cloneNamespaceFlags = unix.CLONE_NEWNS | unix.CLONE_NEWUSER

// namespaceTest notifies unshare(2) and clone(2) when their flags ask for a new mount or user namespace, and
// every setns(2), and the supervisor refuses them (docs/p0/enforce-cgroup-observe.md E24). A Landlock domain refuses
// mount(2) but not the creation of a mount namespace: unshare(CLONE_NEWUSER|CLONE_NEWNS) copies the mount
// tree into new struct mounts that carry none of tier 2's FAN_MARK_MOUNT marks, and a deny_read that
// fanotify alone enforces (one nested in a write entry, a planted .env among them) was read there with no
// permission event, while the kernel record stamped the read refused. SEMANTICS §10 already said these tiers
// refuse `unshare -m`; now they do, and the refusal is recorded as landlock-topology. setns takes a
// namespace descriptor whose type 0 means any, so it is notified whatever its arguments. The flags are
// scalars in args[0], so the decision has no time-of-check gap; clone3, whose flags are in memory, is ENOSYS.
func namespaceTest(t archTable) []bpf.Instruction {
	var out []bpf.Instruction
	for _, nr := range []uint32{t.Unshare, t.Clone} {
		out = append(out,
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipFalse: 4},
			bpf.LoadAbsolute{Off: offArg(0), Size: 4}, // flags: CLONE_NEWNS and CLONE_NEWUSER are low bits
			bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: cloneNamespaceFlags, SkipFalse: 1},
			bpf.RetConstant{Val: retNotify},
			bpf.LoadAbsolute{Off: offNR, Size: 4},
		)
	}
	return append(out, bpf.JumpIf{Cond: bpf.JumpEqual, Val: t.Setns, SkipFalse: 1}, bpf.RetConstant{Val: retNotify})
}

// mptcpSocketTest refuses socket(_, _, IPPROTO_MPTCP) with EPROTONOSUPPORT.
//
// Landlock's network hooks check LANDLOCK_ACCESS_NET_* only for sk_is_tcp()/sk_is_udp() sockets and
// `else return 0` for everything else (security/landlock/net.c), so an MPTCP socket is outside the
// domain's net rules entirely. R6 grants CONNECT_TCP per declared port and BIND_TCP only on a port a
// net.listen entry declares, and with no net.listen the supervisor continues a bind (handleBind) for Landlock
// to decide, so without this arm an agent gets a socket bound to a port the contract never declared, with no
// line, and only the listen on it is refused. go-landlock hit exactly this
// (issue #50) when Go 1.24 made MPTCP the default for net.Listen, and its package documentation now
// carries the caveat permanently. connect(2) is less exposed — it is notified at every ABI and the
// supervisor is authoritative for it — but its in-kernel backstop has the same hole.
//
// EPROTONOSUPPORT, not EPERM as the ioctl guard uses: it is what a kernel built without CONFIG_MPTCP
// returns, so a runtime that probes for MPTCP falls back to a classic TCP socket, which both Landlock
// and the supervisor do see. Go falls back on *any* error from the MPTCP attempt (net/mptcpsock_linux.go),
// so the refusal costs a contract-legal dial nothing. A refusal is not a policy verdict here: the
// protocol is simply not offered inside the domain.
//
// The protocol is a scalar in args[2], so classic BPF can compare it exactly; no family test is needed
// because 262 is not a protocol number in any other address family, where the kernel refuses it anyway.
func mptcpSocketTest(nr uint32) []bpf.Instruction {
	if nr == noSyscall {
		return nil
	}
	return []bpf.Instruction{
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipFalse: 4},
		bpf.LoadAbsolute{Off: offArg(2), Size: 4}, // int protocol: low 32 bits
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ipprotoMPTCP, SkipFalse: 1},
		bpf.RetConstant{Val: retEPROTONOSUPPORT},
		bpf.LoadAbsolute{Off: offNR, Size: 4},
	}
}

// SOL_TCP and TCP_ULP: setsockopt(2)'s level and option that attach an upper-layer protocol to a TCP socket.
const (
	solTCP = 6  // SOL_TCP, IPPROTO_TCP
	tcpULP = 31 // TCP_ULP
)

// tcpULPTest notifies setsockopt(SOL_TCP, TCP_ULP) under a net: section (ADR 0018 (7)), and the supervisor refuses it
// (handleSetsockopt): a ULP is the one way a run turns a socket the allowlist admitted into one of another family. The
// smc module's "smc" ULP builds an AF_SMC socket in place of an unconnected TCP socket (smc_ulp_init, a kernel socket
// that never passes socket(2), inet_create's cgroup/sock_create or security_socket_create), so without this arm every
// tier said socket_families held while the run had an AF_SMC socket (reproduced on 6.17). The ULPs a
// kernel offers are whatever modules are loaded (tls, espintcp, smc), and none is something the network rules govern,
// so every name is refused, as ADR 0018's allowlist refuses every family it does not list; the name is in the agent's
// memory, where a decision on it would race a sibling thread, and the refusal needs none of it. The level and option
// are scalars in args[1] and args[2], ints whose low 32 bits are what the kernel reads, so the decision is race-free.
// io_uring's SOCKET_URING_OP_SETSOCKOPT (6.7+) never passes this filter; cgroup/setsockopt refuses it in the kernel
// wherever io_uring is admitted (enforce/cgroup, ADR 0018 (7)).
func tcpULPTest(nr uint32) []bpf.Instruction {
	if nr == noSyscall {
		return nil
	}
	return []bpf.Instruction{
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipFalse: 6},
		bpf.LoadAbsolute{Off: offArg(1), Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: solTCP, SkipFalse: 3},
		bpf.LoadAbsolute{Off: offArg(2), Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: tcpULP, SkipFalse: 1},
		bpf.RetConstant{Val: retNotify},
		bpf.LoadAbsolute{Off: offNR, Size: 4},
	}
}

// socketAllowTest admits socket(2) and socketpair(2) by an allowlist of what the network rules govern
// (ADR 0018), and notifies every other triple to the supervisor, whose handler refuses and records it.
//
// Landlock's net hooks act only on sk_is_tcp()/sk_is_udp() sockets (security/landlock/net.c), and the cgroup
// connect programs run only under a protocol's pre_connect, so an SCTP socket reached any address through
// setsockopt(SCTP_SOCKOPT_CONNECTX) and a peerless send(), which neither the connect notification nor the
// addressed-sendto arm sees, and left no ledger line, reproduced on 6.17. UDP-Lite
// and every family outside the net rules (AF_VSOCK, AF_TIPC, AF_RDS, AF_SMC, AF_PACKET) were as open. An
// allowlist stays closed against the next such protocol, a blocklist does not.
//
// socket admits AF_UNIX (any type), AF_NETLINK as NETLINK_ROUTE alone (getaddrinfo's and getifaddrs's route query, ADR
// 0128) and AF_INET or AF_INET6 as a stream socket with protocol 0 or TCP, a datagram socket with protocol 0 or UDP,
// and, when the contract names an ICMP destination, a datagram socket with ICMP or ICMPv6 (a ping socket). No other
// netlink protocol is admitted: an unaddressed send(2) or write(2) reaches the kernel with no notification, so a
// generic, sock_diag or audit socket refused only at its addressed sends was still a way to the kernel. socketpair
// admits AF_UNIX only; TIPC implements it too. Every argument is a scalar in a register, so the decision has no
// time-of-check gap. The MPTCP arm ahead of this one keeps answering IPPROTO_MPTCP with EPROTONOSUPPORT and no
// line: runtimes probe it and fall back to TCP, which is not a policy event.
func socketAllowTest(socketNR, pairNR uint32, icmp bool) []bpf.Instruction {
	allowIf := func(v uint32) []bpf.Instruction {
		return []bpf.Instruction{bpf.JumpIf{Cond: bpf.JumpEqual, Val: v, SkipFalse: 1}, bpf.RetConstant{Val: retAllow}}
	}
	var dgram []bpf.Instruction
	dgram = append(dgram, bpf.LoadAbsolute{Off: offArg(2), Size: 4})
	dgram = append(dgram, allowIf(0)...)
	dgram = append(dgram, allowIf(ipprotoUDP)...)
	if icmp {
		dgram = append(dgram, allowIf(ipprotoICMP)...)
		dgram = append(dgram, allowIf(ipprotoICMPv6)...)
	}
	dgram = append(dgram, bpf.RetConstant{Val: retNotify})
	stream := []bpf.Instruction{bpf.LoadAbsolute{Off: offArg(2), Size: 4}}
	stream = append(stream, allowIf(0)...)
	stream = append(stream, allowIf(ipprotoTCP)...)
	stream = append(stream, bpf.RetConstant{Val: retNotify})
	// A holds the masked type from here to the dgram test: the stream block only loads when it is taken.
	inet := []bpf.Instruction{
		bpf.LoadAbsolute{Off: offArg(1), Size: 4},
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: sockTypeMask},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: sockStream, SkipFalse: uint8(len(stream))},
	}
	inet = append(inet, stream...)
	inet = append(inet, bpf.JumpIf{Cond: bpf.JumpEqual, Val: sockDgram, SkipFalse: uint8(len(dgram))})
	inet = append(inet, dgram...)
	inet = append(inet, bpf.RetConstant{Val: retNotify})
	family := []bpf.Instruction{bpf.LoadAbsolute{Off: offArg(0), Size: 4}}
	family = append(family, allowIf(afUnix)...)
	// A is the family past this block: it loads the protocol only when it is taken, and every path of it returns.
	netlink := []bpf.Instruction{bpf.LoadAbsolute{Off: offArg(2), Size: 4}}
	netlink = append(netlink, allowIf(netlinkRoute)...)
	netlink = append(netlink, bpf.RetConstant{Val: retNotify})
	family = append(family, bpf.JumpIf{Cond: bpf.JumpEqual, Val: afNetlink, SkipFalse: uint8(len(netlink))})
	family = append(family, netlink...)
	family = append(family,
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: afInet, SkipTrue: 2},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: afInet6, SkipTrue: 1},
		bpf.RetConstant{Val: retNotify},
	)
	family = append(family, inet...)
	var prog []bpf.Instruction
	if socketNR != noSyscall {
		prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: socketNR, SkipFalse: uint8(len(family))})
		prog = append(prog, family...)
	}
	if pairNR != noSyscall {
		pair := []bpf.Instruction{bpf.LoadAbsolute{Off: offArg(0), Size: 4}}
		pair = append(pair, allowIf(afUnix)...)
		pair = append(pair, bpf.RetConstant{Val: retNotify})
		prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: pairNR, SkipFalse: uint8(len(pair))})
		prog = append(prog, pair...)
	}
	// Every path of a matched block returns, so a syscall that matched neither leaves A holding its number
	// for the arms after this one.
	return prog
}

// The root-tier arm (ADR 0033) answers bpf, init_module, finit_module, delete_module, kexec_load and
// kexec_file_load with EPERM at tiers 2 and 3, whatever the contract's setuid: says. Under setuid: true a root
// agent could otherwise open a pinned BPF map (BPF_OBJ_GET checks inode permission, not file_open, so
// Landlock does not see it) and delete its run's row, silencing the plane, the recorder and the cgroup programs,
// or load kernel code. Docker's default profile refuses the same calls. They are confinement, like the
// io_uring and openat2 ENOSYS arms, not policy verdicts: an errno in the filter itself, which holds with a dead
// supervisor, and no ledger line.

// signalScopeTest stands in for LANDLOCK_SCOPE_SIGNAL below Landlock ABI 6 (R7). With no
// signal scope, an agent at tier 1 shares its launcher's uid and could kill(2) it, SIGSTOP it (every
// notified syscall of the run then waits on a stopped supervisor) or SIGTERM it (run_end reads as an
// operator's stop), and signal every other process of the user: on the 5.14, 6.1 and 6.8 rows of the
// matrix nothing refused it, and no record said so. The arm notifies kill, tkill, tgkill, rt_sigqueueinfo
// and rt_tgsigqueueinfo, whose targets are scalars the supervisor decides against the run's cgroup, and
// fcntl F_SETOWN/F_SETOWN_EX, which aim a descriptor's SIGIO at a process. pidfd_send_signal is answered
// ENOSYS: its target is a descriptor another thread can swap between a decision and the kernel's use of it,
// and runtimes that use it (Go's os.Process) probe it once and fall back to kill(2), which this arm decides.
// From ABI 6 the ruleset's scope decides all of them in the kernel and this arm is not installed.
//
// tkill and tgkill carrying SIGURG are allowed without a notification. SIGURG's default action is to ignore
// it, so it can neither end nor stop another process, and it is the signal the Go runtime preempts its own
// threads with: from any Go program in the run it was a notification per preemption, and from the child
// stage, which is a Go program, a garbage collection between installing the filter and reporting the
// listener sent one to a supervisor not yet running, and the stage hung.
func signalScopeTest(t archTable) []bpf.Instruction {
	var prog []bpf.Instruction
	for _, s := range t.Signal {
		sigArg := -1
		switch s.Name {
		case "tkill":
			sigArg = 1
		case "tgkill":
			sigArg = 2
		}
		if sigArg < 0 {
			prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: s.NR, SkipFalse: 1}, bpf.RetConstant{Val: retNotify})
			continue
		}
		prog = append(prog,
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: s.NR, SkipFalse: 4},
			bpf.LoadAbsolute{Off: offArg(sigArg), Size: 4}, // int sig
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: sigURG, SkipFalse: 1},
			bpf.RetConstant{Val: retAllow},
			bpf.RetConstant{Val: retNotify},
		)
	}
	prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: t.PidfdSignal, SkipFalse: 1}, bpf.RetConstant{Val: retENOSYS})
	return append(prog,
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: t.Fcntl, SkipFalse: 5},
		bpf.LoadAbsolute{Off: offArg(1), Size: 4}, // int cmd
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: fSetown, SkipTrue: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: fSetownEx, SkipFalse: 1},
		bpf.RetConstant{Val: retNotify},
		bpf.LoadAbsolute{Off: offNR, Size: 4},
		// The same owner through ioctl: FIOSETOWN and SIOCSPGRP on a socket set what F_SETOWN sets, and with
		// F_SETSIG and O_ASYNC a byte written to the socket's peer signalled any process of the uid, the
		// launcher included (docs/p0/supervisor.md R33, reproduced at ABI 5).
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: t.Ioctl, SkipFalse: 5},
		bpf.LoadAbsolute{Off: offArg(1), Size: 4}, // the request; both values fit 32 bits
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ioctlFIOSETOWN, SkipTrue: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: ioctlSIOCSPGRP, SkipFalse: 1},
		bpf.RetConstant{Val: retNotify},
		bpf.LoadAbsolute{Off: offNR, Size: 4},
	)
}

// dnotifyTest is the watch arm's third watch API (R11e): fcntl(fd, F_NOTIFY, mask), dnotify, watches the directory fd
// holds, and from a descriptor of a deny_read directory (one a tier-1 ruleset lets the agent open to list, on the
// READ_DIR it inherits) it reported every access, change, creation and rename inside the target, with its timing,
// while each read there was refused. Only the command is tested, a scalar the kernel reads as an unsigned int (the
// low half of args[1], as the signal arm's F_SETOWN test reads it), so every other fcntl(2) is left to the arms after
// this one and the descriptor table's own calls (F_GETFL, F_SETFD, F_DUPFD...) cost no notification; the supervisor
// decides the watch on the descriptor's own file (supervisor R36). The signal arm, below Landlock ABI 6, sees fcntl
// first and notifies its F_SETOWN pair itself; any other command reaches this test with A reloaded to the number.
func dnotifyTest(fcntl uint32) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: fcntl, SkipFalse: 4},
		bpf.LoadAbsolute{Off: offArg(1), Size: 4}, // unsigned int cmd
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: fNotify, SkipFalse: 1},
		bpf.RetConstant{Val: retNotify},
		bpf.LoadAbsolute{Off: offNR, Size: 4},
	}
}

// Which values of setpriority(2) and ioprio_set(2) that name one task (PRIO_PROCESS, IOPRIO_WHO_PROCESS).
const (
	prioProcess      = 0
	ioprioWhoProcess = 1
)

// procScopeTest notifies the calls that change another process's resource limits or scheduling, which no
// Landlock ABI governs: task_prlimit, task_setnice, task_setscheduler and task_setioprio are LSM hooks Landlock
// does not implement, and the kernel's own check for each is only that the caller and target share a uid. At
// tier 1 the agent shares its launcher's, and prlimit64(launcher, RLIMIT_CPU, {1, 1}) had the kernel SIGKILL the
// launcher, supervisor and ledger writer with it, leaving no run_end, even inside an ABI-6 signal scope
// (reproduced on 6.17); RLIMIT_FSIZE 0 or a low RLIMIT_NOFILE crippled it instead, and setpriority or
// sched_setaffinity starved it of CPU while every notified syscall of the run waited on it. The same calls
// reached every other process of the user. The supervisor decides each against the run's cgroup, as the
// signal-scope arm's targets (supervisor R35).
//
// A call on the caller itself is allowed here without a notification: prlimit64 with pid 0 or with no new
// limit (a read), a scheduling call with pid 0, and setpriority or ioprio_set naming the caller's own process
// (which PROCESS, who 0). Every argument tested is a scalar, so the decision has no time-of-check gap; the
// pid and which/who are ints and compared on their low 32 bits, as the kernel reads them, and prlimit64's
// new_rlim pointer on both halves.
func procScopeTest(t archTable) []bpf.Instruction {
	prog := []bpf.Instruction{
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: t.Prlimit, SkipFalse: 8},
		bpf.LoadAbsolute{Off: offArg(0), Size: 4}, // pid_t pid
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 5},
		bpf.LoadAbsolute{Off: offArg(2), Size: 4}, // new_rlim: low half
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipFalse: 2},
		bpf.LoadAbsolute{Off: offArg(2) + 4, Size: 4}, // high half
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1},
		bpf.RetConstant{Val: retNotify},
		bpf.RetConstant{Val: retAllow},
	}
	for _, s := range t.TaskArg0 {
		prog = append(prog,
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: s.NR, SkipFalse: 4},
			bpf.LoadAbsolute{Off: offArg(0), Size: 4}, // pid_t pid
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipFalse: 1},
			bpf.RetConstant{Val: retAllow},
			bpf.RetConstant{Val: retNotify},
		)
	}
	for _, ww := range []struct{ nr, process uint32 }{{t.Setpriority, prioProcess}, {t.IoprioSet, ioprioWhoProcess}} {
		prog = append(prog,
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: ww.nr, SkipFalse: 6},
			bpf.LoadAbsolute{Off: offArg(0), Size: 4}, // int which
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: ww.process, SkipFalse: 3},
			bpf.LoadAbsolute{Off: offArg(1), Size: 4}, // int who
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipFalse: 1},
			bpf.RetConstant{Val: retAllow},
			bpf.RetConstant{Val: retNotify},
		)
	}
	// Every path of a matched block returns, so a syscall that matched none leaves A holding its number.
	return prog
}

// memfdSealTest refuses memfd_create(2) with EACCES unless its flags set MFD_NOEXEC_SEAL and leave
// MFD_HUGETLB clear (SEMANTICS §4).
//
// An anonymous image — a memfd holding a written-in ELF — runs an exec no exec.allow entry named, because
// Landlock's file_open allows a memfd outright (is_nouser_or_private on its SB_NOUSER superblock,
// SEMANTICS §4) and tier 2's FAN_OPEN_EXEC_PERM sees no open a fexecve makes; only tier 3's
// bprm_check_security would. Deciding that exec after the fact, from the descriptor the supervisor's walk
// reads, loses to a thread or CLONE_FILES child that swaps the descriptor between the decision and the
// kernel's re-lookup (supervisor R16b). memfd_create's flags are a scalar in args[1], immutable once the
// syscall traps, so this arm closes the creation itself, race-free: a shmem memfd created with
// MFD_NOEXEC_SEAL has its execute bits cleared and sealed, and the kernel then refuses to exec it
// (mm/memfd.c; verified on 6.17). A hugetlb memfd is refused whatever else it sets, because hugetlbfs does
// not enforce the F_SEAL_EXEC the flag sets (mfdHugetlb). Every memfd the run can create is therefore
// non-executable, and no executable anonymous image is left to run. A data memfd that sets the flag is
// allowed, which is what MFD_NOEXEC_SEAL is for, so a workload that only needs shared memory is unaffected.
// EACCES matches the kernel's own answer under vm.memfd_noexec mode 2 and the supervisor's own
// refusalErrno.
//
// The flags are an unsigned int, so classic BPF compares their low 32 bits exactly. It is emitted for
// MemfdSealed, which Prepare picks when the run restricts exec, the contract did not opt in and the kernel
// honours the flag (MemfdNoexecSealSupported).
func memfdSealTest(nr uint32) []bpf.Instruction {
	if nr == noSyscall {
		return nil
	}
	return []bpf.Instruction{
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipFalse: 5},
		bpf.LoadAbsolute{Off: offArg(1), Size: 4},                          // unsigned int flags: low 32 bits
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: mfdHugetlb, SkipTrue: 1},    // hugetlbfs ignores F_SEAL_EXEC
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: mfdNoexecSeal, SkipTrue: 1}, // sealed non-exec: allowed
		bpf.RetConstant{Val: retEACCES},
		bpf.LoadAbsolute{Off: offNR, Size: 4},
	}
}

// memfdRefuseTest refuses every memfd_create(2) with ENOSYS: the closure of memfd exec on a kernel without
// MFD_NOEXEC_SEAL (upstream before 6.3, and any that did not backport it).
//
// There MFD_NOEXEC_SEAL does not exist (sanitize_flags answers EINVAL), no flag separates an executable
// memfd from a data one, and any memfd can be written with an ELF and run. The only creation-time closure
// is to create none, which is exactly as race-free as memfdSealTest: the decision is the syscall number,
// fixed once the call traps. ENOSYS rather than EACCES because it is what a kernel without memfd_create
// (before 3.17) answers, so a runtime that uses one for shared memory takes its pre-memfd path — a file in
// /dev/shm or an O_TMPFILE, which Landlock's rules and exec.allow govern like any other file — instead of
// failing on an errno it does not expect; the same reasoning puts ENOSYS on io_uring and openat2 (R10).
// What an operator gives up is a memfd for anything, data included, on such a kernel; a contract that
// needs one sets exec.anonymous: true, which drops the arm (GAPS C30).
func memfdRefuseTest(nr uint32) []bpf.Instruction {
	if nr == noSyscall {
		return nil
	}
	return []bpf.Instruction{
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipFalse: 1},
		bpf.RetConstant{Val: retENOSYS},
	}
}

// truncateTest refuses path-based truncate(2) with EPERM; emitted only below ABI 3 (R2, E31).
//
// truncate(2) takes a path and needs no fd, so nothing else in tier 1 constrains it: Landlock has no
// LANDLOCK_ACCESS_FS_TRUNCATE before ABI 3, the open-family write test never sees it, and it is in no
// notify table. On a 6.1-class kernel (Amazon Linux 2023 stock, ARCHITECTURE §14's tested floor) an agent
// could otherwise truncate any DAC-writable file to zero — SEMANTICS §1 promises `fs: {}` refuses
// truncate, and only this arm makes that true below 6.2.
//
// Deliberately coarser than the contract: a truncate(2) of a path inside a declared write dir is refused
// too, because the filter cannot safely resolve the path argument (R11's TOCTOU reason for notifying
// rather than deciding) and over-restriction is the fail-closed direction. ftruncate(2) is NOT refused:
// it needs a fd opened for writing, and WRITE_FILE is handled from ABI 1, so the open already decided it.
func truncateTest(nr uint32) []bpf.Instruction {
	if nr == noSyscall {
		return nil
	}
	return []bpf.Instruction{
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipFalse: 1},
		bpf.RetConstant{Val: retEPERM},
	}
}

// readOnlyTruncateTest refuses an open-family call carrying O_TRUNC unless its access mode is exactly
// O_WRONLY or O_RDWR, so O_RDONLY and access mode 3 (O_ACCMODE) are refused; emitted only below ABI 3,
// alongside truncateTest (R2, E31).
//
// Landlock's required access for file_open derives WRITE_FILE from FMODE_WRITE, which O_RDONLY does not
// set; the O_TRUNC term that would demand LANDLOCK_ACCESS_FS_TRUNCATE arrived with ABI 3. The VFS still
// truncates (may_open adds MAY_WRITE for O_TRUNC, a DAC check the agent's own uid passes), so below ABI 3
// open(path, O_RDONLY|O_TRUNC) destroys the file while asking Landlock for READ_FILE only. WriteFlagMask
// matches O_TRUNC and notifies, but the supervisor's open handler is record-only and answers CONTINUE, so
// the notification records the truncation instead of preventing it. O_RDONLY|O_TRUNC is explicitly
// unspecified behaviour (POSIX, open(2)), so refusing it costs nothing legitimate. Access mode 3 is the
// same hole: OPEN_FMODE(3) sets neither FMODE_READ nor FMODE_WRITE, so Landlock checks nothing, while the
// VFS still adds MAY_WRITE for O_TRUNC and truncates; it is not a portable mode and has no regular-file use.
func readOnlyTruncateTest(nr uint32, arg int) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipFalse: 7},
		bpf.LoadAbsolute{Off: offArg(arg), Size: 4}, // int flags: low 32 bits
		bpf.JumpIf{Cond: bpf.JumpBitsNotSet, Val: oTruncFlag, SkipTrue: 4},
		bpf.ALUOpConstant{Op: bpf.ALUOpAnd, Val: oAccMode},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: oWrOnly, SkipTrue: 2}, // a write open: Landlock decides it
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: oRdWr, SkipTrue: 1},
		bpf.RetConstant{Val: retEPERM}, // access mode 0 (O_RDONLY) or 3 (O_ACCMODE)
		bpf.LoadAbsolute{Off: offNR, Size: 4},
	}
}

// sendToTest notifies sendto when args[4] != 0: the pointer is 64-bit, so both halves are tested and A is
// reloaded with nr afterwards. With more (R11d), a sendto with no address is notified too when its flags,
// args[3], carry MSG_MORE: an int, whose low 32 bits are what the kernel reads.
func sendToTest(nr uint32, more bool) []bpf.Instruction {
	if !more {
		return []bpf.Instruction{
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipFalse: 6},
			bpf.LoadAbsolute{Off: offArg(4), Size: 4},             // low half
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipFalse: 2}, // non-zero -> notify
			bpf.LoadAbsolute{Off: offArg(4) + 4, Size: 4},         // high half
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipTrue: 1},  // zero -> no address
			bpf.RetConstant{Val: retNotify},
			bpf.LoadAbsolute{Off: offNR, Size: 4},
		}
	}
	return []bpf.Instruction{
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipFalse: 8},
		bpf.LoadAbsolute{Off: offArg(4), Size: 4},             // low half
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipFalse: 4}, // non-zero -> notify
		bpf.LoadAbsolute{Off: offArg(4) + 4, Size: 4},         // high half
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipFalse: 2}, // non-zero -> notify
		bpf.LoadAbsolute{Off: offArg(3), Size: 4},             // no address: the flags
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: msgMore, SkipFalse: 1},
		bpf.RetConstant{Val: retNotify},
		bpf.LoadAbsolute{Off: offNR, Size: 4},
	}
}

// MSG_MORE, and setsockopt(2)'s UDP_CORK at its two levels: SOL_UDP and SOL_UDPLITE, which are IPPROTO_UDP's and
// IPPROTO_UDPLITE's numbers.
const (
	msgMore    = 0x8000
	solUDP     = 17
	solUDPLite = 136
	udpCork    = 1
)

// frameTests are R11d's pending-frame arms, for a run that decides datagrams (supervisor R13): setsockopt(UDP_CORK) at
// SOL_UDP or SOL_UDPLITE, on its scalar level and option, and every sendfile and splice, are notified, and the
// supervisor refuses the cork and a sendfile or splice into a socket that can hold a frame. sendToTest's MSG_MORE arm
// and the notify set's sendmsg and sendmmsg are the rest: together they are every syscall that can leave a UDP frame
// pending on a socket. Each arm reloads the syscall number on the paths that do not return.
func frameTests(t archTable) []bpf.Instruction {
	var prog []bpf.Instruction
	if t.Setsockopt != noSyscall {
		prog = append(prog,
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: t.Setsockopt, SkipFalse: 7},
			bpf.LoadAbsolute{Off: offArg(1), Size: 4}, // int level: low 32 bits
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: solUDP, SkipTrue: 1},
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: solUDPLite, SkipFalse: 3},
			bpf.LoadAbsolute{Off: offArg(2), Size: 4}, // int optname: low 32 bits
			bpf.JumpIf{Cond: bpf.JumpEqual, Val: udpCork, SkipFalse: 1},
			bpf.RetConstant{Val: retNotify},
			bpf.LoadAbsolute{Off: offNR, Size: 4},
		)
	}
	for _, s := range t.Frames {
		prog = append(prog, bpf.JumpIf{Cond: bpf.JumpEqual, Val: s.NR, SkipFalse: 1}, bpf.RetConstant{Val: retNotify})
	}
	return prog
}

// writeFlagTest notifies an open-family syscall when the flags argument has a write bit (R12).
func writeFlagTest(nr uint32, arg int) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipFalse: 4},
		bpf.LoadAbsolute{Off: offArg(arg), Size: 4}, // int flags: low 32 bits
		bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: WriteFlagMask, SkipFalse: 1},
		bpf.RetConstant{Val: retNotify},
		bpf.LoadAbsolute{Off: offNR, Size: 4},
	}
}

// assembleFilter is buildFilter plus bpf.Assemble, the form seccomp(2) takes. It is the one form Prepare
// installs; tests pass the filterOpts of the run they stand for.
func assembleFilter(arch Arch, o filterOpts) ([]bpf.RawInstruction, error) {
	insts, err := buildFilter(arch, o)
	if err != nil {
		return nil, err
	}
	raw, err := bpf.Assemble(insts)
	if err != nil {
		return nil, fmt.Errorf("%w: assembling the seccomp filter: %w", ErrRulesetBuild, err)
	}
	return raw, nil
}

// MemfdNoexecSealSupported reports whether this kernel honours MFD_NOEXEC_SEAL: it creates a throwaway memfd
// with the flag and closes it. It decides between the two closing arms: a kernel without the flag rejects it
// as unknown (mm/memfd.c sanitize_flags: EINVAL), so the sealing arm would refuse every memfd_create while
// giving the agent no flag that satisfies it, and MemfdRefused says so plainly instead. It is a probe, not a
// uname parse, because the version does not tell: upstream added the flag in 6.3, RHEL 9.8's 5.14 accepts it,
// and a distribution kernel above 5.14 but below 6.3 need not.
func MemfdNoexecSealSupported() bool {
	fd, err := unix.MemfdCreate("tego-memfd-probe", mfdNoexecSeal|unix.MFD_CLOEXEC)
	if err != nil {
		return false
	}
	_ = unix.Close(fd)
	return true
}

// flagNotifyTest inspects only a scalar open flag, never task memory.
func flagNotifyTest(nr uint32, arg int, mask uint32) []bpf.Instruction {
	return []bpf.Instruction{bpf.JumpIf{Cond: bpf.JumpEqual, Val: nr, SkipFalse: 4}, bpf.LoadAbsolute{Off: uint32(offArg0 + arg*argSize), Size: 4}, bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: mask, SkipFalse: 1}, bpf.RetConstant{Val: retNotify}, bpf.LoadAbsolute{Off: offNR, Size: 4}}
}
