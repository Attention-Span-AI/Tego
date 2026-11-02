// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"fmt"
	"runtime"

	"golang.org/x/sys/unix"
)

// refusalErrno is the errno of the refusals this loop answers itself, save the EPERM of the mount and
// namespace families (refuseTopology, refuseTopologyAs), the keyring and System V IPC families (answerKeyring,
// answerSysVIPC), signal scope (answerSignal), process scope (answerProcScope) and a whole-mount fanotify mark
// (handleFanotifyMark, R36), each of which writes unix.EPERM itself, and an exec whose lookup failed as the task's
// own would, which keeps that lookup's errno (lookupErrno): a refused connect, unix connect, Fast-Open send or
// datagram (R10), every other refused exec (exec.go), a deny_write modification (answerFS, R15c), a watch at or
// beneath a deny_read target (decideWatch, R36), which is the EACCES of the read it stands for, and the answer to a
// handler that could not finish, the mount family's included (failClosed, R5).
//
// EACCES is the errno of a connect this loop refuses, in every tier (R10, spec/policy/SEMANTICS.md §5, "The
// errno of a refusal"): it is what Landlock's own TCP backstop returns, so a refusal looks the same however it
// was reached, and at tier 2 this loop still decides first, so the agent meets it there too. It is not every
// refused connect's errno, nor every network refusal's: at tier 2 an unconnected datagram this loop continues,
// and a connect it relayed that the kernel's rows refuse, meet the kernel program's EPERM (SEMANTICS §5), and
// Landlock's abstract-unix scope refuses a connect or send with EPERM (enforce-landlock R7). It is also what
// Landlock answers for the exec and file refusals the other uses stand beside (spec/reason/REASON-CHANNEL.md
// §1). Never ECONNREFUSED, which is a real peer's answer that a relay returns as it came. docs/ARCHITECTURE.md
// §7 and REASON-CHANNEL §1 once said ECONNREFUSED and EPERM for a network refusal; they were brought in line
// on 2026-09-23 (docs/p0/supervisor.md §11). Because this one constant answers all of the above, a different
// network errno means either splitting it or changing the exec, fs and fail-closed errnos with it, and in
// either case the documents that name each of them.
const refusalErrno = unix.EACCES

// Syscall numbers this loop dispatches (R1). They are compile-time constants per architecture: no syscall
// number is ever taken from runtime or untrusted data (I8). x86-64 carries the legacy forms as well as the
// *at ones; the arm64 generic table has only the *at forms.
const (
	nrX86Open       = 2
	nrX86Connect    = 42
	nrX86Bind       = 49
	nrX86Listen     = 50
	nrX86SendTo     = 44
	nrX86SendMsg    = 46
	nrX86Execve     = 59
	nrX86Rename     = 82
	nrX86Mkdir      = 83
	nrX86Rmdir      = 84
	nrX86Creat      = 85
	nrX86Unlink     = 87
	nrX86Symlink    = 88
	nrX86Link       = 86
	nrX86OpenAt     = 257
	nrX86MkdirAt    = 258
	nrX86UnlinkAt   = 263
	nrX86RenameAt   = 264
	nrX86SymlinkAt  = 266
	nrX86LinkAt     = 265
	nrX86Mknod      = 133
	nrX86MknodAt    = 259
	nrX86SendMMsg   = 307
	nrX86RenameAt2  = 316
	nrX86ExecveAt   = 322
	nrX86PivotRoot  = 155
	nrX86Mount      = 165
	nrX86Umount2    = 166
	nrX86AddKey     = 248
	nrX86RequestKey = 249
	nrX86Keyctl     = 250
	nrX86Unshare    = 272
	nrX86Clone      = 56
	nrX86Setns      = 308
	nrX86Shmget     = 29
	nrX86Shmat      = 30
	nrX86Shmctl     = 31
	nrX86Semget     = 64
	nrX86Semop      = 65
	nrX86Semctl     = 66
	nrX86Msgget     = 68
	nrX86Msgsnd     = 69
	nrX86Msgrcv     = 70
	nrX86Msgctl     = 71
	nrX86Semtimedop = 220
	nrX86Socket     = 41
	nrX86Socketpair = 53
	nrX86Setsockopt = 54
	nrX86Sendfile   = 40
	nrX86Splice     = 275
	nrX86Kill       = 62
	nrX86Fcntl      = 72
	nrX86Ioctl      = 16
	nrX86RtSigqueue = 129
	nrX86Tkill      = 200
	nrX86Tgkill     = 234
	nrX86RtTgsigq   = 297
	nrX86Truncate   = 76
	nrX86Chmod      = 90
	nrX86Fchmod     = 91
	nrX86FchmodAt   = 268
	nrX86Setxattr   = 188
	nrX86Lsetxattr  = 189
	nrX86Fsetxattr  = 190
	nrX86Rmxattr    = 197
	nrX86Lrmxattr   = 198
	nrX86Frmxattr   = 199
	nrX86Chown      = 92
	nrX86Fchown     = 93
	nrX86Lchown     = 94
	nrX86FchownAt   = 260
	nrX86InotifyAdd = 254
	nrX86FanMark    = 301
	nrMoveMount     = 429 // the unified numbering both architectures share from 5.2
	nrFchmodAt2     = 452 // likewise, from 6.6
	nrSetxattrAt    = 463 // likewise, from 6.13
	nrRmxattrAt     = 466 // likewise, from 6.13
	nrARMTruncate   = 45
	nrARMFchmod     = 52
	nrARMFchmodAt   = 53
	nrARMSetxattr   = 5
	nrARMLsetxattr  = 6
	nrARMFsetxattr  = 7
	nrARMRmxattr    = 14
	nrARMLrmxattr   = 15
	nrARMFrmxattr   = 16
	nrARMFchownAt   = 54
	nrARMFchown     = 55
	nrARMInotifyAdd = 27
	nrARMFanMark    = 263
	nrARMUmount2    = 39
	nrARMMount      = 40
	nrARMPivotRoot  = 41
	nrARMMkdirAt    = 34
	nrARMUnlinkAt   = 35
	nrARMSymlinkAt  = 36
	nrARMLinkAt     = 37
	nrARMMknodAt    = 33
	nrARMRenameAt   = 38
	nrARMOpenAt     = 56
	nrARMConnect    = 203
	nrARMBind       = 200
	nrARMListen     = 201
	nrARMSendTo     = 206
	nrARMSendMsg    = 211
	nrARMExecve     = 221
	nrARMSendMMsg   = 269
	nrARMRenameAt2  = 276
	nrARMExecveAt   = 281
	nrARMAddKey     = 217
	nrARMRequestKey = 218
	nrARMKeyctl     = 219
	nrARMUnshare    = 97
	nrARMClone      = 220
	nrARMSetns      = 268
	nrARMMsgget     = 186
	nrARMMsgctl     = 187
	nrARMMsgrcv     = 188
	nrARMMsgsnd     = 189
	nrARMSemget     = 190
	nrARMSemctl     = 191
	nrARMSemtimedop = 192
	nrARMSemop      = 193
	nrARMShmget     = 194
	nrARMShmctl     = 195
	nrARMShmat      = 196
	nrARMSocket     = 198
	nrARMSocketpair = 199
	nrARMSetsockopt = 208
	nrARMSendfile   = 71
	nrARMSplice     = 76
	nrARMFcntl      = 25
	nrARMIoctl      = 29
	nrARMKill       = 129
	nrARMTkill      = 130
	nrARMTgkill     = 131
	nrARMRtSigqueue = 138
	nrARMRtTgsigq   = 240
)

// handlerFunc decides and responds for one notification kind; it owns the whole lifecycle of that
// notification's id. It is always invoked through the worker's recover() wrapper (R25), never directly.
type handlerFunc func(l *Loop, n *notif)

// entry is one dispatch-table row: the syscall's name for the log and the handler. A handler that cannot finish is
// refused whatever the row (failClosed).
type entry struct {
	name string
	fn   handlerFunc
}

// dispatchKey is the (arch, nr) pair a notification is dispatched on. The filter guards the architecture
// before any syscall-number test (enforce-landlock R9), so a foreign arch never reaches the table.
type dispatchKey struct {
	arch uint32
	nr   int32
}

// dispatchTable maps (arch, nr) to a handler. It is built once in New from the compile-time tables above
// and read-only afterwards (I8).
type dispatchTable map[dispatchKey]entry

// auditArchX86 and auditArchARM are the AUDIT_ARCH_* values of the two supported architectures.
const (
	auditArchX86 = uint32(unix.AUDIT_ARCH_X86_64)
	auditArchARM = uint32(unix.AUDIT_ARCH_AARCH64)
)

// nativeAuditArch is the AUDIT_ARCH_* value of this build; the package compiles for amd64 and arm64 only
// (R26), so the switch is total.
func nativeAuditArch() uint32 {
	if runtime.GOARCH == "arm64" {
		return auditArchARM
	}
	return auditArchX86
}

// Dispatches reports whether this loop has a handler for syscall nr of the audit architecture arch (an
// AUDIT_ARCH_* value, as the filter's arch guard compares). It exists for the completeness test that walks
// the filter's notify arms (enforce/landlock): a notified syscall with no handler is answered ENOSYS, so a
// missing entry fails closed, and the test makes it fail loud instead (ADR 0018).
func Dispatches(arch uint32, nr int32) bool {
	_, ok := buildDispatchFor(arch)[dispatchKey{arch: arch, nr: nr}]
	return ok
}

// buildDispatch builds the table for this build's architecture.
func buildDispatch() dispatchTable { return buildDispatchFor(nativeAuditArch()) }

// buildDispatchFor builds the table for one architecture; tests use it to check both tables on one host.
func buildDispatchFor(arch uint32) dispatchTable {
	conn := entry{name: "connect", fn: handleConnect}
	bind := entry{name: "bind", fn: handleBind}
	listen := entry{name: "listen", fn: handleListen}
	sendTo := entry{name: "sendto", fn: handleSendTo}
	sendMsg := entry{name: "sendmsg", fn: handleSendMsg}
	// sendmmsg is a decision kind: its addressed messages on an unconnected stream socket are the
	// Fast-Open shape R12 decides, so a handler that cannot finish must refuse rather than continue (R5).
	sendMMsg := entry{name: "sendmmsg", fn: handleSendMMsg}
	// The exec pair is a decision kind: this loop continues only an exec it matched to a grant (R16b), so a
	// handler that cannot finish refuses rather than continuing an image nothing below tier 3 governs.
	execve := entry{name: "execve", fn: handleExecve}
	execveAt := entry{name: "execveat", fn: handleExecveAt}
	openAt := entry{name: "openat", fn: handleOpenAt}
	mkdirAt := entry{name: "mkdirat", fn: handleMkdirAt}
	unlinkAt := entry{name: "unlinkat", fn: handleUnlinkAt}
	renameAt := entry{name: "renameat", fn: handleRenameAt}
	renameAt2 := entry{name: "renameat2", fn: handleRenameAt}
	symlinkAt := entry{name: "symlinkat", fn: handleSymlinkAt}
	linkAt := entry{name: "linkat", fn: handleLinkAt}
	mknodAt := entry{name: "mknodat", fn: handleMknodAt}
	// truncate(2) is notified from Landlock ABI 3, the mode-change family under record: full (enforce-landlock
	// R11): record-only, like the rest of the fs set, save R15c's refusal of a truncate.
	truncate := entry{name: "truncate", fn: handleTruncate}
	fchmod := entry{name: "fchmod", fn: handleFchmod}
	fchmodAt := entry{name: "fchmodat", fn: handleFchmodAt}
	fchmodAt2 := entry{name: "fchmodat2", fn: handleFchmodAt2}
	// The xattr and chown families reach this loop under an fs.write gate only (enforce-landlock R11), which
	// scores each as a write (recordAttr): record-only kinds, as chmod is.
	setxattr := entry{name: "setxattr", fn: handleSetxattr}
	lsetxattr := entry{name: "lsetxattr", fn: handleLsetxattr}
	fsetxattr := entry{name: "fsetxattr", fn: handleFsetxattr}
	removexattr := entry{name: "removexattr", fn: handleSetxattr}
	lremovexattr := entry{name: "lremovexattr", fn: handleLsetxattr}
	fremovexattr := entry{name: "fremovexattr", fn: handleFsetxattr}
	setxattrAt := entry{name: "setxattrat", fn: handleXattrAt}
	removexattrAt := entry{name: "removexattrat", fn: handleXattrAt}
	fchown := entry{name: "fchown", fn: handleFchown}
	fchownAt := entry{name: "fchownat", fn: handleFchownAt}
	// The watch calls reach this loop in every enforcing run (enforce-landlock R11e): a decision kind, refused where the
	// run withholds a read of the watched object and continued elsewhere (watch.go, R36).
	// The third, dnotify's fcntl(F_NOTIFY), is the fcntl entry's (handleFcntl).
	inotifyAddWatch := entry{name: "inotify_add_watch", fn: handleInotifyAddWatch}
	fanotifyMark := entry{name: "fanotify_mark", fn: handleFanotifyMark}
	// The mount family is a decision kind: a handler that cannot finish refuses (with refusalErrno rather
	// than refuseTopology's EPERM), as the Landlock domain behind it would, instead of continuing.
	mount := entry{name: "mount", fn: handleMount}
	umount := entry{name: "umount2", fn: handleUmount}
	pivotRoot := entry{name: "pivot_root", fn: handlePivotRoot}
	moveMount := entry{name: "move_mount", fn: handleMoveMount}
	// The namespace arm's syscalls reach this loop only when the run must refuse them
	// (docs/p0/enforce-cgroup-observe.md E24).
	unshare := entry{name: "unshare", fn: handleUnshare}
	clone := entry{name: "clone", fn: handleClone}
	setns := entry{name: "setns", fn: handleSetns}
	// The keyring family is a decision kind: this loop refuses these credential-store syscalls (SEMANTICS §1),
	// so a handler that cannot finish refuses rather than continuing into the store unobserved (R5).
	addKey := entry{name: "add_key", fn: handleAddKey}
	requestKey := entry{name: "request_key", fn: handleRequestKey}
	keyctl := entry{name: "keyctl", fn: handleKeyctl}
	// System V IPC is a decision kind for the same reason: refused unless the contract opts in (sysvipc.go),
	// so a handler that cannot finish refuses rather than continuing into the host's IPC namespace.
	ipc := func(name string) entry {
		return entry{name: name, fn: func(l *Loop, n *notif) { l.answerSysVIPC(n, name) }}
	}
	// socket and socketpair reach this loop only for a triple the filter's allowlist did not admit (ADR
	// 0018): the handler refuses and records, and has no CONTINUE path.
	socket := entry{name: "socket", fn: handleSocket}
	socketpair := entry{name: "socketpair", fn: handleSocketpair}
	// setsockopt reaches this loop only as SOL_TCP's TCP_ULP under a net: section (ADR 0018 (7)): refused and
	// recorded, with no CONTINUE path.
	setsockopt := entry{name: "setsockopt", fn: handleSetsockopt}
	// sendfile and splice reach this loop only in a run that decides datagrams (R13's pending frames;
	// enforce-landlock R11): a decision kind, since one into a UDP socket could leave a frame pending.
	sendfile := entry{name: "sendfile", fn: handleSendfile}
	splice := entry{name: "splice", fn: handleSplice}
	// The kill family and fcntl's F_SETOWN reach this loop only below Landlock ABI 6, where the ruleset has no
	// signal scope and this loop decides one in its place (signal.go): a decision kind, since a handler that
	// cannot finish must not let a signal leave the run. fcntl's F_NOTIFY, a dnotify watch, reaches it with the
	// other watch calls (enforce-landlock R11e), and handleFcntl hands it to handleDnotify (watch.go, R36).
	kill := entry{name: "kill", fn: handleKill}
	tkill := entry{name: "tkill", fn: handleTkill}
	tgkill := entry{name: "tgkill", fn: handleTgkill}
	rtSigqueue := entry{name: "rt_sigqueueinfo", fn: handleRtSigqueueinfo}
	rtTgsigqueue := entry{name: "rt_tgsigqueueinfo", fn: handleRtTgsigqueueinfo}
	fcntl := entry{name: "fcntl", fn: handleFcntl}
	ioctl := entry{name: "ioctl", fn: handleIoctl}

	t := dispatchTable{}
	// Two entries at one number is a mistyped constant (arm64 mkdirat typed 33, mknodat's): the second would
	// silently replace the first, and the syscall it dropped would be answered ENOSYS. The numbers are compile-time
	// constants, so this panics in every test that builds a table, never on data (TestDispatchNumbersAreTheKernels).
	add := func(nr int32, e entry) {
		k := dispatchKey{arch: arch, nr: nr}
		if prev, dup := t[k]; dup {
			panic(fmt.Sprintf("supervisor: %s and %s both dispatched at syscall %d of arch %#x", prev.name, e.name, nr, arch))
		}
		t[k] = e
	}
	switch arch {
	case auditArchARM:
		add(nrARMConnect, conn)
		add(nrARMBind, bind)
		add(nrARMListen, listen)
		add(nrARMSendTo, sendTo)
		add(nrARMSendMsg, sendMsg)
		add(nrARMSendMMsg, sendMMsg)
		add(nrARMExecve, execve)
		add(nrARMExecveAt, execveAt)
		add(nrARMOpenAt, openAt)
		add(nrARMMkdirAt, mkdirAt)
		add(nrARMUnlinkAt, unlinkAt)
		add(nrARMRenameAt, renameAt)
		add(nrARMRenameAt2, renameAt2)
		add(nrARMSymlinkAt, symlinkAt)
		add(nrARMLinkAt, linkAt)
		add(nrARMMknodAt, mknodAt)
		add(nrARMTruncate, truncate)
		add(nrARMFchmod, fchmod)
		add(nrARMFchmodAt, fchmodAt)
		add(nrFchmodAt2, fchmodAt2)
		add(nrARMSetxattr, setxattr)
		add(nrARMLsetxattr, lsetxattr)
		add(nrARMFsetxattr, fsetxattr)
		add(nrARMRmxattr, removexattr)
		add(nrARMLrmxattr, lremovexattr)
		add(nrARMFrmxattr, fremovexattr)
		add(nrSetxattrAt, setxattrAt)
		add(nrRmxattrAt, removexattrAt)
		add(nrARMFchown, fchown)
		add(nrARMFchownAt, fchownAt)
		add(nrARMInotifyAdd, inotifyAddWatch)
		add(nrARMFanMark, fanotifyMark)
		add(nrARMMount, mount)
		add(nrARMUmount2, umount)
		add(nrARMPivotRoot, pivotRoot)
		add(nrMoveMount, moveMount)
		add(nrARMAddKey, addKey)
		add(nrARMRequestKey, requestKey)
		add(nrARMKeyctl, keyctl)
		add(nrARMUnshare, unshare)
		add(nrARMClone, clone)
		add(nrARMSetns, setns)
		add(nrARMMsgget, ipc("msgget"))
		add(nrARMMsgctl, ipc("msgctl"))
		add(nrARMMsgrcv, ipc("msgrcv"))
		add(nrARMMsgsnd, ipc("msgsnd"))
		add(nrARMSemget, ipc("semget"))
		add(nrARMSemctl, ipc("semctl"))
		add(nrARMSemtimedop, ipc("semtimedop"))
		add(nrARMSemop, ipc("semop"))
		add(nrARMShmget, ipc("shmget"))
		add(nrARMShmctl, ipc("shmctl"))
		add(nrARMShmat, ipc("shmat"))
		add(nrARMSocket, socket)
		add(nrARMSocketpair, socketpair)
		add(nrARMSetsockopt, setsockopt)
		add(nrARMSendfile, sendfile)
		add(nrARMSplice, splice)
		add(nrARMKill, kill)
		add(nrARMTkill, tkill)
		add(nrARMTgkill, tgkill)
		add(nrARMRtSigqueue, rtSigqueue)
		add(nrARMRtTgsigq, rtTgsigqueue)
		add(nrARMFcntl, fcntl)
		add(nrARMIoctl, ioctl)
	default:
		add(nrX86Connect, conn)
		add(nrX86Bind, bind)
		add(nrX86Listen, listen)
		add(nrX86SendTo, sendTo)
		add(nrX86SendMsg, sendMsg)
		add(nrX86SendMMsg, sendMMsg)
		add(nrX86Execve, execve)
		add(nrX86ExecveAt, execveAt)
		add(nrX86OpenAt, openAt)
		add(nrX86MkdirAt, mkdirAt)
		add(nrX86UnlinkAt, unlinkAt)
		add(nrX86RenameAt, renameAt)
		add(nrX86RenameAt2, renameAt2)
		add(nrX86SymlinkAt, symlinkAt)
		add(nrX86LinkAt, linkAt)
		add(nrX86MknodAt, mknodAt)
		add(nrX86Truncate, truncate)
		add(nrX86Fchmod, fchmod)
		add(nrX86FchmodAt, fchmodAt)
		add(nrFchmodAt2, fchmodAt2)
		add(nrX86Setxattr, setxattr)
		add(nrX86Lsetxattr, lsetxattr)
		add(nrX86Fsetxattr, fsetxattr)
		add(nrX86Rmxattr, removexattr)
		add(nrX86Lrmxattr, lremovexattr)
		add(nrX86Frmxattr, fremovexattr)
		add(nrSetxattrAt, setxattrAt)
		add(nrRmxattrAt, removexattrAt)
		add(nrX86Fchown, fchown)
		add(nrX86FchownAt, fchownAt)
		add(nrX86InotifyAdd, inotifyAddWatch)
		add(nrX86FanMark, fanotifyMark)
		add(nrX86Mount, mount)
		add(nrX86Umount2, umount)
		add(nrX86PivotRoot, pivotRoot)
		add(nrMoveMount, moveMount)
		add(nrX86AddKey, addKey)
		add(nrX86RequestKey, requestKey)
		add(nrX86Keyctl, keyctl)
		add(nrX86Unshare, unshare)
		add(nrX86Clone, clone)
		add(nrX86Setns, setns)
		add(nrX86Shmget, ipc("shmget"))
		add(nrX86Shmat, ipc("shmat"))
		add(nrX86Shmctl, ipc("shmctl"))
		add(nrX86Semget, ipc("semget"))
		add(nrX86Semop, ipc("semop"))
		add(nrX86Semctl, ipc("semctl"))
		add(nrX86Msgget, ipc("msgget"))
		add(nrX86Msgsnd, ipc("msgsnd"))
		add(nrX86Msgrcv, ipc("msgrcv"))
		add(nrX86Msgctl, ipc("msgctl"))
		add(nrX86Semtimedop, ipc("semtimedop"))
		add(nrX86Socket, socket)
		add(nrX86Socketpair, socketpair)
		add(nrX86Setsockopt, setsockopt)
		add(nrX86Sendfile, sendfile)
		add(nrX86Splice, splice)
		add(nrX86Kill, kill)
		add(nrX86Tkill, tkill)
		add(nrX86Tgkill, tgkill)
		add(nrX86RtSigqueue, rtSigqueue)
		add(nrX86RtTgsigq, rtTgsigqueue)
		add(nrX86Fcntl, fcntl)
		add(nrX86Ioctl, ioctl)
		// The legacy, dirfd-less forms exist on x86-64 only.
		add(nrX86Open, entry{name: "open", fn: handleOpen})
		add(nrX86Creat, entry{name: "creat", fn: handleCreat})
		add(nrX86Mkdir, entry{name: "mkdir", fn: handleMkdir})
		add(nrX86Unlink, entry{name: "unlink", fn: handleUnlink})
		add(nrX86Rmdir, entry{name: "rmdir", fn: handleRmdir})
		add(nrX86Rename, entry{name: "rename", fn: handleRename})
		add(nrX86Symlink, entry{name: "symlink", fn: handleSymlink})
		add(nrX86Link, entry{name: "link", fn: handleLink})
		add(nrX86Mknod, entry{name: "mknod", fn: handleMknod})
		add(nrX86Chmod, entry{name: "chmod", fn: handleChmod})
		add(nrX86Chown, entry{name: "chown", fn: handleChown})
		add(nrX86Lchown, entry{name: "lchown", fn: handleLchown})
	}
	// The process-scope arm's resource-limit and scheduling calls, notified at every ABI (procscope.go, R35).
	addProcScope(arch, add)
	return t
}
