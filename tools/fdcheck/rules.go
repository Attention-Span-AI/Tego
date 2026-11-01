// SPDX-License-Identifier: Apache-2.0

package main

import "strings"

// Import paths fdcheck resolves.
const (
	pathUnix    = "golang.org/x/sys/unix"
	pathSyscall = "syscall"
	pathOS      = "os"
	pathEBPF    = "github.com/cilium/ebpf"
	pathLink    = "github.com/cilium/ebpf/link"
	pathSys     = "github.com/attention-span-ai/tego/internal/platform/sys"
	modulePath  = "github.com/attention-span-ai/tego"
	sysDir      = "internal/platform/sys"
)

// The kinds of finding. A raw site (ADR 0023 A9) is any of them in a non-exempt file; the ratchet counts them
// per package and kind.
const (
	kClose      = "close"      // A4: unix/syscall Close, CloseRange, SYS_CLOSE, SYS_CLOSE_RANGE
	kDup        = "dup"        // A4: Dup, Dup2, Dup3, SYS_DUP*, F_DUPFD, F_DUPFD_CLOEXEC
	kNewFile    = "newfile"    // A4: os.NewFile
	kFd         = "fd"         // A4/F5: (*os.File).Fd, any call of a selector Fd, cilium FD(), and their method values
	kRights     = "rights"     // A4: ParseUnixRights, the control-message decoders, SCM_RIGHTS
	kIOURing    = "iouring"    // A4: IoUringSetup, SYS_IO_URING_*
	kFromFD     = "fromfd"     // A4: link.NewFromFD, ebpf.NewMapFromFD, ebpf.NewProgramFromFD
	kProducer   = "producer"   // F1: a producer called (or taken as a value) outside an owner's birth
	kTrap       = "trap"       // F5: a Syscall* whose trap is not a SYS_ constant
	kFcntl      = "fcntl"      // F5: fcntl with a command outside the allowlist
	kUnshare    = "unshare"    // F5: unshare with CLONE_FILES, or with flags that are not constant
	kOwn        = "own"        // F1: sys.Own around something other than a direct producer call
	kStrict     = "strict"     // A1: sys.Strict around something other than a constructor call
	kOwnSyscall = "ownsyscall" // F10: sys.OwnSyscall around a call that is not an admitted pair
	kCloexec    = "cloexec"    // F9: a producer's flags without its CLOEXEC constant, or not constant
	kRelease    = "release"    // F3: ReleaseNumber other than as a taker's direct argument
	kLease      = "lease"      // F2: a Hold result not returned by defer or a hand-off, a *Lease stored, a lent number kept
	kFuncValue  = "funcvalue"  // F1: a constructor, ReleaseNumber, Abandon, Hold or Num taken as a value
	kForTest    = "fortest"    // F4: InertForTest outside tests, a *ForTest accessor outside tests and testhooks
	kAPI        = "api"        // F8: an exported API that takes or returns a bare descriptor number
	kAdopt      = "adopt"      // F4: a sys.Adopt site not in adopt.txt
	kAbandon    = "abandon"    // F4: an Abandon site not in abandon.txt
	kInherited  = "inherited"  // F4: a sys.Inherited site not in inherited.txt
	kStdio      = "stdio"      // F4: a sys.Stdio site not in stdio.txt
	kSweep      = "sweep"      // F4: a sys.CloseInheritedFrom site not in sweep.txt
	kIoctl      = "ioctl"      // F5: an ioctl whose request answers a descriptor, or is not a named constant
	kNolint     = "nolint"     // A4: a nolint directive that silences forbidigo (for it, all, or every linter)
	kOpaque     = "opaque"     // F6: code fdcheck cannot read: a //go:linkname, or a function without a Go body
)

// kindHelp says, per kind, what to write instead. It is printed with every finding.
var kindHelp = map[string]string{
	kClose:      "close through the owner: (*sys.FD).Close or CloseNow",
	kDup:        "duplicate through the owner: (*sys.FD).Dup, or sys.DupFile for an *os.File",
	kNewFile:    "hand an owner to a File with (*sys.FD).Release",
	kFd:         "lend the number under a lease: sys.FileDo, sys.Flock, sys.FstatFile, or internal/bpf ProgramFD/MapFD",
	kRights:     "receive descriptors with sys.ReceiveRights, which owns every number a control message carries, and send them with unix.UnixRights under a Borrow; never decode a control message or name SCM_RIGHTS yourself",
	kIOURing:    "io_uring is outside the TCB (ADR 0023 A4); it needs its own ADR",
	kFromFD:     "give the number with link.NewFromFD(x.ReleaseNumber()), the one sanctioned form (F3)",
	kProducer:   "make the number an owner where it is created: sys.Own(unix.X(...)), or the sys helper for this producer",
	kTrap:       "name the syscall with a unix.SYS_ constant (a package-level constant naming one is resolved); under a darwin build call the x/sys wrapper instead, since fdcheck classifies no macOS trap but its producers, fcntl and ioctl",
	kFcntl:      "use a named fcntl command from the allowlist; duplicate with (*sys.FD).Dup",
	kUnshare:    "never unshare CLONE_FILES: one descriptor table per process is the owner's premise; flags must be constant",
	kOwn:        "sys.Own's argument is a direct call to a producer; a number another owner holds is never wrapped",
	kStrict:     "sys.Strict's argument is a constructor call (sys.Own, OwnSyscall, a sys ...FD helper, Dup, Openat)",
	kOwnSyscall: "sys.OwnSyscall's argument is a direct Syscall of an admitted producer (A10 F1, F10)",
	kCloexec:    "the producer's flags are a constant expression carrying its CLOEXEC flag (F9)",
	kRelease:    "assign ReleaseNumber's number to a local (n, err := x.ReleaseNumber()) and give it to one taker, link.NewFromFD, ebpf.NewMapFromFD or ebpf.NewProgramFromFD, in the statement after the release's error check (if err != nil { return ... }), as that statement itself or its right-hand side (a call statement, an assignment, a var or a return; never an if, for or switch condition, a go or a defer), and nothing else",
	kLease:      "a Hold is followed in its block, past its own error check (if err != nil { return ... }, or l == nil joined by ||; never a test that returns on success), by `defer l.Return()` outside any loop or backward goto, or by its hand-off to a goroutine whose first statement is that defer, after which the holder no longer uses it; a lease is never returned by an explicit call; a *sys.Lease is never stored; a lent number is used in the call it is lent for (a syscall's argument, a comparison, a local) and never kept, returned or handed on (tools/fdcheck/lent.go lists the admitted uses)",
	kFuncValue:  "call it directly; a constructor, ReleaseNumber, Abandon, Hold or Num taken as a value escapes every check",
	kForTest:    "InertForTest belongs in _test.go files; other *ForTest accessors in tests and tegotesthooks files",
	kAPI:        "an exported API gives a *sys.FD or lends a sys.Lender, never a bare number (A11, F8)",
	kAdopt:      "list the site in tools/fdcheck/adopt.txt, with its reason in the commit",
	kAbandon:    "list the site in tools/fdcheck/abandon.txt: Abandon is for a number of unknown identity only (A5)",
	kInherited:  "list the site in tools/fdcheck/inherited.txt: Inherited is the process's first descriptor operation",
	kStdio:      "list the site in tools/fdcheck/stdio.txt",
	kIoctl:      "use an ioctl request from the allowlist in tools/fdcheck/rules.go (none answers a descriptor); one that answers a descriptor needs sys.Own and its own review",
	kNolint:     "never silence forbidigo, whose ADR 0021 and 0023 rules are the editor's copy of these: name the other linters the directive is for",
	kOpaque:     "give the code a Go body fdcheck reads: a //go:linkname or an assembly function reaches code no rule sees (a runtime or library internal that closes or makes a descriptor); one that must stay needs its own review and an A7 exemption",
	kSweep:      "list the site in tools/fdcheck/sweep.txt: CloseInheritedFrom closes every number from first up, so it is the process's first descriptor operation (ReapMain's start-up sweep)",
}

// listedKinds are the F4 kinds a list file admits by site.
var listedKinds = map[string]string{kAdopt: "adopt.txt", kAbandon: "abandon.txt", kInherited: "inherited.txt", kStdio: "stdio.txt",
	kSweep: "sweep.txt"}

// forbiddenCall are the unix/syscall names A4 forbids, with their kind.
var forbiddenCall = map[string]string{
	"Close": kClose, "CloseRange": kClose,
	"Dup": kDup, "Dup2": kDup, "Dup3": kDup,
	"ParseUnixRights": kRights,
	// The control-message decoders: a number a hand decode takes out of an SCM_RIGHTS message is fresh and no
	// owner holds it, so received descriptors are decoded by sys.ReceiveRights only.
	"ParseSocketControlMessage": kRights, "ParseOneSocketControlMessage": kRights,
	"IoUringSetup": kIOURing,
}

// forbiddenConst are the unix/syscall constants A4 forbids, with their kind.
func forbiddenConst(name string) (string, bool) {
	switch name {
	case "SYS_CLOSE", "SYS_CLOSE_RANGE", "SYS_CLOSE_NOCANCEL", "SYS_GUARDED_CLOSE_NP": // the last two macOS's
		return kClose, true
	case "SYS_DUP", "SYS_DUP2", "SYS_DUP3", "F_DUPFD", "F_DUPFD_CLOEXEC":
		return kDup, true
	case "SYS_IO_URING_SETUP", "SYS_IO_URING_ENTER", "SYS_IO_URING_REGISTER":
		return kIOURing, true
	case "SCM_RIGHTS":
		// The type a hand decode of a received control message selects; sending names it in
		// unix.UnixRights, not here.
		return kRights, true
	}
	return "", false
}

// syscallFamily are the unix/syscall functions whose first argument is a trap number.
var syscallFamily = map[string]bool{
	"Syscall": true, "Syscall6": true, "RawSyscall": true, "RawSyscall6": true,
	"SyscallNoError": true, "RawSyscallNoError": true, "AllThreadsSyscall": true, "AllThreadsSyscall6": true,
}

// producerTraps are the traps whose result is a descriptor; a raw Syscall of one outside sys.OwnSyscall is a
// raw producer site. SYS_BPF, SYS_SECCOMP and SYS_LANDLOCK_CREATE_RULESET depend on their command or flags.
var producerTraps = map[string]bool{
	"SYS_OPEN": true, "SYS_OPENAT": true, "SYS_OPENAT2": true, "SYS_CREAT": true, "SYS_OPEN_BY_HANDLE_AT": true,
	"SYS_SOCKET": true, "SYS_SOCKETPAIR": true, "SYS_ACCEPT": true, "SYS_ACCEPT4": true, "SYS_PIPE": true,
	"SYS_PIPE2": true, "SYS_EVENTFD": true, "SYS_EVENTFD2": true, "SYS_EPOLL_CREATE": true, "SYS_EPOLL_CREATE1": true,
	"SYS_INOTIFY_INIT": true, "SYS_INOTIFY_INIT1": true, "SYS_FANOTIFY_INIT": true, "SYS_MEMFD_CREATE": true,
	"SYS_MEMFD_SECRET": true, "SYS_PIDFD_OPEN": true, "SYS_PIDFD_GETFD": true, "SYS_PERF_EVENT_OPEN": true,
	"SYS_TIMERFD_CREATE": true, "SYS_SIGNALFD": true, "SYS_SIGNALFD4": true, "SYS_USERFAULTFD": true,
	"SYS_FSOPEN": true, "SYS_FSMOUNT": true, "SYS_FSPICK": true, "SYS_OPEN_TREE": true, "SYS_OPEN_TREE_ATTR": true,
	"SYS_BPF": true, "SYS_SECCOMP": true, "SYS_LANDLOCK_CREATE_RULESET": true,
	// mq_open answers a message-queue descriptor; clone3 and clone with CLONE_PIDFD write a pidfd through a
	// pointer (clone3's flags are behind one too, so it always counts).
	"SYS_MQ_OPEN": true, "SYS_CLONE": true, "SYS_CLONE3": true,
	// recvmsg and recvmmsg install the descriptors an SCM_RIGHTS message carries, with flags behind a pointer F9
	// cannot read; unix.Recvmsg's are read (recvRules).
	"SYS_RECVMSG": true, "SYS_RECVMMSG": true,
	// macOS's (the maze setup tool's darwin build, ADR 0023's 2026-10-24 F6 note): kqueue, the _nocancel, guarded,
	// data-protection and by-id opens, socket_delegate, peeloff, fileport_makefd, the POSIX shared memory and
	// semaphore opens (each a descriptor in xnu), the NECP and Skywalk opens, and the receives that install
	// SCM_RIGHTS descriptors. Under a darwin build any other raw trap is a finding too (syscall in check.go).
	"SYS_KQUEUE": true, "SYS_GUARDED_KQUEUE_NP": true, "SYS_OPEN_NOCANCEL": true, "SYS_OPENAT_NOCANCEL": true,
	"SYS_OPEN_EXTENDED": true, "SYS_OPEN_DPROTECTED_NP": true, "SYS_GUARDED_OPEN_NP": true,
	"SYS_GUARDED_OPEN_DPROTECTED_NP": true, "SYS_OPENBYID_NP": true, "SYS_FHOPEN": true, "SYS_ACCEPT_NOCANCEL": true,
	"SYS_SOCKET_DELEGATE": true, "SYS_PEELOFF": true, "SYS_FILEPORT_MAKEFD": true, "SYS_SHM_OPEN": true,
	"SYS_SEM_OPEN": true, "SYS_NECP_OPEN": true, "SYS_NECP_SESSION_OPEN": true, "SYS___CHANNEL_OPEN": true,
	"SYS___NEXUS_OPEN": true, "SYS_RECVMSG_NOCANCEL": true, "SYS_RECVMSG_X": true,
}

// recvRule is where an x/sys or syscall recvmsg wrapper's control buffer and flags are: with a control buffer
// that is not nil, the kernel installs every descriptor an SCM_RIGHTS message carries, so the flags carry
// MSG_CMSG_CLOEXEC (F9), as net's ReadMsgUnix does, and sys.ReceiveRights owns them.
type recvRule struct{ oob, flags int }

var recvRules = map[string]recvRule{"Recvmsg": {2, 3}, "RecvmsgBuffers": {2, 3}}

// ioctlAllowed are the ioctl requests a raw SYS_IOCTL or an x/sys wrapper that takes one may name (A10 F5): none answers a
// descriptor of this process. Others do (TIOCGPTPEER, NS_GET_USERNS, NS_GET_PARENT, KVM_CREATE_VM, ...), so a
// request outside the list, or not a named constant, is a finding. SECCOMP_IOCTL_NOTIF_ADDFD answers the number
// it installed in the target's table, not one of ours. TIOCGETA and TIOCSETA are macOS's TCGETS and TCSETS (the
// maze setup tool's darwin build): they read and set a termios and answer nothing else.
var ioctlAllowed = map[string]bool{
	"SECCOMP_IOCTL_NOTIF_RECV": true, "SECCOMP_IOCTL_NOTIF_SEND": true, "SECCOMP_IOCTL_NOTIF_ID_VALID": true,
	"SECCOMP_IOCTL_NOTIF_SET_FLAGS": true, "SECCOMP_IOCTL_NOTIF_ADDFD": true,
	"TCGETS": true, "TCSETS": true, "TCSETSW": true, "TCSETSF": true, "TIOCGWINSZ": true, "TIOCSWINSZ": true,
	"TIOCINQ": true, "TIOCOUTQ": true, "FIONREAD": true, "FIONBIO": true, "TIOCSCTTY": true, "TIOCNOTTY": true,
	"TIOCGPGRP": true, "TIOCSPGRP": true, "NS_GET_NSTYPE": true, "FS_IOC_GETFLAGS": true, "FS_IOC_SETFLAGS": true,
	"TIOCGETA": true, "TIOCSETA": true,
}

// ioctlReqWrappers are the x/sys ioctl wrappers whose second argument is the request. Each one throws ioctl's
// return value away or answers it, and for a request such as TIOCGPTPEER or NS_GET_USERNS that value is a new
// descriptor, so the request runs ioctlAllowed exactly as a raw SYS_IOCTL does.
var ioctlReqWrappers = map[string]bool{
	"IoctlRetInt": true, "IoctlGetInt": true, "IoctlGetUint32": true, "IoctlGetTermios": true, "IoctlGetWinsize": true,
	"IoctlSetInt": true, "IoctlSetPointerInt": true, "IoctlSetString": true, "IoctlSetTermios": true,
	"IoctlSetWinsize": true, "IoctlIfreq": true,
}

// ioctlFixed are the x/sys ioctl wrappers whose request is built in and answers no descriptor. IoctlKCMClone,
// whose SIOCKCMCLONE answers a new KCM socket inside its struct, is a producer instead (otherShapes). Any other
// Ioctl* name, one an x/sys bump adds, is a finding until it is classified here.
var ioctlFixed = map[string]bool{
	"IoctlFileClone": true, "IoctlFileCloneRange": true, "IoctlFileDedupeRange": true,
	"IoctlGetEthtoolDrvinfo": true, "IoctlGetEthtoolTsInfo": true, "IoctlGetHwTstamp": true, "IoctlSetHwTstamp": true,
	"IoctlGetRTCTime": true, "IoctlGetRTCWkAlrm": true, "IoctlSetRTCTime": true, "IoctlSetRTCWkAlrm": true,
	"IoctlGetWatchdogInfo": true, "IoctlWatchdogKeepalive": true,
	"IoctlHIDGetDesc": true, "IoctlHIDGetRawInfo": true, "IoctlHIDGetRawName": true, "IoctlHIDGetRawPhys": true,
	"IoctlHIDGetRawUniq": true, "IoctlKCMAttach": true, "IoctlKCMUnattach": true,
	"IoctlLoopConfigure": true, "IoctlLoopGetStatus64": true, "IoctlLoopSetStatus64": true, "IoctlPidfdInfo": true,
	"IoctlPtpClockGetcaps": true, "IoctlPtpExttsRequest": true, "IoctlPtpPeroutRequest": true,
	"IoctlPtpPinGetfunc": true, "IoctlPtpPinSetfunc": true, "IoctlPtpSysOffsetExtended": true,
	"IoctlPtpSysOffsetPrecise": true,
	// macOS's: CTLIOCGINFO, SIOCGIFMTU and SIOCSIFMTU.
	"IoctlCtlInfo": true, "IoctlGetIfreqMTU": true, "IoctlSetIfreqMTU": true,
}

// bpfFDCommands are the bpf(2) commands whose result is a descriptor (A10 F1).
var bpfFDCommands = map[string]bool{
	"BPF_MAP_CREATE": true, "BPF_PROG_LOAD": true, "BPF_OBJ_GET": true, "BPF_PROG_GET_FD_BY_ID": true,
	"BPF_MAP_GET_FD_BY_ID": true, "BPF_LINK_GET_FD_BY_ID": true, "BPF_BTF_LOAD": true, "BPF_BTF_GET_FD_BY_ID": true,
	"BPF_LINK_CREATE": true, "BPF_ITER_CREATE": true, "BPF_RAW_TRACEPOINT_OPEN": true, "BPF_TOKEN_CREATE": true,
}

// ownSyscallTraps are the traps sys.OwnSyscall admits outright (A10 F1); SYS_BPF, SYS_SECCOMP and
// SYS_LANDLOCK_CREATE_RULESET are admitted by command or flags.
var ownSyscallTraps = map[string]bool{
	"SYS_MEMFD_CREATE": true, "SYS_PIDFD_OPEN": true, "SYS_PIDFD_GETFD": true, "SYS_OPENAT2": true,
	"SYS_PERF_EVENT_OPEN": true,
}

// fcntlAllowed are the fcntl commands that neither make nor alias a descriptor (A10 F5).
var fcntlAllowed = map[string]bool{
	"F_GETFD": true, "F_SETFD": true, "F_GETFL": true, "F_SETFL": true, "F_GETPIPE_SZ": true, "F_SETPIPE_SZ": true,
	"F_ADD_SEALS": true, "F_GET_SEALS": true, "F_OFD_GETLK": true, "F_OFD_SETLK": true, "F_OFD_SETLKW": true,
}

// cloexecRule is where a producer's flags are and which constant must be in them (A10 F9). arg -1 means the
// producer has no flags argument and so never makes its number close-on-exec, or (unread set) has flags F9
// cannot read: always a finding. kernel means the kernel always makes the number close-on-exec, so there is
// nothing to check.
type cloexecRule struct {
	arg    int
	flag   string
	kernel bool
	how    bool   // the flags are the Flags field of an OpenHow composite literal at arg
	unread string // why the flags cannot be read, and the form to write instead
}

var cloexecRules = map[string]cloexecRule{
	"Open":           {arg: 1, flag: "O_CLOEXEC"},
	"Openat":         {arg: 2, flag: "O_CLOEXEC"},
	"Openat2":        {arg: 2, flag: "O_CLOEXEC", how: true},
	"OpenByHandleAt": {arg: 2, flag: "O_CLOEXEC"},
	"Creat":          {arg: -1},
	"Socket":         {arg: 1, flag: "SOCK_CLOEXEC"},
	"InotifyInit":    {arg: -1},
	"InotifyInit1":   {arg: 0, flag: "IN_CLOEXEC"},
	"FanotifyInit":   {arg: 0, flag: "FAN_CLOEXEC"},
	"EpollCreate":    {arg: -1},
	"EpollCreate1":   {arg: 0, flag: "EPOLL_CLOEXEC"},
	"Eventfd":        {arg: 1, flag: "EFD_CLOEXEC"},
	"MemfdCreate":    {arg: 1, flag: "MFD_CLOEXEC"},
	"TimerfdCreate":  {arg: 1, flag: "TFD_CLOEXEC"},
	"Signalfd":       {arg: 2, flag: "SFD_CLOEXEC"},
	"Fsopen":         {arg: 1, flag: "FSOPEN_CLOEXEC"},
	"Fsmount":        {arg: 1, flag: "FSMOUNT_CLOEXEC"},
	"OpenTree":       {arg: 2, flag: "OPEN_TREE_CLOEXEC"},
	"Fspick":         {arg: 2, flag: "FSPICK_CLOEXEC"},
	"PerfEventOpen":  {arg: 4, flag: "PERF_FLAG_FD_CLOEXEC"},
	"PidfdOpen":      {kernel: true},
	"PidfdGetfd":     {kernel: true},
	// sys's own int producers: pidfds, the seccomp listener and the landlock ruleset are close-on-exec by the
	// kernel.
	"PidfdOpenProcess": {kernel: true}, "PidfdOpenThread": {kernel: true},
	"SeccompSetFilterNewListener": {kernel: true}, "LandlockCreateRuleset": {kernel: true},
}

// ownSyscallCloexec are the admitted raw traps whose flags F9 checks, by argument index of the Syscall call
// (the trap is argument 0).
var ownSyscallCloexec = map[string]cloexecRule{
	"SYS_MEMFD_CREATE":    {arg: 2, flag: "MFD_CLOEXEC"},
	"SYS_PERF_EVENT_OPEN": {arg: 5, flag: "PERF_FLAG_FD_CLOEXEC"},
	"SYS_OPENAT2": {arg: -1, unread: "a raw SYS_OPENAT2's flags sit behind a pointer F9 cannot read: write " +
		"sys.Own(unix.Openat2(dirfd, path, &unix.OpenHow{Flags: ...|unix.O_CLOEXEC})), whose literal it reads"},
}

// sysIntProducers are sys's own functions that return a fresh number as an int; their owner forms are the
// ...FD helpers. sys.Own may wrap them; any other call outside the owner's files is a raw site.
var sysIntProducers = map[string]bool{
	"PidfdOpenProcess": true, "PidfdOpenThread": true, "PidfdGetfd": true,
	"SeccompSetFilterNewListener": true, "LandlockCreateRuleset": true,
}

// sweepFunc closes every number from its argument up, owned or not (ADR 0023 A10, the reaper's start-up sweep):
// close_range under another name, so it is an F4 listed site, like Inherited, whose premise it shares.
const sweepFunc = "CloseInheritedFrom"

// sysConstructors are the sys calls whose result is a fresh owner, for sys.Strict's argument.
var sysConstructors = map[string]bool{
	"Own": true, "OwnSyscall": true, "Adopt": true, "Inherited": true, "Stdio": true, "DupFile": true,
	"PidfdOpenProcessFD": true, "PidfdOpenThreadFD": true, "PidfdGetfdFD": true, "SeccompNewListenerFD": true,
	"LandlockCreateRulesetFD": true, "PeerPidfdFD": true,
}

// ownerMethods are the *sys.FD methods whose result is a fresh owner, for sys.Strict's argument.
var ownerMethods = map[string]bool{"Dup": true, "Openat": true, "Openat2": true}

// takers are the cilium constructors that take ownership of a number: ReleaseNumber's only place (F3).
func taker(path, name string) bool {
	return (path == pathLink && name == "NewFromFD") ||
		(path == pathEBPF && (name == "NewMapFromFD" || name == "NewProgramFromFD"))
}

// ownerFileNames are the sys owner's files (ADR 0023 A7, with inert.go from its C2 note), without ".go": exempt
// from every rule, here and in .golangci.yml's first permanent exemption.
var ownerFileNames = []string{"fd", "fd_lease", "fd_errors", "fd_inherited", "fd_testhooks", "pidfd", "cloexec",
	"filedo", "rights", "pipe", "dupover_testhook", "inert"}

var ownerFiles = func() map[string]bool {
	m := map[string]bool{}
	for _, n := range ownerFileNames {
		m[n+".go"] = true
	}
	return m
}()

// permanentExclusions are A7's two permanent ADR 0023 exemptions in .golangci.yml, exactly: the owner's files, and
// test code, internal/testutil, tools, test and internal/bpf's leased borrow (what Exempt exempts). Any other
// exclusion that would hide an ADR 0023 rule must be one package's own files, which baseline.txt lists.
var permanentExclusions = []string{
	`^internal/platform/sys/(` + strings.Join(ownerFileNames, "|") + `)\.go$`,
	`(_test\.go$|internal/testutil/|^tools/|^test/|^internal/bpf/fdborrow\.go$)`,
}

// Exempt is whether a file is outside every rule (ADR 0023 A7): tests, internal/testutil, tools, test, the
// owner's files, internal/bpf/fdborrow.go, and fixtures under a testdata directory, which no build reaches
// (F11 checks that).
func Exempt(f string) bool {
	if strings.HasSuffix(f, "_test.go") || !strings.HasSuffix(f, ".go") {
		return true
	}
	for _, p := range []string{"internal/testutil/", "tools/", "test/"} {
		if strings.HasPrefix(f, p) {
			return true
		}
	}
	if f == "internal/bpf/fdborrow.go" || strings.HasPrefix(f, "testdata/") || strings.Contains(f, "/testdata/") {
		return true
	}
	dir, base := splitDir(f)
	return dir == sysDir && ownerFiles[base]
}

func splitDir(f string) (dir, base string) {
	i := strings.LastIndex(f, "/")
	if i < 0 {
		return ".", f
	}
	return f[:i], f[i+1:]
}
