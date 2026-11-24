// SPDX-License-Identifier: Apache-2.0

package runscope

import (
	"bytes"
	"errors"
	"strconv"
	"syscall"
)

// The kernel's fixed numbers the rule compares with (include/uapi/linux/nsfs.h, include/linux/proc_ns.h,
// include/uapi/linux/magic.h). InitCgroupNS, the first cgroup namespace's inode, is in looks.go.
const (
	// InitUserNS is the inode of the first user namespace (PROC_USER_INIT_INO). No namespace made later has it.
	InitUserNS uint64 = 0xEFFFFFFD
	// CgroupNSType is what NS_GET_NSTYPE answers on a cgroup namespace file: CLONE_NEWCGROUP.
	CgroupNSType = 0x02000000
	// InitScope is the cgroup systemd keeps itself in, as pid 1 and as a user's manager.
	InitScope = "/init.scope"
)

// runtimeRoot is where logind makes each user's runtime folder (pkg/spec/config.LogindRuntimeRoot, which this leaf
// cannot import; internal/cli's TestManagerSocketUsesLogindRoot holds the two together). XDG_RUNTIME_DIR is never read.
const runtimeRoot = "/run/user"

// ManagerCgroup is the one cgroup uid's service manager (systemd --user) lives in, from the cgroup hierarchy's
// root: the path the listener on ManagerSocket must be in, byte for byte.
func ManagerCgroup(uid int) string {
	u := strconv.Itoa(uid)
	return "/user.slice/user-" + u + ".slice/user@" + u + ".service" + InitScope
}

// ManagerSocket is the private socket uid's service manager listens on, an absolute path.
func ManagerSocket(uid int) string {
	return runtimeRoot + "/" + strconv.Itoa(uid) + "/systemd/private"
}

// Namespace is a namespace file as fstat showed it, on a descriptor fstatfs showed to be nsfs.
type Namespace struct{ Dev, Ino uint64 }

// ErrUnanchored is the error of a read that could not be tied to the kernel's own /proc: the /proc descriptor is no
// procfs root, or an anchored open failed (it crossed a mount, met a magic link, or the kernel has no openat2).
var ErrUnanchored = errors.New("runscope: the read is not anchored in the kernel's /proc")

// Facts are the reads the rule makes of the calling process, in the rule's order. Decide calls each at most once and
// calls none after the one that settles the answer, so an implementation may make its system calls lazily. The
// kernel's implementation is internal/platform/peer's; the tests give tables.
type Facts interface {
	// OwnCgroup is the bytes of /proc/self/cgroup, read by its absolute path (step 1).
	OwnCgroup() ([]byte, error)
	// CgroupNS is this process's cgroup namespace: /proc/self/ns/cgroup opened for reading, shown by fstatfs to be a
	// namespace file, and its fstat (step 2). Any failure is an error.
	CgroupNS() (Namespace, error)
	// UIDs are getresuid's three (step 4a).
	UIDs() (real, effective, saved int)
	// Permitted is capget's permitted set of this process (step 4b).
	Permitted() (uint64, error)
	// Seccomp is prctl(PR_GET_SECCOMP): 0 with no filter. It is read after step 4b and recorded on the answer for a
	// diagnostic (Describe), never judged: the signed rule's fact 4c is removed (ADR 0100, 2026-11-19).
	Seccomp() (int, error)
	// AnchoredCgroup is this process's cgroup file read again, as self/cgroup through a /proc descriptor shown to be
	// the root of a procfs (step 5). An anchoring failure wraps ErrUnanchored; any other error is the read's.
	AnchoredCgroup() ([]byte, error)
	// Proof is steps 6 to 9 for this namespace and uid: a proof held, a recent failure, or one bounded probe (Prove).
	Proof(ns Namespace, uid int) Answer
	// Withheld is the gate: a cause for which an answer every fact supports is still not given, and whether there is
	// one. It is asked only where the answer would otherwise be Outside: in the kernel's first cgroup namespace
	// (first true) after the namespace file, and in any other after Proof answered Outside.
	Withheld(first bool) (Cause, bool)
}

// Decide is the rule: whether the calling process is outside every tego run made inside its own cgroup namespace,
// over the facts f reads. It is computed in the caller's own process, so it is the refusal an honest tego gives and
// not a boundary: a process that controls the tego it starts controls the answer.
//
// In the kernel's first cgroup namespace (ordinary Linux) the answer is the path's alone, and nothing of the caller
// beyond the path and the namespace file is read. In any other, a path that shows no run is Outside only when the
// caller is an
// unprivileged process whose cgroup namespace is owned by the first user namespace, whose pid 1 sits in /init.scope,
// and whose user's service manager, in its exact cgroup, answers on its socket (Prove). The caller's seccomp mode is
// read there too and recorded on the answer, never judged. In either branch an answer of Outside then meets the gate
// (Facts.Withheld), which holds it back as Unknown where the rule is not proven yet: on WSL in both branches, and
// outside WSL beyond the first namespace (ADR 0100, amended 2026-11-19).
func Decide(f Facts) Answer {
	b, err := f.OwnCgroup()
	if a, settled := ownPath(b, err); settled {
		return a
	}
	ns, err := f.CgroupNS()
	if err != nil {
		return unknown(CauseNSUnreadable, err)
	}
	if ns.Ino == InitCgroupNS {
		if c, held := f.Withheld(true); held {
			return unknown(c, nil)
		}
		return Answer{verdict: Outside}
	}
	real, effective, saved := f.UIDs()
	if real != effective || effective != saved {
		return unknown(CauseMixedIDs, nil)
	}
	if real == 0 {
		return unknown(CauseRootCaller, nil)
	}
	if permitted, err := f.Permitted(); err != nil || permitted != 0 {
		return unknown(CauseCapabilities, err)
	}
	mode, err := f.Seccomp()
	a := beyondTheCaller(f, ns, real)
	a.seccomp = seccompNote{read: true, mode: mode, err: err}
	return a
}

// beyondTheCaller is the rule after the caller's own facts held, outside the first namespace: the anchored path
// (step 5), the proof (steps 6 to 9) and the gate.
func beyondTheCaller(f Facts, ns Namespace, real int) Answer {
	b, err := f.AnchoredCgroup()
	if errors.Is(err, ErrUnanchored) {
		return unknown(CauseProcUnanchored, err)
	}
	if a, settled := ownPath(b, err); settled {
		return a
	}
	a := f.Proof(ns, real)
	if !a.Outside() {
		if a.verdict == Inside || a.cause == "" { // an implementation's zero value is a failed proof, never a run
			return WithProbeTime(unknown(CauseProbeError, a.err), a.probe)
		}
		return a
	}
	if c, held := f.Withheld(false); held {
		return WithProbeTime(unknown(c, nil), a.probe)
	}
	return a
}

// ownPath is step 1 over what a read of the process's own cgroup file returned: whether the path settles the answer
// as Inside. An unreadable file, one that names no single absolute cgroup v2 path, a path above the namespace root
// and a path that looks governed each do.
func ownPath(b []byte, readErr error) (Answer, bool) {
	if readErr != nil {
		return inside(CausePathUnreadable, readErr), true
	}
	cg, err := Unified(b)
	if err != nil {
		return inside(CausePathMalformed, err), true
	}
	if OutsideNamespace(cg) {
		return inside(CausePathAboveRoot, nil), true
	}
	if LooksGoverned(cg) {
		return inside(CauseGoverned, nil), true
	}
	return Answer{}, false
}

// Owner is what NS_GET_USERNS answered on the cgroup namespace file: whether fstatfs shows the result to be a
// namespace file, and its fstat.
type Owner struct {
	NSFS     bool
	Dev, Ino uint64
}

// Prober is the reads of one probe, each a single fact. Prove calls them in the rule's order and stops at the first
// that fails; an implementation closes whatever it opened when the probe ends. There is no pidfd_open among them:
// below Linux 6.5 the answer is unknown.
type Prober interface {
	// NSType is NS_GET_NSTYPE on the verified cgroup namespace descriptor.
	NSType() (int, error)
	// Owner is NS_GET_USERNS on that descriptor, checked and closed.
	Owner() (Owner, error)
	// InitCgroup is 1/cgroup read through the anchored /proc. An anchoring failure wraps ErrUnanchored.
	InitCgroup() ([]byte, error)
	// Connect connects a non-blocking, close-on-exec stream socket to the manager's socket and sends nothing. It
	// retries EAGAIN to its deadline and then returns it. The error is the connect's errno.
	Connect() error
	// PeerCred is SO_PEERCRED on the connected socket.
	PeerCred() (uid, pid int, err error)
	// PeerPidfd takes the listener's pidfd with SO_PEERPIDFD: ENOPROTOOPT where the kernel has none.
	PeerPidfd() error
	// PidfdPID is the Pid: line of that pidfd's fdinfo, read through the anchored /proc.
	PidfdPID() (int, error)
	// PeerCgroup is <pid>/cgroup read through the anchored /proc. No other file of the peer is opened.
	PeerCgroup(pid int) ([]byte, error)
	// PeerExited polls the pidfd.
	PeerExited() (bool, error)
}

// Prove is the probe, step 8 of the rule, over p's reads for a caller of uid in cgroup namespace ns: Outside when
// facts (a), (b) and (c') all hold, otherwise Unknown with the first failing cause.
//
// (a) The cgroup namespace is owned by the first user namespace. ns_get_owner answers EPERM unless the owner is the
// caller's user namespace or below it, so the first user namespace's inode on a real namespace file of the same
// device proves the caller is in the first user namespace too, and only a holder of CAP_SYS_ADMIN there can have
// made the namespace. (b) Pid 1 of this /proc is exactly in /init.scope, which pins the namespace root to the top
// of a systemd tree. (c') The listener on the user manager's socket is a live process of this uid whose cgroup,
// rendered by the kernel from this reader's namespace root, is exactly the manager's.
func Prove(p Prober, ns Namespace, uid int) Answer {
	// (a)
	if t, err := p.NSType(); err != nil || t != CgroupNSType {
		return unknown(CauseUserNamespace, err)
	}
	o, err := p.Owner()
	if err != nil || !o.NSFS || o.Ino != InitUserNS || o.Dev != ns.Dev {
		return unknown(CauseUserNamespace, err)
	}
	// (b), before any socket
	b, err := p.InitCgroup()
	switch {
	case errors.Is(err, ErrUnanchored):
		return unknown(CauseProcUnanchored, err)
	case err != nil:
		return unknown(CauseInitUnreadable, err)
	}
	if cg, err := Unified(b); err != nil || cg != InitScope {
		return unknown(CauseInitNotAtRoot, err)
	}
	// (c')
	if err := p.Connect(); err != nil {
		return unknown(connectCause(err), err)
	}
	peerUID, pid, err := p.PeerCred()
	switch {
	case err != nil:
		return unknown(CausePeerUnidentified, err)
	case peerUID != uid:
		return unknown(CausePeerUID, nil)
	case pid <= 0:
		return unknown(CausePeerUnidentified, nil)
	}
	if err := p.PeerPidfd(); errors.Is(err, syscall.ENOPROTOOPT) {
		return unknown(CauseNoPeerPidfd, err)
	} else if err != nil {
		return unknown(CausePeerUnidentified, err)
	}
	if shown, err := p.PidfdPID(); err != nil || shown != pid {
		return unknown(CausePeerUnidentified, err)
	}
	b, err = p.PeerCgroup(pid)
	if err != nil {
		return unknown(CausePeerUnidentified, err)
	}
	cg, err := Unified(b)
	if err != nil {
		return unknown(CausePeerUnidentified, err)
	}
	if shown, err := p.PidfdPID(); err != nil || shown != pid {
		return unknown(CausePeerUnidentified, err)
	}
	if exited, err := p.PeerExited(); err != nil || exited {
		return unknown(CausePeerUnidentified, err)
	}
	if cg != ManagerCgroup(uid) {
		return unknown(CausePeerElsewhere, nil)
	}
	return Answer{verdict: Outside}
}

// connectCause is the cause of a failed connect to the manager's socket.
func connectCause(err error) Cause {
	switch {
	case errors.Is(err, syscall.ENOENT), errors.Is(err, syscall.ENOTDIR):
		return CauseNoUserManager
	case errors.Is(err, syscall.ECONNREFUSED):
		return CauseManagerNotListening
	case errors.Is(err, syscall.EAGAIN):
		return CauseManagerBusy
	case errors.Is(err, syscall.EACCES), errors.Is(err, syscall.EPERM):
		return CauseSocketRefused
	}
	return CauseProbeError
}

// ErrNoPidLine is a pidfd's fdinfo with no well-formed "Pid:" line.
var ErrNoPidLine = errors.New("runscope: the pidfd's fdinfo has no single Pid: line holding a number")

// FdinfoPid is the number on the "Pid:" line of a pidfd's fdinfo: the process's pid in the pid namespace of the
// procfs read, 0 when it has none there and -1 once it is reaped (pidfd_show_fdinfo). Exactly one such line, holding
// one decimal number, or ErrNoPidLine. Pure and total (FuzzFdinfoPid).
func FdinfoPid(fdinfo []byte) (int, error) {
	found, n := 0, 0
	for line := range bytes.SplitSeq(fdinfo, []byte("\n")) {
		v, ok := bytes.CutPrefix(line, []byte("Pid:"))
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(string(bytes.TrimSpace(v)))
		if err != nil {
			return 0, ErrNoPidLine
		}
		found, n = pid, n+1
	}
	if n != 1 {
		return 0, ErrNoPidLine
	}
	return found, nil
}
