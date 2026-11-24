// SPDX-License-Identifier: Apache-2.0

package peer

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Peer is the process at the other end of a unix socket connection, as Identify read and proved it.
type Peer struct {
	// UID and PID are SO_PEERCRED's: the effective uid and the process id of the process that connected, as the
	// kernel recorded them at the connect, in this process's user and pid namespaces.
	UID, PID int
	// Cgroup is the peer's unified (cgroup v2) path, relative to this process's cgroup namespace root.
	Cgroup string
	// CgroupNS is the inode of the peer's cgroup namespace; 0 when it could not be read (another uid's process, or a
	// non-dumpable one), which Refuse refuses unless Undumpable says why it is hidden.
	CgroupNS uint64
	// Undumpable is set only when CgroupNS is 0 and the kernel's own files show the reason: the peer has the dumpable
	// flag at 0 (its /proc/<pid>/environ belongs to another uid than its own), its real, effective, saved and filesystem
	// uids are all the connecting uid, and it holds no capability. A process that holds a secret makes itself so
	// (sys.MakeUndumpable), and /proc then hides its namespace files from every reader without CAP_SYS_PTRACE. It says
	// nothing of where the peer is: its cgroup path, read from this process's own namespace, is as readable as anyone's,
	// and Refuse judges it exactly as it does a dumpable peer's (ADR 0100 (7), amended 2026-11-22).
	Undumpable bool
	// StartBootNS is the peer's start time (/proc/<pid>/stat), which tells it from a later process with its pid.
	StartBootNS uint64
	// PidfdFallback is set when the kernel has no SO_PEERPIDFD (below Linux 6.5) and the pidfd was opened on the pid
	// instead: a pid reused between the connect and that open is not detected. A caller discloses it
	// (WarnPidfdFallback).
	PidfdFallback bool
}

// The bracketed codes a Refusal carries, and the warning a caller gives for a PidfdFallback peer.
const (
	CodeUnidentified  = "peer-unidentified" // Identify could not read or prove who connected
	CodeUnmappedUID   = "unmapped-uid"      // another uid than the socket owner's, or one this namespace cannot map
	CodeRunMember     = "run-member"        // inside a run's or an adoption's scope, or a look-alike of one
	CodeCgroupNS      = "peer-cgroupns"     // another or an unreadable cgroup namespace, above this one's root, or this process outside the initial one
	WarnPidfdFallback = "peer-pidfd-fallback"
)

// Refusal is why a connection's peer is not served. It is an error; Err, when set, is the read that failed.
type Refusal struct {
	Code   string
	Detail string
	Err    error
}

func (r *Refusal) Error() string {
	what := "peer refused: " + r.Detail
	if r.Err != nil {
		what += ": " + r.Err.Error()
	}
	return identity.FormatMessage("", 0, 0, what, r.Code)
}

func (r *Refusal) Unwrap() error { return r.Err }

// ErrExited is a peer whose connecting process had exited by the end of the reads: what was read under its pid may
// be another process's.
var ErrExited = errors.New("peer: the connecting process has exited")

// unidentified is a Refusal [peer-unidentified].
func unidentified(err error, format string, args ...any) error {
	return &Refusal{Code: CodeUnidentified, Detail: fmt.Sprintf(format, args...), Err: err}
}

// procFS is what Identify reads of a pid. dirFS is the kernel's /proc; tests give a fixture tree, or one that
// changes between reads.
type procFS interface {
	pidfdPID(pidfd *sys.FD) (int, error)
	cgroup(pid int) ([]byte, error)
	leaderState(pid int) (byte, error)
	threadCgroups(pid int) (map[int][]byte, error)
	cgroupNS(pid int) (uint64, error)
	undumpable(pid, uid int) (bool, error)
	startBootNS(pid int) (uint64, error)
	owner(pid int) (int, error)
}

// pidfdPID is the pid this tree shows for the process pidfd names: the "Pid:" line of the pidfd's fdinfo, read
// through the tree's own self, so the number is in the pid namespace of the mount the other reads go to (the
// kernel's pidfd_show_fdinfo takes the namespace from the procfs instance read). It is 0 when the process has no pid
// in that namespace and -1 once it has been reaped. procfs looks the number up when the fdinfo is read, so the open,
// the read and the close all run while pidfd's number is lent.
func (d dirFS) pidfdPID(pidfd *sys.FD) (int, error) {
	var b []byte
	if err := pidfd.Borrow(func(n int) error {
		f, err := sys.Own(unix.Open(string(d)+"/self/fdinfo/"+strconv.Itoa(n), unix.O_RDONLY|unix.O_CLOEXEC, 0))
		if err != nil {
			return fmt.Errorf("open the pidfd's fdinfo under %s/self: %w", string(d), err)
		}
		file, err := f.Release("fdinfo")
		if err != nil {
			_ = f.Close()
			return err
		}
		defer func() { _ = file.Close() }()
		b, err = io.ReadAll(file)
		return err
	}); err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "Pid:"); ok {
			return strconv.Atoi(strings.TrimSpace(v))
		}
	}
	return 0, errors.New("the pidfd's fdinfo has no Pid: line")
}

// dirFS reads a proc tree rooted at its value.
type dirFS string

func (d dirFS) path(pid int, name string) string {
	return filepath.Join(string(d), strconv.Itoa(pid), name)
}

func (d dirFS) cgroup(pid int) ([]byte, error) { return os.ReadFile(d.path(pid, "cgroup")) }

// leaderState is the state of pid's first thread, the thread-group leader (field 3 of /proc/<pid>/stat): Z once that
// thread has exited, whether or not other threads of the process run on.
func (d dirFS) leaderState(pid int) (byte, error) {
	st, err := proc.NewAt(string(d)).Stat(pid)
	if err != nil {
		return 0, err
	}
	return st.State, nil
}

// maxThreads bounds how many threads of one peer are read; a peer with more is refused.
const maxThreads = 16384

// threadCgroups is the cgroup file of every thread of pid, by thread id (/proc/<pid>/task/<tid>/cgroup). A thread
// that exited between the listing and its read (no file, or ESRCH from the read) is in no cgroup and is left out.
// Anything else that is not a thread's readable file is an error.
func (d dirFS) threadCgroups(pid int) (map[int][]byte, error) {
	dir := d.path(pid, "task")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(entries) > maxThreads {
		return nil, fmt.Errorf("%s lists %d threads, more than the %d this check reads", dir, len(entries), maxThreads)
	}
	out := make(map[int][]byte, len(entries))
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err != nil || tid <= 0 {
			return nil, fmt.Errorf("%s holds %q, which is no thread id", dir, e.Name())
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name(), "cgroup"))
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out[tid] = b
	}
	return out, nil
}

// cgroupNS is the inode of pid's cgroup namespace. Reading another uid's or a non-dumpable process's namespace is
// refused by the kernel (ptrace read access); that is 0 with no error, for Refuse to refuse.
func (d dirFS) cgroupNS(pid int) (uint64, error) {
	var st unix.Stat_t
	err := unix.Stat(d.path(pid, "ns/cgroup"), &st)
	switch {
	case errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM):
		return 0, nil
	case err != nil:
		return 0, fmt.Errorf("stat %s: %w", d.path(pid, "ns/cgroup"), err)
	}
	return st.Ino, nil
}

// undumpable reports whether pid's namespace files are hidden for the one reason a process of uid hides them from its
// own user's other processes, the dumpable flag at 0, and for no other. The kernel shows the flag in the owner of the
// process's per-process files: /proc/<pid>/environ (mode 0400) belongs to the process's effective uid while it is
// dumpable, and to the root of its memory's user namespace otherwise (task_dump_owner), which is root for every
// process Tego starts and never a uid that maps to a person's. Reading ns/cgroup needs ptrace read access, which
// the kernel also refuses a caller that does not hold the process's capabilities or whose uid is not all four of the
// process's (__ptrace_may_access), so those are held to nothing: all four uids are uid, and the permitted capability
// set is empty. A process that fails any of the three is not undumpable here, and Refuse refuses it as before. Every
// read here is of files that stay readable whatever the flag.
func (d dirFS) undumpable(pid, uid int) (bool, error) {
	var st unix.Stat_t
	if err := unix.Lstat(d.path(pid, "environ"), &st); err != nil {
		return false, err
	}
	if int(st.Uid) == uid {
		return false, nil // dumpable, or one whose root is the peer's own uid
	}
	b, err := os.ReadFile(d.path(pid, "status"))
	if err != nil {
		return false, err
	}
	return statusHoldsNothing(b, uid)
}

// statusHoldsNothing reads a /proc/<pid>/status: true when its Uid line is uid four times and its CapPrm line is zero.
// A status that lacks either line, or shows them twice, is an error: it is not a kernel's.
func statusHoldsNothing(status []byte, uid int) (bool, error) {
	var uids, caps int
	same, empty := false, false
	for line := range strings.SplitSeq(string(status), "\n") {
		if v, ok := strings.CutPrefix(line, "Uid:"); ok {
			f := strings.Fields(v)
			uids++
			same = len(f) == 4
			for _, x := range f {
				same = same && x == strconv.Itoa(uid)
			}
		}
		if v, ok := strings.CutPrefix(line, "CapPrm:"); ok {
			caps++
			n, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			if err != nil {
				return false, fmt.Errorf("CapPrm line %q: %w", line, err)
			}
			empty = n == 0
		}
	}
	if uids != 1 || caps != 1 {
		return false, fmt.Errorf("the status file has %d Uid: and %d CapPrm: lines, want one of each", uids, caps)
	}
	return same && empty, nil
}

func (d dirFS) startBootNS(pid int) (uint64, error) {
	st, err := proc.NewAt(string(d)).Stat(pid)
	if err != nil {
		return 0, err
	}
	return st.StartBootNS(), nil
}

// owner is the uid /proc/<pid> belongs to: the process's effective uid, dumpable or not (task_dump_owner leaves a
// world-readable directory with its process's own uid; only the files below it go to root).
func (d dirFS) owner(pid int) (int, error) {
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join(string(d), strconv.Itoa(pid)), &st); err != nil {
		return 0, err
	}
	return int(st.Uid), nil
}

// host is where Identify reads. noPeerPidfd makes it act on a kernel without SO_PEERPIDFD, as the tests of the
// fallback do.
type host struct {
	proc        procFS
	noPeerPidfd bool
}

// kernel is the running system.
var kernel = host{proc: dirFS("/proc")}

// Identify reads and proves who is at the other end of c (see the package doc). Every failure is a Refusal
// [peer-unidentified]; a caller refuses the connection on any error. It does not judge the peer: Refuse does.
func Identify(c *net.UnixConn) (Peer, error) { return kernel.identify(c) }

func (h host) identify(c *net.UnixConn) (Peer, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return Peer{}, unidentified(err, "the connection has no descriptor")
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return Peer{}, unidentified(err, "the connection's descriptor is closed")
	}
	if credErr != nil {
		return Peer{}, unidentified(credErr, "SO_PEERCRED")
	}
	p := Peer{UID: int(cred.Uid), PID: int(cred.Pid)}
	if p.PID <= 0 {
		return Peer{}, unidentified(nil, "the connecting process is not in this pid namespace")
	}
	pidfd, err := h.peerPidfd(raw)
	if errors.Is(err, unix.ENOPROTOOPT) {
		p.PidfdFallback = true
		if pidfd, err = sys.PidfdOpenProcessFD(p.PID); err != nil {
			return Peer{}, unidentified(err, "pidfd_open of pid %d (no SO_PEERPIDFD on this kernel)", p.PID)
		}
	} else if err != nil {
		return Peer{}, unidentified(err, "SO_PEERPIDFD")
	}
	defer func() { _ = pidfd.Close() }()
	if err := h.read(&p, pidfd, raw); err != nil {
		return Peer{}, err
	}
	return p, nil
}

// peerPidfd is SO_PEERPIDFD's pidfd of the connection's peer, ENOPROTOOPT below Linux 6.5.
func (h host) peerPidfd(raw syscall.RawConn) (*sys.FD, error) {
	if h.noPeerPidfd {
		return nil, unix.ENOPROTOOPT
	}
	return sys.PeerPidfdFD(raw)
}

// read fills in what /proc says of p.PID, and proves it was the connecting process: /proc showing the pidfd's
// process as p.PID, its pidfd alive after every read and, on the fallback, the uid holding the pid, the start time
// unchanged and the connection still open.
func (h host) read(p *Peer, pidfd *sys.FD, raw syscall.RawConn) error {
	// SO_PEERCRED's pid is in this process's pid namespace, /proc's numbers in the namespace of whoever mounted it:
	// a process that entered a pid namespace without remounting /proc would read another process under p.PID. The
	// pid /proc shows for the pidfd's process ties the two together.
	shown, err := h.proc.pidfdPID(pidfd)
	if err != nil {
		return unidentified(err, "the pid /proc shows for the pidfd of pid %d", p.PID)
	}
	if shown != p.PID {
		return unidentified(nil, "/proc shows the connecting process as pid %d, not as pid %d: this /proc is not of this "+
			"process's pid namespace, or the process is gone", shown, p.PID)
	}
	var before uint64
	if p.PidfdFallback {
		if before, err = h.proc.startBootNS(p.PID); err != nil {
			return unidentified(err, "the start time of pid %d", p.PID)
		}
		owner, err := h.proc.owner(p.PID)
		if err != nil {
			return unidentified(err, "the owner of pid %d", p.PID)
		}
		if owner != p.UID {
			return unidentified(nil, "pid %d is now held by uid %d, not by the connecting uid %d", p.PID, owner, p.UID)
		}
	}
	b, err := h.proc.cgroup(p.PID)
	if err != nil {
		return unidentified(err, "the cgroup of pid %d", p.PID)
	}
	if p.Cgroup, err = runscope.Unified(b); err != nil {
		return unidentified(err, "the cgroup of pid %d", p.PID)
	}
	if err := h.everyThread(p); err != nil {
		return err
	}
	if p.CgroupNS, err = h.proc.cgroupNS(p.PID); err != nil {
		return unidentified(err, "the cgroup namespace of pid %d", p.PID)
	}
	if p.CgroupNS == 0 {
		if p.Undumpable, err = h.proc.undumpable(p.PID, p.UID); err != nil {
			return unidentified(err, "why the cgroup namespace of pid %d is hidden", p.PID)
		}
	}
	if p.StartBootNS, err = h.proc.startBootNS(p.PID); err != nil {
		return unidentified(err, "the start time of pid %d", p.PID)
	}
	if p.PidfdFallback {
		if p.StartBootNS != before {
			return unidentified(nil, "pid %d was taken by another process while it was read", p.PID)
		}
		if err := stillOpen(raw); err != nil {
			return unidentified(err, "the connection")
		}
	}
	exited, err := sys.PollPidfdFD(pidfd, 0)
	if err != nil {
		return unidentified(err, "the liveness of pid %d", p.PID)
	}
	if exited {
		return unidentified(ErrExited, "pid %d", p.PID)
	}
	return nil
}

// everyThread holds every thread of the peer to the cgroup its first thread's file names (p.Cgroup).
// /proc/<pid>/cgroup is the first thread's, and the kernel never moves a thread that has exited: a process whose first
// thread exited while others run on keeps that thread's old cgroup in the file after the process is moved (into an
// adoption's scope, say), and reads as outside every run while it is inside one (cgroup_migrate_add_task passes over
// a PF_EXITING task; proc_cgroup_show says a zombie "keeps reporting the cgroup it belonged to before exiting"). So a
// first thread that is a zombie is refused whatever the files say, and so is any thread whose file names another
// cgroup, or no single one. A launched run's processes are not affected (every thread is born in the scope, and an
// exec makes its caller the first thread); the refusal costs a process built this way its answer and nothing else.
func (h host) everyThread(p *Peer) error {
	state, err := h.proc.leaderState(p.PID)
	if err != nil {
		return unidentified(err, "the state of the first thread of pid %d", p.PID)
	}
	if state == 'Z' || state == 'X' {
		return unidentified(nil, "the first thread of pid %d has exited: its cgroup file names the cgroup that thread "+
			"exited in, which may not be where the process's other threads run", p.PID)
	}
	threads, err := h.proc.threadCgroups(p.PID)
	if err != nil {
		return unidentified(err, "the threads of pid %d", p.PID)
	}
	if len(threads) == 0 {
		return unidentified(nil, "pid %d shows no thread with a cgroup", p.PID)
	}
	for tid, b := range threads {
		cg, err := runscope.Unified(b)
		if err != nil {
			return unidentified(err, "the cgroup of thread %d of pid %d", tid, p.PID)
		}
		if cg != p.Cgroup {
			return unidentified(nil, "thread %d of pid %d is in cgroup %s, and the process's first thread in %s",
				tid, p.PID, cg, p.Cgroup)
		}
	}
	return nil
}

// errHungUp is a connection whose peer has closed its end.
var errHungUp = errors.New("the peer closed its end")

// hangup is what poll answers on a socket whose peer closed its end, or which has an error; poll reports all three
// whatever was asked. A peer's socket that is closed (the peer exited, or closed it) shuts both directions down,
// which is POLLHUP (unix_release_sock, unix_poll). POLLRDHUP is not among them: it is a peer that shut down only its
// writing side (shutdown(SHUT_WR), as nc -N does once it has sent its request), which still holds its socket and
// reads the reply, and SO_PEERPIDFD's path serves it too.
const hangup = unix.POLLHUP | unix.POLLERR | unix.POLLNVAL

// stillOpen fails when the connection's peer has hung up or the socket has an error.
func stillOpen(raw syscall.RawConn) error {
	var hungUp bool
	var pollErr error
	if err := raw.Control(func(fd uintptr) {
		fds := []unix.PollFd{{Fd: int32(fd)}}
		for {
			_, pollErr = unix.Poll(fds, 0)
			if pollErr != unix.EINTR {
				break
			}
		}
		hungUp = fds[0].Revents&hangup != 0
	}); err != nil {
		return err
	}
	if pollErr != nil {
		return fmt.Errorf("poll: %w", pollErr)
	}
	if hungUp {
		return errHungUp
	}
	return nil
}

// selfCgroupNS is the inode of this process's cgroup namespace, read as the rule reads it (openNamespace): from a
// descriptor fstatfs shows to be a kernel namespace file, never from the stat of a path.
func selfCgroupNS() (uint64, error) {
	fd, ns, err := openNamespace(machine.selfNS)
	if err != nil {
		return 0, err
	}
	_ = fd.Close()
	return ns.Ino, nil
}

// Refuse is why p is not served on a socket ownerUID owns, nil when it may be (see the package doc): a Refusal
// [peer-unidentified], [unmapped-uid], [run-member] or [peer-cgroupns], in that order. A PidfdFallback peer is not
// refused for that; its caller discloses it. Outside the initial cgroup namespace (runscope.InitCgroupNS) the peer's
// path is read from this process's namespace root, so a peer is served only when this process's own answer is
// outside (Self): every run made inside the namespace then shows in the path. Otherwise every peer is
// [peer-cgroupns] there, as before. In the initial cgroup namespace the gate is asked too (selfHost.withheld): on
// WSL, where a process an agent starts through WSL's own launcher is truly outside the run, no peer is served until
// the launcher's refusal is proven (ADR 0100, amended 2026-11-19); on ordinary Linux the gate holds nothing back.
func Refuse(p Peer, ownerUID int) error {
	ns, err := selfCgroupNS()
	return refuse(p, ownerUID, ns, err, Self, func() (runscope.Cause, bool) { return machine.withheld(true) })
}

func refuse(p Peer, ownerUID int, selfNS uint64, selfErr error, self func() runscope.Answer,
	firstGate func() (runscope.Cause, bool)) error {
	switch {
	case p.PID <= 0 || !strings.HasPrefix(p.Cgroup, "/"):
		return &Refusal{Code: CodeUnidentified, Detail: "the peer was not identified"}
	case p.UID != ownerUID:
		return &Refusal{Code: CodeUnmappedUID, Detail: fmt.Sprintf("pid %d runs as uid %d, and this socket serves uid %d only", p.PID, p.UID, ownerUID)}
	case runscope.LooksGoverned(p.Cgroup):
		return &Refusal{Code: CodeRunMember, Detail: fmt.Sprintf("pid %d is inside a run (%s)", p.PID, p.Cgroup)}
	case runscope.OutsideNamespace(p.Cgroup):
		return &Refusal{Code: CodeCgroupNS, Detail: fmt.Sprintf("pid %d is in a cgroup above this process's cgroup namespace root (%s)", p.PID, p.Cgroup)}
	case selfErr != nil || selfNS == 0:
		return &Refusal{Code: CodeCgroupNS, Detail: "this process's own cgroup namespace could not be read", Err: selfErr}
	}
	if selfNS != runscope.InitCgroupNS {
		if own := self(); !own.Outside() {
			return &Refusal{Code: CodeCgroupNS, Detail: fmt.Sprintf("this process is in cgroup namespace %d, not the initial one, "+
				"so the cgroup of pid %d is read from that namespace's root, and this process cannot be shown to be outside "+
				"every tego run there: %s", selfNS, p.PID, runscope.Why(own))}
		}
	} else if c, held := firstGate(); held {
		return &Refusal{Code: CodeCgroupNS, Detail: fmt.Sprintf("pid %d is not served on this machine: %s", p.PID,
			runscope.Why(runscope.Unproven(c, nil)))}
	}
	switch {
	case p.Undumpable && (p.CgroupNS != 0 || p.UID == 0):
		// Identify sets the flag only on a hidden namespace and for a uid that is not root's (root's per-process files
		// belong to root whether or not it is dumpable, so nothing shows it): any other is no reading of the kernel's.
		return &Refusal{Code: CodeUnidentified, Detail: "the peer was not identified: it is undumpable and shows a cgroup namespace, or is root"}
	case p.Undumpable:
		// A namespace file the kernel hides from every reader without CAP_SYS_PTRACE, for the one reason Identify
		// proved (the dumpable flag at 0, the connecting uid in all four ids, no capability). Nothing is left to compare,
		// and nothing else is skipped: the uid, the cgroup path of every thread, the first thread, the run test and
		// the namespace rules above all judged this peer as they judge a dumpable one's.
	case p.CgroupNS == 0:
		return &Refusal{Code: CodeCgroupNS, Detail: fmt.Sprintf("the cgroup namespace of pid %d could not be read", p.PID)}
	case p.CgroupNS != selfNS:
		return &Refusal{Code: CodeCgroupNS, Detail: fmt.Sprintf("pid %d is in another cgroup namespace (a container's)", p.PID)}
	}
	return nil
}
