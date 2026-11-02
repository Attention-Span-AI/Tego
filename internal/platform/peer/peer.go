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
	// non-dumpable one), which Refuse refuses.
	CgroupNS uint64
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
	cgroupNS(pid int) (uint64, error)
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

func (d dirFS) startBootNS(pid int) (uint64, error) {
	st, err := proc.NewAt(string(d)).Stat(pid)
	if err != nil {
		return 0, err
	}
	return st.StartBootNS(), nil
}

// owner is the uid /proc/<pid> belongs to: the process's effective uid while it is dumpable, root's otherwise.
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
	if p.CgroupNS, err = h.proc.cgroupNS(p.PID); err != nil {
		return unidentified(err, "the cgroup namespace of pid %d", p.PID)
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

// selfCgroupNS is the inode of this process's cgroup namespace.
func selfCgroupNS() (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/cgroup", &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

// Refuse is why p is not served on a socket ownerUID owns, nil when it may be (see the package doc): a Refusal
// [peer-unidentified], [unmapped-uid], [run-member] or [peer-cgroupns], in that order. A PidfdFallback peer is not
// refused for that; its caller discloses it. Outside the initial cgroup namespace (runscope.InitCgroupNS) this
// process cannot judge run membership at all, as runscope.InRun cannot: every peer is [peer-cgroupns] there.
func Refuse(p Peer, ownerUID int) error {
	ns, err := selfCgroupNS()
	return refuse(p, ownerUID, ns, err)
}

func refuse(p Peer, ownerUID int, selfNS uint64, selfErr error) error {
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
	case selfNS != runscope.InitCgroupNS:
		return &Refusal{Code: CodeCgroupNS, Detail: fmt.Sprintf("this process is in cgroup namespace %d, not the initial one, "+
			"so the cgroup of pid %d is read from that namespace's root, and a run's scope above it would not show", selfNS, p.PID)}
	case p.CgroupNS == 0:
		return &Refusal{Code: CodeCgroupNS, Detail: fmt.Sprintf("the cgroup namespace of pid %d could not be read", p.PID)}
	case p.CgroupNS != selfNS:
		return &Refusal{Code: CodeCgroupNS, Detail: fmt.Sprintf("pid %d is in another cgroup namespace (a container's)", p.PID)}
	}
	return nil
}
