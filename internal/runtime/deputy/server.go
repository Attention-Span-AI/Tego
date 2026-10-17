// SPDX-License-Identifier: Apache-2.0

package deputy

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// PinQuery is one pin as the walk takes it: what the trapping task's syscall named, exactly as it passed it.
type PinQuery struct {
	// TID is the task that trapped; its /proc entry gives the root, cwd and descriptors the walk starts from.
	TID int
	// TGID is TID's thread group, which /proc/self and /proc/thread-self are read as: the supervisor knows it, and
	// the deputy reads no /proc file (its filter allows no read).
	TGID int
	// DirFD is the syscall's directory descriptor (AT_FDCWD for none).
	DirFD int32
	// Path is the pathname as the task passed it, uncleaned.
	Path string
	// Nofollow has a final symlink fail ELOOP; Create has a missing final component end the walk at its directory;
	// Empty pins the descriptor itself (AT_EMPTY_PATH); Excl pins the parent and names the final component, never
	// followed (O_CREAT|O_EXCL).
	Nofollow, Create, Empty, Excl bool
	// Directory is an open that needs a directory (O_DIRECTORY, or O_TMPFILE, which carries it): with Nofollow, a final
	// symlink fails ENOTDIR, not ELOOP, as the kernel answers such an open (do_open's LOOKUP_DIRECTORY check comes
	// before may_open's refusal of a symlink).
	Directory bool
}

// walkBits are q's walk flags as a request carries them.
func (q PinQuery) walkBits() uint8 {
	var w uint8
	for _, b := range []struct {
		on  bool
		bit uint8
	}{{q.Nofollow, walkNofollow}, {q.Create, walkCreate}, {q.Empty, walkEmpty}, {q.Excl, walkExcl}, {q.Directory, walkDirectory}} {
		if b.on {
			w |= b.bit
		}
	}
	return w
}

// Pinned is what a pin reached.
type Pinned struct {
	// FD is the O_PATH descriptor of what the walk reached, the caller's to close.
	FD int
	// Leaf names the missing final component of a create (or the final component of an O_CREAT|O_EXCL pin) beneath FD,
	// "" for none.
	Leaf string
	// ByDescriptor says the walk reached FD through a descriptor, not by a name in a directory: the AT_EMPTY_PATH
	// descriptor itself, a procfs magic link (/proc/<pid>/fd/N, cwd, root) as its last step, or the start of a relative
	// walk named by "." alone. Only such an object may lack a name (a pipe, an unlinked file); one reached by a name
	// that has none by the time it is read lost it after the walk (supervisor's pinnedPath).
	ByDescriptor bool
}

// PinFunc walks q as the task's own lookup walks it and returns what it reached (Pinned). Its error is the errno the
// task's lookup would have failed with, or one that says the walk could not finish. The supervisor provides it
// (supervisor.DeputyPinner): the walk is the one its own decisions use.
type PinFunc func(q PinQuery) (Pinned, error)

// Exit codes of Main.
const (
	exitOK       = 0
	exitSetup    = 125 // a confinement step failed: the deputy never served
	exitProtocol = 126 // the launcher sent something this protocol does not have
)

// Main is `tego __open-deputy --parent <pid>`: it confines this process, says hello on ControlFD, reports readiness
// on ReadyFD and serves until the launcher's end of the control socket closes (ADR 0041 D2). It returns the exit
// code. Every confinement step comes before the hello, so a deputy the launcher hears from is confined.
//
// The confinement runs on one thread, locked to it for the deputy's life: no_new_privs is a thread's, and a privileged
// stage starts the deputy before it sets no_new_privs on itself, so the deputy's threads start without it. The filter
// is installed with TSYNC from the thread that set no_new_privs, which carries it to every thread. Unlocked, the Go
// scheduler could move the goroutine to another thread between the two steps, and the filter's install was then
// refused EACCES for want of no_new_privs on that thread: the deputy died before it was ready, at random, at a root
// tier only.
func Main(args []string, pin PinFunc) int {
	runtime.LockOSThread() // never unlocked: the thread that confined the deputy serves its control socket
	parent, err := parseArgs(args)
	if err != nil {
		return fatal(err)
	}
	if err := confine(parent); err != nil {
		return fatal(err)
	}
	hello := reply{op: opHello, pid: int32(os.Getpid())}
	buf := make([]byte, maxReply)
	oob := make([]byte, oobSize)
	msg, err := hello.encode(buf)
	if err == nil {
		err = sendMsg(ControlFD, msg, oob, -1)
	}
	if err != nil {
		return fatal(fmt.Errorf("hello: %w", err))
	}
	// ReadyFD is a socket, since the filter allows no write but to standard error: one message, then its end of
	// stream. The stage reads the message as confined-and-up, and an end of stream without it as a deputy that died.
	if err := sendMsg(ReadyFD, []byte{1}, oob, -1); err != nil {
		return fatal(fmt.Errorf("ready: %w", err))
	}
	_ = unix.Close(ReadyFD)
	return serve(pin)
}

func parseArgs(args []string) (int, error) {
	if len(args) != 2 || args[0] != "--parent" {
		return 0, fmt.Errorf("usage: %s --parent <pid>", Command)
	}
	pid, err := strconv.Atoi(args[1])
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("--parent %q is not a pid", args[1])
	}
	return pid, nil
}

// fatal writes one line on standard error (the stage passes /dev/null), sends the same reason on ReadyFD in place of
// the readiness message (a 0 byte, then the text, at most maxLeaf bytes), and returns the setup exit code. The stage
// names the reason in its report of a deputy that did not start (deputy.ReportFailure); the launcher learns of the
// failure from that report, never from this line.
func fatal(err error) int {
	fmt.Fprintf(os.Stderr, "tego %s: %v\n", Command, err)
	_ = sendMsg(ReadyFD, failureMessage(err.Error()), make([]byte, oobSize), -1)
	return exitSetup
}

// failureMessage is a start failure's message on ReadyFD: a 0 byte, then reason cut to maxLeaf bytes.
func failureMessage(reason string) []byte {
	if len(reason) > maxLeaf {
		reason = reason[:maxLeaf]
	}
	return append([]byte{0}, reason...)
}

// confine is every step before the hello, in order: PR_SET_PDEATHSIG against the launcher (re-checked against its
// pid, as the stage does), PR_SET_DUMPABLE 0, no capability in any set, no_new_privs, the Go runtime's poller
// started so its descriptors are known, and the allowlist filter on every thread (TSYNC).
func confine(parent int) error {
	if err := sys.SetPdeathsig(syscall.SIGKILL); err != nil {
		return fmt.Errorf("pdeathsig: %w", err)
	}
	if ppid := os.Getppid(); ppid != parent {
		return fmt.Errorf("launcher pid %d gone, parent is now %d", parent, ppid)
	}
	if err := sys.SetDumpable(false); err != nil {
		return fmt.Errorf("dumpable: %w", err)
	}
	if on, err := sys.Dumpable(); err != nil || on {
		return fmt.Errorf("PR_GET_DUMPABLE still 1 after PR_SET_DUMPABLE 0 (%v)", err)
	}
	// The stage starts the deputy with the agent's credentials, which hold no capability: an empty inheritable set
	// is made so on every thread (a cgo build cannot reach them all, ENOTSUP, and keeps what it inherited), and a
	// permitted, effective or ambient capability left would be a power the agent does not have, so it refuses. An
	// inheritable bit alone grants nothing to a process that cannot exec.
	if err := sys.ClearProcessCapabilities(); err != nil && !errors.Is(err, unix.ENOTSUP) {
		return fmt.Errorf("clear capabilities: %w", err)
	}
	eff, perm, _, err := sys.Capabilities()
	if err != nil {
		return fmt.Errorf("capabilities: %w", err)
	}
	amb, err := sys.AmbientCapabilities()
	if err != nil {
		return fmt.Errorf("ambient capabilities: %w", err)
	}
	if eff|perm|amb != 0 {
		return fmt.Errorf("capabilities held (effective %#x, permitted %#x, ambient %#x)", eff, perm, amb)
	}
	if err := sys.SetNoNewPrivs(); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	if confineStep != nil {
		confineStep("nnp")
	}
	// A timer starts the runtime's poller (netpollGenericInit) now, while its epoll_create1, eventfd2 and epoll_ctl
	// are still allowed; afterwards it only waits on the epoll descriptor and reads and writes the eventfd.
	time.AfterFunc(time.Hour, func() {}).Stop()
	efd, err := runtimeEventFD()
	if err != nil {
		return err
	}
	prog, err := Filter(FilterSpec{TGID: os.Getpid(), EventFD: efd})
	if err != nil {
		return err
	}
	if err := installTSync(prog); err != nil {
		return err
	}
	return nil
}

// confineStep, when set (this package's tests alone), runs at confine's named steps: "nnp" once no_new_privs is set.
var confineStep func(step string)

// runtimeEventFD finds the Go runtime poller's eventfd among this process's descriptors: the one anonymous eventfd
// inode. -1 when there is none; an error when there is more than one, since the filter could then not tell which
// the runtime reads.
func runtimeEventFD() (int, error) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1, fmt.Errorf("list descriptors: %w", err)
	}
	found := -1
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		link, err := os.Readlink("/proc/self/fd/" + e.Name())
		if err != nil || !strings.HasPrefix(link, "anon_inode:") || !strings.Contains(link, "eventfd") {
			continue
		}
		if found >= 0 {
			return -1, fmt.Errorf("two eventfds (%d, %d): the runtime's poller cannot be told apart", found, fd)
		}
		found = fd
	}
	return found, nil
}

// installTSync installs prog on every thread of this process (SECCOMP_FILTER_FLAG_TSYNC): the Go runtime's threads
// already exist, and a filter on one thread alone would leave the others unconfined. A thread that cannot be synced
// fails the call with its tid.
func installTSync(raw []bpf.RawInstruction) error {
	filter := make([]unix.SockFilter, len(raw))
	for i, in := range raw {
		filter[i] = unix.SockFilter{Code: in.Op, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	r, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC,
		uintptr(unsafe.Pointer(&prog)))
	if errno != 0 {
		return fmt.Errorf("seccomp(SET_MODE_FILTER, TSYNC): %w", errno)
	}
	if r != 0 {
		return fmt.Errorf("seccomp(SET_MODE_FILTER, TSYNC): thread %d could not be synced", r)
	}
	return nil
}

// serve reads the control socket: each message attaches a request socket, served on a goroutine of its own until
// the launcher closes its end. The control socket's end of stream is the launcher's: the deputy exits.
func serve(pin PinFunc) int {
	buf := make([]byte, maxRequest)
	oob := make([]byte, oobSize)
	for {
		n, c, err := recvMsg(ControlFD, buf, oob, nil)
		if err != nil || n == 0 {
			closeControl(c)
			return exitOK
		}
		req, err := decodeRequest(buf[:n])
		if err != nil || req.op != opConn || c.fd < 0 || len(c.extra) != 0 {
			closeControl(c)
			return exitProtocol
		}
		go serveConn(c.fd, pin)
	}
}

// serveConn answers one request socket's requests in order, one at a time, until its peer closes it.
func serveConn(sock int, pin PinFunc) {
	defer unix.Close(sock) //nolint:errcheck // a socket this goroutine owns
	buf := make([]byte, maxRequest)
	out := make([]byte, maxReply)
	oob := make([]byte, oobSize)
	for {
		n, c, err := recvMsg(sock, buf, oob, nil)
		if err != nil || n == 0 {
			closeControl(c)
			return
		}
		req, err := decodeRequest(buf[:n])
		if err != nil || len(c.extra) != 0 {
			closeControl(c)
			return
		}
		rep, fd, second := handle(req, c.fd, pin)
		if c.fd >= 0 {
			_ = unix.Close(c.fd)
		}
		msg, err := rep.encode(out)
		if err == nil {
			err = sendMsg2(sock, msg, oob, fd, second)
		}
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		if second >= 0 {
			_ = unix.Close(second)
		}
		if err != nil {
			return
		}
	}
}

// createMu serializes umask(2) and the create it applies to: the deputy's threads share one fs_struct, so one
// create's umask must not be another's (ADR 0041 D5).
var createMu sync.Mutex

// handle performs one request and returns its reply and the descriptors to send with it (-1 for none), which the
// caller closes once sent: the pin or the opened file, and an opPinOpen's opened file after its pin. in is the
// descriptor the request carried, the caller's to close.
func handle(req request, in int, pin PinFunc) (reply, int, int) {
	rep := reply{op: req.op, seq: req.seq}
	switch req.op {
	case opPin, opPinOpen:
		q := PinQuery{TID: int(req.tid), TGID: int(req.tgid), DirFD: req.dirfd, Path: req.path,
			Nofollow: req.walk&walkNofollow != 0, Create: req.walk&walkCreate != 0, Empty: req.walk&walkEmpty != 0,
			Excl: req.walk&walkExcl != 0, Directory: req.walk&walkDirectory != 0}
		p, err := pin(q)
		if err != nil {
			rep.errno = errnoOf(err)
			return rep, -1, -1
		}
		fd, leaf := p.FD, p.Leaf
		if len(leaf) > maxLeaf {
			_ = unix.Close(fd)
			rep.errno = unix.ENAMETOOLONG
			return rep, -1, -1
		}
		rep.leaf, rep.byFD = leaf, p.ByDescriptor
		if req.op == opPinOpen && leaf == "" && readOnly(int(req.flags)) && regularOrDir(fd) {
			opened, err := openPinned(fd, "", int(req.flags), 0, -1)
			rep.opened = true
			if err != nil {
				rep.openErrno = errnoOf(err)
				return rep, fd, -1
			}
			return rep, fd, opened
		}
		return rep, fd, -1
	case opOpen:
		if in < 0 {
			rep.errno = unix.EBADF
			return rep, -1, -1
		}
		fd, err := openPinned(in, req.leaf, int(req.flags), req.mode, int(req.umask))
		if err != nil {
			rep.errno = errnoOf(err)
			return rep, -1, -1
		}
		return rep, fd, -1
	}
	rep.errno = unix.EINVAL
	return rep, -1, -1
}

// readOnly reports whether open flags only read: no write access, no create, truncate, temporary file or O_PATH.
func readOnly(flags int) bool {
	return flags&unix.O_ACCMODE == unix.O_RDONLY && flags&(unix.O_CREAT|unix.O_TRUNC|unix.O_PATH) == 0 &&
		flags&unix.O_TMPFILE != unix.O_TMPFILE
}

// regularOrDir reports whether the pinned object is a regular file or a directory, whose read-only open has no effect
// but atime: no FIFO, whose open waits for or wakes a peer, and no device, whose open may act.
func regularOrDir(fd int) bool {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		return false
	}
	t := st.Mode & unix.S_IFMT
	return t == unix.S_IFREG || t == unix.S_IFDIR
}

// openPinned is an open's kernel half, made by this process of the run: a create beneath the pinned directory, an
// O_TMPFILE in it, or the pinned object reopened through /proc/self/fd with the task's flags. The walk honoured
// O_NOFOLLOW already, so it is dropped from the reopen, whose final component is the magic link itself. O_CREAT and
// O_EXCL are kept: the object exists, so nothing is created, and the kernel answers them as it answers the task's own
// open of an existing object, EISDIR for O_CREAT on a directory and EEXIST for O_CREAT|O_EXCL ("." or "..", the only
// O_EXCL pins with no leaf). The magic link's directory is no sticky directory, so the kernel's
// fs.protected_regular and fs.protected_fifos check of such a reopen is the supervisor's (heldStickyCreate), made on
// the directory the pinned path names before this open is asked for.
func openPinned(pin int, leaf string, flags int, mode uint32, mask int) (int, error) {
	creates := flags&unix.O_CREAT != 0 || flags&unix.O_TMPFILE == unix.O_TMPFILE
	if creates && leaf == "" && flags&unix.O_TMPFILE != unix.O_TMPFILE {
		creates = false // an existing object an O_CREAT open finds: no mode, no umask
	}
	if creates {
		if mask < 0 || mask > 0o777 {
			return -1, unix.EINVAL
		}
		createMu.Lock()
		defer createMu.Unlock()
		unix.Umask(mask)
		if flags&unix.O_TMPFILE == unix.O_TMPFILE {
			return openatRetry(pin, ".", flags|unix.O_CLOEXEC, mode)
		}
		return openatRetry(pin, leaf, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	}
	if leaf != "" {
		return -1, unix.EINVAL
	}
	return openatRetry(unix.AT_FDCWD, "/proc/self/fd/"+strconv.Itoa(pin), flags&^unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}

// openatRetry is openat(2), restarted on EINTR.
func openatRetry(dir int, name string, flags int, mode uint32) (int, error) {
	for {
		fd, err := unix.Openat(dir, name, flags, mode)
		if err != unix.EINTR {
			return fd, err
		}
	}
}

// errnoOf is err's errno, or EIO for an error that carries none.
func errnoOf(err error) unix.Errno {
	var errno unix.Errno
	if errors.As(err, &errno) && errno != 0 {
		return errno
	}
	return unix.EIO
}
