// SPDX-License-Identifier: Apache-2.0

// Package adopt decides what an adoption may move and moves it (ADR 0055): an agent
// that was already running when Tego met it, started from a terminal or an IDE, is governed by moving its own process
// tree, and nothing else, into a fresh cgroup of its run, whose tier-2 programs then record it from the kernel.
//
// What it decides. Identify reads one process from /proc as an Identity (its pid and its start time, the pair that
// tells a process from one that reused its pid) with the facts the rules need; Check refuses what is never adopted (pid
// 1, a kernel thread, tego itself, an ancestor of the caller, a service manager, a process in another cgroup or pid
// namespace, a process already inside a run); UIDs is the guard's owner filter; Move moves the agent's tree (walk): the
// process and every descendant still in the cgroup the process is in, never its parent, its siblings or the rest of
// that cgroup.
//
// What it does. Move writes each member's pid into the run cgroup's cgroup.procs, root first, re-reading the member's
// start time just before the write (a pid reused since the member was identified is reported and not moved, and a
// root whose identity changed moves nothing at all), and again over a fresh /proc snapshot until no member is left
// behind (a process forked by a member before that member moved). Release moves a run cgroup's processes back out:
// the cgroup is frozen first, so nothing forks while its processes leave, and thawed after.
//
// Every read and write goes through Proc, CgroupFS and Liveness, so the whole of it runs over fakes in tests; FS,
// Cgroups and Pidfds are the system's. It never signals, kills, traces or alters a process: moving it between cgroups
// is the one thing it does to one.
package adopt

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// Identity names one process: its pid and its start time, /proc/<pid>/stat's starttime in clock ticks since boot
// (internal/watch/tree's Entry uses the same pair). A pid is reused once its process is gone; the pair is not.
type Identity struct {
	PID   int
	Start uint64
}

// String is the pair as "pid/start".
func (id Identity) String() string { return fmt.Sprintf("%d/%d", id.PID, id.Start) }

// FileID is a file's device and inode: what identifies tego's own binary whatever it is called.
type FileID struct{ Dev, Ino uint64 }

// Process is what an adoption reads of one process.
type Process struct {
	Identity
	PPID  int
	State byte
	Comm  string
	// Exe is the program it runs; "" for a kernel thread.
	Exe  string
	Argv []string
	// Cgroup is its cgroup v2 path relative to the cgroup2 mount ("/user.slice/.../session-2.scope").
	Cgroup string
	// UID is its real, effective and saved user id, in that order (/proc/<pid>/status Uid:), and GID the same of its
	// group ids.
	UID, GID [3]int
	// Tgid is its thread group: the process a thread id belongs to; equal to PID for a process.
	Tgid int
	// ExeFile is the identity of the file Exe names, the zero value when it could not be read.
	ExeFile FileID
	// CgroupNS and PidNS are the inode numbers of its cgroup and pid namespaces, 0 when unknown.
	CgroupNS, PidNS uint64
	// MntNS is the inode number of its mount namespace, 0 when unknown. Check does not compare it (a process in a
	// mount namespace of its own, a snap's or a sandboxed tool's, is the operator's to adopt); what /proc names of
	// such a process's files is not a path of tego's namespace, so an adoption does not count them by name.
	MntNS uint64
}

// Owner is the uid the process runs as when its three user ids agree, -1 when they do not (a set-user-id program
// mid-switch, which the guard never adopts).
func (p Process) Owner() int {
	if p.UID[0] == p.UID[1] && p.UID[1] == p.UID[2] {
		return p.UID[0]
	}
	return -1
}

// Proc is the /proc an adoption reads. Every read may fail for a process that has exited; proc.ErrGone says so.
type Proc interface {
	PIDs() ([]int, error)
	Stat(pid int) (proc.Stat, error)
	Exe(pid int) (string, error)
	Argv(pid int) ([]string, error)
	Cgroup(pid int) (string, error)
	// Status is /proc/<pid>/status's Tgid, Uid and Gid lines.
	Status(pid int) (Status, error)
	// Cwd is the process's working directory; "" when it cannot be read.
	Cwd(pid int) (string, error)
	// FDs lists the process's open descriptors.
	FDs(pid int) ([]FD, error)
	// ExeFile is the identity of the file /proc/<pid>/exe opens.
	ExeFile(pid int) (FileID, error)
	// Namespace is the inode of /proc/<pid>/ns/<kind> ("cgroup", "pid", "mnt").
	Namespace(pid int, kind string) (uint64, error)
	// Tasks lists the thread ids of process pid, its leader's included (/proc/<pid>/task).
	Tasks(pid int) ([]int, error)
}

// Status is what an adoption reads of /proc/<pid>/status.
type Status struct {
	Tgid     int
	UID, GID [3]int
}

// FD is one open descriptor of a process: its number, what /proc/<pid>/fd/<n> names ("/path", "socket:[ino]",
// "pipe:[ino]", "anon_inode:[...]") and its open flags (/proc/<pid>/fdinfo/<n>).
type FD struct {
	Num    int
	Target string
	Flags  int
	// NoPath says the file is on one of the kernel-internal superblocks tego found on this kernel (FS.FDs: its
	// device is one of internalDevices', nopath.go): a memfd, of any page size, which no path the process could open
	// names, so no fs rule covers it and the decision plane decides no open of it either (bpf/decide.bpf.c
	// tego_no_path). Decided from the device, never from the name /proc gives the file nor from which mount shows it:
	// a file reached through a detached or lazily unmounted mount, or held from a chroot, is a path. False for a
	// pseudo file of an internal superblock tego did not probe (a dma-buf, secretmem), whose mount no line of tego's
	// mountinfo shows either, so it is Unnamed: its process is counted unread.
	NoPath bool
	// Unnamed says Target is no path of the file in tego's own mount namespace (names.go): it was opened through a
	// mount that namespace does not hold (a detached clone, a lazily unmounted mount), whose root /proc's name stops
	// at, or its mount could not be read, or the name, not deleted, now leads to another file or none. A rule's
	// verdict on Target is then no verdict on the file. False for a NoPath file and for what is not a file.
	Unnamed bool
	// Aliases are the other paths of tego's namespace that reach the file, through the other mounts of its
	// filesystem that show its directory (a bind mount of a directory above it): a rule may name the file by one of
	// them, and the decision plane's walk meets it whichever mount the file was opened through.
	Aliases []string
	// ID is the held file's device and inode (a statx through /proc/<pid>/fd/<n>), the zero value when it could not be
	// read: the decision plane keys a file entry's row on the inode, so a rule decides every name the inode has, a
	// hard link /proc names the file by included. Set for a file, and for an io_uring
	// instance (Ring), whose inode its mappings name, when that inode is its own: a ring on the kernel's shared
	// anonymous inode (an older kernel's io_uring) has none (FS.unidentifySharedRings).
	ID FileID
	// Ring says the descriptor is an io_uring instance; RegisteredFiles that it holds a table of registered files, or
	// that its fdinfo could not say (the kernel prints the table only when it takes the ring's lock at once, and no
	// kernel before 5.9 prints it). A registered file is held by the ring, not by a descriptor or a mapping /proc
	// lists, and stays readable and writable through it with no open, so what such a
	// process holds is not all read.
	Ring, RegisteredFiles bool
	// Unread says /proc could not say what the descriptor holds or how: its link could not be read for a reason other
	// than its closing (the kernel refuses a name longer than PATH_MAX, ENAMETOOLONG), so Target is "", or its fdinfo
	// could not be read, so Flags are unknown. Its process is counted
	// unread, never taken as holding only the rest.
	Unread bool
}

// RingTarget is what /proc/<pid>/fd/<n> and a mapping's smaps line name an io_uring instance by.
const RingTarget = "anon_inode:[io_uring]"

// Socket reports whether the descriptor is a socket.
func (f FD) Socket() bool { return strings.HasPrefix(f.Target, "socket:") }

// File reports whether the descriptor names a file by an absolute path.
func (f FD) File() bool { return strings.HasPrefix(f.Target, "/") }

// Writes reports whether the descriptor was opened for writing.
func (f FD) Writes() bool { return f.Flags&syscall.O_ACCMODE != syscall.O_RDONLY }

// ErrGone is a process that exited, became a zombie or was replaced under its pid while it was being read.
var ErrGone = proc.ErrGone

// Identify reads pid as a Process. The start time is read before and after the other files, so a pid reused while
// they were read is ErrGone rather than one process's facts under another's identity (as internal/watch/watcher
// reads a sighting). A zombie is ErrGone too: it has no tree left to move. A process whose leader exited while other
// threads of it run (proc.Stat.LeaderExited) is read through one of those threads (liveTask): its program, owner, cgroup and
// namespaces are theirs, and its identity is the leader's pid and start time, which the zombie leader keeps until
// the whole group has exited.
func Identify(p Proc, pid int) (Process, error) {
	st1, err := p.Stat(pid)
	if err != nil {
		return Process{}, err
	}
	if st1.Gone() {
		return Process{}, fmt.Errorf("pid %d: %w (a zombie)", pid, ErrGone)
	}
	via, viaStart, err := liveTask(p, pid, st1)
	if err != nil {
		return Process{}, err
	}
	out := Process{Identity: Identity{PID: pid, Start: st1.StartTicks}, PPID: st1.PPID, State: st1.State, Comm: st1.Comm}
	if out.Exe, err = p.Exe(via); err != nil {
		return Process{}, err
	}
	if out.Argv, err = p.Argv(via); err != nil {
		return Process{}, err
	}
	if out.Cgroup, err = p.Cgroup(via); err != nil {
		return Process{}, err
	}
	s, err := p.Status(via)
	if err != nil {
		return Process{}, err
	}
	out.Tgid, out.UID, out.GID = s.Tgid, s.UID, s.GID
	if out.Exe != "" {
		if id, err := p.ExeFile(via); err == nil {
			out.ExeFile = id
		}
	}
	out.CgroupNS, _ = p.Namespace(via, "cgroup")
	out.PidNS, _ = p.Namespace(via, "pid")
	out.MntNS, _ = p.Namespace(via, "mnt")
	st2, err := p.Stat(pid)
	if err != nil {
		return Process{}, err
	}
	if st2.StartTicks != st1.StartTicks || st2.Gone() {
		return Process{}, fmt.Errorf("pid %d: %w (the pid was reused while it was read)", pid, ErrGone)
	}
	if !sameTask(p, pid, via, viaStart) {
		return Process{}, fmt.Errorf("pid %d: %w (the thread it was read through exited)", pid, ErrGone)
	}
	return out, nil
}

// FS is the system's /proc as a Proc.
type FS struct {
	*proc.FS
	root string
	// internal is the kernel-internal superblocks' devices (internalDevices); a test sets its own.
	internal func() map[devID]bool
	// mounts reads tego's own mount table (readOwnMounts), once per listing; nil names every file as itself.
	mounts func() (mountTable, error)
	// anon is the kernel's shared anonymous inode (sharedAnonInode), ok false when it could not be learnt; a test sets
	// its own. Nil, or not ok, leaves every io_uring instance with no identity (FD.ID).
	anon func() (FileID, bool)
	// sameFiles says whether a task of the process shares the leader's descriptor table (sameFilesTable, kcmp); a test
	// sets its own. Nil, or an error, reads the task's table.
	sameFiles func(pid, tid int) (bool, error)
	// maxReads bounds the descriptors one FDs listing reads across a process's tables: maxFDReads, which a test lowers.
	maxReads int
}

// NewFS reads the proc filesystem mounted at root ("/proc" when empty).
func NewFS(root string) *FS {
	if root == "" {
		root = proc.DefaultRoot
	}
	return &FS{FS: proc.NewAt(root), root: root, internal: internalDevices, mounts: readOwnMounts, anon: sharedAnonInode,
		sameFiles: sameFilesTable, maxReads: maxFDReads}
}

// Status reads /proc/<pid>/status's Tgid and Uid lines.
func (f *FS) Status(pid int) (Status, error) {
	b, err := os.ReadFile(filepath.Join(f.root, strconv.Itoa(pid), "status"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			return Status{}, fmt.Errorf("pid %d: %w", pid, ErrGone)
		}
		return Status{}, err
	}
	return ParseStatus(b)
}

// ParseStatus reads the Tgid, Uid and Gid lines of a /proc/<pid>/status. All three must be there: a status without
// them is not one a kernel wrote, and a process whose owner cannot be read is never adopted.
func ParseStatus(b []byte) (Status, error) {
	var s Status
	var tgid, uid, gid bool
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		f := strings.Fields(val)
		switch key {
		case "Tgid":
			if len(f) < 1 {
				return Status{}, errors.New("status: an empty Tgid line")
			}
			n, err := strconv.Atoi(f[0])
			if err != nil || n <= 0 {
				return Status{}, fmt.Errorf("status: Tgid %q", f[0])
			}
			s.Tgid, tgid = n, true
		case "Uid", "Gid":
			if len(f) < 3 {
				return Status{}, fmt.Errorf("status: %s has %d fields, want real, effective, saved", key, len(f))
			}
			dst := &s.UID
			if key == "Gid" {
				dst = &s.GID
			}
			for i := range 3 {
				n, err := strconv.ParseUint(f[i], 10, 32)
				if err != nil {
					return Status{}, fmt.Errorf("status: %s %q", key, f[i])
				}
				dst[i] = int(n)
			}
			if key == "Uid" {
				uid = true
			} else {
				gid = true
			}
		}
	}
	if !tgid || !uid || !gid {
		return Status{}, errors.New("status: no Tgid, Uid or Gid line")
	}
	return s, nil
}

// maxFDs bounds how many descriptors FDs lists of one process, and how many it reads of one table.
const maxFDs = 4096

// maxFDReads bounds how many descriptors FDs reads of one process across all its tables: each thread that called
// unshare(CLONE_FILES) holds a table of its own, which kcmp cannot say is the leader's, so a process of M such threads
// would cost M full tables of reads (a readlink, an fdinfo and a statx each) before the adoption records, whatever the
// merge then keeps (200 copied tables of 4000 took 11 s). Past it the
// listing stops, ErrTruncated, so the process is counted unread rather than taken for what was read.
const maxFDReads = 4 * maxFDs

// ErrTruncated is a listing that stopped at its cap (maxFDs descriptors, maxMaps mapped files): what it returns is
// the first entries read, never the whole, so a caller that counts what it was given must say that the rest went
// unread rather than take the list for all the process holds.
var ErrTruncated = errors.New("adopt: the listing stopped at its cap")

// FDs lists the process's descriptors with each one's target and flags: /proc/<pid>/fd, the thread group leader's
// table, and each other task's table (/proc/<pid>/task/<tid>/fd) the kernel does not say is that one (sameFiles), each
// descriptor once (fdKey: a file once per number, name and identity; a ring, an unread descriptor or a file with no
// identity once per table that lists it). A thread may hold a table of its own (unshare CLONE_FILES), which only its
// task directory lists, and a leader that exited while its threads run lists none. It marks each file on a
// kernel-internal superblock (FD.NoPath), and each other one whose target is no path
// of it in tego's namespace (FD.Unnamed) or which other paths reach (FD.Aliases). A descriptor whose link or fdinfo
// cannot be read for a reason other than its closing is listed Unread (FD.Unread). Past maxFDs listed, or maxFDReads
// read across the tables, it returns what it listed with an error matching ErrTruncated; a task's table it could not
// list is an error too, with what it read.
func (f *FS) FDs(pid int) ([]FD, error) {
	base := filepath.Join(f.root, strconv.Itoa(pid))
	l := &fdListing{pid: pid, internal: f.internalDevs(), nm: newNamer(f.mounts), seen: map[fdKey]bool{}, maxReads: f.maxReads}
	if err := l.table(filepath.Join(base, "fd"), filepath.Join(base, "fdinfo")); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("pid %d: %w", pid, ErrGone)
		}
		return nil, err
	}
	tasksErr := f.otherTables(base, l)
	f.unidentifySharedRings(l.out)
	if l.truncated != nil {
		return l.out, l.truncated
	}
	return l.out, tasksErr
}

// otherTables adds to l the descriptors of each task of the process whose table is not the leader's: one sameFiles
// says is the leader's is not read, and one it cannot compare (no kcmp, a thread that exited meanwhile, or an FS with
// no sameFiles) is. A process with no task directory left (it ended since its fd listing) has none; one whose task
// directory, or a live task's table, cannot be listed is an error.
func (f *FS) otherTables(base string, l *fdListing) error {
	ents, err := os.ReadDir(filepath.Join(base, "task"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("pid %d: its threads' descriptor tables: %w", l.pid, err)
	}
	var first error
	for _, e := range ents {
		if l.truncated != nil {
			break
		}
		tid, err := strconv.Atoi(e.Name())
		if err != nil || tid == l.pid {
			continue
		}
		if f.sameFiles != nil {
			if same, err := f.sameFiles(l.pid, tid); err == nil && same {
				continue
			}
		}
		dir := filepath.Join(base, "task", e.Name())
		err = l.table(filepath.Join(dir, "fd"), filepath.Join(dir, "fdinfo"))
		if err != nil && !errors.Is(err, os.ErrNotExist) && first == nil {
			first = fmt.Errorf("pid %d, thread %d: its descriptor table: %w", l.pid, tid, err)
		}
	}
	return first
}

// fdKey tells one descriptor of FDs' listing from another: a table copied by unshare(CLONE_FILES) lists the same
// descriptor under the same number, target and flags, and it is listed once. A file is told by its identity too (FD.ID,
// set by markFDs before the key is taken): two tables can hold two different files under one number and one name (a
// name deleted and made again, a hard link moved there), and the count asks the rules by the inode as well as the
// name. A file with no identity, an io_uring instance (on an older kernel
// every ring has the shared anonymous inode, so no ring's ID tells it from another's) and an Unread descriptor are
// never merged (mergeable): listed twice, the count errs upward, never down.
type fdKey struct {
	num    int
	target string
	flags  int
	id     FileID
}

// mergeable reports whether fd may be merged with an entry of another table that has the same fdKey.
func mergeable(fd FD) bool {
	switch {
	case fd.Unread || fd.Ring:
		return false
	case fd.File():
		return fd.ID != FileID{}
	default:
		return true // a socket or a pipe, whose target names its inode, or a descriptor no rule counts
	}
}

// fdListing is one FDs listing, over the tables it reads.
type fdListing struct {
	pid       int
	internal  map[devID]bool
	nm        *namer
	seen      map[fdKey]bool
	out       []FD
	read      int // descriptors read across the tables
	maxReads  int // the bound on read (FS.maxReads)
	truncated error
}

// table adds the descriptors of one table (dir, the process's or a task's fd directory, and info, its fdinfo) that
// are not listed yet (fdKey), each marked (markFDs) through dir before it is compared. The cap counts what is listed,
// after the merge: a table copied from the leader's adds nothing to it.
// One table holding more than maxFDs descriptors passes it alone (its numbers differ), and no more of it is read. An
// error is the directory's listing's.
func (l *fdListing) table(dir, info string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var fds []FD
	over, readOver := false, false
	for _, e := range ents {
		if len(fds) == maxFDs {
			over = true
			break
		}
		n, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if l.read >= l.maxReads {
			readOver = true
			break
		}
		l.read++
		var fd FD
		switch target, err := os.Readlink(filepath.Join(dir, e.Name())); {
		case errors.Is(err, os.ErrNotExist):
			continue // closed since the listing
		case err != nil:
			// /proc cannot name it (a path longer than PATH_MAX: ENAMETOOLONG): what it holds is not known.
			fd = FD{Num: n, Unread: true}
		default:
			fd = FD{Num: n, Target: target, Ring: target == RingTarget}
			at := filepath.Join(info, e.Name())
			b, err := os.ReadFile(at)
			switch {
			case err == nil:
				fd.Flags = parseFDFlags(b)
			case !errors.Is(err, os.ErrNotExist):
				fd.Unread = true // how it was opened, for writing or not, is not known
			}
			if fd.Ring {
				fd.RegisteredFiles = ringRegisteredFiles(b, err, func() ([]byte, error) { return os.ReadFile(at) })
			}
		}
		fds = append(fds, fd)
	}
	markFDs(dir, fds, l.internal, l.nm)
	for _, fd := range fds {
		if mergeable(fd) {
			k := fdKey{fd.Num, fd.Target, fd.Flags, fd.ID}
			if l.seen[k] {
				continue
			}
			l.seen[k] = true
		}
		if len(l.out) == maxFDs {
			over = true
			break
		}
		l.out = append(l.out, fd)
	}
	switch {
	case over:
		l.truncated = fmt.Errorf("pid %d: more than %d descriptors, %d read: %w", l.pid, maxFDs, len(l.out), ErrTruncated)
	case readOver:
		l.truncated = fmt.Errorf("pid %d: its descriptor tables hold more than %d descriptors in all, %d of them listed: %w",
			l.pid, l.maxReads, len(l.out), ErrTruncated)
	}
	return nil
}

// kcmpFiles is KCMP_FILES (include/uapi/linux/kcmp.h), which golang.org/x/sys/unix does not define.
const kcmpFiles = 2

// sameFilesTable asks kcmp(2) whether tasks a and b share one descriptor table (0: the same; 1, 2 or 3 order two
// different ones). It needs PTRACE_MODE_READ on both, as reading their fd directories does, and a kernel built with
// CONFIG_KCMP; an error leaves the question open, and FDs reads the table.
func sameFilesTable(a, b int) (bool, error) {
	r, _, e := unix.Syscall6(unix.SYS_KCMP, uintptr(a), uintptr(b), kcmpFiles, 0, 0, 0)
	if e != 0 {
		return false, e
	}
	return r == 0, nil
}

// unidentifySharedRings clears the ID of each io_uring instance on the kernel's shared anonymous inode (f.anon): a
// kernel whose io_uring makes its instances with no inode of their own (before io_uring asked fs/anon_inodes.c for
// one) gives every ring the inode an eventfd has, so the ID would match a mapping of any other ring of the process
// and the count would take a ring it only maps (registered with itself and closed, its files unreadable) for the
// one it holds. With no ID, a mapped ring is matched by no descriptor and its process is counted unread. An FS with
// no probe, or a probe that learnt nothing, gives no ring an ID: fail-closed.
func (f *FS) unidentifySharedRings(fds []FD) {
	var shared FileID
	ok := false
	if f.anon != nil {
		shared, ok = f.anon()
	}
	for i := range fds {
		if fds[i].Ring && (!ok || fds[i].ID == shared) {
			fds[i].ID = FileID{}
		}
	}
}

// internalDevs is f.internal's set, nil when f has none (an FS not made by NewFS): nothing is then NoPath.
func (f *FS) internalDevs() map[devID]bool {
	if f.internal == nil {
		return nil
	}
	return f.internal()
}

// parseFDFlags reads the octal flags: line of a /proc/<pid>/fdinfo/<n>.
func parseFDFlags(b []byte) int {
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "flags:"); ok {
			n, err := strconv.ParseInt(strings.TrimSpace(v), 8, 64)
			if err == nil {
				return int(n)
			}
		}
	}
	return 0
}

// ringReadTries bounds how often FDs reads an io_uring descriptor's fdinfo for its table of registered files: the
// kernel prints the ring's state only when it takes the ring's lock at once (io_uring/fdinfo.c), so a ring in use can
// print none on one read and its table on the next.
const ringReadTries = 3

// ringRegisteredFiles says, from an io_uring descriptor's fdinfo (b, as read with err; reread reads it again), whether
// the ring holds a table of registered files: its UserFiles line counts the table's slots, and a ring with none
// prints 0. A table of any size is taken as holding files (a sparse one is filled by later updates), and an fdinfo
// with no UserFiles line after ringReadTries reads (the lock was busy, or a kernel before 5.9) as one that may:
// fail-closed, the process is counted unread.
func ringRegisteredFiles(b []byte, err error, reread func() ([]byte, error)) bool {
	for try := 1; ; try++ {
		if err == nil {
			if n, ok := userFiles(b); ok {
				return n > 0
			}
		}
		if try == ringReadTries {
			return true
		}
		b, err = reread()
	}
}

// userFiles reads the UserFiles: line of an io_uring descriptor's fdinfo.
func userFiles(b []byte) (uint64, bool) {
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "UserFiles:"); ok {
			n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			return n, err == nil
		}
	}
	return 0, false
}

// Mapping is one file a process has mapped, from /proc/<pid>/smaps: its path, and whether some mapping of it is shared
// and writable or may be made so (stores through it reach the file with no descriptor and no further check by any LSM
// hook).
type Mapping struct {
	Path string
	// NoPath says every mapping of the file is on one of the kernel-internal superblocks tego found on this kernel
	// (FS.Maps: the smaps line's device is one of internalDevices', nopath.go): a memfd, a System V segment, the AIO
	// ring (/[aio]), hugetlb or shared anonymous memory (/anon_hugepage, /dev/zero (deleted)) or a GPU driver's
	// shmem object, which no path names and the decision plane passes as no fs decision. Decided from the device,
	// never from the name nor from which mount shows it; false for an internal superblock tego did not probe, whose
	// mapping is Unnamed.
	NoPath bool
	// Unnamed says some mapping of it is of a file Path does not name in tego's own mount namespace (FD.Unnamed): one
	// mapped through a detached or lazily unmounted mount, one whose mount could not be read (its
	// /proc/<pid>/map_files entry, which only CAP_SYS_ADMIN may follow), or one whose name now leads elsewhere.
	Unnamed bool
	// Aliases are the other paths of tego's namespace that reach a file mapped under Path (FD.Aliases).
	Aliases []string
	// SharedWritable: some shared mapping of the file is writable now (perms rw?s) or may be made writable (VmFlags
	// mw, VM_MAYWRITE: the file was open for writing when it was mapped, so mprotect(PROT_WRITE) needs no open, and the
	// plane decides file_mprotect for PROT_EXEC alone). A shared mapping whose VmFlags cannot be read counts as one,
	// fail-closed.
	SharedWritable bool
	// IDs are the devices and inodes of the files mapped under Path (a statx through /proc/<pid>/map_files), each
	// once: the decision plane decides every name of a keyed inode as it decides the keyed one (FD.ID).
	IDs []FileID
	// Ring says this is an io_uring instance's mapping rather than a file's (Path is RingTarget, and IDs holds the
	// instance's device and inode from the smaps line, one Mapping per instance): a ring stays in use while it is
	// mapped, with no descriptor of it left when it was registered with the ring itself (IORING_REGISTER_RING_FDS), and
	// its registered files are then read through no descriptor tego can read (FD.RegisteredFiles).
	Ring bool
}

// MapsReader is a Proc that can also list a process's file mappings (FS does). A mapping made before an adoption
// reads, or for a shared writable one writes, its file with no open the decision plane could refuse.
type MapsReader interface {
	Maps(pid int) ([]Mapping, error)
}

// maxMaps bounds how many distinct mapped files Maps returns for one process.
const maxMaps = 4096

// Maps lists the files /proc/<pid>/smaps names, each once, each marked NoPath when every mapping of it is on a
// kernel-internal superblock's device (Mapping.NoPath), and Unnamed and Aliases from each other mapping's file, read
// through /proc/<pid>/map_files (Mapping.Unnamed, Mapping.Aliases). Past maxMaps distinct files it returns the first maxMaps with
// an error matching ErrTruncated. A process whose leader exited while other threads of it run (proc.Stat.LeaderExited) is read
// through one of those threads (liveTask): the exited leader has let go of the memory its threads share, so its own
// smaps lists nothing.
func (f *FS) Maps(pid int) ([]Mapping, error) {
	st, err := f.Stat(pid)
	if err != nil {
		return nil, err
	}
	if st.Gone() {
		return nil, fmt.Errorf("pid %d: %w (a zombie)", pid, ErrGone)
	}
	via, start, err := liveTask(f, pid, st)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(f.root, strconv.Itoa(via), "smaps"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("pid %d: %w", pid, ErrGone)
		}
		return nil, err
	}
	if !sameTask(f, pid, via, start) {
		return nil, fmt.Errorf("pid %d: %w (the thread it was read through exited)", pid, ErrGone)
	}
	var name func(rng, path string, deleted bool) naming
	if nm := newNamer(f.mounts); nm != nil {
		files := filepath.Join(f.root, strconv.Itoa(via), "map_files")
		name = func(rng, path string, deleted bool) naming {
			id, err := statHeld(filepath.Join(files, rng))
			if err != nil {
				return naming{unnamed: true} // unmapped since, or a map_files entry tego may not follow: unknown
			}
			v := nm.name(path, deleted, id)
			v.id, v.idKnown = id.file(), true
			return v
		}
	}
	out, truncated := parseMappings(b, f.internalDevs(), name)
	if truncated {
		return out, fmt.Errorf("pid %d: more than %d mapped files: %w", pid, maxMaps, ErrTruncated)
	}
	return out, nil
}

// mappingBlock is one mapping of smaps as parseMappings reads it: its header line, then its VmFlags line.
type mappingBlock struct {
	path             string
	shared, writable bool
	// flagged says a VmFlags line was read for it; mayWrite that the line has mw.
	flagged, mayWrite bool
	// noPath says its device is one of the internal devices parseMappings was given.
	noPath bool
	// rng is its address range as map_files names it (mapFilesName); deleted says its path ended in " (deleted)".
	rng     string
	deleted bool
	// ring says it maps an io_uring instance, ringID that instance (the header's device and inode).
	ring   bool
	ringID FileID
}

// mapFilesName is /proc/<pid>/map_files' name for the address range an smaps header gives: smaps pads each address
// to eight hex digits ("00400000-00a00000", the text of an executable that is not position-independent) and
// map_files does not ("400000-a00000"), so a padded range named no entry and the mapping was taken for one tego may
// not follow. A range it cannot read is returned as it is: it then names no entry, and the mapping is unnamed.
func mapFilesName(rng string) string {
	lo, hi, ok := strings.Cut(rng, "-")
	if !ok {
		return rng
	}
	a, errLo := strconv.ParseUint(lo, 16, 64)
	b, errHi := strconv.ParseUint(hi, 16, 64)
	if errLo != nil || errHi != nil {
		return rng
	}
	return strconv.FormatUint(a, 16) + "-" + strconv.FormatUint(b, 16)
}

// parseMappings reads /proc/<pid>/smaps (or maps, which is smaps without its key lines): each mapping's header line
// (address perms offset dev inode [path]) and its VmFlags line. Every absolute path is returned once, marked
// SharedWritable when any of its mappings is shared and writable now (perms rw?s) or may be made writable (VmFlags
// mw), or is shared with no VmFlags line to say it may not, and NoPath when every mapping of it is on one of the
// kernel-internal superblocks' devices internal holds (nil: nothing is NoPath). name, when not nil, is asked of each
// mapping of a path that is not NoPath whether its path names its file in tego's namespace and by what other paths:
// the path is Unnamed when any one is not named, and its Aliases are all of theirs. truncated says a distinct path
// past maxMaps was left out.
func parseMappings(b []byte, internal map[devID]bool, name func(rng, path string, deleted bool) naming) (out []Mapping, truncated bool) {
	at := map[string]int{}
	rings := map[FileID]bool{}
	var cur *mappingBlock
	flush := func() {
		if cur != nil && cur.ring && !rings[cur.ringID] {
			if len(rings) >= maxMaps {
				truncated = true
				return
			}
			rings[cur.ringID] = true
			out = append(out, Mapping{Path: RingTarget, Ring: true, IDs: []FileID{cur.ringID}})
		}
		if cur == nil || cur.path == "" {
			return
		}
		sw := cur.shared && (cur.writable || cur.mayWrite || !cur.flagged)
		i, ok := at[cur.path]
		if !ok {
			if len(at) >= maxMaps {
				truncated = true
				return
			}
			i = len(out)
			at[cur.path] = i
			out = append(out, Mapping{Path: cur.path, NoPath: true})
		}
		m := &out[i]
		m.SharedWritable = m.SharedWritable || sw
		m.NoPath = m.NoPath && cur.noPath
		if name != nil && !cur.noPath {
			v := name(cur.rng, cur.path, cur.deleted)
			m.Unnamed = m.Unnamed || v.unnamed
			for _, a := range v.aliases {
				if !slices.Contains(m.Aliases, a) {
					m.Aliases = append(m.Aliases, a)
				}
			}
			if v.idKnown && !slices.Contains(m.IDs, v.id) {
				m.IDs = append(m.IDs, v.id)
			}
		}
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "VmFlags:"); ok {
			if cur != nil {
				cur.flagged, cur.mayWrite = true, slices.Contains(strings.Fields(v), "mw")
			}
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 || len(fields[1]) != 4 || !isAddressRange(fields[0]) {
			continue // a key line of smaps (Size:, Rss:, ...)
		}
		flush()
		perms := fields[1]
		cur = &mappingBlock{shared: perms[3] == 's', writable: perms[1] == 'w', rng: mapFilesName(fields[0])}
		if dev, ok := parseDev(fields[3], 16); ok {
			cur.noPath = internal[dev] // a device field it cannot read is a path: counted, fail-closed
		}
		if len(fields) < 6 {
			continue // anonymous
		}
		// The path is the rest of the line after the fifth field: it can hold spaces.
		path := line
		for range 5 {
			path = strings.TrimLeft(path, " ")
			if i := strings.IndexByte(path, ' '); i >= 0 {
				path = path[i:]
			}
		}
		path = strings.TrimLeft(path, " ")
		switch {
		case strings.HasPrefix(path, "/"): // not [heap], [stack], [vdso]
			cur.path, cur.deleted = strings.CutSuffix(path, " (deleted)")
		case path == RingTarget:
			// A device or inode it cannot read names no ring: it is an instance of its own, which no descriptor matches.
			cur.ring = true
			if dev, ok := parseDev(fields[3], 16); ok {
				cur.ringID.Dev = unix.Mkdev(dev.major, dev.minor)
			}
			cur.ringID.Ino, _ = strconv.ParseUint(fields[4], 10, 64)
		}
	}
	flush()
	return out, truncated
}

// isAddressRange reports whether s is a maps line's first field: start-end, in hexadecimal.
func isAddressRange(s string) bool {
	lo, hi, ok := strings.Cut(s, "-")
	if !ok || lo == "" || hi == "" {
		return false
	}
	for _, c := range lo + hi {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ExeFile stats /proc/<pid>/exe, which follows the link to the program's file.
func (f *FS) ExeFile(pid int) (FileID, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Join(f.root, strconv.Itoa(pid), "exe"), &st); err != nil {
		return FileID{}, err
	}
	return FileID{Dev: uint64(st.Dev), Ino: st.Ino}, nil //nolint:unconvert // Dev is uint64 on amd64 and arm64, not everywhere
}

// Namespace is the inode of /proc/<pid>/ns/<kind>.
func (f *FS) Namespace(pid int, kind string) (uint64, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Join(f.root, strconv.Itoa(pid), "ns", kind), &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}
