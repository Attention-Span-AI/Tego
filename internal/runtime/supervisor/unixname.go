// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// One model for every unix pathname the run passes (R11, R11a; ADR 0041's 2026-10-16 note): a connect's, an addressed
// datagram's and a bind's name is resolved in the task's own view — from /proc/<tid>/root, beneath it, for an absolute
// name and from /proc/<tid>/cwd for a relative one, with openat2's RESOLVE_NO_MAGICLINKS — to what the task's own lookup
// reaches, and the decision is made on the identity of that inode (unixPlace), never on the name's spelling. A connect
// is then made to that inode (relayUnix); a datagram is matched by it and continued (R13b's stated limit is the kernel's
// second lookup); a bind R11a could not record is remembered at the path its walk reaches, which names a refusal and
// never admits (a recorded bind walks nothing: its socket's file is decided by identity, unixorigin.go). A name that
// cannot be resolved that way — a magic link, whose target this process would resolve as itself, a walk that ends on
// procfs, where "self" is this process, a relative name from a task with a root of its own, a place this process
// cannot see at the same inode (sameInodeHere) — is refused for a connect or a datagram, and leaves an unrecorded
// bind's path unknown, which only names the refusal unix-bind-unrecorded for every socket.

// unixQuery is one unix pathname to resolve as the task tid would.
type unixQuery struct {
	tid int
	// path is the sun_path as the task passed it, up to its first NUL, never cleaned: the kernel resolves "lnk/.."
	// after following lnk, where a lexical clean drops the pair.
	path string
	// joined is R6's cleaned absolute spelling of path. The real walk never reads it; the fake kernel keys on it.
	joined string
	// parent asks for the directory a bind creates the socket in (unix_bind_bsd's kern_path_create): every component
	// but the last followed, the last one the name the socket file gets. Otherwise the whole name is followed, a final
	// symlink included, as unix_find_bsd's lookup for a connect or a send follows it.
	parent bool
}

// unixPlace is what a unix name reaches: where it lies in this process's view, the view every policy path is
// written in, and its identity there (R11a's unixFile). For a bind (unixQuery.parent) it is the directory.
type unixPlace struct {
	at   string
	file unixFile
}

// errUnixProcfs is the walk's answer for a name that ends on procfs. "self" and "thread-self" there are this
// process when this process resolves them, and no socket can be bound on procfs, so nothing the task could reach
// there is a socket a policy entry names.
var errUnixProcfs = fmt.Errorf("%w: the name ends on procfs", errOtherView)

// errNoFinal is the answer for a bind whose name has no final component a socket file can take — it ends in "/"
// (kern_path_create refuses to create there, ENOENT) or in "." or ".." (EEXIST, which bind answers EADDRINUSE) —
// so the bind binds nothing.
var errNoFinal = errors.New("supervisor: the bind's name has no final component a socket file can take")

// bindParent splits a bind's sun_path into the directory part the kernel walks (every component but the last, "."
// for a bare name, "/" for a name directly under the root) and reports whether a socket file can be created there.
// The split is on the raw bytes: the directory part keeps its "..", which openat2 resolves after the component
// before it, as the kernel does.
func bindParent(p string) (string, bool) {
	if p == "" || strings.HasSuffix(p, "/") {
		return "", false
	}
	i := strings.LastIndexByte(p, '/')
	if base := p[i+1:]; base == "." || base == ".." {
		return "", false
	}
	switch {
	case i < 0:
		return ".", true
	case i == 0:
		return "/", true
	}
	return p[:i], true
}

// bindBase is the final component of a bind's sun_path, the name its socket file takes.
func bindBase(p string) string {
	return p[strings.LastIndexByte(p, '/')+1:]
}

// openTaskDirs opens a task's root and cwd O_PATH, the directories its own lookup of a name starts from. The caller
// closes both (closeTask); nothing is left open when it fails.
func openTaskDirs(tid int) (taskView, error) {
	return openTaskView(tid, true)
}

// openTaskView is openTaskDirs, with the cwd opened, and the root compared with this process's, only when withCwd
// asks: an absolute name's walk starts at the root and never reads either. cwd is -1 when it is not opened.
func openTaskView(tid int, withCwd bool) (taskView, error) {
	base := "/proc/" + strconv.Itoa(tid)
	root, err := unix.Open(base+"/root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return taskView{}, err
	}
	if !withCwd {
		return taskView{tid: tid, root: root, cwd: -1}, nil
	}
	cwd, err := unix.Open(base+"/cwd", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(root)
		return taskView{}, err
	}
	return taskView{tid: tid, root: root, cwd: cwd, sameRoot: sameAsOwnRoot(root)}, nil
}

// UnixTarget resolves a unix name as the task q.tid would and says what it reaches (unixWalk, unixPlaceOf), with
// this process's credentials: what a datagram's decision and an unrecorded bind's path need. Credentials decide only whether a
// lookup may pass a directory or follow a symlink, never where it lands, so a walk this process completes lands where
// the task's would, or where the task's fails; a walk this process cannot complete is refused.
func (sysKernel) UnixTarget(q unixQuery) (unixPlace, error) {
	task, err := openTaskView(q.tid, !strings.HasPrefix(q.path, "/"))
	if err != nil {
		return unixPlace{}, err
	}
	defer func() {
		_ = unix.Close(task.root)
		if task.cwd >= 0 {
			_ = unix.Close(task.cwd)
		}
	}()
	fd, _, err := unixWalk(task, q)
	if err != nil {
		return unixPlace{}, err
	}
	defer unix.Close(fd) //nolint:errcheck // an O_PATH descriptor unixWalk opened
	return unixPlaceOf(fd)
}

// errWalkedOnly is a relayed connect's answer for a name that only the walk a component at a time resolved: that walk
// reads each symlink rather than following it, so it is not held to what the kernel holds a lookup to when it follows
// one (fs.protected_symlinks), and a relay that connected where it landed could make a connect the task's own would
// not. A decision that only matches the landing (a datagram's, an unrecorded bind's path) leaves the lookup to the kernel and
// takes the landing as it is.
var errWalkedOnly = fmt.Errorf("%w: the name resolved only a component at a time", errOtherView)

// unixWalk opens O_PATH what q's name reaches for the task whose root and cwd task holds (for a bind, the directory
// its socket file is created in). One openat2(2) answers it: beneath the task's root with RESOLVE_IN_ROOT for an
// absolute name, so an absolute symlink and ".." stay inside it as they do for the task, from its cwd for a relative
// one, and with RESOLVE_NO_MAGICLINKS, so a /proc/<pid>/fd, cwd or root link fails ELOOP rather than being followed
// as this process. That lookup lands where the task's lands whenever it succeeds off procfs: the only links whose
// target depends on who follows them are procfs's "self" and "thread-self", which lead nowhere but procfs save
// through a magic link (refused) or through ".." back up to /proc, the same climb for every pid. A lookup that fails
// as the task's may (ENOENT, ENOTDIR, EACCES) is walked again a component at a time (execWalk), which answers "self"
// and "thread-self" for the task and refuses every magic link, so the answer is the task's own and not what this
// process's pid directory holds; walked reports that it was that walk which landed. A relative name from a task whose
// root is not this process's is errOtherRoot: no flag roots a walk at one descriptor while starting it at another.
func unixWalk(task taskView, q unixQuery) (fd int, walked bool, err error) {
	p := q.path
	flags := uint64(unix.O_PATH | unix.O_CLOEXEC)
	if q.parent {
		dir, ok := bindParent(p)
		if !ok {
			return -1, false, errNoFinal
		}
		p = dir
		flags |= unix.O_DIRECTORY
	}
	if p == "" {
		return -1, false, unix.ENOENT
	}
	how := unix.OpenHow{Flags: flags, Resolve: unix.RESOLVE_NO_MAGICLINKS}
	start := task.cwd
	if strings.HasPrefix(p, "/") {
		start = task.root
		how.Resolve |= unix.RESOLVE_IN_ROOT
	} else if !task.sameRoot {
		return -1, false, errOtherRoot
	}
	fd, err = openat2Retry(start, p, &how)
	if err != nil {
		if !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOTDIR) && !errors.Is(err, unix.EACCES) {
			return -1, false, err
		}
		w := &execWalk{q: pathQuery{tid: task.tid, dirfd: atFDCWD, path: p}, root: task.root, noMagic: true}
		if fd, err = w.walk(start); err != nil {
			return -1, false, err
		}
		walked = true
		if q.parent && !isDirFD(fd) {
			_ = unix.Close(fd)
			return -1, false, unix.ENOTDIR
		}
	}
	if onProcfs(fd) {
		_ = unix.Close(fd)
		return -1, false, errUnixProcfs
	}
	return fd, walked, nil
}

// openat2Retry is openat2(2) retried on EINTR and, a few times, on the EAGAIN RESOLVE_IN_ROOT answers when it saw a
// rename or mount race (openat2(2)).
func openat2Retry(dir int, p string, how *unix.OpenHow) (int, error) {
	return openat2Tries(dir, p, how, 8)
}

// openat2Tries is openat2(2) retried on EINTR, and on EAGAIN up to eagain times: 0 for a lookup whose EAGAIN is its
// answer (lookupInOne's RCU-only RESOLVE_CACHED lookup, which fails so wherever the RCU walk cannot finish).
func openat2Tries(dir int, p string, how *unix.OpenHow, eagain int) (int, error) {
	for tries := 0; ; tries++ {
		fd, err := unix.Openat2(dir, p, how)
		if (err == unix.EAGAIN && tries < eagain) || err == unix.EINTR {
			continue
		}
		return fd, err
	}
}

// onProcfs reports whether fd lies on procfs; one that cannot be told is taken as procfs, which only refuses.
func onProcfs(fd int) bool {
	var sf unix.Statfs_t
	return unix.Fstatfs(fd, &sf) != nil || sf.Type == unix.PROC_SUPER_MAGIC
}

// unixPlaceOf says where the O_PATH descriptor fd lies in this process's view and what it is there: the path the kernel
// reports for its inode, walked again here following no symlink (fileHere), and the identity reached, which must be the
// descriptor's own. An inode that has no link left, or that the kernel names with no path, is no longer reachable by
// any name (ENOENT, as the task's own lookup would now answer); one whose path names another inode here, or none, lies
// in a mount tree that is not this process's (errOtherView), and no policy path can be matched against it.
func unixPlaceOf(fd int) (unixPlace, error) {
	resolved, err := readlinkRaw("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return unixPlace{}, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return unixPlace{}, err
	}
	if st.Nlink == 0 || !strings.HasPrefix(resolved, "/") {
		return unixPlace{}, unix.ENOENT
	}
	here, same := fileHere(resolved, &st)
	if !same {
		return unixPlace{}, errOtherView
	}
	return unixPlace{at: resolved, file: here}, nil
}

// unixPlaceMemo is one resolved name of a notification's.
type unixPlaceMemo struct {
	place unixPlace
	err   error
}

// unixTarget is UnixTarget for notification n: bracketed by ID_VALID on both sides, because the walk reads
// /proc/<tid> and only a live notification says the tid was still the task that trapped (R2, E3), and remembered for
// the notification, so each name is walked at most once per notification: a sendmmsg batch asks one question per
// addressed message, at most UIO_MAXIOV (1024) of them, some twice (the tail's line), and a batch alternating between
// many names would otherwise walk each of them every time. The batch is decided on one snapshot either way: the kernel
// resolves every message's name again after the answer (R13b).
func (l *Loop) unixTarget(n *notif, q unixQuery) (unixPlace, error) {
	p := n.pass()
	if m, ok := p.places[q]; ok {
		return m.place, m.err
	}
	if !l.valid(n) {
		return unixPlace{}, errGone
	}
	place, err := l.k.UnixTarget(q)
	if !l.valid(n) {
		return unixPlace{}, errGone
	}
	place.file.placed = p.tick() // reached now: a dump of the namespace's sockets begun after lists its binder (R11a)
	if p.places == nil {
		p.places = map[unixQuery]unixPlaceMemo{}
	}
	p.places[q] = unixPlaceMemo{place: place, err: err}
	return place, err
}

// unixLandedRefusal is the refusal of a datagram whose name could not be resolved in the task's view (R11a). A name
// that names nothing is refused with the errno the kernel's own lookup meets, ENOENT or ENOTDIR, and a rule that says
// so (unix-absent): continued, a symlink made before the kernel's lookup would decide where the datagram goes. Every
// other failure — a magic link or a symlink loop (ELOOP), procfs, another root, a place this process cannot see, a
// directory it may not search, its own descriptors exhausted — is a name the loop cannot place, refused
// path-unreliable with R10's errno.
func unixLandedRefusal(err error) verdictOf {
	var errno unix.Errno
	if errors.As(err, &errno) && (errno == unix.ENOENT || errno == unix.ENOTDIR) {
		absent := refuse(ruleUnixAbsent)
		absent.errno = errno
		absent.landed = true
		return absent
	}
	v := refuse(rulePathUnreliable)
	v.landed = true
	return v
}

// unixLostPath is the path, in this process's view, of the socket file a bind whose socket was not recorded makes:
// the directory its walk reached joined with the name's final component, or "" when the walk failed.
func unixLostPath(place unixPlace, err error, name string) string {
	if err != nil || place.at == "" {
		return ""
	}
	return path.Join(place.at, bindBase(name))
}
