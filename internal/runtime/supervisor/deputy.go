// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/deputy"
)

// DeputyPinner is the open deputy's walk (deputy.PinFunc, ADR 0041 D2) for tego __open-deputy: deputyPin with the
// follower's facts its walk needs read now, before deputy.Main installs a filter that allows no read and no getuid, and
// with this process's thread group as the deputy's own, whose /proc tree a held open may never reach (deputyProcDepth,
// landsInDeputyProc).
func DeputyPinner() deputy.PinFunc {
	f := currentFollowFacts()
	tgid := os.Getpid()
	return func(q deputy.PinQuery) (deputy.Pinned, error) { return deputyPin(q, f, tgid) }
}

// deputyPin is the open deputy's walk (deputy.PinFunc, ADR 0041 D2): the walk this loop's own decisions take
// (walkExec), made by the deputy, a process of the run, so every lookup on the way is the run's own:
// its credentials, its root and mount namespace, its search permissions. It starts from /proc/<tid>/root and the
// task's cwd or dirfd, as the task's lookup does, and reads /proc/self as q.TGID: the deputy reads no /proc file.
//
//   - Empty pins the descriptor itself (AT_EMPTY_PATH).
//   - Excl (O_CREAT|O_EXCL) pins the parent and names the final component, never followed: an existing one, a
//     symlink included, is EEXIST, as the kernel answers it.
//   - Create pins what walkExec reaches for an O_CREAT open (q.create): the file, or the directory a missing final
//     component is made in, a dangling final symlink followed to its target as the kernel's open follows it.
//   - Otherwise walkExec's descriptor, a final symlink followed unless Nofollow makes it ELOOP (ENOTDIR for an open
//     that needs a directory, Directory, as the kernel answers O_DIRECTORY|O_NOFOLLOW and O_TMPFILE|O_NOFOLLOW).
//
// A pathname whose final component is "", "." or ".." or that ends in "/" is walked whole: the kernel names no leaf
// there. A Create or Excl pin of a name followed by "/" is answered as the kernel answers that open, never pinned
// (trailingSlashCreate). The result says whether the object was reached through a descriptor (deputy.Pinned's
// ByDescriptor): the AT_EMPTY_PATH descriptor, a magic link as the walk's last step, or a relative walk's start named
// by "." alone.
//
// Every symlink is followed only where the kernel's lookup would follow it for the task (f, the follower's facts): a
// trailing link fs.protected_symlinks refuses is EACCES and a link on a nosymfollow mount ELOOP, as the task's own open
// answers; the walk followed them in userspace and pinned their targets. The deputy takes f once, before its filter,
// through DeputyPinner.
//
// No pin reaches the thread group deputyTgid's /proc tree, the deputy's own (ADR 0041 D4): a lookup there, the walk's
// or the final component's an Excl or trailing-slash Create pin names, is EACCES (deputyProcDepth), and so is a pin
// that ends inside it with no lookup there, through a magic link or an AT_EMPTY_PATH descriptor (landsInDeputyProc).
func deputyPin(q deputy.PinQuery, f *followFacts, deputyTgid int) (deputy.Pinned, error) {
	none := deputy.Pinned{FD: -1}
	pq := pathQuery{tid: q.TID, dirfd: q.DirFD, path: q.Path, nofollow: q.Nofollow, create: q.Create, directory: q.Directory}
	if q.TGID <= 0 {
		return none, unix.EINVAL
	}
	if q.Empty {
		fd, err := unix.Open(dirOf("/proc/"+strconv.Itoa(q.TID), q.DirFD), unix.O_PATH|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) && q.DirFD != atFDCWD {
			err = unix.EBADF // no such descriptor: what the task's own call is answered
		}
		if err != nil {
			return none, err
		}
		if landsInDeputyProc(fd, deputyTgid, q.TGID) {
			_ = unix.Close(fd)
			return none, unix.EACCES
		}
		return deputy.Pinned{FD: fd, ByDescriptor: true}, nil
	}
	dir, base := splitFinal(q.Path)
	named := base != "" && base != "." && base != ".."
	if (q.Create || q.Excl) && named && strings.HasSuffix(q.Path, "/") {
		return none, trailingSlashCreate(pq, dir, base, q.TGID, f, deputyTgid)
	}
	if !q.Excl {
		if p, ok := pinInRun(pq); ok {
			return p, nil
		}
	}
	whole := !named || strings.HasSuffix(q.Path, "/")
	if q.Excl && !whole {
		parent := pq
		parent.path, parent.nofollow, parent.create = dir, false, false
		pp, err := walkAs(parent, q.TGID, false, f, deputyTgid)
		if err != nil {
			return none, err
		}
		pfd := pp.FD
		if !isDirFD(pfd) {
			_ = unix.Close(pfd)
			return none, unix.ENOTDIR
		}
		if deputyProcDepth(pfd, deputyTgid, q.TGID) != notDeputyProc {
			_ = unix.Close(pfd)
			return none, unix.EACCES // the final component's lookup in the deputy's own /proc tree
		}
		var st unix.Stat_t
		switch err := unix.Fstatat(pfd, base, &st, unix.AT_SYMLINK_NOFOLLOW); {
		case err == nil:
			_ = unix.Close(pfd)
			return none, unix.EEXIST
		case !errors.Is(err, unix.ENOENT):
			_ = unix.Close(pfd)
			return none, err
		}
		return deputy.Pinned{FD: pfd, Leaf: base, ByDescriptor: pp.ByDescriptor}, nil
	}
	return walkAs(pq, q.TGID, q.Create, f, deputyTgid)
}

// trailingSlashCreate is the kernel's answer to an O_CREAT open whose final component is a name followed by "/": the
// errno of the walk to its parent, ENOTDIR for a parent that is no directory, EACCES where the task may not search the
// parent (link_path_walk's may_lookup runs before the final component too), and otherwise EISDIR, whatever the name
// holds or lacks, since open_last_lookups refuses the slash before it looks the name up. The walk had answered the
// name's own ENOENT or ENOTDIR, or pinned a directory the reopen then opened (review finding F4's family).
func trailingSlashCreate(q pathQuery, dir, base string, tgid int, f *followFacts, deputyTgid int) error {
	parent := q
	parent.path, parent.nofollow, parent.create = dir, false, false
	pp, err := walkAs(parent, tgid, false, f, deputyTgid)
	if err != nil {
		return err
	}
	pfd := pp.FD
	defer unix.Close(pfd) //nolint:errcheck // an O_PATH descriptor this call opened
	if !isDirFD(pfd) {
		return unix.ENOTDIR
	}
	if deputyProcDepth(pfd, deputyTgid, tgid) != notDeputyProc {
		return unix.EACCES // the name's lookup in the deputy's own /proc tree
	}
	// The lookup of the name is the deputy's, under the task's credentials, so its search check is the task's; any
	// other answer it gives (the name missing, too long, a symlink) the kernel's open never reaches.
	fd, err := unix.Openat(pfd, base, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(fd)
	}
	if errors.Is(err, unix.EACCES) {
		return unix.EACCES
	}
	return unix.EISDIR
}

// pinInRun is the pin in one kernel lookup, for the deputy alone: it shares the task's root, mount namespace and
// credentials (the run's filter refuses chroot's way in, a new user or mount namespace), so openat2(2) from the task's
// cwd or dirfd, or from the shared root, resolves exactly as the task's own lookup does, every symlink, ".." and
// trailing slash included, save what procfs computes from the caller: "self" and "thread-self" would name the deputy,
// and a magic link (/proc/<pid>/fd/N, cwd, root) is followed by the walk alone. RESOLVE_NO_MAGICLINKS makes the lookup
// fail on any magic link, and a result on procfs is walked again, so every such path takes the walk (walkAs); so does
// any failure, the walk giving the errno the task's lookup meets. ok is false when the walk must decide. A create whose
// final component is missing, or whose final component is a dangling symlink the open would follow, is the walk's too.
// With no magic link on the way, the object was reached by a name, save a relative pathname of "." components alone,
// which names the walk's start, the task's cwd or dirfd (deputy.Pinned's ByDescriptor).
func pinInRun(q pathQuery) (deputy.Pinned, bool) {
	none := deputy.Pinned{FD: -1}
	dirfd := unix.AT_FDCWD
	relative := !strings.HasPrefix(q.path, "/")
	if relative {
		d, err := unix.Open(dirOf("/proc/"+strconv.Itoa(q.tid), q.dirfd), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			return none, false
		}
		defer unix.Close(d) //nolint:errcheck // an O_PATH descriptor this call opened
		dirfd = d
	}
	flags := uint64(unix.O_PATH | unix.O_CLOEXEC)
	if q.nofollow {
		flags |= unix.O_NOFOLLOW
	}
	if q.directory {
		// The open needs a directory: so does the lookup, as the task's own (LOOKUP_DIRECTORY). A target that is no
		// directory fails here and the walk gives the kernel's ENOTDIR; and an idle automount point the open names is
		// mounted by this lookup as by the task's (follow_automount mounts for a directory lookup, never for a bare
		// O_PATH one).
		flags |= unix.O_DIRECTORY
	}
	how := unix.OpenHow{Flags: flags, Resolve: unix.RESOLVE_NO_MAGICLINKS}
	for {
		fd, err := unix.Openat2(dirfd, q.path, &how)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return none, false
		}
		var sf unix.Statfs_t
		if unix.Fstatfs(fd, &sf) != nil || sf.Type == unix.PROC_SUPER_MAGIC {
			_ = unix.Close(fd)
			return none, false
		}
		if q.nofollow {
			// O_PATH|O_NOFOLLOW pins a final symlink, which the open the walk stands for fails ELOOP on.
			var st unix.Stat_t
			if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT == unix.S_IFLNK {
				_ = unix.Close(fd)
				return none, false
			}
		}
		return deputy.Pinned{FD: fd, ByDescriptor: relative && onlyDots(q.path)}, true
	}
}

// onlyDots reports whether every component of p is "." (or empty): a relative pathname that names its start.
func onlyDots(p string) bool {
	for p != "" {
		var c string
		c, p, _ = strings.Cut(p, "/")
		if c != "" && c != "." {
			return false
		}
	}
	return true
}

// walkAs is walkExec, as an O_CREAT open walks when create is set, with the task's thread group known: the walk's
// /proc/self is answered as tgid without reading /proc/<tid>/status. deputyTgid is the thread group of the process running the
// walk (the open deputy), whose own /proc tree the walk refuses to reach (deputyProcDepth); 0 disables that guard.
func walkAs(q pathQuery, tgid int, create bool, f *followFacts, deputyTgid int) (deputy.Pinned, error) {
	w, start, done, err := newWalk(q)
	if err != nil {
		return deputy.Pinned{FD: -1}, err
	}
	defer done()
	w.tgid = tgid
	w.create = create
	w.follow = f
	w.deputyTgid = deputyTgid
	fd, err := w.walk(start)
	if err != nil {
		return deputy.Pinned{FD: -1}, err
	}
	return deputy.Pinned{FD: fd, Leaf: w.missing, ByDescriptor: w.byFD}, nil
}
