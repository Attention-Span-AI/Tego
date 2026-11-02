// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// taskRoot is the task's root directory held through one exec's decision in a run with command rules: the first walk
// that needs it (the exec's own image walk, usually) opens /proc/<tid>/root inside its ID_VALID bracket, and the walks
// of its #! interpreters and of a loader's program start from that same descriptor, one open where each walk made its
// own (ADR 0048 C8). All of them resolve against one view of the task's root, as close to the kernel's own lookups,
// made later inside the same execve, as a fresh open per walk was. The decision's owner (recordExec) closes it.
type taskRoot struct {
	fd   int
	held bool
}

// close closes the held root, if any.
func (r *taskRoot) close() {
	if r != nil && r.held {
		_ = sysKernel{}.CloseFD(r.fd)
		r.held = false
	}
}

// inOneResolve is the resolve flags of lookupInOne's answering lookup, and inOneGuard of the lookup before it.
// resolveCached is openat2's RESOLVE_CACHED (Linux 5.12), which golang.org/x/sys does not name for Linux.
const (
	inOneResolve  = unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV
	resolveCached = 0x20
	inOneGuard    = unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS | resolveCached
)

// inOneLookups is whether this kernel answers openat2 (Linux 5.6) with RESOLVE_CACHED (5.12): asked once, of "/", so
// no pathname an agent names can turn lookupInOne off for the run.
var inOneLookups = sync.OnceValue(func() bool {
	how := unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: inOneGuard}
	fd, err := openat2Tries(unix.AT_FDCWD, "/", &how, 0)
	if err != nil {
		return !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.EPERM)
	}
	_ = sysKernel{}.CloseFD(fd)
	return true
})

// lookupInOneOn is lookupInOne's switch; tests of the component walk turn it off.
var lookupInOneOn = true

// lookupInOne looks an image walk's absolute pathname up from the task's root in two openat2 calls, where that lookup
// is provably the component walk's (walk) and so the task's own: two syscalls and the descriptor's fstatfs where the
// component walk of /bin/sh makes about thirty (ADR 0048 C8). It answers only where the component walk would reach a
// file with nothing unsure on the way and no name of its own to keep; false (any failure, any doubt) leaves the
// answer, errno, automount point, unsure step and name included, to the component walk. It is made only where no
// search check is (w.search: this process's own lookups are refused where the task's are, tier landlock), for an
// absolute pathname (the start is the task's root) that follows a final symlink (no AT_SYMLINK_NOFOLLOW) and that the
// walk does not name (w.named: a ".." component or a final ".", whose line name only the walk takes).
//
// The lookup that answers is RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV (inOneResolve), and with them it is
// the task's: RESOLVE_IN_ROOT resolves an absolute symlink from the task's root and keeps ".." at it, as the kernel does
// for the task and the component walk does; RESOLVE_NO_MAGICLINKS refuses every procfs magic link; RESOLVE_NO_XDEV
// refuses EXDEV wherever the lookup would cross a mount point, so every component lies on the root's mount, whose
// filesystem is no procfs (the descriptor's fstatfs says so; a root on procfs is left to the component walk): no
// "self" or "thread-self" was resolved as this process rather than the task (walk), and no procfs directory of another
// process was passed (procForeign). Everything else, symlinks, their count, ".", "..", a trailing slash, a nosymfollow
// mount, permissions with this process's credentials, is the kernel's own lookup, which is what the component walk
// asks one component at a time.
//
// The walk mounts no automount point (automountLookup), and RESOLVE_NO_XDEV alone does not keep that: the kernel's
// handle_mounts refuses EXDEV only after traverse_mounts has run, follow_automount included, and on 5.14 (RHEL 9) the
// lookup mounts an automount point it meets and then refuses EXDEV (TestLookupInOneNeverMountsAnAutomountPoint). So the
// same pathname is first looked up with RESOLVE_CACHED|RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS (inOneGuard): the RCU
// walk alone, from the dentry cache, which never mounts (follow_automount runs only in the reference walk, so an
// unmounted automount point fails it EAGAIN), never calls a filesystem's lookup and never waits on a daemon. Only where
// it reaches a file is the answering lookup made, and that one then crosses nothing the first did not just find
// mounted (an expiry in the microseconds between the two is the exception, and the kernel's own exec lookup would
// mount it again). Rejected: the answering lookup without RESOLVE_NO_XDEV (it crosses into procfs, where "self" is
// this process: a path through a symlink to /proc/self/task/<one of this process's threads>/../../../.. reaches a file
// where the task's own lookup fails ENOENT); one lookup with RESOLVE_CACHED and RESOLVE_NO_XDEV both (the RCU walk
// fails EAGAIN at every dentry another mount namespace mounts on, /usr and /etc wherever a systemd unit protects the
// system, so the lookup missed on most hosts); the answering lookup alone (it mounted on 5.14, above); choosing between
// the two by kernel version (nothing upstream marks the line, and the guard costs about 1.3 us); the one-call lookup at
// the search-checked tiers (its permission checks are root's, not the task's).
func (w *execWalk) lookupInOne() (int, bool) {
	q := w.q
	if !lookupInOneOn || w.search || w.named || q.nofollow || q.predict || q.create || q.parent || q.directory ||
		!strings.HasPrefix(q.path, "/") || !inOneLookups() {
		return -1, false
	}
	how := unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: inOneGuard}
	fd, err := openat2Tries(w.root, q.path, &how, 0)
	if err != nil {
		return -1, false
	}
	_ = sysKernel{}.CloseFD(fd)
	how.Resolve = inOneResolve
	if fd, err = openat2Tries(w.root, q.path, &how, 0); err != nil {
		return -1, false
	}
	var sfs unix.Statfs_t
	if unix.Fstatfs(fd, &sfs) != nil || sfs.Type == unix.PROC_SUPER_MAGIC {
		_ = sysKernel{}.CloseFD(fd)
		return -1, false
	}
	return fd, true
}
