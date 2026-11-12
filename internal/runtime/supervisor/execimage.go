// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
)

// fileID is a file's identity: the device and inode a Landlock rule is bound to (enforce-landlock R3 opens
// each exec entry and grants EXECUTE on what it reaches, not on its name).
type fileID struct{ dev, ino uint64 }

// pathQuery is what one execve or execveat names, or the path an fs syscall names, exactly as the trapping
// task passed it (R15b, R16, R16b).
type pathQuery struct {
	// tid is the task that trapped. Its /proc entry is the one whose root, cwd and descriptor table the
	// kernel resolves the exec against.
	tid int
	// dirfd is execveat's descriptor (atFDCWD for execve and for AT_FDCWD).
	dirfd int32
	// path is the pathname as read from the task, uncleaned: the kernel resolves "link/.." physically,
	// and a lexically cleaned spelling can name another file (walkExec).
	path string
	// empty is execveat(dirfd, "", AT_EMPTY_PATH): the image is dirfd itself.
	empty bool
	// nofollow is AT_SYMLINK_NOFOLLOW: a final symlink is ELOOP, as the kernel's exec open answers it.
	nofollow bool
	// create is an open with O_CREAT (and without O_EXCL, which makes nofollow): the kernel follows a final
	// symlink whose target does not exist and creates that target, so FSTarget follows it too (walkExec).
	create bool
	// directory is an open that needs a directory (O_DIRECTORY, or O_TMPFILE, which carries it), for the open deputy's
	// walk (deputyPin): with nofollow, a final symlink is ENOTDIR, the kernel's answer (do_open checks LOOKUP_DIRECTORY
	// before may_open refuses the symlink ELOOP).
	directory bool
	// parent says the syscall looks up only the final component's directory and makes, removes or renames the name in it
	// (filename_parentat, filename_create: unlink, rmdir, mkdir, mknod, symlink, both ends of a rename, a link's new name,
	// a unix bind). It refuses a final "." or ".." before a lookup of its own (EEXIST, EBUSY, EISDIR, EINVAL, ENOTEMPTY),
	// so FSTarget walks no such end, and a trailing slash does not have it follow a final symlink: the name is looked up
	// in its directory as it is (lookup_one_qstr_excl), where FSTarget lands it. Every other
	// syscall resolves a final "." or ".." where path_lookupat lands it,
	// physically, followed or not, since neither is ever a symlink: an attribute change with AT_SYMLINK_NOFOLLOW of
	// out/lk/.. acts on where out/lk leads, then up.
	parent bool
	// joined is R6's cleaned absolute spelling of path, the one the record carries. The real walk never
	// reads it; the fake kernel keys its answers on it.
	joined string
	// deletedBase says path was joined to a directory link that ends in " (deleted)" (reader.resolve). The
	// kernel spells an unlinked directory that way, and a live directory may carry that name too, so joined
	// can name a directory other than the one the task's lookup starts in. Only the walk answers such a
	// query (spellingShape).
	deletedBase bool
	// head asks ExecImage for the image's first binprmBuf bytes, read through the walk's own descriptor
	// (ADR 0048 (3)): a run with command rules reads every image's #! line, since any ruled tool can be an interpreter.
	head bool
	// nodePin asks only for Node build attestation of a loader's mapped program.
	// Mapping that file does not require MAY_EXEC; q.head's exec permission check
	// belongs only to an actual binfmt image/interpreter walk.
	nodePin bool
	// predict is compile --test's question (Land), asked of the tree as compile finds it, before the agent runs. A
	// component that does not exist yet is taken as a directory the agent makes later: the names after it lie beneath
	// it, a ".." among them climbs back out of it, and once the walk is back in the existing tree it goes on there,
	// physically, symlinks followed. The answer is the place the run's walk reaches once each missing component is made
	// a directory, so a dangling symlink, intermediate or final where the syscall follows it, is followed to its target
	// as the kernel follows it, which realpath -m answers too. The run's own walks never set it: there a missing
	// component fails the task's lookup (ENOENT).
	predict bool
	// kid asks ExecImage for the image's identity as the decision plane holds it (kernelID), for a pinned run's pin
	// (ADR 0048 (3) P2).
	kid bool
	// root, when set, holds the task's root for every walk of one exec's decision (taskRoot); nil has each walk open its
	// own.
	root *taskRoot
}

// binprmBuf is BINPRM_BUF_SIZE, the bytes of an image's start the kernel reads for its binfmt handlers and the #!
// line.
const binprmBuf = 256

// execImage describes the file an exec query resolved to.
type execImage struct {
	id fileID
	// linked is st_nlink > 0. A memfd is created unlinked, and a file unlinked since it was opened is too:
	// neither has a path any rule can name.
	linked bool
	// nlink is st_nlink from the same fstat: more than one marks a multicall image to the command rules
	// (execmatch.Facts.Links). It is the inode's count, not a name the agent chose, and needs no read of its memory.
	nlink uint64
	// link is readlink(2) of the image's descriptor in this process's view, as the kernel spells it: a
	// memfd reads "/memfd:<name> (deleted)", another anonymous inode "anon_inode:[...]".
	link string
	// here says link, looked up in this process's own view with no symlink followed, reaches this same
	// inode (sameInodeHere), so link is where the file lies in the view every policy path is written in.
	here bool
	// changed is the inode's ctime: when its content or metadata last changed (stat(2)).
	changed time.Time
	// regular is S_IFREG, read from the walk's own O_PATH descriptor. Only a regular file is ever reopened to read
	// its head: the kernel answers the exec of anything else EACCES before it reads a byte (do_open_execat), and an
	// open of a device, a FIFO or a socket can act (a watchdog arms on open), which a supervisor that may run as root
	// must never do on a name the agent chose.
	regular bool
	// mode, uid and gid are the image's st_mode permission bits and owner, for execRefused.
	mode     uint32
	uid, gid uint32
	// head is the image's first binprmBuf bytes when the query asked for them and they could be read; nil
	// otherwise (an execute-only file, an anonymous image, and anything not a regular file, which is never opened).
	// It is read by reopening the walk's own O_PATH descriptor through /proc/self/fd, never by resolving the path
	// again, and kept only when the reopened file is the walked inode (readHead).
	head []byte
	// nodeVersion is attested from the opened executable, never its path/argv.
	nodeVersion string
	// name is the name an exec line gives a pathname with a ".." component (lineName's rule): where this walk landed the
	// directory of its final component, as spelled, joined with that component, never followed. "" for any other
	// pathname, and where that directory is not where it lies in this process's view.
	name string
	// kid is the image's identity as the decision plane holds it, read when the query asked (pathQuery.kid); kidOK says
	// it was, and kidErr why not.
	kid    fileID
	kidOK  bool
	kidErr error
	// unsure says the walk that reached the image passed a directory whose search answer for the task this process
	// could not be sure of (walkImage): the task's own lookup may be refused EACCES on the way, so nothing read from
	// the image (its #! line, and a later walk that line leads to) may change the errno the task is answered
	// (shebangChain).
	unsure bool
}

// fileless reports whether the image is anonymous: a memfd, another anonymous inode, or a file unlinked
// since it was opened (SEMANTICS §4). None of these has a linked path, which is what Landlock's file_open hook
// and tier 2's FAN_OPEN_EXEC_PERM both key on: is_nouser_or_private() in security/landlock/fs.c allows a
// file on an SB_NOUSER superblock outright, and a memfd lives on one. It is decided on the inode's link
// count and the kernel's own spelling of the descriptor, never on a name the agent chose: a memfd's name
// follows "/memfd:" and may hold "/" and "..", which is why link is never cleaned (recordExec).
func (img execImage) fileless() bool {
	return !img.linked || strings.HasPrefix(img.link, "/memfd:") || !strings.HasPrefix(img.link, "/")
}

// maxSymlinks is the kernel's MAXSYMLINKS: the number of symlinks one lookup may follow before ELOOP.
const maxSymlinks = 40

// procRootIno is PROC_ROOT_INO, the inode number of every procfs root.
const procRootIno = 1

// ExecImage resolves an exec query to the file the kernel would load, walked the way the task's own lookup
// walks it, and describes that file (R16b). The caller brackets it with ID_VALID: every descriptor it opens
// is reached through /proc/<tid> (R2, E3). The image's name is this walk's (execImage.name), and a walk that fails
// past the directory it names still answers it.
func (k sysKernel) ExecImage(q pathQuery) (execImage, error) {
	base := "/proc/" + strconv.Itoa(q.tid)
	var fd int
	var err error
	unsure, name := false, ""
	if q.empty {
		fd, err = unix.Open(dirOf(base, q.dirfd), unix.O_PATH|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) && q.dirfd != atFDCWD {
			err = unix.EBADF // no such descriptor: what the task's own execveat is answered
		}
	} else {
		fd, unsure, name, err = walkImage(q)
	}
	if err != nil {
		return execImage{name: name}, err
	}
	defer unix.Close(fd) //nolint:errcheck // an O_PATH descriptor this call opened
	img, err := describeImage(fd)
	img.unsure, img.name = unsure, name
	if err == nil && q.kid {
		img.kid, img.kidErr = k.kernelID(fd)
		img.kidOK = img.kidErr == nil
	}
	if err == nil && (q.head || q.nodePin) && img.regular {
		// A file the kernel's do_open_execat is sure to refuse the task, EACCES before it reads a byte, is that
		// lookup's failure, and its head is never read: the supervisor, root at tiers cgroup and bpflsm, would
		// otherwise read a file the task cannot run, and answer from its #! line what the task cannot learn.
		if q.head && execRefused(fd, img, q.tid) {
			return execImage{name: name}, unix.EACCES
		}
		// Only a regular file is reopened: anything else keeps head nil, its form unknown, and a run with command
		// rules refuses it image-unreadable with EACCES, the kernel's own answer to its exec.
		if execmatch.NodeName(path.Base(q.path)) || execmatch.NodeName(path.Base(img.link)) {
			img.head, img.nodeVersion = readExecBytes(fd, img.id, true)
		} else if q.head {
			img.head = readHead(fd, img.id)
		}
	}
	return img, err
}

// taskCreds reads a task's credentials for execRefused; tests replace it.
var taskCreds = sys.ReadTaskCreds

// execRefused reports whether the kernel is sure to refuse the task's exec of a regular file with EACCES before it
// reads a byte of it (do_open_execat: path_noexec, then inode_permission's MAY_EXEC): no execute bit at all, which
// even CAP_DAC_OVERRIDE needs one of; a noexec mount, or procfs or sysfs (SB_I_NOEXEC); or permission bits that
// give the task's filesystem ids no execute bit, read as generic_permission reads them. It answers false whenever
// it cannot be sure: the bits are 0111 in every class, the task's credentials cannot be read, the task holds
// CAP_DAC_OVERRIDE, or the file has an access ACL, whose entries are not read here. The head is then read as before.
func execRefused(fd int, img execImage, tid int) bool {
	if img.mode&0o111 == 0 {
		return true
	}
	var sfs unix.Statfs_t
	if unix.Fstatfs(fd, &sfs) == nil {
		if sfs.Flags&unix.ST_NOEXEC != 0 || sfs.Type == unix.PROC_SUPER_MAGIC || sfs.Type == unix.SYSFS_MAGIC {
			return true
		}
	}
	if img.mode&0o111 == 0o111 {
		return false
	}
	creds, err := taskCreds(tid)
	if err != nil || creds.CapEff&(1<<unix.CAP_DAC_OVERRIDE) != 0 {
		return false
	}
	if creds.FSUID == img.uid {
		return img.mode&0o100 == 0 // the owner class, which an ACL does not change
	}
	if hasAccessACL(fd) {
		return false
	}
	if creds.FSGID == img.gid || slices.Contains(creds.Groups, img.gid) {
		return img.mode&0o010 == 0
	}
	return img.mode&0o001 == 0
}

// hasAccessACL reports whether a file may have a POSIX access ACL: true unless getxattr answers that it has none.
func hasAccessACL(fd int) bool {
	_, err := unix.Getxattr("/proc/self/fd/"+strconv.Itoa(fd), "system.posix_acl_access", nil)
	return !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.EOPNOTSUPP)
}

// headOpen is readHead's reopen. Tests wrap it to see which descriptors are reopened.
var headOpen = func(p string) (int, error) {
	return unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
}

// readHead reads an image's first binprmBuf bytes through the walk's own descriptor (ADR 0048 (3)): it reopens the
// O_PATH descriptor with O_RDONLY through /proc/self/fd, a reopen of the same inode that never resolves the path
// again, and keeps the bytes only when the reopened file is a regular file of the walked identity. nil when the
// file cannot be read (an execute-only file at tier 1): the exec's form is then unknown. The caller reopens only a
// file the O_PATH descriptor's fstat found regular (execImage.regular).
func readHead(fd int, id fileID) []byte {
	head, _ := readExecBytes(fd, id, false)
	return head
}

// readExecBytes binds the inventory to the same inode as the executable walk.
// Version strings and node --version are not attestations. Hash only named Node
// images, at most 256 MiB, and reject a changed/read-failed file. Shared-libnode
// loader hashes are intentionally absent: they do not bind the runtime library.
func readExecBytes(fd int, id fileID, node bool) ([]byte, string) {
	rd, err := headOpen("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return nil, ""
	}
	defer unix.Close(rd) //nolint:errcheck // a read-only descriptor this call opened
	var st unix.Stat_t
	if err := unix.Fstat(rd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || uint64(st.Dev) != id.dev || st.Ino != id.ino {
		return nil, ""
	}
	buf := make([]byte, binprmBuf)
	n, err := unix.Pread(rd, buf, 0)
	if err != nil || n < 0 {
		return nil, ""
	}
	head := buf[:n]
	if !node || st.Size <= 0 || st.Size > 256<<20 {
		return head, ""
	}
	return head, nodeBuilds.version(rd, st)
}

// dirOf is the /proc link of the directory an exec starts from: the task's cwd, or its dirfd.
func dirOf(base string, dirfd int32) string {
	if dirfd == atFDCWD {
		return base + "/cwd"
	}
	return base + "/fd/" + strconv.Itoa(int(dirfd))
}

// describeImage reads what the decision needs of the image's descriptor.
func describeImage(fd int) (execImage, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return execImage{}, err
	}
	link, err := readlinkRaw("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return execImage{}, err
	}
	img := execImage{
		id:      fileID{dev: st.Dev, ino: st.Ino},
		linked:  st.Nlink > 0,
		nlink:   uint64(st.Nlink),
		link:    link,
		changed: time.Unix(st.Ctim.Sec, st.Ctim.Nsec),
		regular: st.Mode&unix.S_IFMT == unix.S_IFREG,
		mode:    st.Mode & 0o7777,
		uid:     st.Uid,
		gid:     st.Gid,
	}
	if img.linked && strings.HasPrefix(link, "/") {
		img.here = sameInodeHere(link, &st)
	}
	return img, nil
}

// walkExec resolves q.path O_PATH the way the task's own exec lookup does, and returns a descriptor of what
// it reaches. It is a userspace path walk, one component at a time from the task's root (absolute) or its
// cwd or dirfd (relative), because no single kernel lookup made from this process reaches what the task's
// does:
//
//   - A symlink is read and its target walked in turn, an absolute one from the task's root, so a link the
//     agent planted in its write directory is followed as the kernel follows it.
//   - procfs's "self" and "thread-self" name the *caller*. Resolved by this process they would be this
//     process and its descriptors, so at a procfs root they are read as the task's thread group and thread
//     — which is what makes /proc/self/fd/N, /dev/fd/N (a link to /proc/self/fd), /proc/thread-self/fd/N
//     and /proc/self/task/<tid>/fd/N all reach the task's descriptor.
//   - Every other procfs symlink (/proc/<pid>/fd/N, exe, cwd, root, map_files/...) is a magic link, whose
//     target is decided by the pid directory it sits in and not by the caller, and whose readlink string
//     is not a path the file can be reached by: the kernel follows it here, as it would for the task.
//   - ".." at the task's root stays there, as it does for the task.
//
// A walk that cannot vouch for what it reached fails rather than guessing (EXDEV: a procfs instance that
// is not this process's, whose pid numbers "self" cannot be translated into). Every error is an errno the
// decision maps onto the task's answer (lookupErrno).
//
// For an open with O_CREAT (q.create), where the whole path exists it returns what it returns otherwise and missing is
// "". Where only the final component is missing — after every symlink on the way is followed, a final dangling one
// included — it returns the directory that component would be created in and its name (missing), which is where the
// kernel's open creates the file: a symlink the agent planted that points at a name not yet there is followed to that
// name, not created in place of the link. For compile --test's question (q.predict), where part of the path does not
// exist yet, it returns the existing directory that part lies beneath and the part itself, cleaned (missing), which is
// where the run's walk lands once that part is made. Any other walk's missing is "". With named, name is the walk's
// name for a pathname with a ".." component (execWalk.named), answered also when the walk fails past the directory it
// names.
func walkExec(q pathQuery, named bool) (fd int, missing, name string, err error) {
	w, start, done, err := newWalk(q)
	if err != nil {
		return -1, "", "", err
	}
	defer done()
	w.create = q.create
	w.named = named && namedByWalk(q)
	fd, err = w.walk(start)
	return fd, w.missing, w.name, err
}

// walkImage is walkExec for an exec's own pathname (ExecImage), with the task's search permission held to every
// directory the walk looks a component up in, as the kernel's link_path_walk holds it (may_lookup, MAY_EXEC on the
// directory, before each component), wherever this process's own lookups pass directories the task's cannot
// (searchChecked: it holds CAP_DAC_OVERRIDE or CAP_DAC_READ_SEARCH, as the supervisor does at tiers cgroup and
// bpflsm). A directory the task is sure not to be able to search ends the walk with EACCES, the kernel's own answer
// there; a directory whose answer is not sure (an access ACL, a filesystem outside the closed list known to decide by
// what is read here (modeBitsFS), credentials that cannot be read) turns a failed walk's errno into EACCES and leaves a
// walk that reached a file as it was. So the
// answer a root supervisor gives from its walk (a miss's ENOENT, R16b (0); a refusal carrying the lookup's errno)
// never tells the task whether a name exists in a directory it cannot search, or what an unreachable script's #! line
// names. At tier landlock the supervisor runs with the agent's own credentials, its own
// lookup is refused where the task's is, and no check is made. The check goes on past an unsure directory, so a
// directory further down that the task is sure not to search still ends the walk with EACCES; unsure reports that
// the walk passed one, and the caller then lets nothing read from the image change the
// task's errno (execImage.unsure).
//
// At every tier, a procfs magic link (/proc/<pid>/cwd, root, exe, fd/N, ns/*, map_files/*) of a process other than
// the task's own thread group (ownMagicDir) is an unsure step, as an unsure directory is: the kernel follows such a
// link for the task only when ptrace_may_access(PTRACE_MODE_READ_FSCREDS) lets the task at that process, which this
// process cannot decide (Landlock's ptrace scoping and the other LSMs answer it, dumpability changes), while its own
// rights (root at tiers cgroup and bpflsm, a process outside the agent's Landlock domain at tier landlock) let it
// follow a link the task cannot. A walk through one that fails is EACCES, the kernel's answer wherever the task is
// refused, so a miss there never tells the task whether a name exists behind the link; a walk that reaches a file is
// decided as before, and nothing read from that file changes the task's errno. Rejected: EACCES for every such
// link, which refused the exec of a granted file through a run process's descriptor the kernel lets the task follow,
// and recorded a memfd reached that way by its spelling rather than as fileless; reading ptrace_may_access's
// credential and dumpability rules here, which still leaves the LSMs unread.
//
// At every tier, a procfs directory of a process other than the task's own thread group (procForeign: its pid directory
// or any directory beneath it, such as /proc/<pid>/fdinfo, whose 0555 bits say nothing of the ptrace_may_access check
// its permission operation makes) is an unsure step too, for the same reason.
//
// A walk that failed at an automount point, looking a name up there or stepping ".." out of it, is no miss
// (automountLookup): this walk's O_PATH lookup of an intermediate component does not trigger an automount the kernel's
// own walk would.
//
// name is the walk's name for a pathname with a ".." component (execWalk.named), kept when the walk fails past it too.
func walkImage(q pathQuery) (fd int, unsure bool, name string, err error) {
	w, start, done, err := newWalk(q)
	if err != nil {
		return -1, false, "", err
	}
	defer done()
	w.search = searchChecked()
	w.image = true
	w.named = namedByWalk(q)
	if fd, ok := w.lookupInOne(); ok {
		return fd, false, "", nil
	}
	fd, err = w.walk(start)
	if err != nil && w.automount {
		err = automountLookup{err}
	}
	if err != nil && w.unsure && !errors.Is(err, unix.EACCES) && execLookupFailure(err) {
		return -1, true, w.name, unix.EACCES
	}
	return fd, w.unsure, w.name, err
}

// automountLookup is a walk failure met at an automount point (walkImage): a name looked up there, or a ".." step out
// of it. The walk opens every component O_PATH as a final lookup, with no LOOKUP_PARENT, LOOKUP_DIRECTORY, LOOKUP_OPEN
// or LOOKUP_AUTOMOUNT, so the kernel's follow_automount does not mount an idle automount point whose dentry is positive
// (a direct or systemd autofs mount point, an S_AUTOMOUNT stub): the walk lands on the point itself and the next name
// is missing there (an autofs root, an empty stub directory such as debugfs's tracing) or nothing can be looked up from
// it at all, ".." included (an NFS submount or referral stub has no lookup operation: ENOTDIR), where the kernel's walk
// of the same path, as an intermediate component, mounts it, finds the file or climbs back out. Such a failure keeps
// the errno it wraps (lookupErrno, execLookupFailure) but is not a miss (execMissing): the exec is decided as it was
// before R16b (0), continued where a contract with no exec: section or a granted spelling continues it, and recorded.
// An indirect autofs map's key is a negative dentry, which follow_automount mounts on any lookup, this walk's
// included, so the walk reaches what lies under it and misses nothing there. Rejected:
// triggering the mount of a positive automount point from this walk, which would have a root supervisor mount
// filesystems for an exec it then refuses. Only autofs was recognised, and a walk under any
// other automount point (NFS crossmnt and referral submounts, CIFS DFS links, FUSE submounts, debugfs's tracing) missed
// a file that exists, answered with no line; a ".." step out of a stub was still a miss.
type automountLookup struct{ err error }

func (e automountLookup) Error() string { return e.err.Error() + " (at an automount point)" }
func (e automountLookup) Unwrap() error { return e.err }

// atAutomount reports whether the directory fd is an automount point the walk landed on without mounting it: an inode
// the filesystem marked S_AUTOMOUNT, which statx(2) reports as STATX_ATTR_AUTOMOUNT (NFS, CIFS and FUSE submount stubs,
// debugfs's tracing, AFS mountpoints), or a directory on autofs, whose automount flag is on the dentry and not on the
// inode, so that statx does not report it. The attribute is read without its attributes_mask bit, which kernels before
// 5.8 do not set for it: the kernel sets the attribute itself only for an S_AUTOMOUNT inode. Tests replace it.
var atAutomount = func(fd int) bool {
	var stx unix.Statx_t
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT|unix.AT_SYMLINK_NOFOLLOW, 0, &stx) == nil &&
		stx.Attributes&unix.STATX_ATTR_AUTOMOUNT != 0 {
		return true
	}
	var sfs unix.Statfs_t
	return unix.Fstatfs(fd, &sfs) == nil && uint32(sfs.Type) == unix.AUTOFS_SUPER_MAGIC
}

// searchChecked reports whether this process's lookups can pass a directory without search permission, which is
// when walkImage checks the task's own. Tests replace it.
var searchChecked = sync.OnceValue(func() bool {
	c, err := sys.ReadTaskCreds(os.Getpid())
	// Unreadable: checked, the safe side (a check only ever answers EACCES where the kernel may).
	return err != nil || c.CapEff&(1<<unix.CAP_DAC_OVERRIDE|1<<unix.CAP_DAC_READ_SEARCH) != 0
})

// searchAnswer is mayLookup's verdict on one directory.
type searchAnswer int

const (
	searchSure   searchAnswer = iota // the kernel lets the task look a name up in it
	searchDenied                     // the kernel answers the task EACCES before looking a name up in it
	searchUnsure                     // the answer depends on what is not read here
)

// modeBitsFS reports whether a filesystem is one whose permission operation, for MAY_EXEC on a directory, is
// generic_permission over the mode bits, owner and group that fstat reads and the POSIX access ACL that hasAccessACL
// asks about, so that what this process reads there decides the task's answer: it has no permission operation of its
// own (ext2/3/4, xfs, f2fs, tmpfs, ramfs, squashfs, erofs, isofs, vfat and msdos, exfat, udf, debugfs, autofs), or one
// that adds only a check that is the same for every caller before it calls generic_permission (btrfs's and kernfs's,
// for sysfs and both cgroup hierarchies; overlayfs's, whose second check runs with the mounter's credentials). It is a
// closed list: every other filesystem is unsure whatever its bits, the filesystems whose
// server or daemon decides each lookup by the caller's credentials (FUSE without default_permissions, NFS, SMB, Ceph,
// kAFS, 9p mounted access=user, Coda), those whose permission operation asks another inode or adds a rule of its own
// (eCryptfs's lower inode, ntfs3's noacsrules), ZFS (out of tree, so its permission operation is not read here), and
// any this list does not name. Procfs is read apart (mayLookup, procForeign).
func modeBitsFS(fsType uint32) bool {
	switch fsType {
	case unix.EXT4_SUPER_MAGIC, // ext2 and ext3 too
		unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.F2FS_SUPER_MAGIC,
		unix.TMPFS_MAGIC, unix.RAMFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC,
		unix.SQUASHFS_MAGIC, unix.EROFS_SUPER_MAGIC_V1, unix.ISOFS_SUPER_MAGIC,
		unix.MSDOS_SUPER_MAGIC, unix.EXFAT_SUPER_MAGIC, unix.UDF_SUPER_MAGIC,
		unix.SYSFS_MAGIC, unix.CGROUP2_SUPER_MAGIC, unix.CGROUP_SUPER_MAGIC,
		unix.DEBUGFS_MAGIC, unix.AUTOFS_SUPER_MAGIC:
		return true
	}
	return false
}

// mayLookup is the kernel's may_lookup for the task on the directory fd, whose fstat is st and whose filesystem type is
// fsType (fsErr when it could not be read), read as generic_permission reads MAY_EXEC on a directory: a directory on a
// filesystem outside modeBitsFS's closed list, procfs aside, or whose type is unknown, is unsure whatever its bits;
// bits that give every class execute and no access ACL are sure with nothing more read; otherwise the owner's class by
// the owner bits, an access ACL (only when the group bits are not all clear, the ACL mask) not read and so unsure, the
// group's class by the filesystem gid or a supplementary group, the others' class otherwise; then CAP_DAC_OVERRIDE or
// CAP_DAC_READ_SEARCH grant it, sure only when the task shares this process's user namespace
// (capable_wrt_inode_uidgid also needs the inode's ids mapped there). On procfs bits that deny are unsure (its
// /proc/<pid>/fd lets its own thread group in whoever owns it), and another thread group's directories are unsure
// whatever their bits (procForeign). The credentials are read once per walk.
func (w *execWalk) mayLookup(fd int, st *unix.Stat_t, fsType uint32, fsErr error) searchAnswer {
	// Only a filesystem known to answer from what is read here is read: a server's (FUSE, NFS) answers the task by its
	// own credentials, which no bit read here stands for (a 0755 directory on NFS or FUSE was sure, and a root walk's
	// miss there told the task whether a name exists in a directory the server refuses it), and
	// so does any filesystem nobody listed (kAFS, 9p and Coda were sure on their bits).
	if fsErr != nil || (fsType != unix.PROC_SUPER_MAGIC && !modeBitsFS(fsType)) {
		return searchUnsure
	}
	// Every class has the bit and no ACL narrows a named entry: searchable whoever the task is, with no credentials
	// read (the usual system directory, 0755 and no ACL, on a PATH search).
	acl := -1
	if st.Mode&0o111 == 0o111 {
		if !hasAccessACL(fd) {
			return searchSure
		}
		acl = 1
	}
	if w.credsErr == nil && w.creds == nil {
		c, err := taskCreds(w.q.tid)
		if err != nil {
			w.credsErr = err
		} else {
			w.creds = &c
			if c.CapEff&(1<<unix.CAP_DAC_OVERRIDE|1<<unix.CAP_DAC_READ_SEARCH) != 0 {
				if sameUserNS(w.q.tid) {
					w.search = false // every directory is searchable to the task
					return searchSure
				}
				w.capUnsure = true
			}
		}
	}
	if w.credsErr != nil {
		return searchUnsure
	}
	c, mode := w.creds, st.Mode
	var x bool
	switch {
	case c.FSUID == st.Uid:
		x = mode&0o100 != 0
	case mode&0o070 != 0 && (acl == 1 || acl == -1 && hasAccessACL(fd)):
		return searchUnsure
	case c.FSGID == st.Gid || slices.Contains(c.Groups, st.Gid):
		x = mode&0o010 != 0
	default:
		x = mode&0o001 != 0
	}
	if x {
		return searchSure
	}
	if w.capUnsure || fsType == unix.PROC_SUPER_MAGIC {
		return searchUnsure
	}
	return searchDenied
}

// dirFSType is fstatfs(2)'s f_type of the directory fd; tests replace it.
var dirFSType = func(fd int) (uint32, error) {
	var sfs unix.Statfs_t
	if err := unix.Fstatfs(fd, &sfs); err != nil {
		return 0, err
	}
	return uint32(sfs.Type), nil
}

// sameUserNS reports whether the task shares this process's user namespace; false when either cannot be read.
var sameUserNS = func(tid int) bool {
	var theirs, ours unix.Stat_t
	if unix.Stat("/proc/"+strconv.Itoa(tid)+"/ns/user", &theirs) != nil || unix.Stat("/proc/self/ns/user", &ours) != nil {
		return false
	}
	return theirs.Dev == ours.Dev && theirs.Ino == ours.Ino
}

// newWalk opens what a walk of q starts from: the task's root, and its cwd or dirfd for a relative path. The root is
// q.root's when it holds one, and is kept there when q.root is set (taskRoot). done closes what the walk alone owns.
func newWalk(q pathQuery) (w *execWalk, start int, done func(), err error) {
	base := "/proc/" + strconv.Itoa(q.tid)
	var root int
	if q.root != nil && q.root.held {
		root = q.root.fd
	} else {
		if root, err = unix.Open(base+"/root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err != nil {
			return nil, -1, nil, err
		}
		if q.root != nil {
			q.root.fd, q.root.held = root, true
		}
	}
	closeRoot := func() {
		if q.root == nil {
			_ = unix.Close(root)
		}
	}
	w = &execWalk{q: q, root: root}
	start = root
	done = closeRoot
	if !strings.HasPrefix(q.path, "/") {
		start, err = unix.Open(dirOf(base, q.dirfd), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			done()
			if errors.Is(err, unix.ENOENT) && q.dirfd != atFDCWD {
				err = unix.EBADF
			}
			return nil, -1, nil, err
		}
		done = func() { _ = unix.Close(start); closeRoot() }
	}
	if q.path == "" {
		done()
		return nil, -1, nil, unix.ENOENT // an empty path without AT_EMPTY_PATH
	}
	return w, start, done, nil
}

// execWalk is one walkExec in progress.
type execWalk struct {
	q     pathQuery
	root  int
	links int
	tgid  int // the task's thread group, read the first time "self" is met
	// create has a missing final component end the walk at its directory (q.create), and missing is that
	// component's name once it has.
	create  bool
	missing string
	// byFD says the walk's current object was reached through a descriptor, not by a name in a directory: the start
	// of a relative walk (the task's cwd or dirfd) or a procfs magic link's target, until a component is looked up by
	// name (deputy.Pinned's ByDescriptor).
	byFD bool
	// search has each directory looked a component up in checked for the task's search permission (walkImage), and
	// unsure records a directory whose answer was not sure. creds is the task's, read at the first check (credsErr
	// when it cannot be), and capUnsure a task whose DAC capabilities may or may not reach the inode.
	search    bool
	unsure    bool
	creds     *sys.TaskCreds
	credsErr  error
	capUnsure bool
	// image is walkImage's walk: a procfs directory or magic link of a process other than the task's own thread group is
	// unsure (procForeign, ownMagicDir), and automount records a failed lookup made at an automount point
	// (automountLookup).
	image     bool
	automount bool
	// follow, when set, has every symlink followed only where the kernel's own lookup would follow it for the task:
	// the open deputy's walk (deputyPin), whose pin is what a held open delivers.
	follow *followFacts
	// deputyTgid, when non-zero, is the thread group of the process that runs this walk and the reopen it leads to:
	// the open deputy (DeputyPinner, os.Getpid()). A lookup into that process's own /proc tree is refused EACCES
	// (deputyProcDepth, landsInDeputyProc; ADR 0041 D4): the deputy runs the walk and the reopen itself, and a process always passes
	// ptrace_may_access against itself, so without this a held open would reach the deputy's own ptrace-gated entries
	// (mem, environ, fd/N, cwd, ...) that the agent's own open is refused, the deputy being undumpable. Zero for the
	// supervisor's own walks, which this never guards.
	deputyTgid int
	// noMagic refuses every magic link with ELOOP, as openat2's RESOLVE_NO_MAGICLINKS does, where walk otherwise
	// follows it: a unix name's walk (unixWalk), whose decision R11 makes only on what is reached with no magic link.
	noMagic bool
	// madeOnProcfs says a component the walk took as made later (pathQuery.predict) lies in a procfs directory: what
	// appears there is a magic link or a procfs directory, never a socket a name can reach (predictUnix).
	madeOnProcfs bool
	// madeDir says the part taken as made later (missing) is a directory the agent makes, not the file the name ends
	// on: the path, or a final link's body, ends in "/" or "/." beyond what exists, or the walk went beneath that part
	// before it ended on it ("x/y/.."). A unix name that ends there reaches no socket (predictUnix).
	madeDir bool
	// named has the walk keep name, the name a line gives a pathname with a ".." component or a final "." (walkNamed,
	// lineName, R15b): where this
	// walk landed the directory the final component as spelled is looked up in, joined with that component, which is
	// not followed for the name whatever the walk then does with it; for a final "." or "..", which has no name of its
	// own, where the whole walk lands (nameWhole). The name is taken from the walk that decides, never from another
	// one, so an agent that moves a symlink between two walks cannot have a line name a file its verdict was not taken
	// on. name stays "" when that directory is not where it lies
	// in this process's view (hereLink), or the walk never reached it.
	named     bool
	nameWhole bool
	name      string
}

// namedByWalk reports whether a walk of q keeps its line's name (execWalk.named): a pathname walkNamed says R6's
// lexical clean cannot name. Compile's question (predict) names nothing.
func namedByWalk(q pathQuery) bool {
	return !q.empty && !q.predict && walkNamed(q.path)
}

// takeName keeps where the directory dir lies in this process's view, joined with the component c unless c is "." or
// "..", as the walk's name (execWalk.named), once. A dir that is no directory names nothing: the kernel's
// filename_parentat fails ENOTDIR there, and so does the walk.
func (w *execWalk) takeName(dir int, c string) {
	w.named, w.nameWhole = false, false
	if c != "." && c != ".." && !isDirFD(dir) {
		return
	}
	at, err := hereLinkOf(dir) // dir stays the walk's
	if err != nil {
		return
	}
	if c != "." && c != ".." {
		at = path.Join(at, c)
	}
	w.name = at
}

// stNoSymfollow is ST_NOSYMFOLLOW, statfs(2)'s flag of a nosymfollow mount (include/linux/statfs.h), which x/sys/unix
// does not name.
const stNoSymfollow = 0x2000

// followFacts is what the open deputy's walk needs to follow a symlink as the kernel's lookup follows it for the task:
// the follower's fsuid (the deputy's, which is the task's) and whether fs.protected_symlinks is on, read before the
// deputy's filter, which allows no read and no getuid (DeputyPinner). The supervisor's own walks decide verdicts on
// where a name lands, and follow every link: a link the kernel then refuses to follow fails the continued syscall.
type followFacts struct {
	fsuid     uint32
	protected bool
}

// mayFollow is the kernel's pick_link refusals of a symlink, link, whose fstat is lst, found in a directory whose fstat
// is dir (dirOK when it could be read): fs.protected_symlinks for a trailing link (may_follow_link: EACCES for a link
// in a sticky world-writable directory owned by neither the follower nor the directory's owner), then a nosymfollow
// mount (ELOOP). The walk followed both in userspace, so a held open delivered what the task's own open fails on.
// Trailing only, as the kernel's: pick_link calls may_follow_link under
// WALK_TRAILING alone (fs/namei.c), and makes the nosymfollow check for every link; root's
// TestHeldOpenDifferentialAcrossMounts holds both to the kernel's answers, an intermediate link fs.protected_symlinks
// would refuse as the final one followed by the task's own open (protected_symlink_mid; refuted). Owners are
// compared raw: on an idmapped mount the kernel compares mapped ones, a residual.
func (f *followFacts) mayFollow(dir *unix.Stat_t, dirOK bool, link int, lst *unix.Stat_t, trailing bool) error {
	if trailing && f.protected && lst.Uid != f.fsuid {
		if !dirOK {
			return unix.EACCES // the directory's mode cannot be read: the refusal the check may give
		}
		if dir.Mode&(unix.S_ISVTX|0o002) == unix.S_ISVTX|0o002 && dir.Uid != lst.Uid {
			return unix.EACCES
		}
	}
	var sfs unix.Statfs_t
	if err := unix.Fstatfs(link, &sfs); err != nil {
		return err
	}
	if sfs.Flags&stNoSymfollow != 0 {
		return unix.ELOOP
	}
	return nil
}

// currentFollowFacts reads followFacts for this process now: its effective uid, which is its fsuid (nothing here sets
// another), and /proc/sys/fs/protected_symlinks, taken as on (every distribution's default) when it cannot be read.
func currentFollowFacts() *followFacts {
	f := &followFacts{fsuid: uint32(unix.Geteuid()), protected: true}
	if b, err := os.ReadFile("/proc/sys/fs/protected_symlinks"); err == nil && strings.TrimSpace(string(b)) == "0" {
		f.protected = false
	}
	return f
}

// walk resolves w.q.path from start and returns a descriptor the caller owns.
func (w *execWalk) walk(start int) (int, error) {
	cur, err := unix.Dup(start)
	if err != nil {
		return -1, err
	}
	fail := func(err error) (int, error) {
		_ = unix.Close(cur)
		return -1, err
	}
	todo := components(w.q.path)
	trailingSlash := strings.HasSuffix(w.q.path, "/")
	w.byFD = !strings.HasPrefix(w.q.path, "/")
	// curSt is cur's fstat when curStOK (a component's own, kept when it becomes cur), for the search check.
	var curSt unix.Stat_t
	curStOK := false
	// virt is the part of the path beneath cur that does not exist yet (pathQuery.predict): a ".." climbs out of it, and
	// once it is empty the walk goes on from cur in the existing tree.
	var virt []string
	// virtDot says a "." followed the last name taken into virt, and virtDir that this name is a directory the walk
	// went beneath: the made part ends on a directory either way (madeDir), as it does when the path ends in "/".
	// madeDirs are the made parts the walk went beneath, by the existing directory they lie in, so a name the walk comes
	// back to is that directory: the agent makes one tree, in which a part is a directory or the name's file, not both.
	virtDot, virtDir := false, false
	var madeDirs map[string]bool
	for len(todo) > 0 {
		c := todo[0]
		todo = todo[1:]
		last := len(todo) == 0
		if len(virt) > 0 {
			if k := virtKey(cur, virt); c != "." && k != "" {
				if madeDirs == nil {
					madeDirs = map[string]bool{}
				}
				madeDirs[k] = true
			}
			switch c {
			case ".":
				virtDot = true
			case "..":
				virt = virt[:len(virt)-1]
				virtDot, virtDir = false, true
			default:
				virt = append(virt, c)
				virtDot, virtDir = false, madeDirs[virtKey(cur, virt)]
			}
			continue
		}
		if last && w.named {
			// The final component as spelled, looked up in cur: the line's name (named), taken here, once.
			if c == "." || c == ".." {
				w.named, w.nameWhole = false, true
			} else {
				w.takeName(cur, c)
			}
		}
		if deputyProcDepth(cur, w.deputyTgid, w.tgid) != notDeputyProc {
			// A held open that would look a component up in the open deputy's own thread group's /proc tree, refused
			// the agent's own errno, EACCES, which pinHeld returns to the task as the kernel's answer (deputyProcDepth).
			// A plain read of a world-readable entry (status, stat, cmdline) is refused too, a deliberate over-refusal:
			// it is never more permissive than the agent's own, and the run has no business reaching the deputy
			// through the gate.
			return fail(unix.EACCES)
		}
		var fsType uint32
		var fsErr error
		if w.image {
			fsType, fsErr = dirFSType(cur)
			// Another process's procfs directory lets the task in only as ptrace_may_access and hidepid allow, which
			// this process cannot decide for it, whatever the bits say and at every tier (procForeign).
			if !w.unsure && w.procForeign(cur, fsType, fsErr) {
				w.unsure = true
			}
		}
		if w.search {
			// The kernel checks the directory before every component, "." and ".." included (link_path_walk's
			// may_lookup); a cur that is no directory fails below with ENOTDIR, as the kernel's walk does. The check
			// goes on past an unsure directory: one further down that the task is sure not to search is still EACCES.
			if !curStOK {
				curStOK = unix.Fstat(cur, &curSt) == nil
			}
			switch {
			case !curStOK:
				w.unsure = true
			case curSt.Mode&unix.S_IFMT == unix.S_IFDIR:
				switch w.mayLookup(cur, &curSt, fsType, fsErr) {
				case searchSure:
				case searchDenied:
					return fail(unix.EACCES)
				case searchUnsure:
					w.unsure = true
				}
			}
		}
		switch c {
		case ".":
			// The kernel's lookup fails a "." after a non-directory (link_path_walk's d_can_lookup), before the
			// next component or at the end; skipped, "f/./g" landed on f/g where the task gets ENOTDIR.
			if !isDirFD(cur) {
				return fail(unix.ENOTDIR)
			}
			continue
		case "..":
			if samePlace(cur, w.root) {
				continue
			}
			up, err := unix.Openat(cur, "..", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				// A stub with no lookup operation (an NFS submount or referral) fails every lookup that starts from it,
				// ".." too, where the kernel's walk mounted it and climbs back out.
				if w.image && atAutomount(cur) {
					w.automount = true
				}
				return fail(err)
			}
			_ = unix.Close(cur)
			cur, curStOK, w.byFD = up, false, false
			continue
		}
		next, err := unix.Openat(cur, c, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			if w.create && last && !trailingSlash && errors.Is(err, unix.ENOENT) {
				w.missing = c // the name an O_CREAT open makes in cur (q.create)
				return cur, nil
			}
			if w.q.predict && errors.Is(err, unix.ENOENT) {
				w.madeOnProcfs = w.madeOnProcfs || onProcfs(cur)
				virt = append(virt, c) // a directory the agent makes later (pathQuery.predict)
				virtDot, virtDir = false, madeDirs[virtKey(cur, virt)]
				continue
			}
			if w.image && atAutomount(cur) {
				w.automount = true
			}
			return fail(err)
		}
		var st unix.Stat_t
		if err := unix.Fstat(next, &st); err != nil {
			_ = unix.Close(next)
			return fail(err)
		}
		if st.Mode&unix.S_IFMT != unix.S_IFLNK {
			_ = unix.Close(cur)
			cur, curSt, curStOK, w.byFD = next, st, true, false
			continue
		}
		if last && w.q.nofollow && !trailingSlash {
			_ = unix.Close(next)
			if w.q.directory {
				return fail(unix.ENOTDIR)
			}
			return fail(unix.ELOOP)
		}
		if w.links++; w.links > maxSymlinks {
			_ = unix.Close(next)
			return fail(unix.ELOOP)
		}
		if w.follow != nil {
			// The open deputy's walk follows a symlink only where the kernel's lookup would for the task (followFacts).
			if !curStOK {
				curStOK = unix.Fstat(cur, &curSt) == nil
			}
			if err := w.follow.mayFollow(&curSt, curStOK, next, &st, last); err != nil {
				_ = unix.Close(next)
				return fail(err)
			}
		}
		var target string
		switch proc, procRoot := procDir(cur); {
		case procRoot:
			target, err = w.procRootLink(cur, c, next)
		case proc:
			// A magic link: the kernel follows it from the pid directory it sits in, for the task only when the task
			// may ptrace that process (walkImage).
			_ = unix.Close(next)
			if w.noMagic {
				return fail(unix.ELOOP)
			}
			if w.image && !w.ownMagicDir(cur) {
				w.unsure = true
			}
			jumped, err := unix.Openat(cur, c, unix.O_PATH|unix.O_CLOEXEC, 0)
			if err != nil {
				return fail(err)
			}
			_ = unix.Close(cur)
			cur, curStOK, w.byFD = jumped, false, true
			continue
		default:
			target, err = readlinkFD(next)
		}
		_ = unix.Close(next)
		if err != nil {
			return fail(err)
		}
		if target == "" {
			return fail(unix.ENOENT) // an empty symlink resolves to nothing
		}
		if strings.HasPrefix(target, "/") {
			r, err := unix.Dup(w.root)
			if err != nil {
				return fail(err)
			}
			_ = unix.Close(cur)
			cur, curStOK, w.byFD = r, false, false
		}
		// A trailing slash in the body of a final link is the path's own trailing slash from here on: the
		// kernel walks it and fails a non-directory with ENOTDIR (link_path_walk's d_can_lookup), where
		// components alone dropped it and a link to "f/" landed on the file f.
		if last && strings.HasSuffix(target, "/") {
			trailingSlash = true
		}
		todo = append(components(target), todo...)
	}
	if len(virt) > 0 {
		w.missing = path.Join(virt...) // beneath cur, where the run's walk reaches once it is made (walkExec)
		w.madeDir = trailingSlash || virtDot || virtDir
		return cur, nil
	}
	// A trailing slash, and for the open deputy's walk an open that needs a directory (pathQuery.directory), make the
	// lookup's end a directory or ENOTDIR, as the kernel's LOOKUP_DIRECTORY does before the open is made.
	if (trailingSlash || w.q.directory) && !isDirFD(cur) {
		return fail(unix.ENOTDIR)
	}
	if landsInDeputyProc(cur, w.deputyTgid, w.tgid) {
		return fail(unix.EACCES) // the deputy's own tree reached with no lookup in it: a magic link as the last step
	}
	if w.nameWhole {
		w.takeName(cur, ".") // a final "." or "..": the name is where the whole walk lands
	}
	return cur, nil
}

// procRootLink is the target of a symlink at a procfs root, as the task reads it. "self" and
// "thread-self" are computed from the caller in the kernel, so they are answered for the task; the others
// ("mounts", "net") are ordinary symlinks into "self" and are read as they are.
func (w *execWalk) procRootLink(procRoot int, name string, link int) (string, error) {
	if name != "self" && name != "thread-self" {
		return readlinkFD(link)
	}
	// The task's pid numbers are this process's only in this process's own procfs instance: another
	// instance counts in another pid namespace, where no translation of the task's tid is at hand.
	if !sameProcInstance(procRoot) {
		return "", unix.EXDEV
	}
	tgid, err := w.taskTgid()
	if err != nil {
		return "", err
	}
	if name == "self" {
		return strconv.Itoa(tgid), nil
	}
	return strconv.Itoa(tgid) + "/task/" + strconv.Itoa(w.q.tid), nil
}

// taskTgid is the task's thread group, read the first time it is needed.
func (w *execWalk) taskTgid() (int, error) {
	if w.tgid == 0 {
		b, err := os.ReadFile("/proc/" + strconv.Itoa(w.q.tid) + "/status")
		if err != nil {
			return 0, unix.ESRCH
		}
		if w.tgid, err = parseTgid(string(b)); err != nil {
			return 0, unix.ESRCH
		}
	}
	return w.tgid, nil
}

// ownMagicDir reports whether cur, the procfs directory a magic link sits in, is one of the task's own thread group's
// in this process's procfs instance: a pid directory of any of its threads (/proc/<n> for n any of its threads, the
// leader's /proc/<tgid> or a non-leader thread's top-level /proc/<tid>, which readdir hides, and
// /proc/<n>/task/<any of its threads>), or the fd or ns directory of one. Those are the links the kernel follows for
// the task without asking whether it may ptrace another process (ptrace_may_access lets a thread group at itself,
// before any LSM is asked), and the ones /proc/self, /proc/thread-self and /dev/fd lead to. Everything else is "no":
// another process's directory, map_files (whose lookup also needs CAP_CHECKPOINT_RESTORE), a procfs instance whose
// pid numbers are not this process's, and anything that cannot be opened or compared. The comparison is samePlace on
// descriptors opened fresh here: cur pins its own dentry and its parents', so the task's directories compare equal
// to it exactly when cur is one of them; a thread's top-level directory, another inode than its task/<tid> entry, is
// the task's when its task directory holds the task's tgid (member).
// The top-level /proc/<tid> of a non-leader thread was "no", so a miss behind its cwd was EACCES with a
// refusal line where the kernel answers ENOENT.
func (w *execWalk) ownMagicDir(cur int) bool {
	var cs, ps unix.Stat_t
	if unix.Fstat(cur, &cs) != nil || unix.Stat("/proc", &ps) != nil || cs.Dev != ps.Dev {
		return false
	}
	tgid, err := w.taskTgid()
	if err != nil {
		return false
	}
	const dir = unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC
	root, err := unix.Open("/proc", dir, 0)
	if err != nil {
		return false
	}
	defer unix.Close(root) //nolint:errcheck // an O_PATH descriptor this call opened
	// member: x is /proc/<n> for n any of the task's threads. procfs looks a thread id up at its root as it does a
	// tgid, and /proc/<tid> of a thread other than the leader is a directory of its own; it is the task's when its task
	// directory holds the task's tgid, which proc_task_lookup finds only within x's own thread group (the task's side,
	// which a comparison with /proc/<tgid> alone missed).
	member := func(x int) bool {
		up, err := unix.Openat(x, "..", dir, 0)
		if err != nil {
			return false
		}
		defer unix.Close(up) //nolint:errcheck // an O_PATH descriptor this call opened
		var st unix.Stat_t
		return samePlace(up, root) && unix.Fstatat(x, "task/"+strconv.Itoa(tgid), &st, unix.AT_SYMLINK_NOFOLLOW) == nil
	}
	// ownPid: x is a member or <member>/task/<tid>, where cwd, root and exe sit.
	ownPid := func(x int) bool {
		if member(x) {
			return true
		}
		up, err := unix.Openat(x, "..", dir, 0)
		if err != nil {
			return false
		}
		defer unix.Close(up) //nolint:errcheck // an O_PATH descriptor this call opened
		m, err := unix.Openat(up, "..", dir, 0)
		if err != nil {
			return false
		}
		defer unix.Close(m) //nolint:errcheck // an O_PATH descriptor this call opened
		if !member(m) {
			return false
		}
		tasks, err := unix.Openat(m, "task", dir, 0)
		if err != nil {
			return false
		}
		defer unix.Close(tasks) //nolint:errcheck // an O_PATH descriptor this call opened
		return samePlace(up, tasks)
	}
	if ownPid(cur) {
		return true
	}
	up, err := unix.Openat(cur, "..", dir, 0)
	if err != nil {
		return false
	}
	defer unix.Close(up) //nolint:errcheck // an O_PATH descriptor this call opened
	if !ownPid(up) {
		return false
	}
	for _, sub := range []string{"fd", "ns"} {
		d, err := unix.Openat(up, sub, dir, 0)
		if err != nil {
			continue
		}
		same := samePlace(cur, d)
		_ = unix.Close(d)
		if same {
			return true
		}
	}
	return false
}

// statusTgid reads the Tgid line of the status file in the procfs directory x. A directory with no status file (one
// that belongs to no process: /proc/sys, /proc/driver) answers ENOENT.
func statusTgid(x int) (int, error) {
	fd, err := unix.Openat(x, "status", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd) //nolint:errcheck // a read-only descriptor this call opened
	// The Tgid line is the fourth, after Name (a comm of at most 16 bytes, escaped to at most 64), Umask and State.
	var buf [512]byte
	n, err := unix.Read(fd, buf[:])
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, unix.EIO
	}
	return parseTgid(string(buf[:n]))
}

// procOwnerDepth bounds procForeign's climb from a procfs directory to the directory just below the procfs root: the
// directories beneath a pid directory lie a few levels down (/proc/<pid>/task/<tid>/fdinfo, /proc/<pid>/net/stat,
// /proc/<pid>/attr/<lsm>), and a directory deeper than this is answered as another process's, the safe side.
const procOwnerDepth = 8

// procForeign reports whether the directory fd, on a filesystem of type fsType (fsErr when it could not be read), is a
// procfs directory that belongs to a thread group other than the task's (walkImage): another process's pid directory
// (/proc/<pid>, /proc/<pid>/task/<tid>) or any directory beneath one, or a directory of a procfs instance whose pid
// numbers are not this process's. The kernel lets the task into such a directory only as its permission operation
// decides for the caller: /proc/<pid>/fdinfo is 0555 and asks ptrace_may_access (which Landlock's scoping, Yama and the
// other LSMs answer), and a pid directory under hidepid asks whether the caller may see the process, none of which this
// process can decide for the task, while its own rights (root at tiers cgroup and bpflsm, a process outside the
// agent's Landlock domain at tier landlock) let it in. A procfs directory that belongs to no process (/proc itself,
// /proc/sys, /proc/driver) is not foreign, nor are the task's own thread group's directories, a non-leader thread's
// top-level /proc/<tid> included, nor any directory off procfs. It climbs ".." from fd to the directory just below
// this instance's root and reads that
// directory's status file, which only a pid directory has: its Tgid line names the thread group the directory belongs
// to, read through the directory itself. Anything it cannot open, read or compare is "yes".
func (w *execWalk) procForeign(fd int, fsType uint32, fsErr error) bool {
	if fsErr != nil {
		return true
	}
	if fsType != unix.PROC_SUPER_MAGIC {
		return false
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		return true
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		// The kernel fails the next lookup ENOTDIR without asking about the file (link_path_walk's d_can_lookup); the
		// directory the file was looked up in was already judged.
		return false
	}
	if st.Ino == procRootIno {
		return !sameProcInstance(fd) // a root's own lookups name pids, which procForeign reads below it
	}
	const dir = unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC
	x, err := unix.Dup(fd)
	if err != nil {
		return true
	}
	defer func() { _ = unix.Close(x) }()
	for range procOwnerDepth {
		up, err := unix.Openat(x, "..", dir, 0)
		if err != nil {
			return true
		}
		var ust unix.Stat_t
		if unix.Fstat(up, &ust) != nil {
			_ = unix.Close(up)
			return true
		}
		if ust.Ino != procRootIno {
			_ = unix.Close(x)
			x = up
			continue
		}
		same := sameProcInstance(up)
		_ = unix.Close(up)
		if !same {
			return true
		}
		got, err := statusTgid(x)
		if errors.Is(err, unix.ENOENT) {
			return false // no status file: a directory of no process
		}
		tgid, terr := w.taskTgid()
		return err != nil || terr != nil || got != tgid
	}
	return true
}

// Where a directory lies against the open deputy's own thread group's /proc directories (deputyProcDepth), when it is
// no depth in that tree: notDeputyProc outside it, unsureDeputyProc where that cannot be told, which every guard
// refuses as the deputy's own.
const (
	notDeputyProc    = -1
	unsureDeputyProc = -2
)

// deputyProcDepth is how far the directory dir lies below a /proc directory of the open deputy's own thread group: 0
// for such a directory (/proc/<tgid>, or /proc/<tid> of any of its threads), 1 for an entry directory in it (task, fd,
// fdinfo, ns, net, attr, ...), 2 for task/<tid>, and so on; notDeputyProc for a directory outside that tree, or
// anything that is no procfs directory; unsureDeputyProc where it cannot tell. The deputy (deputyTgid, os.Getpid())
// runs the walk and the reopen it leads to, and a process always passes ptrace_may_access against its own thread
// group, so a lookup there reaches the deputy's own ptrace-gated entries (mem, environ, auxv, maps, fd/N, cwd, root,
// exe, ...) that the agent's own open is refused, the deputy being undumpable (PR_SET_DUMPABLE 0, deputy confine).
// Every pin refuses a lookup there EACCES, the agent's own errno (ADR 0041 D4).
//
// It climbs from dir to the root of dir's own procfs mount, keeping the directory right under it: the pid directory
// /proc/<n> the tree hangs from. procfs looks any thread id up at its root, and /proc/<tid> of a thread other than
// the leader is a directory of its own, with its own inode, whose entries ask about that thread; the deputy is a Go
// program with several threads, so a comparison with the leader's directory alone ("self") missed them. That
// directory is the deputy's when its task directory holds the deputy's tgid as the instance numbers it (the root's
// "self", which procfs computes from the caller): proc_task_lookup finds a thread id there only within the
// directory's own thread group. A second procfs mount, or a bind mount of /proc, is so asked in its own numbering,
// which a mount-sensitive comparison with the deputy's own /proc/<tgid> missed. A climb whose procfs mount has a root
// that is no instance root (a bind mount of part of a procfs, which the run cannot make), and anything it cannot open,
// stat or look up, is unsure; an instance with no "self" (ENOENT: a pid namespace the deputy is not in) holds no
// directory of the deputy's threads. The guard is off (notDeputyProc) when deputyTgid is 0, the supervisor's own
// walks, or the task's own thread group: only a test stands the test process in for both, and the task legitimately
// reaches its own /proc (its /proc/self/fd magic links among them); a real run's deputy is always a distinct process.
func deputyProcDepth(dir, deputyTgid, tgid int) int {
	if deputyTgid == 0 || deputyTgid == tgid {
		return notDeputyProc
	}
	// procfs's statfs never fails, so a directory whose statfs does is no procfs one.
	var sf unix.Statfs_t
	if unix.Fstatfs(dir, &sf) != nil || sf.Type != unix.PROC_SUPER_MAGIC {
		return notDeputyProc
	}
	var st unix.Stat_t
	if unix.Fstat(dir, &st) != nil {
		return unsureDeputyProc
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return notDeputyProc // a lookup in a non-directory fails ENOTDIR, as the kernel's does
	}
	const flags = unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC
	probe, err := unix.Openat(dir, ".", flags, 0)
	if err != nil {
		return unsureDeputyProc
	}
	defer func() { _ = unix.Close(probe) }()
	// The climb from dir to the root of its procfs mount, the directory whose ".." leaves procfs or is itself: below
	// is the directory it climbed from last, open, and climbs counts the steps. A /proc/<pid> tree is shallow
	// (task/<tid>/fd is four below the procfs root); the bound stops a cycle a surprising mount could make, never a real
	// climb.
	below, climbs := -1, 0
	defer func() {
		if below >= 0 {
			_ = unix.Close(below)
		}
	}()
	for {
		if climbs > 8 {
			return unsureDeputyProc
		}
		up, err := unix.Openat(probe, "..", flags, 0)
		if err != nil {
			return unsureDeputyProc
		}
		var ust unix.Stat_t
		if unix.Fstatfs(up, &sf) != nil || sf.Type != unix.PROC_SUPER_MAGIC {
			_ = unix.Close(up)
			break // probe is its procfs mount's root: ".." leaves procfs
		}
		if unix.Fstat(up, &ust) != nil {
			_ = unix.Close(up)
			return unsureDeputyProc
		}
		if ust.Dev == st.Dev && ust.Ino == st.Ino {
			_ = unix.Close(up)
			break // probe is its procfs mount's root: ".." is probe itself
		}
		if below >= 0 {
			_ = unix.Close(below)
		}
		below, probe, st = probe, up, ust
		climbs++
	}
	if st.Ino != procRootIno {
		// The mount's root is no procfs root: a mount of part of a procfs, which the run cannot make, has no "self" to
		// name the deputy's thread group by.
		return unsureDeputyProc
	}
	if below < 0 {
		return notDeputyProc // dir is the procfs root, no directory of the deputy's
	}
	buf := make([]byte, 32)
	n, err := unix.Readlinkat(probe, "self", buf)
	if errors.Is(err, unix.ENOENT) {
		return notDeputyProc
	}
	if err != nil || n <= 0 || n >= len(buf) {
		return unsureDeputyProc
	}
	switch err := unix.Fstatat(below, "task/"+string(buf[:n]), &st, unix.AT_SYMLINK_NOFOLLOW); {
	case err == nil:
		return climbs - 1
	case errors.Is(err, unix.ENOENT):
		return notDeputyProc // another process's directory, or a procfs directory that is no pid one (sys, net, ...)
	default:
		return unsureDeputyProc
	}
}

// landsInDeputyProc reports whether fd, where a pin of the open deputy ends, lies inside the deputy's own thread
// group's /proc tree, which the pin then refuses EACCES as it refuses every lookup there (deputyProcDepth): a directory
// below the deputy's /proc/<tgid> directory or a thread's /proc/<tid>, or any other procfs object whose directory is
// one of those or below it. Those directories themselves stay reached, as the agent's own open of a listable
// directory is. A walk reaches the
// tree by name only through a lookup in it, refused before it is made; a magic link as the walk's last step, or an
// AT_EMPTY_PATH pin, lands there with none (a run process may hold an O_PATH descriptor of
// /proc/<deputy-pid>/environ, an O_PATH open being continued). A procfs object that is no directory is placed by its
// directory, which procParent finds and verifies; where it cannot, the object is refused as the deputy's own.
func landsInDeputyProc(fd, deputyTgid, tgid int) bool {
	if deputyTgid == 0 || deputyTgid == tgid {
		return false
	}
	var sf unix.Statfs_t
	if unix.Fstatfs(fd, &sf) != nil || sf.Type != unix.PROC_SUPER_MAGIC {
		return false // procfs's statfs never fails
	}
	if isDirFD(fd) {
		d := deputyProcDepth(fd, deputyTgid, tgid)
		return d > 0 || d == unsureDeputyProc
	}
	parent, ok := procParent(fd)
	if !ok {
		return true
	}
	defer unix.Close(parent) //nolint:errcheck // an O_PATH descriptor procParent opened
	return deputyProcDepth(parent, deputyTgid, tgid) != notDeputyProc
}

// procParent opens the directory the procfs object fd, no directory, lies in. Its path is this process's view of its
// own descriptor (/proc/self/fd/N), looked up again: that directory must hold fd's inode under the path's last
// component, a procfs object having one name, or ok is false (a dead process's entry, whose path the kernel marks
// deleted, among those).
func procParent(fd int) (int, bool) {
	p, err := readlinkRaw("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil || !strings.HasPrefix(p, "/") {
		return -1, false
	}
	dir, base := splitFinal(p)
	if base == "" || base == "." || base == ".." {
		return -1, false
	}
	d, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, false
	}
	var want, got unix.Stat_t
	if unix.Fstat(fd, &want) != nil || unix.Fstatat(d, base, &got, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		want.Dev != got.Dev || want.Ino != got.Ino {
		_ = unix.Close(d)
		return -1, false
	}
	return d, true
}

// components splits a path into its components, dropping the empty ones a leading, doubled or trailing
// slash leaves.
func components(p string) []string {
	var out []string
	for _, c := range strings.Split(p, "/") {
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

// virtKey names the made part virt beneath the existing directory dir (execWalk.walk's madeDirs): dir by its device
// and inode, since the walk may come back to it by another spelling. A dir it cannot fstat names nothing a later walk
// matches.
func virtKey(dir int, virt []string) string {
	var st unix.Stat_t
	if unix.Fstat(dir, &st) != nil {
		return ""
	}
	return fmt.Sprintf("%d:%d/%s", st.Dev, st.Ino, path.Join(virt...))
}

// procDir reports whether fd is a procfs directory, and whether it is a procfs root.
func procDir(fd int) (proc, root bool) {
	var sf unix.Statfs_t
	if unix.Fstatfs(fd, &sf) != nil || sf.Type != unix.PROC_SUPER_MAGIC {
		return false, false
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		return true, false
	}
	return true, st.Ino == procRootIno
}

// sameProcInstance reports whether the procfs root fd is the instance this process's /proc is.
func sameProcInstance(fd int) bool {
	var theirs, ours unix.Stat_t
	if unix.Fstat(fd, &theirs) != nil || unix.Stat("/proc", &ours) != nil {
		return false
	}
	return theirs.Dev == ours.Dev && theirs.Ino == ours.Ino
}

// samePlace reports whether two directory descriptors are one place in the tree: the same inode on the
// same mount, which is what the kernel compares when ".." meets a process's root (a bind mount of the root
// elsewhere is the same inode and not the root). Anything it cannot tell is "no", which only lets ".."
// climb, and the climb stops at this process's own root.
func samePlace(a, b int) bool {
	const mask = unix.STATX_INO | unix.STATX_MNT_ID
	var sa, sb unix.Statx_t
	if unix.Statx(a, "", unix.AT_EMPTY_PATH, mask, &sa) != nil || unix.Statx(b, "", unix.AT_EMPTY_PATH, mask, &sb) != nil {
		return false
	}
	if sa.Mask&sb.Mask&mask != mask {
		return false
	}
	return sa.Mnt_id == sb.Mnt_id && sa.Ino == sb.Ino && sa.Dev_major == sb.Dev_major && sa.Dev_minor == sb.Dev_minor
}

// isDirFD reports whether fd is a directory.
func isDirFD(fd int) bool {
	var st unix.Stat_t
	return unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR
}

// readlinkFD reads the symlink an O_PATH|O_NOFOLLOW descriptor names (readlinkat with an empty path).
func readlinkFD(fd int) (string, error) {
	buf := make([]byte, pathMax)
	n, err := unix.Readlinkat(fd, "", buf)
	if err != nil {
		return "", err
	}
	if n >= len(buf) {
		return "", unix.ENAMETOOLONG
	}
	return string(buf[:n]), nil
}

// fsLanding is FSTarget's answer for one end: where it lands (at), and the name its line gives it (name: execWalk.named,
// "" for a pathname with no ".." component or where its directory cannot be named here). Both come from one walk.
type fsLanding struct {
	at, name string
}

// FSTarget resolves the path an fs syscall names to where it lands in this process's view, walked the way
// the task's own lookup walks it (R15b): the whole path when the syscall follows its final component and
// the path exists, as path_lookupat does when the path ends in "/" whatever the flags say (a name-making end,
// q.parent, never: its final name is looked up in its directory unfollowed, slash or not); for an O_CREAT open whose
// final component is missing, the name it creates, a dangling
// final symlink followed to its target as the kernel follows it (q.create); and otherwise the resolved
// parent directory joined with the final component — the directory Landlock's create, remove and rename
// hooks decide on. errOtherView when the place reached is not the same inode under that path here: the
// policy's paths are this process's view. A pathname with a ".." component is also named by the walk that answers
// at (fsLanding.name), and a walk that fails past the directory it names still answers that name.
func (k sysKernel) FSTarget(q pathQuery) (fsLanding, error) {
	if fsTargetIsSpelling(q) {
		return fsLanding{at: q.joined}, nil
	}
	if at, ok, err := fsTargetInRoot(q); ok {
		return fsLanding{at: at}, err
	}
	dir, base := splitFinal(q.path)
	// A final "." or ".." (or "/" alone) names no entry in a directory. A syscall that makes, removes or renames a name
	// refuses it before a lookup of its own (pathQuery.parent: EEXIST, EBUSY, EISDIR, EINVAL, ENOTEMPTY): no walk, so
	// no name. Every other syscall resolves it physically where path_lookupat lands, followed or not, since it is
	// never a symlink: lchown("out/lk/..") changes the directory above where out/lk leads.
	dots := base == "" || base == "." || base == ".."
	if dots && q.parent {
		return fsLanding{}, unix.EINVAL
	}
	// A trailing slash has path_lookupat follow a final symlink even when the syscall does not (O_NOFOLLOW,
	// AT_SYMLINK_NOFOLLOW): open("lnk/", O_NOFOLLOW) opens the directory lnk names, and an O_TMPFILE open
	// there makes its file in it. The walk keeps q.nofollow and follows such a link itself (execWalk.walk);
	// answered parent+base instead, the verdict and deny_write were decided on the link's own name. A name-making end
	// (q.parent) is no such lookup: filename_parentat strips the slash and the name is looked up in its directory, never
	// followed (lookup_one_qstr_excl), so mkdir("lnk/") is EEXIST, rmdir, unlink and a rename onto it are ENOTDIR, and
	// Landlock's rmdir and rename hooks are asked at lnk itself. It is its directory's walk joined with the name, slash
	// or not, as compile lands it too.
	if !q.nofollow || dots || (strings.HasSuffix(q.path, "/") && !q.parent) {
		fd, missing, name, err := walkExec(q, true)
		if err == nil {
			at, err := hereLink(fd)
			if err != nil || missing == "" {
				return fsLanding{at: at, name: name}, err
			}
			return fsLanding{at: path.Join(at, missing), name: name}, nil
		}
		// A missing final name lies in its directory; a final "." or ".." of a missing directory is the lookup's ENOENT.
		if dots || !errors.Is(err, unix.ENOENT) {
			return fsLanding{name: name}, err
		}
	}
	parent := q
	// The parent is looked up as a directory, as filename_parentat does: a file there fails the walk ENOTDIR, the task's answer.
	parent.path, parent.nofollow, parent.create, parent.directory = dir, false, false, true
	fd, missing, _, err := walkExec(parent, false)
	if err != nil {
		return fsLanding{}, err
	}
	at, err := hereLink(fd)
	if err != nil {
		return fsLanding{}, err
	}
	at = path.Join(at, missing, base)
	if namedByWalk(q) {
		return fsLanding{at: at, name: at}, nil // the final component not followed: where it lands is its name
	}
	return fsLanding{at: at}, nil
}

// fsTargetIsSpelling reports whether q lands where R6's spelling says, which is the common case and costs one
// lookup: the place FSTarget answers with (the file, or for a name that is missing or not followed, its parent
// directory) is reached from this process's root through no symlink at all (RESOLVE_NO_SYMLINKS, magic links
// included), so no component of the spelling can lead anywhere else. It holds only for the task's own lookup
// when the task shares this process's root and mount tree, which a run's task does: the filter refuses a new
// mount or user namespace (enforce-cgroup-observe E24) and no_new_privs leaves chroot(2) to no one. A pathname
// with a ".." component or a trailing slash, and a descriptor's own file, are never answered here (R6's spelling
// is cleaned lexically), and a dangling final symlink an O_CREAT open would follow is not either.
func fsTargetIsSpelling(q pathQuery) bool {
	if !spellingShape(q) {
		return false
	}
	dir, base := splitFinal(q.joined)
	if base == "" || base == "." || base == ".." {
		return false
	}
	how := unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC | unix.O_DIRECTORY, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS}
	var fd int
	var err error
	for {
		if fd, err = unix.Openat2(unix.AT_FDCWD, dir, &how); err != unix.EINTR {
			break
		}
	}
	if err != nil {
		return false
	}
	defer unix.Close(fd) //nolint:errcheck // an O_PATH descriptor this call opened
	var st unix.Stat_t
	switch err := unix.Fstatat(fd, base, &st, unix.AT_SYMLINK_NOFOLLOW); {
	case errors.Is(err, unix.ENOENT):
		return true // a missing name is created, or fails, right there
	case err != nil:
		return false
	}
	// A final symlink is where the path lands only when the syscall does not follow it.
	return st.Mode&unix.S_IFMT != unix.S_IFLNK || q.nofollow
}

// finalDot reports whether a pathname's last component is ".", which R6's lexical spelling drops: "f/." is
// ENOTDIR for a file f, which only the walk sees. A "." before another component needs no such care, since the
// directory the shortcuts open then includes the file and fails.
func finalDot(p string) bool {
	return p == "." || strings.HasSuffix(p, "/.")
}

// fsTargetInRoot is FSTarget in one kernel lookup, for the shapes where one openat2(2) from the task's root
// resolves exactly as the task's own lookup does: every verdict is taken where its path lands (R15b), so the
// walk runs for every notified fs syscall, and walkExec's descriptor per component made that the fast path's
// largest cost. The lookup is R6's absolute spelling (q.joined) under /proc/<tid>/root with RESOLVE_IN_ROOT,
// so an absolute symlink and ".." stay inside the task's root, and RESOLVE_NO_MAGICLINKS, so a
// /proc/<pid>/fd, cwd or root link — which only the walk follows for the task — fails it. ok is false, and the
// walk decides, for everything else: a pathname with a ".." component or a trailing slash (R6's spelling is
// cleaned lexically, the kernel resolves physically), a descriptor's own file (q.empty), a place on procfs
// (its "self" is resolved here as this process), a final symlink a followed lookup misses on (a dangling one, or
// one whose body goes through procfs's "self", which this lookup resolves as this process), and any error but a
// missing name.
func fsTargetInRoot(q pathQuery) (at string, ok bool, err error) {
	if !spellingShape(q) {
		return "", false, nil
	}
	root, err := unix.Open("/proc/"+strconv.Itoa(q.tid)+"/root", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", false, nil
	}
	defer unix.Close(root) //nolint:errcheck // an O_PATH descriptor this call opened
	lookup := func(p string, flags uint64) (int, error) {
		how := unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC | flags, Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS}
		for tries := 0; ; tries++ {
			fd, err := unix.Openat2(root, p, &how)
			// EAGAIN: RESOLVE_IN_ROOT saw a rename or mount race and asks for a retry (openat2(2)).
			if (err == unix.EAGAIN && tries < 8) || err == unix.EINTR {
				continue
			}
			return fd, err
		}
	}
	// landed is where fd lies here, joined with name when name is not "", and not ok when fd is on procfs.
	landed := func(fd int, name string) (string, bool, error) {
		var sf unix.Statfs_t
		if unix.Fstatfs(fd, &sf) != nil || sf.Type == unix.PROC_SUPER_MAGIC {
			_ = unix.Close(fd)
			return "", false, nil
		}
		at, err := hereLink(fd)
		if err != nil || name == "" {
			return at, true, err
		}
		return path.Join(at, name), true, nil
	}
	if !q.nofollow {
		fd, err := lookup(q.joined, 0)
		if err == nil {
			return landed(fd, "")
		}
		if !errors.Is(err, unix.ENOENT) {
			return "", false, nil
		}
	}
	dir, base := splitFinal(q.joined)
	if base == "" || base == "." || base == ".." {
		return "", false, nil
	}
	fd, err := lookup(dir, unix.O_DIRECTORY)
	if err != nil {
		return "", false, nil
	}
	if !q.nofollow {
		// The followed lookup missed and the directory is there. A final name that is there all the same is a symlink this
		// lookup could not follow as the task's lookup does: one whose body goes through procfs's "self" or "thread-self",
		// which name this process here (a link to /proc/self/task/<the task's tid>/../../../../d/f misses here and lands
		// on d/f for the task), or a dangling one, which an O_CREAT open follows to the name it creates (q.create) and
		// compile --test's question takes as made later (q.predict). Only the walk, which reads "self" as the task's,
		// answers either. Answered here with the link's own name, the verdict and the line named the link while the
		// kernel opened the file its body names: an open for writing went past a deny_write on that file. A name missing
		// here reaches no file for the task either.
		var st unix.Stat_t
		if err := unix.Fstatat(fd, base, &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
			_ = unix.Close(fd)
			return "", false, nil
		}
	}
	return landed(fd, base)
}

// errLinkedElsewhere is hereLink's answer for a walk that reached a linked file whose path, looked up in this
// process's view, names another inode or none: a file the task sees by a name this process cannot. It is an
// errOtherView, and every verdict reads it as one; only a gate tells the two apart, since a nameless object
// (a pipe, a socket, an unlinked file) has no name a predicate could match, while this one has a name the
// gate cannot read (gate.md R1, ADR 0041 D4).
var errLinkedElsewhere = fmt.Errorf("%w: a linked file this process cannot see by its path", errOtherView)

// errUnlinkedFile is a nameless object that had a name: a regular file with no link left on a filesystem with names
// (unlinkedFile), reached through a descriptor. It is an errOtherView, and every verdict reads it as a nameless object;
// a read gate does not (gateFactsIncomplete): the name it lost may have been one an fs.read predicate matches.
var errUnlinkedFile = fmt.Errorf("%w: a regular file whose name was removed", errOtherView)

// unlinkedFile reports whether st is a regular file with no link left on a filesystem with names: an unlinked file, or
// an O_TMPFILE never linked, which no predicate can tell apart. A file on the kernel's internal shmem mount (a memfd, a
// System V segment, a shared anonymous mapping) never had a name, and is not one.
func unlinkedFile(st *unix.Stat_t) bool {
	return unlinkedRegular(st.Mode&unix.S_IFMT == unix.S_IFREG, st.Nlink > 0, uint64(st.Dev))
}

// unlinkedRegular is unlinkedFile on an object's facts: a regular file, with no link, on device dev.
func unlinkedRegular(regular, linked bool, dev uint64) bool {
	return regular && !linked && dev != internalShmDev()
}

// internalShmDev is the device of the kernel's internal shmem mount, which every memfd lies on, read from a memfd of
// this process's own. ^0, which no file has, when none can be made: every nameless regular file is then unlinkedFile's,
// the side that refuses.
var internalShmDev = sync.OnceValue(func() uint64 {
	fd, err := unix.MemfdCreate("tego-shm-device", unix.MFD_CLOEXEC)
	if err != nil {
		return ^uint64(0)
	}
	defer unix.Close(fd) //nolint:errcheck // a memfd this function made
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		return ^uint64(0)
	}
	return uint64(st.Dev)
})

// hereLink is where the walked descriptor fd lies in this process's view, and closes fd.
func hereLink(fd int) (string, error) {
	at, err := hereLinkOf(fd)
	_ = unix.Close(fd)
	return at, err
}

// hereLinkOf is hereLink of a descriptor the caller keeps: fd is left open.
func hereLinkOf(fd int) (string, error) {
	img, err := describeImage(fd)
	if err != nil {
		return "", err
	}
	if unlinkedRegular(img.regular, img.linked, uint64(img.id.dev)) {
		return "", errUnlinkedFile // a regular file behind a descriptor whose name was removed
	}
	if !img.linked || !strings.HasPrefix(img.link, "/") {
		return "", errOtherView // pipe:[...], socket:[...], anon_inode:..., or unlinked
	}
	if !img.here {
		return "", errLinkedElsewhere
	}
	return img.link, nil
}

// splitFinal splits a pathname at its final component, trailing slashes ignored: "/a/b/" is ("/a", "b"),
// "/x" is ("/", "x"), "x" is (".", "x"), and "/" has no final component.
func splitFinal(p string) (dir, base string) {
	t := strings.TrimRight(p, "/")
	if t == "" {
		return "/", ""
	}
	i := strings.LastIndex(t, "/")
	switch {
	case i < 0:
		return ".", t
	case i == 0:
		return "/", t[1:]
	}
	return t[:i], t[i+1:]
}

// StatID stats p following symlinks, the way the Landlock builder opens an exec entry to grant it.
func (k sysKernel) StatID(p string) (fileID, error) {
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		return fileID{}, err
	}
	return fileID{dev: st.Dev, ino: st.Ino}, nil
}

// LstatID stats p without following its final component, as a rename or a link acts on the name itself.
func (k sysKernel) LstatID(p string) (fileID, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(unix.AT_FDCWD, p, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fileID{}, err
	}
	return fileID{dev: st.Dev, ino: st.Ino}, nil
}
