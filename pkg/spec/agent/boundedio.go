// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Compile reads files and lists directories whose content someone other than the operator chose: the
// binaries R8 opens for their PT_INTERP loader or #! interpreter (the command, an mcp command and exec.allow
// entries, which often sit in the worktree: ./run.sh, .venv/bin/python, node_modules/.bin), and R20's .git
// files, commondir files and git configs beneath a write entry, and the directories beneath it. The next
// compile may run as root under sudo, and I6 bounds every read it makes, so every one of those reads goes
// through openData, which a file's owner cannot turn into a wait on the file, an unbounded read or a driver's
// side effect. The shapes it refuses: a FIFO blocks an ordinary open until a writer comes and then feeds the
// read as long as the writer likes; /dev/zero never ends; a sparse file can claim any size; opening some
// devices acts (a watchdog starts counting down when opened); a file of the kernel's own interfaces is a
// handler, not data: /proc/kmsg is a regular file of size 0 whose read, as root, consumes the unread kernel
// log and otherwise waits for the next message; and a file its owner holds a write lease on (F_SETLEASE,
// which any owner may take on its own files) holds a blocking open for the lease-break time, 45 s by
// default. O_NONBLOCK turns the lease wait and a lock's into EWOULDBLOCK, but Go's runtime poller turns
// EAGAIN on any descriptor that polls back into a wait, so O_NONBLOCK alone protects nothing through an
// *os.File.
//
// What openData does not bound is the path walk before it and how many there are. One walk is the kernel's:
// at most 40 links, each up to 4095 bytes, so a planted chain of 39 links through directories 1980 levels
// deep makes one lstat or open cost 5 to 11 ms (measured on two machines), against microseconds for an
// ordinary path. How many walks R20's search and the .env scan make is the agent's choice, so each has a time
// limit as a whole (denySearch, builtIn), and the walks of a compile's declared paths are as many as its
// contract has entries. Without /proc a path is resolved by filepath.EvalSymlinks instead (resolvePath), a
// walk in user space that follows up to 255 links and costs seconds through the same chain.

// dataFS are the file systems whose regular files hold data someone stored, which openData reads: local
// disk and flash file systems, the memory-backed tmpfs and ramfs (an initramfs root is one of them), the
// union and stacked ones over them (overlayfs, the container root; aufs and shiftfs, older Docker and LXD
// hosts; ecryptfs, an encrypted home), read-only images (squashfs, as snaps are; erofs; romfs; ISO 9660;
// UDF), the network, cluster and shared-folder file systems a home or a worktree is mounted from (NFS, SMB,
// 9p, Ceph, AFS, Coda, Lustre, IBM Storage Scale (GPFS), BeeGFS, PanFS, OrangeFS, Oracle ACFS, StorNext,
// the VirtualBox, VMware and Parallels shared folders, User-Mode Linux's hostfs, and FUSE, which carries
// virtiofs, sshfs and NTFS-3G). It is a list of what to read, not of what to skip: a file system not on it,
// a kernel interface file system (procfs, sysfs, debugfs, tracefs, securityfs, configfs, cgroup, bpffs,
// efivarfs, pstore), one whose regular files are pipes or endpoints (rpc_pipefs, mqueue, functionfs, xenfs)
// or one added to the kernel after this list, is not read, whatever its mode says, and a binary on one fails
// the run at Prepare (R8), so a data file system missing here is a bug to report, not a setting.
//
// A read on a network, cluster or FUSE file system waits on its server or its daemon, which O_NONBLOCK does
// not change, and so does each step of a path walk through one; and a walk that crosses an automount point
// (autofs: /net's -hosts map, a systemd automount unit for an NFS or SMB share) makes the kernel mount it
// first, waiting on that server, however it answers, down or not. That wait is the mounter's, not the file's
// owner's, and an agent inside a run whose Landlock domain handles filesystem rights cannot mount one itself
// (the domain refuses mount(2), SEMANTICS §10). It can still have one mounted, and left mounted, or name one
// the host mounts on demand: a FUSE file system it mounted in a run that enforced nothing (--observe); a
// mount a daemon outside the run made at its request, through a host socket R19 names (the session bus to
// gvfsd or udisks2, gio mount of an archive it built); or an automount point the host already has, which any
// path the agent chooses (a core.hooksPath value, a gitdir, a .env link) can name, so the walk triggers the
// mount itself, with no request of the agent's needed. None of these is bounded by R20's or the .env scan's
// time limit, which is asked between walks, not within one. They are the residual agent-contract R20 names.
var dataFS = map[uint32]bool{
	unix.EXT4_SUPER_MAGIC:      true, // ext2, ext3 and ext4 share it
	unix.XFS_SUPER_MAGIC:       true,
	unix.BTRFS_SUPER_MAGIC:     true,
	zfsMagic:                   true,
	unix.F2FS_SUPER_MAGIC:      true,
	unix.BCACHEFS_SUPER_MAGIC:  true,
	unix.REISERFS_SUPER_MAGIC:  true,
	jfsMagic:                   true,
	unix.NILFS_SUPER_MAGIC:     true,
	unix.OCFS2_SUPER_MAGIC:     true,
	gfs2Magic:                  true,
	unix.MSDOS_SUPER_MAGIC:     true, // vfat and msdos
	unix.EXFAT_SUPER_MAGIC:     true,
	ntfsMagic:                  true,
	ntfs3Magic:                 true,
	hfsPlusMagic:               true,
	hfsMagic:                   true,
	ufsMagic:                   true,
	vxfsMagic:                  true,
	ubifsMagic:                 true,
	unix.JFFS2_SUPER_MAGIC:     true,
	unix.MINIX_SUPER_MAGIC:     true,
	unix.MINIX_SUPER_MAGIC2:    true,
	unix.MINIX2_SUPER_MAGIC:    true,
	unix.MINIX2_SUPER_MAGIC2:   true,
	unix.MINIX3_SUPER_MAGIC:    true,
	unix.ADFS_SUPER_MAGIC:      true,
	unix.AFFS_SUPER_MAGIC:      true,
	unix.EFS_SUPER_MAGIC:       true,
	unix.HPFS_SUPER_MAGIC:      true,
	unix.QNX4_SUPER_MAGIC:      true,
	unix.QNX6_SUPER_MAGIC:      true,
	bfsMagic:                   true,
	befsMagic:                  true,
	unix.TMPFS_MAGIC:           true,
	unix.RAMFS_MAGIC:           true,
	unix.OVERLAYFS_SUPER_MAGIC: true,
	aufsMagic:                  true,
	shiftfsMagic:               true,
	unix.ECRYPTFS_SUPER_MAGIC:  true,
	unix.SQUASHFS_MAGIC:        true,
	unix.EROFS_SUPER_MAGIC_V1:  true,
	romfsMagic:                 true,
	unix.ISOFS_SUPER_MAGIC:     true,
	unix.UDF_SUPER_MAGIC:       true,
	unix.CRAMFS_MAGIC:          true,
	unix.NFS_SUPER_MAGIC:       true,
	unix.SMB_SUPER_MAGIC:       true,
	unix.SMB2_SUPER_MAGIC:      true,
	unix.CIFS_SUPER_MAGIC:      true,
	unix.V9FS_MAGIC:            true,
	unix.CEPH_SUPER_MAGIC:      true,
	unix.AFS_SUPER_MAGIC:       true,
	unix.AFS_FS_MAGIC:          true,
	unix.CODA_SUPER_MAGIC:      true,
	lustreMagic:                true,
	gpfsMagic:                  true,
	beegfsMagic:                true,
	panfsMagic:                 true,
	orangefsMagic:              true,
	acfsMagic:                  true,
	snfsMagic:                  true,
	unix.HOSTFS_SUPER_MAGIC:    true,
	unix.FUSE_SUPER_MAGIC:      true,
	vboxsfMagic:                true,
	vmhgfsMagic:                true,
	prlfsMagic:                 true,
}

// The magics dataFS names that golang.org/x/sys/unix does not define, each as its own file system sets
// f_type (and as GNU coreutils' stat -f, src/stat.c, names it).
const (
	zfsMagic      = 0x2fc12fc1 // OpenZFS include/sys/zfs_vfsops.h ZFS_SUPER_MAGIC
	jfsMagic      = 0x3153464a // fs/jfs/jfs_filsys.h JFS_SUPER_MAGIC
	gfs2Magic     = 0x01161970 // include/uapi/linux/gfs2_ondisk.h GFS2_MAGIC
	ntfsMagic     = 0x5346544e // fs/ntfs NTFS_SB_MAGIC, the driver ntfs3 replaced
	ntfs3Magic    = 0x7366746e // fs/ntfs3/super.c
	hfsPlusMagic  = 0x482b     // fs/hfsplus/hfsplus_raw.h HFSPLUS_SUPER_MAGIC
	hfsMagic      = 0x4244     // fs/hfs/hfs.h HFS_SUPER_MAGIC
	ufsMagic      = 0x00011954 // fs/ufs/ufs_fs.h UFS_MAGIC
	vxfsMagic     = 0xa501fcf5 // fs/freevxfs/vxfs.h VXFS_SUPER_MAGIC
	ubifsMagic    = 0x24051905 // fs/ubifs/ubifs.h UBIFS_SUPER_MAGIC
	bfsMagic      = 0x1badface // include/uapi/linux/bfs_fs.h BFS_MAGIC
	befsMagic     = 0x42465331 // fs/befs/befs_fs_types.h BEFS_SUPER_MAGIC1
	romfsMagic    = 0x7275     // include/uapi/linux/romfs_fs.h ROMFS_MAGIC
	aufsMagic     = 0x61756673 // aufs include/uapi/linux/aufs_type.h AUFS_SUPER_MAGIC ("aufs")
	shiftfsMagic  = 0x6a656a62 // Ubuntu's fs/shiftfs.c SHIFTFS_MAGIC
	lustreMagic   = 0x0bd00bd0 // Lustre lustre/include/uapi/linux/lustre/lustre_user.h LL_SUPER_MAGIC
	gpfsMagic     = 0x47504653 // IBM Storage Scale (GPFS), coreutils S_MAGIC_GPFS
	beegfsMagic   = 0x19830326 // BeeGFS (formerly FhGFS), coreutils S_MAGIC_FHGFS
	panfsMagic    = 0xaad7aaea // Panasas PanFS, coreutils S_MAGIC_PANFS
	orangefsMagic = 0x20030528 // fs/orangefs/orangefs-kernel.h ORANGEFS_SUPER_MAGIC (coreutils "pvfs2")
	acfsMagic     = 0x61636673 // Oracle ACFS, coreutils S_MAGIC_ACFS
	snfsMagic     = 0xbeefdead // Quantum StorNext, coreutils S_MAGIC_SNFS
	vboxsfMagic   = 0x786f4256 // fs/vboxsf/super.c VBOXSF_SUPER_MAGIC
	vmhgfsMagic   = 0xbacbacbc // VMware's vmhgfs shared folders, coreutils S_MAGIC_VMHGFS
	prlfsMagic    = 0x7c7c6673 // Parallels Tools' prl_fs
)

// fsNames names the file systems a refusal most often meets, for its message; the rest are named by magic.
var fsNames = map[uint32]string{
	unix.PROC_SUPER_MAGIC:     "procfs",
	unix.SYSFS_MAGIC:          "sysfs",
	unix.DEBUGFS_MAGIC:        "debugfs",
	unix.TRACEFS_MAGIC:        "tracefs",
	unix.SECURITYFS_MAGIC:     "securityfs",
	unix.CGROUP_SUPER_MAGIC:   "cgroup",
	unix.CGROUP2_SUPER_MAGIC:  "cgroup2",
	unix.BPF_FS_MAGIC:         "bpffs",
	unix.EFIVARFS_MAGIC:       "efivarfs",
	unix.PSTOREFS_MAGIC:       "pstore",
	unix.DEVPTS_SUPER_MAGIC:   "devpts",
	unix.HUGETLBFS_MAGIC:      "hugetlbfs",
	unix.XENFS_SUPER_MAGIC:    "xenfs",
	unix.ZONEFS_MAGIC:         "zonefs",
	unix.SELINUX_MAGIC:        "selinuxfs",
	unix.SMACK_MAGIC:          "smackfs",
	unix.BINFMTFS_MAGIC:       "binfmt_misc",
	unix.AUTOFS_SUPER_MAGIC:   "autofs",
	unix.NSFS_MAGIC:           "nsfs",
	configfsMagic:             "configfs",
	mqueueMagic:               "mqueue",
	rpcPipefsMagic:            "rpc_pipefs",
	functionfsMagic:           "functionfs",
	unix.OPENPROM_SUPER_MAGIC: "openpromfs",
}

const (
	configfsMagic   = 0x62656570 // fs/configfs/mount.c CONFIGFS_MAGIC
	mqueueMagic     = 0x19800202 // ipc/mqueue.c MQUEUE_MAGIC
	rpcPipefsMagic  = 0x67596969 // net/sunrpc/rpc_pipe.c RPCAUTH_GSSMAGIC
	functionfsMagic = 0xa647361  // include/uapi/linux/usb/functionfs.h FUNCTIONFS_MAGIC
)

// pathMax is PATH_MAX (include/uapi/linux/limits.h), counting the terminating NUL: the kernel refuses a
// longer path name, so no program opens one by name.
const pathMax = 4096

// procSelfFD is where this process's descriptors are named, through which every probe (resolveProbe) and
// every read (openData) goes. A variable so a test can take it away, as a system without /proc mounted does.
var procSelfFD = "/proc/self/fd/"

// procMounted reports whether procSelfFD is there: without it, R20's search resolves and reads nothing, and
// says so rather than naming nothing in silence.
func procMounted() bool {
	return unix.Access(procSelfFD, unix.F_OK) == nil
}

// refusal says why openData read nothing; it is the Err of the *fs.PathError openData returns.
type refusal string

func (r refusal) Error() string { return string(r) }

// fsRefusal is openData's refusal of a regular file on a file system that is not in dataFS.
type fsRefusal struct{ magic uint32 }

func (r fsRefusal) Error() string {
	name := ""
	if n := fsNames[r.magic]; n != "" {
		name = n + ", "
	}
	return "on a file system not known to store data (" + name + "magic 0x" + strconv.FormatUint(uint64(r.magic), 16) +
		"), which is not on the list of file systems read"
}

// errOverBound is the Err of the *fs.PathError readSmallErr returns for a file larger than its bound, including
// one that grew past it while read.
var errOverBound = errors.New("larger than the bound of this read")

// errReadCap is what a boundedReaderAt answers once a read would pass its cap.
var errReadCap = errors.New("read past the bound")

// openData is the one way this package opens a file whose content someone other than the operator chose
// (in compile, and in the Landlock tier's Prepare through ReadInterp and ReadShebang), and returns a
// descriptor to read it with and fstat's view of it. The path is opened O_PATH first, which runs
// no driver's open and breaks no lease, and fstat and fstatfs on that descriptor decide: only a regular
// file on one of dataFS is then opened for reading, through /proc/self/fd, so the file read is the one
// fstat saw even if the path is swapped in between, and with O_NONBLOCK, so a lease or a lock held on it is
// EWOULDBLOCK, not a wait. A final symlink is followed only when follow is set. The caller closes the
// descriptor and reads it with read(2) or pread(2) only (readBounded, preadFull), never through an *os.File.
func openData(path string, follow bool) (int, unix.Stat_t, error) {
	var st unix.Stat_t
	flags := unix.O_PATH | unix.O_CLOEXEC
	if !follow {
		flags |= unix.O_NOFOLLOW
	}
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return -1, st, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.Fstat(fd, &st); err != nil {
		return -1, st, &fs.PathError{Op: "fstat", Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return -1, st, &fs.PathError{Op: "open", Path: path, Err: refusal("not a regular file (" + fileType(st.Mode) + ")")}
	}
	var sfs unix.Statfs_t
	if err := unix.Fstatfs(fd, &sfs); err != nil {
		return -1, st, &fs.PathError{Op: "fstatfs", Path: path, Err: err}
	}
	if !dataFS[uint32(sfs.Type)] {
		return -1, st, &fs.PathError{Op: "open", Path: path, Err: fsRefusal{uint32(sfs.Type)}}
	}
	rfd, err := unix.Open(procSelfFD+strconv.Itoa(fd), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, st, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	return rfd, st, nil
}

// fileType names a file type fstat reported, for a refusal's message.
func fileType(mode uint32) string {
	switch mode & unix.S_IFMT {
	case unix.S_IFIFO:
		return "a FIFO"
	case unix.S_IFCHR:
		return "a character device"
	case unix.S_IFBLK:
		return "a block device"
	case unix.S_IFSOCK:
		return "a socket"
	case unix.S_IFDIR:
		return "a directory"
	case unix.S_IFLNK:
		return "a symlink"
	}
	return "type " + strconv.FormatUint(uint64(mode&unix.S_IFMT), 8)
}

// readSmallErr returns the content of the file at path when openData opens it and it is at most limit bytes,
// or the reason it read nothing: openData's, errOverBound, or the read's own error. The read is readBounded's loop, which stops one byte past limit, so a file that grew beyond the
// bound after fstat is refused, not read to its end.
func readSmallErr(path string, limit int64, follow bool) ([]byte, error) {
	fd, st, err := openData(path, follow)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	if st.Size > limit {
		return nil, &fs.PathError{Op: "read", Path: path, Err: errOverBound}
	}
	data, err := readBounded(fd, st.Size, limit)
	if err != nil {
		return nil, &fs.PathError{Op: "read", Path: path, Err: err}
	}
	return data, nil
}

// readBounded reads fd to its end with read(2), starting from a buffer of size+1 bytes (fstat's size, and one
// more to see growth), and refuses the content when it passes limit (errOverBound) or any read fails. It is
// the raw read(2) loop, never an *os.File: Go registers any descriptor that supports poll with its poller
// and parks the goroutine on EAGAIN until the descriptor is readable, which for a file that only becomes
// readable when the kernel says so is a hang. Here EAGAIN and every other error refuse the file, except EINTR,
// which is retried (retryEINTR).
func readBounded(fd int, size, limit int64) ([]byte, error) {
	buf := make([]byte, min(size, limit)+1)
	n := 0
	var eintr retryEINTR
	for {
		if n == len(buf) {
			if int64(n) > limit {
				return nil, errOverBound
			}
			buf = append(buf, make([]byte, limit+1-int64(n))...)
		}
		m, err := sysRead(fd, buf[n:])
		if eintr.again(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if m == 0 {
			return buf[:n], nil
		}
		n += m
	}
}

// preadFull fills p from fd at off with pread(2), for the same reason readBounded uses read(2); it returns
// fewer bytes than len(p) only at the end of the file, and the first error, EAGAIN among them, as it comes,
// except EINTR, which is retried (retryEINTR).
func preadFull(fd int, p []byte, off int64) (int, error) {
	n := 0
	var eintr retryEINTR
	for n < len(p) {
		m, err := sysPread(fd, p[n:], off+int64(n))
		if eintr.again(err) {
			continue
		}
		if err != nil {
			return n, err
		}
		if m == 0 {
			break
		}
		n += m
	}
	return n, nil
}

// sysRead and sysPread are read(2) and pread(2), and sysOpenat2 and sysReadlinkat ReadPlaceLink's openat2(2) and
// readlinkat(2), variables so a test can interrupt them.
var (
	sysRead       = unix.Read
	sysPread      = unix.Pread
	sysOpenat2    = unix.Openat2
	sysReadlinkat = unix.Readlinkat
)

// maxEINTR is how many interrupted reads one readBounded or preadFull call retries before it refuses the file.
const maxEINTR = 16

// retryEINTR counts the retries of one read loop. A read on a local file system is not interrupted, but one
// on FUSE or a network file system can answer EINTR when a signal arrives while it waits on the daemon or
// the server (a FUSE daemon that honours FUSE_INTERRUPT does, under SA_RESTART too, and the Go runtime's
// preemption signal is one such), and os.File retries it. Refusing it instead failed a run on such a
// mount at Prepare (R8), now and then. A retry is a new read(2) with no wait of its own: it waits only as the
// interrupted read did, on the mounter's daemon or server, never on the file's owner (EAGAIN still refuses),
// and the count bounds a signal storm.
type retryEINTR int

// again reports whether err is EINTR with retries left, counting the retry.
func (r *retryEINTR) again(err error) bool {
	if !errors.Is(err, unix.EINTR) || *r >= maxEINTR {
		return false
	}
	*r++
	return true
}

// boundedReaderAt is an io.ReaderAt over a descriptor openData returned that reads at most left bytes in
// all: the ELF reader's reads are few and small (readInterp), and the cap makes that a property of the
// reader rather than of the parser.
type boundedReaderAt struct {
	fd   int
	left int
}

func (r *boundedReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if len(p) > r.left {
		return 0, errReadCap
	}
	r.left -= len(p)
	n, err := preadFull(r.fd, p, off)
	if err != nil {
		return n, err
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// resolveProbe returns where path leads when it exists, resolved by the kernel: the path is opened O_PATH,
// following links, and the descriptor's /proc/self/fd link names what it reached. A final symlink that
// leads nowhere, or loops, exists as itself: opened O_NOFOLLOW, its link names the symlink in its resolved
// directory, as compiler.resolve has it. ok is false when nothing is at path, the kernel refuses to resolve
// it, or /proc is not mounted.
//
// The path can be chosen by the agent (R20's core.hooksPath values, a .git file's gitdir), and the lstat
// first answers the common case, a candidate that does not exist, with one walk. Each walk is the kernel's:
// a name of PATH_MAX bytes or more is refused before any, and a walk through more than 40 links is refused
// when it reaches the 41st, but each link can be up to 4095 bytes, so one walk through a planted chain costs
// 5 to 11 ms (39 links through directories 1980 levels deep), and a probe makes up to three. That is the
// cost of one probe, not of the search: how many the search makes is bounded by its time limit (denySearch).
// filepath.EvalSymlinks, which this replaces, re-walks the path from the root at every component and follows
// up to 255 links: 2000 real directories cost it 90 ms, where the kernel's walk costs 0.3 ms.
func resolveProbe(path string) (string, bool) {
	r, _, ok := probeLanding(path)
	return r, ok
}

// probeLanding is resolveProbe's answer, and whether the walk followed path to where it leads (followed): false for
// a final symlink answered as itself because the following open failed (it leads nowhere yet, it loops, or a
// directory on the way to its target is not searchable). A loader that opens such a path follows the link, and a
// file made where it leads is what the loader reads, so neither placePath's directory nor R20's candidates take that
// answer as where the walk lands.
func probeLanding(path string) (r string, followed, ok bool) {
	r, _, followed, ok = probeAt(path, false)
	return r, followed, ok
}

// probeLandingName is probeLanding with the place of path's own final name (name): for a final symlink the walk
// followed, the link itself, opened O_NOFOLLOW (one walk more, still at most three), else r. R20's candidates are held
// at both places, since a link beneath a write entry can be replaced whatever it leads to.
func probeLandingName(path string) (r, name string, followed, ok bool) {
	return probeAt(path, true)
}

func probeAt(path string, wantName bool) (r, name string, followed, ok bool) {
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil {
		return "", "", false, false
	}
	if p, ok := fdPath(path, unix.O_PATH|unix.O_CLOEXEC); ok {
		name = p
		if wantName && st.Mode&unix.S_IFMT == unix.S_IFLNK {
			if n, ok := fdPath(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC); ok {
				name = n
			}
		}
		return p, name, true, true
	}
	p, ok := fdPath(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC)
	return p, p, false, ok
}

// resolvePath is where the kernel's walk of p leads (placePath), or p itself when no walk places it.
func resolvePath(p string) string {
	r, _ := placePath(p)
	return r
}

// placePath is where the kernel's walk of p leads, for a path compile compares as a rule names it (compiler.resolve:
// write, deny and exec entries): resolveProbe's answer when something is at p, a final symlink leading nowhere (or
// looping) as itself, as an O_PATH rule on that name pins it; else p's directory resolved the same way with p's name
// kept (a write directory run creates); else, with p's directory not made yet either, ResolveUnixPlace's place, where
// the walk lands once the missing directories are made, as realpath -m places it. ok is false, and p
// as given, for "" and for a path no walk places (a relative one, a loop of links, a read that fails:
// ResolveUnixPlace). A place tego itself loads or keeps (R10's targets, OwnState, OwnReadable) is walkTarget's, not
// this: it follows a final link leading nowhere, and names every directory the walk reads a name in.
// Compile resolves every path it compares this way (compiler.resolve). Each call is
// at most six walks of resolveProbe's, each one's cost bounded as resolveProbe says, so a declared path
// through a chain the agent planted costs tens of milliseconds; how many calls there are is the contract's
// (its entries, their loaders and interpreters), except the .env scan's results, whose resolution has the
// scan's time limit (builtIn). Where /proc is not mounted resolveProbe answers nothing, and the walk is
// filepath.EvalSymlinks's instead: the same answer, at its cost, which that bound does not hold for. It
// lstats the path from the root at every component and follows up to 255 links, so one call through the
// 39-link chain took 3.3 s, and a resolution makes up to two (p, then its directory): a declared path the
// agent linked into the chain costs seconds each, and the .env scan, whose time limit is checked between
// resolutions, not within one, overruns it by up to one resolution. The last fallback, ResolveUnixPlace, is
// one read a name, bounded by unixPlaceNames, and is reached only for a path whose directory is missing too.
//
// A directory is always followed: the walk of p goes through p's directory to where it leads, so a directory that is a
// symlink leading nowhere yet (or looping) is placed by ResolveUnixPlace, never as the link's own spelling with p's
// name beneath it, which no walk reaches (a registry root linked to a directory not made yet placed its agents/
// beside the link).
func placePath(p string) (string, bool) {
	if p == "" {
		return "", false
	}
	if r, ok := resolveProbe(p); ok {
		return r, true
	}
	if dir, name, ok := splitAsWalked(p); ok {
		if d, followed, ok := probeLanding(dir); ok && followed {
			return filepath.Join(d, name), true
		}
		if !procMounted() {
			if r, err := filepath.EvalSymlinks(p); err == nil {
				return r, true
			}
			if d, err := filepath.EvalSymlinks(dir); err == nil {
				return filepath.Join(d, name), true
			}
		}
	}
	return ResolveUnixPlace(p, ReadPlaceLink)
}

// targetWalk is the kernel's walk of a path tego loads or keeps (agent-contract R10, ADR 0059 (1)): where it lands and
// every name it reads on the way.
type targetWalk struct {
	place  string   // where the walk lands, a name not there yet taken as a directory the run could make (realpath -m)
	placed bool     // false, and place the path as given: no walk places it (ResolveUnixPlace)
	names  []string // every name the walk looks up, in walk order, each by its placed directory and its name
	links  []string // those of names that are symlinks the walk follows
}

// walkTarget is the walk of the absolute path p as a loader's open takes it, one name at a time from the root, never
// cleaned (ResolveUnixPlace, each name read with ReadPlaceLink): a symlink is followed to where it points, whether its
// target is there yet or not, and its text walked the same way; a ".." is taken from where the walk stands; a name not
// there yet is kept, as the directory the run could make. Every name the walk looks up is recorded, a ".." none: the
// kernel takes it from the directory the walk stands in, which a name in the directory before it led to. So the
// places R10 compares are the walk's own, and none is a spelling: a probe's /proc/self/fd name answered a final link
// leading nowhere as the link itself, and the /proc-less fallback did too; and the
// directories holding a link were R10's only other targets, so a name a later ".." leaves (<w>/sub/x/../../reg), which
// the agent could make a link once it wrote <w>/sub, was compared with nothing. A relative or empty p
// is not placed. The cost is ResolveUnixPlace's: one read a name, at most unixPlaceNames, with no /proc needed.
func walkTarget(p string) targetWalk {
	var w targetWalk
	if !filepath.IsAbs(p) {
		w.place = p
		return w
	}
	w.place, w.placed = ResolveUnixPlace(p, func(name string) (string, error) {
		w.names = append(w.names, name)
		t, err := ReadPlaceLink(name)
		if err == nil {
			w.links = append(w.links, name)
		}
		return t, err
	})
	return w
}

// splitAsWalked is p's directory and last name as the kernel's walk takes them: the text before p's last name, never
// cleaned, since filepath.Dir cleans and a ".." after a link is then taken from the link's directory, not from where
// the link leads (a registry's agents/ not made yet was placed beside the link's spelling). ok is false
// when the last name is "." or "..", which name a directory, not a name in it.
func splitAsWalked(p string) (dir, name string, ok bool) {
	p = strings.TrimRight(p, "/")
	dir, name = ".", p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		dir, name = p[:i], p[i+1:]
	}
	if dir == "" {
		dir = "/"
	}
	return dir, name, name != "" && name != "." && name != ".."
}

// WalkedPath is the absolute path p spelled where the kernel's walk of it lands, for a path some loader opens as
// given (a contract file, a machine config layer, a registry): filepath.Clean's spelling when no name of p is "..",
// since cleaning then names the same file; else the directory up to p's last "..", placed by the kernel's walk
// (ResolveUnixPlace, every link on the way followed), with the names after it kept as written. filepath.Clean (and
// filepath.Abs, filepath.Join and filepath.Dir, which clean) removes a ".." with the name before it, where the
// kernel's walk goes up from the directory a link before it led to: <dir>/lnk/../x is <lnk's target's parent>/x, not
// <dir>/x (reviews RS5-1..3). ok is false, and p as given, for a relative p or one ResolveUnixPlace cannot place.
func WalkedPath(p string) (string, bool) {
	if !filepath.IsAbs(p) {
		return p, false
	}
	names := placeNames(p)
	up := -1
	for i, n := range names {
		if n == ".." {
			up = i
		}
	}
	if up < 0 {
		return filepath.Clean(p), true
	}
	dir, ok := ResolveUnixPlace("/"+strings.Join(names[:up+1], "/"), ReadPlaceLink)
	if !ok {
		return p, false
	}
	return filepath.Join(append([]string{dir}, names[up+1:]...)...), true
}

// resolveDeepest is a declared unix: path's place (NetRule.UnixResolved): ResolveUnixPlace over this process's view,
// its symlinks read with ReadPlaceLink, or the path as given when it cannot be placed.
func resolveDeepest(p string) string {
	if p == "" {
		return ""
	}
	r, _ := ResolveUnixPlace(p, ReadPlaceLink)
	return r
}

// ReadPlaceLink reads the symlink at p, one name of a unix path being placed (ResolveUnixPlace), without following any
// symlink before its last name: p's directory is opened with openat2 RESOLVE_NO_SYMLINKS and the name read with
// readlinkat there. A directory on the way that is a symlink fails ELOOP. ResolveUnixPlace reads only names whose
// directories its walk passed and found no symlink, so it meets ELOOP only when one of them became a symlink after
// the walk passed it — an agent's thread racing the placement — and that placement ends, not placed. One read so
// costs one walk of at most PATH_MAX bytes through plain directories, whatever links the agent makes meanwhile
// (a readlink of the whole path walked it from the root again and followed a name the agent had just made a symlink,
// up to 40 links of PATH_MAX bytes on every later read, 1.17 s for one placement). Where
// openat2 is refused (ENOSYS or EPERM: a kernel before 5.6, or a seccomp filter without it, as a governed run's is)
// the read is readlink's of the whole path, whose cost that bound does not hold for against a racing agent: it is
// then bounded only by the constants, 1024 reads each through up to 40 links (1.46 s measured for one placement).
// EINTR (a FUSE or network file system's lookup interrupted by a signal) is retried, as os.Readlink retries it, up
// to maxEINTR times; still interrupted, it is returned, and ResolveUnixPlace then does not place the path, where an
// unread name would otherwise be kept as if it were no link.
func ReadPlaceLink(p string) (string, error) {
	dir, name := filepath.Split(p)
	if dir == "" || name == "" {
		return os.Readlink(p)
	}
	how := unix.OpenHow{Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS}
	var eintr retryEINTR
	fd, err := sysOpenat2(unix.AT_FDCWD, dir, &how)
	for eintr.again(err) {
		fd, err = sysOpenat2(unix.AT_FDCWD, dir, &how)
	}
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) {
		return os.Readlink(p)
	}
	if err != nil {
		return "", &fs.PathError{Op: "openat2", Path: dir, Err: err}
	}
	defer func() { _ = unix.Close(fd) }()
	for size := 128; ; size *= 2 {
		buf := make([]byte, size)
		n, err := sysReadlinkat(fd, name, buf)
		for eintr.again(err) {
			n, err = sysReadlinkat(fd, name, buf)
		}
		if err != nil {
			return "", &fs.PathError{Op: "readlinkat", Path: p, Err: err}
		}
		if n < size || size >= unix.PathMax {
			return string(buf[:n]), nil
		}
	}
}

// unixPlaceLinks is how many symlinks ResolveUnixPlace follows on one path: the kernel's own bound (MAXSYMLINKS).
const unixPlaceLinks = 40

// unixPlaceNames is how many names ResolveUnixPlace takes on one path, those of the link targets it follows included:
// a path a person writes, or a socket's name, has tens. It bounds one placement's cost by a constant, one read
// (ReadPlaceLink) per name, each a walk of at most PATH_MAX bytes through directories with no symlink (a chain of
// dangling links an agent made through thousands of directories and back cost tens of seconds of the supervisor's
// time per connect before).
const unixPlaceNames = 1024

// ResolveUnixPlace is the place a unix socket path p names (SEMANTICS §5, supervisor R11c): where the kernel's lookup
// of p lands once the directories and the socket below its deepest existing ancestor are made, as realpath -m
// resolves a path. The path is walked as the kernel walks it, one name at a time from the root, never cleaned
// lexically first: a name that is a symlink (readlink reads it, whether or not its target exists yet) is followed to
// where it points, relative to its own directory, as the kernel follows it once the run makes that target, and its
// target's names are walked the same way; a ".." removes the name before it, a symlink before it already followed;
// any other name, one that names nothing yet included, is kept. Each name costs one read at most, so a placement is
// linear in the names walked; with ReadPlaceLink each read walks only directories the walk kept, never through a
// symlink, so a name an agent's thread turns into a link after the walk passed it cannot make the later reads
// longer: the read meets it, fails ELOOP, and the placement ends there, not placed. One placement so costs at most
// unixPlaceNames reads through plain directories, raced or not: 35 to 56 ms measured for a path 1100 directories
// deep (TestResolveUnixPlaceIsBounded).
// Compile (NetRule.UnixResolved) and the supervisor (its table's entries and scopes when the loop is built, and the
// name of a connect whose socket or directory is not there yet) resolve with this one function, each over its own
// view, so compile --test and the run place a scope alike. ok is false, and the place p as given, for a relative
// path, one through more than 40 links, one of more than unixPlaceNames names (theirs included), one whose place
// grows past PATH_MAX, or one whose read fails with anything but EINVAL, ENOENT or ENOTDIR (namesNoLink: ELOOP when a
// directory the walk kept became a symlink meanwhile, EINTR past ReadPlaceLink's retries, EMFILE, EACCES and the
// like, whether the name is a link unknown): the kernel's walk fails ELOOP on the second, and the others cannot be a
// socket's place this process can compare (a scope's then matches only the place it spells; a connect's name is no
// scope's).
func ResolveUnixPlace(p string, readlink func(string) (string, error)) (string, bool) {
	if !filepath.IsAbs(p) {
		return p, false
	}
	at, todo := "/", placeNames(p)
	for taken, links := 0, 0; len(todo) > 0; taken++ {
		if taken == unixPlaceNames {
			return p, false
		}
		name := todo[0]
		todo = todo[1:]
		if name == ".." {
			at = filepath.Dir(at)
			continue
		}
		next := strings.TrimSuffix(at, "/") + "/" + name
		if len(next) >= unix.PathMax {
			return p, false
		}
		target, err := readlink(next)
		if err != nil {
			if !namesNoLink(err) {
				return p, false // a directory the walk kept is a symlink by now (ReadPlaceLink), or the name's kind unknown
			}
			at = next // not a symlink, or nothing there yet
			continue
		}
		if links++; links > unixPlaceLinks {
			return p, false
		}
		if filepath.IsAbs(target) {
			at = "/"
		}
		todo = append(placeNames(target), todo...)
	}
	return at, true
}

// namesNoLink reports whether a failed read of one name of a unix path being placed says the name is no symlink:
// EINVAL (readlink's answer for a name that is something else), ENOENT or ENOTDIR (nothing is there yet, which the
// kernel's own lookup finds too). Every other failure leaves the name's kind unknown — ELOOP (a directory the walk
// kept became a symlink, ReadPlaceLink), EINTR past the retries, the descriptor table full (EMFILE, ENFILE: the
// openat2 takes a descriptor), ENOMEM, EIO, EACCES (this process may not search a directory the task may) — and
// ResolveUnixPlace then does not place the path: keeping such a name as if it were no link would place the path
// where the kernel's lookup does not land.
func namesNoLink(err error) bool {
	return errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR)
}

// placeNames is a path's components as the kernel's walk takes them: "" and "." are no step and dropped, ".." is kept
// for the walk to apply where it stands.
func placeNames(p string) []string {
	names := strings.Split(p, "/")
	kept := names[:0]
	for _, n := range names {
		if n != "" && n != "." {
			kept = append(kept, n)
		}
	}
	return kept
}

// fdPath opens path with flags and returns the absolute path the kernel reached.
func fdPath(path string, flags int) (string, bool) {
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return "", false
	}
	defer func() { _ = unix.Close(fd) }()
	p, err := os.Readlink(procSelfFD + strconv.Itoa(fd))
	if err != nil || !filepath.IsAbs(p) {
		return "", false
	}
	return p, true
}

// readDirN is (*os.File).ReadDir; a test replaces it to fail a listing partway.
var readDirN = (*os.File).ReadDir

// partialListError is a listing that failed after it began (getdents' EIO, a network or FUSE file
// system's error): the entries before it were returned, but the directory was not read whole.
type partialListError struct{ err error }

func (e *partialListError) Error() string { return "listing stopped partway: " + e.err.Error() }
func (e *partialListError) Unwrap() error { return e.err }

// listDir returns up to max entries of the directory at path, sorted by name, and more when the
// directory held further entries that were not read. Which entries a bounded read returns is the file
// system's order, not the names', so a caller that must find one name uses a lookup of that name instead.
// O_DIRECTORY makes the kernel refuse anything but a directory before any driver's open runs, and O_NOFOLLOW
// refuses a symlink in the final component, so a FIFO, a device or a link planted where a directory was
// expected yields nothing. epoll refuses a directory's descriptor (no directory implements poll), so Go's
// poller never parks these reads: each is a plain getdents call.
//
// err is the error that left it listing nothing, or, as a *partialListError beside the entries read before
// it, the one that stopped it partway, for a caller that must tell a directory that is not there from one it
// could not open or read whole. A partial listing with no error
// read as the whole directory, so a scan said nothing of the names it never saw.
func listDir(path string, max int) (entries []os.DirEntry, more bool, err error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = f.Close() }()
	entries, rerr := readDirN(f, max+1)
	if rerr != nil && !errors.Is(rerr, io.EOF) {
		err = &partialListError{rerr}
	}
	if len(entries) > max {
		entries, more = entries[:max], true
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, more, err
}
