// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/internal/platform/sys"

	"golang.org/x/sys/unix"
)

// A root launcher (`sudo tego run`, docs/P0-DESIGN.md §7) writes the ledger of a run it makes for the
// invoking user, and by default into that user's home: ~/.tego/runs and ~/.tego/chain.log. Everything
// it creates there would otherwise be root's, 0700 and 0600, and the user could then neither read the run
// with `tego status`, `events` or `drift`, nor start an unprivileged run of their own: mkdir in a
// root-owned ~/.tego/runs and the append to a root-owned chain.log both fail (docs/OPERATIONS.md: "the
// files a root run creates for it are handed to that user"; record-ledger.md §3).
//
// The rule is decided by the filesystem, not by SUDO_UID: what root creates inside a directory some other
// uid owns is handed to that uid and the directory's group. Only what a call itself created is handed
// over — a directory its mkdirat made, a file its O_CREAT|O_EXCL open made, a run directory root made and
// wrote alone — never an entry that was already there: the directory's owner can rename a file of root's
// into their own directory, and renaming never let them read it, so chowning whatever root-owned file sits
// under a name would give them its contents. A tree root owns — a server's /var/lib/tego/runs set up by
// the operator — keeps what root made in it.
//
// Root walks every directory it writes into one component at a time (openDir), and in a directory that is
// not root's alone — owned by another uid, or writable by its group or by others — it never follows a
// symlink: the user who can change that directory could have left a link to /etc under the name root is
// about to resolve, and a root launcher appending, creating or chowning through it would do so anywhere on
// the machine. What the walk opens is then used by descriptor: the Writer holds its run directory open from
// Open to Close and makes every file below it with *at() calls on that descriptor (openRunDir), so renaming
// a component of the ledger root while the run is live does not change where the Writer writes. A store made
// by NewBlobRepository — a uprobe source's, beside the Writer — has no descriptor: it walks to blobs/ afresh
// for every blob, refusing a link as above, so after the user replaces their ledger root its blobs land in
// whatever real directory the user's tree then names, never through a link: one the user owns, or a
// root-owned run directory already in it, since renames inside a directory the user owns need no write on
// the root-owned directories moved (mv runs/X runs/X.aside; mv runs/Y runs/X sends X's blobs to Y's
// blobs/). The bytes are the user's own agent traffic, and they cannot leave the user's tree (record-ledger.md
// §3, residual). A link in a directory
// only root can change is followed, as the kernel follows it: root put it there. A run directory is handed
// over only once its writer is done with it (Writer.Close). While the run is live the directory stays
// root's 0700, so the user cannot plant a link under a name root is about to create; the price is that a
// live root run is readable only as root.

// handOverDepth bounds the walk below a run directory: blobs/ is the only directory the writer creates
// in it.
const handOverDepth = 2

// owner is who an entry is handed to.
type owner struct{ uid, gid int }

// fchown hands the entry f is open on to uid and gid; the walk's tests record through it which entries
// would be handed over, since only root can hand a file to another uid.
var fchown = func(f *sys.FD, uid, gid int) error {
	return f.Borrow(func(n int) error { return unix.Fchown(n, uid, gid) })
}

// ownerOf is the owner the hand-over rule gives what root creates in the directory open at at: its own
// uid and gid when this process is root and the directory is someone else's; ok is false otherwise.
func ownerOf(at *sys.FD, path string) (owner, bool, error) {
	if os.Geteuid() != 0 {
		return owner{}, false, nil
	}
	var st unix.Stat_t
	if err := at.Fstat(&st); err != nil {
		return owner{}, false, &os.PathError{Op: "fstat", Path: path, Err: err}
	}
	if st.Uid == 0 {
		return owner{}, false, nil
	}
	return owner{uid: int(st.Uid), gid: int(st.Gid)}, true, nil
}

// giveTo hands the entry open at f to o when it is this process's own: a directory, or a regular file
// with no other link. Anything else is left alone — a hard link or a device is not something the writer
// made, and another user's entry is theirs already. giveTo cannot tell a file root created from one of
// root's that was renamed into place, so a caller passes only an entry its own call created, or one found
// in a directory that only this process could have written (handOverDir).
func giveTo(f *sys.FD, path string, o owner) error {
	var st unix.Stat_t
	if err := f.Fstat(&st); err != nil {
		return &os.PathError{Op: "fstat", Path: path, Err: err}
	}
	if int(st.Uid) != os.Geteuid() {
		return nil
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
	case unix.S_IFREG:
		if st.Nlink != 1 {
			return nil
		}
	default:
		return nil
	}
	if err := fchown(f, o.uid, o.gid); err != nil {
		return &os.PathError{Op: "chown", Path: path, Err: err}
	}
	return nil
}

// giveCreated hands f, an entry this call has just created in the directory open at at, to that
// directory's owner under the hand-over rule; it does nothing unless this process is root and the
// directory is another uid's.
func giveCreated(at *sys.FD, dir string, f *sys.FD, path string) error {
	o, ok, err := ownerOf(at, dir)
	if err != nil || !ok {
		return err
	}
	return giveTo(f, path, o)
}

// MakeDirs is os.MkdirAll(path, 0700) under the hand-over rule: each directory it creates inside a
// directory another uid owns is handed to that uid when this process is root, and, as root, an existing
// component that is a symlink in a directory that is not root's alone is refused with ErrLinkRefused rather
// than followed (openDir). Every other existing component is resolved as given, symlinks included:
// ledger_root is machine configuration, and a link an operator made in a directory only root can change is
// theirs to make. Only the directories this call creates are handed over, never one that already existed.
func MakeDirs(path string) error {
	d, err := openDir(path, true)
	if err != nil {
		return err
	}
	return d.Close()
}

// MakeRunDir creates the run directory name (0700, this process's own) in the ledger root at root, which
// it creates first as MakeDirs does. The directory is made through the descriptor the walk ended on, so
// the ledger root it lands in is the one the walk checked, not whatever the path names a moment later. A
// name that already exists is an error (os.ErrExist): a run directory is never reused.
func MakeRunDir(root, name string) error {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return fmt.Errorf("ledger: run directory name %q", name)
	}
	d, err := openDir(root, true)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	if err := mkdirAt(d, name); err != nil {
		return &os.PathError{Op: "mkdir", Path: filepath.Join(root, name), Err: err}
	}
	return nil
}

// mkdirAt is mkdirat(2) of name, 0700, in the directory open at at.
func mkdirAt(at *sys.FD, name string) error {
	return at.Borrow(func(n int) error { return unix.Mkdirat(n, name, 0o700) })
}

// unlinkAt is unlinkat(2) of the file name in the directory open at at.
func unlinkAt(at *sys.FD, name string) error {
	return at.Borrow(func(n int) error { return unix.Unlinkat(n, name, 0) })
}

// actingAsRoot reports whether this process is root, the one case the walk refuses links for. It is a
// variable so the unprivileged unit tests can take the privileged branch; only root's writes can land in
// a file the directory's owner could not write themselves.
var actingAsRoot = func() bool { return os.Geteuid() == 0 }

// refuseLinksIn reports whether a symlink in the directory open at at is refused rather than followed:
// when this process is root and the directory is not root's alone. An unprivileged process follows links
// as the kernel does, since a link can only take it where its own permissions already let it write.
func refuseLinksIn(at *sys.FD, dir string) (bool, error) {
	if !actingAsRoot() {
		return false, nil
	}
	var st unix.Stat_t
	if err := at.Fstat(&st); err != nil {
		return false, &os.PathError{Op: "fstat", Path: dir, Err: err}
	}
	return st.Uid != 0 || st.Mode&0o022 != 0, nil
}

// openDir opens the directory at path as an O_PATH descriptor for *at() calls, resolving it one component
// at a time from / (or from the working directory, for a relative path). A component in a directory
// refuseLinksIn names is opened O_NOFOLLOW, so a symlink there ends the walk with ErrLinkRefused instead of
// redirecting it. With create, a missing component is made 0700 and, as root inside a directory another uid
// owns, handed to that uid, exactly as MakeDirs documents.
func openDir(path string, create bool) (*sys.FD, error) {
	path = filepath.Clean(path)
	cur, rest := ".", path
	if filepath.IsAbs(path) {
		cur, rest = "/", path[1:]
	}
	d, err := sys.Own(unix.Open(cur, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: cur, Err: err}
	}
	for _, name := range strings.Split(rest, "/") {
		if name == "" || name == "." {
			continue
		}
		next := filepath.Join(cur, name)
		nd, err := stepDir(d, cur, name, next, create)
		_ = d.Close()
		if err != nil {
			return nil, err
		}
		d, cur = nd, next
	}
	return d, nil
}

// stepDir opens the directory name in the directory open at at (named dir; path is the two joined).
func stepDir(at *sys.FD, dir, name, path string, create bool) (*sys.FD, error) {
	nofollow, err := refuseLinksIn(at, dir)
	if err != nil {
		return nil, err
	}
	flags := unix.O_PATH | unix.O_DIRECTORY
	if nofollow {
		flags |= unix.O_NOFOLLOW
	}
	d, err := at.Openat(name, flags|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) && create {
		if _, err := makeDir(at, dir, name, path); err != nil {
			return nil, err
		}
		// What this walk just made is a directory, so a link under the name now was put there since:
		// it is not followed whoever owns dir.
		flags |= unix.O_NOFOLLOW
		d, err = at.Openat(name, flags|unix.O_CLOEXEC, 0)
	}
	if err != nil {
		if flags&unix.O_NOFOLLOW != 0 && isLink(at, name) {
			return nil, fmt.Errorf("%w: %s", ErrLinkRefused, path)
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var st unix.Stat_t
	if err := d.Fstat(&st); err != nil {
		_ = d.Close()
		return nil, &os.PathError{Op: "fstat", Path: path, Err: err}
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		return d, nil
	case unix.S_IFLNK: // O_PATH|O_NOFOLLOW can hand back the link itself rather than fail
		_ = d.Close()
		return nil, fmt.Errorf("%w: %s", ErrLinkRefused, path)
	}
	_ = d.Close()
	return nil, &os.PathError{Op: "open", Path: path, Err: unix.ENOTDIR}
}

// isLink reports whether name in the directory open at at is a symlink, without following it.
func isLink(at *sys.FD, name string) bool {
	var st unix.Stat_t
	if err := at.Fstatat(name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false
	}
	return st.Mode&unix.S_IFMT == unix.S_IFLNK
}

// makeDir creates name 0700 in the directory open at at and hands it over under the hand-over rule.
// EEXIST is not an error: a directory another process made in between keeps the owner it was given, and
// the caller's O_NOFOLLOW open decides whether it is used at all. created reports whether this call made it.
func makeDir(at *sys.FD, dir, name, path string) (created bool, err error) {
	if err := mkdirAt(at, name); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return false, nil
		}
		return false, &os.PathError{Op: "mkdir", Path: path, Err: err}
	}
	if _, ok, err := ownerOf(at, dir); err != nil || !ok {
		return true, err
	}
	d, err := at.Openat(name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return true, &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer func() { _ = d.Close() }()
	return true, giveCreated(at, dir, d, path)
}

// openRunDir opens the run directory at dir for a Writer, creating it 0700 when missing, and returns it as
// an O_RDONLY descriptor the Writer keeps until Close, with the owner Close hands the directory to (ok false
// when there is none: not root, or a ledger root root owns). With mustExist a missing run directory is
// os.ErrNotExist and nothing is created, the ledger root included. The ledger root is reached and, when missing,
// created as MakeDirs does; the run directory itself is never handed over at creation, since a live root
// run's directory stays root's until Close. As root, a run directory that is a symlink in a ledger root
// that is not root's alone is refused (ErrLinkRefused), as every component of the walk is.
func openRunDir(dir string, mustExist bool) (d *sys.FD, handTo owner, ok bool, err error) {
	dir = filepath.Clean(dir)
	parent, name := filepath.Dir(dir), filepath.Base(dir)
	if name == "/" || name == "." || name == ".." {
		return nil, owner{}, false, fmt.Errorf("ledger: run directory %q", dir)
	}
	pd, err := openDir(parent, !mustExist)
	if err != nil {
		return nil, owner{}, false, err
	}
	defer func() { _ = pd.Close() }()
	if handTo, ok, err = ownerOf(pd, parent); err != nil {
		return nil, owner{}, false, err
	}
	if mustExist {
		// no mkdirat: the Openat below reports a missing directory as ENOENT
	} else if err := mkdirAt(pd, name); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, owner{}, false, &os.PathError{Op: "mkdir", Path: dir, Err: err}
	}
	nofollow, err := refuseLinksIn(pd, parent)
	if err != nil {
		return nil, owner{}, false, err
	}
	flags := unix.O_RDONLY | unix.O_DIRECTORY
	if nofollow {
		flags |= unix.O_NOFOLLOW
	}
	d, err = sys.Strict(pd.Openat(name, flags|unix.O_CLOEXEC, 0))
	if err != nil {
		if nofollow && isLink(pd, name) {
			return nil, owner{}, false, fmt.Errorf("%w: %s", ErrLinkRefused, dir)
		}
		return nil, owner{}, false, &os.PathError{Op: "open", Path: dir, Err: err}
	}
	return d, handTo, ok, nil
}

// openFileAt opens the regular file name in the directory open at at (named dir) with flags, which
// must not include O_CREAT: with create, the file is made 0600 by an O_CREAT|O_EXCL open when it is
// missing, created reports that, and a file made inside a directory another uid owns is handed to that
// uid (giveCreated). The name is never followed as a symlink and a FIFO there never blocks the open; the
// file must be regular and have one link: an alias beneath a governed write entry
// could rewrite an ordinary user's records too (ADR 0059, SEC07).
func openFileAt(at *sys.FD, dir, name string, flags int, create bool) (f *os.File, created bool, err error) {
	path := filepath.Join(dir, name)
	flags |= unix.O_NOFOLLOW | unix.O_NONBLOCK
	var fd *sys.FD
	if create {
		fd, err = at.Openat(name, flags|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0o600)
		created = err == nil
		if err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, false, openError(at, name, path, err)
		}
	}
	if !created {
		if fd, err = at.Openat(name, flags|unix.O_CLOEXEC, 0); err != nil {
			return nil, false, openError(at, name, path, err)
		}
	}
	defer func() { _ = fd.Close() }() // a no-op once Release has handed the number to f
	var st unix.Stat_t
	if err := fd.Fstat(&st); err != nil {
		return nil, false, &os.PathError{Op: "fstat", Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return nil, false, fmt.Errorf("ledger: %s is not a regular file with one link", path)
	}
	if created {
		if err := giveCreated(at, dir, fd, path); err != nil {
			return nil, false, err
		}
	}
	if f, err = fd.Release(path); err != nil {
		return nil, false, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return f, created, nil
}

// openError is err from opening name in the directory open at at, as ErrLinkRefused when name is a
// symlink the O_NOFOLLOW open refused.
func openError(at *sys.FD, name, path string, err error) error {
	if errors.Is(err, unix.ELOOP) && isLink(at, name) {
		return fmt.Errorf("%w: %s", ErrLinkRefused, path)
	}
	return &os.PathError{Op: "open", Path: path, Err: err}
}

// createTempAt creates a new file prefix<random> 0600 in the directory open at at with O_EXCL and
// O_NOFOLLOW, so whatever is already under a name is never opened, and hands it over as openFileAt hands a
// created file. It returns the file and its name in that directory.
func createTempAt(at *sys.FD, dir, prefix string) (*os.File, string, error) {
	for range 10000 {
		name := prefix + strconv.FormatUint(uint64(rand.Uint32()), 10)
		fd, err := at.Openat(name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		path := filepath.Join(dir, name)
		if err != nil {
			return nil, "", &os.PathError{Op: "createtemp", Path: path, Err: err}
		}
		err = giveCreated(at, dir, fd, path)
		var f *os.File
		if err == nil {
			f, err = fd.Release(path)
		}
		if err != nil {
			_ = fd.Close()
			_ = unlinkAt(at, name)
			return nil, "", err
		}
		return f, name, nil
	}
	return nil, "", &os.PathError{Op: "createtemp", Path: filepath.Join(dir, prefix+"*"), Err: os.ErrExist}
}

// handOverDir hands the run directory open at d, and every entry in it, to o — but only a run
// directory this process owns. Root made that one 0700 and nobody else could add an entry to it, so
// everything in it is what root's writer created. A run directory another uid owns (a user's orphan that
// a root sweep ended) is theirs already, and a root-owned file in it is one the user could have renamed
// there: the Writer hands over each file it creates in such a directory as it creates it, and this walk
// touches nothing there. Entries are handed over before the directory that holds them, so the user owns
// nothing in the tree until root has finished walking it. Every failure is collected and the walk
// continues: one entry root could not hand over must not keep the rest from the user.
func handOverDir(d *sys.FD, path string, o owner) error {
	var st unix.Stat_t
	if err := d.Fstat(&st); err != nil {
		return &os.PathError{Op: "fstat", Path: path, Err: err}
	}
	if int(st.Uid) != os.Geteuid() {
		return nil
	}
	errs := giveTree(d, path, o, handOverDepth)
	if err := giveTo(d, path, o); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// giveTree hands every entry of the directory open at d to o, descending depth-1 more levels, deepest
// entries first.
func giveTree(d *sys.FD, path string, o owner, depth int) []error {
	names, err := readDirNames(d, path)
	if err != nil {
		return []error{fmt.Errorf("ledger: hand over %s: %w", path, err)}
	}
	var errs []error
	for _, name := range names {
		p := filepath.Join(path, name)
		// O_NONBLOCK so a FIFO planted in the tree cannot hang the open; O_NOFOLLOW so a symlink, which
		// the writer never creates, is neither followed nor handed over.
		fd, err := d.Openat(name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != nil {
			if !errors.Is(err, unix.ELOOP) && !errors.Is(err, unix.ENOENT) {
				errs = append(errs, &os.PathError{Op: "open", Path: p, Err: err})
			}
			continue
		}
		var st unix.Stat_t
		if err := fd.Fstat(&st); err == nil && st.Mode&unix.S_IFMT == unix.S_IFDIR && depth > 1 {
			errs = append(errs, giveTree(fd, p, o, depth-1)...)
		}
		if err := giveTo(fd, p, o); err != nil {
			errs = append(errs, err)
		}
		_ = fd.Close()
	}
	return errs
}
