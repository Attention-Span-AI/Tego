// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
)

// A root launcher makes its run's scope under the cgroup2 mount root, and a sweep finds a run's scope by the
// run's id, agent and the cgroup id its run_start recorded (orphanScope). All three are ledger data, and a
// ledger is its owner's to write: under `sudo tego run` or `sudo tego stop`, a sweep of a ledger root the
// invoking user can write looked under the mount root for any run directory there, so a planted run directory
// named after another user's root-launched run, its run_start naming that run's scope, had root write
// cgroup.kill into it (R20).
//
// The mount root is now searched for a run directory the sweeper does not own only when a record only root can
// write says root launched that very directory: a root launcher writes, right after MakeRunDir, a file named
// after the run id in rootMarkDir holding the run directory's device and inode. A planted directory is another
// inode; one the sweeper owns (root's own, not yet handed over) needs no record. The record lives in tmpfs, so
// a reboot, which takes every scope with it, takes it too; the launcher removes it with its scope, and a sweep
// that removed the scope removes it as well.

// markDir is a directory of root launch records. Every read, write and removal of a record goes through one,
// so a sweep or a stop can be pointed at a directory other than the host's (WithSweepRootMarks) without a
// package variable a test in another package would have to reach.
type markDir string

// rootMarkDir is where a root launcher records the runs it launched: a directory in hoststate.Path that root
// alone can write. A variable so tests can root it in a temporary tree.
var rootMarkDir = markDir(filepath.Join(hoststate.Path, "launched"))

// WithSweepRootMarks makes a sweep, or RunScope, read and remove root launch records in dir instead of the
// host's (hoststate.Path/launched). Records there are held to the same rule — the directory and each record
// owned by root and writable by nobody else — so it widens nothing: it lets a root test in another package
// stand a run up as a root launcher leaves it without writing into the real /run/tego.
func WithSweepRootMarks(dir string) SweepOption {
	return func(o *sweepOptions) { o.marks = markDir(dir) }
}

// rootMarkParent makes and verifies rootMarkDir's parent, the host state directory (hoststate.Open). A
// variable so tests can root rootMarkDir elsewhere.
var rootMarkParent = func() error {
	d, err := hoststate.Open()
	if err != nil {
		return err
	}
	return d.Close()
}

// rootMarkOwner is the uid a record, and its directory, must be owned by: root. A variable for the same tests.
var rootMarkOwner = 0

// sweeperUID is the effective uid of the process that sweeps. A variable so a test can sweep as if it were
// root.
var sweeperUID = os.Geteuid

// writeRootMark records that this process, root, launched the run in runDir. The directory is made 0700 in
// the verified host state directory; one that is not root's alone, or a name already taken, is an error and
// nothing is written.
func writeRootMark(runDir, id string) error { return rootMarkDir.write(runDir, id) }

// write is writeRootMark into d.
func (d markDir) write(runDir, id string) error {
	var st unix.Stat_t
	if err := unix.Lstat(runDir, &st); err != nil {
		return fmt.Errorf("runtime: root launch record: %w", &os.PathError{Op: "lstat", Path: runDir, Err: err})
	}
	if err := rootMarkParent(); err != nil {
		return fmt.Errorf("runtime: root launch record: %w", err)
	}
	if err := unix.Mkdir(string(d), 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("runtime: root launch record: %w", &os.PathError{Op: "mkdir", Path: string(d), Err: err})
	}
	dfd, err := d.open()
	if err != nil {
		return err
	}
	defer func() { _ = dfd.Close() }()
	fd, err := dfd.Openat(id, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("runtime: root launch record: %w", &os.PathError{Op: "create", Path: filepath.Join(string(d), id), Err: err})
	}
	f, werr := fd.Release(filepath.Join(string(d), id))
	if werr == nil {
		_, werr = fmt.Fprintf(f, "%d %d\n", st.Dev, st.Ino)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
	}
	if werr != nil {
		_ = fd.Close() // a Release that failed left the owner holding the number
		_ = dfd.Borrow(func(n int) error { return unix.Unlinkat(n, id, 0) })
		return fmt.Errorf("runtime: root launch record: %w", werr)
	}
	return nil
}

// launched reports whether a record root wrote in d says root launched the run in run: a regular file named
// after the run id in d, the file and the directory owned by root and writable by nobody else, whose
// device and inode are run's own (the lent directory's when a sweep hook was lent it).
func (d markDir) launched(run runDir) bool {
	dfd, err := d.open()
	if err != nil {
		return false
	}
	defer func() { _ = dfd.Close() }()
	fd, err := dfd.Openat(run.id(), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	var st unix.Stat_t
	if err := fd.Fstat(&st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || !rootOnly(st) {
		_ = fd.Close()
		return false
	}
	f, err := fd.Release(filepath.Join(string(d), run.id()))
	if err != nil {
		_ = fd.Close()
		return false
	}
	defer func() { _ = f.Close() }()
	b := make([]byte, 64)
	n, _ := f.Read(b)
	dev, ino, ok := strings.Cut(strings.TrimSpace(string(b[:n])), " ")
	if !ok {
		return false
	}
	dir, err := run.lstat()
	if err != nil || dir.Mode&unix.S_IFMT != unix.S_IFDIR {
		return false
	}
	return dev == strconv.FormatUint(dir.Dev, 10) && ino == strconv.FormatUint(dir.Ino, 10)
}

// removeRootMark removes run id's record from the host's records, if there is one.
func removeRootMark(id string) { rootMarkDir.remove(id) }

// remove removes run id's record from d, if there is one.
func (d markDir) remove(id string) {
	dfd, err := d.open()
	if err != nil {
		return
	}
	defer func() { _ = dfd.Close() }()
	_ = dfd.Borrow(func(n int) error { return unix.Unlinkat(n, id, 0) })
}

// open opens d O_PATH, not through a link, and only when it is a directory root alone can write.
func (d markDir) open() (*sys.FD, error) {
	dfd, err := sys.Own(unix.Open(string(d), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0))
	if err != nil {
		return nil, fmt.Errorf("runtime: root launch records: %w", &os.PathError{Op: "open", Path: string(d), Err: err})
	}
	var st unix.Stat_t
	if err := dfd.Fstat(&st); err != nil || !rootOnly(st) {
		_ = dfd.Close()
		return nil, fmt.Errorf("runtime: root launch records: %s is not root's alone", string(d))
	}
	return dfd, nil
}

// rootOnly reports whether st is owned by rootMarkOwner and writable by no group or other.
func rootOnly(st unix.Stat_t) bool {
	return int(st.Uid) == rootMarkOwner && st.Mode&0o022 == 0
}
