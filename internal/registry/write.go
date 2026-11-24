// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// DirectoryIdentity identifies the exact directory a person reviewed.
type DirectoryIdentity struct{ Device, Inode uint64 }

// FileIdentity identifies an existing contract and the exact bytes read from it.
type FileIdentity struct {
	Device, Inode uint64
	SHA256        string
}

// Directory is a pinned directory reached without following any symbolic link.
// The caller keeps it open until all writes and identity checks finish.
type Directory struct{ fd *sys.FD }

// OpenDirectory opens every component beneath the previous descriptor with O_NOFOLLOW.
// With create set, missing components are made with mode 0700 and owned by the effective user.
func OpenDirectory(path string, create bool) (*Directory, error) {
	return OpenDirectoryContext(context.Background(), path, create)
}

// Walking a directory needs search permission on its ancestors, never read: they are opened O_PATH, which the
// kernel grants on search alone, as a whole-path open does. Only the destination, whose entries are listed and
// which is synced, is opened for reading.
const (
	ancestorFlags    = unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	destinationFlags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
)

// syncDirectory syncs the directory fd names. An O_PATH descriptor cannot be synced, so "." is opened beneath it
// for reading: the same inode, which needs read permission on it only when a component was made in it.
func syncDirectory(fd *sys.FD) error {
	d, err := fd.Openat(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }() // Read-only; the sync's result is reported.
	return d.Fsync()
}

// OpenDirectoryContext refuses new path mutations after cancellation.
// A syscall already submitted can still have an uncertain outcome.
func OpenDirectoryContext(ctx context.Context, path string, create bool) (*Directory, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("open-directory %s: absolute canonical path required", path)
	}
	var parts []string
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part != "" {
			parts = append(parts, part)
		}
	}
	// "/" is the destination itself only when the path is "/".
	var fd *sys.FD
	var err error
	if len(parts) == 0 {
		fd, err = sys.Own(unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	} else {
		fd, err = sys.Own(unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	}
	if err != nil {
		return nil, fmt.Errorf("open-directory /: %w", err)
	}
	for i, part := range parts {
		flags := ancestorFlags
		if i == len(parts)-1 {
			flags = destinationFlags
		}
		if err := ctx.Err(); err != nil {
			_ = fd.Close()
			return nil, err
		}
		next, openErr := fd.Openat(part, flags, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			if err := ctx.Err(); err != nil {
				_ = fd.Close()
				return nil, err
			}
			if err = fd.Borrow(func(n int) error { return unix.Mkdirat(n, part, 0700) }); err != nil && !errors.Is(err, unix.EEXIST) {
				_ = fd.Close() // The mkdir failure is the error to report.
				return nil, fmt.Errorf("mkdir %s: %w", part, err)
			}
			if err = syncDirectory(fd); err != nil {
				_ = fd.Close() // The sync failure is the error to report.
				return nil, fmt.Errorf("mkdir-directory-sync %s: %w", part, err)
			}
			next, openErr = fd.Openat(part, flags, 0)
		}
		_ = fd.Close() // The next descriptor owns the remaining walk; no write is buffered here.
		if openErr != nil {
			return nil, fmt.Errorf("open-directory %s: %w", part, openErr)
		}
		fd = next
	}
	return &Directory{fd: fd}, nil
}

// Close releases the directory descriptor.
func (d *Directory) Close() error { return d.fd.Close() }

// Dup returns another owned descriptor for this same pinned directory.
func (d *Directory) Dup() (*sys.FD, error) { return d.fd.Dup() }

// Identity reads the device and inode of the pinned descriptor.
func (d *Directory) Identity() (DirectoryIdentity, error) {
	return directoryIdentity(d.fd)
}

func directoryIdentity(fd *sys.FD) (DirectoryIdentity, error) {
	var st unix.Stat_t
	if err := fd.Fstat(&st); err != nil {
		return DirectoryIdentity{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return DirectoryIdentity{}, errors.New("descriptor is not a directory")
	}
	return DirectoryIdentity{Device: uint64(st.Dev), Inode: st.Ino}, nil
}

// WriteOptions describes a single atomic publication. A nil Expected creates only
// when the final name is absent. A non-nil Expected replaces only that inode and digest.
type WriteOptions struct {
	// Context cancels work before a new mutation, including after blocking reads.
	// Nil preserves the synchronous caller's existing behavior.
	Context context.Context
	// Mode is the published file's permission bits; special mode bits are not retained.
	Mode os.FileMode
	// ExpectedDirectory, when supplied, must identify the same descriptor used for creation.
	ExpectedDirectory *DirectoryIdentity
	// Expected permits replacement of only the old inode and bytes it identifies.
	Expected *FileIdentity
	// BeforePublish runs after the temporary file is synced, before the final recheck.
	// It lets an owning service repeat its stronger guards before publication.
	BeforePublish func() error
}

// ErrFileChanged means the file or directory differs from the reviewed identity.
var ErrFileChanged = errors.New("the reviewed file or directory changed")

// writeStep allows deterministic failures at publication boundaries in package tests.
var writeStep func(string) error

func publicationStep(step string) error {
	if writeStep != nil {
		return writeStep(step)
	}
	return nil
}

// Write publishes text beneath this same pinned descriptor.
func (d *Directory) Write(name string, text []byte, o WriteOptions) error {
	return WriteFileAt(d.fd, name, text, o)
}

// WriteFileAt writes and syncs a temporary file beneath fd, then publishes it atomically
// and syncs fd. The caller owns fd and must keep it open for this entire call.
// On failure the temporary name is removed. Errors name the failing step; a directory-sync
// error after publication explicitly says that the complete final file was published.
func WriteFileAt(fd *sys.FD, name string, text []byte, o WriteOptions) (err error) {
	ctx := o.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
		return errors.New("validate-name: a direct child filename is required")
	}
	id, err := directoryIdentity(fd)
	if err != nil {
		return fmt.Errorf("directory-stat: %w", err)
	}
	if o.ExpectedDirectory != nil && id != *o.ExpectedDirectory {
		return fmt.Errorf("directory-identity: %w", ErrFileChanged)
	}
	var rnd [16]byte
	if _, err = rand.Read(rnd[:]); err != nil {
		return fmt.Errorf("temporary-name: %w", err)
	}
	tmp := "." + name + ".tego-write-" + hex.EncodeToString(rnd[:])
	if err := ctx.Err(); err != nil {
		return err
	}
	temporary, err := fd.Openat(tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return fmt.Errorf("temporary-create: %w", err)
	}
	defer func() {
		if cleanup := fd.Borrow(func(n int) error { return unix.Unlinkat(n, tmp, 0) }); cleanup != nil && !errors.Is(cleanup, unix.ENOENT) {
			err = errors.Join(err, fmt.Errorf("temporary-remove: %w", cleanup))
		}
	}()
	var temporaryStat unix.Stat_t
	if err = temporary.Fstat(&temporaryStat); err != nil {
		_ = temporary.Close() // The stat failure is the error to report.
		return fmt.Errorf("temporary-stat: %w", err)
	}
	sum := sha256.Sum256(text)
	temporaryIdentity := FileIdentity{Device: uint64(temporaryStat.Dev), Inode: temporaryStat.Ino, SHA256: hex.EncodeToString(sum[:])}
	f, err := temporary.Release(tmp)
	if err != nil {
		_ = temporary.Close() // Release failed; this owner still holds the descriptor.
		return fmt.Errorf("temporary-file: %w", err)
	}
	fail := func(step string, e error) error {
		if e != nil {
			return fmt.Errorf("%s: %w", step, e)
		}
		return nil
	}
	if err = ctx.Err(); err == nil {
		_, err = f.Write(text)
	}
	if err != nil {
		_ = f.Close()
		return fail("temporary-write", err)
	}
	if err = f.Chmod(o.Mode.Perm()); err != nil {
		_ = f.Close()
		return fail("temporary-mode", err)
	}
	if err = publicationStep("file-sync"); err == nil {
		err = f.Sync()
	}
	if err != nil {
		_ = f.Close()
		return fail("file-sync", err)
	}
	if err = f.Close(); err != nil {
		return fail("temporary-close", err)
	}
	if o.BeforePublish != nil {
		if err = o.BeforePublish(); err != nil {
			return fail("before-publish", err)
		}
	}
	if err = publicationStep("publish"); err != nil {
		return fail("publish", err)
	}
	// A caller's review callback can perform blocking I/O. Refuse a temporary
	// name replaced or edited during that interval. The final path syscalls
	// still require a trusted directory; this is not an atomic inode CAS.
	gotTemporary, err := ReadIdentityAt(fd, tmp)
	if err != nil {
		return fail("temporary-recheck", err)
	}
	if gotTemporary != temporaryIdentity {
		return fail("temporary-recheck", ErrFileChanged)
	}
	published := false
	if o.Expected != nil {
		var got FileIdentity
		got, err = ReadIdentityAt(fd, name)
		if err != nil {
			return fail("file-recheck", err)
		}
		if got != *o.Expected {
			return fail("file-recheck", ErrFileChanged)
		}
		if err = ctx.Err(); err != nil {
			return fail("publish", err)
		}
		err = fd.Borrow(func(n int) error { return unix.Renameat(n, tmp, n, name) })
		published = err == nil
	} else {
		published, err = noReplace(ctx, fd, tmp, name)
	}
	if err != nil && !published {
		return fail("publish", err)
	}
	publicationErr := fail("publish", err)
	if err = publicationStep("directory-sync"); err == nil {
		err = fd.Fsync()
	}
	if err != nil {
		err = fmt.Errorf("directory-sync: complete %s was published: %w", name, err)
	}
	return errors.Join(publicationErr, err)
}

// ReadIdentityAt reads an existing regular file without following a link, through
// the descriptor whose identity is returned. Reads are bounded by MaxContractSize.
func ReadIdentityAt(fd *sys.FD, name string) (FileIdentity, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
		return FileIdentity{}, errors.New("validate-name: a direct child filename is required")
	}
	opened, err := fd.Openat(name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return FileIdentity{}, err
	}
	defer func() { _ = opened.Close() }() // Read-only, or released to the file below.
	var st unix.Stat_t
	if err = opened.Fstat(&st); err != nil {
		return FileIdentity{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return FileIdentity{}, errors.New("not a regular file with one name")
	}
	if st.Size > agent.MaxContractSize {
		return FileIdentity{}, errors.New("file exceeds maximum contract size")
	}
	f, err := opened.Release(name)
	if err != nil {
		return FileIdentity{}, err
	}
	defer func() { _ = f.Close() }() // Read-only.
	b, err := config.ReadRulesFile(context.Background(), f, name, agent.MaxContractSize+1)
	if err != nil {
		return FileIdentity{}, err
	}
	if len(b) > agent.MaxContractSize {
		return FileIdentity{}, errors.New("file exceeds maximum contract size")
	}
	sum := sha256.Sum256(b)
	return FileIdentity{Device: uint64(st.Dev), Inode: st.Ino, SHA256: hex.EncodeToString(sum[:])}, nil
}

// The fallback can publish before removing the temporary name. Keep that state
// explicit so even a cleanup failure is reported honestly and the directory synced.
func noReplace(ctx context.Context, fd *sys.FD, from, to string) (published bool, err error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	err = fd.Borrow(func(n int) error {
		err := unix.Renameat2(n, from, n, to, unix.RENAME_NOREPLACE)
		if !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.EOPNOTSUPP) {
			published = err == nil
			return err
		}
		// An unsupported rename can return after the request expired.
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := unix.Linkat(n, from, n, to, 0); err != nil {
			return err
		}
		published = true
		if err := unix.Unlinkat(n, from, 0); err != nil {
			return fmt.Errorf("temporary-remove: complete %s was published: %w", to, err)
		}
		return nil
	})
	return published, err
}
