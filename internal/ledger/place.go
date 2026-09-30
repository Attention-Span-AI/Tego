// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// placeNewFileAt places a new file name holding b in the directory dir, held as dfd, which the caller reached
// by the §3 walk (openDir): as root, a symlink in a directory that is not root's alone ends that walk with
// ErrLinkRefused instead of taking it anywhere. The bytes go to a temporary file made in that directory
// O_CREAT|O_EXCL|O_NOFOLLOW, handed over as any file root creates in another uid's directory (createTempAt), and
// the file is linked into place by linkat(2), which never replaces what is under name: a name already there is
// os.ErrExist, whatever it is, and nothing is followed or written through. A filesystem with no hard links gets
// renameat2(RENAME_NOREPLACE), with the same answer. The temporary name is removed on every path. placed, when
// not nil, receives the new inode's identity before the temporary name is removed.
//
// internal/runtime places `tego stop`'s stop marker this way: a root stop writes into the run directory of a
// user's ledger root, and creating the marker by path followed whatever that user had put there by then.
func placeNewFileAt(dfd *sys.FD, dir, name string, b []byte, placed *unix.Stat_t) error {
	path := filepath.Join(dir, name)
	var st unix.Stat_t
	if err := dfd.Fstatat(name, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		return &os.PathError{Op: "place", Path: path, Err: os.ErrExist}
	}
	f, tmp, err := createTempAt(dfd, dir, "."+name+".")
	if err != nil {
		return fmt.Errorf("ledger: place %s: %w", path, err)
	}
	defer func() { _ = unlinkAt(dfd, tmp) }()
	_, werr := f.Write(b)
	if werr == nil && placed != nil {
		werr = sys.FstatFile(f, placed)
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return fmt.Errorf("ledger: place %s: %w", path, werr)
	}
	err = dfd.Borrow(func(n int) error {
		err := unix.Linkat(n, tmp, n, name, 0)
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EOPNOTSUPP) {
			err = unix.Renameat2(n, tmp, n, name, unix.RENAME_NOREPLACE)
		}
		return err
	})
	if errors.Is(err, unix.EEXIST) {
		return &os.PathError{Op: "place", Path: path, Err: os.ErrExist}
	}
	if err != nil {
		return &os.PathError{Op: "place", Path: path, Err: err}
	}
	return nil
}

// placeLockWait bounds a marker publisher waiting for a concurrent delivery.
const placeLockWait = 2 * time.Second

// PlaceNewFileThen serializes publication and after under a persistent per-name
// flock in the guarded directory. after sees a fully published file, or true
// when a previous publisher already placed the name. An after error rolls back
// only this call's newly published inode; a pre-existing name is always kept.
// Every cooperating publisher must use this function for the same marker. The
// private lock is never unlinked: replacing it would split the serialization.
// Lock acquisition observes ctx and is also bounded by placeLockWait.
func PlaceNewFileThen(ctx context.Context, dir, name string, b []byte, after func(bool) error) error {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return fmt.Errorf("ledger: place %q in %s: not a file name", name, dir)
	}
	ctx, cancel := context.WithTimeout(ctx, placeLockWait)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	dfd, err := openDir(dir, false)
	if err != nil {
		return fmt.Errorf("ledger: place %s: %w", filepath.Join(dir, name), err)
	}
	defer func() { _ = dfd.Close() }()
	lockName := "." + name + ".lock"
	lock, _, err := openFileAt(dfd, dir, lockName, unix.O_RDONLY, true)
	if err != nil {
		return fmt.Errorf("ledger: publication lock: %w", err)
	}
	defer func() { _ = lock.Close() }()
	var dst, lst unix.Stat_t
	if err := dfd.Fstat(&dst); err != nil {
		return err
	}
	if err := sys.FstatFile(lock, &lst); err != nil {
		return err
	}
	if lst.Mode&unix.S_IFMT != unix.S_IFREG || lst.Mode&0o777 != 0o600 || lst.Nlink != 1 || lst.Uid != dst.Uid {
		return fmt.Errorf("ledger: publication lock %s has unsafe type, owner, mode or links", lock.Name())
	}
	if err := acquirePlaceLock(ctx, lock); err != nil {
		return fmt.Errorf("ledger: publication lock: %w", err)
	}
	defer func() { _ = sys.Flock(lock, unix.LOCK_UN) }()
	var named unix.Stat_t
	if err := dfd.Fstatat(lockName, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if named.Dev != lst.Dev || named.Ino != lst.Ino || named.Mode != lst.Mode || named.Uid != lst.Uid || named.Nlink != 1 {
		return fmt.Errorf("ledger: publication lock %s changed while acquiring it", lock.Name())
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	var placed unix.Stat_t
	err = placeNewFileAt(dfd, dir, name, b, &placed)
	exists := errors.Is(err, os.ErrExist)
	if err != nil && !exists {
		return err
	}
	if after == nil {
		return err
	}
	err = ctx.Err()
	if err == nil {
		err = after(exists)
	}
	if err != nil && !exists {
		return errors.Join(err, rollbackPlacedFile(dfd, dir, name, placed))
	}
	return err
}

func acquirePlaceLock(ctx context.Context, lock *os.File) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := sys.Flock(lock, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			return err
		}
		timer := time.NewTimer(time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func rollbackPlacedFile(dfd *sys.FD, dir, name string, placed unix.Stat_t) error {
	var current unix.Stat_t
	err := dfd.Fstatat(name, &current, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ledger: rollback %s: %w", filepath.Join(dir, name), err)
	}
	if current.Dev != placed.Dev || current.Ino != placed.Ino || current.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("ledger: rollback %s: published inode was replaced", filepath.Join(dir, name))
	}
	if err := unlinkAt(dfd, name); err != nil && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("ledger: rollback %s: %w", filepath.Join(dir, name), err)
	}
	return nil
}
