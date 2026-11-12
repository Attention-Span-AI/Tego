// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// The overlay's files in the run directory.
const (
	// FileName is the overlay: <ledger_root>/<run>/live-block.json.
	FileName = "live-block.json"
	// LockName is the writers' lock, flocked for each read-modify-write so two writers (the CLI and the
	// dashboard) never lose each other's change.
	LockName = "live-block.lock"
	// ControlName is the launcher's mark that it reads a pause and a resume (OpPause, OpResume): an empty file it
	// makes once its live-block poll runs over a run cgroup it can freeze (MarkControl). A writer asks a pause only of
	// a run whose directory has it (TakesControl). A launcher from before the pause refuses the whole overlay once
	// it lists one, so a pause written to it would never take and every later live block of the run would stay
	// waiting; an adopted run, or one with no cgroup of its own, has no poll or nothing to freeze. None of them
	// makes the mark. It is a mark of capability, not of authority: a same-uid process could make it, as it could
	// write the overlay itself (ADR 0123).
	ControlName = "live-control"
	// RealName is the launcher's mark that it reads a block's real path (Entry.Real, VersionReal): an empty file it
	// makes once its live-block poll runs (MarkReal). A writer stores a real path only for a run whose directory has
	// it (TakesReal). A launcher from before the real path refuses the whole overlay once it is VersionReal, keeps the
	// blocks it last read and ignores every later change, so a real path written to it would undo every later block.
	// Like ControlName it is a mark of capability, not of authority.
	RealName = "live-real"
	// LinkName is the launcher's mark that it reads a block that matches by link (Entry.Match, VersionLink): an empty
	// file it makes once its live-block poll runs (MarkLink). A writer places such a block only on a run whose
	// directory has it (TakesLink), and the whole-file block otherwise: a launcher from before it refuses the whole
	// overlay once it is VersionLink, keeps the blocks it last read and ignores every later change. Like ControlName it
	// is a mark of capability, not of authority.
	LinkName = "live-link"
)

// lockWait bounds how long a writer waits for another writer's lock.
const lockWait = 3 * time.Second

// ErrUntrusted is an overlay file the launcher does not read: not a regular file, not owned by the launcher's user
// (or root), or writable by its group or others.
var ErrUntrusted = errors.New("liveblock: overlay file not trusted")

// Signature is what a poll compares to tell that the overlay changed: the writer replaces the file by a rename, so
// every write is a new inode. The zero value is no file.
type Signature struct {
	Dev, Ino        uint64
	Size            int64
	MtimeNS, CtNS   int64
	Exists, Errored bool
}

// Stat is the overlay's signature in dir, without opening it. A file that is not there is the zero Signature; one
// that cannot be stat'ed for another reason is Errored.
func Stat(dir string) Signature {
	var st unix.Stat_t
	if err := unix.Lstat(filepath.Join(dir, FileName), &st); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return Signature{}
		}
		return Signature{Errored: true}
	}
	return Signature{Dev: st.Dev, Ino: st.Ino, Size: st.Size, MtimeNS: st.Mtim.Nano(), CtNS: st.Ctim.Nano(), Exists: true}
}

// MarkControl makes dir's ControlName, the launcher's mark that it reads a pause (0600, no symlink followed); one
// already there is kept.
func MarkControl(dir string) error { return mark(dir, ControlName) }

// mark makes dir's name, an empty mark file (0600, no symlink followed); one already there is kept.
func mark(dir, name string) error {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

// TakesControl reports whether the launcher of the run in dir reads a pause: dir holds ControlName as a regular
// file (no symlink followed) owned by this process's effective user or root, as MarkControl makes it.
func TakesControl(dir string) bool { return marked(dir, ControlName) }

// marked reports whether dir holds name as a regular file (no symlink followed) owned by this process's effective
// user or root, as mark makes it.
func marked(dir, name string) bool {
	var st unix.Stat_t
	if err := unix.Lstat(filepath.Join(dir, name), &st); err != nil {
		return false
	}
	return st.Mode&unix.S_IFMT == unix.S_IFREG && (st.Uid == uint32(os.Geteuid()) || st.Uid == 0)
}

// MarkReal makes dir's RealName, the launcher's mark that it reads a block's real path (0600, no symlink followed);
// one already there is kept.
func MarkReal(dir string) error { return mark(dir, RealName) }

// TakesReal reports whether the launcher of the run in dir reads a block's real path: dir holds RealName as MarkReal
// makes it (as TakesControl checks ControlName).
func TakesReal(dir string) bool { return marked(dir, RealName) }

// MarkLink makes dir's LinkName, the launcher's mark that it reads a block that matches by link (0600, no symlink
// followed); one already there is kept.
func MarkLink(dir string) error { return mark(dir, LinkName) }

// TakesLink reports whether the launcher of the run in dir reads a block that matches by link: dir holds LinkName as
// MarkLink makes it (as TakesControl checks ControlName).
func TakesLink(dir string) bool { return marked(dir, LinkName) }

// Read is the overlay in dir, decoded and validated against run. A file that is not there is os.ErrNotExist (no live
// blocks). A file is read only when it is a regular file, reached with no symlink followed, owned by this process's
// effective user or root, and not writable by group or others (ErrUntrusted).
func Read(dir, run string) (*Overlay, error) {
	f, err := os.OpenFile(filepath.Join(dir, FileName), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%w: %s is a symlink", ErrUntrusted, FileName)
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := sys.FstatFile(f, &st); err != nil {
		return nil, err
	}
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFREG:
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrUntrusted, FileName)
	case st.Uid != uint32(os.Geteuid()) && st.Uid != 0:
		return nil, fmt.Errorf("%w: %s is owned by uid %d", ErrUntrusted, FileName, st.Uid)
	case st.Mode&0o022 != 0:
		return nil, fmt.Errorf("%w: %s is writable by its group or others", ErrUntrusted, FileName)
	case st.Size > MaxFileBytes:
		return nil, fmt.Errorf("%w: overlay of %d bytes, more than %d", ErrInvalid, st.Size, MaxFileBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	return Decode(b, run)
}

// Update is the one read-modify-write of the overlay in dir: under the writers' lock it reads the overlay (a new one
// when there is none), hands it to fn, and, when fn reports a change, writes it by an atomic rename (a temporary file
// in dir, fsync'ed, renamed over FileName, the directory fsync'ed). An overlay that is there but unreadable is an
// error, never replaced: the launcher keeps the last good one in force, and a new file written over it would drop
// those blocks. It returns the overlay as it now stands.
func Update(ctx context.Context, dir, run string, fn func(*Overlay) (bool, error)) (*Overlay, error) {
	unlock, err := lock(ctx, dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	o, err := Read(dir, run)
	switch {
	case errors.Is(err, os.ErrNotExist):
		o = New(run)
	case err != nil:
		return nil, fmt.Errorf("the run's %s cannot be read, so it is not replaced (remove it to start over): %w", FileName, err)
	}
	o.dropEnded(readClock().Wall)
	changed, err := fn(o)
	if err != nil || !changed {
		return o, err
	}
	b, err := o.Encode()
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(dir, b); err != nil {
		return nil, err
	}
	return o, nil
}

// endedKeep is how long past its until by the wall clock a block stays in the file. The launcher wrote its expiry line
// when it ended, but it judges a block's end on BOOTTIME too (Ended): a wall clock stepped forward must not let a
// writer drop a block the launcher still holds in force.
const endedKeep = 24 * time.Hour

// dropEnded removes the blocks whose until is more than endedKeep before now, recording no change: their lines were
// written by the launcher when they ended, and dropping them keeps them from filling MaxBlocks over a long run.
func (o *Overlay) dropEnded(now time.Time) {
	o.Blocks = slices.DeleteFunc(o.Blocks, func(e Entry) bool { return !e.Until.IsZero() && now.Sub(e.Until) > endedKeep })
}

// lock flocks dir's LockName, waiting at most lockWait, and returns its release.
func lock(ctx context.Context, dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, LockName), os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("live-block lock: %w", err)
	}
	deadline := time.Now().Add(lockWait)
	for {
		err := sys.Flock(f, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() { _ = f.Close() }, nil // closing the file drops the flock
		}
		if !errors.Is(err, unix.EWOULDBLOCK) || time.Now().After(deadline) || ctx.Err() != nil {
			_ = f.Close()
			if errors.Is(err, unix.EWOULDBLOCK) {
				err = errors.New("another writer holds it")
			}
			return nil, fmt.Errorf("live-block lock: %w", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// writeAtomic replaces dir's FileName with b: a new 0600 file, synced, renamed over it, and the directory synced.
func writeAtomic(dir string, b []byte) error {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+FileName+"."+hex.EncodeToString(rnd[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(b)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp, filepath.Join(dir, FileName))
	}
	if werr != nil {
		_ = os.Remove(tmp)
		return werr
	}
	d, err := os.Open(dir)
	if err != nil {
		return nil // the rename is done; only its durability across a crash is not proved
	}
	_ = d.Sync()
	return d.Close()
}

// By is the by of a change this process makes, via "cli" or "dashboard": "uid:<uid> pid:<pid> <via>", the form
// an answer line's by has.
func By(via string) string {
	return fmt.Sprintf("uid:%d pid:%d %s", os.Getuid(), os.Getpid(), via)
}
