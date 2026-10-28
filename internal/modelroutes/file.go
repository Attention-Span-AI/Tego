// SPDX-License-Identifier: Apache-2.0

package modelroutes

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// The files in the run directory.
const (
	// FileName is the overlay: <ledger_root>/<run>/model-routes.json.
	FileName = "model-routes.json"
	// LockName is the writers' lock, flocked for each read-modify-write so the CLI and the dashboard never lose
	// each other's change.
	LockName = "model-routes.lock"
)

// lockWait bounds how long a writer waits for another writer's lock.
const lockWait = 3 * time.Second

// ErrUntrusted is a file the forwarder does not read: not a regular file, reached through a symlink, not owned by this
// process's user (or root), or writable by its group or others.
var ErrUntrusted = errors.New("modelroutes: file not trusted")

// Signature is what a poll compares to tell that the overlay changed: a writer replaces the file by a rename, so
// every write is a new inode. The zero value is no file.
type Signature struct {
	Dev, Ino      uint64
	Size          int64
	MtimeNS, CtNS int64
	Exists        bool
	Errored       bool
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

// Read is the overlay in dir, decoded and validated against run. A file that is not there is os.ErrNotExist (no live
// routes: every endpoint on its own).
func Read(dir, run string) (*Overlay, error) {
	b, err := readTrusted(filepath.Join(dir, FileName), MaxFileBytes)
	if err != nil {
		return nil, err
	}
	return Decode(b, run)
}

// Update is the one read-modify-write of the overlay in dir: under the writers' lock it reads the overlay (a new one
// when there is none), hands it to fn, and, when fn reports a change, writes it by an atomic rename. An overlay that
// is there but unreadable is an error, never replaced: the forwarder keeps the last good one in force. It returns the
// overlay as it now stands.
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
	changed, err := fn(o)
	if err != nil || !changed {
		return o, err
	}
	b, err := o.Encode()
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(dir, FileName, b, 0o600); err != nil {
		return nil, err
	}
	return o, nil
}

// SHA256Base is the overlay file's bytes as a preview binds them: the raw bytes, or nil when there is no file.
// A caller hashes them; an unreadable file is an error.
func SHA256Base(dir string) ([]byte, error) {
	b, err := readTrusted(filepath.Join(dir, FileName), MaxFileBytes)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// readTrusted reads name when it is a regular file reached with no symlink followed, owned by this process's
// effective user or root, not writable by group or others, and at most limit bytes.
func readTrusted(name string, limit int64) ([]byte, error) {
	f, err := os.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("%w: %s is a symlink", ErrUntrusted, filepath.Base(name))
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
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrUntrusted, filepath.Base(name))
	case st.Uid != uint32(os.Geteuid()) && st.Uid != 0:
		return nil, fmt.Errorf("%w: %s is owned by uid %d", ErrUntrusted, filepath.Base(name), st.Uid)
	case st.Mode&0o022 != 0:
		return nil, fmt.Errorf("%w: %s is writable by its group or others", ErrUntrusted, filepath.Base(name))
	case st.Size > limit:
		return nil, fmt.Errorf("%w: %s of %d bytes, more than %d", ErrInvalid, filepath.Base(name), st.Size, limit)
	}
	return io.ReadAll(io.LimitReader(f, limit+1))
}

// lock flocks dir's LockName, waiting at most lockWait, and returns its release.
func lock(ctx context.Context, dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, LockName), os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("model-routes.lock: %w", err)
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
			return nil, fmt.Errorf("model-routes.lock: %w", err)
		}
		select {
		case <-ctx.Done():
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// writeAtomic replaces dir's name with b: a new file of mode perm, synced, renamed over it, and the directory synced.
func writeAtomic(dir, name string, b []byte, perm os.FileMode) error {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+name+"."+hex.EncodeToString(rnd[:]))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, perm)
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
		werr = os.Rename(tmp, filepath.Join(dir, name))
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

// By is the by of a change this process makes, via "cli" or "dashboard": "uid:<uid> pid:<pid> <via>", the form an
// answer line's by has (internal/liveblock.By's form).
func By(via string) string {
	return fmt.Sprintf("uid:%d pid:%d %s", os.Getuid(), os.Getpid(), via)
}
