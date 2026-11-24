// SPDX-License-Identifier: Apache-2.0

package result

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"golang.org/x/sys/unix"
)

// ErrMode asks the caller to show the fixed chmod 700 repair, without repairing
// an existing path or printing filesystem error text that may contain input.
var ErrMode = errors.New("scan directory must have mode 0700")

// ErrUnsafe rejects an unsafe file without opening its contents.
var ErrUnsafe = errors.New("unsafe saved scan")

// ErrSize rejects oversized state before decoding.
var ErrSize = errors.New("saved scan too large")

// ErrChanged rejects state replaced or modified during a read.
var ErrChanged = errors.New("saved scan changed during read")

// ErrSync means rename succeeded but directory durability is unknown.
var ErrSync = errors.New("saved scan replacement durability unknown")

// ReadResult separates historical, untrusted evidence from display freshness.
type ReadResult struct {
	Snapshot  Snapshot
	Freshness string
	// Identity is derived from the checked inode, never from saved JSON.
	Identity string
}

func scanDir(home string, uid uint32, create bool) (*sys.FD, error) {
	if !filepath.IsAbs(home) {
		return nil, ErrUnsafe
	}
	base := filepath.Join(home, ".tego")
	if create {
		if err := os.Mkdir(base, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	// Deliberately resolve home/.tego links, as guide.openState does; pin once.
	tfd, err := sys.Own(unix.Open(base, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		return nil, err
	}
	defer func() { _ = tfd.Close() }()
	var st unix.Stat_t
	if err = tfd.Fstat(&st); err != nil {
		return nil, err
	}
	if st.Uid != uid || st.Mode&0022 != 0 {
		return nil, ErrUnsafe
	}
	if create {
		err = tfd.Borrow(func(n int) error { return unix.Mkdirat(n, "scan", 0700) })
		if err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, err
		}
	}
	d, err := tfd.Openat("scan", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err = d.Fstat(&st); err != nil {
		_ = d.Close()
		return nil, err
	}
	if err = checkedDirectory(st, uid); err != nil {
		_ = d.Close()
		return nil, err
	}
	return d, nil
}

// Encode validates producer output with the same strict reader used for disk.
func Encode(s Snapshot) ([]byte, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, ErrInvalid
	}
	b = append(b, '\n')
	if len(b) > MaxBytes {
		return nil, ErrSize
	}
	if _, err = Decode(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Save replaces only a valid, nonfailed result. It never follows last.json,
// and removes only the exclusive temporary entry this invocation created.
func Save(home string, uid uint32, s Snapshot) error {
	if s.Status == "failed" || s.As.Recipient != uid {
		return ErrInvalid
	}
	b, err := Encode(s)
	if err != nil {
		return err
	}
	d, err := scanDir(home, uid, true)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	old, err := d.Openat("last.json", unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == nil {
		var st unix.Stat_t
		e := old.Fstat(&st)
		_ = old.Close()
		if e != nil {
			return e
		}
		if st.Mode&unix.S_IFMT == unix.S_IFDIR || st.Uid != uid {
			return ErrUnsafe
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	name := ".last-" + hex.EncodeToString(nonce[:]) + ".tmp"
	fd, err := d.Openat(name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = d.Borrow(func(n int) error { return unix.Unlinkat(n, name, 0) }) }()
	if err = fd.Borrow(func(n int) error { return unix.Fchmod(n, 0600) }); err != nil {
		_ = fd.Close()
		return err
	}
	var st unix.Stat_t
	if err = fd.Fstat(&st); err != nil {
		_ = fd.Close()
		return err
	}
	if err = checkedFile(st, uid); err != nil {
		_ = fd.Close()
		return err
	}
	f, err := fd.Release("scan-result-temp")
	if err != nil {
		_ = fd.Close()
		return err
	}
	_, err = io.Copy(f, bytes.NewReader(b))
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	err = d.Borrow(func(n int) error { return unix.Renameat(n, name, n, "last.json") })
	if err != nil {
		return err
	}
	if err = d.Fsync(); err != nil {
		return ErrSync
	}
	return nil
}

func checkedFile(st unix.Stat_t, uid uint32) error {
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || st.Uid != uid || st.Mode&07777 != 0600 {
		return ErrUnsafe
	}
	if st.Size < 0 || st.Size > MaxBytes {
		return ErrSize
	}
	return nil
}
func unchanged(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Mode == b.Mode && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

// Read pins and type-checks before any data open, then checks the opened inode
// and final path identity. A link, FIFO, socket or device is never data-opened.
func Read(home string, uid uint32, boot string, now time.Time) (ReadResult, error) {
	d, err := scanDir(home, uid, false)
	if err != nil {
		return ReadResult{}, err
	}
	defer func() { _ = d.Close() }()
	pin, err := d.Openat("last.json", unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ReadResult{}, err
	}
	defer func() { _ = pin.Close() }()
	var before unix.Stat_t
	if err = pin.Fstat(&before); err != nil {
		return ReadResult{}, err
	}
	if before.Nlink == 0 {
		// A Save renamed a newer result over the name between the pin and its fstat: the pinned file has no name
		// left. That is a change, not an unsafe file; nothing of it is read.
		return ReadResult{}, ErrChanged
	}
	if err = checkedFile(before, uid); err != nil {
		return ReadResult{}, err
	}
	var fd *sys.FD
	err = pin.ProcPath(func(path string) error {
		var e error
		fd, e = sys.Own(unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0))
		return e
	})
	if err != nil {
		return ReadResult{}, err
	}
	f, err := fd.Release("scan-result")
	if err != nil {
		_ = fd.Close()
		return ReadResult{}, err
	}
	defer func() { _ = f.Close() }()
	var opened unix.Stat_t
	if err = sys.FstatFile(f, &opened); err != nil {
		return ReadResult{}, err
	}
	if !unchanged(before, opened) {
		return ReadResult{}, ErrChanged
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return ReadResult{}, err
	}
	if len(b) > MaxBytes {
		return ReadResult{}, ErrSize
	}
	var after unix.Stat_t
	if err = sys.FstatFile(f, &after); err != nil {
		return ReadResult{}, err
	}
	if !unchanged(before, after) {
		return ReadResult{}, ErrChanged
	}
	current, err := d.Openat("last.json", unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ReadResult{}, ErrChanged
	}
	defer func() { _ = current.Close() }()
	if err = current.Fstat(&after); err != nil || !unchanged(before, after) {
		return ReadResult{}, ErrChanged
	}
	s, err := Decode(b)
	if err == nil && s.As.Recipient != uid {
		err = ErrInvalid
	}
	if err != nil {
		return ReadResult{}, err
	}
	return ReadResult{Snapshot: s, Freshness: freshness(s, boot, now), Identity: fmt.Sprintf("%d:%d:%d:%d:%d:%d:%d:%d:%d", before.Dev, before.Ino, before.Uid, before.Mode, before.Size, before.Mtim.Sec, before.Mtim.Nsec, before.Ctim.Sec, before.Ctim.Nsec)}, nil
}

func freshness(s Snapshot, boot string, now time.Time) string {
	if s.Boot == nil || !bootPattern.MatchString(boot) {
		return "unknown"
	}
	if *s.Boot != boot {
		return "another-boot"
	}
	if s.Finished.After(now) {
		return "future"
	}
	if now.Sub(s.Finished) > 5*time.Minute {
		return "stale"
	}
	return "fresh"
}

func checkedDirectory(st unix.Stat_t, uid uint32) error {
	if st.Uid != uid {
		return ErrUnsafe
	}
	if st.Mode&07777 != 0700 {
		return ErrMode
	}
	return nil
}
