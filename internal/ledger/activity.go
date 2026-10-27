// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// ActivityFile is a live run's activity sidecar (§3): the CLOCK_MONOTONIC reading of the newest activity the
// run's stall check counted without a ledger line (limits-check-doctor-cli.md R4: a supervisor answer or a
// kernel stamp under record: off, a relayed model chunk in any mode), so `status` measures the same idle the
// watcher kills on (R9). It is not part of the record: no hash, no fsync, nothing reads it once the run's lock
// is free.
const ActivityFile = "activity"

// activitySize is the sidecar's one format: the reading as a little-endian uint64, then its bitwise complement.
// The launcher overwrites the file in place while status reads it, and a pwrite(2) is not atomic against a
// concurrent read(2) of the same bytes; a reading whose two halves disagree was read mid-write and is ignored.
const activitySize = 16

// Activity is the launcher's open activity sidecar, written in place with one pwrite(2) per Publish.
type Activity struct {
	f   *os.File
	buf [activitySize]byte
}

// OpenActivity creates the run's activity sidecar, 0600, through the Writer's directory descriptor: O_CREAT|O_EXCL
// and O_NOFOLLOW, so a name already there (a link, a planted file, a second call) is refused rather than written
// through, and a root launcher hands it over as it does every file it creates in a directory another uid owns
// (the hand-over rule). The caller owns the returned file and closes it.
func (w *Writer) OpenActivity() (*Activity, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil, ErrClosed
	}
	path := filepath.Join(w.dir, ActivityFile)
	fd, err := w.dirFD.Openat(ActivityFile,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("ledger: create activity sidecar: %w", openError(w.dirFD, ActivityFile, path, err))
	}
	err = giveCreated(w.dirFD, w.dir, fd, path)
	var f *os.File
	if err == nil {
		f, err = fd.Release(path)
	}
	if err != nil {
		_ = fd.Close()
		_ = unlinkAt(w.dirFD, ActivityFile)
		return nil, fmt.Errorf("ledger: hand over activity sidecar: %w", err)
	}
	return &Activity{f: f}, nil
}

// Publish overwrites the sidecar with monoNS. It is called from one goroutine (the budget watcher's), at most
// once per tick.
func (a *Activity) Publish(monoNS uint64) error {
	binary.LittleEndian.PutUint64(a.buf[:8], monoNS)
	binary.LittleEndian.PutUint64(a.buf[8:], ^monoNS)
	if _, err := a.f.WriteAt(a.buf[:], 0); err != nil {
		return fmt.Errorf("ledger: publish activity: %w", err)
	}
	return nil
}

// Close closes the sidecar's descriptor. The file stays: a reader ignores it once the run's lock is free.
func (a *Activity) Close() error { return a.f.Close() }

// ReadActivity is the reading in dir's activity sidecar, and false when there is none to use: no file, not a
// regular file (opened O_NOFOLLOW|O_NONBLOCK, so a link or a FIFO planted under the name neither redirects nor
// blocks the read), not exactly activitySize bytes, a torn reading, or 0 (nothing published, E20's unknown). The
// caller decides whether the reading is comparable with its clock: it is only while the run's lock is held.
func ReadActivity(dir string) (uint64, bool) {
	f, err := openRegular(filepath.Join(dir, ActivityFile))
	if err != nil {
		return 0, false
	}
	defer func() { _ = f.Close() }()
	var b [activitySize + 1]byte
	n, err := io.ReadFull(f, b[:])
	if n != activitySize || err != io.ErrUnexpectedEOF {
		return 0, false
	}
	v := binary.LittleEndian.Uint64(b[:8])
	if v == 0 || binary.LittleEndian.Uint64(b[8:activitySize]) != ^v {
		return 0, false
	}
	return v, true
}
