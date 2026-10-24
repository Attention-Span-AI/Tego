// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// ErrBusy is returned when another maze command is changing the rules and doesn't finish in time.
var ErrBusy = errors.New("another maze command is changing these rules right now; try again in a moment")

// lockWait is how long a command waits for another one to finish changing the rules.
const lockWait = 10 * time.Second

// Lock takes Maze's write lock (~/.maze/.lock) for one read-change-write of the rules files and the approval
// record, so two commands at once (two `maze allow` in a script) can't lose each other's changes or make Maze's
// own write look like tampering. The returned function releases it. The lock is the kernel's (flock): a command
// that dies releases it at once.
func Lock(ctx context.Context, home string) (unlock func(), err error) {
	dir := filepath.Join(home, ".maze")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("make %s: %w", dir, err)
	}
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(lockWait)
	for {
		err := flock(f, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() {
				_ = flock(f, unix.LOCK_UN) // closing releases it too
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			_ = f.Close()
			return nil, err
		}
		if time.Now().After(deadline) {
			_ = f.Close()
			return nil, ErrBusy
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// flock is flock(2) on f's descriptor under the standard library's lease, the Control of f's SyscallConn, which
// holds the descriptor open for the call: (*os.File).Fd hands out a number with no lease (ADR 0023 A4).
func flock(f *os.File, how int) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := rc.Control(func(fd uintptr) { ferr = unix.Flock(int(fd), how) }); err != nil {
		return err
	}
	return ferr
}
