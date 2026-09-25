// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
)

// TestProbeLockRefusesWhatIsNoLockFile: ProbeLock opened <run>/lock with a plain
// O_RDONLY, so a FIFO planted under the name blocked `tego stop`, and every sweep that probed the run, in
// open(2) until something opened its other end; a link was followed out of the run directory. The lock file is
// now opened O_NOFOLLOW|O_NONBLOCK and must be a regular file: both return at once, with an error.
func TestProbeLockRefusesWhatIsNoLockFile(t *testing.T) {
	for _, tc := range []struct {
		name  string
		plant func(t *testing.T, path string)
	}{
		{"a FIFO", func(t *testing.T, path string) {
			if err := syscall.Mkfifo(path, 0o600); err != nil {
				t.Fatal(err)
			}
			// A probe that blocked in open(2) is released when the test ends, so it cannot outlive it.
			t.Cleanup(func() {
				if fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
					_ = syscall.Close(fd)
				}
			})
		}},
		{"a link to a lock file elsewhere", func(t *testing.T, path string) {
			target := filepath.Join(t.TempDir(), "lock")
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		}},
		{"a directory", func(t *testing.T, path string) {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.plant(t, filepath.Join(dir, ledger.LockFile))
			done := make(chan error, 1)
			go func() {
				_, _, err := ProbeLock(dir)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("ProbeLock read something that is no lock file as a lock")
				}
			case <-time.After(time.Second):
				t.Fatal("ProbeLock was still blocked after 1 s")
			}
		})
	}
}
