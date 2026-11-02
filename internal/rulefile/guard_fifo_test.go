// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestReadRefusesFIFO (SEC-5): a FIFO at the contract's path is refused at once as not a regular file. The open is
// O_NONBLOCK, so it does not wait for a writer that never comes (a blocking open of a FIFO hangs the dashboard's
// request), and fstat's S_IFMT refuses it before anything is read.
func TestReadRefusesFIFO(t *testing.T) {
	g, path := fixture(t)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Skipf("no FIFO here: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := Read(path, g)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrGuard) {
			t.Fatalf("Read of a FIFO: %v, want ErrGuard", err)
		}
	case <-time.After(2 * time.Second):
		// Unblock the open so the goroutine ends, then fail: Read waited on a FIFO.
		if f, err := os.OpenFile(path, os.O_WRONLY|unix.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
		t.Fatal("Read of a FIFO did not return within 2 s")
	}
	if _, err := Replace(t.Context(), g, path, Sum([]byte(textA)), []byte(textB), Change{Via: "dashboard"}); !errors.Is(err, ErrGuard) {
		t.Errorf("Replace over a FIFO: %v, want ErrGuard", err)
	}
	if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeNamedPipe == 0 {
		t.Errorf("the FIFO was replaced: %v %v", fi, err)
	}
}

// TestReadNamesAMissingContract: a run's contract moved since the run. The open is relative to the pinned directory,
// so its error carried no name, and tego rule printed "no such file or directory" alone.
func TestReadNamesAMissingContract(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "agent.yaml")
	_, err = Read(path, Guard{})
	if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), path) {
		t.Errorf("Read of a contract that is gone: %v; want it named, and still os.ErrNotExist", err)
	}
}
