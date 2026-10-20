// SPDX-License-Identifier: Apache-2.0

package hoststate

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/testutil"
	"golang.org/x/sys/unix"
)

// TestDirClosesOnceAndLendsNothingAfter is ADR 0023 C12: a Dir's descriptor is a sys.FD, so concurrent Closes
// close it once (the race detector sees no write to a shared number) and every use after a Close answers
// sys.ErrClosed instead of reaching a number the process may since have given to another file.
func TestDirClosesOnceAndLendsNothingAfter(t *testing.T) {
	testutil.NoFDLeak(t)
	d, err := OpenAt(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = d.Close()
		}()
	}
	wg.Wait()
	if err := d.Close(); err != nil {
		t.Errorf("a second Close = %v, want nil", err)
	}
	if _, err := d.OpenFile("x", os.O_RDWR|os.O_CREATE, 0o600); !errors.Is(err, sys.ErrClosed) {
		t.Errorf("OpenFile after Close = %v, want sys.ErrClosed", err)
	}
	if _, err := d.Stat("x"); !errors.Is(err, sys.ErrClosed) {
		t.Errorf("Stat after Close = %v, want sys.ErrClosed", err)
	}
	if err := d.Unlink("x"); !errors.Is(err, sys.ErrClosed) {
		t.Errorf("Unlink after Close = %v, want sys.ErrClosed", err)
	}
	if _, err := d.Dup(); !errors.Is(err, sys.ErrClosed) {
		t.Errorf("Dup after Close = %v, want sys.ErrClosed", err)
	}
}

// TestDirUnwindsLeaveNoDescriptor: every refusal of OpenAt, of Open (openHost) and of OpenFile (a FIFO, a missing
// name, a file another uid owns) that a test can reach (an fstat of an open descriptor, or a Release, cannot
// fail here), a duplicate and its close, and the files it opens leave the descriptor table as they found it
// (ADR 0023's NoFDLeak on the unwind paths).
func TestDirUnwindsLeaveNoDescriptor(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "state")
	open := filepath.Join(base, "open")
	wide := filepath.Join(base, "wide")
	for _, p := range []string{real, open, wide} {
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wide, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(real, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "file"), filepath.Join(real, "link-to-file")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "made-through-the-link"), filepath.Join(real, "link-to-absent")); err != nil {
		t.Fatal(err)
	}
	// A regular file another uid owns, for OpenFile's owner refusal: root makes one; anyone else reads one of
	// root's in a directory OpenAt accepts.
	foreignDir, foreign := "/etc", "passwd"
	if os.Geteuid() == 0 {
		foreignDir, foreign = real, "foreign"
		if err := os.WriteFile(filepath.Join(real, foreign), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(filepath.Join(real, foreign), 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	testutil.NoFDLeak(t)
	for _, p := range []string{filepath.Join(base, "link"), open, filepath.Join(base, "file"), filepath.Join(base, "absent")} {
		if d, err := OpenAt(p); err == nil {
			_ = d.Close()
			t.Errorf("OpenAt(%s) succeeded", p)
		}
	}
	// Open's refusals after the directory is open: wide is mode 0755 (refused for its mode as root, for its owner
	// otherwise), open 0777, and real is not root's unless the test runs as root; the link fails before it.
	hostRefused := []string{wide, open, filepath.Join(base, "link"), filepath.Join(base, "file")}
	if os.Geteuid() != 0 {
		hostRefused = append(hostRefused, real)
	}
	for _, p := range hostRefused {
		if d, err := openHost(p); !errors.Is(err, ErrHostState) {
			if err == nil {
				_ = d.Close()
			}
			t.Errorf("openHost(%s) = %v, want ErrHostState", p, err)
		}
	}
	d, err := OpenAt(real)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	if _, err := d.OpenFile("fifo", os.O_RDWR, 0); !errors.Is(err, ErrHostState) {
		t.Errorf("OpenFile of a FIFO = %v, want ErrHostState", err)
	}
	if _, err := d.OpenFile("absent", os.O_RDONLY, 0); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("OpenFile of a missing name = %v, want os.ErrNotExist", err)
	}
	// A link at the name is not followed, even to a regular file this uid owns, and with O_CREATE nothing is made
	// where it points.
	if f, err := d.OpenFile("link-to-file", os.O_RDONLY, 0); err == nil {
		_ = f.Close()
		t.Error("OpenFile read through a link")
	}
	if f, err := d.OpenFile("link-to-absent", os.O_RDWR|os.O_CREATE, 0o600); err == nil {
		_ = f.Close()
		t.Error("OpenFile with O_CREATE opened through a link")
	}
	if _, err := os.Lstat(filepath.Join(base, "made-through-the-link")); !os.IsNotExist(err) {
		t.Errorf("OpenFile created the link's target: %v", err)
	}
	fd, err := OpenAt(foreignDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fd.OpenFile(foreign, os.O_RDONLY, 0); !errors.Is(err, ErrHostState) {
		t.Errorf("OpenFile of a file another uid owns = %v, want ErrHostState", err)
	}
	if err := fd.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := d.OpenFile("x", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Names("x", f) {
		t.Error("Names does not see the file just opened")
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	dup, err := d.Dup()
	if err != nil {
		t.Fatal(err)
	}
	if err := dup.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Unlink("x"); err != nil {
		t.Fatal(err)
	}
}
