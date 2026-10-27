// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestActivitySidecarRoundTrip is record-ledger.md §3's activity row: the launcher publishes the stall check's
// latest activity reading into <run>/activity, a 0600 file it created in its own run directory through the
// Writer's descriptor, overwritten in place, and status reads back the newest value whole.
func TestActivitySidecarRoundTrip(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	t.Cleanup(func() { _ = w.Abandon() })
	if _, ok := ReadActivity(dir); ok {
		t.Fatal("a run with no sidecar read as having one")
	}
	a, err := w.OpenActivity()
	if err != nil {
		t.Fatalf("OpenActivity: %v", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if _, ok := ReadActivity(dir); ok {
		t.Fatal("a sidecar nothing was published to read as a reading")
	}
	for _, v := range []uint64{5_000_000_000, 7_000_000_000, 1 << 62} {
		if err := a.Publish(v); err != nil {
			t.Fatalf("Publish(%d): %v", v, err)
		}
		if got, ok := ReadActivity(dir); !ok || got != v {
			t.Fatalf("ReadActivity = %d, %v; want %d", got, ok, v)
		}
	}
	st, err := os.Lstat(filepath.Join(dir, ActivityFile))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 || !st.Mode().IsRegular() {
		t.Fatalf("sidecar mode %v, want a regular 0600 file", st.Mode())
	}
	if _, err := w.OpenActivity(); err == nil {
		t.Fatal("a second OpenActivity reopened the sidecar; it is the Writer's alone, made once")
	}
}

// TestActivitySidecarRefusesWhatIsAlreadyThere: the sidecar is created O_EXCL|O_NOFOLLOW in the run directory, so
// a link or a file someone put under its name is never written through.
func TestActivitySidecarRefusesWhatIsAlreadyThere(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	t.Cleanup(func() { _ = w.Abandon() })
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, ActivityFile)); err != nil {
		t.Fatal(err)
	}
	if a, err := w.OpenActivity(); err == nil {
		_ = a.Close()
		t.Fatal("OpenActivity wrote through a link planted under the sidecar's name")
	}
	if b, _ := os.ReadFile(target); len(b) != 0 {
		t.Fatalf("the link's target was written: %q", b)
	}
	if _, ok := ReadActivity(dir); ok {
		t.Fatal("a link under the sidecar's name read as a reading")
	}
}

// TestReadActivityIgnoresWhatIsNotAWholeReading: status reads the sidecar while the launcher overwrites it, as any
// local user may in their own run directory, so anything but one whole reading — absent, short, long, zero, torn
// (its check half disagrees), or not a regular file — is no reading, never an error and never a block.
func TestReadActivityIgnoresWhatIsNotAWholeReading(t *testing.T) {
	whole := func(v uint64) []byte {
		b := make([]byte, activitySize)
		binary.LittleEndian.PutUint64(b[:8], v)
		binary.LittleEndian.PutUint64(b[8:], ^v)
		return b
	}
	torn := whole(9_000_000_000)
	torn[3] ^= 0xff
	cases := map[string][]byte{
		"empty": {},
		"short": whole(9_000_000_000)[:8],
		"long":  append(whole(9_000_000_000), 0),
		"zero":  whole(0),
		"torn":  torn,
	}
	for name, b := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, ActivityFile), b, 0o600); err != nil {
				t.Fatal(err)
			}
			if v, ok := ReadActivity(dir); ok {
				t.Fatalf("ReadActivity = %d, true; want no reading", v)
			}
		})
	}
	t.Run("fifo", func(t *testing.T) {
		dir := t.TempDir()
		if err := syscall.Mkfifo(filepath.Join(dir, ActivityFile), 0o600); err != nil {
			t.Fatal(err)
		}
		done := make(chan bool, 1)
		go func() { _, ok := ReadActivity(dir); done <- ok }()
		select {
		case ok := <-done:
			if ok {
				t.Fatal("a FIFO read as a reading")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("ReadActivity blocked on a FIFO under the sidecar's name")
		}
	})
	t.Run("whole", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ActivityFile), whole(9_000_000_000), 0o600); err != nil {
			t.Fatal(err)
		}
		if v, ok := ReadActivity(dir); !ok || v != 9_000_000_000 {
			t.Fatalf("ReadActivity = %d, %v; want 9000000000", v, ok)
		}
	})
}

// TestActivityAfterCloseIsRefused: the sidecar is opened through the live Writer's directory descriptor, never by
// name, so a closed Writer has none to open it with.
func TestActivityAfterCloseIsRefused(t *testing.T) {
	w, _, _ := openTestWriter(t)
	if err := w.Abandon(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.OpenActivity(); !errors.Is(err, ErrClosed) {
		t.Fatalf("OpenActivity after Abandon = %v, want ErrClosed", err)
	}
}
