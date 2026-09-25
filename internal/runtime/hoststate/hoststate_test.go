// SPDX-License-Identifier: Apache-2.0

package hoststate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestVerifyHost is ADR 0034 item 2's table as ADR 0042 (3)(b) narrowed it: only root 0700 is trusted. The
// root:tego 1770 form is refused whatever group the directory has, so the tego group's existence on this box
// does not matter; TestRootLauncherRefusesGroupHostState (internal/runtime) shows the same with the group present.
func TestVerifyHost(t *testing.T) {
	for _, tc := range []struct {
		name string
		st   unix.Stat_t
		ok   bool
	}{
		{"root 0700", unix.Stat_t{Mode: unix.S_IFDIR | 0o700}, true},
		{"root 0755", unix.Stat_t{Mode: unix.S_IFDIR | 0o755}, false},
		{"a user's 0700", unix.Stat_t{Mode: unix.S_IFDIR | 0o700, Uid: 1000}, false},
		{"root 1777", unix.Stat_t{Mode: unix.S_IFDIR | 0o1777}, false},
		{"root:other 1770", unix.Stat_t{Mode: unix.S_IFDIR | 0o1770, Gid: 12345}, false},
		{"root 1770 (the withdrawn tmpfiles form)", unix.Stat_t{Mode: unix.S_IFDIR | 0o1770, Gid: 4242}, false},
		{"root 0770", unix.Stat_t{Mode: unix.S_IFDIR | 0o770, Gid: 4242}, false},
		{"a file", unix.Stat_t{Mode: unix.S_IFREG | 0o700}, false},
	} {
		d := &Dir{path: "/run/tego"}
		err := d.verifyHost(tc.st)
		if (err == nil) != tc.ok {
			t.Errorf("%s: verifyHost = %v, want ok=%v", tc.name, err, tc.ok)
		}
		if err != nil && !errors.Is(err, ErrHostState) {
			t.Errorf("%s: %v does not wrap ErrHostState", tc.name, err)
		}
		if err != nil && tc.st.Mode&unix.S_IFMT == unix.S_IFDIR && !strings.Contains(err.Error(), Fix) {
			t.Errorf("%s: %v does not carry the fix %q", tc.name, err, Fix)
		}
	}
}

// TestOpenFileRefusesAFileAnotherUIDOwns is ADR 0042 (3)(b)'s defence in depth: a file of the right name that this
// process's effective uid does not own is refused, whoever could create it, so a name planted before the
// launcher created it is never used even if the directory check ever lets a writer in. Unprivileged, /etc/passwd
// is root's; as root, a file handed to another uid stands in for it.
func TestOpenFileRefusesAFileAnotherUIDOwns(t *testing.T) {
	dir, name := "/etc", "passwd"
	if os.Geteuid() == 0 {
		dir, name = t.TempDir(), "slots-planted"
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(filepath.Join(dir, name), 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	d, err := OpenAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	f, err := d.OpenFile(name, os.O_RDONLY, 0)
	if err == nil {
		_ = f.Close()
		t.Fatalf("OpenFile(%s/%s) opened a file another uid owns", dir, name)
	}
	if !errors.Is(err, ErrHostState) || !strings.Contains(err.Error(), "owned by uid") {
		t.Errorf("OpenFile of another uid's file = %v, want ErrHostState naming the owner", err)
	}
}

// TestOpenAtRefusesWhatALinkOrAWriterCouldPlant: the caller's own directory is still opened without following
// a link and refused when others can write it, and files in it are opened only as regular files, never
// through a link.
func TestOpenAtRefusesWhatALinkOrAWriterCouldPlant(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "state")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAt(link); !errors.Is(err, ErrHostState) {
		t.Errorf("OpenAt through a link = %v, want ErrHostState", err)
	}
	open := filepath.Join(base, "open")
	if err := os.Mkdir(open, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAt(open); !errors.Is(err, ErrHostState) {
		t.Errorf("OpenAt of a world-writable directory = %v, want ErrHostState", err)
	}
	d, err := OpenAt(real)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	f, err := d.OpenFile("bpf-h.lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	_ = f.Close()
	if err := os.Symlink("/etc/passwd", filepath.Join(real, "planted")); err != nil {
		t.Fatal(err)
	}
	if _, err := d.OpenFile("planted", os.O_RDWR, 0); err == nil {
		t.Error("OpenFile followed a symbolic link")
	}
	if err := unix.Mkfifo(filepath.Join(real, "fifo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := d.OpenFile("fifo", os.O_RDWR, 0); !errors.Is(err, ErrHostState) {
		t.Errorf("OpenFile of a FIFO = %v, want ErrHostState", err)
	}
	for _, name := range []string{"", ".", "..", "a/b"} {
		if _, err := d.OpenFile(name, os.O_RDONLY, 0); err == nil {
			t.Errorf("OpenFile(%q) succeeded", name)
		}
	}
}

// TestOpenHostAsRoot is the root half of ADR 0034's guest tests: a missing directory is created root 0700 and
// trusted, a linked one or one of another mode refuses. It needs root and runs in the KVM guest.
func TestOpenHostAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: the trusted directory is root's")
	}
	base := t.TempDir()
	fresh := filepath.Join(base, "fresh")
	d, err := openHost(fresh)
	if err != nil {
		t.Fatalf("openHost of a missing directory: %v", err)
	}
	_ = d.Close()
	if st, err := os.Stat(fresh); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("created %v (%v), want root 0700", st, err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(fresh, link); err != nil {
		t.Fatal(err)
	}
	if _, err := openHost(link); !errors.Is(err, ErrHostState) {
		t.Errorf("openHost through a link = %v, want ErrHostState", err)
	}
	if err := os.Chmod(fresh, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := openHost(fresh); !errors.Is(err, ErrHostState) {
		t.Errorf("openHost of a 0755 directory = %v, want ErrHostState", err)
	}
}

// TestDupKeepsTheVerifiedDirectory: a duplicate holds the same directory by its own descriptor, and closing it
// leaves the original open.
func TestDupKeepsTheVerifiedDirectory(t *testing.T) {
	dir := t.TempDir()
	d, err := OpenAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	dup, err := d.Dup()
	if err != nil {
		t.Fatal(err)
	}
	var dn, on int
	_ = d.fd.Borrow(func(n int) error { on = n; return nil })
	if err := dup.fd.Borrow(func(n int) error {
		dn = n
		flags, err := unix.FcntlInt(uintptr(n), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			t.Errorf("the duplicate is not close-on-exec (%#x, %v)", flags, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if dn == on || dup.path != d.path {
		t.Fatalf("Dup = %d %s of %d %s", dn, dup.path, on, d.path)
	}
	if err := dup.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := d.OpenFile("x", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("the original stopped working once its duplicate closed: %v", err)
	}
	_ = f.Close()
}

// TestStatLooksRelativeToTheVerifiedDescriptor is ADR 0034 (3) for a stat: Stat reads the file the verified
// directory holds, not whatever its path names now, does not follow a link, and refuses a name that is not one path
// component. The linger timer read its build lock's mtime by path (ADR 0022, D4).
func TestStatLooksRelativeToTheVerifiedDescriptor(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	d, err := OpenAt(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("verified"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("f", filepath.Join(dir, "l")); err != nil {
		t.Fatal(err)
	}
	// The directory's path now names another directory, with another f in it.
	if err := os.Rename(dir, filepath.Join(base, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("planted, longer"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := d.Stat("f")
	if err != nil || st.Size != int64(len("verified")) {
		t.Errorf("Stat(f) = size %d, %v; want the verified directory's file (%d bytes)", st.Size, err, len("verified"))
	}
	if st, err := d.Stat("l"); err != nil || st.Mode&unix.S_IFMT != unix.S_IFLNK {
		t.Errorf("Stat(l) = mode %#o, %v; want the link itself, not followed", st.Mode, err)
	}
	if _, err := d.Stat("missing"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Stat(missing) = %v, want os.ErrNotExist", err)
	}
	for _, name := range []string{"", ".", "..", "a/b"} {
		if _, err := d.Stat(name); !errors.Is(err, ErrHostState) {
			t.Errorf("Stat(%q) = %v, want ErrHostState", name, err)
		}
	}
}
