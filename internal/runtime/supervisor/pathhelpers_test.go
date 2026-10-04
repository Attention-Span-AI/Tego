// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSplitFinal(t *testing.T) {
	for _, c := range []struct{ in, dir, base string }{
		{"/a/b", "/a", "b"},
		{"/a/b/", "/a", "b"},
		{"/a/b///", "/a", "b"},
		{"/x", "/", "x"},
		{"x", ".", "x"},
		{"a/b", "a", "b"},
		{"/", "/", ""},
		{"///", "/", ""},
		{"", "/", ""},
	} {
		if dir, base := splitFinal(c.in); dir != c.dir || base != c.base {
			t.Errorf("splitFinal(%q) = (%q, %q), want (%q, %q)", c.in, dir, base, c.dir, c.base)
		}
	}
}

func openPath(t *testing.T, p string, flags int) int {
	t.Helper()
	fd, err := unix.Open(p, flags|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open %s: %v", p, err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

// ".." meets a process's root only at the same inode on the same mount; two descriptors of one directory
// are one place, two directories are not, and a descriptor that cannot be statted is never "the same".
func TestSamePlaceAndIsDirFD(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	a := openPath(t, dir, unix.O_PATH|unix.O_DIRECTORY)
	b := openPath(t, dir, unix.O_RDONLY|unix.O_DIRECTORY)
	c := openPath(t, sub, unix.O_PATH|unix.O_DIRECTORY)
	if !samePlace(a, b) {
		t.Error("two descriptors of one directory are one place")
	}
	if samePlace(a, c) {
		t.Error("a directory and its child are two places")
	}
	if samePlace(a, -1) || samePlace(-1, a) {
		t.Error("an invalid descriptor is never the same place")
	}
	if !isDirFD(a) || !isDirFD(c) {
		t.Error("directories are directories")
	}
	f := filepath.Join(dir, "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if isDirFD(openPath(t, f, unix.O_RDONLY)) || isDirFD(-1) {
		t.Error("a file and an invalid descriptor are not directories")
	}
}

func TestSameProcInstanceOnlyForThisProcessesProc(t *testing.T) {
	if !sameProcInstance(openPath(t, "/proc", unix.O_RDONLY|unix.O_DIRECTORY)) {
		t.Error("/proc is this process's own procfs instance")
	}
	if sameProcInstance(openPath(t, t.TempDir(), unix.O_RDONLY|unix.O_DIRECTORY)) {
		t.Error("an ordinary directory is not the procfs root")
	}
	if sameProcInstance(-1) {
		t.Error("an invalid descriptor is not")
	}
}

func TestReadlinkFDReadsTheLinkNotItsTarget(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "l")
	if err := os.Symlink("/nonexistent/target", link); err != nil {
		t.Fatal(err)
	}
	fd := openPath(t, link, unix.O_PATH|unix.O_NOFOLLOW)
	got, err := readlinkFD(fd)
	if err != nil || got != "/nonexistent/target" {
		t.Fatalf("readlinkFD = %q, %v", got, err)
	}
	if _, err := readlinkFD(openPath(t, dir, unix.O_PATH|unix.O_DIRECTORY)); err == nil {
		t.Error("a descriptor that is not a link has nothing to read")
	}
}

func TestStatIDFollowsSymlinksAndDistinguishesFiles(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(a, link); err != nil {
		t.Fatal(err)
	}
	k := sysKernel{}
	ida, _ := k.StatID(a)
	idb, _ := k.StatID(b)
	idl, err := k.StatID(link)
	if err != nil {
		t.Fatal(err)
	}
	if ida != idl || ida == idb {
		t.Errorf("ids: a=%v b=%v link=%v", ida, idb, idl)
	}
	if _, err := k.StatID(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing file has no identity")
	}
}
