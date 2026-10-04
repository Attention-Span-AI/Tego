// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestWalkExecKeepsALinksTrailingSlash: a trailing slash in the body of the final symlink the walk follows is
// the path's own trailing slash from there on, so a link to "f/" with f a file fails ENOTDIR as the kernel's
// lookup does, where the walk used to drop the slash and land on f. Each case is checked against the kernel's
// own openat of the same spelling first.
func TestWalkExecKeepsALinksTrailingSlash(t *testing.T) {
	dir := t.TempDir()
	w := filepath.Join(dir, "w")
	for _, d := range []string{w, filepath.Join(w, "d")} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(w, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		"lf":   "f/",      // a link to a file, with a slash
		"lf2":  "lf",      // a chain whose last link has the slash
		"lfa":  w + "/f/", // absolute
		"lb":   "f",
		"la":   "lb/", // the slash on a link whose target is itself a link to a file
		"ld":   "d/",  // a link to a directory, with a slash: fine
		"self": ".",
		"ln":   "new/", // dangling, with a slash
	} {
		if err := os.Symlink(target, filepath.Join(w, link)); err != nil {
			t.Fatal(err)
		}
	}
	pid := spawnTask(t, dir)
	for _, tc := range []struct {
		path string
		want string // "" for a failure
	}{
		{"w/lf", ""},
		{"w/self/lf", ""},
		{"w/lf2", ""},
		{"w/lfa", ""},
		{"w/la", ""},
		{"w/ld", filepath.Join(w, "d")},
		{"w/lb", filepath.Join(w, "f")},
	} {
		t.Run(tc.path, func(t *testing.T) {
			fd, kerr := unix.Openat(unix.AT_FDCWD, dir+"/"+tc.path, unix.O_PATH|unix.O_CLOEXEC, 0)
			if kerr == nil {
				_ = unix.Close(fd)
			}
			if (tc.want == "") != (kerr != nil) {
				t.Fatalf("the kernel answered %v, the case expects want=%q", kerr, tc.want)
			}
			fd, _, _, err := walkExec(pathQuery{tid: pid, dirfd: atFDCWD, path: tc.path}, false)
			if tc.want == "" {
				if err == nil {
					got, _ := hereLink(fd)
					t.Fatalf("walkExec landed on %q; want the kernel's %v", got, kerr)
				}
				if !errors.Is(err, kerr) {
					t.Errorf("walkExec: %v, the kernel %v", err, kerr)
				}
				return
			}
			if err != nil {
				t.Fatalf("walkExec: %v", err)
			}
			got, err := hereLink(fd)
			if err != nil {
				t.Fatal(err)
			}
			if want, _ := filepath.EvalSymlinks(tc.want); got != want {
				t.Errorf("landed %q, want %q", got, want)
			}
		})
	}
	// FSTarget, for a write-open of the link, fails with the lookup rather than naming f.
	t.Run("FSTarget of w/lf", func(t *testing.T) {
		got, err := sysKernel{}.FSTarget(pathQuery{tid: pid, dirfd: atFDCWD, path: "w/lf"})
		if !errors.Is(err, unix.ENOTDIR) {
			t.Errorf("FSTarget = %q, %v; want the kernel's ENOTDIR", got.at, err)
		}
	})
	// An O_CREAT open through a dangling link to "new/" fails in the kernel (EISDIR); the walk used to answer
	// that it creates "new" in w.
	t.Run("create through a dangling link to new/", func(t *testing.T) {
		fd, kerr := unix.Openat(unix.AT_FDCWD, dir+"/w/ln", unix.O_CREAT|unix.O_WRONLY|unix.O_CLOEXEC, 0o644)
		if kerr == nil {
			_ = unix.Close(fd)
			t.Fatal("the kernel created through a link to new/")
		}
		if _, err := os.Lstat(filepath.Join(w, "new")); err == nil {
			t.Fatal("new exists")
		}
		fd, missing, _, err := walkExec(pathQuery{tid: pid, dirfd: atFDCWD, path: "w/ln", create: true}, false)
		if err == nil {
			_ = unix.Close(fd)
			t.Fatalf("walkExec answered missing=%q; want a failure (the kernel's %v)", missing, kerr)
		}
	})
}
