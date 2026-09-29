// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestFSTargetFailsADotAfterAFile is R15b's "walked as the task's own lookup walks it" for a "." component: the
// kernel's lookup fails a "." after a non-directory with ENOTDIR, before the next component or at the end, so
// the walk does too, where it used to skip the "." and report the file (or a name beneath it) as the landing.
// Each case is checked against the kernel's own openat of the same spelling first. A "." after a directory
// stays a no-op.
func TestFSTargetFailsADotAfterAFile(t *testing.T) {
	dir := t.TempDir()
	w := filepath.Join(dir, "w")
	if err := os.Mkdir(w, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("f", filepath.Join(w, "lf")); err != nil {
		t.Fatal(err)
	}
	pid := spawnTask(t, dir)
	for _, tc := range []struct {
		name string
		q    pathQuery
		want string // "" for ENOTDIR
	}{
		{"a name after file/.", pathQuery{path: "w/f/./g", nofollow: true}, ""},
		{"a name after file/. followed", pathQuery{path: "w/f/./g"}, ""},
		{"a name after link-to-file/.", pathQuery{path: "w/lf/./g", nofollow: true}, ""},
		{"file/. at the end", pathQuery{path: "w/f/."}, ""},
		{"file/. at the end, not followed", pathQuery{path: "w/f/.", nofollow: true}, ""},
		{"link-to-file/. at the end", pathQuery{path: "w/lf/."}, ""},
		{"file/. created", pathQuery{path: "w/f/.", create: true}, ""},
		{"dir/. then a file", pathQuery{path: "w/./f"}, filepath.Join(w, "f")},
		{"./dir then a file", pathQuery{path: "./w/f", nofollow: true}, filepath.Join(w, "f")},
	} {
		// The kernel's own answer for the spelling, from the same cwd (not joined: a join cleans the ".").
		flags := unix.O_PATH
		if tc.q.nofollow {
			flags |= unix.O_NOFOLLOW
		}
		fd, kerr := unix.Openat(unix.AT_FDCWD, dir+"/"+tc.q.path, flags|unix.O_CLOEXEC, 0)
		if kerr == nil {
			_ = unix.Close(fd)
		}
		if tc.want == "" && !errors.Is(kerr, unix.ENOTDIR) {
			t.Fatalf("%s: the kernel answered %v, the case expects ENOTDIR", tc.name, kerr)
		}
		for _, joined := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/joined=%v", tc.name, joined), func(t *testing.T) {
				q := tc.q
				q.tid, q.dirfd = pid, atFDCWD
				if joined {
					q.joined = filepath.Clean(filepath.Join(dir, q.path))
				}
				landing, err := sysKernel{}.FSTarget(q)
				got := landing.at
				if tc.want == "" {
					if err == nil || !lookupFailure(err) {
						t.Errorf("FSTarget = %q, %v; want a lookup failure (the kernel's ENOTDIR)", got, err)
					}
					return
				}
				if err != nil {
					t.Fatalf("FSTarget: %v", err)
				}
				want, _ := filepath.EvalSymlinks(filepath.Dir(tc.want))
				if want = filepath.Join(want, filepath.Base(tc.want)); got != want {
					t.Errorf("landed %q, want %q", got, want)
				}
			})
		}
	}
}

// TestWalkCacheDeclinesAFinalDot: the walk cache answers a spelling from R6's cleaned join, which drops a final
// ".", so "f/." would land on the file f where the task gets ENOTDIR; it leaves such a path to the walk, as it
// leaves one with "..".
func TestWalkCacheDeclinesAFinalDot(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"w/f/.", false},
		{".", false},
		{"w/./f", true},
		{"./w/f", true},
		{"w/f", true},
		{"w/../f", false},
	} {
		q := pathQuery{path: tc.path, joined: filepath.Clean("/d/" + tc.path)}
		if got := spellingShape(q); got != tc.want {
			t.Errorf("spellingShape(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
