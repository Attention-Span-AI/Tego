// SPDX-License-Identifier: Apache-2.0

//go:build integration

package landlock

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// helperPaths names the file of newline-separated paths the snapshot helper opens.
const helperPaths = "TEGO_LANDLOCK_PATHS"

// TestIntegrationSnapshotAgreesWithTheKernel is the property on the real kernel: over random trees changed after
// Prepare (directories and files made beside an ancestor of the target and inside listed siblings, siblings renamed,
// moved into new directories or replaced, a write entry moved, files replaced), Snapshot.Refuses answers true for a
// read open exactly where the domain refuses it EACCES, for every path outside the target. The supervisor refuses what
// Refuses says (snapshotRead), so a false true would refuse a read the kernel allows, and a false false would keep a
// line that says allow for an open the kernel refused.
func TestIntegrationSnapshotAgreesWithTheKernel(t *testing.T) {
	for seed := uint64(1); seed <= 24; seed++ {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			root := tempDir(t)
			// An overlayfs may renumber a copied-up file (ADR 0010), so Refuses leaves a listed file with a new inode
			// there to the kernel: such a tree replaces no file.
			overlay := onOverlay(root)
			rng := rand.New(rand.NewPCG(seed, 0x5eed))
			levels := []string{root, filepath.Join(root, "a")}
			var dirs, files []string
			mkTree(t, root, "a/secret/key", "w/w.txt")
			for i := 0; i < 6; i++ {
				at := levels[rng.IntN(len(levels))]
				d := filepath.Join(at, fmt.Sprintf("d%d", i))
				mkTree(t, d, "f.txt")
				dirs = append(dirs, d)
				f := filepath.Join(at, fmt.Sprintf("f%d", i))
				mkTree(t, at, filepath.Base(f))
				files = append(files, f)
			}
			h := realPrepare(t, denyTable([]string{filepath.Join(root, "a", "secret")}, filepath.Join(root, "w")))
			refuses := h.DenyReadSnapshot()
			if refuses == nil {
				t.Fatal("no snapshot")
			}
			for i := 0; i < 10; i++ {
				at := levels[rng.IntN(len(levels))]
				n := fmt.Sprintf("late%d", i)
				op := rng.IntN(8)
				if overlay && op == 6 {
					op = 1
				}
				switch op {
				case 0: // a directory made beside an ancestor, with a file and a directory in it
					mkTree(t, filepath.Join(at, n), "f.txt", "sub/g.txt")
				case 1: // a file made beside an ancestor
					mkTree(t, at, n)
				case 2: // a file made inside a listed sibling
					mkTree(t, dirs[rng.IntN(len(dirs))], n)
				case 3, 4, 5, 6: // a sibling renamed, moved into a new directory, or replaced; a file replaced
					src := dirs[rng.IntN(len(dirs))]
					if op == 6 {
						src = files[rng.IntN(len(files))]
					}
					if _, err := os.Lstat(src); err != nil {
						continue
					}
					dst := filepath.Join(at, n)
					if op == 4 {
						mkTree(t, at, n+"/")
						dst = filepath.Join(dst, "moved")
					}
					if err := os.Rename(src, dst); err != nil {
						t.Fatal(err)
					}
					if op == 5 {
						mkTree(t, src, "f.txt")
					}
					if op == 6 {
						mkTree(t, filepath.Dir(src), filepath.Base(src))
					}
				case 7: // the write entry moved into a new directory
					if _, err := os.Lstat(filepath.Join(root, "w")); err == nil {
						mkTree(t, at, n+"/")
						if err := os.Rename(filepath.Join(root, "w"), filepath.Join(at, n, "w")); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			var paths []string
			secret := filepath.Join(root, "a", "secret")
			if err := filepath.WalkDir(root, func(p string, _ os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if p == secret {
					return filepath.SkipDir
				}
				paths = append(paths, p)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			list := filepath.Join(t.TempDir(), "paths")
			if err := os.WriteFile(list, []byte(strings.Join(paths, "\n")), 0o600); err != nil {
				t.Fatal(err)
			}
			fd, _ := h.LandlockRuleset()
			r := runHelper(t, "snapshot", fd, helperPaths+"="+list)
			if c, ok := r.Checks["apply"]; ok {
				t.Fatalf("apply: %+v", c)
			}
			refused := 0
			for _, p := range paths {
				c, ok := r.Checks[p]
				if !ok {
					t.Errorf("%s: no result", p)
					continue
				}
				kernel := !c.OK && strings.Contains(c.Err, "permission denied")
				if !c.OK && !kernel {
					t.Errorf("%s: %s, neither opened nor refused", p, c.Err)
				}
				if got := refuses(p); got != kernel {
					t.Errorf("%s: Refuses %v, the kernel refused %v (%s)", strings.TrimPrefix(p, root), got, kernel, c.Err)
				}
				if kernel {
					refused++
				}
			}
			t.Logf("%d paths, %d refused by the kernel", len(paths), refused)
		})
	}
}

// snapshotHelper applies the ruleset and opens each path read-only, reporting each one's error. The list is read
// first: it was written after Prepare, beside the tree's ancestor, so the domain refuses it.
func snapshotHelper() report {
	r := report{Checks: map[string]check{}}
	b, err := os.ReadFile(os.Getenv(helperPaths))
	if err != nil {
		record(&r, "apply", err, "")
		return r
	}
	if err := applyAllThreads(rulesetFD); err != nil {
		if errors.Is(err, unix.ENOTSUP) {
			r.Skip = "AllThreadsSyscall needs CGO_ENABLED=0"
			return r
		}
		record(&r, "apply", err, "")
		return r
	}
	for _, p := range strings.Split(string(b), "\n") {
		fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err == nil {
			_ = unix.Close(fd)
		}
		record(&r, p, err, "")
	}
	return r
}
