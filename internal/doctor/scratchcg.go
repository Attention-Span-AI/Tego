// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// makeScratchDir makes the throwaway cgroup prefix<pid> under root, the invoking uid's delegated subtree, for D3,
// D7 and the plane probe. One policy for a directory already there, which only a crashed doctor of the same pid
// leaves: it is removed when empty and made afresh, and it is an error when it is not, never reused, since a
// cgroup that still holds a process or a link is not the empty one the probe reasons about.
// It first sweeps the empty ones a killed doctor of another pid left (sweepScratchDirs).
func makeScratchDir(root, prefix string) (string, error) {
	sweepScratchDirs(root, prefix)
	path := filepath.Join(root, prefix+strconv.Itoa(os.Getpid()))
	err := os.Mkdir(path, 0o755)
	if errors.Is(err, os.ErrExist) {
		if rerr := unix.Rmdir(path); rerr != nil {
			return "", fmt.Errorf("mkdir %s: a leftover one is not empty: %w", path, rerr)
		}
		err = os.Mkdir(path, 0o755)
	}
	if err != nil {
		return "", fmt.Errorf("mkdir %s: %w", path, err)
	}
	return path, nil
}

// sweepScratchDirs removes root's prefix<pid> scratch cgroups whose pid no longer runs (makeScratchDir). A probe
// removes its own on return; SIGKILL or the OOM killer skips that, and the probe child dies with its parent
// (Pdeathsig), so the cgroup is left empty in the delegated subtree for good. rmdir fails on a cgroup that still
// holds a process or a child, so only an empty one goes. A name whose rest is not just a pid is another prefix's
// (".tego-doctor-" is the front of the other two) and is left alone.
func sweepScratchDirs(root, prefix string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		rest, ok := strings.CutPrefix(e.Name(), prefix)
		if !ok || !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(rest)
		if err != nil || pid <= 0 || strconv.Itoa(pid) != rest || pid == os.Getpid() ||
			!errors.Is(unix.Kill(pid, 0), unix.ESRCH) {
			continue
		}
		_ = unix.Rmdir(filepath.Join(root, e.Name()))
	}
}
