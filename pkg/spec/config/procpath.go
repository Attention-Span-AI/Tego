// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// maxProcHops bounds ThroughProc's symlink walk at the kernel's own limit on links followed in one lookup (ELOOP).
const maxProcHops = 40

// ThroughProc reports whether the absolute path p is a /proc path, or reaches one by its symlinks, and the spelling
// that did: a path under /proc, a link whose target is one (/dev/fd is /proc/self/fd, /dev/stdin /proc/self/fd/0), or
// a directory on a procfs mounted elsewhere. Such a path names a file relative to the process that opens it
// (/proc/self/exe is that process's executable, /proc/self/cwd its working directory, /proc/<pid>/root that process's
// root), so what one process resolves it to is not what another reaches. Compile refuses an exec entry that does
// (agent-contract.md R8a), tego learn proposes none, and the Load refuses a layer or a path setting that does
// (identity-config.md R14). A component that cannot be read stops the walk with false, leaving the
// missing path to the caller's own refusal.
//
// The walk resolves the way the kernel's path lookup does, one component at a time over Lstat and Readlink: a
// symlink's target is put in front of the components still to walk, as written, and ".." drops the last component
// of the prefix already resolved, which holds no symlink. Every resolved prefix is tested, so a magic link is judged
// by its name, never followed into the file it stands for. Until 2026-10-16 the walk joined and cleaned a link's
// target lexically, which is not the kernel's reading: with s/b -> / and s/a -> b/../proc, s/a/self/exe cleaned to
// s/proc/self/exe, which does not exist, while the kernel follows b to / first and reaches /proc/self/exe
// (agent-contract.md R8a). It lives in this leaf package so that the Load and the compiler share one walk.
func ThroughProc(p string) (string, bool) {
	pending := strings.Split(p, "/")
	resolved := "/"
	for hops := 0; len(pending) > 0; {
		part := pending[0]
		pending = pending[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}
		comp := filepath.Join(resolved, part)
		if comp == "/proc" || strings.HasPrefix(comp, "/proc/") {
			return filepath.Join(append([]string{comp}, pending...)...), true
		}
		fi, err := os.Lstat(comp)
		if err != nil {
			return "", false
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			if hops++; hops > maxProcHops {
				return "", false
			}
			target, err := os.Readlink(comp)
			if err != nil {
				return "", false
			}
			if filepath.IsAbs(target) {
				resolved = "/"
			}
			pending = append(strings.Split(target, "/"), pending...)
			continue
		}
		if fi.IsDir() {
			var st unix.Statfs_t
			if unix.Statfs(comp, &st) == nil && st.Type == unix.PROC_SUPER_MAGIC {
				return comp, true
			}
		}
		resolved = comp
	}
	return "", false
}
