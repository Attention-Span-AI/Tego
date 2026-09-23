// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// ErrNoCandidate is a process whose mappings name nothing this package could even try to read: the
// no-openssl gap of R37. It is also where a /proc/<pid>/maps the kernel refused to show us lands — an
// unprivileged attach against a non-dumpable or setuid target fails the read itself, and the closed why set
// has no value that tells the two apart (edge case #31).
var ErrNoCandidate = errors.New("uprobe: no TLS library found")

// DefaultMaxScan bounds how many mapped ELFs are parsed looking for OpenSSL symbols once the named and
// obvious candidates are exhausted. A big interpreter maps hundreds of objects and §4 gives discovery and
// attach 50 ms together.
const DefaultMaxScan = 32

// libsslName matches the SONAME shapes a system libssl is installed under: libssl.so, libssl.so.3,
// libssl.so.1.1 (R4).
var libsslName = regexp.MustCompile(`^libssl\.so(\.[0-9]+)*$`)

// candidate is one ELF worth reading for a process.
type candidate struct {
	// Path is what the ELF is read from. For a mapped library it goes through /proc/<pid>/root, which
	// is the only spelling that means anything for a process in another mount namespace (R39); for the
	// static-link fallback it is /proc/<pid>/exe, the magic link that resolves to the file itself
	// whatever namespace it lives in.
	Path string
	// Name is how the process itself names the file: what a gap reports as its binary, because
	// "/proc/4711/exe" tells an operator nothing.
	Name string
	// Open is set for a library the process opened by name (OnOpen), whose attach counts against
	// MaxOpenAttach: the file is one the agent chose.
	Open bool
}

// discoverer finds the ELFs a process's TLS might live in. It holds no state, so one value serves every
// process of every run.
type discoverer struct {
	fs      *proc.FS
	maxScan int
}

// candidates applies R4 in order: every mapped file named like a libssl, then the process's own
// executable, then — bounded by maxScan — the rest of its mappings.
//
// The exe comes before the general scan rather than after it, which is where R4's wording puts it: a
// process with no libssl mapping is overwhelmingly a statically linked binary (uv Pythons, official Node),
// and parsing every one of a large interpreter's mappings before looking at the obvious answer would spend
// the whole 50 ms budget of §4 to reach the same place. Every candidate is still tried in turn, so nothing
// R4 admits is lost — only the order changes.
func (d *discoverer) candidates(pid int) ([]candidate, error) {
	libs, err := d.fs.Libraries(pid)
	if err != nil {
		return nil, fmt.Errorf("%w: %d: %w", ErrNoCandidate, pid, err)
	}
	var named, rest []candidate
	for _, p := range libs {
		c := candidate{Path: d.rootPath(pid, p), Name: p}
		if libsslName.MatchString(filepath.Base(p)) {
			named = append(named, c)
			continue
		}
		rest = append(rest, c)
	}
	out := named
	exe, err := d.fs.Exe(pid)
	if err == nil && exe != "" {
		out = append(out, candidate{Path: d.procPath(pid, "exe"), Name: exe})
	}
	limit := d.maxScan
	if limit <= 0 {
		limit = DefaultMaxScan
	}
	for _, c := range rest {
		if len(out)-len(named) >= limit {
			break
		}
		if exe != "" && c.Name == exe {
			continue // already there as the exe candidate
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: pid %d maps no file-backed ELF", ErrNoCandidate, pid)
	}
	return out, nil
}

// rootPath resolves a path from /proc/<pid>/maps against the process's own mount namespace (R39). A
// container's libssl is at /usr/lib/.../libssl.so.3 inside the container and nowhere at all in the
// launcher's namespace, so opening the bare path would silently miss every containerized process; ARCHITECTURE
// §9 names /proc/<pid>/root as the way in. A path outside any namespace — the launcher's own processes —
// resolves to the same file either way, because /proc/<pid>/root is then the host root.
func (d *discoverer) rootPath(pid int, path string) string {
	if !strings.HasPrefix(path, "/") {
		return path
	}
	return filepath.Join(d.procPath(pid, "root"), path)
}

// procPath builds /proc/<pid>/<name> against the injected proc filesystem.
func (d *discoverer) procPath(pid int, name string) string {
	return filepath.Join(d.fs.Root(), strconv.Itoa(pid), name)
}
