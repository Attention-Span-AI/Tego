// SPDX-License-Identifier: Apache-2.0

package proc

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// DefaultRoot is where a Linux system mounts proc(5).
const DefaultRoot = "/proc"

// maxFileSize caps every /proc file this package slurps. The kernel generates these files on
// demand, so a hostile or pathological process (a megabyte of argv, tens of thousands of mappings)
// must not be able to make a reader allocate without bound.
const maxFileSize = 1 << 20

// ErrGone is a pid that no longer exists, or that exited between two of the reads one Process needs.
// It is the expected outcome of racing a short-lived process, not a failure: callers record the
// event with a degraded attribution rather than failing the run
// (docs/p0/enforce-cgroup-observe.md §7).
var ErrGone = errors.New("proc: process is gone")

// FS reads one mounted proc filesystem. The zero value is unusable; use New or NewAt. It holds no
// fd and no state, so one value is safe for concurrent use.
type FS struct{ root string }

// New reads the system's /proc.
func New() *FS { return &FS{root: DefaultRoot} }

// NewAt reads a proc filesystem mounted elsewhere, or a directory tree that imitates one — what the
// tests in this repository use instead of spawning processes.
func NewAt(root string) *FS { return &FS{root: root} }

// Root is the directory this FS reads.
func (f *FS) Root() string {
	if f == nil || f.root == "" {
		return DefaultRoot
	}
	return f.root
}

// Process is one process as /proc describes it, enough to stamp an exec event and build an exec id.
// Every field past PID is best-effort: a field whose file could not be read is left at its zero
// value rather than failing the whole read, because a half-known process still attributes events
// better than none. Err records the first such partial failure for the caller's diagnostics.
type Process struct {
	PID         int
	PPID        int
	Comm        string   // kernel comm, at most 15 bytes
	State       byte     // R, S, D, Z, ...
	StartTicks  uint64   // /proc/<pid>/stat field 22, USER_HZ ticks since boot
	StartBootNS uint64   // StartTicks in nanoseconds; see Stat.StartBootNS on its resolution
	Exe         string   // readlink /proc/<pid>/exe; "" for a kernel thread or a raced exit
	Argv        []string // /proc/<pid>/cmdline, NUL-separated
	Cwd         string   // readlink /proc/<pid>/cwd; "" when not permitted
	Cgroup      string   // the unified hierarchy path, "" on a v1-only host
	Err         error    // the first partial failure, nil when everything was read
}

// Process reads one pid. It returns ErrGone when the process does not exist or vanishes during the
// read, and a wrapped ErrStat when its stat line is unparsable; a missing exe, cwd or cgroup only
// sets Process.Err.
func (f *FS) Process(pid int) (Process, error) {
	st, err := f.Stat(pid)
	if err != nil {
		return Process{}, err
	}
	p := Process{
		PID:         st.PID,
		PPID:        st.PPID,
		Comm:        st.Comm,
		State:       st.State,
		StartTicks:  st.StartTicks,
		StartBootNS: st.StartBootNS(),
	}
	var partial error
	keep := func(err error) {
		if err != nil && partial == nil {
			partial = err
		}
	}
	exe, err := f.Exe(pid)
	keep(err)
	p.Exe = exe
	argv, err := f.Argv(pid)
	if errors.Is(err, ErrGone) {
		return Process{}, err
	}
	keep(err)
	p.Argv = argv
	cwd, err := f.Cwd(pid)
	keep(err)
	p.Cwd = cwd
	cg, err := f.Cgroup(pid)
	if errors.Is(err, ErrGone) {
		return Process{}, err
	}
	keep(err)
	p.Cgroup = cg
	p.Err = partial
	return p, nil
}

// Stat reads and parses /proc/<pid>/stat.
func (f *FS) Stat(pid int) (Stat, error) {
	b, err := f.read(pid, "stat")
	if err != nil {
		return Stat{}, err
	}
	st, err := ParseStat(b)
	if err != nil {
		return Stat{}, fmt.Errorf("proc: pid %d: %w", pid, err)
	}
	return st, nil
}

// Argv reads /proc/<pid>/cmdline.
func (f *FS) Argv(pid int) ([]string, error) {
	b, err := f.read(pid, "cmdline")
	if err != nil {
		return nil, err
	}
	return ParseArgv(b), nil
}

// Cgroup reads the unified-hierarchy cgroup path of a pid, "" on a v1-only host.
func (f *FS) Cgroup(pid int) (string, error) {
	b, err := f.read(pid, "cgroup")
	if err != nil {
		return "", err
	}
	return ParseCgroup(b), nil
}

// Exe resolves /proc/<pid>/exe, the binary the process is running. A kernel thread has no exe and
// yields "" with no error (link treats an absent link on a live pid as absent, not gone); a process
// whose binary was deleted yields the path with the kernel's " (deleted)" suffix stripped, which is
// what a contract rule names.
func (f *FS) Exe(pid int) (string, error) {
	target, err := f.link(pid, "exe")
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(target, " (deleted)"), nil
}

// Cwd resolves /proc/<pid>/cwd, the process's working directory as this process's root sees it; "" when the
// link is absent on a live pid.
func (f *FS) Cwd(pid int) (string, error) { return f.link(pid, "cwd") }

// PIDs lists every numeric entry of the proc root, the process set a cache rebuilds from.
func (f *FS) PIDs() ([]int, error) {
	ents, err := os.ReadDir(f.Root())
	if err != nil {
		return nil, fmt.Errorf("proc: read %s: %w", f.Root(), err)
	}
	pids := make([]int, 0, len(ents))
	for _, e := range ents {
		n, err := strconv.Atoi(e.Name())
		if err != nil || n <= 0 {
			continue
		}
		pids = append(pids, n)
	}
	sort.Ints(pids)
	return pids, nil
}

// Tasks lists the thread ids of process pid, its leader's included (/proc/<pid>/task), sorted; ErrGone when the
// process has no directory left.
func (f *FS) Tasks(pid int) ([]int, error) {
	ents, err := os.ReadDir(filepath.Join(f.Root(), strconv.Itoa(pid), "task"))
	if err != nil {
		return nil, f.wrap(pid, "task", err)
	}
	tids := make([]int, 0, len(ents))
	for _, e := range ents {
		if tid, err := strconv.Atoi(e.Name()); err == nil && tid > 0 {
			tids = append(tids, tid)
		}
	}
	sort.Ints(tids)
	return tids, nil
}

// Libraries lists the distinct file-backed shared objects a process has mapped, sorted. It is how
// capture/uprobe finds the libssl a process actually loaded (docs/p0/capture-derive.md §5); an
// anonymous, special ([heap], [stack]) or deleted mapping is skipped.
func (f *FS) Libraries(pid int) ([]string, error) {
	b, err := f.read(pid, "maps")
	if err != nil {
		return nil, err
	}
	return ParseMaps(b), nil
}

// ParseMaps extracts the distinct file-backed mapping paths of a /proc/<pid>/maps blob, sorted.
// Pure and total (fuzzed by FuzzParseMaps): a truncated final line is ignored, a path containing
// spaces is kept whole because the path is the rest of the line after five whitespace-separated
// columns.
func ParseMaps(b []byte) []string {
	seen := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		// address perms offset dev inode path
		rest := line
		for i := 0; i < 5; i++ {
			rest = strings.TrimLeft(rest, " \t")
			j := strings.IndexAny(rest, " \t")
			if j < 0 {
				rest = ""
				break
			}
			rest = rest[j:]
		}
		path := strings.TrimLeft(rest, " \t")
		if path == "" || path[0] != '/' || strings.HasSuffix(path, " (deleted)") {
			continue
		}
		seen[path] = true
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// read slurps one per-process file, capped at maxFileSize and mapping a vanished process to ErrGone.
func (f *FS) read(pid int, name string) ([]byte, error) {
	path := filepath.Join(f.Root(), strconv.Itoa(pid), name)
	file, err := os.Open(path)
	if err != nil {
		return nil, f.wrap(pid, name, err)
	}
	defer func() { _ = file.Close() }()
	return f.slurp(pid, name, file)
}

// slurp reads an opened per-process file up to maxFileSize. A process reaped after the open makes
// the read fail with ESRCH, which wrap maps to ErrGone like a failed open.
func (f *FS) slurp(pid int, name string, file io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(file, maxFileSize))
	if err != nil {
		return nil, f.wrap(pid, name, err)
	}
	return b, nil
}

// link resolves one per-process symlink. A link that is absent while the pid directory is still
// there is not an error: a kernel thread has no exe and no cwd. A link that is absent because the
// whole directory went away is ErrGone, and a permission denial is a wrapped error the caller may
// downgrade to a partial read.
func (f *FS) link(pid int, name string) (string, error) {
	path := filepath.Join(f.Root(), strconv.Itoa(pid), name)
	target, err := os.Readlink(path)
	if err == nil {
		return target, nil
	}
	var pe *fs.PathError
	if errors.As(err, &pe) && errors.Is(pe.Err, os.ErrInvalid) {
		return "", nil // a directory stub in a test tree, not a symlink
	}
	if errors.Is(err, os.ErrNotExist) && f.alive(pid) {
		return "", nil
	}
	return "", f.wrap(pid, name, err)
}

// alive reports whether the pid still has a directory under the proc root.
func (f *FS) alive(pid int) bool {
	_, err := os.Stat(filepath.Join(f.Root(), strconv.Itoa(pid)))
	return err == nil
}

// wrap turns a not-found into ErrGone and everything else into a located error. ESRCH counts as
// not-found: the kernel returns it from a read on a file opened before the process was reaped.
func (f *FS) wrap(pid int, name string, err error) error {
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("proc: pid %d: %s: %w", pid, name, ErrGone)
	}
	return fmt.Errorf("proc: pid %d: %s: %w", pid, name, err)
}
