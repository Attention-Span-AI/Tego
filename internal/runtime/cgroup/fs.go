// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// fileIDKernfs is the name_to_handle_at handle type cgroup2fs (kernfs) encodes: one u64, the
// cgroup id (linux/exportfs.h FILEID_KERNFS, 5.5+).
const fileIDKernfs = 0xfe

// Removal retry policy for EBUSY (case 9): five attempts over one second.
const (
	removeAttempts = 5
	removeDelay    = 200 * time.Millisecond
)

// controllers are the ones a run needs, in cgroup.subtree_control order.
var controllers = [...]string{ControllerCPU, ControllerMemory, ControllerPids}

// FS is the Manager over a cgroup2 root directory. Values are immutable after construction and
// safe for concurrent use; the only state is the root path.
type FS struct {
	root        string
	privileged  bool
	removeDelay time.Duration
}

// NewAt returns a Manager rooted at root, which must be an existing directory. Detect uses it
// after choosing the root; tests and tegod pass one explicitly. It does not require cgroup2fs:
// on any other filesystem control files simply do not exist, so SetLimits reports every
// controller missing.
func NewAt(root string) (*FS, error) {
	st, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("cgroup: root: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("cgroup: root %s: not a directory", root)
	}
	return &FS{root: filepath.Clean(root), removeDelay: removeDelay}, nil
}

// Root is the directory tego.slice is created under.
func (fs *FS) Root() string { return fs.root }

// Privileged reports whether the root is the cgroup2 mount root of a uid-0 launcher.
func (fs *FS) Privileged() bool { return fs.privileged }

// Create makes tego.slice/tego-<agent>.slice/run-<id>.scope under Root (RUN-IDENTITY.md
// "Cgroup"). The two slices are created if absent and get "+cpu +memory +pids" written to their
// cgroup.subtree_control for every controller the parent offers; a refusal there is not fatal
// because the scope's own cgroup.controllers (recorded on the result) tells SetLimits the truth
// and case 31 diagnoses it then. The scope itself must not exist (ErrCgroupExists). On success the
// scope's O_RDONLY|O_DIRECTORY|O_CLOEXEC fd and cgroup id are filled in; on any failure after the
// mkdir the scope is removed again so nothing half-made survives (case 33).
func (fs *FS) Create(agent, runID string) (Cgroup, error) {
	return fs.create(agent, runID, func(id string) string { return identity.RunScope(identity.RunID(id)) })
}

// CreateScope is Create with the scope named scope instead of run-<id>.scope: an adoption's
// adopt-<id>.scope (internal/watch/adopt.ScopeName), which the sweep and `tego stop` do not take for a
// launched run's and so never kill (ADR 0055). scope must be one path segment ending in
// .scope that is not a launched run's name.
func (fs *FS) CreateScope(agent, runID, scope string) (Cgroup, error) {
	if scope == "" || scope == "." || scope == ".." || strings.ContainsAny(scope, "/\x00") ||
		!strings.HasSuffix(scope, ".scope") || strings.HasPrefix(scope, "run-") {
		return Cgroup{}, fmt.Errorf("%w: scope %q", ErrBadName, scope)
	}
	return fs.create(agent, runID, func(string) string { return scope })
}

// create makes the slices and the scope leaf(runID) names under them (Create).
func (fs *FS) create(agent, runID string, leaf func(runID string) string) (Cgroup, error) {
	aid, err := identity.ParseAgentID(agent)
	if err != nil {
		return Cgroup{}, fmt.Errorf("%w: %v", ErrBadName, err)
	}
	if err := checkRunID(runID); err != nil {
		return Cgroup{}, err
	}
	top := filepath.Join(fs.root, identity.TopSlice)
	slice := filepath.Join(top, identity.AgentSlice(aid))
	// A slice's refusal to enable a controller is not fatal here: the scope's own cgroup.controllers says
	// what is enabled, and SetLimits refuses a limit whose controller is missing (case 31). The refusal is
	// kept per controller for that error, so it names the cause, not only the absence.
	var refused map[string]error
	for _, dir := range []string{top, slice} {
		if err := fs.ensureSlice(dir); err != nil {
			var ce *enableError
			if !errors.As(err, &ce) {
				return Cgroup{}, err
			}
			for ctl, cerr := range ce.refused {
				if refused == nil {
					refused = map[string]error{}
				}
				if _, seen := refused[ctl]; !seen {
					refused[ctl] = cerr
				}
			}
		}
	}
	path := filepath.Join(slice, leaf(runID))
	if err := unix.Mkdir(path, 0o755); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return Cgroup{}, fmt.Errorf("%w: %s: %w", ErrCgroupExists, path, err)
		}
		return Cgroup{}, fmt.Errorf("mkdir(%s): %w", path, err)
	}
	c, err := fs.open(path)
	if err != nil {
		_ = unix.Rmdir(path)
		return Cgroup{}, err
	}
	c.enableRefused = refused
	return c, nil
}

// open fills a Cgroup for an existing scope directory: fd, id and controllers.
func (fs *FS) open(path string) (Cgroup, error) {
	fd, err := sys.Own(unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		return Cgroup{}, fmt.Errorf("open(%s, O_DIRECTORY): %w", path, err)
	}
	c := Cgroup{Path: path, dir: fd}
	id, err := fs.ID(c)
	if err != nil {
		_ = c.Close()
		return Cgroup{}, err
	}
	c.ID = id
	if data, err := readControl(c, fileControllers); err == nil {
		c.Controllers = strings.Fields(string(data))
	}
	return c, nil
}

// checkRunID accepts what identity.RunScope can turn into one path segment. The full id format
// is pkg/spec/identity's rule; this package only refuses what would escape the scope directory.
func checkRunID(runID string) error {
	if runID == "" || len(runID) > 128 || strings.ContainsAny(runID, "/\x00") ||
		runID == "." || runID == ".." {
		return fmt.Errorf("%w: run id %q", ErrBadName, runID)
	}
	return nil
}

// ensureSlice creates dir when absent and enables the run controllers in its subtree_control. A refused
// controller is an *enableError, which Create keeps rather than fails on; any other error is fatal.
func (fs *FS) ensureSlice(dir string) error {
	if err := unix.Mkdir(dir, 0o755); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("mkdir(%s): %w", dir, err)
	}
	return fs.enableControllers(dir)
}

// enableError is the controllers a slice's cgroup.subtree_control refused, each with its own error.
type enableError struct {
	refused map[string]error // controller -> the write's error, which names it
}

// Error lists each refusal.
func (e *enableError) Error() string {
	var parts []string
	for _, c := range controllers {
		if err, ok := e.refused[c]; ok {
			parts = append(parts, err.Error())
		}
	}
	return strings.Join(parts, "; ")
}

// enableControllers writes "+cpu", "+memory" and "+pids" (those dir's cgroup.controllers offers and its
// subtree_control lacks), one write each, so children get the controller files and a refusal names its
// controller. A slice that already holds tasks (EBUSY) or a read-only parent (EACCES) refuses: the
// result is an *enableError, which Create keeps for SetLimits' missing-controller error (case 31) rather
// than failing the run, since the scope's own cgroup.controllers says what is really enabled. A root that is
// no cgroup filesystem (no cgroup.controllers) offers nothing, and nothing is refused.
func (fs *FS) enableControllers(dir string) error {
	avail, err := os.ReadFile(filepath.Join(dir, fileControllers))
	if err != nil {
		return nil
	}
	enabled, _ := os.ReadFile(filepath.Join(dir, fileSubtreeCtl))
	have := fields(avail)
	on := fields(enabled)
	var want []string
	for _, c := range controllers {
		if have[c] && !on[c] {
			want = append(want, "+"+c)
		}
	}
	if len(want) == 0 {
		return nil
	}
	path := filepath.Join(dir, fileSubtreeCtl)
	refused := map[string]error{}
	for _, w := range want {
		if err := writeSubtree(path, w); err != nil {
			refused[strings.TrimPrefix(w, "+")] = fmt.Errorf("cgroup: write %q to %s: %w", w, path, err)
		}
	}
	if len(refused) > 0 {
		return &enableError{refused: refused}
	}
	return nil
}

// writeSubtree writes one "+<controller>" to a cgroup.subtree_control file.
func writeSubtree(path, what string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(what)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// Offered reads root's cgroup.controllers, the controllers root's parent lets it enable, as a set (EnableFix). When
// the file cannot be read it returns nil and the error: nil is EnableFix's "not known", never "offers nothing",
// which an empty file says with an empty set.
func Offered(root string) (map[string]bool, error) {
	data, err := os.ReadFile(filepath.Join(root, fileControllers))
	if err != nil {
		return nil, err
	}
	return fields(data), nil
}

// offeredOrUnknown is Offered without its error, nil (not known) when root's cgroup.controllers cannot be read: the
// refusal it goes into is the error a caller sees, and its fix says that the file was not read.
func offeredOrUnknown(root string) map[string]bool {
	offered, _ := Offered(root)
	return offered
}

// fields turns a space-separated control file into a set.
func fields(data []byte) map[string]bool {
	out := make(map[string]bool)
	for _, w := range strings.Fields(string(data)) {
		out[w] = true
	}
	return out
}

// ID returns the cgroup id of c: the u64 inside name_to_handle_at's FILEID_KERNFS handle
// (5.5+; identical to bpf_get_current_cgroup_id()), falling back to st_ino, which cgroup2fs
// sets to the same value, on any other handle type or an unsupported filesystem.
// It reads the scope's directory under a lease while c's descriptor is open, and c.Path once it is closed.
func (fs *FS) ID(c Cgroup) (uint64, error) {
	var id uint64
	err := c.dir.Borrow(func(n int) error {
		var err error
		id, err = cgroupID(n, "", unix.AT_EMPTY_PATH, c.Path)
		return err
	})
	if errors.Is(err, sys.ErrClosed) {
		id, err = cgroupID(unix.AT_FDCWD, c.Path, 0, c.Path)
	}
	return id, err
}

// cgroupID is ID of name relative to dirfd (flags as name_to_handle_at and fstatat take them); path names
// the cgroup in the error.
func cgroupID(dirfd int, name string, flags int, path string) (uint64, error) {
	h, _, err := unix.NameToHandleAt(dirfd, name, flags)
	if err == nil && h.Type() == fileIDKernfs && len(h.Bytes()) == 8 {
		return binary.NativeEndian.Uint64(h.Bytes()), nil
	}
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, flags); err != nil {
		return 0, fmt.Errorf("stat(%s): %w", path, err)
	}
	return st.Ino, nil
}

// SetLimits writes every non-zero field of l in the order cpu.max, cpu.weight, memory.max,
// memory.swap.max, memory.high, pids.max, one write(2) each (§4). ENOENT on a control file is a
// *MissingControllerError (case 31), except on memory.swap.max, which a kernel without swap accounting does
// not have and which is then skipped: the cap is then exceeded into any active swap, which the caller records
// (UncappedSwap); EINVAL wraps ErrInvalidLimit; both stop at the first failure
// and are fatal to startup for the caller (case 33: the half-configured scope is removed, never
// reused).
func (fs *FS) SetLimits(c Cgroup, l Limits) error {
	for _, f := range limitFiles(l) {
		if err := writeControl(c, f.Name, f.Value); err != nil {
			if f.Optional && errors.Is(err, unix.ENOENT) {
				continue
			}
			return fs.classify(c, f, err)
		}
	}
	return nil
}

// LiftLimits writes every limit file of c back to the kernel's default (liftFiles), one write(2) each, so the
// processes c still holds keep no limit tego set. A file c does not have (its controller is not enabled there) holds
// no limit and is skipped. Every file is tried; the failures are returned joined.
func (fs *FS) LiftLimits(c Cgroup) error {
	var errs []error
	for _, f := range liftFiles() {
		if err := writeControl(c, f.Name, f.Value); err != nil && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, fmt.Errorf("cgroup: lift %s: %w", filepath.Join(c.Path, f.Name), err))
		}
	}
	return errors.Join(errs...)
}

// limitKeys names the contract key behind each control file SetLimits writes, for a refusal's message.
var limitKeys = map[string]string{
	"cpu.max": "limits.cpu", "cpu.weight": "limits.cpu_weight", "memory.max": "limits.memory",
	fileSwapMax: "limits.memory", "memory.high": "limits.memory_high", "pids.max": "limits.pids",
}

// classify maps a control-file write error to the package's error classes.
func (fs *FS) classify(c Cgroup, f limitFile, err error) error {
	path := filepath.Join(c.Path, f.Name)
	var errno unix.Errno
	if errors.As(err, &errno) {
		switch errno {
		case unix.ENOENT:
			return &MissingControllerError{
				Controller: f.Controller, Limit: limitKeys[f.Name], File: path, Root: fs.root,
				// The fix a root launcher must be given is not the one an unprivileged launcher
				// needs; Fix() branches on this rather than naming a systemd drop-in that has no
				// bearing on the cgroup2 mount root.
				Privileged: fs.privileged, Offered: offeredOrUnknown(fs.root), Errno: errno,
				EnableErr: c.enableRefused[f.Controller],
			}
		case unix.EINVAL:
			return fmt.Errorf("cgroup: write %s %q: %w: %w", path, f.Value, ErrInvalidLimit, errno)
		}
	}
	return fmt.Errorf("cgroup: write %s %q: %w", path, f.Value, err)
}

// Kill writes "1" to cgroup.kill (5.14+): SIGKILL to every task in the subtree, delivered
// asynchronously (R10); confirm with WaitEmpty.
//
// ENOENT has two causes and they need different words. The scope directory being gone is the
// ordinary one — the signal killer and the limits watcher both hold a Cgroup that outlives its
// scope, and once Remove has run every copy resolves cgroup.kill through Path, so a signal landing
// after teardown arrives here. cgroup.kill missing from a scope that does exist is the other, and
// it is the only one the kernel floor explains. Reporting both as "needs kernel 5.14" sends an
// operator on a kernel that has had cgroup.kill since 5.14 — which every supported host is —
// looking for a kernel problem behind a race.
func (fs *FS) Kill(c Cgroup) error {
	if err := writeControl(c, fileKill, "1"); err != nil {
		if errors.Is(err, unix.ENOENT) {
			if _, serr := os.Stat(c.Path); errors.Is(serr, os.ErrNotExist) {
				return fmt.Errorf("cgroup: %s: the cgroup no longer exists: %w", c.Path, err)
			}
			return fmt.Errorf("cgroup: %s: cgroup.kill needs kernel 5.14: %w", c.Path, err)
		}
		return fmt.Errorf("cgroup: write %s/cgroup.kill: %w", c.Path, err)
	}
	return nil
}

// WaitEmpty returns once cgroup.events reports populated 0 (or the cgroup is gone), waking on
// inotify and re-reading at least every pollFallback; ctx bounds the wait.
func (fs *FS) WaitEmpty(ctx context.Context, c Cgroup) error {
	// Most callers have already reaped the last task. Avoid creating and tearing
	// down an inotify watch in that case: closing its marks can wait for a kernel
	// grace period. If tasks remain, the loop reads again after arming the watch
	// so an exit between the first read and registration cannot be missed.
	if populated, err := Populated(c); err != nil || !populated {
		return err
	}
	w := newWatcher(filepath.Join(c.Path, fileEvents))
	defer w.close()
	for {
		populated, err := Populated(c)
		if err != nil {
			return err
		}
		if !populated {
			return nil
		}
		if err := w.wait(ctx); err != nil {
			return fmt.Errorf("cgroup: wait empty %s: %w", c.Path, err)
		}
	}
}

// Events emits the populated flag: the state at subscription first, then every transition, until
// ctx ends, when the channel is closed. The goroutine it starts is owned by the returned channel's
// lifetime and exits on ctx; a read error ends the stream the same way. runtime.Run does not call it: it
// is kept because P0-DESIGN.md §2.5 freezes Manager with it, and Run waits on WaitEmpty and polls
// ReadLimitEvents instead (docs/p0/runtime-launch.md §4).
func (fs *FS) Events(ctx context.Context, c Cgroup) (<-chan bool, error) {
	last, err := Populated(c)
	if err != nil {
		return nil, err
	}
	out := make(chan bool, 1)
	out <- last
	w := newWatcher(filepath.Join(c.Path, fileEvents))
	go func() {
		defer close(out)
		defer w.close()
		for {
			if err := w.wait(ctx); err != nil {
				return
			}
			cur, err := Populated(c)
			if err != nil {
				return
			}
			if cur == last {
				continue
			}
			last = cur
			select {
			case out <- cur:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

// OOMKilled reports whether memory.events shows at least one oom_kill in c.
func (fs *FS) OOMKilled(c Cgroup) (bool, error) {
	n, _, err := readCounter(c, fileMemoryEvents, "oom_kill")
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// Remove closes c's fd and removes the scope, deepest descendants first (§4 Remove). rmdir's
// EBUSY (a task in uninterruptible sleep survived SIGKILL) is retried removeAttempts times with
// removeDelay between, then ErrBusy (case 9): the caller logs and leaves it to the sweep. A scope
// that is already gone is not an error. The parent slices stay: they are shared by concurrent runs
// of the same agent and removing one would race a sibling's Create.
//
// A failing close is reported only once the scope is gone: R18 runs every step of teardown however
// the previous one went, so a descriptor that is already closed (a stale copy of the value) must
// never turn "remove the cgroup" into "leak the cgroup".
func (fs *FS) Remove(ctx context.Context, c Cgroup) error {
	closeErr := c.Close()
	if err := fs.removeTree(ctx, c.Path); err != nil {
		return err
	}
	return closeErr
}

// removeTree removes dir and everything under it, bottom-up.
func (fs *FS) removeTree(ctx context.Context, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("readdir(%s): %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			if err := fs.removeTree(ctx, filepath.Join(dir, e.Name())); err != nil {
				return err
			}
		}
	}
	return fs.rmdir(ctx, dir)
}

// rmdir removes one cgroup directory with the case-9 retry.
func (fs *FS) rmdir(ctx context.Context, dir string) error {
	var err error
	for attempt := 0; attempt < removeAttempts; attempt++ {
		if attempt > 0 {
			t := time.NewTimer(fs.removeDelay)
			select {
			case <-ctx.Done():
				t.Stop()
				return fmt.Errorf("rmdir(%s): %w", dir, ctx.Err())
			case <-t.C:
			}
		}
		err = unix.Rmdir(dir)
		switch {
		case err == nil, errors.Is(err, unix.ENOENT):
			return nil
		case errors.Is(err, unix.EBUSY), errors.Is(err, unix.ENOTEMPTY):
			continue
		default:
			return fmt.Errorf("rmdir(%s): %w", dir, err)
		}
	}
	return fmt.Errorf("%w: rmdir(%s): %w", ErrBusy, dir, err)
}

// readControl reads one control file of c relative to its fd (or path when the fd is closed).
func readControl(c Cgroup, name string) ([]byte, error) {
	fd, err := openControl(c, name, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = fd.Close() }()
	var out []byte
	err = fd.Borrow(func(n int) error {
		var buf [4096]byte
		for {
			k, err := unix.Read(n, buf[:])
			if err != nil {
				if errors.Is(err, unix.EINTR) {
					continue
				}
				return err
			}
			if k == 0 {
				return nil
			}
			out = append(out, buf[:k]...)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("read(%s/%s): %w", c.Path, name, err)
	}
	return out, nil
}

// writeControl writes value to one control file of c with a single write(2).
func writeControl(c Cgroup, name, value string) error {
	fd, err := openControl(c, name, true)
	if err != nil {
		return err
	}
	defer func() { _ = fd.Close() }()
	if err := fd.Borrow(func(n int) error {
		_, err := unix.Write(n, []byte(value))
		return err
	}); err != nil {
		return fmt.Errorf("write(%s/%s): %w", c.Path, name, err)
	}
	return nil
}

// openControl opens a control file of c, write-only when write is set and read-only otherwise; the
// returned owner is the caller's to close. It resolves against the scope's directory descriptor, under a
// lease, while that is open (immune to a path that was removed or replaced underneath), and against Path
// once any copy of c has closed it or when c was built by hand (sys.ErrClosed from the directory's owner).
func openControl(c Cgroup, name string, write bool) (*sys.FD, error) {
	var (
		fd  *sys.FD
		err error
	)
	if write {
		fd, err = c.dir.Openat(name, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	} else {
		fd, err = c.dir.Openat(name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	}
	if err == nil {
		return fd, nil
	}
	if !errors.Is(err, sys.ErrClosed) {
		return nil, fmt.Errorf("openat(%s/%s): %w", c.Path, name, err)
	}
	path := filepath.Join(c.Path, name)
	if write {
		fd, err = sys.Own(unix.Open(path, unix.O_WRONLY|unix.O_CLOEXEC, 0))
	} else {
		fd, err = sys.Own(unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0))
	}
	if err != nil {
		return nil, fmt.Errorf("open(%s/%s): %w", c.Path, name, err)
	}
	return fd, nil
}
