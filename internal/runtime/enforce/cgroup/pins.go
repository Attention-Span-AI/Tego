// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
)

// Pin and lock layout (docs/p0/enforce-cgroup-observe.md §3, §5 R14). One bpf_hash names one directory of
// pins and one lock file; every launcher of that build shares them, and two builds never meet:
//
//	/sys/fs/bpf/tego/<bpf_hash>/{maps,progs,links}/<name>
//	<runtime dir>/bpf-<bpf_hash>.lock
//
// The lock is the whole coexistence protocol: every launcher holds it shared for the life of its run, and a
// launcher that is leaving tries to take it exclusively without blocking. Succeeding means nobody else holds
// it, so this launcher is the last one out and unpins; failing means another run is still using the pins and
// is the normal case, not an error (§7).
const (
	// DefaultBPFFS is where pins live when the machine config names nothing else.
	DefaultBPFFS = "/sys/fs/bpf"
	// pinRoot is the directory under the bpf filesystem this project owns.
	pinRoot = "tego"
	// bpffsMagic identifies a bpf filesystem mount; anything else at the pin path is not usable (§6 E30).
	bpffsMagic = int64(unix.BPF_FS_MAGIC)
)

// Subdirectories of one build's pin directory.
const (
	pinMaps  = "maps"
	pinProgs = "progs"
	pinLinks = "links"
	// uprobePins holds the capture probes' links, one directory per library (internal/runtime/capture/uprobe's
	// UprobePinDir, which this package does not import).
	uprobePins = "uprobes"
)

// pinLayout is one build's pin directory, resolved but not yet created.
type pinLayout struct {
	// Base is /sys/fs/bpf/tego, shared by every build and never removed by a single one of them.
	Base string
	// Root is /sys/fs/bpf/tego/<hash>.
	Root string
	// Maps, Progs and Links are its three subdirectories.
	Maps, Progs, Links string
}

// newPinLayout resolves the pin paths for a build hash under a bpf filesystem mount.
func newPinLayout(bpffs, hash string) (pinLayout, error) {
	if hash == "" {
		return pinLayout{}, fmt.Errorf("%w: empty build hash", ErrProgramLoad)
	}
	if !IsBuildHash(hash) {
		return pinLayout{}, fmt.Errorf("%w: build hash %q is not a single path component", ErrProgramLoad, hash)
	}
	if bpffs == "" {
		bpffs = DefaultBPFFS
	}
	base := filepath.Join(bpffs, pinRoot)
	root := filepath.Join(base, hash)
	return pinLayout{
		Base:  base,
		Root:  root,
		Maps:  filepath.Join(root, pinMaps),
		Progs: filepath.Join(root, pinProgs),
		Links: filepath.Join(root, pinLinks),
	}, nil
}

// runLinksPrefix names a run's own link directory under a build's links/: run-<run id> (ADR 0020 (1)).
const runLinksPrefix = "run-"

// runLinks is the directory a run's cgroup links are pinned in, <Links>/run-<id>; "" for a run with no id or
// one that is not a single path component, which pins nothing.
func (p pinLayout) runLinks(id string) string {
	if p.Links == "" || id == "" || strings.ContainsAny(id, "/\x00") || id == "." || id == ".." {
		return ""
	}
	return filepath.Join(p.Links, runLinksPrefix+id)
}

// pinRunLink pins one of a run's cgroup links in dir, made on first use; dir "" pins nothing. A link that
// cannot be pinned fails the attach: unpinned, it would go with the launcher's descriptors (§6 E38).
func pinRunLink(dir string, l interface{ Pin(string) error }, name string) error {
	if dir == "" {
		return nil
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%w: create run link directory %s: %w", ErrProgramLoad, dir, err)
	}
	if err := l.Pin(filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("%w: pin cgroup link %s in %s: %w", ErrProgramLoad, name, dir, err)
	}
	return nil
}

// removeRunLinks unpins every link in a run's link directory (teardown.unpinLink) and removes it; one already gone is
// not an error. A link whose last reference was its pin is detached by the removal; one whose cgroup was removed
// before is already detached, and the removal frees it. td, when not nil, records the links' programs for its wait.
func removeRunLinks(dir string, td *teardown) error {
	if dir == "" {
		return nil
	}
	return errors.Join(removePinDir(dir, td.unpinLink, nil)...)
}

// teardown is one removal of a build's pins, which returns only once the kernel has released the build's links
// (perf-cold C3, roadmap TEARDOWN-SYNC). Removing a link's pin alone left its last reference to the bpf filesystem's
// release of the pin, which the kernel does not do in the removing process: from a workqueue on 6.x (bpf_link_put
// defers there), after an RCU grace period on RHEL 9's 5.14 (bpffs frees its inodes from an RCU callback). A build's
// removal returned while the kernel still released its 17 to 43 links, each fentry, fexit, fmod_ret or lsm one
// holding its trampoline's mutex through the RCU Tasks waits of ftrace's unregistration, and the next run's load
// waited for them in bpf_trampoline_get, 1.4 to 3.3 s of a cold start on 6.17 (enforce-plane §10.1, gate G-H2).
//
// So unpinLink opens each link before it removes the pin and closes that descriptor after, which makes its close(2)
// the last reference where the pin's release is immediate (6.17: bpf_link_release frees the link in the closing
// process), and records the program the link ran. wait, once every pin of the removal is gone and the remover holds
// no descriptor of the build, blocks until the kernel has freed those programs: a program is freed only after every
// link over it has been released, whichever context the kernel released it in.
type teardown struct {
	progs []ebpf.ProgramID
}

// unpinLink removes the link pinned at path, holding a descriptor of it across the removal (teardown). A pin this
// process cannot open as a link (gone, not a link, refused) is removed alone, as before C3, and logs nothing: its
// only effect is the release timing every removal had before, and the removals that reach it have no run log
// (enforce-cgroup-observe R14). The error is the removal's, os.ErrNotExist included, or else the close's. td may be
// nil: nothing is recorded then.
func (td *teardown) unpinLink(path string) error {
	l, lerr := link.LoadPinnedLink(path, nil)
	if lerr == nil && td != nil {
		if info, err := l.Info(); err == nil && info.Program != 0 {
			td.progs = append(td.progs, info.Program)
		}
	}
	err := os.Remove(path)
	if lerr == nil {
		if cerr := l.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close the link: %w", cerr)
		}
	}
	return err
}

// teardownWait bounds teardown.wait. A removal of a build with a plane takes 1 to 6 s on the 6.17 and 5.14 guests; a
// program something outside the removal still holds (an inspecting bpftool) is waited for this long and then left to
// the kernel, as every removal was before C3. A variable for the tests.
var teardownWait = 30 * time.Second

// programHeld reports whether the kernel still holds the program of id; a variable for the tests. Only ENOENT says
// it is gone; an ID this process may not open (not root) is not waited for either.
var programHeld = func(id ebpf.ProgramID) bool {
	p, err := ebpf.NewProgramFromID(id)
	if err != nil {
		return false
	}
	_ = p.Close()
	return true
}

// wait returns once the kernel holds none of the programs td recorded, or after teardownWait, and forgets them. It
// is called after every pin of the removal is gone and the remover's own descriptors of the build are closed: a
// program pinned, or held by the remover, is not freed until then.
func (td *teardown) wait() {
	pending := td.progs
	td.progs = nil
	if len(pending) == 0 {
		return
	}
	deadline := time.Now().Add(teardownWait)
	for pause := time.Millisecond; ; pause = min(2*pause, 20*time.Millisecond) {
		still := pending[:0]
		for _, id := range pending {
			if programHeld(id) {
				still = append(still, id)
			}
		}
		pending = still
		if len(pending) == 0 || !time.Now().Before(deadline) {
			return
		}
		time.Sleep(pause)
	}
}

// checkBPFFS asserts the pin path's mount really is a bpf filesystem before anything is loaded, so a missing
// or misplaced mount is ErrBpffsUnavailable with its own fix rather than an opaque verifier-rejection
// bucket (§6 E30, §7).
func checkBPFFS(bpffs string) error {
	if bpffs == "" {
		bpffs = DefaultBPFFS
	}
	var st unix.Statfs_t
	if err := unix.Statfs(bpffs, &st); err != nil {
		return fmt.Errorf("%w: %s: %w (mount it with: mount -t bpf bpf %s)", ErrBpffsUnavailable, bpffs, err, bpffs)
	}
	if int64(st.Type) != bpffsMagic {
		return fmt.Errorf("%w: %s is not a bpf filesystem (mount it with: mount -t bpf bpf %s)",
			ErrBpffsUnavailable, bpffs, bpffs)
	}
	return nil
}

// create makes the shared base directory, this build's directory and its three subdirectories, in that order:
// bpffs creates one level at a time, so a MkdirAll would fail on it. An EEXIST is the expected concurrent
// case, not a failure — several launchers of one build create the same layout.
func (p pinLayout) create() error {
	for _, dir := range []string{p.Base, p.Root, p.Maps, p.Progs, p.Links} {
		if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: create pin directory %s: %w", ErrBpffsUnavailable, dir, err)
		}
	}
	return nil
}

// remove unpins everything of this build and removes the directories, under the exclusive build lock, tolerating
// anything already gone. It returns once the kernel has released the build's links (teardown), so `gc --builds`, the
// linger timer's sweep, a reaper's and `Prepare`'s sweep leave no detach behind for the next run's load to wait on. A
// removal that failed part way returns at once: what it could not unpin keeps programs the wait would wait out.
func (p pinLayout) remove() error {
	var td teardown
	if err := p.removeAll(&td); err != nil {
		return err
	}
	td.wait()
	return nil
}

// removeAll is remove without the wait, its links' programs recorded in td: the last launcher out, which still holds
// descriptors of the build, waits once it has closed them (bpfKernel.close). The planes' links go first (R20), not
// the tracing links perf-cold C3 put first: the wait covers every recorded program, so the order leaves the same.
func (p pinLayout) removeAll(td *teardown) error {
	var errs []error
	// The build's decision planes first, beside it as <hash>-<mode> (plane.go): their links detach with their pins,
	// and a plane pinned without the build it was loaded over reads maps that are gone. A plane that could not be
	// removed keeps the build's maps too: unpinned under it, the next launcher's run set would be a new map its
	// pinned programs never read (enforce-plane R20).
	if err := removePlaneDirs(p.Base, filepath.Base(p.Root), td); err != nil {
		return err
	}
	// The capture probes pinned per library (ADR 0026 (7)): one directory per library, detaching ones
	// included, each holding link pins only.
	uprobes := filepath.Join(p.Root, uprobePins)
	if libs, err := os.ReadDir(uprobes); err == nil {
		for _, lib := range libs {
			errs = append(errs, removePinDir(filepath.Join(uprobes, lib.Name()), td.unpinLink, nil)...)
		}
		if err := os.Remove(uprobes); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("cgroup: remove %s: %w", uprobes, err))
		}
	}
	// The links first, then the programs, then the maps, and a link that cannot be unpinned keeps the programs and
	// maps it runs over: a removal killed or failing part way then leaves links over maps still pinned, which the
	// next launcher adopts whole. Maps first left links over maps no launcher holds any more, which the next one,
	// re-creating the maps, adopted (attachShared now refuses them; v73 review plane-2).
	if err := p.unpinLinks(td); err != nil {
		return errors.Join(append(errs, err)...)
	}
	for _, dir := range []string{p.Progs, p.Maps} {
		errs = append(errs, removePinDir(dir, os.Remove, nil)...)
	}
	if err := os.Remove(p.Root); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("cgroup: remove %s: %w", p.Root, err))
	}
	return errors.Join(errs...)
}

// unpinLinks unpins every link of the build and removes its links directory: the host-wide ones and what runs
// whose cgroup is gone left (ADR 0020 (1)), their programs recorded in td.
func (p pinLayout) unpinLinks(td *teardown) error {
	return errors.Join(removePinDir(p.Links, td.unpinLink, func(e os.DirEntry) (bool, error) {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), runLinksPrefix) {
			return false, nil
		}
		// A run's own links, left by one whose cgroup is gone: a build is removed only when its run set names no
		// live cgroup.
		return true, removeRunLinks(filepath.Join(p.Links, e.Name()), td)
	})...)
}

// removePinDir unpins every entry of dir with unpin (a teardown's unpinLink for links, os.Remove for programs and
// maps) and removes dir, tolerating anything already gone. special, when it reports an entry handled, removes that
// entry itself.
func removePinDir(dir string, unpin func(string) error, special func(os.DirEntry) (bool, error)) []error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return []error{fmt.Errorf("cgroup: list %s: %w", dir, err)}
		}
		return nil
	}
	var errs []error
	for _, e := range entries {
		if special != nil {
			if handled, err := special(e); handled {
				if err != nil {
					errs = append(errs, err)
				}
				continue
			}
		}
		if err := unpin(filepath.Join(dir, e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("cgroup: unpin %s/%s: %w", dir, e.Name(), err))
		}
	}
	if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Errorf("cgroup: remove %s: %w", dir, err))
	}
	return errs
}

// buildLock is one launcher's hold on a build's shared pins. It is held shared for the whole run and
// converted, without blocking, to exclusive at teardown to find out whether this launcher is the last out.
type buildLock struct {
	path string
	f    *os.File
}

// acquireBuildLockIn is acquireBuildLock in a verified state directory (ADR 0034): the file is opened relative
// to its descriptor, never through a link.
func acquireBuildLockIn(d *hoststate.Dir, hash string) (*buildLock, error) {
	name := "bpf-" + hash + ".lock"
	path := filepath.Join(d.Path(), name)
	for range 8 {
		f, err := d.OpenFile(name, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, fmt.Errorf("%w: open %s: %w", ErrBuildLock, path, err)
		}
		if err := unix.Flock(int(f.Fd()), unix.LOCK_SH); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("%w: shared lock on %s: %w", ErrBuildLock, path, err)
		}
		// A gone build's lock file is removed by its holder (removeStaleState): one opened just before that is
		// no longer the build's lock, and holding it would let another launcher hold the new one alone.
		if d.Names(name, f) {
			return &buildLock{path: path, f: f}, nil
		}
		_ = f.Close()
	}
	return nil, fmt.Errorf("%w: %s kept being removed under this launcher", ErrBuildLock, path)
}

// lockBuildExclusiveNB takes build hash's lock exclusively without blocking, for a sweep, a reaper or a probe that
// must know no launcher of the build is preparing, running or leaving. It opens the lock file, creating it when
// create, and returns it held; busy means a launcher holds it. With create false a build with no lock file is an
// error wrapping os.ErrNotExist.
//
// Once it holds the lock it checks that the name still leads to that file, as acquireBuildLockIn does: a gone
// build's lock is unlinked by its holder (removeStaleState), so a file opened just before that is no longer the
// build's lock, and holding it exclusively said nothing of the launcher that has since created and holds the new
// one. It opens the name again then; a name that keeps being replaced reads as busy.
func lockBuildExclusiveNB(d *hoststate.Dir, hash string, create bool) (f *os.File, busy bool, err error) {
	name := "bpf-" + hash + ".lock"
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE
	}
	for range 8 {
		f, err := d.OpenFile(name, flags, 0o600)
		if err != nil {
			return nil, false, err
		}
		buildLockOpened(name, f)
		if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			_ = f.Close()
			if errors.Is(err, unix.EWOULDBLOCK) {
				return nil, true, nil
			}
			return nil, false, fmt.Errorf("%w: exclusive lock on %s: %w", ErrBuildLock, filepath.Join(d.Path(), name), err)
		}
		if d.Names(name, f) {
			return f, false, nil
		}
		_ = f.Close()
	}
	return nil, true, nil
}

// unlockClose lets go the flock f holds, then closes f. A close alone drops an flock only with the last descriptor
// of its open file description, and a child that any goroutine of this process forks while f is open holds a copy
// of that descriptor until its exec closes it (every lock file here is opened close-on-exec): the lock outlived
// the look that took it for that long, and a timer's probe in that moment found the build still held and backed off
// a whole linger (ADR 0022 (8)). LOCK_UN releases the description's lock whatever copies of it live.
func unlockClose(f *os.File) {
	_ = sys.Flock(f, unix.LOCK_UN) // best effort: the close below releases it too, once no copy is left
	_ = f.Close()
}

// buildLockOpened runs between lockBuildExclusiveNB's open and its flock; a test replaces it to remove and recreate
// the lock file in that window, or to hand a copy of the opened file to a child as a fork there does.
var buildLockOpened = func(string, *os.File) {}

// lastOut converts the hold to exclusive without blocking. True means no other launcher of this build is
// running and the caller may unpin; false is the ordinary multi-run case and not an error (§7). Only a
// departing launcher asks (Detach, and a failed Prepare's release).
//
// On true the lock stays exclusive until Close, deliberately: downgrading first would let a launcher starting
// at that instant attach to pins this one is about to remove. On false the caller holds nothing: Linux
// converts an flock by dropping the shared hold before it tries the exclusive one (flock(2)), and this used to
// take the shared hold back, so two launchers of one build leaving together each found the other's hold and
// both answered false, and nobody unpinned: the build's host-wide links and ring stayed attached until some
// later launcher of the same hash left last, which after an upgrade is never (I10). Holding
// nothing, the second to ask finds the lock free.
func (l *buildLock) lastOut() (bool, error) {
	if l == nil || l.f == nil {
		return false, nil
	}
	err := unix.Flock(int(l.f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
		return false, nil
	}
	return false, fmt.Errorf("%w: exclusive lock on %s: %w", ErrBuildLock, l.path, err)
}

// Close releases the lock. The kernel drops an flock when the last descriptor closes, so a launcher that is
// killed can never leave one behind.
func (l *buildLock) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	f := l.f
	l.f = nil
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	if err := f.Close(); err != nil {
		return fmt.Errorf("cgroup: close build lock %s: %w", l.path, err)
	}
	return nil
}
