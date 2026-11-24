// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func readLayer(path string, layer Layer, uid int) ([]byte, bool, error) {
	return readLayerBounded(path, layer, uid, MaxLayerSize)
}

// readLayerBounded is readLayer with a per-layer byte limit no larger than MaxLayerSize (LoadSourcesBounded).
func readLayerBounded(path string, layer Layer, uid int, maxBytes int64) ([]byte, bool, error) {
	if layer != LayerEtc {
		return readTrustedBounded(path, uid, maxBytes)
	}
	data, absent, err := readSystemTrustedAt("/", path, 0, uid, maxBytes)
	var ue *UntrustedError
	if errors.As(err, &ue) {
		ue.system = true
	}
	return data, absent, err
}

// readSystemTrustedAt checks system placement using metadata only (I10). Starting at the trusted
// root, each directory must exclude non-root changes before the walk descends through it. Thus a
// non-root user cannot replace a later name between its Lstat and the final open. The opened file
// must match the walk, and its immediate directory is bound to that descriptor by readTrustedFile.
// Rechecking the walk catches replacement or permission changes by the trusted authority too.
// root and rootUID let unprivileged tests model the same checks within a fixture tree.
func readSystemTrustedAt(root, path string, rootUID, uid int, maxBytes int64) ([]byte, bool, error) {
	walk, absent, err := inspectSystemLayer(root, path, rootUID)
	if err != nil {
		return nil, false, err
	}
	if err := walk.recheck(); err != nil {
		return nil, false, err
	}
	if absent {
		return nil, true, nil
	}
	f, err := os.OpenFile(walk.resolved, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, false, fmt.Errorf("config: open system layer %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	st, err := fstat(f)
	if err != nil {
		return nil, false, fmt.Errorf("config: fstat %s: %w", path, err)
	}
	if !sameSystemComponent(st, walk.file) {
		return nil, false, untrusted(path, st, reasonSystemReplaced)
	}
	if err := walk.recheck(); err != nil {
		return nil, false, err
	}
	data, _, err := readTrustedFile(f, path, uid, maxBytes)
	if err != nil {
		return nil, false, err
	}
	if err := walk.recheck(); err != nil {
		return nil, false, err
	}
	return data, false, nil
}

// systemLayerWalk shares one symlink resolver for configuration and account evidence.
// Account readers retain its file and ancestor descriptors through both passes.
type systemLayerWalk struct {
	resolved string
	file     *syscall.Stat_t
	checks   []systemComponent
	missing  string
	opened   []*os.File
	pinned   []systemComponent
	roots    []*os.Root
	observe  func(string, *syscall.Stat_t) *syscall.Stat_t
}

type systemComponent struct {
	path string
	stat *syscall.Stat_t
}

const reasonSystemReplaced = "system layer placement was replaced or changed while it was being checked"

func inspectSystemLayer(root, path string, rootUID int) (systemLayerWalk, bool, error) {
	return inspectPolicyLayer(root, path, rootUID, true)
}

func inspectPolicyLayer(root, path string, rootUID int, system bool) (systemLayerWalk, bool, error) {
	return inspectPolicyLayerWalk(root, path, rootUID, system, false, nil)
}

// OpenSystemFileAt reuses the system placement resolver and retains the verified
// descriptors until Close. Production callers use root "/" and rootUID 0;
// controlled fixtures can model root ownership without privileges.
// It requires a regular readable file and root-owned placement with no group or
// other write bits, including resolved link targets. It never reads file bytes.
func OpenSystemFileAt(root, path string, rootUID int) (*SystemFile, error) {
	return openSystemFileAt(root, path, rootUID, nil)
}

// observe supplies controlled ownership facts only from same-package tests.
func openSystemFileAt(root, path string, rootUID int, observe func(string, *syscall.Stat_t) *syscall.Stat_t) (*SystemFile, error) {
	w, absent, err := inspectSystemLayerWalk(root, path, rootUID, true, observe)
	if absent && err == nil {
		err = os.ErrNotExist
	}
	if err == nil {
		err = w.recheck()
	}
	if err != nil {
		_ = w.close()
		return nil, fmt.Errorf("system file %s: %w", path, err)
	}
	return &SystemFile{File: w.opened[len(w.opened)-1], walk: w}, nil
}

// SystemFile holds a verified file and its placement descriptors. The caller
// reads File, calls Recheck after reading and closes the whole object once.
type SystemFile struct {
	File *os.File
	walk systemLayerWalk
}

// Recheck refuses changed descriptor or pathname placement.
func (f *SystemFile) Recheck() error { return f.walk.recheck() }

// PathInfo observes the resolved final pathname for the caller's identity comparison.
func (f *SystemFile) PathInfo() (os.FileInfo, error) { return os.Lstat(f.walk.resolved) }

// Close releases all file and ancestor descriptors, reporting close errors.
func (f *SystemFile) Close() error { return f.walk.close() }

func (w systemLayerWalk) close() (err error) {
	for _, f := range w.opened {
		if e := f.Close(); err == nil {
			err = e
		}
	}
	for _, r := range w.roots {
		if e := r.Close(); err == nil {
			err = e
		}
	}
	return err
}

// Configuration and general sources retain metadata-only ancestor inspection.
// Account evidence pins descriptors using the same resolver and trust checks.
func inspectSystemLayerWalk(root, path string, rootUID int, pin bool, observe func(string, *syscall.Stat_t) *syscall.Stat_t) (systemLayerWalk, bool, error) {
	return inspectPolicyLayerWalk(root, path, rootUID, true, pin, observe)
}

func inspectPolicyLayerWalk(root, path string, rootUID int, system, pin bool, observe func(string, *syscall.Stat_t) *syscall.Stat_t) (systemLayerWalk, bool, error) {
	modeReason := func(st *syscall.Stat_t) string {
		if system {
			return systemModeReason(st, rootUID)
		}
		return ownerModeReason(st, rootUID)
	}
	ownerReason := func(st *syscall.Stat_t) string {
		if system {
			return systemOwnerReason(st, rootUID)
		}
		if st.Uid != 0 && int(st.Uid) != rootUID {
			return "policy source link belongs to another owner"
		}
		return ""
	}
	walk := systemLayerWalk{observe: observe}
	root = filepath.Clean(root)
	var dirs map[string]*os.Root
	var dirFiles map[string]*os.File
	linkBytesLeft := 128 << 10
	var st *syscall.Stat_t
	var err error
	if pin {
		r, e := os.OpenRoot(root)
		if e != nil {
			return walk, false, e
		}
		walk.roots = append(walk.roots, r)
		dirs = map[string]*os.Root{"/": r}
		rootFile, e := r.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK, 0)
		if e != nil {
			return walk, false, e
		}
		walk.opened = append(walk.opened, rootFile)
		dirFiles = map[string]*os.File{"/": rootFile}
		st, err = fstat(rootFile)
	} else {
		st, err = lstatSystem(root)
	}
	if err != nil {
		return walk, false, fmt.Errorf("config: inspect system root: %w", err)
	}
	if observe != nil {
		st = observe(root, st)
	}
	if why := modeReason(st); why != "" {
		return walk, false, untrusted(root, st, why)
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return walk, false, untrusted(root, st, "not a system layer directory")
	}
	walk.checks = append(walk.checks, systemComponent{root, st})
	walk.pinned = append(walk.pinned, systemComponent{root, st})
	pending, resolved, links := layerSteps(path, false), "/", 0
	components := 0
	for len(pending) > 0 {
		step := pending[0]
		pending = pending[1:]
		if step.name == "" || step.name == "." {
			continue
		}
		components++
		if pin && components > 512 {
			return walk, false, fmt.Errorf("system placement %s: component limit reached", path)
		}
		if step.name == ".." {
			resolved = filepath.Dir(resolved)
		} else {
			resolved = filepath.Join(resolved, step.name)
		}
		if pin && len(resolved) > 4096 {
			return walk, false, fmt.Errorf("system placement %s: path length limit reached", path)
		}
		comp := filepath.Join(root, resolved)
		parent, name := dirs[filepath.Dir(resolved)], filepath.Base(resolved)
		if step.name == ".." {
			parent, name = dirs[resolved], "."
		}
		if pin && parent == nil {
			return walk, false, fmt.Errorf("system placement %s: unverified parent", comp)
		}
		var fi os.FileInfo
		var err error
		if pin {
			fi, err = parent.Lstat(name)
		} else {
			fi, err = os.Lstat(comp)
		}
		var st *syscall.Stat_t
		if err == nil {
			var ok bool
			st, ok = fi.Sys().(*syscall.Stat_t)
			if !ok {
				err = errors.New("no Stat_t in FileInfo")
			}
		}
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && !step.linkTarget {
				walk.missing = comp
				return walk, true, nil
			}
			return walk, false, fmt.Errorf("config: system layer %s: %w", path, err)
		}
		if observe != nil {
			st = observe(comp, st)
		}
		walk.checks = append(walk.checks, systemComponent{comp, st})
		if st.Mode&syscall.S_IFMT == syscall.S_IFLNK {
			if why := ownerReason(st); why != "" {
				return walk, false, untrusted(comp, st, why)
			}
			links++
			if links > maxProcHops {
				return walk, false, fmt.Errorf("config: system layer %s: %w", path, syscall.ELOOP)
			}
			var target string
			var err error
			if pin {
				target, err = readSystemLink(dirFiles[filepath.Dir(resolved)], name, &linkBytesLeft)
			} else {
				target, err = os.Readlink(comp)
			}
			if err != nil {
				return walk, false, fmt.Errorf("config: system layer %s: read link %s: %w", path, comp, err)
			}
			if filepath.IsAbs(target) {
				resolved = "/"
			} else {
				resolved = filepath.Dir(resolved)
			}
			pending = append(layerSteps(target, true), pending...)
			continue
		}
		if why := modeReason(st); why != "" {
			return walk, false, untrusted(comp, st, why)
		}
		if st.Mode&syscall.S_IFMT == syscall.S_IFDIR && len(pending) > 0 {
			if !pin {
				continue
			}
			next, err := parent.OpenRoot(name)
			if err != nil {
				return walk, false, fmt.Errorf("system directory %s: %w", comp, err)
			}
			walk.roots = append(walk.roots, next)
			f, err := next.OpenFile(".", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK, 0)
			if err != nil {
				return walk, false, err
			}
			walk.opened = append(walk.opened, f)
			pinned, err := fstat(f)
			if err != nil {
				return walk, false, err
			}
			if observe != nil {
				pinned = observe(comp, pinned)
			}
			if !sameSystemComponent(st, pinned) {
				return walk, false, untrusted(comp, pinned, reasonSystemReplaced)
			}
			walk.pinned = append(walk.pinned, systemComponent{comp, st})
			dirs[resolved] = next
			dirFiles[resolved] = f
			continue
		}
		if len(pending) > 0 || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
			return walk, false, untrusted(path, st, "not a regular system layer file")
		}
		if system && st.Mode&0o444 != 0o444 {
			return walk, false, untrusted(path, st, "system layer must be readable by governed users (normally 0644)")
		}
		if pin {
			f, err := parent.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
			if err != nil {
				return walk, false, fmt.Errorf("system file %s: %w", comp, err)
			}
			walk.opened = append(walk.opened, f)
			pinned, err := fstat(f)
			if err != nil {
				return walk, false, err
			}
			if observe != nil {
				pinned = observe(comp, pinned)
			}
			if !sameSystemComponent(st, pinned) {
				return walk, false, untrusted(comp, pinned, reasonSystemReplaced)
			}
			walk.pinned = append(walk.pinned, systemComponent{comp, st})
		}
		walk.resolved, walk.file = comp, st
		return walk, false, nil
	}
	return walk, false, fmt.Errorf("config: system layer %s is not a regular file", path)
}

// readSystemLink bounds descriptor-walk link input, including a truncated
// probe. Six account walks consume at most 768 KiB of link text in total.
func readSystemLink(parent *os.File, name string, left *int) (string, error) {
	if *left <= 0 {
		return "", errors.New("system placement symlink input limit reached")
	}
	var buffer [4096]byte
	size := min(len(buffer), *left)
	raw, err := parent.SyscallConn()
	if err != nil {
		return "", err
	}
	var n int
	var readErr error
	if err := raw.Control(func(fd uintptr) { n, readErr = unix.Readlinkat(int(fd), name, buffer[:size]) }); err != nil {
		return "", err
	}
	// Failed calls consume the whole allowance for that probe.
	if readErr != nil {
		*left -= size
		return "", readErr
	}
	*left -= n
	if n == size {
		return "", errors.New("system placement symlink target or input limit reached")
	}
	return string(buffer[:n]), nil
}

func (w systemLayerWalk) recheck() error {
	for i, c := range w.pinned {
		// Configuration did not request ancestor descriptors.
		if len(w.opened) == 0 {
			break
		}
		st, err := fstat(w.opened[i])
		if err != nil {
			return fmt.Errorf("system placement %s: %w", c.path, err)
		}
		if w.observe != nil {
			st = w.observe(c.path, st)
		}
		if !sameSystemComponent(st, c.stat) {
			return untrusted(c.path, st, reasonSystemReplaced)
		}
	}
	for _, c := range w.checks {
		st, err := lstatSystem(c.path)
		if err != nil {
			return fmt.Errorf("config: recheck system placement %s: %w", c.path, err)
		}
		if w.observe != nil {
			st = w.observe(c.path, st)
		}
		if !sameSystemComponent(st, c.stat) {
			return untrusted(c.path, st, reasonSystemReplaced)
		}
	}
	if w.missing != "" {
		if _, err := os.Lstat(w.missing); !errors.Is(err, fs.ErrNotExist) {
			if err == nil {
				err = errors.New("name appeared")
			}
			return fmt.Errorf("config: absent system layer %s changed while checking: %w", w.missing, err)
		}
	}
	return nil
}

func sameSystemComponent(a, b *syscall.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Uid == b.Uid && a.Mode == b.Mode
}

func lstatSystem(path string) (*syscall.Stat_t, error) {
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func systemModeReason(st *syscall.Stat_t, rootUID int) string {
	if why := systemOwnerReason(st, rootUID); why != "" {
		return why
	}
	if st.Mode&groupOtherWrite != 0 {
		return "system layer placement is group or other writable"
	}
	if st.Mode&syscall.S_IFMT == syscall.S_IFDIR && st.Mode&0o111 != 0o111 {
		return "system layer directory must be searchable by governed users"
	}
	return ""
}

// linkTarget distinguishes an absent layer name from an existing dangling link.
type layerStep struct {
	name       string
	linkTarget bool
}

func layerSteps(path string, linkTarget bool) []layerStep {
	var steps []layerStep
	for _, name := range strings.Split(path, "/") {
		steps = append(steps, layerStep{name, linkTarget})
	}
	return steps
}

// layerAbsent distinguishes missing optional names from a dangling link anywhere in the walk.
// It runs only after open returned ENOENT. A name that reappeared is uncertainty, not absence.
func layerAbsent(path string) (bool, error) {
	pending, resolved, links := layerSteps(path, false), "/", 0
	for len(pending) > 0 {
		step := pending[0]
		pending = pending[1:]
		if step.name == "" || step.name == "." {
			continue
		}
		comp := strings.TrimSuffix(resolved, "/") + "/" + step.name
		fi, err := os.Lstat(comp)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && !step.linkTarget {
				return true, nil
			}
			return false, err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			links++
			if links > maxProcHops {
				return false, syscall.ELOOP
			}
			target, err := os.Readlink(comp)
			if err != nil {
				return false, err
			}
			if strings.HasPrefix(target, "/") {
				resolved = "/"
			}
			pending = append(layerSteps(target, true), pending...)
			continue
		}
		if len(pending) > 0 && !fi.IsDir() {
			return false, syscall.ENOTDIR
		}
		resolved = comp
	}
	return false, fmt.Errorf("layer appeared while checking absence")
}

// Symlinks need root ownership, but their conventional 0777 mode grants no write authority.
func systemOwnerReason(st *syscall.Stat_t, rootUID int) string {
	if int(st.Uid) != rootUID {
		return "system layer placement is not root-owned"
	}
	return ""
}
