// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A run's agent runs as the user who owns tego's own state, and no Landlock ABI has a chmod right (CAPABILITIES
// fs.deny_chmod): with no write entry anywhere near them, an agent can still chmod 000 ~/.tego, the per-user config
// layer and tego.log in it, chain.log, the ledger root, its live index, tego's runtime parent ($XDG_RUNTIME_DIR/tego),
// and its own run's directory, runtime directory and the files in them. Neither their contents nor the record change,
// but tego can no longer search, read or write its own files: the run's Close could not fsync its directory or append
// its anchor (exit 125), its summary could not read its ledger, and every later run failed, at the config's load, at
// compile, which could not place the anchor, or making its runtime directory, until the modes were restored by hand
// (GAPS C52). So tego restores them where it needs them, and the ledger says so: `tego run` before anything of the run
// reads them, ~/.tego, the config layer and tego.log before the machine config is read and the rest before the compile
// (RestoreOwnState), `tego gc` the first three before it reads the config, and the run itself all of them at its end,
// before the ledger's Close, once no process of the run is left to take them again (restoreRunState).
//
// A mode is restored only on a directory or a regular file this process owns, of the type tego makes at that name, that
// lacks an owner right tego needs on it: read, write and search on a directory, read and write on a file it writes,
// read on the config layer, which it only reads. Those owner bits are added and no other bit is changed: chmod 000
// becomes 0700 on a directory and 0600 on a file tego writes, the modes tego makes them with, and 0400 on the config
// layer, and a group or other bit stays for the check that judges it. The config trust check (identity-config.md R20)
// refuses a layer, or its directory, that group or others can write, since someone else could have replaced what is in
// it, and the runtime directory's check (agent-contract.md R10a) refuses such a runtime parent for the same reason;
// setting the mode to 0700 would have passed them over a directory that was writable to others until then. A mode that
// keeps the owner's rights is left as it is. Each object is opened O_PATH and O_NOFOLLOW, so a link at its name is
// neither followed nor changed, and its mode is changed through the descriptor's /proc/self/fd link, so the change
// lands on the object checked whatever is renamed meanwhile.
//
// A root launcher restores no mode: it reads and writes through any (CAP_DAC_OVERRIDE). Its agent cannot take the
// modes of the run's own directory, which root makes and holds until Close hands it to the user, nor of a runtime
// directory, since root makes none; what it can take is the user's own state above, which the user's next unprivileged
// `tego run` restores at its start (and `tego gc` the part of it the config is read from). Nothing restores an earlier
// run's directory, whoever launched it.

// runTreeDepth bounds the walk below a run directory at its end: blobs/ is the only directory the writer makes in it.
const runTreeDepth = 2

// The owner rights tego needs on each of its own objects, by what it does with it.
const (
	needDir  uint32 = 0o700 // a directory tego lists, searches and makes entries in
	needFile uint32 = 0o600 // a file tego writes and reads
	needRead uint32 = 0o400 // a file tego only reads: the per-user config layer, which tego never writes
)

// ownPath is one of tego's own objects a restore looks at, with the owner rights tego needs on it by its type: dir when
// a directory is there, file when a regular file is; 0 is a type tego does not make at that name, which is left alone.
type ownPath struct {
	path      string
	dir, file uint32
}

// ModeRestored is one of tego's own files or directories whose mode was restored: its path, and its permission bits
// before and after, as chmod(2) takes them.
type ModeRestored struct {
	Path     string
	From, To uint32
}

// OwnState names the state of tego's own that every run needs, whose modes RestoreOwnState restores; "" names none.
type OwnState struct {
	// Home is the home whose ~/.tego holds the per-user config layer (config.UserRelPath): that directory, and the layer,
	// on which tego needs only read. The machine config is read from it before anything else, so `tego run` and `tego
	// gc` restore it before they read the config: with either taken the run was refused [config-untrusted] before
	// anything was restored, and gc passed the layer over and deleted by the built-in retention.
	Home string
	// Log is tego's own log, ~/.tego/tego.log, which every tego process appends to: with its mode taken, tego's own
	// diagnostics stopped, silently, since the log is best effort.
	Log string
	// Anchor is chain.log; the directory that holds it is restored too.
	Anchor string
	// Root is the ledger root; its live index is restored too.
	Root string
	// RuntimeParent is tego's runtime parent, $XDG_RUNTIME_DIR/tego (RuntimeParent), in which every run of the user
	// makes its runtime directory: with it taken, no later run could make one, and each was refused [run].
	RuntimeParent string
}

// RuntimeParent is the runtime parent a run of this launcher makes its runtime directory in (createRuntimeDir):
// $XDG_RUNTIME_DIR/tego, or "" for a root launcher, which makes none, and for an XDG_RUNTIME_DIR unset or not absolute.
func RuntimeParent() string {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if launcherEUID() == 0 || !filepath.IsAbs(base) {
		return ""
	}
	return filepath.Join(base, agent.RuntimeDirName)
}

// paths is s as RestoreOwnState looks at it: each object with the rights tego needs on it, each directory before what
// it holds, since one whose owner may not search it hides everything beneath it. A path named twice is looked at once.
func (s OwnState) paths() []ownPath {
	var paths []ownPath
	if s.Home != "" {
		home := filepath.Clean(s.Home)
		paths = append(paths, ownPath{path: filepath.Join(home, StateDir), dir: needDir},
			ownPath{path: filepath.Join(home, config.UserRelPath), file: needRead})
	}
	if s.Log != "" {
		paths = append(paths, ownPath{path: filepath.Clean(s.Log), file: needFile})
	}
	if s.Anchor != "" {
		anchor := filepath.Clean(s.Anchor)
		paths = append(paths, ownPath{path: filepath.Dir(anchor), dir: needDir}, ownPath{path: anchor, file: needFile})
	}
	if s.Root != "" {
		root := filepath.Clean(s.Root)
		paths = append(paths, ownPath{path: root, dir: needDir}, ownPath{path: filepath.Join(root, ledger.LiveDir), dir: needDir})
	}
	if s.RuntimeParent != "" {
		paths = append(paths, ownPath{path: filepath.Clean(s.RuntimeParent), dir: needDir})
	}
	return dirsFirst(paths)
}

// dirsFirst sorts paths shortest first, so a directory comes before what it holds, and folds a path named twice into
// one that needs what both did.
func dirsFirst(paths []ownPath) []ownPath {
	slices.SortStableFunc(paths, func(a, b ownPath) int {
		if d := len(a.path) - len(b.path); d != 0 {
			return d
		}
		return strings.Compare(a.path, b.path)
	})
	out := paths[:0]
	for _, p := range paths {
		if n := len(out); n > 0 && out[n-1].path == p.path {
			out[n-1].dir |= p.dir
			out[n-1].file |= p.file
			continue
		}
		out = append(out, p)
	}
	return out
}

// RestoreOwnState restores the modes of s under the rule above. What does not exist is passed over. It returns what it
// restored, and joined the errors it met, which a caller logs and goes on from: the step that then needs the object
// says what is wrong with it.
func RestoreOwnState(s OwnState) ([]ModeRestored, error) {
	if launcherEUID() == 0 {
		return nil, nil
	}
	var out []ModeRestored
	err := restoreModes(s.paths(), &out)
	return out, err
}

// restoreModes restores each path in turn, appending what it restored to out.
func restoreModes(paths []ownPath, out *[]ModeRestored) error {
	var errs []error
	for _, p := range paths {
		if _, err := restoreAt(nil, p.path, p.path, p.dir, p.file, out); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// restoreTree restores, under the rule above, every entry of the directory at dir and, depth-1 levels further down,
// every entry of each directory it holds, a directory before what it holds, appending what it restored to out; dir and
// file are the rights tego needs on a directory and on a file there. A directory that cannot be listed is an error,
// and the walk goes on with the rest.
func restoreTree(dir string, depth int, dirNeed, fileNeed uint32, out *[]ModeRestored) error {
	d, err := sys.Own(unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0))
	if err != nil {
		return &os.PathError{Op: "open", Path: dir, Err: err}
	}
	defer func() { _ = d.Close() }() // an O_PATH descriptor: nothing to report on close
	return restoreBeneath(d, dir, depth, dirNeed, fileNeed, out)
}

// restoreBeneath is restoreTree over the directory open at d, named dir.
func restoreBeneath(d *sys.FD, dir string, depth int, dirNeed, fileNeed uint32, out *[]ModeRestored) error {
	names, err := dirNames(d, dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, name := range names {
		path := filepath.Join(dir, name)
		isDir, err := restoreAt(d, name, path, dirNeed, fileNeed, out)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !isDir || depth <= 1 {
			continue
		}
		sub, err := d.Openat(name, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			errs = append(errs, &os.PathError{Op: "open", Path: path, Err: err})
			continue
		}
		errs = append(errs, restoreBeneath(sub, path, depth-1, dirNeed, fileNeed, out))
		_ = sub.Close() // an O_PATH descriptor, as above
	}
	return errors.Join(errs...)
}

// dirNames lists the directory open at d, named path.
func dirNames(d *sys.FD, path string) ([]string, error) {
	fd, err := d.Openat(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f, err := fd.Release(path)
	if err != nil {
		_ = fd.Close()
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer func() { _ = f.Close() }() // read only
	return f.Readdirnames(-1)
}

// restoreAt restores the mode of name in the directory open at at, or of the path name when at is nil, under the rule
// above, appending it to out when it changed it; path names it in what is reported, and dirNeed and fileNeed are the
// owner rights tego needs on a directory and on a regular file there (0: tego makes none of that type there, and it is
// left alone). It reports whether the object is a directory. Nothing there is not an error.
func restoreAt(at *sys.FD, name, path string, dirNeed, fileNeed uint32, out *[]ModeRestored) (isDir bool, err error) {
	const flags = unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC
	var fd *sys.FD
	if at == nil {
		fd, err = sys.Own(unix.Open(name, flags, 0))
	} else {
		fd, err = at.Openat(name, flags, 0)
	}
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer func() { _ = fd.Close() }() // an O_PATH descriptor, as above
	var st unix.Stat_t
	if err := fd.Fstat(&st); err != nil {
		return false, &os.PathError{Op: "fstat", Path: path, Err: err}
	}
	var need uint32
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		need, isDir = dirNeed, true
	case unix.S_IFREG:
		need = fileNeed
	default: // a link, a FIFO, a socket or a device is nothing tego makes
		return false, nil
	}
	euid := launcherEUID()
	if need == 0 || euid == 0 || int(st.Uid) != euid || st.Mode&need == need {
		return isDir, nil
	}
	// The owner's bits alone: a group or other bit is for the check that judges it, never cleared here.
	to := st.Mode&0o7777 | need
	if err := fd.ProcPath(func(p string) error { return unix.Fchmodat(unix.AT_FDCWD, p, to, 0) }); err != nil {
		return isDir, &os.PathError{Op: "chmod", Path: path, Err: err}
	}
	*out = append(*out, ModeRestored{Path: path, From: st.Mode & 0o7777, To: to})
	return isDir, nil
}

// restoreRunState is shutdown's restore, run just before the ledger's Close, once no process of the run is left to
// change a mode again: the state RestoreOwnState restores, the user's ~/.tego, config layer and tego.log
// (Deps.UserState) and the runtime parent included, then the run's directory and everything the writer made in it,
// and the run's runtime directory, which shutdown removes after Close. Of that one only the directory: the files tego
// makes in it are read-only on purpose (applyProvision), and no file's mode bears on its removal. Each mode it restored
// is a gap line, the last lines before run_end; an error is logged, and Close and the removal then report whatever
// they still cannot do.
func (r *runner) restoreRunState() {
	if launcherEUID() == 0 || r.dir == "" {
		return
	}
	own := OwnState{Home: r.deps.UserState.Home, Log: r.deps.UserState.Log, Anchor: r.anchorFile(), Root: filepath.Dir(r.dir)}
	paths := []ownPath{{path: r.dir, dir: needDir}}
	if r.runtimeDir != "" {
		own.RuntimeParent = filepath.Dir(r.runtimeDir)
		paths = append(paths, ownPath{path: r.runtimeDir, dir: needDir})
	}
	var restored []ModeRestored
	err := restoreModes(dirsFirst(append(own.paths(), paths...)), &restored)
	if terr := restoreTree(r.dir, runTreeDepth, needDir, needFile, &restored); terr != nil {
		err = errors.Join(err, terr)
	}
	if err != nil {
		r.log.Warn("run: restore the modes of tego's own files", "err", err)
	}
	r.recordRestored(restored, r.emitGapNow)
}

// emitOwnStateGap records, right after run_start, each mode the run's caller restored before it (Deps.OwnStateRestored).
func (r *runner) emitOwnStateGap() {
	r.recordRestored(r.deps.OwnStateRestored, r.emitGap)
}

// recordRestored logs each restored mode and writes its gap line, record.GapOwnStateModeRestored naming the path,
// through emit: right after run_start for what the run's caller restored before it (Deps.OwnStateRestored), and as the
// last lines before run_end for what it restored at its end.
func (r *runner) recordRestored(restored []ModeRestored, emit func(source.Gap)) {
	for _, m := range restored {
		r.log.Warn("run: restored the mode of one of tego's own files, which something had taken from its owner",
			"path", m.Path, "from", fmt.Sprintf("%04o", m.From), "to", fmt.Sprintf("%04o", m.To))
		emit(source.Gap{What: record.GapRecord, Why: record.GapOwnStateModeRestored, Binary: m.Path})
	}
}
