// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/presets"
)

// CheckEnv is the machine a composed contract is checked against. The caller supplies it, so this package reads no
// machine config and holds no engine code: `tego init` passes the machine config it loaded and the options
// `tego compile` uses (PATH, home, the tiers its binary builds, the chain anchor); a dashboard passes its own.
type CheckEnv struct {
	// Machine is the machine config; nil is config.Builtin().
	Machine *config.Machine
	// Profiles resolves the contract's extends: names; nil is the built-in presets alone, which is all a composed
	// contract names.
	Profiles agent.ProfileSource
	// Options are added to the compile's own (Offline and the project directory as the cwd); WithPATH belongs here,
	// since without it no command basename resolves.
	Options []agent.CompileOption
}

// Check loads contract as the agent.yaml in dir and compiles it offline, as `tego compile --offline agent.yaml`
// run from dir does: relative entries resolve against dir, an unresolvable host is a warning. It returns every
// diagnostic, labelled with dir/agent.yaml, sorted as compile prints them; ok is false when any is an error.
// It reads the paths the contract names and writes nothing.
func Check(contract []byte, dir string, env CheckEnv) (diags []agent.Diagnostic, ok bool) {
	return CheckFile(contract, filepath.Join(dir, ContractFile), dir, env)
}

// CheckFile is Check of contract as the file label, run from dir: a contract that does not live in dir, such as a
// user registry's entry that `tego run <name>` typed in dir finds, is compiled as that file.
func CheckFile(contract []byte, label, dir string, env CheckEnv) (diags []agent.Diagnostic, ok bool) {
	profiles := env.Profiles
	if profiles == nil {
		profiles = (&agent.ProfileChain{}).WithBuiltin(presets.Source{})
	}
	c, ds, err := agent.LoadBytes(label, contract, profiles)
	if err != nil {
		if !agent.HasErrors(ds) {
			ds = append(ds, agent.Diagnostic{File: label, Code: agent.CodeSchema, Message: err.Error(), Severity: agent.SeverityError})
		}
		return ds, false
	}
	m := env.Machine
	if m == nil {
		m = config.Builtin()
	}
	opts := append([]agent.CompileOption{agent.Offline(), agent.WithCwd(dir)}, env.Options...)
	_, cds, err := agent.Compile(c, m, opts...)
	ds = append(ds, cds...)
	if err != nil && !agent.HasErrors(ds) {
		ds = append(ds, agent.Diagnostic{File: label, Code: agent.CodeSchema, Message: err.Error(), Severity: agent.SeverityError})
	}
	return ds, !agent.HasErrors(ds)
}

// ContractFile is the file name init writes the contract to, in the project directory.
const ContractFile = "agent.yaml"

// Draft is the whole composition without a write: Compose, then Check of the bytes against env, with the
// diagnostics in the result. It is the entry a "set up a new agent" page calls on every change of its form, since it
// creates nothing: a write folder that does not exist yet (one of MakeDirs) is reported by compile as path-missing
// only when its parent is missing too, and Draft drops exactly those diagnostics, which Create makes untrue. An
// options mistake is a UsageError; a contract that does not compile is not an error but a Result with OK false.
func Draft(o Options, env CheckEnv) (*Result, error) {
	res, err := Compose(o)
	if err != nil {
		return nil, err
	}
	ds, _ := Check(res.Contract, o.Dir, env)
	for _, d := range ds {
		if d.Code == agent.CodePathMissing && res.created(d.Message) {
			continue
		}
		res.Diagnostics = append(res.Diagnostics, d)
	}
	res.OK = !agent.HasErrors(res.Diagnostics)
	return res, nil
}

// created reports whether msg is compile's path-missing message for an fs.write entry naming one of MakeDirs.
func (r *Result) created(msg string) bool {
	for _, v := range r.makeEntries {
		if strings.HasPrefix(msg, fmt.Sprintf("fs.write %q:", v)) {
			return true
		}
	}
	return false
}

// Apply is Create followed by Check of r.Contract in dir (the project directory with its symlinks resolved, as Create
// takes it), now that every folder it names exists: compile stops checking an fs.write entry at its path-missing
// error, so a check Draft could not make (an entry inside tego's own directory, R10) shows up only here. When that
// compile finds an error, or Create fails, Apply removes the folders Create made as Remove does, beneath the project
// folder Create opened, which it holds until then, and returns ok false with the diagnostics: the caller writes
// nothing. made are the folders Create made, relative to dir, in creation order.
func Apply(r *Result, dir string, env CheckEnv) (made []string, diags []agent.Diagnostic, ok bool, err error) {
	root, err := openDir(dir)
	if err != nil {
		return nil, nil, false, rootRefusal(dir, err)
	}
	defer func() { _ = root.Close() }() // a path descriptor: nothing to flush
	made, err = create(root, r, dir)
	if err == nil {
		if diags, ok = Check(r.Contract, dir, env); ok {
			return made, diags, true, nil
		}
	}
	remove(root, made)
	return nil, diags, false, err
}

// Remove removes the folders made, as Create returned them for the project directory dir (relative to dir inside it,
// absolute outside it, a parent before its child), the deepest first and only while empty; a caller whose write
// after Create failed (the dashboard's agent.yaml) calls it. Each is removed with unlinkat AT_REMOVEDIR in its
// parent, reached as Create reached it: from dir opened with no symlink followed, or, outside it, from the nearest
// folder above it that Create did not make, resolved once, and below that a component at a time with no link
// followed. So a folder that holds anything stays, and so does one swapped since for a file or a link, or with a link
// swapped in on its way: Remove never unlinks a file and never removes through a link. It is best effort and says
// nothing: what it cannot remove stays.
func Remove(made []string, dir string) {
	root, err := openDir(dir)
	if err != nil {
		root = nil // dir is a link now, or gone: the folders inside it stay, those outside it are still removed
	} else {
		defer func() { _ = root.Close() }() // a path descriptor: nothing to flush
	}
	remove(root, made)
}

// remove is Remove beneath root, the project folder open (nil: the folders inside it stay).
func remove(root *sys.FD, made []string) {
	for i := len(made) - 1; i >= 0; i-- {
		p := made[i]
		if filepath.IsAbs(p) {
			rmdirOutside(p, made[:i])
		} else if root != nil {
			rmdirIn(root, filepath.FromSlash(p))
		}
	}
}

// rmdirOutside removes the empty folder p, made outside the project beneath the nearest folder above it that Create
// did not make (before are the folders it made ahead of p): that folder is resolved once, as mkdirOutside resolved
// it, and p's parent reached below it with no link followed.
func rmdirOutside(p string, before []string) {
	top := filepath.Dir(p)
	for slices.Contains(before, top) && filepath.Dir(top) != top {
		top = filepath.Dir(top)
	}
	rel, err := filepath.Rel(top, p)
	if err != nil {
		return
	}
	resolved, err := filepath.EvalSymlinks(top)
	if err != nil {
		return
	}
	root, err := openDir(resolved)
	if err != nil {
		return
	}
	defer func() { _ = root.Close() }() // a path descriptor: nothing to flush
	rmdirIn(root, rel)
}

// rmdirIn removes the empty folder rel beneath root: its parent is opened a component at a time (walk), and the
// folder removed there with unlinkat AT_REMOVEDIR, which removes an empty folder alone, never a file, and follows no
// link (a link there is ENOTDIR).
func rmdirIn(root *sys.FD, rel string) {
	parent, name := filepath.Split(rel)
	dir := root
	if parent != "" {
		d, err := walk(root, parent)
		if err != nil {
			return // a link or a file on the way, swapped in since: nothing is removed through it
		}
		defer func() { _ = d.Close() }() // a path descriptor: nothing to flush
		dir = d
	}
	_ = dir.Borrow(func(n int) error { return unix.Unlinkat(n, name, unix.AT_REMOVEDIR) }) // best effort: what stays, stays
}

// Create makes the folders r.MakeDirs names (mode 0755) and returns every folder it made, a missing parent included,
// in creation order (a parent before its child), each relative to dir when inside it. A folder that already exists
// is not returned. It stops at the first failure, returning what it made until then.
//
// dir is the project directory r was composed for with its symlinks resolved (Options.Dir), as the caller checked
// it. Create opens it once with no symlink followed and makes every folder inside it beneath that descriptor, a
// component at a time: each is opened relative to the one above it with openat2 RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS,
// and made there with mkdirat first when it is missing. Where openat2 is refused (ENOSYS inside a tego run, whose
// filter answers it so, or on a kernel before 5.6; EPERM from an older container profile), each component is opened
// with openat O_NOFOLLOW instead, and fstatat tells a link from a file, with the same answers. A symbolic link on the
// way, in dir's own path or under it, there before or swapped in since the caller's check, is refused with an error
// naming it, and nothing is made through it, so no folder lands outside the project through a link. A folder outside
// dir (Claude Code's socket folder under the runtime directory) is made the same way beneath its nearest existing
// parent, whose own path no check came before: it is resolved once, its links followed.
func Create(r *Result, dir string) ([]string, error) {
	root, err := openDir(dir)
	if err != nil {
		return nil, rootRefusal(dir, err)
	}
	defer func() { _ = root.Close() }() // a path descriptor: nothing to flush
	return create(root, r, dir)
}

// create is Create beneath root, the project folder dir opened with no symlink followed.
func create(root *sys.FD, r *Result, dir string) ([]string, error) {
	var made []string
	for _, d := range r.MakeDirs {
		d = filepath.Clean(d)
		rel, rerr := filepath.Rel(dir, d)
		inside := rerr == nil && filepath.IsLocal(rel)
		var m []string
		var err error
		if inside {
			m, err = mkdirs(root, dir, rel, d)
		} else {
			m, err = mkdirOutside(d)
		}
		for _, p := range m {
			if inside {
				p, _ = filepath.Rel(dir, p) // under dir: mkdirs joined it to dir
				p = filepath.ToSlash(p)
			}
			made = append(made, p)
		}
		if err != nil {
			return made, err
		}
	}
	return made, nil
}

// mkdirOutside makes d, a folder outside the project, beneath its nearest existing parent (found with links followed,
// as Compose found d missing): no check came before, so that parent's path is resolved once, and below it mkdirs goes
// on as inside the project, refusing a link. It returns the folders it made as d's path names them, parent first.
func mkdirOutside(d string) ([]string, error) {
	top := d
	for !exists(top) && filepath.Dir(top) != top {
		top = filepath.Dir(top)
	}
	resolved, err := filepath.EvalSymlinks(top)
	if err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", d, err)
	}
	root, err := openDir(resolved)
	if err != nil { // a link swapped in since the resolve
		return nil, refusal(resolved, d, err)
	}
	defer func() { _ = root.Close() }() // a path descriptor: nothing to flush
	rel, err := filepath.Rel(top, d)
	if err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", d, err)
	}
	return mkdirs(root, top, rel, d)
}

// mkdirs makes rel beneath root, the folder at path base, a component at a time: each is opened relative to the one
// above it (openIn), and made there with mkdirat first when it is missing, so no step follows a symbolic link or
// leaves root. It returns the folders it made, by their paths under base, parent first, and stops at the first
// failure, whose error names the component and target, the folder rel leads to.
func mkdirs(root *sys.FD, base, rel, target string) ([]string, error) {
	var made []string
	cur, p := root, base
	defer func() {
		if cur != root {
			_ = cur.Close() // a path descriptor: nothing to flush
		}
	}()
	for _, name := range strings.Split(rel, string(filepath.Separator)) {
		if name == "." { // rel is "." for base itself, which exists: nothing to make
			continue
		}
		p = filepath.Join(p, name)
		next, err := openIn(cur, name)
		if errors.Is(err, unix.ENOENT) {
			err = cur.Borrow(func(n int) error { return unix.Mkdirat(n, name, 0o755) })
			switch {
			case err == nil:
				made = append(made, p)
			case !errors.Is(err, unix.EEXIST): // EEXIST: something is there since the open, and the open below says what
				return made, fmt.Errorf("mkdir %s: %w", p, err)
			}
			next, err = openIn(cur, name)
		}
		if err != nil {
			return made, refusal(p, target, err)
		}
		if cur != root {
			_ = cur.Close() // a path descriptor: nothing to flush
		}
		cur = next
	}
	return made, nil
}

// pathOnly are the open flags of every folder Create goes through: O_PATH, since only the *at calls use it (and so
// it needs no read permission on the folder, as mkdir needs none), O_DIRECTORY, and no O_NOFOLLOW: with O_DIRECTORY
// that answers ENOTDIR for a link and hides that it was one, where RESOLVE_NO_SYMLINKS refuses a link as the last
// component too, with ELOOP, a dangling one included. openNoFollow, which has no RESOLVE_NO_SYMLINKS, adds it.
const pathOnly = unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC

// openDir opens the folder at the absolute path p with no symlink on the way: one openat2 RESOLVE_NO_SYMLINKS, or,
// where openat2 is refused (refusedOpenat2), a walk from / a component at a time (walkDir).
func openDir(p string) (*sys.FD, error) {
	for {
		d, err := sys.Own(unix.Openat2(unix.AT_FDCWD, p, &unix.OpenHow{Flags: pathOnly, Resolve: unix.RESOLVE_NO_SYMLINKS}))
		if refusedOpenat2(err) {
			return walkDir(p)
		}
		if !errors.Is(err, unix.EINTR) && !errors.Is(err, unix.EAGAIN) {
			return d, err
		}
	}
}

// openIn opens the folder name in dir, with no symlink followed and nothing outside dir reached: openat2
// RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS, or, where openat2 is refused, openNoFollow, with the same answers.
func openIn(dir *sys.FD, name string) (*sys.FD, error) {
	for {
		d, err := dir.Openat2(name, &unix.OpenHow{Flags: pathOnly, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS})
		if refusedOpenat2(err) {
			d, err = openNoFollow(dir, name)
		}
		if !errors.Is(err, unix.EINTR) && !errors.Is(err, unix.EAGAIN) {
			return d, err
		}
	}
}

// refusedOpenat2 reports whether err says openat2 is not answered here: ENOSYS from a kernel before 5.6 or from a
// seccomp filter, as tego's own run filter answers it at every tier (enforce-landlock R10), so `tego init --preset`
// run inside a run meets it; EPERM from a container's seccomp profile that predates it. pkg/spec/agent's
// ReadPlaceLink falls back on the same two.
func refusedOpenat2(err error) bool { return errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) }

// openNoFollow is openIn where openat2 is refused. name is one component, so openat with O_NOFOLLOW resolves nothing
// but name in dir and follows no link there; a name holding a "/", or "..", could reach past dir and is refused
// EXDEV, as RESOLVE_BENEATH refuses it (Create never passes one). With O_DIRECTORY a link answers ENOTDIR, as a file
// does, so fstatat AT_SYMLINK_NOFOLLOW tells which, and a link, a dangling one included, answers ELOOP, as
// RESOLVE_NO_SYMLINKS answers it.
func openNoFollow(dir *sys.FD, name string) (*sys.FD, error) {
	if name == ".." || strings.ContainsRune(name, '/') {
		return nil, unix.EXDEV
	}
	d, err := dir.Openat(name, pathOnly|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOTDIR) {
		var st unix.Stat_t
		if dir.Fstatat(name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
			return nil, unix.ELOOP
		}
	}
	return d, err
}

// walkDir is openDir where openat2 is refused: from / a component at a time (walk), so no link on the way is
// followed and a link answers ELOOP, as openat2 answers it. (A relative p, which Create never passes, is walked from
// the working directory, a ".." in it refused.)
func walkDir(p string) (*sys.FD, error) {
	start := "."
	if filepath.IsAbs(p) {
		start = "/"
	}
	top, err := sys.Own(unix.Open(start, pathOnly, 0))
	if err != nil {
		return nil, err
	}
	defer func() { _ = top.Close() }() // a path descriptor: nothing to flush
	return walk(top, p)
}

// walk opens the folder rel beneath dir a component at a time with openIn, so no link on the way is followed and
// nothing outside dir is reached. dir stays open; the folder returned is a descriptor of its own (dir's duplicate
// when rel names no component), the caller's to close.
func walk(dir *sys.FD, rel string) (*sys.FD, error) {
	cur := dir
	for name := range strings.SplitSeq(filepath.Clean(rel), string(filepath.Separator)) {
		if name == "" || name == "." { // an absolute rel's empty first name, or a rel that is "."
			continue
		}
		next, err := openIn(cur, name)
		if cur != dir {
			_ = cur.Close() // a path descriptor: nothing to flush
		}
		if err != nil {
			return nil, err
		}
		cur = next
	}
	if cur == dir {
		return dir.Dup()
	}
	return cur, nil
}

// refusal is why the folder target is not made through p, a component of its path that openIn or openDir refused. A
// link's fix is to remove it: one an agent planted leads where the agent chose, so making the folder through it by
// hand would put the folder there, and the next contract would grant it.
func refusal(p, target string, err error) error {
	switch {
	case errors.Is(err, unix.ELOOP):
		return fmt.Errorf("%s is a symbolic link, and a folder is never made through one: remove the link, or replace it "+
			"with a folder, and try again", p)
	case errors.Is(err, unix.ENOTDIR):
		return fmt.Errorf("%s is not a folder, so %s cannot be made", p, target)
	}
	return fmt.Errorf("mkdir %s: open %s: %w", target, p, err)
}

// rootRefusal is why the project directory dir, resolved when it was checked, does not open with no symlink on the
// way: a link on its path now means it changed since, and the error names the link (found again by path, for the
// message alone; the refusal is openat2's).
func rootRefusal(dir string, err error) error {
	if !errors.Is(err, unix.ELOOP) {
		return fmt.Errorf("open the project folder %s: %w", dir, err)
	}
	var path []string // dir and each folder above it, dir first
	for p := filepath.Clean(dir); ; p = filepath.Dir(p) {
		path = append(path, p)
		if filepath.Dir(p) == p {
			break
		}
	}
	for i := len(path) - 1; i >= 0; i-- { // the first link on the way down
		if fi, err := os.Lstat(path[i]); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			continue
		}
		if i == 0 {
			return fmt.Errorf("the project folder %s is a symbolic link now, so it changed after it was checked: "+
				"no folder was made in it", dir)
		}
		return fmt.Errorf("%s is a symbolic link now, so the project folder %s changed after it was checked: "+
			"no folder was made in it", path[i], dir)
	}
	return fmt.Errorf("a folder on the path of the project folder %s was a symbolic link when it was opened, so it "+
		"changed after it was checked: no folder was made in it", dir)
}
