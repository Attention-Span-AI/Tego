// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"slices"
)

// The names tego goes by on a machine: the launcher and the dashboard's binary beside it.
const (
	binaryTego    = "tego"
	binaryControl = "tego-control"
)

// pathShadow is a directory on the launcher's PATH searched before the one holding binary (at): anything named binary
// there runs in its place the next time a person types the name.
type pathShadow struct {
	declared, resolved string
	binary, at         string
}

// ownBinaries is what WithOwnBinaries adds to R10: the targets for the running tego and for the tego and tego-control
// the launcher's PATH finds, each beside the tego-control a tego there would hand off to, and the PATH directories
// searched before those. Each of those binaries runs outside any contract the next time a person starts it, or as root
// under sudo "$(command -v tego)", so an agent that can replace one has left its own run. The os.Executable name alone
// would miss what a person types: a link on PATH to the real file, which R10's walk follows from the name found here.
//
// A PATH directory is the launcher's, k.o.path, never the agent's env.set: the one the person's next `tego` is looked up
// on. A tego that is not on PATH is not found through it, so it shadows nothing, and a running file that cannot be named
// (WithOwnBinaries(""), a tego-control's sealed copy) leaves the search of PATH.
func (k *compiler) ownBinaries() ([]writeTarget, []pathShadow) {
	if !k.o.ownBinaries {
		return nil, nil
	}
	const fix = "name the folders the agent needs instead: an agent that can write here can replace tego, and the next run would run its code"
	var targets []writeTarget
	add := func(name, p string) {
		for _, t := range targets {
			if t.declared == p {
				return
			}
		}
		targets = append(targets, k.r10Target(name, p, fix))
	}
	// tego hands off to the tego-control beside its own file and nowhere else, so a name still free there is one too.
	addControl := func(dir string) {
		p := filepath.Join(dir, binaryControl)
		if isExecutableFile(p) {
			add("the tego-control binary", p)
		} else {
			add("the place beside tego for tego-control,", p)
		}
	}
	if exe := k.o.ownExe; isExecutableFile(exe) {
		add("the tego binary", exe)
		addControl(filepath.Dir(exe))
	}
	dirs := pathDirs(k.o.path, k.o.cwd)
	var shadows []pathShadow
	for _, binary := range []string{binaryTego, binaryControl} {
		for i, d := range dirs {
			p := filepath.Join(d, binary)
			if !isExecutableFile(p) {
				continue
			}
			add("the "+binary+" binary on PATH", p)
			if binary == binaryTego {
				if r := k.resolve(p); r != "" {
					addControl(filepath.Dir(r))
				}
			}
			for _, before := range dirs[:i] {
				if r := k.resolve(before); r != "" {
					shadows = append(shadows, pathShadow{declared: before, resolved: r, binary: binary, at: p})
				}
			}
			break
		}
	}
	return targets, shadows
}

// pathDirs is path's directories as a lookup walks them, absolute and once each: an empty element is the current
// directory, and a relative one lies under it (execvp), the compile's cwd here as in searchPath.
func pathDirs(path, cwd string) []string {
	var dirs []string
	for _, d := range filepath.SplitList(path) {
		if !filepath.IsAbs(d) {
			d = filepath.Join(cwd, d)
		}
		if d = filepath.Clean(d); !slices.Contains(dirs, d) {
			dirs = append(dirs, d)
		}
	}
	return dirs
}

// isExecutableFile reports whether p names a regular file with an execute bit: what a PATH search takes.
func isExecutableFile(p string) bool {
	if p == "" {
		return false
	}
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0
}

// warnPathShadow warns once for a write entry over a PATH directory searched before tego: the agent could put its own
// tego there, and the next one typed in this shell would run it. A warning where R10 refuses, because the directory
// holds nothing of tego's, and the common case is a project's own: an activated .venv/bin or node_modules/.bin under
// a project the contract rightly lets the agent write.
func warnPathShadow(k *compiler, pos Pos, raw, p, resolved string, shadows []pathShadow) {
	for _, s := range shadows {
		if isAncestorOrSelf(resolved, s.resolved) {
			k.ds.warnf(pos, CodePathShadow, "fs.write %q%s lets the agent write %s, which this PATH searches before %s: a %s it puts there would run in place of tego's, outside the contract, the next time you type %s",
				raw, resolvedNote(p, resolved), s.declared, s.at, s.binary, s.binary).
				fix("put %s first on your PATH, or start tego by its full path", filepath.Dir(s.at))
			return
		}
	}
}
