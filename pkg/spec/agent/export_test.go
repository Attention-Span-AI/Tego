// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"syscall"
	"time"
)

// readSmall is readSmallErr (whose doc is the contract) reporting only whether it read.
func readSmall(path string, limit int64, follow bool) ([]byte, bool) {
	data, err := readSmallErr(path, limit, follow)
	return data, err == nil
}

// readDirBounded is listDir (whose doc is the contract) without its error.
func readDirBounded(path string, max int) (entries []os.DirEntry, more bool) {
	entries, more, _ = listDir(path, max)
	return entries, more
}

// withHostSocketProbe re-roots R19's host-socket probe at root, as uid, so a test decides which daemon
// sockets exist instead of inheriting the machine's.
func withHostSocketProbe(root string, uid int) CompileOption {
	return func(o *compileOptions) { o.socketRoot, o.socketUID, o.socketSet = root, uid, true }
}

// withWSLFacts gives compile WSL's facts: whether the machine is WSL, and the launcher sockets it has, each with
// its identity read from the file at its path (a path that cannot be read keeps identity zero).
func withWSLFacts(on bool, sockets ...string) CompileOption {
	return func(o *compileOptions) {
		f := wslFacts{on: on}
		for _, p := range sockets {
			s := wslSocket{path: p}
			if fi, err := os.Stat(p); err == nil {
				if st, ok := fi.Sys().(*syscall.Stat_t); ok {
					s.dev, s.ino = st.Dev, st.Ino
				}
			}
			f.sockets = append(f.sockets, s)
		}
		o.wsl = &f
	}
}

// canonical is decide.Canonical: path with the longest symlinked entry's declared prefix rewritten to its
// resolved one.
func (rt *RuleTable) canonical(path string) string { return core().Canonical(rt, path) }

// action is build (whose doc is the contract) with each path cleaned.
func (r TestRow) action(cwd, home string) Action { return r.build(cwd, home, false) }

// withInstallDirs names the directories ownBinaries looks for an installed tego in, so a test decides which installs
// exist instead of inheriting the machine's.
func withInstallDirs(dirs ...string) CompileOption {
	return func(o *compileOptions) { o.installDirs, o.installDirsSet = dirs, true }
}

// withFileIdentity gives compile the device and inode each path reaches (compileOptions.fileID), so a test can model a
// bind's two names as one file without a symlink (bindStandIn).
func withFileIdentity(id func(string) (dev, ino uint64, err error)) CompileOption {
	return func(o *compileOptions) { o.fileID = id }
}

// withSearchTimes sets the deny_write search's two time limits, so a test of the operation budgets alone puts them
// out of reach and does not depend on the machine's speed. The tests of the time limits themselves keep the real ones.
func withSearchTimes(entry, whole time.Duration) CompileOption {
	return func(o *compileOptions) { o.searchEntryTime, o.searchWholeTime = entry, whole }
}
