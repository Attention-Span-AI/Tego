// SPDX-License-Identifier: Apache-2.0

package agent

import "os"

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
