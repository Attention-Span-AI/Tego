// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// A run launched with sudo keeps its folder root's until it ends (ADR 0042): the agent runs as the person, so a folder
// the person could open would let the agent reach the live chain and the live files. A dashboard served by that person
// therefore gets "permission denied" on the run's record, and the run is neither shown nor changed live. That is the
// design, not a fault of the record, and the words for it must say so rather than quote the failed system call.

// runFolderOwner is the uid that owns a run's folder, and false when it cannot be told. A variable so a test, which cannot
// make a root-owned folder, can stand one in.
var runFolderOwner = func(dir string) (int, bool) {
	fi, err := os.Lstat(dir)
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}

// callerEUID is the effective uid of this process (a seam, as runFolderOwner is).
var callerEUID = os.Geteuid

// RootLaunched reports whether err, from reading run id under root, is the person's dashboard being refused a run that was
// launched as root: the error is a permission refusal, this process is not root, and the run's folder is root's. It
// decides from those three facts and never from the error's text; it opens nothing of the run and tries no other path to
// its files. Anything else (a folder of the person's own, an owner that cannot be told, root itself) is not this case.
// internal/cli's [root-run] refusal reads the same three facts for the commands; the two should be one helper, and
// when they are unified it should use one of Stat and Lstat (this copy uses Lstat, the safer one for a symlink).
func RootLaunched(root, id string, err error) bool {
	if err == nil || !errors.Is(err, fs.ErrPermission) || callerEUID() == 0 {
		return false
	}
	uid, ok := runFolderOwner(filepath.Join(root, id))
	return ok && uid == 0
}

// RootLaunchedWords is what a page says of a run RootLaunched names. id is a run id (letters, digits and hyphens). The
// three facts show who owns the folder, not that a sudo run made it or that it is still going, so the words say the
// owner and what a sudo run does, and no cause.
func RootLaunchedWords(id string) string {
	return "run " + id + ": its folder is owned by root (a run launched with sudo does this), so this dashboard cannot show or " +
		"change it live; run the command with sudo, or open the dashboard as root"
}

// SetRootRunSeams replaces how the owner of a run's folder and the effective uid are read, and returns what puts them
// back. It is for tests, which cannot make a folder owned by root.
func SetRootRunSeams(owner func(dir string) (uid int, ok bool), euid func() int) (restore func()) {
	o, e := runFolderOwner, callerEUID
	runFolderOwner, callerEUID = owner, euid
	return func() { runFolderOwner, callerEUID = o, e }
}
