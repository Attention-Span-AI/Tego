// SPDX-License-Identifier: Apache-2.0

package runlock

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// A run launched with sudo keeps its folder root's until it ends (ADR 0042): the agent runs as the person, so a folder
// the person could open would let the agent reach the live chain and the live files. A command or a dashboard served
// by that person therefore gets "permission denied" on the run's files, and the words for it must say what the folder
// is, not quote the failed system call. RootOwned is the one place that decides it; internal/cli's [root-run] refusal
// and the dashboard's read error both ask it (N125 (a): the two used to keep a copy each, one with Stat and one with
// Lstat).

// runFolderOwner is the uid that owns a run's folder, and false when it cannot be told. It does not follow a symlink
// at dir (Lstat): a link planted where a run folder belongs is not a folder root owns. A variable so a test, which
// cannot make a root-owned folder, can stand one in.
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

// RootOwned reports whether err, from opening files of the run folder dir, is a person being refused a run that was
// launched as root: the error is a permission refusal, this process is not root, and the folder is root's. It
// decides from those three facts and never from the error's text; it opens nothing of the run and tries no other path
// to its files. Anything else (a folder of the person's own, an owner that cannot be told, root itself, any other
// failure) is not this case. The facts show who owns the folder, not that a sudo run made it or that it still goes.
func RootOwned(dir string, err error) bool {
	if err == nil || !errors.Is(err, fs.ErrPermission) || callerEUID() == 0 {
		return false
	}
	uid, ok := runFolderOwner(dir)
	return ok && uid == 0
}

// SetRootOwnedSeams replaces how the owner of a run's folder and the effective uid are read, and returns what puts
// them back. It is for tests, which cannot make a folder owned by root.
func SetRootOwnedSeams(owner func(dir string) (uid int, ok bool), euid func() int) (restore func()) {
	o, e := runFolderOwner, callerEUID
	runFolderOwner, callerEUID = owner, euid
	return func() { runFolderOwner, callerEUID = o, e }
}
