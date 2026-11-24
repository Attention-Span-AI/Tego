// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"path/filepath"

	"github.com/attention-span-ai/tego/internal/runlock"
)

// A run launched with sudo keeps its folder root's until it ends (ADR 0042): the agent runs as the person, so a folder
// the person could open would let the agent reach the live chain and the live files. A dashboard served by that person
// therefore gets "permission denied" on the run's record, and the run is neither shown nor changed live. That is the
// design, not a fault of the record, and the words for it must say so rather than quote the failed system call.

// RootLaunched reports whether err, from reading run id under root, is the person's dashboard being refused a run that was
// launched as root: the error is a permission refusal, this process is not root, and the run's folder is root's. It
// decides from those three facts and never from the error's text (runlock.RootOwned, the one helper the commands'
// [root-run] refusal asks too); it opens nothing of the run and tries no other path to its files.
func RootLaunched(root, id string, err error) bool {
	return runlock.RootOwned(filepath.Join(root, id), err)
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
	return runlock.SetRootOwnedSeams(owner, euid)
}
