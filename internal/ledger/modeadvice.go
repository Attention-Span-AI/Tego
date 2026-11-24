// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// A run's agent runs as the user who owns the run directory, and at tier 1 nothing stops its chmod (GAPS C52): it can
// take the rights off its own run directory, its events file or its blobs/ while it lives, and every reader of the
// run then answers "permission denied". `tego run` and `tego gc` give the owner those rights back (the runtime's
// restoreRunDirs); a reader that only reads changes no mode, so it says the exact state and the one command instead.

// ModeAdvice says what keeps the user out of run directory dir and the one command that gives them back their rights,
// or "" when it finds no such state: a directory it cannot stat, that is not one, whose owner rights and those of
// the three names a run is read through (events.jsonl, the lock file, blobs/) are all there, or that it cannot
// explain. The command adds the owner's bits only (chmod u+rwX), never a group or other right, so it widens nothing
// beyond the 0700 and 0600 the run was made with. A directory of another user's names its owner and no command: only
// they, or root, can change it.
func ModeAdvice(dir string) string {
	var st syscall.Stat_t
	if err := syscall.Lstat(dir, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		return ""
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Sprintf("%s belongs to uid %d, not you: only its owner or root can give it back its rights", dir, st.Uid)
	}
	var lacking []string
	note := func(p string, mode uint32, need uint32) {
		if mode&need != need {
			lacking = append(lacking, fmt.Sprintf("%s has mode %04o, which lacks your %s", p, mode&0o7777, rightsWord(need)))
		}
	}
	note(dir, st.Mode, 0o700)
	if st.Mode&0o100 != 0 { // the names below can be looked at only through a directory the owner may search
		for _, n := range []struct {
			name string
			need uint32
		}{{EventsFile, 0o600}, {LockFile, 0o600}, {BlobsDir, 0o700}} {
			var cs syscall.Stat_t
			if err := syscall.Lstat(filepath.Join(dir, n.name), &cs); err == nil && cs.Uid == st.Uid {
				note(filepath.Join(dir, n.name), cs.Mode, n.need)
			}
		}
	}
	if len(lacking) == 0 {
		return ""
	}
	return strings.Join(lacking, "; ") + "; give them back with: chmod -R u+rwX " + shellQuote(dir)
}

func rightsWord(need uint32) string {
	if need == 0o700 {
		return "read, write and search"
	}
	return "read and write"
}

// WithModeAdvice is err with ModeAdvice(dir) after it when err is a permission refusal and the advice has something to say.
func WithModeAdvice(dir string, err error) error {
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		return err
	}
	if a := ModeAdvice(dir); a != "" {
		return fmt.Errorf("%w; %s", err, a)
	}
	return err
}

// shellQuote is s as one word for a POSIX shell: single quotes, each embedded quote as '\”.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
