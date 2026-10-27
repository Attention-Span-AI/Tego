// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// AbsentRow is one row of the built-in deny_read list that did not exist when the table compiled (RuleTable.AbsentDenyRead,
// ADR 0067 D3).
type AbsentRow struct {
	// Path is the row under the home directory, as the list names it (the Path a rule for the row would have).
	Path string
	// Resolved is where the row's walk lands: the row with every directory on its way followed, or, for a row that is
	// a symlink leading nowhere yet, the place the link leads (walkTarget), since that is the file a login writing
	// through the link makes and the kernel opens.
	Resolved string
	// At is the name the Landlock ruleset leaves ungranted for the row: the first name on Resolved that did not exist
	// at compile, directly beneath the nearest directory that did. It is Resolved itself, or an ancestor of it
	// (~/.codex for ~/.codex/auth.json when ~/.codex is missing too), and everything later made at or beneath it is
	// refused a read. The Landlock builder holds At's directory and leaves At out, or holds At and denies it where it
	// exists by then, and refuses to build a ruleset that would leave out anything else (enforce-landlock E9), so this
	// is what the tier models answer from.
	At string
}

// RuleName is the rule a refusal the row explains is named by: the one a rule for the row would carry,
// fs.deny_read[<row>].
func (a AbsentRow) RuleName() string {
	return FSRule{Path: a.Path, Kind: FSDenyRead, BuiltIn: true}.RuleName()
}

// AbsentRowOf is the row of RuleTable.AbsentDenyRead whose ungranted name (AbsentRow.At) is p or an ancestor of p, and
// whether one is: the Landlock ruleset refuses a read of p for it. Of the rows sharing that name the one whose own
// path covers p is chosen, else the first in list order, so a read of ~/.claude/.credentials.json with ~/.claude
// missing is named by that row and one of ~/.claude/settings.json by the list's first ~/.claude row. p is matched as
// the kernel names it (resolved); a cost of a few string comparisons per row, with no allocation.
func (rt *RuleTable) AbsentRowOf(p string) (AbsentRow, bool) {
	if rt == nil || len(rt.AbsentDenyRead) == 0 || !filepath.IsAbs(p) {
		return AbsentRow{}, false
	}
	first := -1
	for i, a := range rt.AbsentDenyRead {
		if !Covers(a.At, p) {
			continue
		}
		if Covers(a.Resolved, p) {
			return a, true
		}
		if first < 0 {
			first = i
		}
	}
	if first < 0 {
		return AbsentRow{}, false
	}
	return rt.AbsentDenyRead[first], true
}

// absentAt is AbsentRow.At for a row whose walk lands at the absolute path res: the first name on res that does not
// exist, directly beneath the nearest directory that does. ok is false where that nearest existing node is not a
// directory (nothing can be made beneath a file) or cannot be looked at. A res that exists by now (made since the
// caller looked) is its own At: the Landlock builder then holds it and denies it.
func absentAt(res string) (string, bool) {
	child := ""
	for cur := filepath.Clean(res); ; cur = filepath.Dir(cur) {
		fi, err := os.Lstat(cur)
		if err == nil {
			if child == "" {
				return cur, true
			}
			return child, fi.IsDir()
		}
		if !errors.Is(err, fs.ErrNotExist) || cur == "/" {
			return "", false
		}
		child = cur
	}
}

// danglingPlace is where the final symlink p leads when nothing is there yet: the place a login writing through
// the link makes its file (walkTarget, which follows a final link leading nowhere). ok is false for a p that is
// not a symlink, a link whose target exists, and one no walk places (a loop).
func danglingPlace(p string) (string, bool) {
	fi, err := os.Lstat(p)
	if err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		return "", false
	}
	if _, err := os.Stat(p); !errors.Is(err, fs.ErrNotExist) {
		return "", false
	}
	w := walkTarget(p)
	if !w.placed || !filepath.IsAbs(w.place) {
		return "", false
	}
	return filepath.Clean(w.place), true
}
