// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"time"
)

// Bounds of the expansion of fs.watch and fs.deny_read globs (SEMANTICS §2), every glob of one compile together.
// A glob may name a directory the agent writes into (fs.watch: ["./out/*"]), so how many entries it lists and
// matches is the agent's choice, and I6 bounds every read compile makes there: filepath.Glob listed each directory
// whole and returned every match, so a directory of millions of planted names cost the next compile, perhaps under
// sudo, unbounded time and memory, and one rule per match.
var (
	globScanMaxEntries = 50000
	globScanMaxTime    = 2 * time.Second
	globMaxMatches     = 4096
)

// globStop says why an expansion stopped before it had read every entry it would have; "" is a whole expansion.
type globStop string

const (
	globWhole   globStop = ""
	globEntries globStop = "entries"
	globTime    globStop = "time"
	globMatches globStop = "matches"
	globUnread  globStop = "unread"
)

// globBudget is what is left of the bounds for the compile's globs.
type globBudget struct {
	left    int
	matches int
	end     time.Time
}

func newGlobBudget() *globBudget {
	return &globBudget{left: globScanMaxEntries, matches: globMaxMatches, end: time.Now().Add(globScanMaxTime)}
}

// expand is filepath.Glob's expansion of the absolute pattern within the budget: each directory is listed through
// listDir with what is left of the entries (O_DIRECTORY, O_NONBLOCK: a FIFO or a device where a directory was is
// not opened), a directory reached through a symlink is listed at where the kernel's walk leads, and the matches
// found are counted against the budget's. stop says why the expansion ended short; the matches before it are
// returned.
func (g *globBudget) expand(pattern string) ([]string, globStop, error) {
	if _, err := filepath.Match(pattern, ""); err != nil {
		return nil, globWhole, err
	}
	ms, stop := g.glob(pattern)
	if stop == globWhole && len(ms) > g.matches {
		ms, stop = ms[:g.matches], globMatches
	}
	g.matches -= len(ms)
	return ms, stop, nil
}

func (g *globBudget) glob(pattern string) ([]string, globStop) {
	if !hasGlobMeta(pattern) {
		if _, err := os.Lstat(pattern); err != nil {
			return nil, globWhole
		}
		return []string{pattern}, globWhole
	}
	dir, file := filepath.Split(pattern)
	if dir != "/" {
		dir = dir[:len(dir)-1]
	}
	dirs := []string{dir}
	if hasGlobMeta(dir) {
		var stop globStop
		if dirs, stop = g.glob(dir); stop != globWhole {
			return nil, stop
		}
	}
	var out []string
	for _, d := range dirs {
		if time.Now().After(g.end) {
			return out, globTime
		}
		if g.left <= 0 {
			return out, globEntries
		}
		ms, stop := g.dirMatches(d, file)
		out = append(out, ms...)
		if stop != globWhole {
			return out, stop
		}
		if len(out) > g.matches {
			return out[:g.matches], globMatches
		}
	}
	return out, globWhole
}

// dirMatches lists the names in dir that match the one-component pattern file.
func (g *globBudget) dirMatches(dir, file string) ([]string, globStop) {
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return nil, globWhole
	}
	list := dir
	if lst, err := os.Lstat(dir); err == nil && lst.Mode()&os.ModeSymlink != 0 {
		r, ok := resolveProbe(dir)
		if !ok {
			return nil, globWhole
		}
		list = r
	}
	es, more, err := listDir(list, g.left)
	g.left -= len(es)
	var out []string
	for _, e := range es {
		if ok, _ := filepath.Match(file, e.Name()); ok {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	var partial *partialListError
	switch {
	case errors.As(err, &partial):
		return out, globUnread
	case more:
		return out, globEntries
	}
	return out, globWhole
}
