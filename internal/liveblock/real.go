// SPDX-License-Identifier: Apache-2.0

package liveblock

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The budget of one RealPath. A governed agent can plant the folders and links an operator's path runs through, so the
// walk's work is bounded in calls and in time: the writer puts the block in force with its value alone before it
// calls RealPath, and a walk that runs out of budget leaves it so (ErrRealBudget). Measured on the probe that found it
// (a 1000-deep folder and dangling links of ~780 "../a/" hops each), the unbounded walk took 1 min 24 s for 60 links.
const (
	// maxRealCalls bounds the lstat and readlink calls of one walk.
	maxRealCalls = 512
	// realWait bounds one walk's time.
	realWait = 250 * time.Millisecond
	// maxRealLinks is how many links one walk follows, the kernel's MAXSYMLINKS: a path that needs more fails with
	// ELOOP for the agent too, so it leads nowhere and has no real path.
	maxRealLinks = 40
)

// ErrRealBudget is a path RealPath could not resolve within its budget (maxRealCalls calls, realWait): the block then
// refuses its value alone, and the writer says the real path is not covered.
var ErrRealBudget = errors.New("liveblock: the path's links took more work than a block waits for")

// RealPath is the path a path, read or write block's value (absolute, cleaned) leads to now, found by one walk of its
// elements by hand as the kernel's lookup makes it: each symbolic link followed, a relative target read against the
// real folder the link is in, ".." taken against the real path walked so far, and from the first element that does
// not exist (a dangling link's target included) the rest appended as written. It is "" when that is the value itself,
// or when the walk cannot go on (a folder that cannot be searched, a file with elements after it, more than
// maxRealLinks links): the block then refuses its value alone, as before Entry.Real, never less. A walk that needs more
// than maxRealCalls lstat and readlink calls, or more than realWait, stops with ErrRealBudget.
//
// The writer calls it once, after the block is in force, when a block is added (`tego block`, runact.BlockUntil), so a
// link made or moved later does not change what the block refuses; the supervisor's own walk of each action decides
// the rest.
func RealPath(value string) (string, error) {
	return realPath(value, maxRealCalls, time.Now().Add(realWait))
}

// realPath is RealPath with its budget: calls lstat and readlink calls, until the deadline.
func realPath(value string, calls int, deadline time.Time) (string, error) {
	if !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return "", nil
	}
	budget := func() error {
		if calls <= 0 || !time.Now().Before(deadline) {
			return fmt.Errorf("%w (%s)", ErrRealBudget, value)
		}
		calls--
		return nil
	}
	todo := split(value) // the elements still to walk, first first
	at, missing, links := "/", false, 0
	for len(todo) > 0 {
		elem := todo[0]
		todo = todo[1:]
		switch elem {
		case "", ".":
			continue
		case "..":
			at = filepath.Dir(at) // at holds no link, so its parent as written is its parent on disk
			continue
		}
		next := filepath.Join(at, elem)
		if missing {
			at = next
			continue
		}
		if err := budget(); err != nil {
			return "", err
		}
		st, err := os.Lstat(next)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			missing, at = true, next // what would be made here is made at this path: the rest is appended
			continue
		case err != nil:
			return "", nil
		case st.Mode()&fs.ModeSymlink == 0:
			if !st.IsDir() && len(todo) > 0 {
				return "", nil // a file with elements after it: the lookup fails with ENOTDIR
			}
			at = next
			continue
		}
		if links++; links > maxRealLinks {
			return "", nil
		}
		if err := budget(); err != nil {
			return "", err
		}
		target, err := os.Readlink(next)
		if err != nil || target == "" {
			return "", nil
		}
		if filepath.IsAbs(target) {
			at = "/"
		}
		todo = append(split(target), todo...)
	}
	if at == value || len(at) > MaxValueBytes || plain(at) != nil {
		return "", nil
	}
	return at, nil
}

// split is a path's elements, empty ones dropped.
func split(p string) []string {
	return strings.FieldsFunc(p, func(r rune) bool { return r == '/' })
}

// RealOutcome is what AddReal did for a block: the real path it now refuses too, or why it refuses its value alone.
type RealOutcome struct {
	// Real is the block's Real now: a path its value leads to through a link, which it refuses too. "" when none.
	Real string
	// Uncovered is the path the value leads to through a link that the block does not refuse, because the run's
	// launcher predates the real path (no RealName mark): the block refuses the value as written only.
	Uncovered string
	// Unknown is a value whose real path could not be worked out within RealPath's budget, or not stored: whether it
	// leads elsewhere through a link is not known, and the block refuses it as written only.
	Unknown bool
}

// AddReal is the second step of adding a path, read or write block of kind on value to the run in dir, after the
// Update that put held (the block the overlay holds, Kind "" for none) in force with its value alone: it resolves the
// value's real path with RealPath's budget, outside the lock, and stores it with SetReal in a second Update, which
// only narrows. An exec or net block, a block no longer held, and a value that is its own real path leave it at the
// zero RealOutcome; a held block that has a Real keeps it. A real path is stored only for a run whose launcher reads it
// (TakesReal); for an older one it is reported as Uncovered. A failed second Update is Unknown, with its error.
func AddReal(ctx context.Context, dir, run string, kind Kind, value string, held Entry) (RealOutcome, error) {
	if kind.Access() == 0 || held.Kind == "" {
		return RealOutcome{}, nil
	}
	if held.Real != "" {
		return RealOutcome{Real: held.Real}, nil
	}
	resolved, err := RealPath(value)
	switch {
	case err != nil:
		return RealOutcome{Unknown: true}, nil
	case resolved == "":
		return RealOutcome{}, nil
	case !TakesReal(dir):
		return RealOutcome{Uncovered: resolved}, nil
	}
	var out RealOutcome
	if _, err := Update(ctx, dir, run, func(o *Overlay) (bool, error) {
		changed := o.SetReal(kind, value, resolved)
		if e, ok := o.Find(kind, value); ok {
			out.Real = e.Real
		}
		return changed, nil
	}); err != nil {
		return RealOutcome{Unknown: true}, err
	}
	return out, nil
}
