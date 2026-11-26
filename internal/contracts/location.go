// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"context"
	"path/filepath"
	"slices"
	"sync"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// Which locations a check touches, and whether they are local (ADR 0144, "A local location is a busy disk, not a
// stuck mount"). The helper's wait function cannot be read for a helper that is undumpable, which every helper is, so
// the refusal after a location budget that ran out is not decided by what the helper waits in alone: it is also decided
// by what the location is. A location on a filesystem of this computer's own storage does answer in the end, only
// slowly when its disk is busy, so a check of it is waited for longer and refused in the disk's words; any other (a
// network or user-space filesystem, a type this code does not know, a mount table that cannot be read) is as it was.

type locationsKey struct{}

// localKey is the class of the exchanges made with a context: true when the locations of the check are all local.
type localKey struct{}

// WithLocations declares the absolute paths the check made with ctx will touch, for the class of its location. Calls add
// to each other. A path the helper reaches that is not declared is not classified: declare every directory or file the
// operation is given (its home, its ledger, its contract), and nothing that is only a spelling of another. A check
// that declares none is not local.
func WithLocations(ctx context.Context, paths ...string) context.Context {
	prev, _ := ctx.Value(locationsKey{}).([]string)
	return context.WithValue(ctx, locationsKey{}, addPaths(prev, paths))
}

// addPaths is prev and the paths of more that are not in it, without the empty path, in a new slice.
func addPaths(prev, more []string) []string {
	seen := make(map[string]bool, len(prev)+len(more))
	out := make([]string, 0, len(prev)+len(more))
	for _, group := range [][]string{prev, more} {
		for _, p := range group {
			if p != "" && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// readLocal is how a class is decided; a test replaces it. It reads the mount table of this process now, once per
// check, so a filesystem mounted over a location after an earlier check is seen by the next one. The read is of
// /proc/self/mountinfo: the kernel's own listing of this process's mount namespace, from memory, which never calls into
// a mounted filesystem and so cannot wait for one that does not answer; that is why it is made here, in the caller's
// process, and not in a helper. Its size is bounded (proc.ReadMountInfo): a table over the bound is not read, and the
// check is not local.
var readLocal = func(paths []string) bool { return proc.PathsLocal(paths...) }

// withClass returns ctx with the class of the locations declared on it (and of the extra paths a request names
// itself) decided now.
func withClass(ctx context.Context, own ...string) context.Context {
	paths, _ := ctx.Value(locationsKey{}).([]string)
	paths = addPaths(paths, own)
	local := false
	if len(paths) > 0 {
		// A relative path cannot be placed in the mount table: the class is the one that may stop answering.
		local = !slices.ContainsFunc(paths, func(p string) bool { return !filepath.IsAbs(p) }) && readLocal(paths)
	}
	return context.WithValue(ctx, localKey{}, local)
}

// localCheck says whether the check made with ctx is of local locations (withClass decided it).
func localCheck(ctx context.Context) bool {
	local, _ := ctx.Value(localKey{}).(bool)
	return local
}

type waitNoteKey struct{}

// DiskWaitNote is what a caller with a terminal is told once, when a check of a local location has not been answered in
// its first budget and is being waited for longer (it can take up to localCap, 30 s).
const DiskWaitNote = "this computer's disk is slow to answer; still waiting for it (up to 30 seconds)"

// WithWaitNote makes ctx carry a function the check calls when it begins to wait for a local disk longer than the
// ordinary budget: a command on a terminal prints it, so a wait of up to 30 seconds is not silent. It is called once for
// everything made with the returned context, however many checks and scopes that is (a command makes a scope of its own
// for each check), so a command says it once.
func WithWaitNote(ctx context.Context, note func(string)) context.Context {
	var once sync.Once
	return context.WithValue(ctx, waitNoteKey{}, func(m string) { once.Do(func() { note(m) }) })
}

// noteDiskWait calls the note of ctx, if it has one, for the first extension of its scope.
func noteDiskWait(ctx context.Context, b *budget) {
	note, ok := ctx.Value(waitNoteKey{}).(func(string))
	if !ok || !b.firstNote() {
		return
	}
	note(DiskWaitNote)
}

// requestLocations are the paths a request names in its own fields.
func requestLocations(req *checkRequest) []string {
	out := []string{req.Path, req.Entry.Path, req.Places.Dir, req.Places.User}
	return out
}
