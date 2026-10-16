// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The sweep of a lost run that is an adoption (ADR 0055 Decision 4). An adoption's scope is adopt-<id>.scope, which
// a launched run's sweep (orphanScope, killOrphan) never looks for, and an adopted agent is never killed. With its
// adopter and its reaper both dead the run reads lost, and the sweep used to end it `orphaned` while the agent stayed in
// the scope and the plane went on refusing its writes with nothing recording them: the ledger said the run had ended
// while it still held. Now run_end is written only once the tree is released: a root sweep releases it from the
// adoption's record, as the reaper would (holding the adopted process's lock), and otherwise the run stays lost
// (errOrphanAlive), for a root sweep or `sudo tego adopt --release` to release.

// sweepAdoptStateDir is the adoption records a sweep reads; "" is AdoptStateDir. A variable so a test can keep them
// elsewhere.
var sweepAdoptStateDir = ""

// sweepAdoption handles ref when it is an adoption, before killOrphan's search for a launched run's scope. adoption
// false says it is none (no record names it and no adopt-<id>.scope of it exists): the caller sweeps it as a launched
// run. With adoption true, a nil error says the tree was released (or was gone) and the scope removed, so run_end may
// be written; any error wraps errOrphanAlive and keeps the run lost.
func sweepAdoption(ctx context.Context, o sweepOptions, dir runDir, ref record.RunRef) (adoption bool, err error) {
	if sweeperUID() == 0 {
		store, rec, found, err := sweptAdoptionRecord(ref.ID)
		if err != nil {
			return true, fmt.Errorf("adoption %s: %w: its record: %w", ref.ID, errOrphanAlive, err)
		}
		if found {
			return true, releaseSwept(ctx, o, store, rec, dir)
		}
	}
	scope, ok := adoptScopeOf(o.manager, dir, ref)
	if !ok {
		return false, nil
	}
	if sweeperUID() == 0 {
		return true, fmt.Errorf("adoption %s: %w: its scope %s is there with no record to release it from; move its "+
			"processes out and remove it by hand (docs/OPERATIONS.md)", ref.ID, errOrphanAlive, scope)
	}
	return true, fmt.Errorf("adoption %s: %w: its scope %s is there and only root can release it: sudo tego gc, or sudo "+
		"tego adopt --release --pid <pid>", ref.ID, errOrphanAlive, scope)
}

// sweptAdoptionRecord reads run's adoption record, found false when there is none. The records' directory is never
// made here: a host that never adopted has none.
func sweptAdoptionRecord(run string) (*adoptStore, adoptRecord, bool, error) {
	dir := sweepAdoptStateDir
	if dir == "" {
		dir = AdoptStateDir
	}
	if !ledger.IsRunID(run) {
		return nil, adoptRecord{}, false, nil // no adoption has a record under a name that is no run id
	}
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil, adoptRecord{}, false, nil
	}
	store := &adoptStore{dir: dir}
	rec, err := store.read(run)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, adoptRecord{}, false, nil
	case err != nil:
		return nil, adoptRecord{}, false, err
	}
	return store, rec, true, nil
}

// releaseSwept releases an adoption the sweep met lost: only when its record names this very run directory (a
// directory planted under another adoption's run id releases nothing) and its adopter is gone, under the adopted
// process's lock (so a reaper or a release at work is waited for, and one that finished first leaves nothing to do).
// It writes no ledger line: the sweep holds the run's lock and writes run_end itself once this returns nil.
func releaseSwept(ctx context.Context, o sweepOptions, store *adoptStore, rec adoptRecord, dir runDir) error {
	if !sameDirectory(rec.Dir, dir) {
		return fmt.Errorf("adoption %s: %w: its record names the run directory %s, not this one", rec.Run, errOrphanAlive, rec.Dir)
	}
	if adopterAlive(rec.Adopter) {
		return fmt.Errorf("adoption %s: %w: its adopter (pid %d) is alive", rec.Run, errOrphanAlive, rec.Adopter.PID)
	}
	run, root := rec.Run, rec.Root
	lock, err := store.claimWait(ctx, root, releaseWait)
	if err != nil {
		return fmt.Errorf("adoption %s: %w: take its lock: %w", run, errOrphanAlive, err)
	}
	rec, err = store.read(run)
	if errors.Is(err, os.ErrNotExist) {
		store.unclaim(lock, root)
		return nil // a reaper or a release ended it meanwhile: the tree is released
	}
	if err != nil {
		_ = lock.Close()
		return fmt.Errorf("adoption %s: %w: its record: %w", run, errOrphanAlive, err)
	}
	env := adoptReleaseEnv()
	env.Mount = rec.Mount
	out := OrphanRelease{Released: adopt.Release(env, rec.Scope, adopt.ReleaseTargets(rec.Mount, rec.From))}
	errs := finishOrphan(store, rec, &out)
	_ = lock.Close() // finishOrphan removed its file with the record, or kept both for the next release
	o.log.Warn("sweep: released an adoption whose adopter and reaper were both gone; it is never killed", "run", rec.Run,
		"released", describeRelease(out.Released, rec), "scope_removed", out.Removed)
	if !out.Removed {
		return fmt.Errorf("adoption %s: %w: %d process(es) stay in %s: %w", rec.Run, errOrphanAlive, len(out.Released.Left),
			rec.Scope, errors.Join(errs...))
	}
	if err := errors.Join(errs...); err != nil {
		o.log.Warn("sweep: after an adoption's release", "run", rec.Run, "err", err)
	}
	return nil
}

// sameDirectory reports whether the path a names the run directory b (the lent directory itself when a sweep
// hook was lent it).
func sameDirectory(a string, b runDir) bool {
	if a == "" {
		return false
	}
	var sa unix.Stat_t
	if err := unix.Stat(a, &sa); err != nil {
		return false
	}
	sb, err := b.lstat()
	return err == nil && sa.Dev == sb.Dev && sa.Ino == sb.Ino
}

// adoptScopeOf finds an adoption's scope for the lost run in dir: tego.slice/tego-<agent>.slice/adopt-<id>.scope
// under the cgroup2 mount root (where a root adopter makes it) or the sweeper's manager's root, with the cgroup id
// run_start recorded when it recorded one. It decides only whether the run is kept lost, never what is moved, so a
// directory planted under another run's id can at most keep itself lost.
func adoptScopeOf(m cgroup.Manager, dir runDir, ref record.RunRef) (string, bool) {
	agentID, err := identity.ParseAgentID(ref.Agent)
	if err != nil {
		return "", false
	}
	rel := filepath.Join(identity.TopSlice, identity.AgentSlice(agentID), adopt.ScopeName(ref.ID))
	bases := []string{cgroup.Mount}
	if m != nil && m.Root() != cgroup.Mount {
		bases = append(bases, m.Root())
	}
	want := runCgroupID(dir)
	for _, base := range adoptScopeBases(bases) {
		c := cgroup.Cgroup{Path: filepath.Join(base, rel)}
		if _, err := os.Lstat(c.Path); err != nil {
			continue
		}
		if want != 0 && m != nil {
			if id, err := m.ID(c); err != nil || id != want {
				continue
			}
		}
		return c.Path, true
	}
	return "", false
}

// adoptScopeBases is the roots adoptScopeOf searches; a variable so a test can root them in a temporary tree.
var adoptScopeBases = func(bases []string) []string { return bases }
