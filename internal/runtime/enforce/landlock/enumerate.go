// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/policy/fsplan"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// denyRead compiles every deny_read entry (R3, R4): an entry at or below a write/ask entry is left out
// of the ruleset entirely and reported through the handle (R4), which must agree with compile's own
// Unenforced flag (I5); the rest are enumerated jointly. With nothing to deny, "/" gets the read set
// so reads stay allowed (SEMANTICS §1) while every write-side right is still handled (I4).
func (bd *builder) denyRead() error {
	writes, err := bd.heldWritablePaths()
	if err != nil {
		return err
	}
	var targets []fsplan.Target
	var rules []agent.FSRule
	grants := fsplan.NewGrants(writes)
	for _, r := range bd.rt.FS {
		if r.Kind != agent.FSDenyRead {
			continue
		}
		if filepath.Clean(r.Path) == "/" || filepath.Clean(resolvedOr(r.Resolved, r.Path)) == "/" {
			return fmt.Errorf("%w: deny_read %q has no parent to enumerate", ErrRulesetBuild, r.Path)
		}
		t, err := bd.snapshotTarget(r.Path, grants)
		if err != nil {
			return err
		}
		if err := checkHeldName(r.Path, r.Resolved, t.Path); err != nil {
			return err
		}
		targets = append(targets, t)
		rules = append(rules, r)
	}
	// ADR 0067 D3: a built-in row absent at compile is a target too, by the name compile predicted the ruleset leaves
	// out for it (AbsentRow.At), so the directory it would appear in is enumerated and a file created there during the
	// run gets no grant. It follows the rules, so the I5 loop below indexes only theirs; one a grant covers was left out
	// by compile, which drops it as fsplan.Build would leave it unenumerated.
	for _, a := range bd.rt.AbsentDenyRead {
		t, err := bd.snapshotAbsent(a)
		if err != nil {
			return err
		}
		targets = append(targets, t)
	}
	bd.fsPlan = fsplan.Build(targets, writes)
	for i, r := range rules {
		un := bd.fsPlan.Unenforced[i]
		if un != r.Unenforced { // I5: never disagree with compile
			return fmt.Errorf("%w: deny_read %q: compile marked unenforced=%v but the held-object plan says %v (write/ask/exec-directory entries %q)", ErrRulesetBuild, r.Path, r.Unenforced, un, bd.grantNames())
		}
		if un {
			bd.unenforced = append(bd.unenforced, r.Path)
			continue
		}
		// E5: compile must reject; fail closed here, on the path the entry leads to (a link to / is /).
		if targets[i].Path == "/" {
			return fmt.Errorf("%w: deny_read %q has no parent to enumerate", ErrRulesetBuild, r.Path)
		}
	}
	if len(bd.fsPlan.Targets) == 0 {
		_, err := bd.hold("/", kindReadRoot, bd.readSet())
		return err
	}
	return bd.applyEnumeration(bd.fsPlan)
}

func (bd *builder) grantNames() []string {
	var names []string
	for _, r := range bd.rt.FS {
		if r.Kind == agent.FSWrite || r.Kind == agent.FSAsk {
			names = append(names, r.Path)
		}
	}
	for _, r := range bd.rt.Exec {
		if r.IsDir {
			names = append(names, r.Path)
		}
	}
	return names
}

// snapshotTarget holds an existing target, or its nearest existing parent for
// E9's vanished-name plan. Names are read from owned descriptors, not re-resolved
// from compile's cached spelling. No right is granted during collection.
//
// A target whose name a write or ask entry covers (grants; R4) is left out of the ruleset, so nothing of it is
// kept: its name is read from a descriptor opened and closed here, and its Ref is -1. Holding one for the run cost a
// descriptor of the launcher's budget (E11) that the plan never used, and a project with thousands of .env files
// beneath a write entry met the cap at every tier, though the decision plane decides them by name (ADR 0043 D6).
func (bd *builder) snapshotTarget(path string, grants *fsplan.Grants) (fsplan.Target, error) {
	clean := filepath.Clean(path)
	for cur := clean; ; cur = filepath.Dir(cur) {
		t, err := bd.snapshotAt(cur, clean, grants)
		if err == nil {
			return t, nil
		}
		if !errors.Is(err, ErrPathVanished) || cur == "/" || cur == "." {
			return fsplan.Target{}, err
		}
	}
}

// snapshotAbsent is snapshotTarget for a row of RuleTable.AbsentDenyRead, by the name compile predicted the ruleset
// leaves out for it (AbsentRow.At), which the tier models answer from. Held
// now (made since compile), that name is a target like any deny_read entry, denied rather than left readable.
// Otherwise its directory is held and enumerated with the name left out, so it, made later with whatever is created
// inside it, gets no grant. Any other state, the directory gone or no longer a directory, or either now reached
// through a link compile did not see, is refused (E9): the plan would leave out another name than the one the models
// refuse, and the ledger would name the reads it refuses allowed, or the ones it lets through refused.
func (bd *builder) snapshotAbsent(a agent.AbsentRow) (fsplan.Target, error) {
	at := filepath.Clean(a.At)
	drift := func(what string) error {
		return fmt.Errorf("%w: built-in deny_read %q: %q %s since compile, so the ruleset cannot leave out the name compile predicted; recompile the contract", ErrRulesetBuild, a.Path, at, what)
	}
	idx, err := bd.hold(at, kindWatch, 0)
	if err == nil {
		if err := checkHeldName(at, at, bd.heldNames[at]); err != nil {
			return fsplan.Target{}, err
		}
		return fsplan.Target{Path: bd.heldNames[at], Ref: idx}, nil
	}
	if !errors.Is(err, ErrPathVanished) {
		return fsplan.Target{}, err
	}
	dir := filepath.Dir(at)
	if dir == at {
		return fsplan.Target{}, drift("has no directory")
	}
	idx, err = bd.hold(dir, kindWatch, 0)
	if errors.Is(err, ErrPathVanished) {
		return fsplan.Target{}, drift("lost its directory")
	}
	if err != nil {
		return fsplan.Target{}, err
	}
	if err := checkHeldName(dir, dir, bd.heldNames[dir]); err != nil {
		return fsplan.Target{}, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(bd.fds.open[idx].FD, &st); err != nil {
		return fsplan.Target{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fsplan.Target{}, drift("lies in what is no longer a directory")
	}
	return fsplan.Target{Path: filepath.Join(bd.heldNames[dir], filepath.Base(at)), Ref: -1}, nil
}

// snapshotAt is snapshotTarget's step at cur, target itself or an ancestor of it on E9's walk up: the target's name
// as the object at cur reports it (cur's name, and the rest of target beneath it), with cur held unless grants
// cover that name.
func (bd *builder) snapshotAt(cur, target string, grants *fsplan.Grants) (fsplan.Target, error) {
	named := func(name string) (string, error) {
		if cur == target {
			return name, nil
		}
		rest, err := filepath.Rel(cur, target)
		if err != nil {
			return "", err
		}
		return filepath.Join(name, rest), nil
	}
	if _, held := bd.fds.paths[cur]; held {
		idx, err := bd.hold(cur, kindWatch, 0)
		if err != nil {
			return fsplan.Target{}, err
		}
		return bd.snapshotRef(cur, target, idx, named)
	}
	if err := bd.tick(); err != nil {
		return fsplan.Target{}, err
	}
	var full string
	fd, st, name, err := openNamed(cur, nil, func(name string) (bool, error) {
		var err error
		if full, err = named(name); err != nil {
			return false, err
		}
		if grants.FirstCover(full) >= 0 {
			return false, nil // R4: left out of the ruleset, so not held
		}
		return true, bd.fds.room(cur)
	})
	if err != nil {
		return fsplan.Target{}, err
	}
	if fd < 0 {
		return fsplan.Target{Path: full, Ref: -1}, nil
	}
	return bd.snapshotRef(cur, target, bd.keep(fd, &st, cur, name, kindWatch, 0), named)
}

// snapshotRef is the target snapshotAt took at cur, held at entry idx: Ref is idx for the target itself and -1 for
// an ancestor held in its place (E9).
func (bd *builder) snapshotRef(cur, target string, idx int, named func(string) (string, error)) (fsplan.Target, error) {
	full, err := named(bd.heldNames[cur])
	if err != nil {
		return fsplan.Target{}, err
	}
	if cur != target {
		idx = -1
	}
	return fsplan.Target{Path: full, Ref: idx}, nil
}

func (bd *builder) heldWritablePaths() ([]string, error) {
	var grants []string
	for _, r := range bd.rt.FS {
		if r.Kind == agent.FSWrite || r.Kind == agent.FSAsk {
			if err := checkHeldName(r.Path, r.Resolved, bd.heldNames[r.Path]); err != nil {
				return nil, err
			}
			grants = append(grants, bd.heldNames[r.Path])
		}
	}
	for i, r := range bd.rt.Exec {
		if !r.IsDir {
			continue
		}
		if _, err := bd.hold(r.Path, execKind(r), 0); err != nil {
			return nil, err
		}
		name := bd.heldNames[r.Path]
		if err := checkHeldName(r.Path, r.Resolved, name); err != nil {
			return nil, err
		}
		grants = append(grants, name)
		if bd.execResolved == nil {
			bd.execResolved = make([]string, len(bd.rt.Exec))
		}
		bd.execResolved[i] = name
	}
	return grants, nil
}

// Runtime path models retain compile's resolved names. A moved grant and deny
// can keep containment unchanged while moving outside those models; refuse that
// drift before installing a plan instead of silently indexing another subtree.
// Hand-built tables with no resolved prediction retain their existing contract.
func checkHeldName(path, predicted, actual string) error {
	if predicted != "" && filepath.Clean(predicted) != actual {
		return fmt.Errorf("%w: %q resolved to %q at compile but its held descriptor names %q; recompile the contract", ErrRulesetBuild, path, predicted, actual)
	}
	return nil
}

func (bd *builder) applyEnumeration(plan fsplan.Plan) error {
	for _, t := range plan.Targets {
		if t.Ref < 0 {
			continue
		}
		if err := bd.seal(t.Ref, t.Path, kindDenyTarget, 0); err != nil {
			return err
		}
		bd.fds.open[t.Ref].Path = t.Path
	}
	held := make([]int, len(plan.Levels))
	enumerate := make([]bool, len(plan.Levels))
	// Hold identity only until the pure plan decides which levels are outside
	// denied object aliases. In particular, do not reopen a target's contents.
	selection := plan.Selection()
	for i, l := range plan.Levels {
		held[i] = -1
		if !selection.NeedsHold() {
			selection.Advance(-1)
			continue
		}
		idx, err := bd.hold(l.Path, kindWatch, 0)
		if err != nil {
			return err
		}
		held[i] = idx
		enumerate[i] = selection.Advance(idx)
	}
	for i, selected := range enumerate {
		if !selected {
			continue
		}
		l, idx := plan.Levels[i], held[i]
		if err := bd.seal(idx, l.Path, kindDenyAncestor, bd.profile.mask(bd.ancestorAccess())); err != nil {
			return err
		}
		var st unix.Stat_t
		if err := unix.Fstat(bd.fds.open[idx].FD, &st); err != nil {
			return err
		}
		bd.fds.open[idx].Access |= bd.fitAccess(bd.ancestorAccess(), &st)
	}
	for i, selected := range enumerate {
		if selected {
			if err := bd.level(held[i], plan.Levels[i].Path, plan.Levels[i].Exclude); err != nil {
				return err
			}
		}
	}
	return nil
}

// seal makes the entry hold returned for a deny node carry that node's kind, so that add's guard applies
// to it (I11). hold hands back whichever entry already holds the inode, and fsEntries runs first: an
// fs.watch, fs.ask or implicit entry for the same inode would otherwise keep its own kind, and every
// later union — a hardlink of the target enumerated as a sibling, a PT_INTERP naming one — would go
// through. Such an entry carries no more than the node may (max), so it is re-marked. One that carries
// more is an fs.write entry reaching the same inode by another name, a hardlink or a bind mount: its
// rights cover exactly what the node denies. That is R4 decided by identity, and compile, which compares
// paths, cannot have marked the deny_read entry unenforced, so reporting it unenforced here would break
// I5. The build fails closed instead (§7: build correct kernel objects or fail loudly). A level that is a
// target's own inode never gets here: walk skips it before sealing, so it stays a target.
func (bd *builder) seal(idx int, path string, kind entryKind, max accessFS) error {
	e := &bd.fds.open[idx]
	switch {
	case e.Kind == kind:
		return nil
	case e.Access&^max != 0:
		return fmt.Errorf("%w: %s %q is the same inode as the %s entry %q (a hardlink or a bind mount), whose rights %#x would reach what deny_read denies",
			ErrRulesetBuild, kindName(kind), path, kindName(e.Kind), e.Path, e.Access)
	}
	e.Kind = kind
	return nil
}

// resolveTarget resolves a target live (E12, E14) so the walk is over resolved directories: a symlinked
// ancestor never leaves the resolved location's siblings ungranted. A vanished target resolves its parent
// and keeps its own name (E9: enumeration is path-driven, not existence-driven).
func resolveTarget(p string) string {
	p = filepath.Clean(p)
	if resolved, err := filepath.EvalSymlinks(p); err == nil {
		return resolved
	}
	if parent, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
		return filepath.Join(parent, filepath.Base(p))
	}
	return p
}

// level lists one ancestor walk already holds with READ_DIR (R3 (3)) in a single snapshot (E28) and
// grants every sibling (R3 (2)); the ancestor itself never gets READ_FILE (R3 (1)). Landlock rules are
// hierarchical, so the ancestor's READ_DIR also lets the target directory be listed: the names inside
// a denied directory are visible, its file contents are not (verified on ABI 7).
func (bd *builder) level(idx int, dir string, onPath map[string]bool) error {
	names, err := listDir(bd.fds.open[idx].FD, dir, len(bd.fds.open))
	if err != nil {
		return err
	}
	bd.noteLevel(dir, names, onPath)
	for _, name := range names {
		if onPath[name] {
			continue
		}
		if err := bd.sibling(bd.fds.open[idx].FD, dir, name); err != nil {
			return err
		}
	}
	return nil
}

// listDir reopens the held O_PATH fd for reading and returns one snapshot of its names, raw bytes
// preserved (E13). The reopen is one more descriptor, so running out of them here is E11's exhaustion
// like any other open, and says so (ErrFDExhausted) with the count held, as openAt's does (§7): as
// ErrRulesetBuild alone it read as a broken ruleset, found as root in the KVM guest, where the test tree's
// ancestors include a /tmp to list.
//
// An ancestor the launcher may search but not read (mode --x to it, such as another user's 0711 home)
// refuses the reopen with EACCES. That level has no snapshot to take, so it lists as empty (E33): it
// stays held and sealed with READ_DIR, and none of its siblings is granted. That is more restrictive
// than the contract, never less (E10, E28): a name there the agent could open by name is refused too.
func listDir(pathFD int, dir string, held int) ([]string, error) {
	rfd, err := unix.Openat(pathFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.EMFILE) || errors.Is(err, unix.ENFILE) {
		return nil, fmt.Errorf("%w: %w: %d fds held when listing %q: %w", ErrRulesetBuild, ErrFDExhausted, held, dir, err)
	}
	if errors.Is(err, unix.EACCES) {
		return nil, nil // E33
	}
	if err != nil {
		return nil, fmt.Errorf("%w: listing %q: %w", ErrRulesetBuild, dir, err)
	}
	f := os.NewFile(uintptr(rfd), dir)
	defer func() { _ = f.Close() }()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("%w: listing %q: %w", ErrRulesetBuild, dir, err)
	}
	sort.Strings(names)
	return names, nil
}

// sibling grants one enumerated entry: a directory gets the read set, any other node READ_FILE (plus
// EXECUTE while exec is unrestricted); a symlink is skipped so it never grants its target (which has
// its own rule wherever it really lives); a name that vanished since the snapshot is skipped (E28); a
// name that is a deny node's inode under another name keeps that node's rights, because add never
// unions onto a sealed entry (I11, E32 (b)). A name that is the inode of something *inside* a directory
// target — a hardlink of a file in it, a bind mount of a directory in it — is no deny node: nothing
// short of scanning the target's subtree knows it, so it is granted, on that inode, and readable under
// every name. E32 records that limitation.
func (bd *builder) sibling(dirFD int, dir, name string) error {
	if err := bd.tick(); err != nil {
		return err
	}
	fd, st, err := openAt(dirFD, name, false, bd.fds)
	if err != nil {
		if errors.Is(err, ErrPathVanished) {
			return nil
		}
		return err
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return unix.Close(fd)
	}
	access := bd.readSet()
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		access &= fileRights
	}
	bd.fds.add(fd, filepath.Join(dir, name), kindDenySibling, bd.profile.mask(access), &st)
	return nil
}
