// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// Snapshot is the deny_read enumeration as Prepare froze it (R3, E28), kept so the supervisor can say what the kernel
// will answer for a read beneath an enumerated ancestor (ADR 0069's 2026-10-26 note). Landlock is an allow-list:
// a deny_read is built by granting every sibling of each ancestor of the target, as one listing at launch named them,
// and the ancestor itself READ_DIR only. A name made beside an ancestor after that listing (a directory a person
// creates in $HOME while a run's built-in ~/.ssh deny_read is in force, a file in the project's root beside ./secret/)
// is no sibling: Landlock refuses a read of any file beneath it for the rest of the run, while the decision core,
// which reasons on the contract's paths, answers allow. The snapshot never widens anything; it lets the record say
// what happened instead of allow.
//
// It holds no descriptor: the ancestors' listings by name and the identity of every inode the ruleset grants READ_FILE
// on. The ruleset's own references keep those inodes alive while the run's domain lives, so an identity in reads never
// names another file during the run. It is immutable after Prepare and safe for concurrent use.
type Snapshot struct {
	levels map[string]snapshotLevel // enumerated ancestor -> its one listing at launch
	reads  map[devIno]bool          // every held inode whose rule grants READ_FILE (true) or nothing to read (false)
	lstat  func(path string, st *unix.Stat_t) error
	// renumbers reports whether the file system at a path may give a file a new inode number without replacing it
	// (an overlayfs copy-up, ADR 0010).
	renumbers func(path string) bool
}

// snapshotLevel is one enumerated ancestor: every name its listing returned, and the names on the path to a target
// (which the enumeration did not grant, and which the decision core already decides).
type snapshotLevel struct {
	listed map[string]bool
	onPath map[string]bool
}

// noteLevel records one ancestor's listing as level took it.
func (bd *builder) noteLevel(dir string, names []string, onPath map[string]bool) {
	if bd.levels == nil {
		bd.levels = map[string]snapshotLevel{}
	}
	listed := make(map[string]bool, len(names))
	for _, n := range names {
		listed[n] = true
	}
	bd.levels[dir] = snapshotLevel{listed: listed, onPath: onPath}
}

// snapshot is the run's Snapshot once every stage has held and unioned its rights, nil when no ancestor was
// enumerated (nothing denied, or every target unenforced).
func (bd *builder) snapshot() *Snapshot {
	if len(bd.levels) == 0 {
		return nil
	}
	reads := make(map[devIno]bool, len(bd.fds.ids))
	for id, i := range bd.fds.ids {
		reads[id] = bd.fds.open[i].Access&accessReadFile != 0
	}
	return &Snapshot{levels: bd.levels, reads: reads, lstat: lstatNoAutomount, renumbers: onOverlay}
}

// onOverlay reports whether path lies on an overlayfs, whose copy-up can renumber a non-directory (ADR 0010); a
// file system that cannot be asked counts as one.
func onOverlay(path string) bool {
	var fs unix.Statfs_t
	return unix.Statfs(path, &fs) != nil || fs.Type == unix.OVERLAYFS_SUPER_MAGIC
}

// lstatNoAutomount stats a path without following its final symlink or triggering an automount, so the question asked
// changes nothing it asks about.
func lstatNoAutomount(path string, st *unix.Stat_t) error {
	return unix.Fstatat(unix.AT_FDCWD, path, st, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT)
}

// DenyReadSnapshot is the run's Snapshot's Refuses, nil when the ruleset enumerated no ancestor.
func (h *Handle) DenyReadSnapshot() func(path string) bool {
	if h.snapshot == nil {
		return nil
	}
	return h.snapshot.Refuses
}

// DenyReadFrozen is the directories the run's deny_read enumeration listed once at launch (Snapshot.Frozen), nil when
// the ruleset enumerated no ancestor.
func (h *Handle) DenyReadFrozen() []string { return h.snapshot.Frozen() }

// Frozen is every ancestor the enumeration listed (R3 (3), E28), sorted, in a slice of its own: a name made directly in
// one of them after launch is no sibling the ruleset grants, so a read beneath it is refused until the run ends
// (GAPS A12). run_start.deny_read_frozen and the run's note name them. nil for a nil Snapshot.
func (s *Snapshot) Frozen() []string {
	if s == nil {
		return nil
	}
	return slices.Sorted(maps.Keys(s.levels))
}

// Refuses reports whether the run's Landlock ruleset refuses a read open of the object at p, a resolved absolute path
// (no symlink on it) that the decision core allows, because p lies beneath an enumerated ancestor through a name that
// ancestor's listing did not grant. It answers as the kernel will, from the tree as it stands now: Landlock unions the
// rights of the rules on every inode from p up to the root, so p is readable when any inode on that chain is one the
// ruleset grants READ_FILE on, and a directory is listable beneath any ancestor (READ_DIR). It answers true only when
// it knows that no such inode lies on the chain and p is no directory; every doubt answers false, leaving the open
// to the kernel and its line to the decision core:
//
//   - p not beneath any enumerated ancestor, or beneath a target's name (the decision core decides those);
//   - a component that cannot be stat'ed, or one that is a symlink now (the tree moved since p was resolved);
//   - a non-directory named at launch whose inode the ruleset does not hold, on an overlayfs: a copy-up can renumber a
//     file (ADR 0010), which reads as the replacement it may also be. Elsewhere such a file is a replacement (an
//     editor's save by rename, a file deleted and made again), and the ruleset refuses it as a new name.
//
// The fast path is one fstatat: the name beneath the deepest ancestor, granted at launch. A rename keeps a granted
// sibling granted under its new name (Landlock's rule is on the inode), and a directory held as a write entry and moved
// into a new directory stays readable; both are found by identity, not by name.
func (s *Snapshot) Refuses(p string) bool {
	if s == nil || !strings.HasPrefix(p, "/") {
		return false
	}
	p = filepath.Clean(p)
	level, name := "", ""
	for cur := p; cur != "/"; cur = filepath.Dir(cur) {
		if _, ok := s.levels[filepath.Dir(cur)]; ok {
			level, name = filepath.Dir(cur), filepath.Base(cur)
			break
		}
	}
	if level == "" || s.levels[level].onPath[name] {
		return false
	}
	var st unix.Stat_t
	if s.lstat(filepath.Join(level, name), &st) != nil {
		return false
	}
	read, held := s.reads[devIno{dev: st.Dev, ino: st.Ino}]
	if read || (!held && s.levels[level].listed[name] && st.Mode&unix.S_IFMT != unix.S_IFDIR && s.renumbers(filepath.Join(level, name))) {
		return false
	}
	for cur := p; ; cur = filepath.Dir(cur) {
		if err := s.lstat(cur, &st); err != nil || st.Mode&unix.S_IFMT == unix.S_IFLNK {
			return false
		}
		if (cur == p && st.Mode&unix.S_IFMT == unix.S_IFDIR) || s.reads[devIno{dev: st.Dev, ino: st.Ino}] {
			return false
		}
		if cur == "/" {
			return true
		}
	}
}
