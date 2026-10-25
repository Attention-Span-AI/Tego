// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// fs.deny_write (ADR 0071) is the user's own list beside the built-in deny_write set (R20, compile_denywrite.go):
// literal files or directories beneath a write entry whose every modification is refused, the same set of actions a
// built-in target refuses. Both live in RuleTable.DenyWrite, so every tier enforces them through one path (the plane's
// inode rows at tier cgroup with a plane mode and at tier bpflsm, the supervisor's copied-name refusal, R15c, at tier
// landlock and on the fanotify listener); FSRule.BuiltIn keeps them apart, so R20's top-level write entry lifts only a
// built-in target, and only an fs.deny_write entry is reopened by a write entry strictly inside it (nearest wins).

// UserDenyWriteLabel is what every user-facing sentence about an fs.deny_write entry says (ADR 0071): it holds against
// the commands an agent ordinarily runs at every tier, and only a kernel decision plane holds it against an agent that
// races the supervisor's check.
const UserDenyWriteLabel = "blocked for ordinary commands; not race-free at the no-root tier"

// userDenyWrite is one fs.deny_write entry as declared and as placed.
type userDenyWrite struct {
	raw            string
	pos            Pos
	path, resolved string
	// name is where the entry's own final name lies (its directory placed, its name kept): resolved, unless the name
	// is a symlink, whose own place the agent could replace beneath a write entry whatever it leads to.
	name string
}

// places is where the entry is placed: where it leads, and the link that leads there when its name is one.
func (u userDenyWrite) places() []string {
	if u.name == u.resolved {
		return []string{u.resolved}
	}
	return []string{u.resolved, u.name}
}

// spelled is the entry's FSRule.Path: as declared, or, when its name is a symlink, the link's own place, where the
// kernel's lookup of any spelling of the link lands and the supervisor matches an end its spelling does not (R15c).
func (u userDenyWrite) spelled() string {
	if u.name == u.resolved {
		return u.path
	}
	return u.name
}

// resolveDenyWrite places each fs.deny_write entry as fs entries are placed (k.abs, then the kernel's walk), and its
// own name. A glob entry, which the schema refuses, is left out.
func (b *fsBuilder) resolveDenyWrite(entries []string) []userDenyWrite {
	out := make([]userDenyWrite, 0, len(entries))
	for i, raw := range entries {
		if raw == "" || hasGlobMeta(raw) {
			continue
		}
		p := b.k.abs(raw)
		u := userDenyWrite{raw: raw, pos: b.k.pos("fs.deny_write." + strconv.Itoa(i)), path: p,
			resolved: filepath.Clean(b.k.resolve(p))}
		u.name = u.resolved
		if dir := filepath.Dir(p); dir != p {
			u.name = filepath.Join(filepath.Clean(b.k.resolve(dir)), filepath.Base(p))
		}
		out = append(out, u)
	}
	return out
}

// reopens reports whether the write entry resolved at w lies strictly beneath an fs.deny_write entry, where nearest wins
// makes it the grant beneath itself rather than a narrower duplicate of the write entry above (E10).
func (b *fsBuilder) reopens(w string) bool {
	for _, u := range b.userDW {
		if u.resolved != w && isAncestorOrSelf(u.resolved, w) {
			return true
		}
	}
	return false
}

// compileDenyWrite compiles fs.deny_write into RuleTable.DenyWrite, after the built-in set: each entry beneath a write
// entry becomes FSRule{Kind: FSDenyWrite, BuiltIn: false, Unenforced: true}, named fs.deny_write[<entry>]. The placement
// rules:
//
//   - an entry at a write entry's own path is a contradiction, from any file: the two say opposite things of one place;
//   - an entry outside every write entry and every fs.ask scope refuses nothing that is not refused already: redundant
//     from the top-level file, silent from a profile, which cannot know its users' write entries;
//   - an entry that does not exist has no inode for any tier to hold, and the agent may create it: path-missing from the
//     top-level file, an unenforced warning from a profile;
//   - an entry beneath another with no write entry between is covered by it: redundant from the top-level file, silent
//     from a profile.
//
// An entry only an fs.ask scope covers joins RuleTable.AskDenyWrite instead (fsAsk), so no approval opens it.
func (b *fsBuilder) compileDenyWrite(writes []writePath) {
	k := b.k
	asks := k.askScopesResolved()
	type placed struct {
		u      userDenyWrite
		inside bool // beneath a write entry, not only an fs.ask scope
	}
	var kept []placed
	for _, u := range b.userDW {
		top := u.pos.File == k.top
		if w, ok := writeAt(writes, u.resolved); ok {
			pos, raw := b.writeEntry(w.declared)
			k.ds.errorf(u.pos, CodeContradiction, "fs.deny_write %q%s names the place of write entry %q (line %d): one refuses "+
				"every modification there and the other grants it", u.raw, resolvedNote(u.path, u.resolved), raw, pos.Line).
				fix("remove one of the two; to refuse part of the write entry, name that part in fs.deny_write")
			continue
		}
		// Placed at each of its places: a symlink beneath a write entry leading out of every one is held at
		// its name, or the agent could replace the link.
		inWrite, inAsk := false, false
		for _, at := range u.places() {
			_, w := enclosingWrite(writes, at)
			inWrite = inWrite || w
			inAsk = inAsk || slices.ContainsFunc(asks, func(a string) bool { return isAncestorOrSelf(a, at) })
		}
		if !inWrite && !inAsk {
			if top {
				k.ds.warnf(u.pos, CodeRedundantRule, "fs.deny_write %q%s lies outside every write entry, where every "+
					"modification is refused already", u.raw, resolvedNote(u.path, u.resolved)).
					fix("remove the entry, or name a place beneath a write entry")
			}
			continue
		}
		if _, err := os.Stat(u.path); err != nil {
			if top {
				k.ds.errorf(u.pos, CodePathMissing, "fs.deny_write %q: %s does not exist, so no tier has an inode to hold, "+
					"and the agent may create it", u.raw, u.path).
					fix("create it (an empty file or directory) before the run, or remove the entry")
			} else {
				k.ds.warnf(u.pos, CodeUnenforced, "fs.deny_write %q: %s does not exist, so no tier holds it, and the agent "+
					"may create it beneath the write entry", u.raw, u.path).
					fix("create it (an empty file or directory) before the run to have it refused")
			}
			continue
		}
		kept = append(kept, placed{u: u, inside: inWrite})
	}
	// reopened: a write entry lies strictly beneath outer and at or above inner.
	reopened := func(outer, inner string) bool {
		return slices.ContainsFunc(writes, func(w writePath) bool {
			return w.resolved != outer && isAncestorOrSelf(outer, w.resolved) && isAncestorOrSelf(w.resolved, inner)
		})
	}
	// matters: a place beneath a write entry or an fs.ask scope, where the entry refuses what nothing else does.
	matters := func(at string) bool {
		_, w := enclosingWrite(writes, at)
		return w || slices.ContainsFunc(asks, func(a string) bool { return isAncestorOrSelf(a, at) })
	}
	// coveredBy: another entry than kept[i] refuses every modification at the place at already: one with a place at
	// it (the earlier of two at one place), or above it with no write entry between.
	coveredBy := func(i int, at string) bool {
		for j := range kept {
			if j != i && slices.ContainsFunc(kept[j].u.places(), func(s string) bool {
				if s == at {
					return j < i
				}
				return isAncestorOrSelf(s, at) && !reopened(s, at)
			}) {
				return true
			}
		}
		return false
	}
	for i, p := range kept {
		// Covered when every place of it that matters is (placed by where it leads alone, an entry whose link lies outside
		// the covering entry was dropped, and the link left replaceable).
		covered := !slices.ContainsFunc(p.u.places(), func(at string) bool { return matters(at) && !coveredBy(i, at) })
		if covered {
			if p.u.pos.File == k.top {
				k.ds.warnf(p.u.pos, CodeRedundantRule, "fs.deny_write %q%s lies beneath another fs.deny_write entry with no "+
					"write entry between, which refuses every modification there already", p.u.raw, resolvedNote(p.u.path, p.u.resolved)).
					fix("remove the narrower entry")
			}
			continue
		}
		r := FSRule{Path: p.u.spelled(), Kind: FSDenyWrite, Raw: p.u.raw, Pos: p.u.pos, Resolved: p.u.resolved, Unenforced: true}
		b.metaDeclared(&r, p.u.pos)
		if !p.inside {
			k.askDenyWrite = append(k.askDenyWrite, r)
			continue
		}
		k.rt.DenyWrite = beforeBuiltInAt(k.rt.DenyWrite, r)
		under, ok := enclosingWrite(writes, r.Resolved)
		if !ok {
			under, _ = enclosingWrite(writes, p.u.name) // a link held at its name alone
		}
		b.warnUserDenyWrite(r, under)
	}
}

// beforeBuiltInAt adds the fs.deny_write rule r to the table's deny_write rules: just before a built-in target placed
// where r is, else at the end. A built-in target is never left out for an entry: it is never reopened
// and it holds its own link spelling, which the entry need not carry, so leaving it out let a nested write entry, or a
// replaced link, past R20. Every index answers with the lowest position that reaches a path, so where the entry
// reaches, the refusal names it as declared, and where a write entry reopens it, the built-in target still refuses.
func beforeBuiltInAt(rules []FSRule, r FSRule) []FSRule {
	for j := range rules {
		if rules[j].BuiltIn && rules[j].Resolved == r.Resolved {
			return slices.Insert(rules, j, r)
		}
	}
	return append(rules, r)
}

// writeAt is the write entry placed at res, if any.
func writeAt(writes []writePath, res string) (writePath, bool) {
	for _, w := range writes {
		if w.resolved == res {
			return w, true
		}
	}
	return writePath{}, false
}

// askScopesResolved is every literal fs.ask scope, placed: an fs.deny_write entry beneath one is kept from its approvals
// (compileDenyWrite).
func (k *compiler) askScopesResolved() []string {
	if k.c.FS == nil {
		return nil
	}
	var out []string
	for _, raw := range k.c.FS.Ask {
		if raw != "" && !hasGlobMeta(raw) {
			out = append(out, filepath.Clean(k.resolve(k.abs(raw))))
		}
	}
	return out
}

// warnUserDenyWrite is an fs.deny_write entry's compile finding, positioned at the entry, as warnDenyWrite's is for a
// built-in target (ADR 0041 D1 (a), ADR 0071 (3)): none where the table is held at tier bpflsm, whose plane always
// decides; by default a warning that the entry is best effort at tier landlock (and on tier cgroup's fanotify
// listener), recorded in run_start's best_effort as fs.deny_write; under fs.assurance: kernel an error at a tier landlock
// the contract pins or the machine config holds, since every run there is refused, and a warning elsewhere.
func (b *fsBuilder) warnUserDenyWrite(r FSRule, under writePath) {
	k := b.k
	if k.heldAt(backend.TierBPFLSM) {
		return
	}
	_, entry := b.writeEntry(under.declared)
	name := r.RuleName() + resolvedNote(r.Path, r.Resolved)
	if k.rt.FilesystemAssurance() != FSAssuranceKernel {
		k.ds.warnf(r.Pos, CodeUnenforced, "%s: %s; best effort at tier landlock (and tier cgroup on the fanotify listener): "+
			"Landlock cannot deny beneath the write entry %q, so the seccomp supervisor refuses a modification there on its "+
			"copied pathname, which a path or symlink swapped between its check and the kernel's own lookup, or a hard link "+
			"made before the run, can still get past, and run_start lists %s in best_effort; a decision plane (tier cgroup "+
			"with lsm or fmod_ret, or bpflsm) refuses it race-free", name, UserDenyWriteLabel, entry, BestEffortUserDenyWrite).
			fix("set fs.assurance: kernel to refuse a run no decision plane enforces it in, or run at a root tier with a decision plane")
		return
	}
	if k.rt.Tier == backend.TierLandlock && !k.buildCapped {
		k.ds.errorf(r.Pos, CodeUnenforced, "%s: fs.assurance: kernel needs a kernel decision plane to refuse modifications "+
			"beneath the write entry %q, and tier landlock has none, so every run of this contract is refused before the "+
			"child starts", name, entry).
			fix("run at a root tier with a kernel decision plane (tier: cgroup with lsm/fmod_ret, or bpflsm), or drop "+
				"fs.assurance: kernel to run with the supervisor's best-effort refusal (%s)", UserDenyWriteLabel)
		return
	}
	k.ds.warnf(r.Pos, CodeUnenforced, "%s: %s; fs.assurance: kernel refuses a run no kernel decision plane decides (tier "+
		"landlock, tier cgroup on the fanotify listener) before the child starts", name, UserDenyWriteLabel).
		fix("run where a decision plane loads (tier cgroup with lsm/fmod_ret, or bpflsm)")
}

// The bounds of the search for linked files beneath the deny_write directory targets (searchDenyWriteLinked). What it
// reads may be what an earlier run planted there before the entry existed, so it reads a bounded amount.
const (
	// maxDenyWriteLinked is how many linked files the plane keys for the targets together: a share of its fs rows
	// (decide.PlaneRowsMax, 4096), past which the table would fall back from the plane altogether.
	maxDenyWriteLinked = 256
	// maxDenyWriteLinkEntries is how many directory entries the search reads for the targets together;
	// maxDenyWriteLinkDepth how many levels beneath a target it descends; maxDenyWriteLinkTime how long it takes.
	maxDenyWriteLinkEntries = 1 << 15
	maxDenyWriteLinkDepth   = 16
	maxDenyWriteLinkTime    = 2 * time.Second
)

// searchDenyWriteLinked walks each deny_write directory target, an fs.deny_write directory entry or a built-in one
// (R20: .git/hooks, .claude), for the regular files beneath it with more than one hard link. A write
// through another name of such a file, which an earlier run could have made before the entry existed, walks from that
// name's directory to the write entry above it, so the plane refuses it only where the file's own inode is keyed, as a
// file entry's or a file target's is; keyDenyWriteLinked decides which files need that once every fs entry is in the
// table. Not searched: a subtree a nested write entry reopens (of an fs.deny_write entry; none reopens a built-in
// target), what a symlink leads to, and anything for a table held at tier landlock, where no plane decides and no tier
// sees the other name (the entry's best-effort warning says so). A search a bound cuts, or one that meets a directory
// it cannot list, is reported at the target (linkSearchCut).
func (b *fsBuilder) searchDenyWriteLinked(writes []writePath) {
	k := b.k
	if k.heldAt(backend.TierLandlock) {
		return
	}
	s := &linkSearch{left: maxDenyWriteLinkEntries, end: time.Now().Add(maxDenyWriteLinkTime), writes: writes,
		seen: map[string]bool{}, files: map[fileKey]int{}}
	for i := range k.rt.DenyWrite {
		// A built-in directory target is searched too: the same alias reaches a hook. No write entry reopens one, so
		// its search skips none.
		r := &k.rt.DenyWrite[i]
		if fi, err := os.Lstat(r.Resolved); err != nil || !fi.IsDir() {
			continue
		}
		s.why, s.at, s.reopens, s.pos = "", i, r.IsDeclaredDenyWrite(), r.Pos
		if w, ok := enclosingWrite(writes, r.Resolved); ok && !r.IsDeclaredDenyWrite() {
			s.pos, _ = b.writeEntry(w.declared) // a built-in target's findings are at the write entry it lies beneath
		}
		s.walk(r.Resolved, 0)
		if s.why != "" {
			k.linkSearchCut(r, s.pos, s.why)
		}
	}
	k.linked = s
}

// keyDenyWriteLinked sets RuleTable.DenyWriteLinked from the files searchDenyWriteLinked met: the ones the plane keys at
// their inodes. The plane keys one fs row per inode, and a table two of whose rows are one file runs on the fanotify
// listener at tier cgroup and is refused at tier bpflsm, so it records at most one name per file, the
// first the search met, and none for a file that needs no row of its own:
//
//   - every name of it lies beneath a target the search walked: each refuses by its path, and the target refuses a
//     link out of it;
//   - another row the plane keys holds its inode and refuses its modification (a deny_write file target, a deny_read
//     file entry): that row answers every name of the file. Compaction never drops such a row (ADR 0043 D6 keeps a
//     row whose file has another link).
//
// A file another row holds while granting its modification (an fs.write file entry, say) is a contradiction: one row
// answers every name of it, and the two entries say opposite things of the file. Past maxDenyWriteLinked rows the
// search is cut (linkSearchCut). It runs after every pass that adds an fs entry (fsAskRead's).
func (k *compiler) keyDenyWriteLinked() {
	s := k.linked
	if s == nil || len(s.found) == 0 {
		return
	}
	need := make(map[fileKey]bool, len(s.found))
	for _, f := range s.found {
		if f.met < f.nlink {
			need[f.key] = true
		}
	}
	rows := k.planeFileRows(need)
	for _, f := range s.found {
		if !need[f.key] {
			continue
		}
		r := &k.rt.DenyWrite[f.at]
		if q, held := rows[f.key]; held {
			if q.grant >= 0 {
				k.ds.errorf(f.pos, CodeContradiction, "%s%s: %s beneath it is %s under another name (a hard link), which %s "+
					"lets the agent modify; the plane keys one row per file, so one answer holds for every name of it, and the "+
					"two entries say opposite things of the file", r.RuleName(), resolvedNote(r.Path, r.Resolved), f.path,
					q.path, k.rt.FS[q.grant].RuleName()).
					fix("remove the hard link (keep a copy of the file instead), or remove one of the two entries")
			}
			continue
		}
		if len(k.rt.DenyWriteLinked) == maxDenyWriteLinked {
			k.linkSearchCut(r, f.pos, "more than "+strconv.Itoa(maxDenyWriteLinked)+" such files")
			return
		}
		k.rt.DenyWriteLinked = append(k.rt.DenyWriteLinked, f.path)
	}
}

// linkSearchCut reports a linked-file search a bound cut beneath the deny_write target r, at pos: a file there it did
// not reach may be written through a name no row keys, at every tier. By default a warning; under fs.assurance: kernel
// an error, since that setting refuses a run in which no kernel decision plane holds a target, and the
// plane holds this one against a hard-link alias only where the search reached.
func (k *compiler) linkSearchCut(r *FSRule, pos Pos, why string) {
	what := r.RuleName() + resolvedNote(r.Path, r.Resolved) + ": the search beneath it for files with another hard link " +
		"stopped at " + why + ", so a file there that an earlier run linked from elsewhere may be written through that " +
		"other name at every tier"
	const fix = "remove the other hard links of the files beneath it (find %s -type f -links +1), or name such a file in " +
		"fs.deny_write, which the plane keys at its own inode"
	if k.rt.FilesystemAssurance() == FSAssuranceKernel {
		k.ds.errorf(pos, CodeUnenforced, "%s; fs.assurance: kernel needs a kernel decision plane to refuse every name of "+
			"every file beneath it, so the contract does not compile", what).
			fix(fix+", or drop fs.assurance: kernel to run with this warning", r.Resolved)
		return
	}
	k.ds.warnf(pos, CodeUnenforced, "%s", what).fix(fix, r.Resolved)
}

// fileKey is a file's identity, its device and inode numbers: what the plane keys an fs row at.
type fileKey struct{ dev, ino uint64 }

// fileKeyOf is fi's identity, false when the platform reports none.
func fileKeyOf(fi os.FileInfo) (fileKey, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fileKey{}, false
	}
	return fileKey{dev: uint64(st.Dev), ino: uint64(st.Ino)}, true //nolint:unconvert // Dev and Ino are uint64 on linux/amd64 and arm64, not everywhere
}

// planeFileRow is a regular file the plane keys a row at for a deny_write target or an fs entry: its path, and the
// rt.FS index of the write entry through which its row grants a modification, -1 when the row refuses one.
type planeFileRow struct {
	path  string
	grant int
}

// planeFileRows is the rows of planeFileRow's kind whose file is one of need, by identity, stated as the plane's own
// shared-inode check states them, following a final symlink (decide.CompilePlane keys these paths): each deny_write
// target beneath a write entry, which refuses its modification, and each fs entry's canonical path, whose row answers a
// modification as planeModifyGrant says. One identity under two such rows is held granting when either grants.
func (k *compiler) planeFileRows(need map[fileKey]bool) map[fileKey]planeFileRow {
	out := map[fileKey]planeFileRow{}
	add := func(p string, grant func() int) {
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() {
			return
		}
		key, ok := fileKeyOf(fi)
		if !ok || !need[key] {
			return
		}
		g := grant()
		if have, dup := out[key]; dup && (have.grant >= 0 || g < 0) {
			return
		}
		out[key] = planeFileRow{path: p, grant: g}
	}
	refuses := func() int { return -1 }
	for i := range k.rt.DenyWrite {
		g := filepath.Clean(k.rt.DenyWrite[i].Governed())
		if slices.ContainsFunc(k.rt.FS, func(w FSRule) bool { return w.Kind == FSWrite && isAncestorOrSelf(w.Canonical(), g) }) {
			add(g, refuses)
		}
	}
	for i := range k.rt.FS {
		if r := &k.rt.FS[i]; r.Path != "" {
			q := r.Canonical()
			add(q, func() int { return k.planeModifyGrant(q) })
		}
	}
	return out
}

// planeModifyGrant is the rt.FS index of the write entry through which the plane's row at q grants a modification, as
// decide's compileRow answers it, -1 when the row refuses one: q lies at or beneath a deny_write target
// (DenyWriteTarget), or the nearest path at or above q that an entry of any kind but watch names is not a write
// entry's (SEMANTICS §2's walk; the lowest such entry there decides, and any write entry there grants here, the
// stricter reading), or no entry names any (an unmatched modification, refused).
func (k *compiler) planeModifyGrant(q string) int {
	if _, ok := k.rt.DenyWriteTarget(q, false); ok {
		return -1
	}
	for cur := q; ; cur = filepath.Dir(cur) {
		decided, write := false, -1
		for i := range k.rt.FS {
			r := &k.rt.FS[i]
			if r.Kind == FSWatch || !slices.ContainsFunc(r.Spellings(), func(s string) bool { return filepath.Clean(s) == cur }) {
				continue
			}
			decided = true
			if r.Kind == FSWrite && write < 0 {
				write = i
			}
		}
		if decided || cur == filepath.Dir(cur) {
			return write
		}
	}
}

// linkedFile is a regular file with more than one hard link that the search met beneath a deny_write directory target.
type linkedFile struct {
	key   fileKey
	path  string // the first of its names the search met
	at    int    // the rt.DenyWrite index of the target the search met that name beneath
	pos   Pos    // where that target's findings are positioned
	met   uint64 // how many of its names the search met beneath the targets it walked
	nlink uint64
}

// linkSearch is searchDenyWriteLinked's walk, what it has left of its bounds and what it found. Its files are bounded
// by the directory entries it reads.
type linkSearch struct {
	left    int
	end     time.Time
	writes  []writePath
	at      int  // the rt.DenyWrite index of the target being walked
	pos     Pos  // where that target's findings are positioned
	reopens bool // a write entry beneath the current target reopens its subtree (an fs.deny_write entry's)
	seen    map[string]bool
	files   map[fileKey]int // found's index of each file
	found   []linkedFile
	why     string // the bound that cut the walk of the current target, "" while none has
}

func (s *linkSearch) walk(dir string, depth int) {
	switch {
	case time.Now().After(s.end):
		s.why = "its time limit (" + maxDenyWriteLinkTime.String() + ")"
		return
	case depth > maxDenyWriteLinkDepth:
		s.why = strconv.Itoa(maxDenyWriteLinkDepth) + " levels beneath the entry"
		return
	case s.left <= 0:
		s.why = "its bound of " + strconv.Itoa(maxDenyWriteLinkEntries) + " directory entries read"
		return
	}
	limit := min(s.left, maxDirEntries)
	es, more, err := listDir(dir, limit)
	s.left -= len(es)
	switch {
	case more && limit < maxDirEntries:
		s.why = "its bound of " + strconv.Itoa(maxDenyWriteLinkEntries) + " directory entries read"
		return
	case err != nil || more:
		s.why = "a directory it could not list whole, " + dir
		return
	}
	for _, e := range es {
		p := filepath.Join(dir, e.Name())
		if s.reopens && slices.ContainsFunc(s.writes, func(w writePath) bool { return w.resolved == p }) {
			continue // a write entry reopens it (nearest wins)
		}
		switch {
		case e.IsDir():
			s.walk(p, depth+1)
		case e.Type().IsRegular() && !s.seen[p]:
			s.seen[p] = true
			s.record(p, e)
		}
		if s.why != "" {
			return
		}
	}
}

// record counts p, a regular file the walk met, under its file's identity when it has another hard link.
func (s *linkSearch) record(p string, e os.DirEntry) {
	fi, err := e.Info()
	if err != nil || nlinkOf(fi) < 2 {
		return
	}
	key, ok := fileKeyOf(fi)
	if !ok {
		return
	}
	if i, dup := s.files[key]; dup {
		s.found[i].met++
		return
	}
	s.files[key] = len(s.found)
	s.found = append(s.found, linkedFile{key: key, path: p, at: s.at, pos: s.pos, met: 1, nlink: nlinkOf(fi)})
}
