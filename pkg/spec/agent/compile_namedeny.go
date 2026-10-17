// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// This file compiles ADR 0043's name entries (RuleTable.NameDeny, NameExempt) beside the compile-time expansion
// they stand behind: the built-in .env list's two entries, scoped to the scan's roots, and every whole deny_read
// glob whose final component is a literal or a literal prefix, scoped to the glob's literal base. The expansion
// stays as it is (every tier keeps its rows; tier landlock has nothing else); the entries are what the root tiers'
// models decide created-later files by.

// nameReach reports whether a run of the table can be given a tier name entries apply at (ADR 0043 D7): cgroup, in
// a plane mode or on the fallback, or bpflsm. A table that can only land at tier landlock compiles none, prints
// nothing new and makes no syscall for them.
func (k *compiler) nameReach() bool {
	return k.mayLand(backend.TierCgroup) || k.mayLand(backend.TierBPFLSM)
}

// nameGlob records a whole deny_read glob's name entry candidate (ADR 0043 Terms): its final component classified by
// NameEntryOf, its scope the glob's literal base, which must exist as a directory. A glob that matched nothing has
// one too: it is the files created later the entry is for.
func (b *fsBuilder) nameGlob(p, raw string, pos Pos) {
	if !b.k.nameReach() {
		return
	}
	lit, prefix, ok := NameEntryOf(filepath.Base(p))
	if !ok {
		return
	}
	base := globBase(p)
	if fi, err := os.Stat(base); err != nil || !fi.IsDir() {
		return
	}
	b.declNames = append(b.declNames, NameDenyRule{Literal: lit, Prefix: prefix, Raw: raw, Pos: pos,
		Scopes: []NameScope{{Canonical: b.k.resolve(base), Spelling: base}}})
}

// envNameScopes is the built-in entries' scopes (ADR 0043 D10, scoped): the scan's roots, each by its resolved path,
// less a root beneath another with no dependency directory between them, whose files the other covers.
func (b *fsBuilder) envNameScopes(roots []string) []NameScope {
	var all []NameScope
	for _, r := range roots {
		if fi, err := os.Stat(r); err != nil || !fi.IsDir() {
			continue
		}
		c := b.k.resolve(r)
		if !slices.ContainsFunc(all, func(s NameScope) bool { return s.Canonical == c }) {
			all = append(all, NameScope{Canonical: c, Spelling: r})
		}
	}
	var out []NameScope
	for i, s := range all {
		nested := false
		for j, t := range all {
			if i == j || t.Canonical == s.Canonical {
				continue
			}
			if _, _, covered, _ := NameClimb([]NameScope{t}, joinName(s.Canonical, "x")); covered {
				nested = true
				break
			}
		}
		if !nested {
			out = append(out, s)
		}
	}
	return out
}

// envNames records the built-in .env list's two entries over scopes: `.env` exact, and `.env.` as a prefix but its
// example files, the scan's own predicate (isEnvFile) as name entries.
func (b *fsBuilder) envNames(scopes []NameScope) {
	if !b.k.nameReach() || len(scopes) == 0 {
		return
	}
	b.builtInNames = BuiltInEnvEntries(scopes)
}

// topLevelWrite is the write entry declared in the top-level contract file, not in a profile it extends, whose
// resolved path is resolved (ADR 0043 D3), and its position in the table; -1 when none is.
func (b *fsBuilder) topLevelWrite(resolved string) int {
	for i := range b.rules {
		if r := &b.rules[i]; r.Kind == FSWrite && r.Resolved == resolved && r.Pos.File == b.k.top {
			return i
		}
	}
	return -1
}

// envWriteDrop reports whether a write entry of the top-level contract file names the built-in .env file at
// resolved, which drops it from the built-in list with a warning naming both (ADR 0043 D3; agent-contract R20's
// parallel for a built-in deny_write target): the author granted it. A write entry from a profile stays the
// contradiction it was (unenforced), so a profile cannot remove a built-in protection.
func (b *fsBuilder) envWriteDrop(p, resolved string) bool {
	i := b.topLevelWrite(resolved)
	if i < 0 {
		return false
	}
	w := &b.rules[i]
	b.k.ds.warnf(w.Pos, CodeUnenforced, "fs.write %q names %s%s, a file of the built-in deny_read list of .env files, so it leaves that list: the agent may read and write it",
		w.Raw, p, resolvedNote(p, resolved)).
		fix("drop the write entry to keep %s unreadable", p)
	return true
}

// nameEntries settles the table's name entries (ADR 0043 Terms): the candidates in allocation order, D3's
// exemptions, the caps (FitNameEntries), then NameDeny in its deciding order: declared entries in declared order,
// the built-in exact entry, the built-in prefix entry. It runs once the fs rules are complete, so an exemption can
// name its write entry's position.
func (b *fsBuilder) nameEntries() {
	k := b.k
	if !k.nameReach() || len(b.builtInNames)+len(b.declNames) == 0 {
		return
	}
	cands := append(slices.Clone(b.builtInNames), b.declNames...)
	exempts := b.nameExempts(cands)
	kept, keptExempt, left := FitNameEntries(cands, exempts)
	var order []NameDenyRule
	for _, e := range kept {
		if !e.BuiltIn {
			order = append(order, e)
		}
	}
	for _, e := range kept {
		if e.BuiltIn {
			order = append(order, e)
		}
	}
	for i := range order {
		for _, s := range order[i].Scopes {
			order[i].BindExposed = order[i].BindExposed || b.mt.bindExposed(s.Canonical)
		}
	}
	k.rt.NameDeny, k.rt.NameExempt, k.rt.NameLeftOut = order, keptExempt, left
	b.laterCoveredWarnings(order)
	for _, l := range left {
		pos := l.Entry.Pos
		what := "deny_read " + strconv.Quote(l.Entry.Raw)
		if l.Entry.BuiltIn {
			pos, what = k.cpos, "the built-in deny_read entry "+l.Entry.Form()
		}
		k.ds.warnf(pos, CodeUnenforced, "%s has no name entry (%s), so a matching file created later is not denied at tiers cgroup and bpflsm; the files that exist now are",
			what, l.Why).
			fix("name fewer deny_read globs, or name the files themselves")
	}
	b.nameScopeWarnings()
	b.compactionFacts()
}

// laterCovered is what a glob warning says of files created later once the glob's name entry is kept.
const laterCovered = laterCoveredRoot + ", not at tier landlock"

// laterCoveredRoot is laterCovered's root-tier half, which heldGlobNotes keeps where held reads cover tier landlock too.
const laterCoveredRoot = "files created later are covered at tiers cgroup and bpflsm by its name entry"

// laterCoveredWarnings rewrites the glob warning of each declared glob whose name entry the caps kept (ADR 0043:
// at tiers cgroup and bpflsm the entry refuses a file created later at a name it matches, which compile's names
// section says too); a glob whose entry was left out keeps "not covered", beside its own unenforced warning.
func (b *fsBuilder) laterCoveredWarnings(kept []NameDenyRule) {
	for _, w := range b.nameGlobWarns {
		if !slices.ContainsFunc(kept, func(e NameDenyRule) bool { return !e.BuiltIn && e.Raw == w.raw && e.Pos == w.pos }) {
			continue
		}
		d := &b.k.ds.list[w.diag]
		d.Message = strings.Replace(d.Message, "files created later are not covered", laterCovered, 1)
	}
}

// nameExempts is ADR 0043 D3's exemptions among the table's write entries: an entry declared in the top-level
// contract file at an existing file whose resolved final name, folded, some candidate matches, keyed by the resolved
// parent. A write entry that does not exist is a directory run creates, which no name entry decides; when its name
// would match one, compile says how to let the agent use such a file.
func (b *fsBuilder) nameExempts(cands []NameDenyRule) []NameExemptRule {
	var out []NameExemptRule
	for i := range b.rules {
		r := &b.rules[i]
		if r.Kind != FSWrite || r.Pos.File != b.k.top || r.Resolved == "" || r.Resolved == "/" {
			continue
		}
		spelled := filepath.Base(r.Resolved)
		name := FoldName(spelled)
		if !slices.ContainsFunc(cands, func(e NameDenyRule) bool { return e.Matches(spelled) }) {
			continue
		}
		if r.Missing {
			b.k.ds.warnf(r.Pos, CodeUnenforced, "fs.write %q does not exist, so run creates it as a directory, and a name entry covers a file of that name: the agent cannot create one there at tiers cgroup and bpflsm",
				r.Raw).
				fix("to let the agent use a %s file, create it before the run and name it in fs.write", filepath.Base(r.Resolved))
			continue
		}
		if fi, err := os.Lstat(r.Resolved); err != nil || fi.IsDir() {
			continue
		}
		out = append(out, NameExemptRule{Parent: filepath.Dir(r.Resolved), Name: name, Write: i})
	}
	return out
}

// nameScopeWarnings says where a scope lies on a filesystem that gives one file other spellings than the ASCII case
// folds (ADR 0043 Residuals): a vfat, exfat, ntfs3 or network filesystem, where such a spelling of a covered name is
// not covered.
func (b *fsBuilder) nameScopeWarnings() {
	seen := map[string]bool{}
	for _, e := range b.k.rt.NameDeny {
		for _, s := range e.Scopes {
			if seen[s.Canonical] {
				continue
			}
			seen[s.Canonical] = true
			m, _, ok := b.mt.lookup(s.Canonical)
			if !ok || !aliasingFS(m.fstype) {
				continue
			}
			b.k.ds.warnf(b.k.cpos, CodeMountWarning, "name entries are scoped to %s, on %s, which gives one file other spellings than ASCII case: a file reached by another spelling of a covered name is not covered",
				s.Spelling, m.fstype).
				fix("keep the project on a filesystem with one spelling per file (ext4, xfs, btrfs, tmpfs)")
		}
	}
}

// aliasingFS reports a filesystem whose files have spellings other than their names' bytes and ASCII case (8.3
// aliases, DOS names, server-side case folding).
func aliasingFS(fstype string) bool {
	switch fstype {
	case "vfat", "msdos", "exfat", "ntfs3", "ntfs", "cifs", "smb3", "9p", "fuseblk":
		return true
	}
	return strings.HasPrefix(fstype, "fuse.")
}

// fsCasefoldFlag is FS_CASEFOLD_FL, the inode flag of a directory whose names compare case-insensitively.
const fsCasefoldFlag = 0x40000000

// compactionFacts records ADR 0043 D6 (e)'s fact a covered file's row may be compacted on: whether its directory
// carries FS_CASEFOLD_FL, on the filesystems that support the flag (ext4, f2fs, tmpfs). It is read only where the
// plane could compact (more keyed paths than NameCompactAt), per directory, and inside the .env scan's own time
// limit (I6: the agent chooses how many .env files exist and where); a directory left unread keeps every row under
// it. xfs and btrfs have no such flag; every other filesystem keeps its rows anyway.
func (b *fsBuilder) compactionFacts() {
	if len(b.rules) <= NameCompactAt || len(b.k.rt.NameDeny) == 0 {
		return
	}
	end := b.envEnd
	if end.IsZero() {
		end = time.Now().Add(envScanMaxTime)
	}
	flags := map[string]bool{}
	for i := range b.rules {
		r := &b.rules[i]
		if r.Kind != FSDenyRead || !r.Regular {
			continue
		}
		switch r.Filesystem {
		case "ext4", "f2fs", "tmpfs":
		default:
			continue
		}
		dir := filepath.Dir(r.Canonical())
		exact, done := flags[dir]
		if !done {
			if time.Now().After(end) {
				return
			}
			exact = dirCaseExact(dir)
			flags[dir] = exact
		}
		r.DirCaseExact = exact
	}
}

// dirCaseExact reports whether the directory's inode flags were read and carry no FS_CASEFOLD_FL. An open or ioctl
// that fails is a no: the row stays.
func dirCaseExact(dir string) bool {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	defer func() { _ = unix.Close(fd) }()
	f, err := unix.IoctlGetUint32(fd, unix.FS_IOC_GETFLAGS)
	return err == nil && f&fsCasefoldFlag == 0
}

// nameAskWarnings says where an fs.ask entry names a file a name entry covers (ADR 0043 D3): no ask entry exempts
// one, so an approval of it is refused without a prompt at the tiers that enforce name entries.
func (k *compiler) nameAskWarnings() {
	if len(k.rt.NameDeny) == 0 {
		return
	}
	for _, r := range k.rt.FSAsk {
		p := r.Canonical()
		if fi, err := os.Lstat(p); err == nil && fi.IsDir() {
			continue
		}
		name := filepath.Base(p)
		for i := range k.rt.NameDeny {
			e := &k.rt.NameDeny[i]
			if _, _, covered, _ := NameClimb(e.Scopes, p); covered && e.Matches(name) {
				k.ds.warnf(r.Pos, CodeUnenforced, "fs.ask %q names a file %s covers, which no approval reopens: an ask of it is refused without a prompt at tiers cgroup and bpflsm",
					r.Raw, e.RuleName(0)).
					fix("name the file in fs.write in the top-level contract to let the agent use it")
				break
			}
		}
	}
}
