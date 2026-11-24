// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// mountAliases gives every fs entry the other names the mount table gives its file (ADR 0011, amended 2026-11-19,
// rounds 4 and 5): a rule is about the file, not one of its names. Every name comes from one computation
// (compiler.otherNamesOf: the table's rows of the same filesystem instance, each name confirmed by device AND inode),
// whatever the entry's kind, and each kind's other names are then what the kernel makes of them:
//
//   - a write entry's other names are write entries too (AliasOf names the original), because Landlock keys a grant
//     to the inode: a write through a bind of the entry, or of a directory above it, is allowed, so every question
//     asked by name (underWrite, aliasUnenforced, the Landlock builder's nesting, decide.LandlockRuleset) sees the
//     grant where the kernel has it. A part of the entry's tree bound elsewhere is not: the kernel's walk from it never
//     meets the entry's inode. A deny entry that lies under another name of a write entry is nested in it, and a
//     built-in row absent at compile there is left out, as for any write entry;
//   - every deny_read entry (declared, built in, tego's own, fs.ask_read, the built-in refusals' read targets) and
//     every built-in row absent at compile gets each other name as an entry of the same kind and rule name: tier
//     landlock's enumeration then descends to it and leaves it out, the held-read floor refuses it, and one a write
//     grant reaches is nested (held) as any other;
//   - every deny_write target, built in or declared, gets each other name, wherever it lies, so the supervisor's
//     floor (RuleTable.DenyWriteTarget, matched by spelling) refuses a write there as it refuses one at the original.
//
// A name the table gives that reaches another file now (a covered mount) shows other content, and a run cannot
// uncover it (Landlock forbids mount changes), so it is left out. Mounts made after compile are not seen (GAPS C68).
// Names a table cannot give (another filesystem instance of the same data, a FUSE mirror, hard links) stay outside
// this, as C68 says.
//
// It fails closed (Y5): with a mount table that cannot be read whole, or a deny entry whose other names cannot all be
// listed (an unlinked directory root on its device, a mount that cannot be placed), compile refuses with the reason.
// A disabled probe (WithMountInfo("")) has no mount facts by the caller's choice and adds nothing.
//
// It runs after every pass that adds an fs entry and before the passes that read them (heldReads,
// keyDenyWriteLinked, the exec grants). otherNamesEnforced, after the exec grants, refuses a contract where some other
// name of a denied file is one no layer refuses in the contract's mode.
func (k *compiler) mountAliases() {
	mt, err := k.mountTable()
	if mt == nil || !mt.probed {
		return
	}
	if err != nil {
		k.ds.errorf(k.cpos, CodeMountWarning, "the mount table cannot be read whole (%v): tego cannot list the other names "+
			"it gives the files these rules deny, so a denied file could be read or written under a name no rule covers", err).
			fix("run where %s can be read (a mounted /proc), or report the table that cannot be parsed", liveMountInfo)
		return
	}
	p := &aliasPass{k: k, mt: mt}
	p.writes()
	p.nested()
	p.denyReads()
	p.absent()
	p.denyWrites()
	p.refuseDoubt()
}

// aliasPass is one compile's mountAliases: the table, and the deny entries whose other names it could not all list.
type aliasPass struct {
	k  *compiler
	mt *mountTable
	// doubt is why the first uncertain deny entry's list may be short, and unsure how many deny entries share it.
	doubt  string
	unsure int
}

// names is otherNamesOf for a deny entry: a list that may be short is counted (refuseDoubt).
func (p *aliasPass) names(path string, beneath bool) []aliasName {
	ns, why := p.k.otherNamesOf(p.mt, path, beneath)
	if why != "" {
		if p.doubt == "" {
			p.doubt = why + " (for " + path + ")"
		}
		p.unsure++
	}
	return ns
}

// writes adds each write entry's other names as write entries (see mountAliases). Only names that show the entry
// itself count: a row whose root lies at or above the entry's place. A write entry that does not exist yet (Missing,
// the run creates it) is named under each other name of its parent, where the run's mkdir lands.
func (p *aliasPass) writes() {
	k := p.k
	have := map[string]bool{}
	for _, r := range k.rt.FS {
		if r.Kind == FSWrite {
			have[r.Canonical()] = true
		}
	}
	for i, n := 0, len(k.rt.FS); i < n; i++ {
		w := k.rt.FS[i]
		if w.Kind != FSWrite || w.AliasOf != "" || w.Runtime != "" {
			continue
		}
		c := w.Canonical()
		ns, _ := k.otherNamesOf(p.mt, c, false) // a write entry's doubt is its deny entries' (same device): counted there
		for _, a := range ns {
			if a.original != c || have[a.alias] {
				continue
			}
			have[a.alias] = true
			k.rt.FS = append(k.rt.FS, FSRule{Path: a.alias, Resolved: a.alias, Kind: FSWrite, Access: w.Access, Raw: w.Raw,
				Pos: w.Pos, BuiltIn: w.BuiltIn, BuiltinRule: w.BuiltinRule, Missing: w.Missing, AliasOf: w.Path})
		}
	}
}

// nested marks what another name of a write entry reaches, as unenforced() and absentBuiltIn mark what the entry's own
// name reaches: a deny_read entry beneath it is unenforced at tier landlock and held (a write entry's other name at
// exactly a deny_read entry is a contradiction), a built-in row absent at compile beneath it is left out, and a
// deny_write target beneath it is refused by the supervisor's floor alone.
func (p *aliasPass) nested() {
	k := p.k
	var aliases []FSRule
	for _, w := range k.rt.FS {
		if w.Kind == FSWrite && w.AliasOf != "" {
			aliases = append(aliases, w)
		}
	}
	if len(aliases) == 0 {
		return
	}
	for i := range k.rt.FS {
		r := &k.rt.FS[i]
		if r.Kind != FSDenyRead || r.Unenforced {
			continue
		}
		for _, w := range aliases {
			if w.Canonical() == r.Canonical() {
				k.ds.errorf(r.Pos, CodeContradiction, "deny_read %s is write entry %s under another name the mount table "+
					"gives the same file (%s): one grants what the other refuses", rawOr(r.Raw, r.Path), rawOr(w.Raw, w.AliasOf), w.Path).
					fix("deny a path beneath the write entry, or drop one of the two")
				break
			}
			if Covers(w.Canonical(), r.Canonical()) {
				r.Unenforced = true
				if k.nestedWrite == nil {
					k.nestedWrite = map[string]writePath{}
				}
				k.nestedWrite[r.Path] = writePath{declared: w.AliasOf, resolved: w.Canonical()}
				break
			}
		}
	}
	k.rt.AbsentDenyRead = deleteAbsentUnder(k.rt.AbsentDenyRead, aliases)
	for i := range k.rt.DenyWrite {
		if r := &k.rt.DenyWrite[i]; !r.Unenforced && k.underWrite(r.Canonical()) {
			r.Unenforced = true
		}
	}
}

// deleteAbsentUnder drops the absent rows a write entry of writes covers by name or by landing.
func deleteAbsentUnder(rows []AbsentRow, writes []FSRule) []AbsentRow {
	out := rows[:0]
	for _, a := range rows {
		covered := false
		for _, w := range writes {
			if Covers(w.Canonical(), a.At) || Covers(w.Canonical(), a.Resolved) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, a)
		}
	}
	return out
}

// denyReads adds each deny_read entry's other names as deny_read entries with its rule name: a bind of the entry or of
// a directory above it, and a bind of a part of its tree elsewhere.
func (p *aliasPass) denyReads() {
	k := p.k
	have := map[string]bool{}
	for i := range k.rt.FS {
		if k.rt.FS[i].Kind == FSDenyRead {
			have[k.rt.FS[i].Canonical()] = true
		}
	}
	for i, n := 0, len(k.rt.FS); i < n; i++ {
		r := k.rt.FS[i]
		if r.Kind != FSDenyRead || r.AliasOf != "" {
			continue
		}
		for _, a := range p.names(r.Canonical(), true) {
			if have[a.alias] {
				continue
			}
			have[a.alias] = true
			ar := FSRule{Path: a.alias, Resolved: a.alias, Kind: FSDenyRead, Raw: r.Raw, Pos: r.Pos, BuiltIn: r.BuiltIn,
				BuiltinRule: r.BuiltinRule, AskRead: r.AskRead, AliasOf: r.Path, Regular: r.Regular}
			k.aliasUnenforced(&ar)
			k.rt.FS = append(k.rt.FS, ar)
		}
	}
}

// absent leaves the name each built-in row absent at compile would appear under ungranted under every other name of
// the directory it would appear in, unless a write entry (or another name of one) covers it there.
func (p *aliasPass) absent() {
	k := p.k
	absent := map[string]bool{}
	for _, a := range k.rt.AbsentDenyRead {
		absent[a.At] = true
	}
	for i, n := 0, len(k.rt.AbsentDenyRead); i < n; i++ {
		a := k.rt.AbsentDenyRead[i]
		dir := filepath.Dir(a.At)
		for _, d := range p.names(dir, false) {
			if d.original != dir {
				continue
			}
			at := joinBeneath(d.alias, d.original, a.At)
			if absent[at] || k.underWrite(at) {
				continue
			}
			absent[at] = true
			res := a.Resolved
			if isAncestorOrSelf(d.original, res) {
				res = joinBeneath(d.alias, d.original, res)
			}
			k.rt.AbsentDenyRead = append(k.rt.AbsentDenyRead, AbsentRow{Path: a.Path, Resolved: res, At: at})
		}
	}
}

// denyWrites adds every deny_write target's other names, built in or declared, wherever they lie: the floor matches
// by spelling, so each name is a target of its own, with the original's rule. One beneath a write entry (or another
// name of one) is unenforced at tier landlock, as the original is; one elsewhere is a name Landlock grants no write
// at.
func (p *aliasPass) denyWrites() {
	k := p.k
	dw := map[string]bool{}
	for _, r := range k.rt.DenyWrite {
		dw[r.Canonical()] = true
	}
	for i, n := 0, len(k.rt.DenyWrite); i < n; i++ {
		r := k.rt.DenyWrite[i]
		if r.AliasOf != "" {
			continue
		}
		for _, a := range p.names(r.Canonical(), true) {
			if dw[a.alias] {
				continue
			}
			dw[a.alias] = true
			k.rt.DenyWrite = append(k.rt.DenyWrite, FSRule{Path: a.alias, Resolved: a.alias, Kind: FSDenyWrite, Raw: r.Raw,
				Pos: r.Pos, BuiltIn: r.BuiltIn, BuiltinRule: r.BuiltinRule, Unenforced: k.underWrite(a.alias), AliasOf: r.Path})
		}
	}
}

// refuseDoubt refuses a contract some of whose deny entries' other names the table cannot all list (Y5): fail closed.
func (p *aliasPass) refuseDoubt() {
	if p.unsure == 0 {
		return
	}
	p.k.ds.errorf(p.k.cpos, CodeMountWarning, "the mount table cannot list every other name of %s denied entr%s: %s; a file "+
		"these rules deny could be read or written under a name no rule covers, so tego refuses to compile them",
		strconv.Itoa(p.unsure), plural(p.unsure, "y", "ies"), p.doubt).
		fix("unmount the mount this message names (its root was deleted or cannot be read, so the files under it show under names the mount table does not list), or run where it is not mounted, then run again")
}

// otherNamesOf is every other name the mount table gives p's file or tree, each confirmed now by device and inode
// (sameFile): a bind of p or of a directory above it, of its whole filesystem elsewhere included, and, with beneath, a
// bind of a part of p's tree elsewhere (the name shows that part, aliasName.original). A p that does not exist yet is
// named under each other name of its nearest existing ancestor, where the file would appear. uncertain says why the
// list may be short ("" when it is not): p's mount cannot be placed, or an unlinked directory root (or one of unknown
// type) on its device may show part of the tree under a name no row gives.
func (k *compiler) otherNamesOf(mt *mountTable, p string, beneath bool) (out []aliasName, uncertain string) {
	at, rest := p, ""
	for !k.exists(at) {
		parent := filepath.Dir(at)
		if parent == at {
			return nil, ""
		}
		rest = filepath.Join(filepath.Base(at), rest)
		at = parent
	}
	if _, _, err := k.fileIdentity(at); err != nil {
		// A name the person who compiles cannot look at (a folder above it they may not search): no other name can be
		// confirmed as the same file (sameFile needs both), and permissions are the inode's, so the agent, started as
		// that person, reaches it under no other name the table lists either. Nothing is listed, and nothing doubted.
		return nil, ""
	}
	ns, why := mt.otherNames(at)
	for _, a := range ns {
		switch {
		case a.original == at:
			if k.sameFile(a.alias, at) {
				out = append(out, aliasName{alias: filepath.Join(a.alias, rest), original: p})
			}
		case beneath && rest == "" && k.sameFile(a.alias, a.original):
			out = append(out, a)
		}
	}
	return out, why
}

// exists reports whether a name is there now (links followed: compile's paths are resolved).
func (k *compiler) exists(p string) bool {
	_, _, err := k.fileIdentity(p)
	return err == nil || !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, unix.ENOTDIR)
}

// fileIdentity is the device and inode p reaches now, links followed (compileOptions.fileID in a test).
func (k *compiler) fileIdentity(p string) (dev, ino uint64, err error) {
	if k.o.fileID != nil {
		return k.o.fileID(p)
	}
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		return 0, 0, &os.PathError{Op: "stat", Path: p, Err: err}
	}
	return uint64(st.Dev), st.Ino, nil //nolint:unconvert // st.Dev is a uint32 on some architectures
}

// sameFile reports whether a and b reach one file now: both can be looked at, links followed, and their device AND
// inode numbers are equal. A name that cannot be looked at is not the same file: the person who compiles cannot
// reach it, and neither can the agent the run starts as the same person.
func (k *compiler) sameFile(a, b string) bool {
	da, ia, err := k.fileIdentity(a)
	if err != nil {
		return false
	}
	db, ib, err := k.fileIdentity(b)
	if err != nil {
		return false
	}
	return da == db && ia == ib
}

// aliasUnenforced marks a deny_read entry that lies at or beneath a write entry, the write entry's other names
// included, as unenforced() marks a declared one by name: tier landlock cannot deny beneath a grant, and held reads hold
// it. A write entry, or another name of one, at exactly the entry is a contradiction.
func (k *compiler) aliasUnenforced(r *FSRule) {
	for _, w := range k.rt.FS {
		if w.Kind != FSWrite {
			continue
		}
		if w.Canonical() == r.Canonical() {
			k.ds.errorf(w.Pos, CodeContradiction, "write entry %s is another name of deny entry %s (the mount table "+
				"shows the same file there): one grants what the other refuses", w.Path, rawOr(r.AliasOf, r.Path)).
				fix("remove the write entry, or name a place beneath it that is not denied")
			return
		}
		if Covers(w.Canonical(), r.Canonical()) {
			r.Unenforced = true
			if k.nestedWrite == nil {
				k.nestedWrite = map[string]writePath{}
			}
			k.nestedWrite[r.Path] = writePath{declared: rawOr(w.AliasOf, w.Path), resolved: w.Canonical()}
			return
		}
	}
}

// underWrite reports whether a write entry, or another name of one, covers p.
func (k *compiler) underWrite(p string) bool {
	for _, w := range k.rt.FS {
		if w.Kind == FSWrite && Covers(w.Canonical(), p) {
			return true
		}
	}
	return false
}

// otherNamesEnforced refuses a contract where some other name of a denied file is one no layer refuses in the
// contract's mode at a tier its runs can land at (Y1): tier landlock cannot deny beneath a grant, so another name a
// write entry's grant reaches is refused there only by held reads (fs.reads: auto or held), and one an exec.allow
// directory's grant reaches by nothing. Compile does not promise what it cannot keep: it names the file, the other
// name and the setting that makes it enforceable. The entry's own name keeps its warning (the contract names it).
func (k *compiler) otherNamesEnforced() {
	if !k.mayLand(backend.TierLandlock) {
		return // a root tier's kernel refuses a read by the inode, whatever its name
	}
	held := k.rt.ReadsHeldAt(backend.TierLandlock)
	reported := map[string]bool{}
	for _, r := range k.rt.FS {
		if r.Kind != FSDenyRead || r.AliasOf == "" || !r.Unenforced || r.AskRead || reported[r.AliasOf] {
			continue
		}
		w, nestedInWrite := k.nestedWrite[r.Path]
		if nestedInWrite && held {
			continue
		}
		reported[r.AliasOf] = true
		if nestedInWrite {
			k.ds.errorf(r.Pos, CodeUnenforced, "%s is readable through %s, another name the mount table gives the same file "+
				"inside write entry %s: under fs.reads: %s nothing refuses a read there at tier landlock", r.AliasOf, r.Path,
				w.declared, k.rt.Reads.Mode).
				fix("remove fs.reads: direct (the run then holds its reads and refuses it), or pin a root tier (tier: cgroup or bpflsm)")
			continue
		}
		k.ds.errorf(r.Pos, CodeUnenforced, "%s is readable through %s, another name the mount table gives the same file "+
			"beneath an exec.allow directory, whose grant carries read access to its whole subtree at tier landlock",
			r.AliasOf, r.Path).
			fix("name the binaries in exec.allow instead of the directory, or pin a root tier (tier: cgroup or bpflsm)")
	}
	// An exec.allow directory's grant lands on its inode too, so it reaches a deny_read entry beneath another name of
	// the directory, where the entry's own name shows no grant (the Landlock builder nests by the names it holds).
	mt, err := k.mountTable()
	if mt == nil || !mt.probed || err != nil {
		return
	}
	for _, e := range k.rt.Exec {
		if !e.IsDir {
			continue
		}
		dir := k.resolve(e.Path)
		ns, _ := k.otherNamesOf(mt, dir, false)
		for _, a := range ns {
			if a.original != dir {
				continue
			}
			for _, r := range k.rt.FS {
				name := rawOr(r.AliasOf, r.Path)
				if r.Kind != FSDenyRead || r.AskRead || reported[name] || !Covers(a.alias, r.Canonical()) || Covers(dir, r.Canonical()) {
					continue
				}
				reported[name] = true
				k.ds.errorf(e.Pos, CodeUnenforced, "%s is readable at tier landlock: exec.allow %s is the same directory as %s, "+
					"another name the mount table gives it, and the grant carries read access to its whole subtree", r.Path, e.Path, a.alias).
					fix("name the binaries in exec.allow instead of the directory, or pin a root tier (tier: cgroup or bpflsm)")
			}
			// The same for a built-in row that did not exist at compile and is placed beneath the other name: the
			// grant's READ_FILE sits on the directory's inode, so a file made there is readable, and the model must not
			// say "refused" (the row beneath the directory's own name is dropped by execDirs).
			for _, ab := range k.rt.AbsentDenyRead {
				if !Covers(a.alias, ab.At) || Covers(dir, ab.At) || reported[ab.At] {
					continue
				}
				reported[ab.At] = true
				k.ds.errorf(e.Pos, CodeUnenforced, "%s, a protected file the built-in rules refuse once it exists, is readable at tier "+
					"landlock under %s: exec.allow %s is the same directory as %s, another name the mount table gives it, and the "+
					"grant carries read access to its whole subtree", ab.At, a.alias, e.Path, a.alias).
					fix("name the binaries in exec.allow instead of the directory, or pin a root tier (tier: cgroup or bpflsm)")
			}
		}
	}
}

// joinBeneath is p, a path at or beneath original, under alias instead.
func joinBeneath(alias, original, p string) string {
	return filepath.Join(alias, strings.TrimPrefix(p, original))
}

// plural is one when n is 1, else many.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// OtherNames is every other name this process's mount table gives the file or tree at p (an absolute path), by the
// computation compile applies to every fs entry (otherNamesOf: a bind of p or of a folder above it, a bind of a part of
// its tree elsewhere, each confirmed now by device and inode). A live block takes them when it is added (ADR 0011,
// amended 2026-11-19, round 5), so a block refuses the file under every name the table shows then; mounts made later
// are not seen (GAPS C68). err when the table cannot be read whole or cannot list every name (names are then those
// it could list).
func OtherNames(p string) (names []string, err error) {
	mt, err := loadMountTable(liveMountInfo)
	if err != nil {
		return nil, err
	}
	ns, why := (&compiler{}).otherNamesOf(mt, filepath.Clean(p), true)
	for _, a := range ns {
		names = append(names, a.alias)
	}
	if why != "" {
		return names, errors.New(why)
	}
	return names, nil
}
