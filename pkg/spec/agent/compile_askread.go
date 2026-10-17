// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// ownState sets RuleTable.OwnState: tego's own state by resolved path, R6a's list (tegoOwn) taken whole, whether
// or not each could be denied: the chain anchor and its directory, ~/.tego under the compile's home, the ledger root,
// the host state (/run/tego), the machine config's price table and profiles directory. And RuleTable.OwnReadable:
// the user registry's agents/ and skills/ (agent-contract.md R26) and the machine config's layer files (ADR 0059),
// which a run may read, so an fs.ask_read entry and a held read beneath them are no different from anywhere else, but
// which no held write's alternate reaches. A path that resolves to "/" is left out (it would hold everything; R10
// already refuses a write entry over
// it). It runs before fs, for every table, since the supervisor's alternate guard reads both for fs.ask writes as
// well (SEMANTICS §6).
func (k *compiler) ownState() {
	var paths []string
	if k.o.chainAnchor != "" {
		// The anchor itself too: a link (or one leading nowhere yet) leads out of its directory, to the file every run's
		// head is checked against. Its directory as the ledger's open walks it, never cleaned.
		dir, _, ok := splitAsWalked(k.o.chainAnchor)
		if !ok {
			dir = k.o.chainAnchor
		}
		paths = append(paths, dir, k.o.chainAnchor)
	}
	if k.o.home != "" {
		paths = append(paths, filepath.Join(k.o.home, ".tego"))
	}
	if k.m.LedgerRoot.Value != "" {
		paths = append(paths, k.abs(k.m.LedgerRoot.Value))
	}
	paths = append(paths, hostStateDir)
	paths = append(paths, k.o.runtimeParents...)
	if p := k.m.Prices.Value; p != "" {
		paths = append(paths, k.asWalked(p))
	}
	if p := k.m.Profiles.Value; p != "" {
		paths = append(paths, k.asWalked(p))
	}
	k.rt.OwnState = k.spellings(k.rt.OwnState, paths)
	if r := k.m.Registry.Value; r != "" { // what other runs resolve an agent's name to (agent-contract.md R26)
		k.rt.OwnReadable = k.spellings(k.rt.OwnReadable, []string{k.registryDir(r, "agents"), k.registryDir(r, "skills")})
	}
	// The machine config's layer files, R10 targets wherever they are (ADR 0059): one outside ~/.tego is not
	// read-denied, and no held write's alternate reaches it either.
	k.rt.OwnReadable = k.spellings(k.rt.OwnReadable, k.m.Layers)
}

// spellings appends to list each of paths as written and resolved, once each, leaving out "/"; a relative path is
// taken against the working directory, as R10 takes its targets (r10Target).
// Each path is one its loader opens as given (or one cleaned already, as the ledger root is by the ledger's own
// walk), so both spellings are taken from the kernel's walk of it: as written is WalkedPath's spelling, which is
// filepath.Clean's unless a ".." follows a name, and resolved is where walkTarget's walk of the path itself lands, as
// R10 places its targets, a final link leading nowhere yet followed to where the loader's open will land. Both were
// taken from filepath.Clean's spelling, which with a ".." after a link names another file than the
// one the loader reads: the file read was in neither list.
func (k *compiler) spellings(list, paths []string) []string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		p = k.asWalked(p) // a relative one against the working directory, as r10Target takes it
		written, ok := WalkedPath(p)
		if !ok {
			written = "" // no spelling of its own: resolve's, if any, names it
		}
		placed := walkTarget(p).place // p as given when no walk places it
		for _, sp := range []string{written, placed} {
			if sp != "" && sp != "/" && filepath.IsAbs(sp) && !slices.Contains(list, sp) {
				list = append(list, sp)
			}
		}
	}
	return list
}

// fsAskRead compiles fs.ask_read (POC 2026-10-06, SEMANTICS §6): each entry becomes a deny_read entry marked
// AskRead, so the Landlock ruleset withholds its reads, Evaluate refuses them and the root tiers' models would
// refuse them, and only tier 1's supervisor, which reads the marker, holds a read-open beneath it for a person.
//
// It refuses, each with its own finding:
//   - a tier other than landlock: no other tier holds a read (the task's open is decided in the kernel), and
//     compiling the entries as plain denies would silently turn every ask into a refusal;
//   - a glob (schema), a path that does not exist (path-missing) and "/" (no parent to enumerate), as deny_read;
//   - a path at or beneath tego's own state (OwnState): those stay refused whatever is listed (R6a);
//   - a path that is a declared deny_read entry or lies beneath one: an ask never lifts a deny;
//   - a path that is a write entry or lies beneath one: Landlock cannot withhold a read beneath a write grant,
//     so a read could reach it without a hold (an ask_read entry never compiles unenforced; askReadEnforced
//     refuses the exec grants that would do the same);
//   - an fs.ask scope at or beneath it: a write-open there is refused read-denied, so the scope would never ask.
//
// An entry at a built-in deny_read entry's path replaces that entry, and one beneath a built-in entry is nearer
// than it, when the top-level contract declares it: the person who wrote the contract chose to be asked for
// that one secret, and compile says so. From a profile either is a contradiction, as ADR 0043 D3 keeps a
// profile's write entry from lifting the built-in .env list: a profile does not lift what the built-in list
// protects for every contract that extends it.
func (k *compiler) fsAskRead() {
	if k.c.FS == nil || len(k.c.FS.AskRead) == 0 {
		return
	}
	if k.rt.Tier != backend.TierLandlock {
		// An observe table is refused already: ask requires an enforcing tier (askConfig).
		if k.rt.Tier != backend.TierObserve {
			at := "pins it"
			if pin := backend.Tier(k.c.Tier); pin == "" || pin == backend.TierAuto {
				at = "resolves to it on this machine"
			}
			k.ds.errorf(k.pos("fs.ask_read.0"), CodeUnenforced, "fs.ask_read holds a read for a person at tier landlock only, and this contract %s tier %s, where no mechanism holds a read: every entry would be refused without asking", at, k.rt.Tier).
				fix("pin tier: landlock, or move the entries to fs.deny_read")
		}
		return
	}
	mt, _ := loadMountTable(k.o.mountInfo) // fs already reports unavailable metadata
	b := &fsBuilder{k: k, mt: mt}
	drop := map[int]bool{}
	seen := map[string]bool{}
	var added []FSRule
	for i, raw := range k.c.FS.AskRead {
		pos := k.pos("fs.ask_read." + strconv.Itoa(i))
		if hasGlobMeta(raw) {
			k.ds.errorf(pos, CodeSchema, "fs.ask_read requires literal files or directories")
			continue
		}
		p := k.abs(raw)
		res := k.resolve(p)
		if filepath.Clean(res) == "/" {
			k.ds.errorf(pos, CodeSchema, "fs.ask_read %q%s holds the whole filesystem, which no tier can enforce and no run could start under", raw, resolvedNote(p, res)).
				fix("name the files or directories to hold beneath /")
			continue
		}
		if _, err := os.Stat(p); err != nil {
			k.ds.errorf(pos, CodePathMissing, "fs.ask_read %q: %s does not exist", raw, p).
				fix("create it or remove the entry; a held read names a file that is there")
			continue
		}
		if seen[res] {
			continue // an exact duplicate was warned at Load; another spelling of one file is the same entry
		}
		seen[res] = true
		if own := k.ownStateOf(res); own != "" {
			d := k.ds.errorf(pos, CodeContradiction, "fs.ask_read %q%s lies inside tego's own state %s, which no run may read and no person can open for it", raw, resolvedNote(p, res), own)
			d.fix("remove the entry: tego's own files stay refused whatever is listed")
			d.overlap = true
			continue
		}
		relaxes, ok := k.askReadAgainstFS(b, pos, raw, p, res, drop)
		if !ok {
			continue
		}
		bad := false
		for _, s := range k.rt.FSAsk {
			if isAncestorOrSelf(res, s.Governed()) {
				k.ds.errorf(s.Pos, CodeContradiction, "fs.ask %q lies inside fs.ask_read %q, where a write-open is refused read-denied: the scope would never ask", s.Raw, raw).
					fix("move the fs.ask scope out of %s, or drop one of the two", raw)
				bad = true
			}
		}
		if bad {
			continue
		}
		r := FSRule{Path: p, Kind: FSDenyRead, AskRead: true, Raw: raw, Pos: pos, Resolved: res}
		b.metaDeclared(&r, pos)
		added = append(added, r)
		for _, rel := range relaxes {
			k.rt.AskReadRelaxes = append(k.rt.AskReadRelaxes, AskReadRelax{Rule: r.RuleName(), BuiltIn: rel.BuiltIn, How: rel.How})
		}
	}
	if len(drop) > 0 {
		kept := k.rt.FS[:0:0]
		for i, r := range k.rt.FS {
			if !drop[i] {
				kept = append(kept, r)
			}
		}
		k.rt.FS = kept
	}
	k.rt.FS = append(k.rt.FS, added...)
}

// ownStateOf is the OwnState path at or above p, "" when none.
func (k *compiler) ownStateOf(p string) string {
	for _, own := range k.rt.OwnState {
		if isAncestorOrSelf(own, p) {
			return own
		}
	}
	return ""
}

// askReadAgainstFS checks one fs.ask_read entry against the fs rules already compiled: the write entries, the
// declared deny_read entries and the built-in ones (fsAskRead). It marks in drop a built-in entry at the entry's
// own path, which the entry replaces, and returns the built-in entries the entry relaxes (Rule left for the caller)
// and whether the entry may compile.
//
// ADR 0057 D4: an entry of the top-level contract at or beneath a built-in deny_read entry is allowed, with a
// warning naming the built-in it relaxes and a run_start field (ask_read_relaxes) that names it in the record. It
// is a relaxation, but not to an allow: every read is still held for a person, who sees the path, and the author of
// the contract file asked for exactly that, as a top-level write entry may lift a built-in .env entry (ADR 0043
// D3). Refusing it would leave no way to be asked for one's own ~/.aws/credentials short of removing the built-in
// protection by hand; allowing it silently would let the record of a run say nothing of a weakened default.
func (k *compiler) askReadAgainstFS(b *fsBuilder, pos Pos, raw, p, res string, drop map[int]bool) ([]AskReadRelax, bool) {
	ok := true
	var relaxes []AskReadRelax
	top := pos.File == k.top
	for i := range k.rt.FS {
		r := &k.rt.FS[i]
		gov := r.Canonical()
		if gov == "" || !isAncestorOrSelf(gov, res) {
			continue
		}
		switch {
		case r.Kind == FSWrite:
			k.ds.errorf(pos, CodeUnenforced, "fs.ask_read %q%s lies inside write entry %s%s: Landlock cannot withhold a read beneath a write grant, so the agent could read it without asking",
				raw, resolvedNote(p, res), r.Path, resolvedNote(r.Path, gov)).
				fix("move the file out of the write entry, or narrow the write entry")
			ok = false
		case r.Kind == FSDenyRead && r.AskRead:
			// Another fs.ask_read entry encloses this one: the nearer decides, and both hold.
		case r.Kind == FSDenyRead && !r.BuiltIn:
			d := k.ds.errorf(pos, CodeContradiction, "fs.ask_read %q%s is also, or lies inside, deny_read %s: a deny is never lifted by an ask",
				raw, resolvedNote(p, res), rawOr(r.Raw, r.Path))
			d.fix("remove one of the two, or narrow the deny_read entry so it no longer covers %s", raw)
			d.overlap = true
			ok = false
		case r.Kind == FSDenyRead && !top:
			d := k.ds.errorf(pos, CodeContradiction, "fs.ask_read %q%s comes from a profile and would lift the built-in deny_read entry %s for every contract that extends it",
				raw, resolvedNote(p, res), r.Path)
			d.fix("declare the entry in the top-level contract, where its author chooses to be asked for that secret")
			d.overlap = true
			ok = false
		case r.Kind == FSDenyRead && gov == res:
			drop[i] = true
			relaxes = append(relaxes, AskReadRelax{BuiltIn: r.Path, How: AskReadReplaces})
			k.ds.warnf(pos, CodeUnenforced, "fs.ask_read %q%s relaxes the built-in deny_read entry %s, which it replaces: a read of it is held for a person instead of refused, and every run's record says so (run_start ask_read_relaxes)",
				raw, resolvedNote(p, res), r.Path).
				fix("drop the fs.ask_read entry to keep %s refused", r.Path)
		case r.Kind == FSDenyRead:
			relaxes = append(relaxes, AskReadRelax{BuiltIn: r.Path, How: AskReadInside})
			k.ds.warnf(pos, CodeUnenforced, "fs.ask_read %q%s relaxes the built-in deny_read entry %s, inside which it lies: a read beneath %s is held for a person, the rest of %s stays refused, and every run's record says so (run_start ask_read_relaxes)",
				raw, resolvedNote(p, res), r.Path, raw, r.Path).
				fix("drop the fs.ask_read entry to keep all of %s refused", r.Path)
		}
	}
	return relaxes, ok
}

// askReadEnforced refuses an fs.ask_read entry an exec grant opens: an exec.allow directory at or above it, or an
// exec grant at or beneath it. An exec grant carries read access at tier 1 (denyReadUnderExecDirs,
// execInsideDenyRead), so a read there would reach the file without a hold. A deny_read in the same place is only
// warned unenforced; an ask_read entry never compiles unenforced, so it is refused. It runs after exec().
func (k *compiler) askReadEnforced() {
	for i := range k.rt.FS {
		r := &k.rt.FS[i]
		if !r.AskRead || r.Kind != FSDenyRead {
			continue
		}
		target := r.Governed()
		for _, x := range k.rt.Exec {
			at := x.Resolved
			if at == "" {
				at = x.Path
			}
			if at == "" {
				continue
			}
			switch {
			case x.IsDir && isAncestorOrSelf(at, target):
				k.ds.errorf(r.Pos, CodeUnenforced, "fs.ask_read %q lies inside exec.allow directory %s%s, which carries read access to its whole subtree at tier landlock: the agent could read it without asking",
					r.Raw, rawOr(x.Raw, x.Path), resolvedNote(x.Path, x.Resolved)).
					fix("name the binaries instead of the directory, or move the file outside %s", rawOr(x.Raw, x.Path))
			case isAncestorOrSelf(target, at):
				k.ds.errorf(r.Pos, CodeUnenforced, "fs.ask_read %q holds exec grant %s%s, which carries read access at tier landlock: the agent could read it without asking",
					r.Raw, rawOr(x.Raw, x.Path), resolvedNote(x.Path, x.Resolved)).
					fix("install the binary outside %s, or drop the exec grant", r.Raw)
			}
		}
	}
}

// IsBuiltInEnvName reports whether a file's base name is one the built-in .env list protects (`.env`, and `.env.*`
// but its example files): the supervisor refuses such a file as a person's alternate whatever its directory
// (ADR 0057 D2), so a mistyped `.env.example` never hands the agent the secret.
func IsBuiltInEnvName(name string) bool { return isEnvFile(name) }
