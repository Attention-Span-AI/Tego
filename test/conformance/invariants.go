// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"path/filepath"
	"slices"
	"strings"
)

// Outcome is the kernel's own result of one action, the judge.
type Outcome struct {
	OK    bool
	Errno int
	// Value is what the actor reported beside the answer: a race's counts, the pid a process op's hook names.
	Value string
}

// Refusal reports whether the kernel refused: EACCES, EPERM, EXDEV (Landlock's REFER refusal of a link or a rename
// across trees) or ENOSYS (the filter's answer where it refuses a syscall as absent: the memfd arm on a kernel without
// MFD_NOEXEC_SEAL, enforce-landlock R11a, and R10). Any other failure (ENOENT, ECONNREFUSED) is no refusal by Tego,
// and a cell that meets one has a broken fixture.
func (o Outcome) Refusal() bool {
	return !o.OK && (o.Errno == 13 || o.Errno == 1 || o.Errno == 18 || o.Errno == 38)
}

// Verdict maps the outcome onto a cell's vocabulary; ok is false for a failure that is neither.
func (o Outcome) Verdict() (v string, ok bool) {
	switch {
	case o.OK:
		return Allow, true
	case o.Refusal():
		return Refused, true
	}
	return "", false
}

func under(anc, p string) bool {
	anc, p = filepath.Clean(anc), filepath.Clean(p)
	return p == anc || strings.HasPrefix(p, anc+"/")
}

// reopened reports whether the declared write entries reopen p beneath the deny_write target d: d is a contract's own
// fs.deny_write entry (Model.DenyWriteDeclared) and a write entry lies strictly beneath it and at or above p, nearest
// wins (ADR 0071). A built-in target is never reopened. Written from the declared strings (ADR 0017 (c)).
func reopened(m Model, d, p string) bool {
	if !slices.ContainsFunc(m.DenyWriteDeclared, func(e string) bool { return filepath.Clean(e) == filepath.Clean(d) }) {
		return false
	}
	return slices.ContainsFunc(m.Write, func(w string) bool {
		return filepath.Clean(w) != filepath.Clean(d) && under(d, w) && under(w, p)
	})
}

func underAny(ancs []string, p string) bool {
	for _, a := range ancs {
		if under(a, p) {
			return true
		}
	}
	return false
}

// canon is the path the kernel resolves the cell's Path to.
func (c *Cell) canon() string {
	if c.Canon != "" {
		return c.Canon
	}
	return c.Path
}

// The enforcement predicates: what the oracle takes a tier to enforce, from the contract alone. The invariants bind
// only where these say so, and capability.go holds them to what the product reports (compile --json's per-entry
// markers, the run's own capability line), so neither can drift from the other unnoticed. A tier here is the one
// whose invariants an axis answers: tier cgroup in a plane mode answers tier bpflsm's.

// denyReadEnforced says whether a tier refuses the reads of a deny_read entry at path, from the contract alone
// (SEMANTICS §2): tier cgroup's listener does, tier 3 does by inode, and tier landlock does where its ruleset holds the
// entry (denyReadRulesetEnforced) or, where a write entry covers it, where the run holds its reads: fs.reads: auto,
// the default, holds them exactly when such an entry exists, and held always (ADR 0069), so only fs.reads: direct
// leaves it readable.
func denyReadEnforced(m Model, t Tier, entry string) bool {
	return denyReadRulesetEnforced(m, t, entry) || m.Reads != ReadsDirect
}

// heldReadsNeeded reports whether a declared deny_read's reads are refused at tier landlock by held reads alone (a
// write entry covers it) or the contract asks for held reads: compile must hold the run's reads there.
func (m Model) heldReadsNeeded() bool {
	if m.Reads == ReadsDirect {
		return false
	}
	if m.Reads == ReadsHeld {
		return true
	}
	return slices.ContainsFunc(m.DenyRead, func(e string) bool { return !denyReadRulesetEnforced(m, TierLandlock, e) })
}

// denyReadRulesetEnforced says whether a tier's kernel layer enforces a deny_read entry at path, from the contract
// alone (SEMANTICS §2): tier landlock's ruleset cannot where a write entry lies at or above the entry's parent
// ("unenforced: parent writable", compile --json's marker), tier cgroup's listener does, and tier 3 does by inode. It
// decides the modifications beneath the entry too: held reads refuse reads only (ADR 0069 D2), so a nested
// deny_read's tree stays writable at tier landlock.
func denyReadRulesetEnforced(m Model, t Tier, entry string) bool {
	if t != TierLandlock {
		return true
	}
	return !underAny(m.Write, entry)
}

// denyWriteEnforced says whether a tier enforces the contract's deny_write targets (the built-in set beneath its
// write entries, agent-contract R20): only where a kernel decision plane decides (the plane axes, tier bpflsm).
// Tier landlock and tier cgroup's listener refuse them through the supervisor, best effort (supervisor R15c, ADR
// 0041 D1 (a)), and under fs.assurance: kernel do not start such a run at all.
func denyWriteEnforced(m Model, t Tier) bool { return t == TierBPFLSM && len(m.DenyWrite) > 0 }

// Invariant checks one action's outcome against the contract's declared entries alone, never the Landlock plan
// or the decision core (ADR 0017 (c)). It returns "" when the outcome violates none; otherwise the invariant it
// breaks. A violation where the kernel allowed is a fail-open.
func Invariant(m Model, c *Cell, t Tier, o Outcome) string {
	if !o.OK {
		return ""
	}
	switch c.Op {
	// Not a chmod, a chown, an xattr or an ACL (space 4's attribute ops alike): ADR 0017 (c) holds "a write, create,
	// delete, rename or mkdir" outside the write entries, and no tier claims fs.deny_chmod (agent-contract E35, CAPABILITIES: Landlock has no chmod right, fanotify no event, and the
	// plane's path_chmod refuses beneath the deny_write targets only, which the deny_write invariant below holds). A
	// tier that comes to claim it adds its case here, beside its capability line.
	case OpWriteOpen, OpCreate, OpCreat, OpOpenTrunc, OpTruncate, OpUnlink, OpRmdir, OpMkdir, OpMknod, OpRaceSymlinkWrite:
		if !underAny(m.Write, c.canon()) {
			return "a mutation succeeded outside every write entry"
		}
	case OpSymlink:
		if !underAny(m.Write, c.Path) {
			return "a symlink was created outside every write entry"
		}
	case OpLink:
		if !underAny(m.Write, c.Dest) {
			return "a hard link was created outside every write entry"
		}
	case OpRename, OpExchange:
		if !underAny(m.Write, c.canon()) || !underAny(m.Write, c.Dest) {
			return "a rename succeeded outside the write entries"
		}
	}
	// Inside the write entries, the nearest entry decides a mutation too: a deny_read nested in a write entry, where
	// the tier enforces it, refuses every modification beneath it (ADR 0021 (5)), and a rename or hard link that takes
	// a name out of it (supervisor R15d). chmod is not held to it: no tier below the plane decides a chmod, and the
	// plane's chmod hook protects the deny_write targets (agent-contract E35, enforce-plane R12).
	for _, p := range mutated(c) {
		if e, deny, ok := governing(m, p); ok && deny && denyReadRulesetEnforced(m, t, e) {
			return "a mutation succeeded under a deny_read nearer than every write entry, which the tier enforces"
		}
	}
	if v := nameInvariant(m, c, t); v != "" {
		return v
	}
	switch c.Op {
	case OpRead, OpRaceSymlinkRead: // the race's success is a byte of its target, Canon, read through the swapped link
		if e, deny, ok := governing(m, c.canon()); ok && deny && denyReadEnforced(m, t, e) {
			if c.Exception != "" && c.ExceptionAt == t && (execGrantInside(m, e, c.canon()) || !under(e, c.Path)) {
				// SEMANTICS §2: an exec grant inside the deny_read carries read at tier landlock; enforce-landlock E32 (ii):
				// the target's content reached through another name (a bind mount beneath a granted sibling) is
				// readable through that name. Never the target's own path.
				return ""
			}
			return "a read succeeded under a deny_read the tier enforces"
		}
	case OpExec, OpExecLoader, OpExecveatFD, OpExecProcFD, OpRaceArgvExec:
		// A race-argv-exec that succeeded had no attempt refused, the denied vector's among them (cells.go).
		if len(m.ExecAllow) > 0 && !underAny(m.ExecAllow, c.canon()) {
			return "an exec of a file outside exec.allow succeeded"
		}
		if v := commandDenied(m, c); v != "" {
			return v // invariants_exec.go: every tier refuses an exec a deny entry names (ADR 0048 P1)
		}
	case OpMemfdExec, OpMemfdMapExec:
		// SEMANTICS §4: a run that restricts exec runs no anonymous image, unless the contract opted out with
		// exec: {anonymous: true}; tiers 1 and 2 refuse the memfd's creation, the plane its exec and its map.
		if len(m.ExecAllow) > 0 && !m.ExecAnonymous {
			return "an anonymous image ran or mapped executable in a run that restricts exec"
		}
	case OpExecmod, OpExecmem:
		// ADR 0027 (c): where the plane decides, a private file mapping that is writable and executable, or made
		// executable after a write, is refused for a file no exec.allow entry covers.
		if t == TierBPFLSM && len(m.ExecAllow) > 0 && !underAny(m.ExecAllow, c.canon()) {
			return "a written or writable private file mapping became executable where the plane decides mappings"
		}
	case OpMapExec, OpMapExecRIE, OpMprotectExec, OpMprotectRIE:
		// ADR 0027: where a decision plane decides (tier bpflsm, and tier cgroup in a plane mode, which the kernel
		// runner holds to bpflsm's invariants), code the agent could have written maps executable only where an
		// exec.allow entry covers it. Tiers 1 and 2's listener decide no mapping (SEMANTICS §4).
		if t == TierBPFLSM && len(m.ExecAllow) > 0 && underAny(m.Write, c.canon()) && !underAny(m.ExecAllow, c.canon()) {
			return "a PROT_EXEC map of code the agent could write succeeded where the plane decides mappings"
		}
	case OpPtraceAttach, OpPtraceTraceme:
		// ARCHITECTURE §11 and enforce-plane §2.20: a run's ptrace stays inside the run. Landlock's ptrace scope, which
		// every tier installs, refuses an attach to a process outside the run's domain; a TRACEME of a tracer outside
		// the run is refused only where the plane decides (Landlock admits an unconfined parent tracing a confined child).
		if c.Target == TargetHost || (c.Target == TargetOrphan && t == TierBPFLSM) {
			return "a ptrace across the run's boundary succeeded"
		}
	case OpKeyctl, OpAddKey, OpRequestKey:
		// SEMANTICS §1: the kernel keyring is refused on every tier unless the contract says keyring: true.
		if !m.Keyring {
			return "a keyring call succeeded in a run whose contract does not say keyring: true"
		}
	case OpBPF:
		// ADR 0033: the filter's root-tier arm refuses bpf(2) at tiers 2 and 3; tier 1 has no arm.
		if t != TierLandlock {
			return "a bpf(2) call succeeded at a tier that refuses it"
		}
	case OpConnectTCP, OpConnectUDP, OpSendUDP:
		if m.NetDeclared {
			for _, a := range append(append([]string{}, m.NetAllow...), m.NetRuntime...) {
				if a == c.Addr {
					return ""
				}
			}
			return "a connect or send to an undeclared destination succeeded"
		}
	case OpConnectUnix:
		// ADR 0070: a unix socket the run did not bind (every connect-unix cell names a host socket the runner bound) is
		// reachable only through a unix: entry naming it, or the contract's host_sockets: true. Only tier landlock is held
		// to it: at the root tiers the same relay and Landlock carry it with no kernel program of the run deciding it,
		// best effort until those tiers carry a kernel program for it (ADR 0070 (5), run_start best_effort host_sockets/root-tier); the cells' root columns
		// still ask the refusal.
		if t == TierLandlock && !m.HostSockets && !slices.Contains(m.NetAllow, "unix:"+c.Addr) {
			return "a connect to a host socket the contract does not name succeeded without host_sockets: true"
		}
	}
	if denyWriteEnforced(m, t) { // the plane; tiers 1 and 2's listener are best effort (SEMANTICS §2)
		for _, d := range m.DenyWrite {
			if (c.Op != OpRead && c.Op != OpRaceSymlinkRead && c.Op != OpExec && !spellingOps[c.Op]) &&
				((under(d, c.canon()) && !reopened(m, d, c.canon())) || under(c.canon(), d)) {
				return "a mutation of a deny_write target succeeded where deny_write is enforced"
			}
			// A rename, an exchange or a hard link changes its destination name too; a symlink's Dest is only its target.
			if (c.Op == OpRename || c.Op == OpExchange || c.Op == OpLink) && ((under(d, c.Dest) && !reopened(m, d, c.Dest)) || under(c.Dest, d)) {
				return "a rename or link onto a deny_write target succeeded where deny_write is enforced"
			}
		}
	}
	return ""
}

// governing is the declared write or deny_read entry nearest to path: the deepest one at or above it, which decides
// the action (SEMANTICS §2's walk, nearest wins), whatever order the contract lists them in. deny says it is a
// deny_read; ok is false where no entry covers the path. A write entry nested in a deny_read so decides beneath
// itself (a regrant; tier 1's union grants it as well), and a deny_read nested in that write entry is nearer still.
// The two kinds at one path are a contradiction compile refuses; were both declared, the deny_read is taken.
// Written from the declared strings, never from the decision core (ADR 0017 (c)).
func governing(m Model, path string) (entry string, deny, ok bool) {
	depth := -1
	for _, kind := range []struct {
		entries []string
		deny    bool
	}{{m.Write, false}, {m.DenyRead, true}} {
		for _, e := range kind.entries {
			e = filepath.Clean(e)
			if !under(e, path) || len(e) < depth || (len(e) == depth && !kind.deny) {
				continue
			}
			entry, deny, ok, depth = e, kind.deny, true, len(e)
		}
	}
	return entry, deny, ok
}

// mutated lists the names an action modifies, or, for a hard link's source, gives a second name to: the ones the
// nearest-wins rule holds a mutation to. A read, an exec, a map, a connect and an attribute change (chmod, chown, an
// xattr or an ACL: see Invariant) have none.
func mutated(c *Cell) []string {
	switch c.Op {
	case OpWriteOpen, OpCreate, OpCreat, OpOpenTrunc, OpTruncate, OpUnlink, OpRmdir, OpMkdir, OpMknod, OpRaceSymlinkWrite:
		return []string{c.canon()}
	case OpSymlink: // Dest is the link's text, not a name the action makes
		return []string{c.Path}
	case OpRename, OpExchange, OpLink: // an exchange's ends each take the other's name
		return []string{c.canon(), c.Dest}
	}
	return nil
}

// execGrantInside says an exec.allow entry lies strictly inside the deny_read entry and covers path (SEMANTICS §2's
// Landlock exception: the exec grant carries READ_FILE).
func execGrantInside(m Model, deny, path string) bool {
	for _, x := range m.ExecAllow {
		if filepath.Clean(x) != filepath.Clean(deny) && under(deny, x) && under(x, path) {
			return true
		}
	}
	return false
}

// spellingOps are the exec space's ops (ADR 0017 space 2): each runs or maps code and mutates no name.
var spellingOps = map[string]bool{
	OpExecLoader: true, OpExecveatFD: true, OpExecProcFD: true, OpMemfdCreate: true, OpMemfdExec: true, OpMemfdMapExec: true,
	OpMapExecRIE: true, OpMprotectExec: true, OpMprotectRIE: true, OpExecmod: true, OpExecmem: true,
}

// dependencyDirs are the directories a name entry's scope does not reach through, compared case-exactly (ADR 0043
// Terms: the built-in scan's skip list), written here from the ADR rather than read from the product's code.
var dependencyDirs = []string{".git", "node_modules", "vendor", "target", ".venv", "venv"}

// fold is ADR 0043 D2's ASCII case folding: bytes A to Z become a to z, every other byte stays.
func fold(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// entryMatches is D2 for one entry: the folded final name equals an exact entry's literal, or starts with a prefix
// entry's literal and is none of its exceptions.
func entryMatches(n NameEntry, name string) bool {
	name = fold(name)
	if n.Exact != "" {
		return name == fold(n.Exact)
	}
	return strings.HasPrefix(name, fold(n.Prefix)) && !slices.ContainsFunc(n.Except, func(e string) bool { return fold(e) == name })
}

// nameMatches reports whether some entry of names matches the final name, wherever it lies.
func nameMatches(names []NameEntry, name string) bool {
	return slices.ContainsFunc(names, func(n NameEntry) bool { return entryMatches(n, name) })
}

// beneathScope is D4 by path: path lies strictly beneath scope (both relative to the project) with no dependency
// directory strictly between them; the scope itself may be one or lie inside one.
func beneathScope(scope, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(scope), filepath.Clean(path))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return false
	}
	between := strings.Split(rel, "/")
	return !slices.ContainsFunc(between[:len(between)-1], func(d string) bool { return slices.Contains(dependencyDirs, d) })
}

// nameCovered says the file at path (relative to the project) is covered by one of the model's name entries (ADR
// 0043 Terms): an entry matches its final name and it lies beneath one of that entry's scopes, and no write entry of
// the contract names that place, its folded name in its parent (D3's exemption, which cancels every entry's arms).
func nameCovered(m Model, path string) bool {
	path = filepath.Clean(path)
	for _, w := range m.Write {
		if w = filepath.Clean(w); filepath.Dir(w) == filepath.Dir(path) && fold(filepath.Base(w)) == fold(filepath.Base(path)) {
			return false
		}
	}
	return slices.ContainsFunc(m.Names, func(n NameEntry) bool {
		return entryMatches(n, filepath.Base(path)) && slices.ContainsFunc(n.Scopes, func(s string) bool { return beneathScope(s, path) })
	})
}

// nameEnforced says whether a tier enforces the contract's name entries (ADR 0043 D7): tier landlock has the
// compile-time expansion only; tier cgroup's listener refuses the opens and its supervisor the other changes, and
// the plane decides them all.
func nameEnforced(t Tier) bool { return t != TierLandlock }

// nameInvariant is ADR 0043 D1 from the contract's name entries: where the tier enforces them, no read of a covered
// file and no change of its content or name (a write-open, its creation, truncation, unlink, a symlink or a link's
// new name, a rename at either end, a link from it) succeeds. A name entry never decides a directory (the loader
// keeps a table's directories off covered names), nor metadata (chmod, chown, xattrs, ACLs), so neither is held
// here; nor D5's directory move, which a cell's names alone cannot tell from a file's (its cells' want holds it).
func nameInvariant(m Model, c *Cell, t Tier) string {
	if len(m.Names) == 0 || !nameEnforced(t) {
		return ""
	}
	var read, changed []string
	switch c.Op {
	case OpRead, OpRaceSymlinkRead:
		read = []string{c.canon()}
	case OpWriteOpen, OpCreate, OpCreat, OpOpenTrunc, OpTruncate, OpUnlink, OpMknod, OpRaceSymlinkWrite:
		changed = []string{c.canon()}
	case OpSymlink:
		changed = []string{c.Path}
	case OpLink:
		changed = []string{c.Path, c.Dest}
	case OpRename, OpExchange:
		changed = []string{c.canon(), c.Dest}
	}
	for _, p := range read {
		if nameCovered(m, p) {
			return "a read of a file a name entry covers succeeded where the tier enforces name entries"
		}
	}
	for _, p := range changed {
		if nameCovered(m, p) {
			return "a change of a file a name entry covers succeeded where the tier enforces name entries"
		}
	}
	return ""
}
