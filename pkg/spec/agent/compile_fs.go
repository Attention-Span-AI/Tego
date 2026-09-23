// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/policy/fsplan"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Implicit entries every RuleTable carries (R9): the run directory (keyed on
// the ledger root, since the run id does not exist yet), the contract file,
// and the two kernel filesystems.
var implicitPaths = []string{"/sys/fs/cgroup", "/sys/fs/bpf"}

// hostStateDir is where tego keeps its host-wide state: build locks, the slot table (ADR 0034). No write
// entry may cover it (R10).
const hostStateDir = "/run/tego"

// builtInDenyRead is the built-in deny_read list relative to the home
// directory (SEMANTICS §1); .env files under the project root are added by
// envFiles. Entries that do not exist are skipped silently.
//
// The credential rows are one per class of secret that a published attack on developer machines
// actually collected. The nx "s1ngularity" compromise (nx 20.9.0-20.12.0, 21.5.0-21.8.0, August
// 2025) drove the developer's own agent CLI to harvest SSH private keys, GitHub tokens via
// `gh auth token`, npm credentials from ~/.npmrc and .env files, and exfiltrated them to public
// repositories. Reads are allowed by default here (SEMANTICS §1; the README: "reads are logged,
// not prevented, unless a path is in deny_read"), so this list is the whole defence against that
// recon step, and .ssh alone covered one of its four credential classes.
//
// Granularity follows where the secret lives: a file where the credential is the file
// (~/.npmrc, ~/.git-credentials, ~/.docker/config.json, ~/.kube/config), a directory where the
// credential is one of several files in it (~/.config/gh holds hosts.yml, ~/.config/gcloud holds
// credentials.db and access_tokens.db). A row that matches nothing compiles no rule and no diagnostic: builtIn
// records it in RuleTable.AbsentDenyRead instead, and the Landlock ruleset enumerates the directory it would
// appear in, so a file created there during the run is refused (ADR 0067 D3).
//
// The agents' own token stores and the stores of the tools an agent runs beside follow (ADR 0067): an agent under
// tego reads no harness's login, its own harness's included, which gets its credential from a variable its profile
// passes instead. A row is here only where the tool's vendor names the location; docs/spec/builtin-deny-read.md
// cites each, and names the rows left out for want of one.
var builtInDenyRead = []string{
	".ssh", ".aws", ".netrc", ".gnupg",
	".npmrc", ".git-credentials", ".config/gh", ".docker/config.json", ".kube/config", ".config/gcloud",
	".claude/.credentials.json", ".claude.json", ".claude/backups", ".codex/auth.json",
	".gemini/oauth_creds.json", ".gemini/.env", ".gemini/mcp-oauth-tokens.json",
	".copilot/config.json", ".copilot/mcp-oauth-config", ".copilot/mcp-secrets",
	".azure", ".config/op", ".password-store", ".pypirc", ".cargo/credentials", ".cargo/credentials.toml",
	".terraform.d/credentials.tfrc.json", ".vault-token", ".pgpass",
	".mozilla/firefox", ".config/google-chrome", ".config/chromium",
	".config/BraveSoftware", ".config/microsoft-edge", ".config/vivaldi", ".config/opera",
	// Other channels and packagings of the same browsers: Chrome beta and unstable, Edge beta and dev,
	// the snap profiles Ubuntu ships Firefox and Chromium as, and the flatpak app data directories.
	".config/google-chrome-beta", ".config/google-chrome-unstable", ".config/microsoft-edge-beta", ".config/microsoft-edge-dev",
	"snap/firefox/common/.mozilla", "snap/chromium/common/chromium",
	".var/app/org.mozilla.firefox", ".var/app/org.chromium.Chromium", ".var/app/com.google.Chrome",
	".var/app/com.brave.Browser", ".var/app/com.microsoft.Edge", ".var/app/com.vivaldi.Vivaldi",
}

// envFile limits for the built-in .env scan of the project root.
const (
	envScanMaxDepth   = 6
	envScanMaxEntries = 50000
	// envScanMaxTime bounds the scan and the resolution of the files it finds together (I6): the project root
	// is usually where the agent writes, so it chooses how many .env files there are and where each links, and
	// one kernel walk through a planted chain of links costs 5 to 11 ms, up to six of them a resolution
	// (resolvePath).
	envScanMaxTime = 2 * time.Second
)

// fs compiles the fs: section (R6, R7, R9, R10, E8, E9, E10) plus the
// built-in deny_read list, the Landlock unenforced marker and, beneath the
// write entries, the built-in deny_write set (R20, RuleTable.DenyWrite).
func (k *compiler) fs() {
	k.rt.FSAssurance = FSAssuranceBestEffort
	if k.c.FS != nil && k.c.FS.Assurance != "" {
		k.rt.FSAssurance = k.c.FS.Assurance
	}
	mt, err := loadMountTable(k.o.mountInfo)
	if err != nil {
		k.ds.warnf(k.cpos, CodeMountWarning, "mount metadata unavailable: %v", err)
	}
	b := &fsBuilder{k: k, mt: mt}
	ledger := k.abs(k.m.LedgerRoot.Value)
	if k.m.LedgerRoot.Value == "" {
		ledger = ""
	}
	b.implicit(ledger)
	b.implicit(k.rt.ContractPath)
	for _, p := range implicitPaths {
		b.implicit(p)
	}
	c := k.c
	if c.FS == nil {
		// R6: no fs: grants no write and adds no declared entry. The built-in deny_read
		// list is governed by deny_read's own tri-state (SEMANTICS §1, "no deny_read:"),
		// not by whether the author typed an fs: key at all: a contract with no fs: has
		// no deny_read: either, so the credential list applies. Only the explicit
		// deny_read: [] disables it, and that route warns at Load (deny-read-disabled).
		// Attaching the list to the presence of fs: made the protection vanish silently
		// on the most common contract shape, and made "unrestricted writes plus the
		// credential denies" inexpressible.
		b.builtIn(nil) // no write entry exists, so nothing can be Unenforced
		b.tegoOwn(ledger, nil)
		b.nameEntries()
		k.rt.FS = b.rules
		return
	}
	if len(c.FS.Write) == 0 { // R6: fs: {} — every write refused
		// Resolved is set like every other entry's: "/" resolves to itself, and a rule
		// carrying an empty Resolved would compare as "" in any containment check that
		// reaches it (agent.FSRule.Resolved, E8).
		b.rules = append(b.rules, FSRule{Path: "/", Kind: FSImplicit, Resolved: "/"})
	}
	b.userDW = b.resolveDenyWrite(c.FS.DenyWrite)
	writes := b.writes(c.FS.Write, ledger)
	b.compileDenyWrite(writes)
	b.searchDenyWriteLinked(writes)
	b.declared(c.FS.Watch, "fs.watch", FSWatch, writes)
	// SEMANTICS §1's tri-state, all three arms: absent -> the built-in list; `deny_read: []` ->
	// disabled, and that is the route that warns (deny-read-disabled); populated -> the declared
	// entries **plus** the built-in list. R6 says "only the explicit `deny_read: []` disables it"
	// and R5 makes deny_read the one list that never loses entries; treating a populated list as a
	// replacement meant one narrow project entry silently dropped ~/.ssh, ~/.aws, ~/.netrc,
	// ~/.gnupg, the credential files and the .env scan, with no diagnostic anywhere — the same
	// fail-open the tri-state exists to prevent, reached by the likelier contract.
	if len(c.FS.DenyRead) > 0 {
		b.declared(c.FS.DenyRead, "fs.deny_read", FSDenyRead, writes)
	}
	// The tri-state is read off the merged slice, the same value Canonical writes down (R13), so
	// the contract.yaml a run leaves behind recompiles to the deny set the run had. A file's
	// `deny_read: []` that the extends union outvoted leaves the list on, and Load says so
	// (denyReadSwitch).
	if c.FS.DenyRead == nil || len(c.FS.DenyRead) > 0 {
		b.builtIn(writes)
	}
	b.tegoOwn(ledger, writes)
	b.nameEntries()
	k.rt.FS = b.rules
}

// tegoOwn adds R6a's read denies, which no deny_read value removes: tego's own directory (the one
// holding the chain anchor, ~/.tego: the machine config, the price table, the profiles, tego.log), ~/.tego
// under the compile's home where the anchor is elsewhere (an adoption's table, compiled against the agent
// owner's home, ADR 0055), the ledger root, and the host state (/run/tego). R10 kept the agent from writing
// them, and nothing kept it from reading them: every run's events.jsonl and blobs, whose argv, headers and,
// under record: full, model bodies a stricter run could then read what a looser one had recorded. R10 also
// keeps every write entry off them, and off the home's ~/.tego beside an anchor elsewhere all but one above it
// (the home), so Landlock can enforce these; that one, under such an entry, is marked unenforced at tier landlock
// like any nested deny, and an entry at or inside it is a contradiction.
//
// The price table and the profiles directory are tego's own wherever the machine config's prices: and
// profiles: put them (limits-check-doctor-cli.md §3): each is denied by its resolved path, the price table as
// the file it is, when it is not under a directory already denied.
//
// A deny attaches to a path that exists; `tego run` makes the ledger root and the anchor's directory
// before it compiles. A directory that also holds what the run needs — the contract, the working directory
// or a write entry, as a ledger root of /tmp or a data disk shared with projects does — is not denied, and
// says so (ledger-readable): denying it would deny the agent its own project.
func (b *fsBuilder) tegoOwn(ledger string, writes []writePath) {
	k := b.k
	var own []string
	if k.o.chainAnchor != "" {
		own = append(own, filepath.Dir(k.o.chainAnchor))
	}
	// ~/.tego under the compile's home too, where the anchor is elsewhere: an adoption compiles against the agent
	// owner's home while the anchor and the ledger are the adopter's (ADR 0055 Decision 5), and the owner's own
	// records (its earlier runs, its machine config and log) stay denied as its own launched run denies them. Where
	// the anchor is in it, the entry above already covers it.
	if k.o.home != "" {
		own = append(own, filepath.Join(k.o.home, ".tego"))
	}
	if ledger != "" {
		own = append(own, ledger)
	}
	own = append(own, hostStateDir)
	var files []string // own entries that may be a regular file rather than a directory
	if k.m != nil {
		if p := k.m.Prices.Value; p != "" {
			own = append(own, p)
			files = append(files, p)
		}
		if p := k.m.Profiles.Value; p != "" {
			own = append(own, p)
		}
	}
	needed := []string{k.resolve(filepath.Dir(k.rt.ContractPath)), k.resolve(k.o.cwd), k.resolve(k.o.home)}
	for _, w := range writes {
		needed = append(needed, w.resolved)
	}
	have := b.denyReadPaths()
	var added []string
	for _, p := range own {
		rp := k.resolve(p)
		if rp == "" || rp == "/" {
			continue
		}
		if fi, err := os.Stat(rp); err != nil || !(fi.IsDir() || fi.Mode().IsRegular() && slices.Contains(files, p)) {
			continue
		}
		if slices.ContainsFunc(added, func(a string) bool { return isAncestorOrSelf(a, rp) }) {
			continue // inside one already denied: ~/.tego/runs under ~/.tego
		}
		if i := slices.IndexFunc(needed, func(n string) bool { return n != "" && isAncestorOrSelf(rp, n) }); i >= 0 {
			k.ds.warnf(k.cpos, CodeLedgerReadable, "%s holds tego's own records and also %s, which the run needs, so it is not read-denied: the agent can read every run's ledger in it",
				p, needed[i]).
				fix("give ledger_root a directory of its own, outside the project and every write entry")
			continue
		}
		added = append(added, rp)
		if have[p] {
			continue
		}
		have[p] = true
		r := FSRule{Path: p, Kind: FSDenyRead, BuiltIn: true, Resolved: rp}
		if fi, err := os.Lstat(rp); err == nil {
			b.meta(&r, fi, rp, Pos{})
		}
		b.unenforced(&r, writes)
		b.rules = append(b.rules, r)
	}
}

type fsBuilder struct {
	k     *compiler
	mt    *mountTable
	rules []FSRule
	// globs is what is left of the bounds of the compile's glob expansions, made at the first glob.
	globs       *globBudget
	writeGrants *fsplan.Grants
	// declNames and builtInNames are the name entry candidates (ADR 0043) of the declared deny_read globs and of the
	// built-in .env list; envEnd is when the .env scan's time limit ends, which compactionFacts keeps to.
	declNames, builtInNames []NameDenyRule
	envEnd                  time.Time
	// userDW is the contract's fs.deny_write entries (ADR 0071), resolved before the write entries are compiled: a
	// write entry beneath one reopens it, which is no redundant entry (E10).
	userDW []userDenyWrite
	// nameGlobWarns is the glob warning of each declared deny_read glob that became a name entry candidate, which
	// laterCoveredWarnings rewrites once the caps kept its entry.
	nameGlobWarns []nameGlobWarn
}

// nameGlobWarn is a candidate glob's warning: where it sits in the diagnostics, and the files it matched (-1: none).
type nameGlobWarn struct {
	raw     string
	pos     Pos
	diag    int
	matches int
}

// implicit adds one Access-0 entry; a missing path is fine (the run creates
// the ledger root; /sys/fs/bpf may be absent), but metadata is probed when
// it exists.
func (b *fsBuilder) implicit(p string) {
	if p == "" {
		return
	}
	r := FSRule{Path: p, Kind: FSImplicit, Resolved: b.k.resolve(p)}
	if fi, err := os.Lstat(r.Resolved); err == nil {
		b.meta(&r, fi, r.Resolved, Pos{})
	} else {
		r.Missing = true
	}
	b.rules = append(b.rules, r)
}

// writePath is one compiled write entry as the checks downstream need it: the
// resolved subtree the kernel will govern, which is what every containment
// question is asked of, and the declared name, which is the string the author
// can find in their own contract when a diagnostic has to name it (E8: "the
// declared path and its target when the two differ").
type writePath struct{ declared, resolved string }

// writes compiles fs.write: the entry may be missing when its parent exists
// (run creates it), a deeper missing chain is path-missing (E9), an entry
// containing the ledger root, the contract file, the chain anchor or another
// of tego's own targets, or a link on the way to one, is a contradiction
// (R10, ADR 0059), and an entry beneath another is redundant (E10)
// unless it grants inside the built-in deny_write set it computes here (R20).
// Returns the write entries, declared and resolved, for the unenforced check.
func (b *fsBuilder) writes(entries []string, ledger string) []writePath {
	k := b.k
	paths := make([]string, 0, len(entries))       // as declared: what E10's redundancy walk is about
	resolved := make([]writePath, 0, len(entries)) // symlink-resolved: what every containment check is about
	set := make(map[string]int, len(entries))
	// Both sides of the R10 comparison are resolved, not just the entry: an admin who symlinks
	// ledger_root onto a bigger disk inside the project would otherwise put the ledger inside a
	// write entry with no diagnostic (E8).
	//
	// The chain anchor is the third: every run's head is checked against it, so an agent that can
	// rewrite it can make a truncated ledger verify. It sat beside the ledger root until the anchor
	// moved to ~/.tego (P0-DESIGN §3.3), and an entry covering it then covered the ledger root too;
	// with any other ledger_root, `fs.write: ["~"]` would otherwise hand the agent chain.log.
	const moveOut = "move the contract and ledger_root outside every write entry, or narrow the entry"
	// The contract is the file the next run reads (ADR 0059): an entry at or over it as declared or where its path
	// leads, or over a directory holding a link its path's walk follows (below), would let the agent rewrite or
	// repoint the contract its next run loads. Its directory and the directory its path led to were the targets, and
	// only the links on the way to those were walked: fs.write [./agent.yaml] compiled, and so did an entry over the
	// directory of a link in the middle of agent.yaml -> l1/x.yaml -> l2/real.yaml.
	targets := []writeTarget{
		k.r10Target("the run directory", ledger, moveOut),
		k.r10Target("the contract file", k.contractWalked, moveOut),
		k.r10Target("the chain anchor", k.o.chainAnchor, "narrow the entry: the chain anchor must stay out of the agent's reach"),
	}
	// tego's runtime parent, $XDG_RUNTIME_DIR/tego, holds every run's private directory: a write entry over it
	// reached every other run's CODEX_HOME and last-refusal mirror (Codex POC F2). The run's own CODEX_HOME is
	// granted by the run itself, never by an entry (R10a).
	runtimeParents := make([]string, 0, len(k.o.runtimeParents))
	for _, declared := range k.o.runtimeParents {
		t := k.r10Target("tego's runtime directory", declared,
			"name the directories the agent needs instead: the run grants its own CODEX_HOME under it by itself (fs.codex_home)")
		runtimeParents = append(runtimeParents, t.path)
		targets = append(targets, t)
	}
	// R9's kernel implicits are never writable from inside the run (SEMANTICS §2), and neither is tego's
	// host state (/run/tego, ADR 0034). Landlock unions rules along a path and crosses mount points, so an
	// entry covering /sys/fs/cgroup granted write on the run's own cgroup files, which at tier 1 the agent's
	// uid owns: with fs.write: ["/sys"] the agent raised its own pids.max and memory.max and wrote another
	// cgroup's cgroup.procs (R10).
	for _, p := range append(slices.Clone(implicitPaths), hostStateDir) {
		targets = append(targets, k.r10Target("tego's kernel or host state", p,
			"name the directories the agent needs beneath it, never /sys/fs/cgroup, /sys/fs/bpf, /run/tego or an ancestor of them"))
	}
	// The machine config's layer files, the price table, the profiles directory and the user registry's agents/ and
	// skills/ wherever the machine config puts them: an agent that rewrites a layer chooses the registry, the
	// profiles, the prices and the ledger root of the runs after it ($TEGO_CONFIG names a file anywhere, and
	// ~/.tego/config.yaml may be a link into a dotfiles tree; ADR 0059), one that rewrites the price table prices
	// every model at $0 for the runs after it, one that rewrites the profiles widens every contract that extends a
	// profile (limits-check-doctor-cli.md §3), and one that rewrites the registry chooses the contract of every later
	// `tego run <name>` the user registry answers (agent-contract.md R26). The registry directory itself is not one:
	// only agents/ and skills/ are read, and a registry: set wide (~) would otherwise refuse every entry beneath it.
	var ownDirs []struct{ name, path string } // an entry strictly inside one of these is refused too
	if k.m != nil {
		for _, l := range k.m.Layers {
			targets = append(targets, k.r10Target("the machine config", l,
				"narrow the entry, or move the machine config's layer file ("+config.EnvConfigVar+", ~/.tego/config.yaml) outside it"))
		}
		const moveMachine = "narrow the entry, or move the machine config's prices:, profiles: and registry: outside it"
		if p := k.m.Prices.Value; p != "" {
			targets = append(targets, k.r10Target("the price table", k.asWalked(p), moveMachine))
		}
		if p := k.m.Profiles.Value; p != "" {
			t := k.r10Target("the profiles directory", k.asWalked(p), moveMachine)
			ownDirs = append(ownDirs, struct{ name, path string }{t.name, t.path})
			targets = append(targets, t)
		}
		if r := k.m.Registry.Value; r != "" {
			for _, sub := range []string{"agents", "skills"} {
				t := k.r10Target("the user registry's "+sub+"/", k.registryDir(r, sub), moveMachine)
				ownDirs = append(ownDirs, struct{ name, path string }{t.name, t.path})
				targets = append(targets, t)
			}
		}
	}
	// tego's own binaries (WithOwnBinaries): an entry over one lets the agent replace what runs outside its contract next.
	ownBinaries, pathShadows := k.ownBinaries()
	targets = append(targets, ownBinaries...)
	// A target is reached by the kernel's walk of its declared path, which looks a name up in every directory it passes,
	// its last name's included, so a write over any of those directories is one as well: it lets the agent make that
	// name a symlink, a directory or a file of its own, and so choose where the next walk lands. That is the directory
	// holding a link the walk follows (registry: ~/.config/tego with tego a link into a dotfiles tree, and an entry
	// over ~/.config), and as surely one holding a name a later ".." leaves (<w>/sub/x/../../reg, and an
	// entry over <w>/sub), a name not there yet, or a name of a link's own text. With no "..", every such
	// directory is at or above the target or a link the walk follows, so no other entry is refused. What R10
	// cannot see by name, the loaders refuse: a file read from agents/ or the profiles directory never leads out of it,
	// and a policy file with a second name is not loaded (config.CheckTrusted, config.CheckOneName; ADR 0059).
	// A target no walk places (a loop of links on its path, a directory on the way this process cannot search) is
	// compared with no entry: its spelling is not where the kernel's walk of it lands, so no comparison would show an
	// entry stays off it. With any write entry declared, the contract is refused instead.
	if len(entries) > 0 {
		for _, t := range targets {
			if t.declared != "" && !t.placed {
				k.ds.errorf(k.pos("fs.write.0"), CodeContradiction, "fs.write: compile cannot place %s %s where the kernel's walk of it lands, so no write entry can be shown to stay off it (R10)",
					t.name, t.declared).
					fix("make %s resolvable (no loop of links on its path, every directory on the way searchable), or remove the write entries", t.declared)
			}
		}
	}
	// And an entry inside tego's own trees is one too, though it contains none of the targets: inside another
	// run's directory under the ledger root it writes that run's record, and inside the directory that holds
	// the chain anchor (~/.tego) it writes the machine config, the price table and the profiles future runs
	// load. The ledger root itself can be a large shared directory (/tmp in a test, a data disk) that holds
	// projects too, so only a path inside one of its run directories counts there.
	ledgerRoot := ""
	if l := k.resolve(ledger); l != "" {
		ledgerRoot = filepath.Dir(l)
	}
	tegoDir := ""
	if k.o.chainAnchor != "" {
		tegoDir = filepath.Dir(k.resolve(k.asWalked(k.o.chainAnchor))) // a relative test hook's where the run opens it
	}
	// And ~/.tego under the compile's home where the anchor is elsewhere (an adoption's table, compiled against the
	// agent owner's home, ADR 0055 Decision 5): it holds that owner's chain anchor, machine config and earlier runs,
	// which R6a read-denies (tegoOwn). An entry at or inside it would drop that deny (tegoOwn's needed) and hand the
	// agent those records to read and write, where the owner's own launched run refuses the same entry (it contains or
	// lies inside that run's anchor directory). An entry above it keeps the deny, nested (marked unenforced at tier
	// landlock), as the home is an ordinary write entry when the anchor is elsewhere. Only a directory that is there,
	// as tegoOwn denies only one: an adoption makes it before it compiles.
	ownerDir := ""
	if k.o.home != "" {
		if d := k.resolve(filepath.Join(k.o.home, ".tego")); d != "" && d != "/" && d != tegoDir {
			if fi, err := os.Stat(d); err == nil && fi.IsDir() {
				ownerDir = d
			}
		}
	}
	for i, raw := range entries {
		key := "fs.write." + strconv.Itoa(i)
		pos := k.pos(key)
		p := k.abs(raw)
		r := FSRule{Path: p, Kind: FSWrite, Access: AccessWriteSet, Raw: raw, Pos: pos, Resolved: k.resolve(p)}
		_, err := os.Stat(p)
		switch {
		case err == nil:
			b.metaDeclared(&r, pos)
		case errors.Is(err, fs.ErrNotExist):
			if hasGlobMeta(p) {
				// A write entry is a path, never a pattern (SEMANTICS §2 expands deny_read and watch only):
				// marked missing, the run would create a directory literally named "*" and grant only it.
				k.ds.errorf(pos, CodePathMissing, "fs.write %q: %s does not exist, and a write entry is not a glob", raw, p).
					fix("name the directory instead: fs.write: [%s] covers everything beneath it", globFreeDir(p))
				continue
			}
			if missing := firstMissing(p); missing != p {
				k.ds.errorf(pos, CodePathMissing, "fs.write %q: parent %s does not exist (run creates only the entry itself)", raw, missing).
					fix("mkdir -p %s", filepath.Dir(p))
				continue
			}
			r.Missing = true
			if pfi, perr := os.Lstat(filepath.Dir(r.Resolved)); perr == nil {
				b.meta(&r, pfi, r.Resolved, pos)
			}
		default:
			k.ds.errorf(pos, CodePathMissing, "fs.write %q: %v", raw, err)
			continue
		}
		for _, target := range targets {
			if target.path != "" && isAncestorOrSelf(r.Resolved, target.path) { // R10
				d := k.ds.errorf(pos, CodeContradiction, "fs.write %q%s contains %s %s%s; Landlock cannot deny beneath an allow",
					raw, resolvedNote(p, r.Resolved), target.name, target.declared, resolvedNote(target.declared, target.path))
				d.fix("%s", target.fix)
				d.overlap = true
				continue
			}
			if name, link := target.nameHeldBy(r.Resolved); link {
				d := k.ds.errorf(pos, CodeContradiction, "fs.write %q%s holds the symlink %s on the way to %s %s%s: the agent could point it elsewhere",
					raw, resolvedNote(p, r.Resolved), name, target.name, target.declared, resolvedNote(target.declared, target.path))
				d.fix("%s", target.fix)
				d.overlap = true
			} else if name != "" {
				d := k.ds.errorf(pos, CodeContradiction, "fs.write %q%s holds %s, a name on the way to %s %s%s: the agent could make it a symlink elsewhere, and the next walk would follow it",
					raw, resolvedNote(p, r.Resolved), name, target.name, target.declared, resolvedNote(target.declared, target.path))
				d.fix("%s", target.fix)
				d.overlap = true
			}
		}
		inside := ""
		switch {
		case tegoDir != "" && tegoDir != "/" && isAncestorOrSelf(tegoDir, r.Resolved) && !isAncestorOrSelf(r.Resolved, tegoDir):
			inside = "tego's own directory " + tegoDir
		case ownerDir != "" && isAncestorOrSelf(ownerDir, r.Resolved):
			inside = "(or is) the agent owner's tego directory " + ownerDir + ", that owner's own records (R6a)"
		case ledgerRoot != "" && inRunDir(ledgerRoot, r.Resolved):
			inside = "a run directory under the ledger root " + ledgerRoot
		case insideOwn(ownDirs, r.Resolved) != "":
			inside = insideOwn(ownDirs, r.Resolved)
		case insideAny(runtimeParents, r.Resolved) != "":
			// A run's private directory, its own included: the run id is not known at compile, and the run grants its
			// own CODEX_HOME by itself.
			inside = "tego's runtime directory " + insideAny(runtimeParents, r.Resolved) + ", where every run keeps its private directory"
		default:
			// Beneath them is no better than over them: an entry inside /sys/fs/cgroup is another cgroup's
			// files, its limits and its cgroup.procs, and one inside /run/tego is the host state a later
			// launcher trusts.
			for _, p := range append(slices.Clone(implicitPaths), hostStateDir) {
				if rp := k.resolve(p); rp != "" && isAncestorOrSelf(rp, r.Resolved) && !isAncestorOrSelf(r.Resolved, rp) {
					inside = "tego's kernel or host state " + p
					break
				}
			}
		}
		if inside != "" {
			d := k.ds.errorf(pos, CodeContradiction, "fs.write %q%s lies inside %s", raw, resolvedNote(p, r.Resolved), inside)
			d.fix("remove the entry: the agent must never write tego's own files")
			d.overlap = true
		}
		kernelFSWrite(k, pos, raw, p, r.Resolved)
		warnPathShadow(k, pos, raw, p, r.Resolved, pathShadows)
		if _, dup := set[p]; dup {
			continue // exact duplicates were warned at Load
		}
		set[p] = i
		paths = append(paths, p)
		resolved = append(resolved, writePath{declared: p, resolved: r.Resolved})
		b.rules = append(b.rules, r)
	}
	regrants := b.denyWrite(resolved)
	for _, w := range resolved {
		if b.reopens(w.resolved) {
			regrants[w.declared] = true // nearest wins: it grants beneath an fs.deny_write entry (ADR 0071)
		}
	}
	if !k.askScope {
		// A top-level entry at an existing .env file is the author's way to let the agent use it (ADR 0043 D3: it
		// leaves the built-in list, and no name entry covers it), not a narrower duplicate to remove.
		for _, r := range b.rules {
			if r.Kind == FSWrite && !r.Missing && r.Pos.File == k.top && isEnvFile(FoldName(filepath.Base(r.Resolved))) {
				if fi, err := os.Lstat(r.Resolved); err == nil && !fi.IsDir() {
					regrants[r.Path] = true
				}
			}
		}
	}
	b.redundant(paths, set, regrants)
	return resolved
}

// kernelFSWrite warns about a write entry on procfs or on /dev itself: their files write to the kernel,
// to this uid's other processes and to devices, not to storage. A grant on /proc reaches /proc/<pid>/mem,
// oom_score_adj and attr of every process the uid owns; one on /dev every device node the uid can open, the
// terminals of its other sessions among them. Both compiled without a word (E38). A single
// device file (/dev/null, which the starter grants) or /dev/shm is not /dev and is not warned about; /sys is
// left to the implicit-entry contradiction.
func kernelFSWrite(k *compiler, pos Pos, raw, p, resolved string) {
	switch {
	case resolved == "/proc" || strings.HasPrefix(resolved, "/proc/"):
		k.ds.warnf(pos, CodeKernelFSWrite, "fs.write %q%s reaches procfs, whose files write to the kernel and to this uid's other processes (/proc/<pid>/mem, oom_score_adj), not to storage",
			raw, resolvedNote(p, resolved)).
			fix("remove the entry")
	case resolved == "/dev":
		k.ds.warnf(pos, CodeKernelFSWrite, "fs.write %q%s grants writes to every device node this uid can open, the terminals of its other sessions among them, not to storage",
			raw, resolvedNote(p, resolved)).
			fix("name the device files the agent needs instead, such as /dev/null or /dev/shm")
	}
}

// insideAny is the first of dirs that path lies strictly beneath, "" when none (a dir of "" or "/" never counts).
func insideAny(dirs []string, path string) string {
	for _, d := range dirs {
		if d != "" && d != "/" && isAncestorOrSelf(d, path) && !isAncestorOrSelf(path, d) {
			return d
		}
	}
	return ""
}

// insideOwn is the first of tego's own directories that path lies strictly inside, named with its path, or "".
func insideOwn(dirs []struct{ name, path string }, path string) string {
	for _, d := range dirs {
		if insideAny([]string{d.path}, path) != "" {
			return d.name + " " + d.path
		}
	}
	return ""
}

// inRunDir reports whether path lies in (or is) a run directory directly under root: its first component
// below root is a run id.
func inRunDir(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return false
	}
	first, _, _ := strings.Cut(rel, string(filepath.Separator))
	return identity.RunID(first).Valid()
}

// resolvedNote is the clause a diagnostic appends when symlinks take a declared
// path somewhere else, so the reader sees both the entry as written and the
// subtree the rule really governs (E8). Empty in the ordinary case, where the
// two are the same and a note would be noise.
func resolvedNote(declared, resolved string) string {
	if resolved == "" || resolved == declared {
		return ""
	}
	return " (resolves to " + resolved + ")"
}

// redundant warns on a write entry beneath another write entry (E10):
// O(n·depth) by walking each path's ancestors against the set. An entry in
// regrants is not redundant: it lies at or inside a built-in deny_write
// target (R20), where it is the author's way of letting the agent write there,
// and "remove the narrower entry" would take that back.
func (b *fsBuilder) redundant(paths []string, set map[string]int, regrants map[string]bool) {
	for _, p := range paths {
		if regrants[p] {
			continue
		}
		for anc := filepath.Dir(p); ; anc = filepath.Dir(anc) {
			if i, ok := set[anc]; ok {
				pos := b.k.pos("fs.write." + strconv.Itoa(set[p]))
				b.k.ds.warnf(pos, CodeRedundantRule, "fs.write %s is already covered by entry %d (%s)", p, i+1, anc).
					fix("remove the narrower entry")
				break
			}
			if anc == "/" || anc == "." {
				break
			}
		}
	}
}

// declared compiles fs.watch and fs.deny_read: every entry must exist (R7);
// a glob expands to its existing matches (SEMANTICS §2), none is a warning.
func (b *fsBuilder) declared(entries []string, key string, kind FSKind, writes []writePath) {
	k := b.k
	for i, raw := range entries {
		pos := k.pos(key + "." + strconv.Itoa(i))
		p := k.abs(raw)
		// A file whose own name holds a glob character ("lit[1].txt") is that file, not a pattern: an entry
		// naming it read as a glob that matched nothing, and the file stayed readable.
		_, literalErr := os.Lstat(p)
		if hasGlobMeta(p) && literalErr != nil {
			// filepath.Glob has no recursive **: "g/**/s.json" matched one directory level, silently, and a
			// file two levels down stayed readable. Refused rather than read as something it is not.
			if strings.Contains(p, "**") {
				k.ds.errorf(pos, CodeSchema, "%s %q: ** is not a recursive match here, only one directory level", key, raw).
					fix("name the directory that holds the files (a directory entry covers everything beneath it)")
				continue
			}
			if b.globs == nil {
				b.globs = newGlobBudget()
			}
			matches, stop, err := b.globs.expand(p)
			if err != nil {
				k.ds.errorf(pos, CodeSchema, "%s %q: bad glob: %v", key, raw, err)
				continue
			}
			if stop != globWhole {
				b.globCut(pos, key, raw, kind, stop, len(matches))
				if kind == FSDenyRead {
					continue
				}
			}
			candidate := false
			if kind == FSDenyRead {
				n := len(b.declNames)
				b.nameGlob(p, raw, pos) // a whole expansion only: one cut short does not compile
				candidate = len(b.declNames) > n
				b.denyReadGlob(p, raw)
			}
			if candidate {
				b.nameGlobWarns = append(b.nameGlobWarns, nameGlobWarn{raw: raw, pos: pos, diag: len(k.ds.list), matches: len(matches)})
			}
			if len(matches) == 0 {
				k.ds.warnf(pos, CodeGlobNoMatch, "%s %q matches nothing now; files created later are not covered", key, raw)
				continue
			}
			// SEMANTICS §2: a glob covers the files that exist when the contract is compiled; one whose name entry the
			// caps keep covers files created later at tiers cgroup and bpflsm too (laterCoveredWarnings).
			k.ds.warnf(pos, CodeGlobNoMatch, "%s %q covers the %d file(s) that exist now; files created later are not covered", key, raw, len(matches))
			sort.Strings(matches)
			for _, m := range matches {
				b.addDeclared(m, raw, pos, kind, writes)
			}
			continue
		}
		if _, err := os.Stat(p); err != nil {
			k.ds.errorf(pos, CodePathMissing, "%s %q: %s does not exist", key, raw, p).
				fix("create it or remove the entry; run refuses to start for a missing %s entry", kind)
			continue
		}
		b.addDeclared(p, raw, pos, kind, writes)
	}
}

// globCut says a glob's expansion stopped short of its bounds (compile_glob.go). A deny_read glob cut short is an
// error: the files it did not reach would stay readable under an entry that names them, so the contract does not
// compile, fail-closed. A watch glob cut short warns, since a watch grants and withholds nothing (SEMANTICS §7).
func (b *fsBuilder) globCut(pos Pos, key, raw string, kind FSKind, stop globStop, found int) {
	why := ""
	switch stop {
	case globEntries:
		why = "read the " + strconv.Itoa(globScanMaxEntries) + " directory entries all of this compile's globs may read, and left more unread"
	case globTime:
		why = "ran out of the " + globScanMaxTime.String() + " all of this compile's globs may take"
	case globMatches:
		why = "matched more than the " + strconv.Itoa(globMaxMatches) + " files all of this compile's globs may cover"
	case globUnread, globWhole:
		why = "could not list a directory it reached whole"
	}
	if kind == FSDenyRead {
		b.k.ds.errorf(pos, CodeUnenforced, "%s %q: the glob's expansion %s, so a file it matches would not be denied", key, raw, why).
			fix("name the directory that holds the files instead (a directory entry covers everything beneath it)")
		return
	}
	b.k.ds.warnf(pos, CodeGlobNoMatch, "%s %q: the glob's expansion %s, so it covers only the %d file(s) found before it stopped", key, raw, why, found).
		fix("name the directory that holds the files instead (a directory entry covers everything beneath it)")
}

func (b *fsBuilder) addDeclared(p, raw string, pos Pos, kind FSKind, writes []writePath) {
	r := FSRule{Path: p, Kind: kind, Raw: raw, Pos: pos, Resolved: b.k.resolve(p)}
	// enforce-landlock.md E5: a deny of / has no parent to enumerate, and would deny the run everything. Judged
	// on the resolved path, so a symlink to / is refused as / is; the Landlock backstop fails closed on the same.
	if kind == FSDenyRead && filepath.Clean(r.Resolved) == "/" {
		b.k.ds.errorf(pos, CodeSchema, "fs.deny_read %q%s denies the whole filesystem, which no tier can enforce and no run could start under", raw, resolvedNote(p, r.Resolved)).
			fix("name the directories to deny beneath /")
		return
	}
	b.metaDeclared(&r, pos)
	if kind == FSDenyRead {
		b.unenforced(&r, writes)
	}
	b.rules = append(b.rules, r)
}

// builtIn adds the built-in deny_read list: existing entries only, never a
// diagnostic for a missing one.
func (b *fsBuilder) builtIn(writes []writePath) {
	have := b.denyReadPaths()
	for _, rel := range builtInDenyRead {
		p := filepath.Join(b.k.o.home, rel)
		if _, err := os.Stat(p); err != nil {
			b.absentBuiltIn(p, writes)
			continue
		}
		b.addBuiltIn(p, writes, have)
	}
	end := time.Now().Add(envScanMaxTime)
	b.envEnd = end
	roots := envScanRoots(b.k.rt.ContractPath, b.k.o.cwd)
	b.envNames(b.envNameScopes(roots))
	// A write entry of the top-level contract file at a .env file the scan finds drops it from the list (ADR 0043
	// D3); kept as a set, since the scan can find tens of thousands of files.
	topWrites := map[string]bool{}
	for i := range b.rules {
		if r := &b.rules[i]; r.Kind == FSWrite && r.Pos.File == b.k.top {
			topWrites[r.Resolved] = true
		}
	}
	envs, cut, late, unread := envFiles(roots, end)
	unresolved := 0
	for i, p := range envs {
		if time.Now().After(end) {
			late, unresolved = true, len(envs)-i
			break
		}
		res := b.k.resolve(p)
		if topWrites[res] && b.envWriteDrop(p, res) {
			continue
		}
		b.addBuiltInResolved(p, res, writes, have)
	}
	// The project root is usually where the agent writes, so what fills it before the next compile is the
	// agent's choice: a scan cut short in silence let a planted directory of names, or of links, hide a .env
	// from the list.
	if cut {
		b.k.ds.warnf(b.k.cpos, CodeUnenforced, "the built-in deny_read scan for .env files under %s read its %d directory entries and left more unread, so a .env file among them is not in the list and nothing refuses reading it",
			strings.Join(roots, " and "), envScanMaxEntries).
			fix("name the .env files in fs.deny_read, or run from a directory with fewer entries")
	}
	if len(unread) > 0 {
		more := ""
		if len(unread) > 1 {
			more = " and " + strconv.Itoa(len(unread)-1) + " more"
		}
		b.k.ds.warnf(b.k.cpos, CodeUnenforced, "the built-in deny_read scan for .env files under %s could not read %s%s, so a .env file in it is not in the list and nothing refuses reading it",
			strings.Join(roots, " and "), unread[0], more).
			fix("name the .env files in fs.deny_read, or make the directory readable")
	}
	if late {
		left := ""
		if unresolved > 0 {
			left = ", with " + strconv.Itoa(unresolved) + " of the " + strconv.Itoa(len(envs)) + " .env files it found not yet resolved"
		}
		b.k.ds.warnf(b.k.cpos, CodeUnenforced, "the built-in deny_read scan for .env files under %s ran out of its time limit, %s%s, so a .env file it did not reach is not in the list and nothing refuses reading it",
			strings.Join(roots, " and "), envScanMaxTime, left).
			fix("name the .env files in fs.deny_read, and look for what slows the scan: many .env names, or .env links through long chains of links")
	}
}

// denyReadPaths is the set of paths the table's deny_read rules name. A populated deny_read list is
// compiled alongside the built-in one, so an author who spells out a path the built-in list also covers
// gets one rule, not two: the duplicate would decide identically but be printed twice and carried into the
// ledger's rule field twice. A set, not a scan of the table per entry: the .env scan finds up to
// envScanMaxEntries files where the agent writes, and a scan each made that quadratic, 49000 planted
// .env.<n> files spending the scan's whole time limit on it.
func (b *fsBuilder) denyReadPaths() map[string]bool {
	have := map[string]bool{}
	for i := range b.rules {
		if b.rules[i].Kind == FSDenyRead {
			have[b.rules[i].Path] = true
		}
	}
	return have
}

// addBuiltIn appends one entry of the built-in list, resolved like any other
// so the unenforced check sees the subtree it governs (E8), unless have, the
// deny_read paths already in the table, names it; have gains it.
func (b *fsBuilder) addBuiltIn(p string, writes []writePath, have map[string]bool) {
	if have[p] {
		return
	}
	b.addBuiltInResolved(p, b.k.resolve(p), writes, have)
}

// addBuiltInResolved is addBuiltIn with p's resolution already made.
func (b *fsBuilder) addBuiltInResolved(p, resolved string, writes []writePath, have map[string]bool) {
	if have[p] {
		return
	}
	have[p] = true
	r := FSRule{Path: p, Kind: FSDenyRead, BuiltIn: true, Resolved: resolved}
	if fi, err := os.Lstat(r.Resolved); err == nil {
		b.meta(&r, fi, r.Resolved, Pos{})
	}
	b.unenforced(&r, writes)
	b.rules = append(b.rules, r)
}

// grants is the containment index of the write entries, built once.
func (b *fsBuilder) grants(writes []writePath) *fsplan.Grants {
	if b.writeGrants == nil {
		paths := make([]string, len(writes))
		for i, w := range writes {
			paths[i] = w.resolved
		}
		b.writeGrants = fsplan.NewGrants(paths)
	}
	return b.writeGrants
}

// absentBuiltIn records a built-in row that does not exist in RuleTable.AbsentDenyRead (ADR 0067 D3), with the name
// the Landlock ruleset leaves ungranted for it (AbsentRow.At), so a file created there during the run is refused. A row
// that is a symlink leading nowhere yet is recorded by the place the link leads (danglingPlace): Landlock decides on
// the file the link reaches, so that is the name to leave ungranted, and a login writing through the link makes its
// file there. A row whose name a write entry covers is left out: the write
// grant reaches it whatever the ruleset enumerates, and compile already warns for one that exists there; one an
// exec.allow directory covers is left out after exec() (denyReadUnderExecDirs).
func (b *fsBuilder) absentBuiltIn(p string, writes []writePath) {
	if !filepath.IsAbs(p) {
		return
	}
	res, ok := danglingPlace(p)
	if !ok {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			return
		}
		res = b.k.resolve(p)
	}
	if res == "" || !filepath.IsAbs(res) {
		return
	}
	at, ok := absentAt(res)
	if !ok {
		return
	}
	if g := b.grants(writes); g.FirstCover(at) >= 0 || g.FirstCover(res) >= 0 {
		return
	}
	b.k.rt.AbsentDenyRead = append(b.k.rt.AbsentDenyRead, AbsentRow{Path: p, Resolved: res, At: at})
}

// unenforced marks a deny_read entry that lies at or below a write entry:
// the Landlock ruleset cannot deny beneath an allow (SEMANTICS §2); root tiers
// still enforce it, and at tier landlock held reads do (ADR 0069). The write
// entry that covers it is kept for heldReads, which says what the tier does
// with the target once fs.reads is known.
func (b *fsBuilder) unenforced(r *FSRule, writes []writePath) {
	// The same path as a write entry and a deny_read entry reads two ways: Evaluate lets the write win the
	// tie, tier 2's open decision lets the deny win (equal length), and nothing said so. Neither reading
	// is the author's plainly, so it is a contradiction, as the tiers would otherwise disagree. Every write
	// entry is asked first: the ancestor check below returns at the first enclosing entry, so asking both in
	// one pass missed the contradiction whenever a broader write entry was listed before the equal one.
	for _, w := range writes {
		if w.resolved == r.Resolved {
			d := b.k.ds.errorf(r.Pos, CodeContradiction, "deny_read %s%s is also a write entry (%s)",
				r.Path, resolvedNote(r.Path, r.Resolved), w.declared)
			d.fix("deny a path beneath the write entry, or drop one of the two")
			d.overlap = true
			return
		}
	}
	// The held-object plan applies this same indexed containment decision to
	// descriptor names at Prepare; I5 compares its result with this prediction.
	if i := b.grants(writes).FirstCover(r.Resolved); i >= 0 {
		r.Unenforced = true
		// Both paths are named as declared, with the target appended when a symlink
		// takes them elsewhere (E8): naming only the resolved write entry pointed the
		// author at a path that appears nowhere in their contract, which is precisely
		// the entry they have to edit (heldReadsDiagnostics).
		if b.k.nestedWrite == nil {
			b.k.nestedWrite = map[string]writePath{}
		}
		b.k.nestedWrite[r.Path] = writes[i]
		return
	}
}

// metaDeclared records the mount metadata of the path the rule governs (E8:
// the O_PATH open follows symlinks, so a symlinked entry is described by its
// target's filesystem — Lstat'ing the link itself reported the link's own
// device and suppressed exactly the mount-point, overlay and btrfs warnings
// R7 exists to emit).
func (b *fsBuilder) metaDeclared(r *FSRule, pos Pos) {
	if fi, err := os.Lstat(r.Resolved); err == nil {
		b.meta(r, fi, r.Resolved, pos)
	}
}

// meta fills mount, filesystem and device from path — the resolved form of
// the entry — and warns on a mount point, overlay layer or btrfs
// (SEMANTICS §2 "Identity").
func (b *fsBuilder) meta(r *FSRule, fi os.FileInfo, path string, pos Pos) {
	r.Device = deviceOf(fi)
	// ADR 0043 D6 (d): what a covered file's row may be compacted on, from the Lstat already made.
	r.Regular, r.Nlink = fi.Mode().IsRegular(), nlinkOf(fi)
	m, isPoint, ok := b.mt.lookup(path)
	if !ok {
		return
	}
	r.Mount, r.Filesystem, r.IsMountPoint = m.point, m.fstype, isPoint && fi.IsDir()
	r.FileMountPoint = isPoint && !fi.IsDir()
	r.Overlay = m.fstype == "overlay"
	r.Btrfs = m.fstype == "btrfs"
	if pos.Line == 0 {
		return
	}
	note := resolvedNote(r.Path, path)
	switch {
	case r.IsMountPoint:
		b.k.ds.warnf(pos, CodeMountWarning, "%s%s is a mount point (%s): the rule applies to the mounted filesystem's root", r.Path, note, m.fstype).info()
	case r.Overlay:
		b.k.ds.warnf(pos, CodeMountWarning, "%s%s is on an overlay filesystem: rules on its upper or lower layers never apply to the merged tree", r.Path, note)
	case r.Btrfs:
		b.k.ds.warnf(pos, CodeMountWarning, "%s%s is on btrfs: subvolumes carry their own device numbers", r.Path, note)
	}
}

// firstMissing walks down from / and returns the first segment of p that
// does not exist (E9), or p itself when only the leaf is missing.
func firstMissing(p string) string {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	cur := "/"
	for _, seg := range parts {
		cur = filepath.Join(cur, seg)
		if _, err := os.Lstat(cur); err != nil {
			return cur
		}
	}
	return p
}

// registryDir is the user registry r's directory sub (agents or skills) as the registry's lookup opens it: under r as
// given, never cleaned, since filepath.Join removes a ".." with the link before it, where the lookup's walk goes up
// from the link's target. R10 and OwnReadable resolve and walk it as the lookup does.
func (k *compiler) registryDir(r, sub string) string {
	return strings.TrimSuffix(k.asWalked(r), "/") + "/" + sub
}

// writeTarget is one of R10's targets: a path no write entry may contain (writes), as declared and as placed, the walk
// that places it, and the fix a refusal names.
type writeTarget struct {
	name, declared, path, fix string
	placed                    bool       // path is where the kernel's walk of declared lands (walkTarget); "" declares none
	held                      []heldName // every name that walk reads, its symlinks first
}

// heldName is a name a target's walk reads, the directory it is read in, and whether it is a symlink the walk follows.
type heldName struct {
	name, dir string
	link      bool
}

// r10Target is the target declared, placed by its walk (walkTarget): where the kernel's walk of it lands, its
// directories made or not yet and a final symlink leading nowhere yet followed to where it leads, since
// the target's loader follows it, whether or not /proc is mounted; and every name the walk
// reads on the way. One no walk places keeps its declared spelling and is not placed: writes refuses
// every write entry against it, since no comparison with that spelling shows the entry stays off it. A relative
// declared path (a test hook's chain anchor) is taken against the compile's working directory, as its loader opens it.
func (k *compiler) r10Target(name, declared, fix string) writeTarget {
	if declared != "" {
		declared = k.asWalked(declared)
	}
	w := walkTarget(declared)
	t := writeTarget{name: name, declared: declared, path: w.place, fix: fix, placed: w.placed}
	for _, l := range w.links {
		t.held = append(t.held, heldName{name: l, dir: filepath.Dir(l), link: true})
	}
	for _, n := range w.names {
		if !slices.Contains(w.links, n) {
			t.held = append(t.held, heldName{name: n, dir: filepath.Dir(n)})
		}
	}
	return t
}

// nameHeldBy is a name the target's walk reads in a directory at or beneath the write entry entry (resolved), and
// whether it is a symlink the walk follows: a name the agent could replace there, and with it where the walk lands. A
// symlink is named first, since the walk follows its text as well; else the first such name in walk order. "" when
// the entry holds none of them.
func (t writeTarget) nameHeldBy(entry string) (string, bool) {
	for _, h := range t.held {
		if isAncestorOrSelf(entry, h.dir) {
			return h.name, h.link
		}
	}
	return "", false
}

// isAncestorOrSelf reports whether anc == p or anc is a directory above p. It allocates nothing: R10 asks it for every
// write entry against every directory each target's walk reads (writes), thousands of times in a large contract.
func isAncestorOrSelf(anc, p string) bool {
	if anc == p || anc == "/" {
		return true
	}
	return len(p) > len(anc) && p[len(anc)] == '/' && strings.HasPrefix(p, anc)
}

func hasGlobMeta(p string) bool { return strings.ContainsAny(p, "*?[") }

// globFreeDir is the deepest ancestor of the absolute path p none of whose components holds a glob
// character: the directory a write entry written as a pattern should name.
func globFreeDir(p string) string {
	for hasGlobMeta(p) && p != "/" {
		p = filepath.Dir(p)
	}
	return p
}

// envScanRoots is where the built-in .env scan starts: the project root, which is the directory of the
// contract file (`tego init` writes agent.yaml there, and a contract is kept with the project it confines),
// and the directory the run starts in, which relative entries resolve against (E28) and where the agent
// works. The scan was rooted at the working directory alone, so `tego run ../agent.yaml` from a
// subdirectory, or a run started in src/, left the project root's .env readable. The working directory
// comes second and is left out when it is the contract's own directory.
func envScanRoots(contractPath, cwd string) []string {
	var roots []string
	if contractPath != "" {
		roots = append(roots, filepath.Dir(contractPath))
	}
	if cwd != "" && (len(roots) == 0 || filepath.Clean(cwd) != roots[0]) {
		roots = append(roots, filepath.Clean(cwd))
	}
	return roots
}

// envFiles lists .env and .env.* files under roots, skipping example files and dependency directories,
// breadth first from every root at once, envScanMaxDepth levels below each, and reading at most
// envScanMaxEntries directory entries in all; cut says entries were left unread, late that the scan stopped
// at end. A directory reached twice, a working directory inside the contract's for one, is read once. The
// roots are usually where the agent writes, so each directory is read through listDir with what is
// left of that budget (I6): filepath.WalkDir read every entry of a directory before any bound was checked,
// so a directory of millions of cheap hard links was listed in full. The files come sorted, symlinks last:
// resolving a symlink is where a planted chain of links costs time, so the regular .env files found are
// resolved before any link, and a plant of links, however slow each is, cannot spend the caller's time
// limit before them.
//
// unread names each directory the scan listed only in part, or, of the operator's own, could not open, with
// the error: a .env file in it is missed as surely as one past the budget. As the deny-write search's
// unlisted, a directory that is gone or no longer a directory is not one, and neither is another user's
// directory the operator cannot open, since the agent, running as the operator, cannot list it either.
func envFiles(roots []string, end time.Time) (out []string, cut, late bool, unread []string) {
	type dir struct {
		path  string
		depth int
	}
	left := envScanMaxEntries
	var links []string
	queue := make([]dir, 0, len(roots))
	for _, r := range roots {
		queue = append(queue, dir{r, 0})
	}
	seen := map[string]bool{}
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		if seen[d.path] {
			continue
		}
		seen[d.path] = true
		if left == 0 {
			cut = true
			break
		}
		if time.Now().After(end) {
			late = true
			break
		}
		es, more, err := listDir(d.path, left)
		if err != nil && envDirUnread(d.path, err) {
			unread = append(unread, d.path+" ("+listErrText(err)+")")
		}
		left -= len(es)
		cut = cut || more
		for _, e := range es {
			p := filepath.Join(d.path, e.Name())
			if e.IsDir() {
				if !IsEnvSkipDir(e.Name()) && d.depth+1 < envScanMaxDepth {
					queue = append(queue, dir{p, d.depth + 1})
				}
				continue
			}
			if isEnvFile(e.Name()) {
				if e.Type()&fs.ModeSymlink != 0 {
					links = append(links, p)
				} else {
					out = append(out, p)
				}
			}
		}
	}
	sort.Strings(out)
	sort.Strings(links)
	return append(out, links...), cut, late, unread
}

// envDirUnread reports whether listDir's err on dir left a .env file there unfound that the agent may read.
func envDirUnread(dir string, err error) bool {
	var partial *partialListError
	if errors.As(err, &partial) {
		return true
	}
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
		return false
	}
	var st unix.Stat_t
	return unix.Lstat(dir, &st) == nil && int(st.Uid) == os.Geteuid()
}

// listErrText is listDir's error without the path an *fs.PathError repeats.
func listErrText(err error) string {
	var partial *partialListError
	if errors.As(err, &partial) {
		return "listed only in part: " + partial.err.Error()
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	return "could not open: " + err.Error()
}

// isEnvFile is the built-in .env scan's predicate, case-exact: `.env`, and `.env.<x>` but the example files. It
// is made of the built-in name entries' own literals and exceptions (ADR 0043), so the two cannot drift
// (FuzzEnvNameRuleMatchesScan).
func isEnvFile(name string) bool {
	if name == builtInEnvExact {
		return true
	}
	return strings.HasPrefix(name, builtInEnvPrefix) && !slices.Contains(builtInEnvExcept, name)
}

// denyReadUnderExecDirs extends R4 to exec.allow directory grants. An exec grant carries READ_FILE as well
// as EXECUTE (the kernel opens a program O_RDONLY|__FMODE_EXEC, so EXECUTE alone never satisfies file_open),
// and Landlock grants an access when any rule on the path grants it. A deny_read target beneath a granted
// directory is therefore readable in the Landlock tier exactly as it is beneath a write entry, and must be
// reported the same way. Runs after exec(), which is where directory grants are resolved.
func (k *compiler) denyReadUnderExecDirs() {
	type execDir struct{ declared, resolved string }
	var dirs []execDir
	for _, r := range k.rt.Exec {
		if r.IsDir {
			// Resolved on both sides for the same reason as the write check: the grant lands
			// on the directory's target inode, not on the name (E8).
			dirs = append(dirs, execDir{declared: r.Path, resolved: k.resolve(r.Path)})
		}
	}
	if len(dirs) == 0 {
		return
	}
	paths := make([]string, len(dirs))
	for i, d := range dirs {
		paths[i] = d.resolved
	}
	grants := fsplan.NewGrants(paths)
	// An absent built-in row's name beneath a directory grant is not left out of the Landlock ruleset (fsplan.Build
	// marks it unenforced, and the grant's READ_FILE reaches it), so it is no longer one the tier models refuse.
	k.rt.AbsentDenyRead = slices.DeleteFunc(k.rt.AbsentDenyRead, func(a AbsentRow) bool {
		return grants.FirstCover(a.At) >= 0 || grants.FirstCover(a.Resolved) >= 0
	})
	for i := range k.rt.FS {
		r := &k.rt.FS[i]
		// An fs.ask_read entry an exec directory covers is refused, not warned (askReadEnforced).
		if r.Kind != FSDenyRead || r.Unenforced || r.AskRead {
			continue
		}
		if j := grants.FirstCover(r.Resolved); j >= 0 {
			dir := dirs[j]
			d := dir.declared
			r.Unenforced = true
			if k.mayLand(backend.TierLandlock) {
				// Both paths as declared, each with its target when a symlink takes it elsewhere
				// (E8): the check compared resolved paths, and naming only the declared ones showed
				// the author two paths that look disjoint.
				dnote := resolvedNote(d, dir.resolved)
				k.ds.warnf(r.Pos, CodeUnenforced, "deny_read %s%s is unenforced in the landlock tier: exec.allow grants %s%s, which carries read access to its whole subtree",
					r.Path, resolvedNote(r.Path, r.Resolved), d, dnote).
					fix("pin a root tier, name the binaries instead of the directory, or move the secret outside %s%s", d, dnote).only(backend.TierLandlock)
			}
		}
	}
}

// execResolved records where each exec grant lands (ExecRule.Resolved): the rule keeps the spelling it
// resolved to, which may pass through a link, and the grant follows it (enforce-landlock R5 holds each rule's
// path without O_NOFOLLOW). Evaluate matches both, as the tiers do (R15).
func (k *compiler) execResolved() {
	for i := range k.rt.Exec {
		if r := &k.rt.Exec[i]; r.Path != "" && filepath.IsAbs(r.Path) {
			r.Resolved = k.resolve(r.Path)
		}
	}
}

// execInsideDenyRead warns about an exec grant that lies strictly inside a deny_read target the Landlock tier
// enforces. The grant keeps an fd of its own with READ_FILE (enforce-landlock R5, I11 (1)), so at tier 1 the
// file, or a directory entry's whole subtree, stays readable through the deny_read; the root tiers and tier 2's
// listener refuse those reads. Evaluate answers the same (execReadGrant; R15). A grant
// enclosing the target is denyReadUnderExecDirs' case, and one at the target itself fails Prepare (E32 (c)).
func (k *compiler) execInsideDenyRead() {
	if len(k.rt.Exec) == 0 || !k.mayLand(backend.TierLandlock) {
		return
	}
	for i := range k.rt.FS {
		r := &k.rt.FS[i]
		// An exec grant inside an fs.ask_read entry is refused, not warned (askReadEnforced).
		if r.Kind != FSDenyRead || r.Unenforced || r.AskRead {
			continue
		}
		target := r.Governed()
		for _, x := range k.rt.Exec {
			at := x.Resolved
			if at == "" {
				at = x.Path
			}
			if at == "" || at == target || !isAncestorOrSelf(target, at) {
				continue
			}
			what := "the binary stays"
			if x.IsDir {
				what = "every file beneath the directory stays"
			}
			k.ds.warnf(r.Pos, CodeUnenforced, "deny_read %s%s does not cover exec grant %s%s in the landlock tier: an exec grant carries read access, so %s readable",
				r.Path, resolvedNote(r.Path, r.Resolved), rawOr(x.Raw, x.Path), resolvedNote(x.Path, x.Resolved), what).
				fix("pin a root tier, or install the binary outside %s", r.Path).only(backend.TierLandlock)
		}
	}
}
