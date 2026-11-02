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

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// The built-in deny_write set (R20) is the write side of the nx "s1ngularity" compromise the built-in
// deny_read list answers (compile_fs.go): files an agent with an ordinary write grant on a worktree can
// change so that code runs outside the run the next time something else reads them. A git hook runs on
// the user's next commit, from the git directory's hooks/ or from the directory core.hooksPath names (Husky's
// .husky, a repository's .githooks); .git/config's core.hooksPath, core.fsmonitor and core.sshCommand name
// programs git runs; a harness's project settings (.claude/, .mcp.json, .cursor/, .codex/, .gemini/) and an
// editor's (.vscode/ tasks and launch configurations) name hooks, commands and MCP servers the next session
// starts (CVE-2025-54135/54136 are Cursor's .cursor/mcp.json); a shell startup file runs in the user's next
// shell. The peer agent sandboxes (Anthropic's sandbox-runtime and Claude Code, OpenAI Codex) refuse writes to
// files of these kinds beneath a directory they otherwise make writable, though their lists differ from this
// one. Not named, as R20's residuals: .idea (a run configuration does not run by itself) and .gitmodules (a
// submodule URL runs nothing until a recursive update, and refusing it would break a submodule add).
//
// Of a git directory only hooks and config are in the set: the rest (objects, refs, the index, the lock
// files a commit creates) is what git itself writes on every commit, so leaving it to the write entry is
// what keeps git working inside the run.
//
// Each is a path, not a pattern, and an entry that does not exist is skipped: the tiers key a rule on the
// inode the path names (SEMANTICS §2), so a name that does not exist has nothing to key, and refusing its
// creation would mean refusing creation in its parent, the write entry itself.
//
// Every file this reads to find the set (a .git file, a commondir, a git config) and every directory it lists
// lies where the agent can write, so each read goes through boundedio.go: an agent that plants a FIFO, a link
// to /dev/zero or /proc/kmsg, or a sparse multi-gigabyte file there must not hang or exhaust the operator's
// next compile. For the same reason the search as a whole is bounded, not only each read: one budget per
// write entry covers every directory it examines, every entry it lists, every byte it reads and every path
// it probes (denySearch), the compile as a whole spends at most maxSearchWhole entries' worth of it, and a
// git directory reached again, through another .git file or another link, is recognised by its identity and
// not read or walked again, unless a limit cut that read, or another write entry's limit that walk (info,
// modules). Without these, a few thousand planted .git files naming one git directory with a wide modules/
// made compile's cost grow with their square.
//
// Those budgets count operations, not what each costs, and the cost of one is the path walk the agent
// shapes: a probe or a read walks a path the agent chose (a core.hooksPath value, a .git file's gitdir) or
// one beneath its write entry, and the kernel follows up to 40 links of up to 4095 bytes each on one walk, so
// a chain of 39 links through directories 1980 levels deep makes one walk 5 to 11 ms, and 16 values probed
// from each of a thousand worktrees, within the budget, took two minutes. So the search also has a time limit,
// maxSearchTime per write entry and maxSearchTimeWhole for all of them, checked before every probe, read,
// listing, directory and core.hooksPath value it takes up: what it bounds is the search's time, and what
// exceeds it is the one step it is in, at most four walks, and for a candidate that is a symlink leading nowhere
// one placement of where it leads (walkTarget: at most unixPlaceNames reads). A search cut by any limit says so in the entry's
// warning, and so does one that found a file it reads but could not read it (chmod 000, a lease the agent
// holds, a FIFO in its place) or a directory of the operator's it could not open, since each would otherwise
// drop what it names or holds from the set in silence.
//
// The time limit makes a cut cheap: a few dozen planted git directories whose core.hooksPath values run
// through the chain spend it. So what the search takes up first is what the agent cannot multiply, and what
// it can comes after, in two passes over the write entries. The first (fixedPass), for every entry before
// any walk: the names at its root; then, when it is a repository, the hooks, config and config.worktree of
// each git directory at its root and the directories their core.hooksPath values and the global configs'
// name; or, when it is none, the directories the enclosing repository's and the global configs'
// core.hooksPath values name. The second (walkPass), entry by entry: the repositories beneath an entry that
// is none, each one's fixed targets probed as the walk finds it; then the git directories under each
// repository's modules/, each one's targets before its own modules/. Both passes are charged to the entry's
// limits and the whole compile's, so the first pass of a contract of thousands of entries is bounded too, and
// a later entry's warning says when that pass, not only its walk, was cut. No plant beneath any entry or in
// any modules/ can spend an entry's fixed pass's time; only the fixed passes before it can, each a bounded
// number of probes and reads, and only by as much as each of those walks costs. Among what the agent can
// multiply, it still chooses what comes first.

// denyWriteAtRoot are the names relative to a write entry's own root.
var denyWriteAtRoot = []struct{ name, what string }{
	{".claude", "harness settings"},
	{".mcp.json", "harness settings"},
	{".cursor", "harness settings"}, {".codex", "harness settings"}, {".gemini", "harness settings"},
	{".vscode", "editor settings"},
	{".bashrc", "shell startup"}, {".bash_profile", "shell startup"}, {".bash_login", "shell startup"},
	{".profile", "shell startup"}, {".zshrc", "shell startup"}, {".zshenv", "shell startup"},
	{".zprofile", "shell startup"}, {".zlogin", "shell startup"}, {".config/fish/config.fish", "shell startup"},
}

// denyWriteAtRepo are the names relative to a repository found beneath a write entry (walkRepos): a harness
// reads its project settings from the directory a session starts in, a repository's root. A shell reads its
// startup files from the home directory only, which denyWriteInHome covers wherever they resolve.
var denyWriteAtRepo = []struct{ name, what string }{
	{".claude", "harness settings"},
	{".mcp.json", "harness settings"},
	{".cursor", "harness settings"}, {".codex", "harness settings"}, {".gemini", "harness settings"},
	{".vscode", "editor settings"},
}

// denyWriteInHome are the names relative to the home directory that count when the path resolves into a
// write entry: a dotfiles repository whose files ~/.bashrc and ~/.gitconfig link to (GNU stow's layout)
// puts the user's own shell and git configuration inside the worktree under another name.
var denyWriteInHome = []struct{ name, what string }{
	{".bashrc", "shell startup"}, {".bash_profile", "shell startup"}, {".bash_login", "shell startup"},
	{".profile", "shell startup"}, {".zshrc", "shell startup"}, {".zshenv", "shell startup"},
	{".zprofile", "shell startup"}, {".zlogin", "shell startup"}, {".config/fish/config.fish", "shell startup"},
	{".gitconfig", "git config"}, {".config/git/config", "git config"},
}

// denyWriteInGitDir are the names relative to a git directory (gitDirTargets): its hooks, and the configs whose
// core.hooksPath, core.fsmonitor and core.sshCommand name programs git runs (config.worktree is read with config
// when extensions.worktreeConfig is set).
var denyWriteInGitDir = []struct{ name, what string }{
	{"hooks", "git hooks"}, {"config", "git config"}, {"config.worktree", "git config"},
}

// BuiltInDenyWriteNames is the built-in deny_write set (R20) as names, a copy: each a slash-separated path relative
// to where the set looks for it (a write entry's root, a repository's, the home directory), a git directory's names
// beneath .git, where a repository keeps it. The directories core.hooksPath values name are not among them: a git
// config names those. A reader that ranks a refused write by its path (the dashboard's severity, which reads a write
// to one as code that runs later) holds its own names to these in its tests, so a name added to the set is not left
// out there.
func BuiltInDenyWriteNames() []string {
	var out []string
	add := func(name string) {
		if !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	for _, table := range [][]struct{ name, what string }{denyWriteAtRoot, denyWriteAtRepo, denyWriteInHome} {
		for _, n := range table {
			add(n.name)
		}
	}
	for _, n := range denyWriteInGitDir {
		add(".git/" + n.name)
	}
	return out
}

// globalGitConfigs are git's per-user configuration files relative to the home directory. A core.hooksPath
// set there applies to every repository the user commits in.
var globalGitConfigs = []string{".gitconfig", ".config/git/config"}

const (
	// maxGitFile bounds the read of a .git file or a commondir file, which holds one path.
	maxGitFile = 4096
	// maxGitConfig bounds the read of a git config file; one larger is not searched for core.hooksPath.
	maxGitConfig = 256 << 10
	// maxHooksValues is how many core.hooksPath values one config file contributes: the last ones, since git
	// uses the last assignment it reads.
	maxHooksValues = 8
	// maxRepoDepth is how many levels beneath a write entry that is not itself a repository the search for
	// repositories descends, and how deep beneath a git directory's modules/ it looks for a submodule's.
	maxRepoDepth = 4
	// maxDirEntries bounds the entries read from one directory.
	maxDirEntries = 4096

	// The budget of one write entry's search (denySearch), so a write entry over a large tree (the home
	// directory) or one the agent filled costs compile a bounded amount of I/O.
	maxSearchDirs    = 4096     // directories examined, for a repository or a submodule's git directory
	maxSearchEntries = 1 << 16  // directory entries read
	maxSearchBytes   = 16 << 20 // bytes read from .git files, commondir files and git configs
	maxSearchPaths   = 16384    // candidate paths probed for the set
	// maxSearchWhole is how many write entries' budgets the compile as a whole spends: a contract of
	// thousands of write entries (E24), each over a tree the agent filled, would otherwise cost that many
	// budgets. Each entry still has its own, so one entry's plant cannot spend another's until the whole is.
	maxSearchWhole = 4
	// maxSearchTime is how long one write entry's search may take, and maxSearchTimeWhole all of them
	// together: the budgets above count operations, and the agent sets what each costs (the header). An
	// ordinary search takes milliseconds, and one that examines all 4096 directories its budget allows a few
	// hundred.
	maxSearchTime      = 2 * time.Second
	maxSearchTimeWhole = 4 * time.Second
)

// denyTarget is one member of the set: its rule, what it is, and the write entry it lies beneath.
type denyTarget struct {
	rule  FSRule
	what  string
	under writePath
}

// denyWrite compiles the built-in deny_write set (R20) into RuleTable.DenyWrite and warns once per target
// (warnDenyWrite). Every rule is Unenforced: it lies beneath a write entry by construction, which Landlock
// cannot deny beneath (SEMANTICS §2), so only a kernel decision plane (cgroup with lsm/fmod_ret, or bpflsm)
// refuses a write to one race-free. Without a plane the supervisor refuses it best effort (supervisor R15c), or,
// under fs.assurance: kernel, the run is refused (ADR 0041 D1 (a)).
//
// A declared write entry at a target's own path is the author granting it on purpose: the target leaves the
// set. One inside a target is granting part of it: the target stays, and nearest-wins lets the inner entry
// decide beneath itself. Both are returned as regrants, so E10 does not tell the author to remove them.
func (b *fsBuilder) denyWrite(writes []writePath) map[string]bool {
	k := b.k
	regrants := map[string]bool{}
	var targets []denyTarget
	var nowhere []denyNowhere
	seen, seenNowhere := map[string]bool{}, map[string]bool{}
	add := func(path, what string) {
		// Only an existing path is a candidate, and whether one exists, and where it leads, is the kernel's
		// answer (probeLanding): the path can be the agent's choice (a core.hooksPath value, a .git file's
		// gitdir), and the walk is the kernel's, never filepath.EvalSymlinks's. Everything a target costs is
		// spent here, within the search's time limit, not after it.
		res, name, followed, ok := probeLandingName(path)
		if !ok || seen[name] {
			return
		}
		if !followed {
			// A symlink leading nowhere yet (or looping) is held as the link, which keeps its name; where it leads has
			// no inode for any tier to key, and git follows the link to whatever the run makes there. Where that place
			// lies beneath a write entry, compile says so.
			if w := walkTarget(path); w.placed && !seenNowhere[w.place] {
				if under, ok := enclosingWrite(writes, w.place); ok {
					seenNowhere[w.place] = true
					nowhere = append(nowhere, denyNowhere{path: path, place: w.place, what: what, under: under})
				}
			}
		}
		under, ok := enclosingWrite(writes, res)
		if !ok {
			// Where it leads lies outside every write entry, where every write is refused already; a link to it whose
			// own name lies beneath a write entry is held there, or the agent could put a directory of its own in the
			// link's place.
			if under, ok = enclosingWrite(writes, name); !ok {
				return
			}
		}
		seen[name] = true
		for _, w := range writes {
			if isAncestorOrSelf(res, w.resolved) {
				regrants[w.declared] = true
			}
		}
		for _, w := range writes {
			if w.resolved == res && !k.askScope {
				return // the author named it in fs.write
			}
		}
		spelled := rebase(path, under)
		if name != res {
			// A link is held at its own name as the kernel's lookup lands there, the spelling the supervisor matches an
			// end with when the agent's own does not match (R15c), and the plane keys (linkRows).
			spelled = name
		}
		r := FSRule{Path: spelled, Kind: FSDenyWrite, BuiltIn: true, Unenforced: true, Resolved: res}
		if fi, err := os.Lstat(res); err == nil {
			b.meta(&r, fi, res, Pos{})
		}
		targets = append(targets, denyTarget{rule: r, what: what, under: under})
	}
	s := &denySearch{home: k.o.home, probe: add, known: map[fileID]*gitDirInfo{}, proc: procMounted()}
	for _, name := range globalGitConfigs {
		p := filepath.Join(k.o.home, name)
		data, err := readSmallErr(p, maxGitConfig, true)
		if err == nil {
			vs := lastValues(hooksPaths(data))
			s.globalHooks = append(s.globalHooks, vs...)
			for _, v := range vs {
				if otherUserHooks(v) {
					s.globalUnread = append(s.globalUnread, hooksNote(p, v)) // it applies to every entry's repositories
				}
			}
		} else if note := s.unreadable(p, maxGitConfig, err); note != "" {
			s.globalUnread = append(s.globalUnread, note) // a core.hooksPath there applies to every entry's repositories
		}
	}
	// Two passes, so that no walk the agent shapes can spend the time the fixed targets need (the header).
	entries := make([]entrySearch, len(writes))
	for i, w := range writes {
		s.fixedPass(&entries[i], w)
	}
	for i, w := range writes {
		s.walkPass(&entries[i], w)
	}
	// The home directory's names and an absolute global hooks path are at most 27 probes whatever the
	// contract, so they are made outside every entry's limits.
	for _, v := range s.globalHooks {
		if p := hooksTarget(v, "", k.o.home); p != "" {
			add(p, "git hooks (core.hooksPath)") // an absolute one applies to every repository, found or not
		}
	}
	for _, n := range denyWriteInHome {
		add(filepath.Join(k.o.home, n.name), n.what)
	}
	rules := make([]FSRule, 0, len(targets))
	byEntry := map[string][]denyTarget{}
	var order []string
	for _, t := range targets {
		rules = append(rules, t.rule)
		if _, ok := byEntry[t.under.declared]; !ok {
			order = append(order, t.under.declared)
		}
		byEntry[t.under.declared] = append(byEntry[t.under.declared], t)
	}
	k.rt.DenyWrite = rules
	// An entry whose search a limit cut, or that met a file it reads but could not read, says so in a warning of
	// its own, whether or not anything of it is in the set: with nothing in it, that warning is the set's only
	// output for the entry, and without it an agent that planted enough directories in front of a repository, or
	// made its config unreadable while the compile ran, removed both the repository's targets and every word
	// about them.
	for i, w := range writes {
		why, fix := s.undone(&entries[i])
		if why == "" {
			continue
		}
		pos, raw := b.writeEntry(w.declared)
		what := "named nothing beneath it, but"
		if len(byEntry[w.declared]) > 0 {
			what = "did not search everything beneath it:"
		}
		k.ds.warnf(pos, CodeUnenforced, "fs.write %q: the built-in deny_write search %s %s, so a git hook or config "+
			"beneath the entry may be writable by the agent without being named", raw, what, why).
			fix("%s", fix)
	}
	for _, entry := range order {
		for _, t := range byEntry[entry] {
			b.warnDenyWrite(t)
		}
	}
	for _, n := range nowhere {
		pos, raw := b.writeEntry(n.under.declared)
		k.ds.warnf(pos, CodeUnenforced, "fs.write %q reaches %s (%s), a symlink to %s, which is not there yet: the run may make "+
			"it beneath the write entry, and what it puts there runs code outside the run when next read; no tier holds a "+
			"place before something is there, so the built-in deny_write set holds the link at most", raw, n.path, n.what, n.place).
			fix("make %s before the run, so the set holds it where the link leads, or remove the link", n.place)
	}
	return regrants
}

// denyNowhere is a candidate of the set that is a symlink leading nowhere yet (R20): the link is held where it lies
// beneath a write entry, and place, where it leads, beneath the write entry under, is named in a warning of its own,
// since no tier holds it.
type denyNowhere struct {
	path, place, what string
	under             writePath
}

// warnDenyWrite is the per-target compile finding of R20 under ADR 0041 D1 (a), positioned at the write entry the
// target lies beneath, as deny_read names each entry Landlock cannot hold. Landlock cannot deny beneath that
// entry, so a target is decided in the kernel only where a decision plane decides the run (tier cgroup in an lsm
// or fmod_ret mode, tier bpflsm), and the finding holds where a run may land without one: tier landlock, and tier
// cgroup on its fanotify listener. A table held at tier bpflsm (pinned there by the contract or the machine
// config) gets none; an auto one does, whatever this build's reach, since the machine it runs on decides.
//
// By default (fs.assurance best-effort) it is a warning that the supervisor refuses a write to the target there
// best effort (supervisor R15c) and that run_start records the cell (BestEffortDenyWrite). Under fs.assurance:
// kernel such a run is refused before its child starts (enforce-landlock R5a): at a tier landlock the contract
// pins or the machine config holds (not one a landlock-only build caps auto to) every run is, so compile says so
// as an error, as it does for setuid: true there, and compile and run agree (ADR 0041 D8);
// elsewhere the machine decides whether a plane loads, and it stays a warning.
func (b *fsBuilder) warnDenyWrite(t denyTarget) {
	k := b.k
	if k.heldAt(backend.TierBPFLSM) {
		return
	}
	pos, raw := b.writeEntry(t.under.declared)
	target := t.rule.Path + resolvedNote(t.rule.Path, t.rule.Resolved) + " (" + t.what + ") as " + t.rule.RuleName()
	git := ""
	if strings.HasPrefix(t.what, "git config") {
		git = "; git's own writes to it (git config, git remote add) are refused with it"
	}
	narrow := "write the directories the agent edits rather than the repository root, or name the target in fs.write " +
		"to let the agent write it, which drops it from the set"
	if k.rt.FilesystemAssurance() != FSAssuranceKernel {
		k.ds.warnf(pos, CodeUnenforced, "fs.write %q reaches %s, which runs code outside the run when next read; "+
			"Landlock cannot deny beneath the write entry, so where no kernel decision plane decides the run (tier landlock, "+
			"tier cgroup on the fanotify listener) the seccomp supervisor refuses a write to it best effort: a path or symlink "+
			"swapped between its check and the kernel's own lookup, or a hard link made before the run, can still reach it, "+
			"and run_start lists %s in best_effort; a decision plane (tier cgroup with lsm or fmod_ret, or bpflsm) refuses "+
			"it race-free%s", raw, target, BestEffortDenyWrite, git).
			fix("%s; or set fs.assurance: kernel to refuse a run no decision plane enforces it in", narrow)
		return
	}
	if k.rt.Tier == backend.TierLandlock && !k.buildCapped {
		k.ds.errorf(pos, CodeUnenforced, "fs.write %q reaches %s, which runs code outside the run when next read; "+
			"fs.assurance: kernel needs a kernel decision plane to refuse writes to it, and tier landlock has none, so "+
			"every run of this contract is refused before the child starts%s", raw, target, git).
			fix("run at a root tier with a kernel decision plane (tier: cgroup with lsm/fmod_ret, or bpflsm), or %s, "+
				"or drop fs.assurance: kernel to run with the supervisor's best-effort refusal", narrow)
		return
	}
	k.ds.warnf(pos, CodeUnenforced, "fs.write %q reaches %s, which runs code outside the run when next read; "+
		"fs.assurance: kernel refuses a run no kernel decision plane decides (tier landlock, tier cgroup on the fanotify "+
		"listener) before the child starts%s", raw, target, git).
		fix("run where a decision plane loads (tier cgroup with lsm/fmod_ret, or bpflsm), or %s", narrow)
}

// writeEntry is the position and the text as declared of the write entry whose absolute path is p, for a
// warning about it.
func (b *fsBuilder) writeEntry(p string) (Pos, string) {
	for i := range b.rules {
		if b.rules[i].Kind == FSWrite && b.rules[i].Path == p {
			return b.rules[i].Pos, b.rules[i].Raw
		}
	}
	return b.k.cpos, p
}

// enclosingWrite returns the nearest write entry at or above res.
func enclosingWrite(writes []writePath, res string) (writePath, bool) {
	var best writePath
	found := false
	for _, w := range writes {
		if isAncestorOrSelf(w.resolved, res) && (!found || len(w.resolved) > len(best.resolved)) {
			best, found = w, true
		}
	}
	return best, found
}

// rebase spells a path beneath a write entry's resolved root with the entry's declared root, so a warning
// names it the way the author wrote the entry; a path elsewhere (a gitdir a .git file points outside the
// entry, or one already spelled from the declared root) is returned as it is.
func rebase(p string, w writePath) string {
	if w.resolved == "" {
		return p
	}
	if rel, err := filepath.Rel(w.resolved, p); err == nil && filepath.IsLocal(rel) {
		return filepath.Join(w.declared, rel)
	}
	return p
}

// hooksTarget is the directory a core.hooksPath value v names: "~/" is the home directory, as git expands it
// for a pathname value, and a relative path is taken from worktree, the directory git runs hooks in (the
// worktree's root, or the git directory of a bare repository: githooks(5)). "" when v is relative and
// worktree is unknown, and when v names another user's home ("~user/", otherUserHooks), which compile does not
// resolve.
//
// Husky 9 sets core.hooksPath to .husky/_, whose scripts only run a helper that executes the hook of the same
// name one level up: the hooks a user edits are in .husky, so that directory, which holds .husky/_, is the
// target. Earlier Husky versions set .husky itself.
func hooksTarget(v, worktree, home string) string {
	var p string
	switch {
	case v == "~":
		p = home
	case strings.HasPrefix(v, "~/"):
		p = filepath.Join(home, v[2:])
	case otherUserHooks(v):
		return ""
	case filepath.IsAbs(v):
		p = filepath.Clean(v)
	case worktree == "":
		return ""
	default:
		p = filepath.Join(worktree, v)
	}
	if filepath.Base(p) == "_" && filepath.Base(filepath.Dir(p)) == ".husky" {
		p = filepath.Dir(p)
	}
	return p
}

// otherUserHooks reports whether the core.hooksPath value v names another user's home directory ("~user" or
// "~user/..."), which git expands through the password database. Compile does not resolve it: it is reported
// as a value compile could not read (hooksNote), so the entry's deny_write is marked unenforced rather than
// quietly missing that directory, or protecting a literal "~user" directory in the worktree instead.
func otherUserHooks(v string) bool {
	return strings.HasPrefix(v, "~") && v != "~" && !strings.HasPrefix(v, "~/")
}

// hooksNote is the note for an unresolved core.hooksPath value v found in the config file at path.
func hooksNote(path, v string) string {
	return "core.hooksPath " + strconv.Quote(v) + " in " + path + " (it names another user's home directory, which compile does not resolve)"
}

// hooksPaths returns every core.hooksPath value a git config file sets. It reads the part of git's config
// syntax such an assignment uses: a [core] section header in any case (a subsection, [core "x"], is another
// section), a hookspath key in any case, and its value read as git's config parser reads one (config.c
// parse_value): a UTF-8 byte order mark at the start of the file skipped, "\r\n" read as "\n", double quotes
// removed, backslash escapes applied, a backslash before a newline continuing the value onto the next line,
// a # or ; comment outside quotes dropped, and only whitespace written outside quotes trimmed from the end, so
// an escaped "\t" is kept. Every section's values are read that way, so a line continued from another key's
// value is never taken for an assignment of its own. A value with a NUL ends at it, as git's C string does.
// [include] and [includeIf] are not followed. Where git refuses the file (an unknown escape, an unclosed
// quote) the value is still read: over-reading only adds a directory to protect. A value of pathMax bytes or
// more is dropped: git runs a hook by a path at least that long, which the kernel refuses, so no hook runs
// from it, and probing it would only cost compile the work of handling a string the agent can make 256 KiB
// long.
func hooksPaths(data []byte) []string {
	s := strings.TrimPrefix(string(data), "\xef\xbb\xbf")
	var out []string
	inCore := false
	for i := 0; i < len(s); {
		end := strings.IndexByte(s[i:], '\n')
		if end < 0 {
			end = len(s)
		} else {
			end += i
		}
		line := s[i:end]
		next := end + 1
		t := strings.TrimLeft(line, gitSpace)
		// git accepts "[core] hooksPath = x" on one line, and a header after a header ("[a][core]hooksPath=x"):
		// the last one before the key is its section.
		for strings.HasPrefix(t, "[") {
			rb := strings.IndexByte(t, ']')
			if rb < 0 {
				inCore, t = false, ""
				break
			}
			inCore = strings.EqualFold(strings.TrimSpace(t[1:rb]), "core")
			t = strings.TrimLeft(t[rb+1:], gitSpace)
		}
		key, _, ok := strings.Cut(t, "=")
		if t == "" || t[0] == '#' || t[0] == ';' || !ok {
			i = next
			continue
		}
		// The value runs from after the "=" to the first newline no backslash continues, which may be on a
		// later line: those lines are the value's, never keys of their own.
		v, after := configValue(s, end-len(t)+len(key)+1)
		if inCore && strings.EqualFold(strings.TrimRight(key, gitSpace), "hookspath") && v != "" && len(v) < pathMax {
			out = append(out, v)
		}
		i = after
	}
	return out
}

// gitSpace is the whitespace git's config parser skips (isspace in the C locale).
const gitSpace = " \t\n\v\f\r"

// configValue decodes the git config value that starts at s[i], as config.c's parse_value does, and returns
// it with the index just past the newline that ends it (len(s) at the end of the file).
func configValue(s string, i int) (string, int) {
	// next is config.c's get_next_char: "\r\n" is one "\n", and the end of the file ends the line.
	next := func() byte {
		if i >= len(s) {
			return '\n'
		}
		c := s[i]
		i++
		if c == '\r' && i < len(s) && s[i] == '\n' {
			i++
			return '\n'
		}
		return c
	}
	var b []byte
	quoted, comment := false, false
	trim := 0 // when non-zero, the length b is cut to at the end: what came before trailing unquoted whitespace
	for {
		c := next()
		if c == '\n' {
			if trim > 0 {
				b = b[:trim]
			}
			break
		}
		if comment {
			continue
		}
		if !quoted && strings.IndexByte(gitSpace, c) >= 0 {
			if trim == 0 {
				trim = len(b)
			}
			if len(b) > 0 {
				b = append(b, c)
			}
			continue
		}
		if !quoted && (c == '#' || c == ';') {
			comment = true
			continue
		}
		trim = 0
		switch c {
		case '\\':
			switch c = next(); c {
			case '\n':
				continue // a continuation: the value goes on on the next line
			case 't':
				c = '\t'
			case 'b':
				c = '\b'
			case 'n':
				c = '\n'
			}
			b = append(b, c)
		case '"':
			quoted = !quoted
		default:
			b = append(b, c)
		}
	}
	v := string(b)
	if k := strings.IndexByte(v, 0); k >= 0 {
		v = v[:k]
	}
	return v, i
}

// lastValues keeps the last maxHooksValues distinct values of vs, in order: git uses the last core.hooksPath
// assignment it reads, so a file of many assignments still contributes the one git runs hooks from.
func lastValues(vs []string) []string {
	var out []string
	seen := map[string]bool{}
	for i := len(vs) - 1; i >= 0 && len(out) < maxHooksValues; i-- {
		if !seen[vs[i]] {
			seen[vs[i]] = true
			out = append(out, vs[i])
		}
	}
	slices.Reverse(out)
	return out
}

// fileID is a file's identity, which two paths through different links share.
type fileID struct{ dev, ino uint64 }

// gitDirInfo is what the search learnt of one git directory, kept by identity for the whole compile.
type gitDirInfo struct {
	// hooks are the core.hooksPath values of its config and config.worktree (lastValues of each), and unread
	// the notes (unreadable) for those of the two it found but could not read.
	hooks, unread []string
	// readCut says a budget or the time left config or config.worktree unread, so hooks may lack what they
	// set: the next reach of the git directory reads them again, within the limits then current, which are
	// another write entry's once this one's are spent.
	readCut bool
	// targeted says its hooks, config and config.worktree (denyWriteInGitDir) were probed, all within the limits.
	targeted bool
	// walked says its submodules were taken up, and walkedIn by which write entry's search; cuts and
	// subUnread are the limits that stopped that walk and the files and directories it could not read, which
	// a write entry that reaches the git directory again inherits, unless the cut was another entry's
	// budget or time (modules).
	walked    bool
	walkedIn  *entrySearch
	cuts      cutSet
	subUnread []string
}

// cutSet is which limits cut a search short.
type cutSet uint8

const (
	cutDepth     cutSet = 1 << iota // the depth limit left directories unsearched
	cutBudget                       // the write entry's own budget ran out
	cutWhole                        // the budget all write entries share ran out
	cutTime                         // the write entry's own time ran out
	cutWholeTime                    // the time all write entries share ran out
)

// denySearch is R20's search for the set beneath the write entries. known persists across the compile, so a
// git directory is read and walked once whichever write entry, .git file or link reaches it, unless a limit
// cut that (info, modules); the budget, the time, the cuts and the unread notes are the current write
// entry's (cur, resume), and every directory examined, entry listed, byte read and path probed is charged to
// it and to the whole compile's (whole).
type denySearch struct {
	home  string
	probe func(path, what string)
	known map[fileID]*gitDirInfo
	// proc says /proc/self/fd is there, through which every probe and read goes (boundedio.go).
	proc bool
	// globalHooks are the core.hooksPath values of the global configs, and globalUnread the notes for those
	// of them that could not be read, which every write entry's warning carries.
	globalHooks, globalUnread []string

	cur                *entrySearch
	entry, whole       spend
	started            time.Time
	entryEnd, wholeEnd time.Time
	cuts               cutSet
	unread             []string
}

// spend is what a search has spent of its budget.
type spend struct {
	dirs, entries, paths int
	bytes                int64
}

// entrySearch is one write entry's search, carried from the pass over the fixed targets (fixedPass) to the
// pass over the walks (walkPass): the budget and time it has spent, the cuts of each pass, the unread notes,
// and the git directories at its root, whose submodules the second pass takes up.
type entrySearch struct {
	spend           spend
	used            time.Duration
	fixedCuts, cuts cutSet
	unread          []string
	gitDirs         []string
	gitDirInfos     []*gitDirInfo
	isRepo          bool
}

// resume goes on with e's search: its budget as it left it, and what is left of its time. The whole
// compile's go on, the time from the first entry's start.
func (s *denySearch) resume(e *entrySearch) {
	now := time.Now()
	if s.wholeEnd.IsZero() {
		s.wholeEnd = now.Add(maxSearchTimeWhole)
	}
	s.cur, s.started = e, now
	s.entry = e.spend
	s.entryEnd = now.Add(maxSearchTime - e.used)
	s.cuts = 0
	s.unread = e.unread
}

// pause keeps what the pass spent of e's budget and time, and its cuts, as the fixed pass's or the walk's.
func (s *denySearch) pause(e *entrySearch, fixed bool) {
	e.spend = s.entry
	e.used += time.Since(s.started)
	if fixed {
		e.fixedCuts |= s.cuts
	} else {
		e.cuts |= s.cuts
	}
	e.unread = s.unread
}

// fixedPass probes, for write entry w, every target whose number is fixed whatever the agent plants: the
// names at the entry's root, and the targets of the repository the entry is (the hooks, config and
// config.worktree of each git directory at its root, and the directories their core.hooksPath values and
// the global configs' name) or, when it is none, of the repository it lies in (enclosing). Every entry's
// fixed pass runs before any entry's walk (denyWrite), so a plant beneath one entry, or in a git directory's
// modules/, cannot spend the time these need, only what is left after them. They are still charged to the
// entry's budget and time and to the whole compile's, since the agent sets what each walk costs and a
// contract can hold thousands of entries (E24).
func (s *denySearch) fixedPass(e *entrySearch, w writePath) {
	s.resume(e)
	s.unread = append(s.unread, s.globalUnread...)
	for _, n := range denyWriteAtRoot {
		s.add(filepath.Join(w.declared, n.name), n.what)
	}
	// Out of time, gitDirs answers nothing and the entry is taken as no repository; enclosing and the walk
	// pass are then out of time too, and each cut is noted.
	e.gitDirs = s.gitDirs(w.resolved)
	if e.isRepo = len(e.gitDirs) > 0; e.isRepo {
		e.gitDirInfos = s.repoTargets(w.resolved, e.gitDirs)
	} else {
		s.enclosing(w.resolved)
	}
	s.pause(e, true)
}

// walkPass takes up what the agent can multiply beneath write entry w: for a repository, its submodules'
// git directories under modules/; otherwise the repositories beneath it (walkRepos), each one's fixed
// targets probed when the walk finds it, and their submodules after the walk.
func (s *denySearch) walkPass(e *entrySearch, w writePath) {
	s.resume(e)
	if s.outOfTime() {
		// The fixed passes spent the time: nothing beneath the entry is searched, and the cut is its walk's.
		s.pause(e, false)
		return
	}
	if e.isRepo {
		for i, gd := range e.gitDirs {
			s.modules(gd, e.gitDirInfos[i])
		}
		s.pause(e, false)
		return
	}
	var found []repoAt
	s.walkRepos(w.resolved, func(r repoAt) {
		r.infos = s.repoTargets(r.path, r.gitDirs)
		for _, n := range denyWriteAtRepo {
			s.add(filepath.Join(r.path, n.name), n.what)
		}
		found = append(found, r)
	})
	for _, r := range found {
		for i, gd := range r.gitDirs {
			s.modules(gd, r.infos[i])
		}
	}
	s.pause(e, false)
}

// repoTargets probes the fixed targets of the repository whose worktree is worktree and whose git
// directories are gds: each git directory's hooks, config and config.worktree and the directories its
// core.hooksPath values name, then those the global configs' values name. It returns what the search knows
// of each git directory, nil for one that is not a directory, for the submodule walk that follows.
func (s *denySearch) repoTargets(worktree string, gds []string) []*gitDirInfo {
	infos := make([]*gitDirInfo, len(gds))
	for i, gd := range gds {
		infos[i] = s.gitDirTargets(gd, worktree)
	}
	s.addHooks(s.globalHooks, worktree)
	return infos
}

// left is what the write entry may still spend of one kind of the budget: the entry's own left of max, or
// the whole compile's left of maxSearchWhole times max, whichever is less. out says the whole compile's was
// the smaller, for the cut that follows when it runs out.
func left(entry, whole, max int64) (n int64, out bool) {
	e, w := max-entry, maxSearchWhole*max-whole
	if w < e {
		return w, true
	}
	return e, false
}

// cut records that a budget stopped the search: the whole compile's when whole says so, else the entry's own.
func (s *denySearch) cut(whole bool) {
	if whole {
		s.cuts |= cutWhole
		return
	}
	s.cuts |= cutBudget
}

// outOfTime reports whether the search has spent its time, the entry's own or the whole compile's, whichever
// ends first, and records the cut. It is asked before each operation, so the search overruns its limit by
// one at most.
func (s *denySearch) outOfTime() bool {
	now := time.Now()
	if s.wholeEnd.Before(s.entryEnd) {
		if now.After(s.wholeEnd) {
			s.cuts |= cutWholeTime
			return true
		}
		return false
	}
	if now.After(s.entryEnd) {
		s.cuts |= cutTime
		return true
	}
	return false
}

// limitNote says which limits c holds cut a pass of the search, for a warning; "" when none did.
func limitNote(c cutSet) string {
	var why []string
	if c&cutDepth != 0 {
		why = append(why, "stops at "+strconv.Itoa(maxRepoDepth)+" levels, leaving directories below that unsearched")
	}
	if c&cutBudget != 0 {
		why = append(why, "ran out of its budget of "+strconv.Itoa(maxSearchDirs)+" directories, "+
			strconv.Itoa(maxSearchEntries)+" directory entries ("+strconv.Itoa(maxDirEntries)+" from one directory), "+
			strconv.Itoa(maxSearchBytes>>20)+" MiB of git files and "+strconv.Itoa(maxSearchPaths)+" candidate paths")
	}
	if c&cutWhole != 0 {
		why = append(why, "ran out of the budget all write entries share, "+strconv.Itoa(maxSearchWhole)+" times one entry's")
	}
	if c&cutTime != 0 {
		why = append(why, "ran out of its time limit, "+maxSearchTime.String())
	}
	if c&cutWholeTime != 0 {
		why = append(why, "ran out of the time limit all write entries share, "+maxSearchTimeWhole.String())
	}
	return strings.Join(why, " and ")
}

// maxUnreadNamed is how many unreadable files one warning names; the rest are counted.
const maxUnreadNamed = 4

// undone says what the search of one write entry left undone, for its warning: each pass a limit cut, the
// fixed targets' (fixedPass) named apart from the walk's, since a cut there leaves the entry's own or its
// enclosing repository's hooks unnamed, not only repositories beneath it; the files it found but could not
// read (deduplicated here, since each worktree that reaches a git directory inherits its notes); and a /proc
// it could not use. "" when it did all it set out to. fix is what the operator can do about each.
func (s *denySearch) undone(e *entrySearch) (why, fix string) {
	var whys, fixes []string
	if note := limitNote(e.fixedCuts); note != "" {
		whys = append(whys, "the search of the names at its root and of the hooks directories and configs of the repository it is or lies in "+note)
		fixes = append(fixes, "declare fewer write entries, and check the entry's root, its .git and its repository's config for links the agent planted there, then compile again")
	}
	if note := limitNote(e.cuts); note != "" {
		whys = append(whys, "the search for repositories and submodules beneath it "+note)
		fixes = append(fixes, "write the directories the agent edits rather than one above them, so the search reaches every repository beneath the entry")
	}
	var names []string
	seen := map[string]bool{}
	for _, n := range e.unread {
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	if len(names) > 0 {
		list := names
		if len(list) > maxUnreadNamed {
			list = append(slices.Clone(list[:maxUnreadNamed]), strconv.Itoa(len(names)-maxUnreadNamed)+" more")
		}
		whys = append(whys, "it could not read "+strings.Join(list, ", ")+", which can name a git directory or a core.hooksPath")
		fixes = append(fixes, "check that nothing the agent left behind changed those files (their mode, a lease or lock a process still holds, a FIFO or link in their place), then compile again")
	}
	if !s.proc {
		whys = append(whys, "/proc is not mounted, and every probe and read of the search goes through /proc/self/fd, so it resolved and read nothing")
		fixes = append(fixes, "mount /proc")
	}
	return strings.Join(whys, "; and "), strings.Join(fixes, "; ")
}

// unreadable is the note for a file the search reads that exists but could not be read, "" for one that is
// absent (a git directory has no config.worktree unless one is made) or a read a budget or the time cut
// (limitNote says those). A git config, config.worktree, .git file or commondir the agent made unreadable
// (chmod 000, a lease it holds while the compile runs, a FIFO or a link to a kernel file in its place, a
// size past the bound) would otherwise drop what it names from the set in silence. Without /proc every read
// fails, which undone says once instead.
func (s *denySearch) unreadable(path string, limit int64, err error) string {
	if err == nil || errors.Is(err, errSearchCut) || !s.proc {
		return ""
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	var why string
	switch {
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENOTDIR):
		var st unix.Stat_t
		if unix.Lstat(path, &st) != nil {
			return ""
		}
		why = "a symlink that leads nowhere"
	case errors.Is(err, errOverBound):
		why = "larger than the " + strconv.FormatInt(limit>>10, 10) + " KiB it is read to"
	case errors.Is(err, unix.EAGAIN):
		why = "a lease or a lock is held on it"
	default:
		why = err.Error()
	}
	return path + " (" + why + ")"
}

// unlisted notes a directory the search could not open, as unreadable notes a file: a directory the agent
// made unsearchable (chmod 000) hides every repository beneath it, and the agent can make it searchable again
// after the compile. Only one the compiling user owns is noted, since only its owner (the agent runs as the
// operator's uid) can change its mode back: a lost+found or a container's storage owned by another user is
// not the agent's doing, and naming it on every compile would say nothing. As root the search is refused
// nothing by mode, so this is the non-root compile's case.
func (s *denySearch) unlisted(dir string, err error) {
	if !s.proc || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ELOOP) {
		return
	}
	var st unix.Stat_t
	if unix.Lstat(dir, &st) != nil || int(st.Uid) != os.Geteuid() {
		return
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err
	}
	var partial *partialListError
	if errors.As(err, &partial) {
		s.unread = append(s.unread, dir+" (a directory it listed only in part: "+partial.err.Error()+")")
		return
	}
	s.unread = append(s.unread, dir+" (a directory it could not open: "+err.Error()+")")
}

// add probes path for the set, charged to the budget; false when a limit left it unprobed.
func (s *denySearch) add(path, what string) bool {
	if s.outOfTime() {
		return false
	}
	if n, whole := left(int64(s.entry.paths), int64(s.whole.paths), maxSearchPaths); n <= 0 {
		s.cut(whole)
		return false
	}
	s.entry.paths++
	s.whole.paths++
	s.probe(path, what)
	return true
}

// examine charges one directory examined; false when the budget or the time has none left.
func (s *denySearch) examine() bool {
	if s.outOfTime() {
		return false
	}
	if n, whole := left(int64(s.entry.dirs), int64(s.whole.dirs), maxSearchDirs); n <= 0 {
		s.cut(whole)
		return false
	}
	s.entry.dirs++
	s.whole.dirs++
	return true
}

// list lists dir through listDir, charged to the budget.
func (s *denySearch) list(dir string) []os.DirEntry {
	es, _ := s.listUpTo(dir, maxDirEntries)
	return es
}

// listUpTo lists at most max entries of dir, charged to the budget; more says entries were left unread, and
// is a cut only when max was the budget's, not the caller's.
func (s *denySearch) listUpTo(dir string, max int) (es []os.DirEntry, more bool) {
	if s.outOfTime() {
		return nil, true
	}
	n, whole := left(int64(s.entry.entries), int64(s.whole.entries), maxSearchEntries)
	if n <= 0 {
		s.cut(whole)
		return nil, true
	}
	es, more, err := listDir(dir, int(min(int64(max), n)))
	if err != nil {
		s.unlisted(dir, err)
	}
	s.entry.entries += len(es)
	s.whole.entries += len(es)
	if more && (max == maxDirEntries || n < int64(max)) {
		s.cut(whole && n < int64(max))
	}
	return es, more
}

// deeper reports whether dir, which the search does not descend into because it is at the depth limit,
// holds a directory the search would have taken up: it reads at most 64 of its entries, and a directory with
// more than that is taken to hold one, since the entries read are the file system's first, not all of them.
func (s *denySearch) deeper(dir string) bool {
	es, more := s.listUpTo(dir, 64)
	for _, e := range es {
		if e.IsDir() && e.Name() != ".git" && e.Name() != "node_modules" {
			return true
		}
	}
	return more
}

// errSearchCut is what read answers when a budget or the time, not the file, left it unread.
var errSearchCut = errors.New("the search's budget or time ran out")

// read is readSmallErr charged to the budget. When what is left of the budget is below limit, the read is
// bounded by what is left, and a file refused for its size then counts as a cut, not as the file's own.
func (s *denySearch) read(path string, limit int64, follow bool) ([]byte, error) {
	if s.outOfTime() {
		return nil, errSearchCut
	}
	n, whole := left(s.entry.bytes, s.whole.bytes, maxSearchBytes)
	if n <= 0 {
		s.cut(whole)
		return nil, errSearchCut
	}
	data, err := readSmallErr(path, min(limit, n), follow)
	if n < limit && errors.Is(err, errOverBound) {
		s.cut(whole)
		return nil, errSearchCut
	}
	s.entry.bytes += int64(len(data))
	s.whole.bytes += int64(len(data))
	return data, err
}

// repoAt is a repository found by the search: its root, the git directories gitDirs found there, and what
// the search knows of each (repoTargets), for the submodule walk that follows the walk for repositories.
type repoAt struct {
	path    string
	gitDirs []string
	infos   []*gitDirInfo
}

// walkRepos searches beneath root, a write entry that is not itself a repository, breadth first, for
// directories in which gitDirs finds a git directory, down to maxRepoDepth levels, without descending into a
// repository found, a .git directory, node_modules or a symlink, within the budget and the time, and hands
// each repository to found as it finds it, so one found early is taken up before the rest of the walk can
// spend the time.
func (s *denySearch) walkRepos(root string, found func(repoAt)) {
	type dir struct {
		path  string
		depth int
	}
	queue := []dir{{root, 0}}
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		if d.depth == maxRepoDepth {
			if s.deeper(d.path) {
				s.cuts |= cutDepth
			}
			continue
		}
		for _, e := range s.list(d.path) {
			if !e.IsDir() || e.Name() == ".git" || e.Name() == "node_modules" {
				continue
			}
			if !s.examine() {
				return
			}
			p := filepath.Join(d.path, e.Name())
			if gds := s.gitDirs(p); len(gds) > 0 {
				found(repoAt{path: p, gitDirs: gds})
				continue
			}
			queue = append(queue, dir{p, d.depth + 1})
		}
	}
}

// info is what the search knows of the git directory gd, read on first reach: nil when gd is not a directory.
// The identity is stat's, following links, so every path to one git directory finds the same info, and each
// write entry that reaches it is told which of its configs could not be read. Configs a limit left unread
// (readCut) are read again on the next reach, within the limits then current: another write entry's plant
// that spent its own time on the way to this git directory must not leave its core.hooksPath unread for the
// entry whose repository it is.
func (s *denySearch) info(gd string) *gitDirInfo {
	var st unix.Stat_t
	if unix.Stat(gd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil
	}
	id := fileID{uint64(st.Dev), st.Ino}
	in, ok := s.known[id]
	if ok && !in.readCut {
		s.unread = append(s.unread, in.unread...)
		return in
	}
	if !ok {
		in = &gitDirInfo{}
		s.known[id] = in
	}
	in.hooks, in.unread, in.readCut = nil, nil, false
	for _, name := range []string{"config", "config.worktree"} {
		p := filepath.Join(gd, name)
		data, err := s.read(p, maxGitConfig, true)
		switch {
		case err == nil:
			vs := lastValues(hooksPaths(data))
			in.hooks = append(in.hooks, vs...)
			for _, v := range vs {
				if otherUserHooks(v) {
					in.unread = append(in.unread, hooksNote(p, v))
				}
			}
		case errors.Is(err, errSearchCut):
			in.readCut = true
		default:
			if note := s.unreadable(p, maxGitConfig, err); note != "" {
				in.unread = append(in.unread, note)
			}
		}
	}
	s.unread = append(s.unread, in.unread...)
	return in
}

// gitDirTargets probes the fixed targets of the git directory gd for one worktree: its hooks, config and
// config.worktree (which a linked worktree reads when extensions.worktreeConfig is set), once per git
// directory, then the directory each of its core.hooksPath values names for worktree. worktree is the
// directory the repository's hooks run in, where a relative core.hooksPath is resolved; "" for a submodule's
// git directory found under modules/, whose worktree the search reaches separately. The same git directory
// reached from two worktrees (a linked worktree's common directory) resolves its relative values against
// each. It returns what the search knows of gd, nil when gd is not a directory or the time is out.
func (s *denySearch) gitDirTargets(gd, worktree string) *gitDirInfo {
	if s.outOfTime() {
		return nil
	}
	in := s.info(gd)
	if in == nil {
		return nil
	}
	if !in.targeted {
		// Each add runs whatever the one before it answered; the names count as probed only when all were.
		ok := true
		for _, n := range denyWriteInGitDir {
			ok = s.add(filepath.Join(gd, n.name), n.what) && ok
		}
		in.targeted = ok
	}
	s.addHooks(in.hooks, worktree)
	return in
}

// modules takes up the submodules of the git directory gd, whose info is in: first the fixed targets of each
// submodule's git directory found under modules/ (gitDirTargets), then each one's own submodules. It runs
// once per git directory, and a write entry that reaches gd again inherits the cuts and unread notes of the
// walk that took it up; except that a walk another write entry's budget or time cut is taken up again,
// within the limits of the entry that reaches it now, since those limits were not this entry's.
func (s *denySearch) modules(gd string, in *gitDirInfo) {
	if in == nil {
		return
	}
	if in.walked && (in.cuts&^cutDepth == 0 || in.walkedIn == s.cur) {
		s.cuts |= in.cuts
		s.unread = append(s.unread, in.subUnread...)
		return
	}
	in.walked, in.walkedIn = true, s.cur
	cuts, unread := s.cuts, s.unread
	s.cuts, s.unread = 0, nil
	subs := s.submodules(gd)
	infos := make([]*gitDirInfo, len(subs))
	for i, sub := range subs {
		infos[i] = s.gitDirTargets(sub, "")
	}
	for i, sub := range subs {
		s.modules(sub, infos[i])
	}
	in.cuts, in.subUnread = s.cuts, s.unread
	s.cuts, s.unread = s.cuts|cuts, append(unread, s.unread...)
}

// addHooks adds the directory each core.hooksPath value names for worktree (hooksTarget). The time is asked
// before each value, not only in add: a value can be 4 KiB, and the thousandth worktree to reach one git
// directory would otherwise still clean and join its values after the time ran out.
func (s *denySearch) addHooks(values []string, worktree string) {
	for _, v := range values {
		if s.outOfTime() {
			return
		}
		if p := hooksTarget(v, worktree, s.home); p != "" {
			s.add(p, "git hooks (core.hooksPath)")
		}
	}
}

// submodules lists the git directories of gd's submodules, which git keeps under gd/modules/<name> (a name
// can hold slashes, so down to maxRepoDepth levels); a submodule's own submodules are under its modules/ in
// turn, which modules reaches when it takes up each one.
func (s *denySearch) submodules(gd string) []string {
	var out []string
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > maxRepoDepth {
			if s.deeper(dir) {
				s.cuts |= cutDepth
			}
			return
		}
		for _, e := range s.list(dir) {
			if !e.IsDir() {
				continue
			}
			if !s.examine() {
				return
			}
			p := filepath.Join(dir, e.Name())
			if isGitDir(p) {
				out = append(out, p)
				continue
			}
			walk(p, depth+1)
		}
	}
	walk(filepath.Join(gd, "modules"), 1)
	return out
}

// enclosing is the repository a write entry that is not itself one lies in: git, run in the entry, finds it
// by walking up to the nearest directory holding a .git (or being a git directory), and runs its hooks from
// the directory its core.hooksPath names, which can lie beneath the entry (Husky's monorepo layout sets
// frontend/.husky/_ in a repository whose frontend/ is the write entry). The walk takes one lstat or two per
// ancestor; the configs it reads are charged to the budget, and only a hooks directory beneath a write entry
// joins the set, as everywhere.
func (s *denySearch) enclosing(entry string) {
	for dir := filepath.Dir(entry); ; dir = filepath.Dir(dir) {
		if s.outOfTime() {
			return
		}
		if gds := s.gitDirs(dir); len(gds) > 0 {
			for _, gd := range gds {
				if in := s.info(gd); in != nil {
					s.addHooks(in.hooks, dir)
				}
			}
			s.addHooks(s.globalHooks, dir)
			return
		}
		if dir == filepath.Dir(dir) {
			return
		}
	}
}

// gitDirs lists the git directories whose hooks and config a write entry rooted at root can reach: the
// entry's own .git directory; the gitdir a .git file names (a linked worktree or a submodule) and that
// gitdir's common directory, where a linked worktree's hooks and config live; and root itself when it is a
// git directory (a bare repository, or a .git directory named directly). The caller keeps only what lies
// beneath a write entry. Nothing once the search is out of time.
func (s *denySearch) gitDirs(root string) []string {
	if s.outOfTime() {
		return nil
	}
	var out []string
	dot := filepath.Join(root, ".git")
	fi, err := os.Lstat(dot)
	if errors.Is(err, unix.EACCES) {
		s.unlisted(root, err) // root cannot be searched, so whether it holds a .git is not known
	}
	if err == nil {
		switch {
		case fi.IsDir():
			out = append(out, dot)
		case fi.Mode().IsRegular():
			if gd, ok := s.pointer(dot, "gitdir: ", false); ok {
				out = append(out, gd)
				if cd, ok := s.pointer(filepath.Join(gd, "commondir"), "", true); ok && cd != gd {
					out = append(out, cd)
				}
			}
		}
	}
	if isGitDir(root) {
		out = append(out, root)
	}
	sort.Strings(out)
	return out
}

// pointer reads the one path a .git file ("gitdir: <path>") or a commondir file ("<path>") holds, relative
// to the file's directory when it is not absolute. The read is bounded at maxGitFile (I6): a file that is
// not regular, or is larger, is not a pointer, and one that exists but could not be read is noted
// (unreadable), since the git directory it names is then not searched. follow says whether a final symlink
// is followed; the .git file is not, since the caller's Lstat found a regular file there.
func (s *denySearch) pointer(file, prefix string, follow bool) (string, bool) {
	data, err := s.read(file, maxGitFile, follow)
	if err != nil {
		if note := s.unreadable(file, maxGitFile, err); note != "" {
			s.unread = append(s.unread, note)
		}
		return "", false
	}
	line, _, _ := strings.Cut(string(data), "\n")
	line = strings.TrimRight(line, "\r")
	if !strings.HasPrefix(line, prefix) || len(line) == len(prefix) {
		return "", false
	}
	p := strings.TrimPrefix(line, prefix)
	if !filepath.IsAbs(p) {
		p = filepath.Join(filepath.Dir(file), p)
	}
	return filepath.Clean(p), true
}

// isGitDir reports whether dir has the layout git accepts as a repository directory: a HEAD file and
// objects/ and refs/ directories.
func isGitDir(dir string) bool {
	head, err := os.Lstat(filepath.Join(dir, "HEAD"))
	if err != nil || !head.Mode().IsRegular() {
		return false
	}
	for _, d := range []string{"objects", "refs"} {
		if fi, err := os.Lstat(filepath.Join(dir, d)); err != nil || !fi.IsDir() {
			return false
		}
	}
	return true
}
