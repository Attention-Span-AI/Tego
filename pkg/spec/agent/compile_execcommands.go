// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// ExecCommands are a table's compiled exec command rules (ADR 0048 (4)): the patterns indexed by tool, the
// identities of the ruled commands' files, git's autocorrect candidates, the helper images granted, and what compile
// found about each entry. Built once by Compile and never mutated.
type ExecCommands struct {
	// Index decides an exec's facts (execmatch.Index.Decide); the supervisor and compile --test both ask it.
	Index *execmatch.Index
	// Entries are the command patterns in contract order (allow, deny, ask), each with its position and notes.
	Entries []ExecCommandEntry
	// Identities maps the (dev, ino) of a ruled command's resolved file of one link to its tool.
	Identities map[execmatch.ID]string
	// Loaders are the (dev, ino) of the host's dynamic loaders (execLoaders): a hard link to one under another name is
	// a loader to the supervisor, which reads the program it runs (ADR 0048 (3)).
	Loaders map[execmatch.ID]bool
	// Candidates is git's autocorrect candidate set: its exec-path listing and the row's built-ins.
	Candidates *execmatch.Candidates
	// Helpers are the helper images granted for a row with a helper closure (git's exec-path git and its dashed
	// helpers).
	Helpers []string
	// Unconstrained maps a tool an implicit grant names to the grant ("command", "mcp:<name>", "interpreter:<x>",
	// "run command"): it keeps any arguments, whatever allow entries say.
	Unconstrained map[string]string
}

// ExecCommandEntry is one compiled command pattern.
type ExecCommandEntry struct {
	Pattern *execmatch.Pattern
	Pos     Pos
	// Notes print under the entry's line: near-misses it also matches, the closure an allow entry admits and the
	// images it grants, the row's coverage note and what the row does not read.
	Notes []string
}

// HasRules reports whether any command rule can decide an exec: a deny or ask entry, or a constrained tool.
func (e *ExecCommands) HasRules() bool {
	if e == nil || e.Index.Empty() {
		return false
	}
	for _, en := range e.Entries {
		if en.Pattern.List != execmatch.ListAllow {
			return true
		}
	}
	return len(e.Index.ConstrainedTools()) > 0
}

// toolOf is the tool a basename is: its row's tool, or the name itself.
func toolOf(name string) string {
	if r := rows.Builtin().Lookup(name); r != nil {
		return r.Tool
	}
	return name
}

// execCommands compiles RuleTable.ExecCommands (ADR 0048 (1), (2), (9)): the patterns of the three lists indexed by
// tool, the implicit grants that keep a tool unconstrained, the identities of the ruled commands' files, git's
// candidate set from its exec-path, each entry's notes, the run's own command and MCP commands checked against the
// rules, and the warnings an author can act on. Runs after exec(), which granted the images.
func (k *compiler) execCommands() {
	c := k.c
	if c.Exec == nil {
		return
	}
	ec := &ExecCommands{Helpers: k.execHelpers}
	var patterns []*execmatch.Pattern
	for _, l := range execLists {
		for i, e := range l.of(c.Exec) {
			p, err := execmatch.Parse(e, l.list, rows.Builtin())
			if err != nil {
				continue // validateExec reported it
			}
			patterns = append(patterns, p)
			if l.list == execmatch.ListAllow && p.Bare {
				continue
			}
			ec.Entries = append(ec.Entries, ExecCommandEntry{Pattern: p, Pos: k.pos(l.key + "." + strconv.Itoa(i))})
		}
	}
	if len(ec.Entries) == 0 {
		return
	}
	ec.Unconstrained = implicitGrants(k.rt, c)
	unconstrained := map[string]bool{}
	for t := range ec.Unconstrained {
		unconstrained[t] = true
	}
	ec.Identities, ec.Candidates = k.execIdentities(patterns)
	ec.Loaders = execLoaders(loaderDirs())
	ec.Index = execmatch.NewIndex(rows.Builtin(), patterns, execmatch.IndexOptions{
		Candidates: ec.Candidates, Identities: ec.Identities, Loaders: ec.Loaders, Unconstrained: unconstrained,
	})
	k.rt.ExecCommands = ec
	k.execCommandNotes(ec)
	k.execOwnCommands(ec)
	k.execCommandWarnings(ec)
}

// implicitGrants is ExecCommands.Unconstrained for rt compiled from c: implicit grants keep "any arguments" (ADR 0048
// (1)), so each maps the tool it names to the grant: the command, each MCP server's command, a #! interpreter of
// either, and the command tego run was given.
func implicitGrants(rt *RuleTable, c *Contract) map[string]string {
	out := map[string]string{}
	for _, r := range rt.Exec {
		for _, src := range strings.Split(r.Source, ",") {
			if src == ExecSourceCommand || strings.HasPrefix(src, ExecSourceMCP+":") || strings.HasPrefix(src, ExecSourceInterpreter+":") {
				if _, ok := out[toolOf(r.Basename)]; !ok {
					out[toolOf(r.Basename)] = src
				}
			}
		}
	}
	if len(c.Command) > 0 {
		out[toolOf(filepath.Base(c.Command[0]))] = ExecSourceCommand
	}
	for _, s := range c.MCP {
		if len(s.Command) > 0 {
			if _, ok := out[toolOf(filepath.Base(s.Command[0]))]; !ok {
				out[toolOf(filepath.Base(s.Command[0]))] = ExecSourceMCP + ":" + s.Name
			}
		}
	}
	if rt.RunCommandGrant != "" {
		out[toolOf(filepath.Base(rt.RunCommandGrant))] = "run command"
	}
	return out
}

// execIdentities resolves every ruled command on the run's PATH (or its path, in an allow entry) and keeps the
// (dev, ino) of each resolved file of one link whose row is no multicall dispatcher (ADR 0048 (2), interpretation 2),
// with git's exec-path git; and builds git's candidate set from the exec-path's git-* executables and the row's
// built-ins. Compile lists a directory and runs nothing.
func (k *compiler) execIdentities(patterns []*execmatch.Pattern) (map[execmatch.ID]string, *execmatch.Candidates) {
	ids := map[execmatch.ID]string{}
	var cand *execmatch.Candidates
	var dirs []string
	if k.rt.PATH != "" {
		dirs = strings.Split(k.rt.PATH, ":")
	}
	b := &execBuilder{k: k}
	addID := func(path, tool string, row *execmatch.Row) {
		res := resolvePath(path)
		if res == "" {
			return
		}
		var st syscall.Stat_t
		if err := syscall.Stat(res, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
			return
		}
		if st.Nlink != 1 || row != nil && row.Multicall {
			return
		}
		ids[execmatch.ID{Dev: uint64(st.Dev), Ino: st.Ino}] = tool
	}
	seen := map[string]bool{}
	for _, p := range patterns {
		key := p.Command
		if seen[key] {
			continue
		}
		seen[key] = true
		path := ""
		if strings.Contains(p.Command, "/") {
			path = k.abs(p.Command)
		} else if found, ok := b.searchPath(p.Command, dirs); ok {
			path = found
		}
		if path == "" {
			continue
		}
		addID(path, p.Tool, p.Row)
		if p.Row != nil && len(p.Row.HelperDirs) > 0 {
			if dir := helperDir(p.Row, path); dir != "" {
				addID(filepath.Join(dir, p.Row.Tool), p.Row.Tool, p.Row)
				if p.Row.Autocorrect && cand == nil {
					cand = execmatch.NewCandidates(append(listDashed(dir, p.Row.Tool), p.Row.Builtins...), p.Row.Common)
				}
			}
		}
	}
	return ids, cand
}

// loaderDirs are the directories a distribution installs its dynamic loaders in: the library directories, and their
// multiarch subdirectories (/usr/lib/x86_64-linux-gnu).
func loaderDirs() []string {
	dirs := []string{"/lib", "/lib64", "/lib32", "/libx32", "/usr/lib", "/usr/lib64", "/usr/lib32", "/usr/libx32"}
	for _, g := range []string{"/lib/*-linux-*", "/usr/lib/*-linux-*"} {
		m, _ := filepath.Glob(g)
		dirs = append(dirs, m...)
	}
	return dirs
}

// execLoaders keeps the (dev, ino) of every regular file a loader's basename (execmatch.LoaderName) names in dirs,
// following links (ADR 0048 (3)). The supervisor reads an exec as a loader's by the names it is
// run under and by these identities, which a hard link under another name keeps; a copy is a file of its own (R2).
// Every link of a loader is the loader, so a file of several links counts. Compile lists directories and runs nothing.
func execLoaders(dirs []string) map[execmatch.ID]bool {
	out := map[execmatch.ID]bool{}
	for _, dir := range dirs {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if !execmatch.LoaderName(e.Name()) {
				continue
			}
			var st syscall.Stat_t
			if err := syscall.Stat(filepath.Join(dir, e.Name()), &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
				continue
			}
			out[execmatch.ID{Dev: uint64(st.Dev), Ino: st.Ino}] = true
		}
	}
	return out
}

// helperDir is a row's helper directory for a command resolved at path: <prefix>/lib/<tool>-core (Debian, Ubuntu) or
// <prefix>/libexec/<tool>-core (RHEL, a source build) beside the binary's bin directory, the directory the resolved
// binary names; "" when neither holds the tool. A row's fixed locations are never taken for another install's
// binary: they would grant some other git's files.
func helperDir(row *execmatch.Row, path string) string {
	res := resolvePath(path)
	if res == "" {
		res = path
	}
	prefix := filepath.Dir(filepath.Dir(res))
	cands := []string{filepath.Join(prefix, "lib", row.Tool+"-core"), filepath.Join(prefix, "libexec", row.Tool+"-core")}
	for _, d := range cands {
		if fi, err := os.Stat(filepath.Join(d, row.Tool)); err == nil && fi.Mode().IsRegular() {
			return d
		}
	}
	return ""
}

// listDashed lists the <tool>-<name> executables of a directory as names.
func listDashed(dir, tool string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		name, ok := strings.CutPrefix(e.Name(), tool+"-")
		if !ok || name == "" {
			continue
		}
		fi, err := os.Stat(filepath.Join(dir, e.Name()))
		if err != nil || !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
			continue
		}
		out = append(out, name)
	}
	return out
}

// helperImages grants the helper images of every row with a helper closure that an allow entry names, bare or
// constrained (ADR 0048 (2), "the image floor follows"): the tool's own binary in its helper directory, which is
// another inode than the one on PATH, and the dashed helpers its closure runs that are files of their own. A bare
// entry admits every closure; constrained entries the union of theirs. Only where images are restricted.
func (b *execBuilder) helperImages() {
	k := b.k
	if k.c.Exec == nil || k.c.Exec.DenyList() || k.c.Exec.Allow == nil {
		return
	}
	type want struct {
		row     *execmatch.Row
		path    string
		all     bool
		closure map[string]bool
		pos     Pos
	}
	byTool := map[string]*want{}
	var order []string
	var dirs []string
	if k.rt.PATH != "" {
		dirs = strings.Split(k.rt.PATH, ":")
	}
	for i, e := range k.c.Exec.Allow {
		p, err := execmatch.Parse(e, execmatch.ListAllow, rows.Builtin())
		if err != nil || p.Row == nil || len(p.Row.Closure) == 0 {
			continue
		}
		w := byTool[p.Tool]
		if w == nil {
			path := ""
			if strings.Contains(p.Command, "/") {
				path = k.abs(p.Command)
			} else if found, ok := b.searchPath(p.Command, dirs); ok {
				path = found
			}
			if path == "" {
				continue
			}
			w = &want{row: p.Row, path: path, closure: map[string]bool{}, pos: k.pos("exec.allow." + strconv.Itoa(i))}
			byTool[p.Tool] = w
			order = append(order, p.Tool)
		}
		if p.Bare {
			w.all = true
			continue
		}
		if len(p.Path) > 0 {
			for h := range execmatch.Closure(p.Row, p.Path[0]) {
				w.closure[h] = true
			}
		}
	}
	for _, tool := range order {
		w := byTool[tool]
		dir := helperDir(w.row, w.path)
		if dir == "" {
			continue
		}
		helpers := []string{filepath.Join(dir, w.row.Tool)}
		set := w.closure
		if w.all {
			set = map[string]bool{}
			for sub := range w.row.Closure {
				set[sub] = true
				for h := range execmatch.Closure(w.row, sub) {
					set[h] = true
				}
			}
		}
		var names []string
		for h := range set {
			first, _, _ := strings.Cut(h, " ")
			names = append(names, first)
		}
		sort.Strings(names)
		for _, n := range names {
			p := filepath.Join(dir, w.row.Tool+"-"+n)
			fi, err := os.Lstat(p)
			if err != nil || !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
				continue // a link to the tool is the tool's own image, granted above
			}
			if !strings.Contains(strings.Join(helpers, "\x00"), p) {
				helpers = append(helpers, p)
			}
		}
		for _, h := range helpers {
			b.add(h, ExecSourceHelper+":"+w.row.Tool, w.pos, false)
			k.execHelpers = append(k.execHelpers, h)
		}
	}
}

// execCommandNotes fills each entry's notes (ADR 0048 (9)): near-misses, the closure an allow entry admits and the
// helper images granted, the row's coverage note, what the row does not read, and a deny command matched by name
// only.
func (k *compiler) execCommandNotes(ec *ExecCommands) {
	var dirs []string
	if k.rt.PATH != "" {
		dirs = strings.Split(k.rt.PATH, ":")
	}
	b := &execBuilder{k: k}
	for i := range ec.Entries {
		en := &ec.Entries[i]
		p := en.Pattern
		if kind, toks := p.NearMisses(ec.Candidates, 5); len(toks) > 0 {
			verb := "refuses"
			if p.List == execmatch.ListAllow {
				verb = "admits"
			}
			en.Notes = append(en.Notes, "also "+verb+" ("+kind+"): "+strings.Join(toks, ", "))
		}
		if p.Row == nil && p.List != execmatch.ListAllow {
			en.Notes = append(en.Notes, "generic reading: it over-matches (a letter inside another option's cluster, an abbreviation)")
		}
		if p.List == execmatch.ListAllow && p.Row != nil && len(p.Path) > 0 && ec.Index.Constrained(p.Tool) {
			if cl := execmatch.Closure(p.Row, p.Path[0]); len(cl) > 0 {
				var names []string
				for h := range cl {
					names = append(names, h)
				}
				sort.Strings(names)
				en.Notes = append(en.Notes, "also admits (helpers): "+strings.Join(names, ", "))
			}
			if len(ec.Helpers) > 0 {
				en.Notes = append(en.Notes, "grants: "+strings.Join(ec.Helpers, ", "))
			}
		}
		if note := p.Coverage(rows.Builtin()); note != "" {
			en.Notes = append(en.Notes, "not covered: "+note)
		}
		if p.Row != nil && p.Row.Residual != "" {
			en.Notes = append(en.Notes, "not read: "+p.Row.Residual)
		}
		if p.List != execmatch.ListAllow && !strings.Contains(p.Command, "/") {
			if _, ok := b.searchPath(p.Command, dirs); !ok {
				en.Notes = append(en.Notes, p.Command+" is not on the run's PATH: matched by name only")
			}
		}
	}
}

// execOwnCommands checks the rules against the run's own commands (ADR 0048 (1)): a deny or ask entry that matches
// the contract's command is an error, since the run could not start; one that matches an MCP server's command warns,
// naming the server that cannot start.
func (k *compiler) execOwnCommands(ec *ExecCommands) {
	image := func(cmd string) string {
		for _, r := range k.rt.Exec {
			if r.Raw == cmd || r.Path == cmd || filepath.Base(r.Path) == filepath.Base(cmd) {
				if res := resolvePath(r.Path); res != "" {
					return filepath.Base(res)
				}
				return filepath.Base(r.Path)
			}
		}
		return filepath.Base(cmd)
	}
	check := func(argv []string) (execmatch.Result, bool) {
		if len(argv) == 0 || argv[0] == "" {
			return execmatch.Result{}, false
		}
		f := execmatch.Facts{Requested: filepath.Base(argv[0]), Image: image(argv[0]), Argv0: argv[0], Argv: argv, ArgvComplete: true}
		r := ec.Index.Decide(&f)
		return r, r.Outcome == execmatch.OutcomeRefused && !r.Unlisted
	}
	if r, refused := check(k.c.Command); refused {
		k.ds.errorf(k.pos("command"), CodeExecRule, "%s refuses the run's own command %q: the run could not start", r.Rule(), strings.Join(k.c.Command, " ")).
			fix("drop or narrow the entry, or change command:")
	}
	for i, s := range k.c.MCP {
		if len(s.Command) == 0 {
			continue // an HTTP server (R16a): nothing of the run launches it
		}
		if r, refused := check(s.Command); refused {
			k.ds.warnf(k.pos("mcp."+strconv.Itoa(i)+".command"), CodeExecRule, "%s refuses the command of mcp %q (%s): that server cannot start", r.Rule(), s.Name, strings.Join(s.Command, " ")).
				fix("drop or narrow the entry, or remove the server")
		}
	}
}

// execCommandWarnings are the findings an author can act on (ADR 0048 (9)): deny-list mode (every deny-list; beside
// fs.write the copy on disk too), a constrained tool an implicit grant shadows, an allow entry naming options, a
// constrained entry beside a bare one, the reserved ask list, tier landlock's refusal of every image its user cannot
// read (R13), and the best-effort cell per tier.
func (k *compiler) execCommandWarnings(ec *ExecCommands) {
	c := k.c
	if c.Exec.DenyList() {
		// A deny-list leaves images unrestricted at every tier (SEMANTICS §1): no memfd arm, no fileless refusal, no
		// exec-map decision (ADR 0027 decides only an exec-restricted run). A copy of a denied program therefore runs
		// from a memfd or from a file the agent deleted, and its file can be mapped into a process with no exec, with
		// or without a write entry; the rules refuse commands, not the programs' code.
		if c.FS != nil && len(c.FS.Write) > 0 {
			k.ds.warnf(k.pos("exec"), CodeExecRuleCoverage, "exec: is a deny-list beside fs.write: the agent can write files and run them; a copy of git under another name is not git to these rules, and neither is a copy run from a memfd or from a file it deleted").
				fix("restrict images with exec.allow (and a plane tier for native code under write entries, ADR 0027)")
		} else {
			// The entry the warning names is the first deny entry's tool, else the first ask entry's (an ask-only
			// section is a deny-list too): what it says of the copy is what that entry decides.
			tool, entry := "a denied program", "a deny entry refuses"
			for _, list := range [...]execmatch.List{execmatch.ListDeny, execmatch.ListAsk} {
				i := slices.IndexFunc(ec.Entries, func(en ExecCommandEntry) bool { return en.Pattern.List == list })
				if i < 0 {
					continue
				}
				tool = ec.Entries[i].Pattern.Tool
				if list == execmatch.ListAsk {
					entry = "an ask entry decides"
				}
				break
			}
			fix := "restrict images with exec.allow, which seals or refuses executable memfds and refuses images with no name unless exec.anonymous is set (and at tiers cgroup and bpflsm refuses executable mappings of written files, ADR 0027)"
			if c.ExecAnonymous() {
				fix = "restrict images with exec.allow and drop exec.anonymous: that pair seals or refuses executable memfds and refuses images with no name (and at tiers cgroup and bpflsm refuses executable mappings of written files, ADR 0027)"
			}
			k.ds.warnf(k.pos("exec"), CodeExecRuleCoverage, "exec: is a deny-list, so images are unrestricted: a copy of %s run from a memfd or from a file it deleted is not %s to these rules, and an agent that maps a program's file into its own process runs that code with no exec; %s a command by its name, argv[0] and identity, not the program's code", tool, tool, entry).
				fix("%s", fix)
		}
	}
	lifted := map[string]bool{}
	for _, e := range c.Exec.Allow {
		if !execmatch.IsPattern(e) && !strings.Contains(e, "/") {
			lifted[toolOf(execmatch.Word(e))] = true
		}
	}
	shadowed := map[string]bool{}
	for _, en := range ec.Entries {
		p := en.Pattern
		if p.List != execmatch.ListAllow {
			continue
		}
		if grant, ok := ec.Unconstrained[p.Tool]; ok && !shadowed[p.Tool] {
			shadowed[p.Tool] = true
			k.ds.warnf(en.Pos, CodeExecRuleCoverage, "exec.allow %q constrains %s, which %s grants implicitly: it keeps any arguments, and this entry constrains nothing", p.Entry, p.Tool, grant).
				fix("drop the entry, or deny the subcommands %s must not run", p.Tool)
		}
		if lifted[p.Tool] {
			k.ds.warnf(en.Pos, CodeRedundantRule, "exec.allow %q is redundant: the bare entry %s admits any %s invocation", p.Entry, p.Tool, p.Tool).
				fix("drop the bare entry to constrain %s, or drop this one", p.Tool)
		}
		if len(p.Opts) > 0 {
			k.ds.warnf(en.Pos, CodeExecRuleCoverage, "exec.allow %q names options: they are required, not a whitelist (%s)", p.Entry, p.Reading()).
				fix("to forbid an option, deny it: exec.deny: [%s]", p.Tool+" "+strings.Join(p.Path, " ")+" <option>")
		}
	}
	if len(c.Exec.Ask) > 0 {
		k.ds.warnf(k.pos("exec.ask"), CodeUnenforced, "exec.ask is reserved: every match is refused at every tier (completion_unsupported), until ADR 0044 gives a list floor a completion").
			fix("move the entries to exec.deny to say what happens, or to exec.allow to admit them")
	}
	if !ec.HasRules() {
		return
	}
	if slices.Contains(k.rt.Reach, backend.TierLandlock) {
		// Every image's #! line is read in a run with command rules (ADR 0048 (3)), and an unprivileged tier-1
		// supervisor reads as the agent's user.
		k.ds.warnf(k.pos("exec"), CodeExecRuleCoverage, "command rules read every image's #! line: at tier landlock, run unprivileged, the supervisor reads as the agent's user, so every exec of an image that user cannot read (an execute-only file, such as RHEL's sudo, mode 4111) is refused image-unreadable with EACCES, even an image no rule names (ADR 0048 R13); a supervisor running as root (sudo tego run, tiers cgroup and bpflsm) reads every image on a local file system, but an NFS export with root_squash serves it as the anonymous user and a FUSE mount without allow_other or allow_root refuses it").
			fix("make such images readable by the agent's user, or run at a root tier").only(backend.TierLandlock)
	}
	why := map[backend.Tier]string{
		backend.TierLandlock: "argv is copied: the supervisor decides on its copy, and the kernel copies argv again after an allow",
		backend.TierCgroup: "argv is copied unless the decision plane pins the run's execs (where doctor's exec pin " +
			"cell, plane.exec_pin, passed in the plane's mode); on the fanotify fallback an allow is a copied fact",
		backend.TierBPFLSM: "argv is copied unless the plane pins the run's execs (where doctor's exec pin cell, " +
			"plane.exec_pin, passed in the plane's mode)",
	}
	for _, t := range k.rt.Reach {
		w, ok := why[t]
		if !ok {
			continue
		}
		k.ds.warnf(k.pos("exec"), CodeUnenforced, "best effort (%s): %s; a refusal is exact, an allow is recorded in run_start best_effort and never counted as enforced (ADR 0048 (6))", BestEffortExecRules, w).
			fix("bound effects with fs and net rules: command rules are launch rules").only(t)
	}
}
