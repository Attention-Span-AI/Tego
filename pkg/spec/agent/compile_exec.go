// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// Exec rule sources. MCP, interpreter and helper sources carry a name after a colon: mcp:<server>,
// interpreter:<script>, helper:<tool> (a helper image helperImages grants for the tool's exec.allow entries).
const (
	ExecSourceCommand     = "command"
	ExecSourceAllow       = "exec.allow"
	ExecSourceMCP         = "mcp"
	ExecSourceInterpreter = "interpreter"
	ExecSourceHelper      = "helper"
)

// exec compiles the exec rules (R8, SEMANTICS §4): Command[0] and every
// mcp[].command[0] are implicit entries; each entry resolves as a path or a
// basename on the run's effective PATH; every resolved binary is opened for
// its PT_INTERP loader; a script's #! interpreter is granted implicitly for
// the command and MCP servers and checked against the list for exec.allow.
func (k *compiler) exec() {
	b := &execBuilder{k: k, byPath: map[string]int{}}
	b.add(k.c.Command[0], ExecSourceCommand, k.pos("command.0"), true)
	for i, s := range k.c.MCP {
		if len(s.Command) == 0 {
			continue
		}
		b.add(s.Command[0], ExecSourceMCP+":"+s.Name, k.pos("mcp."+strconv.Itoa(i)+".command.0"), true)
	}
	if k.c.Exec != nil {
		for i, e := range k.c.Exec.Allow {
			pos := k.pos("exec.allow." + strconv.Itoa(i))
			if execmatch.IsPattern(e) {
				b.addPattern(e, pos)
				continue
			}
			b.add(execmatch.Word(e), ExecSourceAllow, pos, false)
		}
	}
	// Git's own helper images, which git re-executes from another inode than the one on PATH (ADR 0048 (2)).
	b.helperImages()
	// After every entry the contract declares, so a bare run command one of them names by basename runs that
	// entry's binary, as the launcher resolves it, and adds nothing (R8: before exec.allow was added, an
	// exec.allow-pinned name was granted again from PATH, and the launcher ran the PATH binary).
	b.addRunCommand()
	if k.c.Exec != nil {
		b.checkInterpreters()
	}
	k.rt.Exec = b.rules
	// Both checks read k.rt.FS, which fs() compiled before this stage ran (Compile's order).
	b.checkLoaders()
	b.checkTopology()
}

// checkLoaders warns about every declared ELF whose PT_INTERP loader lies at or below an fs.write,
// fs.ask or fs.deny_read entry, enforced or not. The Landlock builder refuses to grant such a loader
// and fails the run naming it (enforce-landlock R5, E29): the path comes from the binary's content,
// so a loader under a write entry is a grant the agent can re-point, and one under a deny_read entry
// would read what the entry denies. Tier 2 inherits that Prepare. Evaluate reports the deny_read case
// as a read-denied exec, but a write or ask entry is no read refusal and every other row of a
// `compile --test` table still passes, for a contract whose landlock and cgroup runs exit 125 before
// the agent starts. Containment is asked of resolved paths on both sides, as Prepare asks it.
func (b *execBuilder) checkLoaders() {
	k := b.k
	for _, r := range b.rules {
		if r.IsDir || r.Interp == "" {
			continue
		}
		ld := k.resolve(r.Interp)
		for _, f := range k.rt.FS {
			if f.Kind != FSWrite && f.Kind != FSAsk && f.Kind != FSDenyRead {
				continue
			}
			if !Covers(f.Governed(), ld) && !Covers(f.Path, filepath.Clean(r.Interp)) {
				continue
			}
			k.ds.warnf(r.Pos, CodeLoaderRefused, "%s %s names loader %s, which lies at or below fs.%s %s: the landlock and cgroup tiers refuse to grant it and the run exits 125",
				r.Source, r.Path, r.Interp, f.Kind, rawOr(f.Raw, f.Path)).
				fix("move the loader, or the binary that names it, outside every fs.write, fs.ask and fs.deny_read entry")
			break
		}
	}
}

// topologyTools are the binaries that build a mount namespace for what they run: bubblewrap, rootless
// podman and buildah, the OCI runtimes they call, and unshare -m. A Landlock domain refuses mount(2),
// umount, move_mount and pivot_root to every sandboxed thread (SEMANTICS §10; docs/GAPS.md A9), and
// both P0 tiers install one, so these fail inside a run however the contract is written.
var topologyTools = map[string]bool{"bwrap": true, "podman": true, "buildah": true, "unshare": true, "runc": true, "crun": true}

// checkTopology warns when an exec rule names one of topologyTools (ARCHITECTURE §4.1 (6): "compile
// warns when exec.allow names podman, buildah or bwrap"; the command and mcp servers are asked the same
// question, since they run under the same domain). The run refuses the mount and records it as gap
// what=enforce why=landlock-topology; this tells the author before the run does.
func (b *execBuilder) checkTopology() {
	for _, r := range b.rules {
		if r.IsDir || !topologyTools[r.Basename] {
			continue
		}
		b.k.ds.warnf(r.Pos, CodeLandlockTopology, "%s %s sets up a mount namespace, which a Landlock domain refuses (mount, umount, move_mount, pivot_root): it fails in the landlock and cgroup tiers and the run records gap why=landlock-topology",
			r.Source, r.Path).
			fix("run the sandbox outside the agent's run; containers: rootless (root tiers) is not supported yet")
	}
}

// CommandLineFile is the Pos.File of the exec rule a run command is granted by (WithRunCommand): it was
// written on tego run's command line, not in the contract.
const CommandLineFile = "<command line>"

// addRunCommand grants the command `tego run` was given on its command line (WithRunCommand) as the run's
// own command: the launching user chose it, so it is admitted for that run as the contract's command is. The
// file granted is the one the launcher will exec (internal/runtime resolveCommand): a bare name an entry the
// contract declares already names by basename runs that entry's binary and adds nothing, so it must run after
// every declared entry; otherwise a bare name is searched on the run's PATH and a path resolves against the
// run's cwd. The grant is that file's absolute path, never a bare name matched by basename: tier 3 admits a
// ByName rule for any file of that name, one the agent writes included, and the launching user chose one
// file (R8). Its loader and a script's #! interpreter (and env's argument) are granted as the
// contract's own command's are. The grant is RuleTable.RunCommandGrant, which run_start records. A name found
// nowhere adds nothing, silently: its execve fails with ENOENT and the run exits 127.
func (b *execBuilder) addRunCommand() {
	k := b.k
	raw := k.o.runCommand
	if raw == "" {
		return
	}
	var p string
	if strings.Contains(raw, "/") {
		p = k.abs(raw)
		if _, err := os.Stat(p); err != nil {
			return
		}
	} else {
		for _, r := range b.rules {
			if !r.IsDir && r.Basename == raw {
				return
			}
		}
		var dirs []string
		if k.rt.PATH != "" {
			dirs = strings.Split(k.rt.PATH, ":")
		}
		found, ok := b.searchPath(raw, dirs)
		if !ok {
			return
		}
		p = k.abs(found)
	}
	if _, dup := b.byPath[p]; !dup {
		k.rt.RunCommandGrant = p
	}
	b.add(p, ExecSourceCommand, Pos{File: CommandLineFile}, true)
}

// ErrHarnessHookGrant is a harness hook the runtime cannot grant exactly (WithHarnessHook): its binary is no ELF file
// it can resolve and read, it has a set-id bit or more than one link (a hard link's other names, which the grant admits
// too, cannot be listed), its loader is or leads through /proc, or a grant of it would admit more than the hook's argv
// because a bare exec.allow entry or an implicit grant (the command, an MCP server, the run command) keeps
// the binary's name unconstrained.
var ErrHarnessHookGrant = errors.New("agent: the harness hook cannot be granted exactly")

// WithHarnessHook is the harness hook's exec grant, the runtime's own (ADR 0064, agent-contract.md R27): a copy of rt
// whose exec rules admit argv[0], the absolute path of the tego binary, with argv and no other vector. Like
// addRunCommand it grants a file the launching user chose, but at run time, since the hook's argv holds the run's
// reason path. It adds two rules. An image rule for the binary (ExecRule.Runtime HarnessHookGrant, rule
// exec.harness-hook[<path>], with its PT_INTERP loader as any binary's), unless an exec rule of rt already names the
// file. And a runtime command rule (execmatch.ExactPattern) on the binary's tool, keyed by its name and by its
// identity, that admits exactly argv, so the tool is constrained to it: every other vector is refused unlisted under
// the same rule, and the decision reads the whole vector, which a plane tier's exec pin then holds (ADR 0048 (3)).
// The caller decides whether the grant may be made at all (the binary must lie under no write or ask entry); rt is
// never mutated (I4).
func (rt *RuleTable) WithHarnessHook(argv []string) (*RuleTable, error) {
	if len(argv) == 0 || !filepath.IsAbs(argv[0]) {
		return nil, fmt.Errorf("%w: the hook's argv %q does not start with an absolute path", ErrHarnessHookGrant, argv)
	}
	exe := argv[0]
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrHarnessHookGrant, exe, err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(resolved, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, fmt.Errorf("%w: %s is not a regular file (%v)", ErrHarnessHookGrant, resolved, err)
	}
	if st.Mode&(syscall.S_ISUID|syscall.S_ISGID) != 0 {
		// The run's no_new_privs already keeps an exec from gaining the bit's credentials; a grant never rests on it.
		return nil, fmt.Errorf("%w: %s has a set-id bit (mode %#o)", ErrHarnessHookGrant, resolved, st.Mode&0o7777)
	}
	if st.Nlink != 1 {
		// The grant admits the file's inode by every name, and a hard link's other names cannot be listed, so none can
		// be shown to lie outside the run's write entries.
		return nil, fmt.Errorf("%w: %s has %d links, whose other names cannot be listed", ErrHarnessHookGrant, resolved, st.Nlink)
	}
	interp, err := ReadInterp(resolved)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrHarnessHookGrant, resolved, err)
	}
	if via, proc := config.ThroughProc(interp); interp != "" && proc {
		return nil, fmt.Errorf("%w: %s names loader %s, which leads through %s", ErrHarnessHookGrant, resolved, interp, via)
	}
	out := *rt
	tool := toolOf(filepath.Base(exe))
	if !slices.ContainsFunc(rt.Exec, func(r ExecRule) bool { return !r.IsDir && (r.Path == exe || r.Resolved == resolved) }) {
		out.Exec = append(slices.Clone(rt.Exec), ExecRule{
			Path: exe, Resolved: resolved, Basename: filepath.Base(exe), Interp: interp, Verdict: VerdictAllow,
			Source: HarnessHookGrant, Runtime: HarnessHookGrant,
		})
	}
	ec := &ExecCommands{}
	var patterns []*execmatch.Pattern
	if old := rt.ExecCommands; old != nil {
		*ec = *old
		ec.Identities, ec.Unconstrained = maps.Clone(old.Identities), maps.Clone(old.Unconstrained)
		patterns = slices.Clone(old.Index.Patterns())
	} else {
		// A table with no command rule compiled none (execCommands): its exec.allow entries are names and paths
		// only, and a bare name among them lifts its tool as it would in an index (execmatch.NewIndex), as do the
		// implicit grants.
		ec.Loaders = execLoaders(loaderDirs())
		if rt.Contract != nil {
			ec.Unconstrained = implicitGrants(rt, rt.Contract)
			if rt.Contract.Exec != nil {
				allow := rt.Contract.Exec.Allow
				// An Adjustable table's exec fence entries joined exec.allow under an allow-list (compileLive), as
				// the table's index did; the contract as written does not list them.
				if rt.Adjustable() && !rt.Contract.Exec.DenyList() {
					allow = slices.Clone(allow)
					for _, e := range rt.Live.Entries {
						if e.Kind == LiveKindExec {
							allow = append(allow, e.Value)
						}
					}
				}
				for _, e := range allow {
					if p, err := execmatch.Parse(e, execmatch.ListAllow, rows.Builtin()); err == nil {
						patterns = append(patterns, p)
					}
				}
			}
		}
	}
	if ec.Identities == nil {
		ec.Identities = map[execmatch.ID]string{}
	}
	id := execmatch.ID{Dev: uint64(st.Dev), Ino: st.Ino}
	if _, ruled := ec.Identities[id]; !ruled {
		ec.Identities[id] = tool
	}
	unconstrained := make(map[string]bool, len(ec.Unconstrained))
	for t := range ec.Unconstrained {
		unconstrained[t] = true
	}
	ec.Index = execmatch.NewIndex(rows.Builtin(), append(patterns, execmatch.ExactPattern(HarnessHookGrant, tool, argv)), execmatch.IndexOptions{
		Candidates: ec.Candidates, Identities: ec.Identities, Loaders: ec.Loaders, Unconstrained: unconstrained,
	})
	if !ec.Index.Constrained(tool) {
		return nil, fmt.Errorf("%w: %s stays unconstrained (%s grants it any arguments), so a grant of %s would admit every argv",
			ErrHarnessHookGrant, tool, rawOr(ec.Unconstrained[tool], "a bare exec.allow entry"), exe)
	}
	out.ExecCommands = ec
	out.HarnessHook = slices.Clone(argv)
	return &out, nil
}

// addPattern grants the image of an exec.allow command pattern (ADR 0048 (1)): its command word, as a bare entry of
// that word would be, so `git status` grants git's file under the rule exec[git] and its words constrain git's
// argv (the command rules, RuleTable.ExecCommands). The filesystem only improves an error: an unquoted path with
// spaces that names an existing file is refused with "quote the path", and a command word that is a directory is
// refused, since a directory entry takes no words.
func (b *execBuilder) addPattern(entry string, pos Pos) {
	k := b.k
	words, _, err := execmatch.SplitWords(entry)
	if err != nil || len(words) == 0 {
		return // validateExec has refused it
	}
	cmd := words[0]
	if strings.Contains(entry, "/") {
		if fi, err := os.Stat(k.abs(entry)); err == nil && !fi.IsDir() {
			k.ds.errorf(pos, CodeExecRule, "exec.allow %q names the file %s, but its unquoted spaces make it a command pattern", entry, k.abs(entry)).
				fix("quote the path: '%s'", entry)
			return
		}
	}
	if strings.Contains(cmd, "/") {
		if fi, err := os.Stat(k.abs(cmd)); err == nil && fi.IsDir() {
			k.ds.errorf(pos, CodeExecRule, "exec.allow %q: %s is a directory, and a directory entry takes no words", entry, cmd).
				fix("grant the directory alone, or name the command in it: %s", strconv.Quote(filepath.Join(cmd, "<command>")+" "+strings.Join(words[1:], " ")))
			return
		}
	}
	b.add(cmd, ExecSourceAllow, pos, false)
}

type execBuilder struct {
	k       *compiler
	rules   []ExecRule
	byPath  map[string]int // resolved path -> index into rules
	scripts []int          // exec.allow entries that are scripts, for the #! check
}

// add resolves one entry and appends its rule; implicit says whether a
// script's interpreter is granted (command, mcp) or only checked (exec.allow).
func (b *execBuilder) add(raw, source string, pos Pos, implicit bool) {
	k := b.k
	p, ok := b.resolve(raw, source, pos)
	if !ok {
		return
	}
	byName := !strings.Contains(raw, "/") // SEMANTICS §4: only a bare command name matches by dentry name
	if i, dup := b.byPath[p]; dup {
		// Whole elements: a substring test dropped mcp:foo beside mcp:foo-bar.
		if !slices.Contains(strings.Split(b.rules[i].Source, ","), source) {
			b.rules[i].Source += "," + source
		}
		// The surviving rule keeps the first spelling for its name (RuleName, the ledger's
		// rule field), but name-matchability is a property of the *set* of spellings: an
		// entry the author wrote as a bare basename must not lose tier 3's dentry
		// match because some other entry happened to name the same file by path.
		b.rules[i].ByName = b.rules[i].ByName || byName
		return
	}
	r := ExecRule{Raw: raw, Path: p, Basename: filepath.Base(p), ByName: byName, Verdict: VerdictAllow, Source: source, Pos: pos}
	if fi, err := os.Stat(p); err == nil && fi.IsDir() {
		r.IsDir = true
		b.append(r)
		return
	}
	interp, err := ReadInterp(p)
	switch {
	case err == nil:
		// The loader is opened in tego's own process too (Landlock's holdLoader, the cgroup listener's allow list),
		// so a PT_INTERP that is or leads through a /proc path grants tego's own file, R8a's class.
		// ReadInterp returns only an absolute loader (a relative one is ErrMalformedELF), so the walk starts at /.
		if via, proc := config.ThroughProc(interp); proc {
			b.refuseProcLoader(raw, source, p, interp, via, pos)
			return
		}
		r.Interp = interp
	case errors.Is(err, ErrNotELF):
		b.script(&r, pos, implicit)
	case errors.Is(err, ErrMalformedELF): // E14
		k.ds.warnf(pos, CodeMalformedELF, "%s: ELF header unreadable; its loader gets no rule and a dynamic binary fails with EACCES in the landlock tier", p).
			fix("check the file with readelf -l %s", p)
	default:
		// The file could not be read, or ReadInterp refused it (a FIFO, a device, a kernel interface file, a
		// file under a lease: I6's bound, boundedio.go), which is no verdict on its content: say which.
		var pe *fs.PathError
		if errors.As(err, &pe) && pe.Path == p {
			err = pe.Err
		}
		fixText := "make " + p + " a readable regular file, not a FIFO, a device or a link to one, with no lease or lock held on it"
		var fr fsRefusal
		if errors.As(err, &fr) {
			fixText = p + " is on " + k.fsTypeOf(p, fr.magic) + ", which is not on the list of file systems Tego reads as data " +
				"(dataFS, pkg/spec/agent/boundedio.go): move it to a file system on the list, or report this one if it stores data, to be added"
		}
		k.ds.warnf(pos, CodeMalformedELF, "%s: %v; no loader or #! interpreter is granted from it, and the landlock and cgroup tiers' Prepare, which reads it again, fails the run (exit 125) if it still cannot", p, err).
			fix("%s", fixText)
	}
	b.append(r)
}

// fsTypeOf names the file system p is on for a refusal's fix, from the mount table (the kernel's name for it,
// lustre or gpfs, which fstatfs does not give), else by its magic.
func (k *compiler) fsTypeOf(p string, magic uint32) string {
	byMagic := "the file system of magic 0x" + strconv.FormatUint(uint64(magic), 16)
	mt, err := loadMountTable(k.o.mountInfo)
	if err != nil {
		return byMagic
	}
	if m, _, ok := mt.lookup(resolvePath(p)); ok && m.fstype != "" {
		return m.fstype + " (magic 0x" + strconv.FormatUint(uint64(magic), 16) + ")"
	}
	return byMagic
}

func (b *execBuilder) append(r ExecRule) {
	b.byPath[r.Path] = len(b.rules)
	b.rules = append(b.rules, r)
}

// script handles a non-ELF entry: a #! interpreter is granted for implicit
// entries (the command, MCP servers) and remembered for exec.allow's check.
func (b *execBuilder) script(r *ExecRule, pos Pos, implicit bool) {
	interp, arg, ok, err := ReadShebang(r.Path)
	if err != nil || !ok {
		return
	}
	if !implicit {
		b.scripts = append(b.scripts, len(b.rules))
		return
	}
	src := ExecSourceInterpreter + ":" + r.Basename
	b.add(interp, src, pos, false)
	if filepath.Base(interp) == "env" && arg != "" && !strings.HasPrefix(arg, "-") {
		b.add(arg, src, pos, false)
	}
}

// checkInterpreters warns when an exec.allow script's #! names a binary the
// list does not cover (SEMANTICS §4). Each rule's spellings are resolved once, and each distinct
// interpreter is asked once: asked per script, covers resolved every rule again for every #! line, so a
// contract of n scripts cost n x n resolutions, each several syscalls (8.6 s at 1,500; E24).
func (b *execBuilder) checkInterpreters() {
	if len(b.scripts) == 0 {
		return
	}
	entries := make([][]string, len(b.rules))
	for j := range b.rules {
		entries[j] = []string{b.rules[j].Path}
		if res := resolvePath(b.rules[j].Path); res != "" && res != b.rules[j].Path {
			entries[j] = append(entries[j], res)
		}
	}
	covered := map[string]bool{}
	for _, i := range b.scripts {
		r := b.rules[i]
		interp, arg, ok, err := ReadShebang(r.Path)
		if err != nil || !ok {
			continue
		}
		want := []string{interp}
		if filepath.Base(interp) == "env" && arg != "" && !strings.HasPrefix(arg, "-") {
			want = append(want, arg)
		}
		for _, w := range want {
			c, seen := covered[w]
			if !seen {
				c = b.covers(w, entries)
				covered[w] = c
			}
			if !c {
				b.k.ds.warnf(r.Pos, CodeInterpreter, "exec.allow %q is a script whose #! needs %s, which no exec.allow entry covers", r.Raw, w).
					fix("add %q to exec.allow", w) // the path itself: a basename can resolve to another inode
			}
		}
	}
}

// covers reports whether a rule grants the interpreter name a #! line gives, as the run matches an exec
// (decide.matchExec): the same file, under its spelling or its symlink-resolved one, or a directory entry
// above it. A bare name (env's argument) is the file env finds on the run's PATH. A same-named binary
// elsewhere is another inode, which tiers 1 and 2 refuse (SEMANTICS §4), so an entry's basename covers it only
// when the author wrote that entry as a bare name and no run of the table can land below tier 3. entries is
// each rule's spellings, its path and its resolved path, in b.rules' order.
func (b *execBuilder) covers(name string, entries [][]string) bool {
	cand := name
	if !strings.Contains(name, "/") {
		cand = ""
		if b.k.rt.PATH != "" {
			cand, _ = b.searchPath(name, strings.Split(b.k.rt.PATH, ":"))
		}
	}
	var spellings []string
	if cand != "" {
		spellings = append(spellings, cand)
		if res := resolvePath(cand); res != "" && res != cand {
			spellings = append(spellings, res)
		}
	}
	byName := !b.k.mayLand(backend.TierLandlock) && !b.k.mayLand(backend.TierCgroup)
	for j, r := range b.rules {
		for _, s := range spellings {
			for _, e := range entries[j] {
				if s == e || (r.IsDir && Covers(e, s)) {
					return true
				}
			}
		}
		if byName && r.ByName && r.Basename == filepath.Base(name) {
			return true
		}
	}
	return false
}

// resolve turns an entry into an absolute path: a path entry via abs (E28),
// a basename via the run's PATH, first regular executable wins, shadowing
// directories skipped (E12); an exhausted PATH is exec-not-on-path with every
// directory searched in Fix (R8, E37), or a versioned sibling's name when one
// resolves.
func (b *execBuilder) resolve(raw, source string, pos Pos) (string, bool) {
	k := b.k
	if strings.Contains(raw, "/") {
		p := k.abs(raw)
		if via, ok := config.ThroughProc(p); ok {
			b.refuseProc(raw, source, p, via, pos)
			return "", false
		}
		if _, err := os.Stat(p); err != nil {
			k.ds.errorf(pos, CodePathMissing, "%s %q: %s does not exist", source, raw, p).
				fix("fix the path or name the binary by basename to search PATH")
			return "", false
		}
		return p, true
	}
	dirs := strings.Split(k.rt.PATH, ":")
	if k.rt.PATH == "" {
		dirs = nil
	}
	if p, ok := b.searchPath(raw, dirs); ok {
		if via, proc := config.ThroughProc(p); proc {
			b.refuseProc(raw, source, p, via, pos)
			return "", false
		}
		return p, true
	}
	what := source + " " + strconv.Quote(raw)
	if strings.HasPrefix(source, ExecSourceMCP+":") {
		what = "mcp " + strconv.Quote(strings.TrimPrefix(source, ExecSourceMCP+":")) + " command " + strconv.Quote(raw)
	}
	d := k.ds.errorf(pos, CodeExecNotOnPath, "%s is not an executable on the run's PATH", what)
	switch {
	case len(dirs) == 0 && !k.o.pathSet:
		d.fix("no PATH was given to compile; tego compile passes the launcher's PATH")
	case len(dirs) == 0:
		d.fix("the run's PATH is empty: env.pass must include PATH (or env.set PATH=...)")
	default:
		// Debian and Ubuntu ship python3 with no python symlink, so a contract written against the
		// upstream name finds nothing; the general form is a versioned sibling (name+"3") that does
		// resolve, not a hardcoded python/python3 special case.
		if _, ok := b.searchPath(raw+"3", dirs); ok {
			d.fix("did you mean %q?", raw+"3")
		} else {
			d.fix("searched: %s", strings.Join(dirs, ", "))
		}
	}
	return "", false
}

// refuseProc is the exec-proc error (agent-contract.md R8a): an exec entry that is, or leads through, a /proc path.
func (b *execBuilder) refuseProc(raw, source, p, via string, pos Pos) {
	what := source + " " + strconv.Quote(raw)
	if strings.HasPrefix(source, ExecSourceMCP+":") {
		what = "mcp " + strconv.Quote(strings.TrimPrefix(source, ExecSourceMCP+":")) + " command " + strconv.Quote(raw)
	}
	msg := what + ": " + p + " is a /proc path"
	if via != p {
		msg = what + ": " + p + " leads through the /proc path " + via
	}
	b.k.ds.errorf(pos, CodeExecProc, "%s, which names a file relative to the process that opens it: compile would resolve it in tego's own process (/proc/self/exe is tego's executable there), not to the program the agent's exec reaches", msg).
		fix("name the program by its own path or by basename on PATH; a program that re-executes itself through /proc/self/exe needs no entry for it")
}

// refuseProcLoader is the exec-proc error for an ELF entry whose loader (PT_INTERP) is, or leads through, a /proc path:
// the loader is resolved and granted in tego's own process as the entry is (agent-contract.md R8a).
func (b *execBuilder) refuseProcLoader(raw, source, p, interp, via string, pos Pos) {
	what := source + " " + strconv.Quote(raw)
	if strings.HasPrefix(source, ExecSourceMCP+":") {
		what = "mcp " + strconv.Quote(strings.TrimPrefix(source, ExecSourceMCP+":")) + " command " + strconv.Quote(raw)
	}
	msg := what + ": " + p + "'s ELF loader (PT_INTERP) " + interp + " is a /proc path"
	if via != interp {
		msg = what + ": " + p + "'s ELF loader (PT_INTERP) " + interp + " leads through the /proc path " + via
	}
	b.k.ds.errorf(pos, CodeExecProc, "%s, which names a file relative to the process that opens it: the loader would be granted as tego's own process resolves it (/proc/self/exe is tego's executable there), not as the agent's exec loads it", msg).
		fix("rebuild %s with a loader on a real path (readelf -l %s shows it), or drop the entry", p, p)
}

// searchPath looks for name as a regular, executable file in dirs, in order (execvp's rule: first
// match wins, an empty element means cwd). It is the one PATH walk resolve and its versioned-sibling
// check both use, so "found" means the same thing in the rule and in the suggestion.
func (b *execBuilder) searchPath(name string, dirs []string) (string, bool) {
	for _, d := range dirs {
		if !filepath.IsAbs(d) {
			// execvp: an empty PATH element is the current directory, and a relative one (node_modules/.bin)
			// lies under it. The current directory is the compile's cwd, not this process's, and the rule
			// must come out absolute: every tier compares absolute canonical paths. No ~ expansion: execvp
			// does none.
			d = filepath.Join(b.k.o.cwd, d)
		}
		cand := filepath.Join(d, name)
		fi, err := os.Stat(cand)
		if err != nil || !fi.Mode().IsRegular() || fi.Mode()&0o111 == 0 {
			continue
		}
		return cand, true
	}
	return "", false
}

// execUnderWrite warns when a rule that grants EXECUTE lands inside a directory the same contract
// makes writable (E38) — content the agent may write later deciding what the agent may run, which is
// the shape of CVE-2025-54135/CVE-2025-54136 (an agent writing a trusted config file to reach RCE).
// Tego is immune to the config half: the boundary is the compiled table, not a harness file the
// agent can edit. This is the half that is not immune.
//
// A directory entry is the whole-list bypass. Landlock's LANDLOCK_RULE_PATH_BENEATH names a *file
// hierarchy* (man 2 landlock_add_rule), so the grant covers files created after
// landlock_restrict_self: the agent writes a binary under the granted directory and runs it. It is
// not landlock-only — tier 2's fanotify exec check (internal/runtime/enforce/cgroup decideExec) and
// tier 3's exec hook match a directory entry by path prefix, so a file created there matches too.
//
// A file entry is the narrower but still real case: AccessWriteSet carries WRITE_FILE and TRUNCATE
// over the whole write subtree, so the agent can overwrite the binary the rule allows — in the
// landlock tier in place, because the pinned inode keeps its EXECUTE, and in the root tiers by
// replacing the path. Landlock cannot deny chmod at any ABI (man 7 landlock, CAVEATS; E35), so the
// agent can also set the execute bit on what it wrote.
//
// Runs after exec(), which resolves the entries, and after fs(), which resolves the write entries.
func (k *compiler) execUnderWrite() {
	// Keyed by the resolved write path and walked by ancestor, the way redundant() does it:
	// O(entries x depth), not O(exec x writes), which E24's thousands-of-entries contracts need.
	// Resolved on both sides, like every other containment question (E8): a write entry that is a
	// symlink governs its target's subtree, which is where the exec grant's inode lives.
	writes := make(map[string]string, len(k.rt.FS)) // resolved write path -> the entry as declared
	// The other nesting: a write entry strictly beneath a directory exec grant. `exec.allow: [tools]`
	// with `fs.write: [tools/cache]` is the same whole-list bypass, because tools/cache/x is inside the
	// exec grant's hierarchy. Each strict ancestor of a resolved write path maps to the first write entry
	// beneath it, so a directory exec rule finds one in a single lookup; still O(entries x depth).
	type writeEntry struct{ declared, resolved string }
	beneath := make(map[string]writeEntry)
	for _, r := range k.rt.FS {
		if r.Kind != FSWrite {
			continue
		}
		if _, dup := writes[r.Resolved]; !dup {
			writes[r.Resolved] = r.Path
		}
		for p := r.Resolved; p != "/" && p != "." && p != ""; {
			p = filepath.Dir(p)
			if _, seen := beneath[p]; !seen {
				beneath[p] = writeEntry{r.Path, r.Resolved}
			}
		}
	}
	if len(writes) == 0 {
		return
	}
	for _, r := range k.rt.Exec {
		resolved := k.resolve(r.Path)
		if resolved == "" {
			continue
		}
		found := false
		for p := resolved; ; p = filepath.Dir(p) { // starts at the entry itself: an exec entry that *is* the write entry counts
			if declared, ok := writes[p]; ok {
				k.execWritable(r, resolved, declared, p)
				found = true
				break
			}
			if p == "/" || p == "." {
				break
			}
		}
		if found || !r.IsDir {
			continue
		}
		if w, ok := beneath[resolved]; ok {
			k.ds.warnf(r.Pos, CodeExecWritable, "%s %s%s holds the writable %s%s: every file the agent creates there is executable, so the exec list no longer bounds what runs",
				r.Source, r.Path, resolvedNote(r.Path, resolved), w.declared, resolvedNote(w.declared, w.resolved)).
				fix("list the individual binaries instead of the directory, or move %s outside the exec directory", w.declared)
		}
	}
}

// execOverRuntimeDir is E38 for the one write grant no entry declares: the run's own CODEX_HOME, which a run whose
// Codex is routed through the forwarder grants under tego's runtime directory on its own authority (R10a). An
// exec.allow or exec.ask directory that holds that directory, or lies inside it, makes whatever the agent writes
// there executable, and execUnderWrite, which sees only declared write entries, said nothing. The
// launcher refuses such a run when it adds the grant (internal/runtime grantCodexHome); compile warns, since it
// cannot tell whether the run will route Codex.
func (k *compiler) execOverRuntimeDir() {
	if len(k.o.runtimeParents) == 0 {
		return
	}
	for _, r := range k.rt.Exec {
		if !r.IsDir || r.Verdict == VerdictRefused {
			continue
		}
		resolved := k.resolve(r.Path)
		if resolved == "" {
			continue
		}
		for _, declared := range k.o.runtimeParents {
			parent := k.resolve(declared)
			if parent == "" || !isAncestorOrSelf(resolved, parent) && !isAncestorOrSelf(parent, resolved) {
				continue
			}
			k.ds.warnf(r.Pos, CodeExecWritable, "%s %s%s holds or lies in tego's runtime directory %s%s, where a run whose Codex is routed through the forwarder grants the agent write on its own CODEX_HOME: every file the agent creates there would be executable, so tego run refuses such a run",
				r.Source, r.Path, resolvedNote(r.Path, resolved), declared, resolvedNote(declared, parent)).
				fix("list the individual binaries instead of the directory, or name a directory outside %s", declared)
			break
		}
	}
}

// sharedWritable are the directories every user of a Linux machine may write, sticky or not: what a directory
// exec grant that holds one makes executable is whatever any process drops there.
var sharedWritable = []string{"/tmp", "/var/tmp", "/dev/shm"}

// execSharedWritable is E38 for writes the contract does not grant: an exec.allow directory every user can
// write (mode o+w, /tmp's 1777 among them), or one that holds such a directory (/, /var, /dev). Anything any
// process drops there, the agent's own writes through whatever grant reaches it included, then runs, and the
// exec list bounds nothing; `exec.allow: [/tmp]` and `[/]` compiled without a word. Runs after exec(),
// which resolves the entries.
func (k *compiler) execSharedWritable() {
	for _, r := range k.rt.Exec {
		if !r.IsDir || !strings.Contains(r.Source, ExecSourceAllow) {
			continue
		}
		resolved := k.resolve(r.Path)
		if resolved == "" {
			continue
		}
		what := ""
		if worldWritable(resolved) {
			what = "is writable by every user"
		} else {
			for _, shared := range sharedWritable {
				if isAncestorOrSelf(resolved, shared) && worldWritable(shared) {
					what = "holds " + shared + ", which every user can write"
					break
				}
			}
		}
		if what == "" {
			continue
		}
		k.ds.warnf(r.Pos, CodeExecWritable, "%s %s%s %s: anything any process drops there is executable, so the exec list no longer bounds what runs",
			r.Source, r.Path, resolvedNote(r.Path, resolved), what).
			fix("list the individual binaries instead of the directory")
	}
}

// worldWritable reports whether the directory at p has the other-write bit.
func worldWritable(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir() && fi.Mode().Perm()&0o002 != 0
}

// execWritable emits the one E38 diagnostic, worded for a directory grant or a single binary. Both
// paths are named as declared, with the resolved target appended when a symlink takes them
// elsewhere, so the reader sees the entry they wrote and the subtree the kernel will govern (E8).
func (k *compiler) execWritable(r ExecRule, resolved, write, writeResolved string) {
	note, wnote := resolvedNote(r.Path, resolved), resolvedNote(write, writeResolved)
	if r.IsDir {
		k.ds.warnf(r.Pos, CodeExecWritable, "%s %s%s is inside the writable %s%s: every file the agent creates there is executable, so the exec list no longer bounds what runs",
			r.Source, r.Path, note, write, wnote).
			fix("list the individual binaries instead of the directory, or move %s outside every fs.write entry", r.Path)
		return
	}
	k.ds.warnf(r.Pos, CodeExecWritable, "%s %s%s is inside the writable %s%s: the agent can overwrite that binary, so the exec rule no longer names fixed code",
		r.Source, r.Path, note, write, wnote).
		fix("move the binary outside every fs.write entry, or narrow the write entry")
}
