// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// execAccess is what every exec grant carries: EXECUTE alone never satisfies file_open under
// O_RDONLY|__FMODE_EXEC (R5, SEMANTICS §4).
const execAccess = accessExecute | accessReadFile

// execGrants is R5: one fd per compiled exec rule (a directory grants its whole subtree), the
// PT_INTERP loader of each ELF binary read live (E14; absent for a static binary), and a fail-closed
// check that every script's #! interpreter is independently granted. Loaders are not pre-scanned
// inside directory grants (E18).
func (bd *builder) execGrants() error {
	for _, r := range bd.rt.Exec {
		access := execAccess
		if r.IsDir {
			access |= accessReadDir
		}
		if err := bd.holdGrant(r.Path, execKind(r), access); err != nil {
			return err
		}
		if r.IsDir {
			continue
		}
		if err := bd.loaderOrInterpreter(r); err != nil {
			return err
		}
	}
	return nil
}

// deputyExecutable is the binary the child stage execs as the open deputy: this one, /proc/self/exe resolved when
// Prepare runs. Tests replace it.
var deputyExecutable = func() (string, error) { return os.Readlink("/proc/self/exe") }

// deputyGrant is the open deputy's runtime exec grant (ADR 0041 D2): a run whose held opens need the deputy
// (RuleTable.NeedsOpenDeputy) and whose domain handles EXECUTE gets EXECUTE|READ_FILE on tego's own binary's inode,
// and its ELF loader for a dynamic build, so the child stage can exec the deputy after landlock_restrict_self. A run
// with no exec: section executes whatever it reads, and needs none. The agent's own exec of the binary is still the
// supervisor's to decide (R16b): the grant is the domain's, not the contract's, and no exec rule names it.
func (bd *builder) deputyGrant() error {
	if !bd.rt.NeedsOpenDeputy() || bd.execUnrestricted {
		return nil
	}
	exe, err := deputyExecutable()
	if err != nil {
		return fmt.Errorf("%w: the open deputy's binary: %w", ErrRulesetBuild, err)
	}
	if err := bd.holdGrant(exe, kindDeputy, execAccess); err != nil {
		return err
	}
	return bd.loaderOrInterpreter(agent.ExecRule{Path: exe, Resolved: exe})
}

// loaderOrInterpreter grants the ELF loader of r or checks its #! interpreter.
func (bd *builder) loaderOrInterpreter(r agent.ExecRule) error {
	interp, err := agent.ReadInterp(r.Path)
	switch {
	case err == nil:
		if interp == "" {
			return nil // E16: static binary
		}
		return bd.loaderGrant(r, interp)
	case errors.Is(err, agent.ErrNotELF):
		return bd.checkScript(r)
	case errors.Is(err, agent.ErrMalformedELF):
		return nil // compile already warned (E14): the binary alone is granted
	}
	return fmt.Errorf("%w: reading %q: %w", ErrRulesetBuild, r.Path, err)
}

// loaderGrant is R5's loader grant with the confinement E29 requires. PT_INTERP is read out of the
// binary at Prepare time (E14: live, never from compile's record), and a binary that lies under an
// fs.write entry is agent-writable between runs — so the content of a file the agent controls chooses
// which path receives EXECUTE|READ_FILE. Unconfined that turns one declared write grant into a read of
// any deny_read target and an execute of any file the agent dropped, which is SEMANTICS §4's "an
// unlisted script is refused in this tier" defeated by another name. The grant is therefore confined
// to what a loader can legitimately be: a regular file outside every write/ask entry and every
// deny_read target. Real loaders (/lib64/ld-linux-*.so.2, musl's, a /nix/store one) satisfy that; any
// other choice fails closed naming the binary and the loader, the posture the #! path already takes.
func (bd *builder) loaderGrant(r agent.ExecRule, interp string) error {
	// A loader that is or leads through a /proc path would be opened here, in tego's own process: /proc/self/exe is
	// tego's executable. Compile refuses such a PT_INTERP (agent-contract.md R8a); Prepare reads the
	// ELF again, so a file rewritten since is refused here too.
	if filepath.IsAbs(interp) {
		if via, ok := config.ThroughProc(interp); ok {
			return fmt.Errorf("%w: %q names loader %q, which is or leads through the /proc path %s: it would be resolved in tego's own process", ErrLoaderRefused, r.Path, interp, via)
		}
	}
	// Both spellings are checked: the resolved path is where the grant lands (hold follows symlinks),
	// the cleaned one catches a target whose own resolution failed. Racing the resolve is E12/E28's
	// documented TOCTOU, and the inode check in holdLoader closes it for a deny_read target's own inode.
	for _, p := range []string{filepath.Clean(interp), resolveTarget(interp)} {
		if g, ok := bd.governs(p); ok {
			return fmt.Errorf("%w: %q names loader %q, which lies at or below the fs.%s entry %q", ErrLoaderRefused, r.Path, interp, g.Kind, g.Path)
		}
	}
	return bd.holdLoader(r, interp)
}

// governs reports the fs entry that forbids a content-chosen grant at p: a deny_read target the grant
// would re-open, or a write/ask entry whose contents the agent replaces at will. Entries are compared
// on their resolved paths for the same reason enumerate walks resolved locations (E12) — where a grant
// lands decides, not how it is spelled. An entry of "/" contains every path, as covers() and fsplan.FirstCover
// treat it: fs.write "/" makes every loader agent-writable, so every dynamic binary's loader is refused under it.
func (bd *builder) governs(p string) (agent.FSRule, bool) {
	if !bd.governedOnce { // resolved once per Prepare, not once per binary (E22: stay linear)
		bd.governed, bd.governedOnce = resolveGoverned(bd.rt.FS), true
	}
	for _, g := range bd.governed {
		if p == g.resolved || g.resolved == "/" || strings.HasPrefix(p, g.resolved+"/") {
			return g.rule, true
		}
	}
	return agent.FSRule{}, false
}

// governedPath pairs an fs entry with the location it actually resolves to.
type governedPath struct {
	resolved string
	rule     agent.FSRule
}

func resolveGoverned(rules []agent.FSRule) []governedPath {
	out := make([]governedPath, 0, len(rules))
	for _, r := range rules {
		switch r.Kind {
		case agent.FSWrite, agent.FSAsk, agent.FSDenyRead:
			out = append(out, governedPath{resolved: resolveTarget(r.Path), rule: r})
		}
	}
	return out
}

// holdLoader is hold() plus the two guards a content-chosen path needs (E29). A loader is always a
// regular file, and a PATH_BENEATH rule on a directory is recursive, so a PT_INTERP naming a directory
// would turn a per-file grant into a whole-subtree read grant. Both guards read the fstat of the fd
// that is about to be added, so nothing can be swapped in after the check; the inode comparison also
// catches a loader that is a deny_read target's own inode under another name (a hardlink of a file target),
// which no path comparison can see (E7: identity is the inode, paths are not). It compares against the
// sealed target entries only. If an enforced denied directory exists, a multiply linked loader could
// also name an unenumerated child of that directory. Refuse that ambiguous content-selected grant;
// a single-link loader and a multiply linked loader with only file denials remain supported.
func (bd *builder) holdLoader(r agent.ExecRule, interp string) error {
	if err := bd.tick(); err != nil {
		return err
	}
	fd, st, err := openAt(unix.AT_FDCWD, interp, true, bd.fds)
	if err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return fmt.Errorf("%w: %q names loader %q, which is not a regular file (type %#o)", ErrLoaderRefused, r.Path, interp, st.Mode&unix.S_IFMT)
	}
	if i, held := bd.fds.ids[devIno{dev: st.Dev, ino: st.Ino}]; held && bd.fds.open[i].Kind == kindDenyTarget {
		_ = unix.Close(fd)
		return fmt.Errorf("%w: %q names loader %q, which is the inode of deny_read %q", ErrLoaderRefused, r.Path, interp, bd.fds.open[i].Path)
	}
	if st.Nlink > 1 {
		for _, denied := range bd.fds.open {
			if denied.Kind == kindDenyTarget && denied.IsDir {
				_ = unix.Close(fd)
				return fmt.Errorf("%w: %q names loader %q with %d hardlinks, whose aliases cannot be excluded from deny_read directory %q; use a dedicated single-link loader outside fs.write and fs.deny_read",
					ErrLoaderRefused, r.Path, interp, st.Nlink, denied.Path)
			}
		}
	}
	bd.fds.add(fd, interp, kindExecLoader, bd.fitAccess(execAccess, &st), &st)
	return nil
}

// checkScript fails closed when a script's #! (and env's argument) is not covered by an exec grant
// (R5, E14). A non-script, non-ELF file is left alone: execve refuses it with ENOEXEC on its own.
func (bd *builder) checkScript(r agent.ExecRule) error {
	interp, arg, ok, err := agent.ReadShebang(r.Path)
	if err != nil {
		return fmt.Errorf("%w: reading %q: %w", ErrRulesetBuild, r.Path, err)
	}
	if !ok {
		return nil
	}
	want := []string{interp}
	if filepath.Base(interp) == "env" && arg != "" && !strings.HasPrefix(arg, "-") {
		want = append(want, arg)
	}
	for _, w := range want {
		if !bd.covers(w) {
			return fmt.Errorf("%w: script %q needs %q", ErrInterpreterMissing, r.Path, w)
		}
	}
	return nil
}

// covers reports whether an exec rule grants the interpreter name. The kernel opens a #! interpreter
// after following its symlinks, and hold follows each rule's symlinks too (E8, E17), so for an absolute
// name the question is asked of resolved paths: a file rule covers it when both resolve to the same
// place, a directory rule when name resolves beneath where the directory does. Asking it of the declared
// strings refused a script whose #! lies under a symlinked exec.allow directory (/bin -> usr/bin and
// #!/usr/bin/sh) although the recursive rule grants it, and accepted an interpreter that is a symlink
// out of a granted directory, which execve then refuses with EACCES instead of Prepare naming it (R5,
// E14). An equal declared path is the same inode by the same resolution, so it covers as it stands.
// A basename covers only a bare name, one with no slash at all: env's argument, which names no file until
// the run's PATH resolves it at exec time, is the one name nothing else can match. A name with a slash is
// a path — env execvp()s `sub/py` relative to the cwd with no PATH search — so the basename arm would be a
// match by name, which this tier cannot make (SEMANTICS §4): a same-named grant anywhere would cover an
// interpreter whose own inode no rule reaches. A relative one is not covered at all, since Prepare cannot
// know the cwd the exec will run in. compile's check (compile_exec.go covers) keeps the basename arm for
// every name, but it only warns, so refusing here is the fail-closed side.
//
// A file rule covers the one path that resolves to its own path. A #! naming a hardlink of a granted file
// under another name is the same inode, and the kernel would run it, but it is refused here on purpose:
// decide.Evaluate is pure and cannot see inodes, so it reports that script refused in this tier, and
// accepting it here would leave `compile --test` and the run disagreeing on the same exec.
func (bd *builder) covers(name string) bool {
	abs := filepath.IsAbs(name)
	bare := !strings.Contains(name, "/")
	var resolved string
	if abs {
		resolved = resolveTarget(name)
	}
	for i, r := range bd.rt.Exec {
		if r.Path == name || bare && r.Basename == name {
			return true
		}
		if !abs {
			continue
		}
		p := bd.resolvedExec(i)
		if r.IsDir && (p == "/" || strings.HasPrefix(resolved, p+"/")) || !r.IsDir && resolved == p {
			return true
		}
	}
	return false
}

// resolvedExec is exec rule i's path resolved the way hold resolves it (it opens without O_NOFOLLOW),
// computed at most once per Prepare however many scripts and deny_read entries ask (E22: stay linear).
func (bd *builder) resolvedExec(i int) string {
	if bd.execResolved == nil {
		bd.execResolved = make([]string, len(bd.rt.Exec))
	}
	if bd.execResolved[i] == "" {
		bd.execResolved[i] = resolveTarget(bd.rt.Exec[i].Path)
	}
	return bd.execResolved[i]
}

// execKind classifies a rule by the first of its comma-joined sources.
func execKind(r agent.ExecRule) entryKind {
	src, _, _ := strings.Cut(r.Source, ",")
	switch {
	case src == agent.ExecSourceCommand:
		return kindAgentCommand
	case strings.HasPrefix(src, agent.ExecSourceMCP+":"):
		return kindMCPCommand
	case strings.HasPrefix(src, agent.ExecSourceInterpreter+":"):
		return kindExecInterp
	case r.IsDir:
		return kindExecDir
	}
	return kindExecBinary
}
