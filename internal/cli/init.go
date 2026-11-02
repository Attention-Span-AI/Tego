// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/setup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/presets"
)

// starter is the agent.yaml tego init writes; __NAME__ becomes the agent id. The starter quotes it,
// since name is a YAML string (agent-contract R3) and an id such as 2024, true or null is not one
// when plain; an agent id ([a-z0-9-]) never needs an escape inside the double quotes.
//
//go:embed agent.starter.yaml
var starter string

// Names of what init creates (relative to the project directory).
const (
	initDir       = ".tego"
	initContract  = "agent.yaml"
	initGitignore = ".gitignore"
	initIgnored   = ".tego/runs/"
	// initMarker opens every starter contract; a file without it is foreign and never overwritten
	// without --force.
	initMarker = setup.Marker
)

func init() { register(cmdInit) }

// cmdInit is `tego init [--name <agent>] [--force] [dir]` (R29): creates .tego/, a starter
// agent.yaml and the .gitignore line. Idempotent: a second run changes nothing and exits 0. An
// agent.yaml that init did not write is refused with exit 1 [exists] unless --force replaces it.
//
// With --preset <list> the agent.yaml extends the named presets and carries the --write
// folders, the --allow-host hosts and the --command line, composed by internal/setup and compiled offline before it
// is written; --list prints the presets and host groups.
func cmdInit() Command {
	var (
		name    string
		force   bool
		list    bool
		preset  string
		command string
		writes  []string
		hosts   []string
		live    string
	)
	return Command{
		Name:    "init",
		Summary: "scaffold .tego/ and a starter agent.yaml in a project directory",
		Usage:   "[--name <agent>] [--force] [--live-mode locked|adjustable] [--preset <list> [--write <dir>]... [--allow-host <host[:port]|@group>]... [--command <line>]] [--list] [dir]",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&name, "name", "", "agent id for the starter contract (default: the directory name)")
			fs.BoolVar(&force, "force", false, "replace an agent.yaml that tego init did not write")
			fs.StringVar(&preset, "preset", "", "write a contract from presets, a comma list of no-secrets, no-prod, repo-only-writes")
			fs.Func("write", "with --preset: a folder the agent may write (repeatable)", func(v string) error { writes = append(writes, v); return nil })
			fs.Func("allow-host", "with --preset: a host[:port] or @group the agent may reach (repeatable)", func(v string) error { hosts = append(hosts, v); return nil })
			fs.StringVar(&command, "command", "", "with --preset: the agent's command line (default: a short demo of the presets)")
			fs.BoolVar(&list, "list", false, "print the presets and host groups")
			fs.StringVar(&live, "live-mode", string(agent.LiveLocked), "how the agent's rules change while it runs: locked (the default: file, program and network rules are "+
				"fixed when the run starts; tighten while it runs, loosen from the next run) or adjustable (live both ways: loosen and tighten "+
				"while it runs inside a fence Tego's live layer enforces; needs tier cgroup or bpflsm). docs/user/live-modes.md weighs the two")
		},
		Run: func(_ context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int {
			if list {
				return printPresetList(stdout, stderr)
			}
			if fs.NArg() > 1 {
				message(stderr, "", 0, 0, "tego init: at most one directory argument", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			dir := "."
			if fs.NArg() == 1 && fs.Arg(0) == "" {
				// An unset "$DIR" named no directory, and the current one got the scaffold.
				message(stderr, "", 0, 0, "tego init: the directory is an empty string; give none for the current directory", codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			if fs.NArg() == 1 {
				dir = fs.Arg(0)
			}
			mode := agent.LiveMode(live)
			if mode != agent.LiveLocked && mode != agent.LiveAdjustable {
				message(stderr, "", 0, 0, fmt.Sprintf("tego init: --live-mode %q is not locked or adjustable (docs/user/live-modes.md)", live), codeUsage)
				return identity.ExitUsage // R25: usage error
			}
			if preset == "" {
				if len(writes) > 0 || len(hosts) > 0 || command != "" {
					message(stderr, "", 0, 0, "tego init: --write, --allow-host and --command fill a preset contract; add --preset <list>", codeUsage)
					return identity.ExitUsage // R25: usage error
				}
				return runInitLive(dir, name, force, nil, mode, stdout, stderr)
			}
			return runInitLive(dir, name, force, &setup.Options{Presets: []string{preset}, Writes: writes, Hosts: hosts, Command: command}, mode, stdout, stderr)
		},
	}
}

// runInitLive performs init in dir, writing a preset contract when po is not nil, in the live mode `--live-mode`
// chose (ADR 0125): Locked writes exactly the contract init always wrote; Adjustable appends liveAdjustableBlock.
func runInitLive(dir, name string, force bool, po *setup.Options, live agent.LiveMode, stdout, stderr io.Writer) int {
	adjustable := live == agent.LiveAdjustable // before the agent id below shadows the package name
	abs, err := filepath.Abs(dir)
	if err != nil {
		message(stderr, dir, 0, 0, "tego init: "+err.Error(), codeIO)
		return identity.ExitError // R25: Tego's own error
	}
	// init scaffolds a project that exists; it does not create one. A missing directory, or a path that is
	// not one, is the caller's mistake and a usage error naming it, where it failed as 125 [io] on the first
	// file it tried to write (R29). Creating it would turn a typo into a new project.
	if fi, err := os.Stat(abs); err != nil || !fi.IsDir() {
		what := "does not exist"
		if err == nil {
			what = "is not a directory"
		} else if !errors.Is(err, os.ErrNotExist) {
			what = "cannot be read: " + err.Error()
		}
		message(stderr, abs, 0, 0, fmt.Sprintf("tego init: %s %s; init scaffolds an existing project directory", abs, what), codeUsage)
		return identity.ExitUsage // R25: usage error
	}
	if name == "" {
		name = agentNameFor(abs)
	}
	agent, err := identity.ParseAgentID(name)
	if err != nil {
		message(stderr, "", 0, 0, fmt.Sprintf("tego init: --name %q is not an agent id ([a-z0-9-]{1,40})", name), codeUsage)
		return identity.ExitUsage // R25: usage error
	}
	var composed *setup.Result
	var env setup.CheckEnv
	if po != nil {
		po.Name, po.Dir = string(agent), abs
		po.Home, _ = os.UserHomeDir()
		var code int
		if env, code = initCheckEnv(stderr); code != identity.ExitOK {
			return code
		}
		composed, err = setup.Draft(*po, env)
		if err != nil {
			code, exit := codeUsage, identity.ExitUsage
			if !setup.IsUsage(err) {
				code, exit = codeIO, identity.ExitError
			}
			message(stderr, "", 0, 0, "tego init: "+err.Error(), code)
			return exit // R25: a usage error, or Tego's own
		}
	}
	var actions []string
	rootTier := false // an Adjustable contract written with tier: cgroup in place of the template's tier: landlock
	step := func(what string, done bool, err error, file string) bool {
		if err != nil {
			code := codeIO
			if errors.Is(err, errForeign) || errors.Is(err, errInitDirTaken) {
				code = codeExists
			}
			message(stderr, filepath.Join(abs, file), 0, 0, "tego init: "+err.Error(), code)
			return false
		}
		if done {
			actions = append(actions, what)
		}
		return true
	}
	contractPath := filepath.Join(abs, initContract)
	write, err := planContract(contractPath, force)
	if !step("", false, err, initContract) {
		if errors.Is(err, errForeign) {
			return identity.ExitFinding // R25: a finding: an existing foreign contract
		}
		return identity.ExitError // R25: Tego's own error
	}
	// .gitignore is planned before anything is written too: a link, a FIFO or an oversized file there
	// refused init only after .tego/ and agent.yaml were created, and the refusal did not say so.
	if _, _, err := readInitFile(filepath.Join(abs, initGitignore)); !step("", false, err, initGitignore) {
		return identity.ExitError // R25: Tego's own error, as ensureLine's refusal below
	}
	done, err := ensureDir(filepath.Join(abs, initDir))
	if !step("created "+initDir+"/", done, err, initDir) {
		if errors.Is(err, errInitDirTaken) {
			return identity.ExitFinding // R25: a finding: the path is something else
		}
		return identity.ExitError // R25: an I/O failure is Tego's own error, not a finding
	}
	if write && composed != nil {
		// Draft compiled the composed bytes offline before anything is created: a contract that does not compile
		// leaves no agent.yaml and no folder behind.
		if refusedComposed(stderr, contractPath, composed) {
			return identity.ExitFinding // R25: a finding, as compile's own exit for the same contract
		}
		// Apply creates the folders and compiles again with them in place (a check Draft could not make, R10); it
		// removes them again when that compile refuses.
		made, ds, ok, err := setup.Apply(composed, abs, env)
		if err != nil {
			message(stderr, abs, 0, 0, "tego init: "+err.Error(), codeIO)
			return identity.ExitError // R25: Tego's own error
		}
		if !ok {
			composed.Diagnostics, composed.OK = errorsOnly(ds), false // Draft printed the warnings
			refusedComposed(stderr, contractPath, composed)
			return identity.ExitFinding // R25: a finding, as compile's own exit for the same contract
		}
		for _, d := range made {
			actions = append(actions, "created "+d+"/")
		}
		content, pinned := withLiveMode(composed.Contract, live)
		err = writeContractBytes(contractPath, content, force)
		rootTier = pinned
		if !step(fmt.Sprintf("created %s (name: %s, presets: %s)", initContract, agent, strings.Join(composed.Presets, ",")), true, err, initContract) {
			if errors.Is(err, errForeign) {
				return identity.ExitFinding // another writer created the contract after planning
			}
			return identity.ExitError // R25: Tego's own error
		}
	} else if write {
		var content []byte
		content, rootTier = withLiveMode([]byte(strings.ReplaceAll(starter, "__NAME__", string(agent))), live)
		err = writeContractBytes(contractPath, content, force)
		if !step(fmt.Sprintf("created %s (name: %s)", initContract, agent), true, err, initContract) {
			if errors.Is(err, errForeign) {
				return identity.ExitFinding // another writer created the contract after planning
			}
			return identity.ExitError // R25: Tego's own error
		}
	}
	ignored := []string{initIgnored}
	if composed != nil {
		ignored = append(ignored, composed.Ignore...)
	}
	for _, line := range ignored {
		done, err = ensureLine(filepath.Join(abs, initGitignore), line)
		if !step(fmt.Sprintf("added %s to %s", line, initGitignore), done, err, initGitignore) {
			return identity.ExitError // R25: Tego's own error
		}
	}
	// A re-run with --preset on the agent.yaml init wrote earlier keeps that file: say the flags were not applied,
	// where "already initialized" alone read as if they had been.
	notApplied := func() {
		if composed != nil && !write {
			fmt.Fprintf(stdout, "tego init: %s already exists, so these --preset flags were not applied: edit it, or re-run with --force to replace it\n", initContract)
		}
		if adjustable && !write {
			fmt.Fprintf(stdout, "tego init: %s already exists, so --live-mode adjustable was not applied: add its live: section (docs/user/live-modes.md), or re-run with --force to replace it\n", initContract)
		}
	}
	if len(actions) == 0 {
		fmt.Fprintf(stdout, "tego init: already initialized (%s)\n", abs)
		notApplied()
		return identity.ExitOK
	}
	for _, a := range actions {
		fmt.Fprintln(stdout, a)
	}
	notApplied()
	if adjustable && write {
		fmt.Fprintln(stdout, "live mode: adjustable (live both ways): list under live.fence what you may grant while it runs; "+
			"Tego's live layer, not the kernel, refuses those entries until you lift them (docs/user/live-modes.md)")
		if rootTier {
			fmt.Fprintln(stdout, "tier: cgroup written in place of tier: landlock: Adjustable needs tier cgroup or bpflsm, which need root")
		} else {
			fmt.Fprintln(stdout, "Adjustable needs tier cgroup or bpflsm, which need root: a run that lands at tier landlock is refused")
		}
	}
	if composed != nil && write {
		fmt.Fprintln(stdout, "presets:")
		for _, n := range composed.Notes {
			fmt.Fprintln(stdout, n)
		}
		fmt.Fprintf(stdout, "next, from %s (the contract's paths are relative to it): tego compile agent.yaml; tego run agent.yaml; tego receipt --last\n", abs)
	}
	if composed == nil && write {
		// The starter's command is a placeholder: run as written in a project with no agent.py, the run ended on
		// python's "can't open file" and tego said nothing more (CO-F14).
		next := "next: set command: in agent.yaml to your agent's command line, then tego compile agent.yaml; tego run agent.yaml"
		if _, err := os.Stat(filepath.Join(abs, "agent.py")); err == nil {
			next = "next: tego compile agent.yaml; tego run agent.yaml (it runs python3 agent.py)"
		}
		fmt.Fprintln(stdout, next)
	}
	return identity.ExitOK
}

// refusedComposed prints the diagnostics Draft's offline compile found for r and, when one is an error, the line
// saying nothing was written, with compile's own code; it reports whether init must stop.
func refusedComposed(stderr io.Writer, contractPath string, r *setup.Result) bool {
	_ = agent.WriteDiagnostics(stderr, r.Diagnostics) // best effort: stderr is the diagnostics' only reader
	if r.OK {
		return false
	}
	message(stderr, contractPath, 0, 0, "tego init: the agent.yaml composed from these flags does not compile, so nothing was written; the diagnostics above say which entry to change (a --command not on PATH, a --write folder)", agent.CodeSchema)
	return true
}

// errorsOnly is the error diagnostics of ds.
func errorsOnly(ds []agent.Diagnostic) []agent.Diagnostic {
	var out []agent.Diagnostic
	for _, d := range ds {
		if d.IsError() {
			out = append(out, d)
		}
	}
	return out
}

// initCheckEnv is the machine a preset contract is checked against before init writes it: the one `tego compile
// --offline` compiles against (the machine config, its profiles, PATH, the home, the tiers this binary builds and the
// chain anchor), so a contract init writes compiles as compile would compile it. A machine config that cannot be read
// is Tego's own error, as it is for compile.
func initCheckEnv(stderr io.Writer) (setup.CheckEnv, int) {
	m, cds, err := loadMachine(config.TrustWarn)
	writeConfigDiagnostics(stderr, cds)
	if err != nil {
		message(stderr, "", 0, 0, "tego init: machine config: "+err.Error(), config.CodeUntrusted)
		return setup.CheckEnv{}, identity.ExitError // R25: Tego's own error (I/O on a config layer)
	}
	opts := []agent.CompileOption{agent.WithPATH(os.Getenv("PATH")), agent.WithClock(time.Now), agent.WithTiers(builtTiers()...)}
	if m.Home != "" {
		opts = append(opts, agent.WithHome(m.Home))
	}
	opts = append(opts, anchorCompileOptions(m)...)
	return setup.CheckEnv{Machine: m, Profiles: profileSources(m), Options: opts}, identity.ExitOK
}

// printPresetList is `tego init --list`: each preset with its revision and promise, and the host groups.
func printPresetList(stdout, stderr io.Writer) int {
	fmt.Fprintln(stdout, "presets (tego init --preset a,b,c; docs/user/presets.md):")
	for _, p := range presets.List() {
		fmt.Fprintf(stdout, "  %-17s %s@%d: %s\n", p.Name, p.Ref(), p.Revision, p.Promise)
	}
	gs, err := presets.HostGroups()
	if err != nil {
		message(stderr, "", 0, 0, "tego init: "+err.Error(), codeIO)
		return identity.ExitError // R25: Tego's own error
	}
	fmt.Fprintln(stdout, "host groups (--allow-host @group):")
	for _, g := range gs {
		fmt.Fprintf(stdout, "  @%-14s %s\n", g.Name, strings.Join(g.Hosts, " "))
	}
	fmt.Fprintln(stdout, "always on: no local daemon sockets (ADR 0070), no privilege escalation (no_new_privs)")
	return identity.ExitOK
}

// errForeign marks an existing file that tego init did not write.
var errForeign = errors.New("exists and was not written by tego init; re-run with --force to replace it")

// errInitDirTaken marks a .tego that is not a directory. --force replaces agent.yaml and nothing else, so the message
// offers no flag: errForeign's sent the reader round in a circle.
var errInitDirTaken = errors.New("exists and is not a directory; move it aside and run tego init again")

// agentNameFor derives an agent id from a directory name: lower-case, every other rune to '-',
// trimmed to 40, "agent" when nothing is left.
func agentNameFor(abs string) string {
	base := strings.ToLower(filepath.Base(abs))
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	if len(s) > 40 {
		s = strings.Trim(s[:40], "-")
	}
	if s == "" {
		return "agent"
	}
	return s
}

// ensureDir creates path (0700) when absent; reports whether it did.
func ensureDir(path string) (bool, error) {
	st, err := os.Stat(path)
	switch {
	case err == nil && st.IsDir():
		return false, nil
	case err == nil:
		return false, errInitDirTaken
	case !errors.Is(err, os.ErrNotExist):
		return false, fmt.Errorf("stat: %w", err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		return false, fmt.Errorf("mkdir: %w", err)
	}
	return true, nil
}

// planContract decides what init does with agent.yaml before anything is created, so a refusal
// leaves nothing behind, .tego/ included: write it when absent, leave an init-written one alone,
// and replace anything else (a foreign file, a symbolic link, a FIFO) only with force.
func planContract(path string, force bool) (write bool, err error) {
	existing, exists, err := readInitFile(path)
	switch {
	case !exists:
		return true, nil
	case force && (err == nil || errors.Is(err, errNotProjectFile)):
		return true, nil
	case err == nil && bytes.HasPrefix(existing, []byte(initMarker)):
		return false, nil
	case err == nil:
		return false, errForeign
	case errors.Is(err, errNotProjectFile):
		return false, fmt.Errorf("%w: %w", err, errForeign)
	}
	return false, err
}

// liveAdjustableBlock is what `tego init --live-mode adjustable` appends to the contract it writes (ADR 0125): the
// two modes in a line each, and an empty fence to fill.
const liveAdjustableBlock = `
# How this agent's rules change while it runs (docs/user/live-modes.md):
#   locked:     file, program and network rules are fixed when the run starts; tighten while it runs, loosen from the next run.
#   adjustable: the kernel enforces a wider fence; Tego's live layer enforces the rules inside it, so you can
#               loosen and tighten while it runs. Weaker if Tego fails; needs tier cgroup or bpflsm (root).
live:
  mode: adjustable
  fence:            # what you may grant while it runs; every entry starts refused
    read: []
    net: []
    exec: []
`

// withLiveMode is content as `--live-mode` makes it: unchanged under Locked; under Adjustable with
// liveAdjustableBlock appended and a `tier: landlock` line, which Adjustable is refused at, made `tier: cgroup`
// (pinned says so).
func withLiveMode(content []byte, live agent.LiveMode) (out []byte, pinned bool) {
	if live != agent.LiveAdjustable {
		return content, false
	}
	lines := strings.SplitAfter(string(content), "\n")
	for i, l := range lines {
		if rest, ok := strings.CutPrefix(l, "tier: landlock"); ok && (rest == "" || rest[0] == ' ' || rest[0] == '\n' || rest[0] == '#') {
			lines[i], pinned = "tier: cgroup"+rest, true
		}
	}
	s := strings.Join(lines, "")
	if !strings.HasSuffix(s, "\n") {
		s += "\n"
	}
	return []byte(s + liveAdjustableBlock), pinned
}

// writeContractBytes publishes a contract atomically. Without force, linking the completed temporary file
// refuses an existing destination, including one created after planContract; a filesystem with no hard links
// gets renameat2(RENAME_NOREPLACE), with the same answer. With force, a rename replaces
// a symbolic link itself rather than the file it leads to.
func writeContractBytes(path string, content []byte, force bool) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".agent.yaml.*")
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, err = tmp.Write(content)
	if err == nil {
		err = tmp.Chmod(0o644)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		if force {
			err = os.Rename(tmp.Name(), path)
		} else {
			err = linkContract(tmp.Name(), path)
			if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.ENOSYS) {
				// No hard links here (vfat, exFAT, vboxsf; some FUSE and network mounts): rename without
				// replacing, as ledger.PlaceNewFileThen does, so the destination is still refused if it exists.
				err = unix.Renameat2(unix.AT_FDCWD, tmp.Name(), unix.AT_FDCWD, path, unix.RENAME_NOREPLACE)
			}
			if errors.Is(err, os.ErrExist) {
				return errForeign
			}
		}
	}
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// linkContract is os.Link; a test stands in a filesystem with no hard links.
var linkContract = os.Link

// errNotProjectFile marks an agent.yaml or .gitignore that is a symbolic link or not a regular file.
// Init writes only a file it can see is the project's own: a link there may lead anywhere, outside
// the project (a cloned repository's .gitignore linked to ~/.bashrc), and a FIFO would hang init.
var errNotProjectFile = errors.New("is a symbolic link or not a regular file")

// readInitFile reads a file init may write, without following a final symbolic link and without
// blocking on a FIFO: exists is false when there is nothing at path.
func readInitFile(path string) (data []byte, exists bool, err error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, false, nil
	case errors.Is(err, syscall.ELOOP):
		return nil, true, errNotProjectFile
	case err != nil:
		return nil, true, fmt.Errorf("read: %w", err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, true, fmt.Errorf("read: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, true, errNotProjectFile
	}
	data, err = io.ReadAll(io.LimitReader(f, maxInitFile+1))
	if err != nil {
		return nil, true, fmt.Errorf("read: %w", err)
	}
	if len(data) > maxInitFile {
		return nil, true, fmt.Errorf("read: larger than %d bytes", maxInitFile)
	}
	return data, true, nil
}

// maxInitFile bounds what init reads of agent.yaml or .gitignore: a contract is at most
// agent.MaxContractSize, and a .gitignore that large is no hand-written one.
const maxInitFile = 4 << 20

// ensureLine appends line to the file (creating it) unless an identical line is present.
func ensureLine(path, line string) (bool, error) {
	existing, _, err := readInitFile(path)
	if err != nil {
		return false, err
	}
	for _, l := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(l) == line {
			return false, nil
		}
	}
	// O_NOFOLLOW and O_NONBLOCK again: the file may have been swapped since the read (a FIFO then
	// fails with ENXIO rather than waiting for a reader).
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o644)
	if err != nil {
		return false, fmt.Errorf("open: %w", err)
	}
	defer func() { _ = f.Close() }()
	prefix := ""
	if len(existing) > 0 && !bytes.HasSuffix(existing, []byte("\n")) {
		prefix = "\n"
	}
	if _, err := fmt.Fprintf(f, "%s%s\n", prefix, line); err != nil {
		return false, fmt.Errorf("write: %w", err)
	}
	return true, nil
}
