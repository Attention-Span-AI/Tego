// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"

	"net/netip"
	"os"

	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/attention-span-ai/tego/internal/ledger"

	"github.com/attention-span-ai/tego/internal/platform/startphase"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"

	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/pkg/policy/gate"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// createCgroup is §4.1 step 2: one cgroup per run, limits written before any process exists (R19).
func (r *runner) createCgroup() error {
	if r.deps.Cgroups != nil {
		r.cgm = r.deps.Cgroups
	} else {
		uid, _ := config.InvokingUID()
		m, err := cgroup.Detect(uid)
		if err != nil {
			return fmt.Errorf("runtime: cgroup: %w", err)
		}
		// Detect's subtree can be one this process may manage and still not place the agent in (a login
		// over ssh, a service): refused here, before anything is made, rather than by clone3 once the
		// scope exists (runtime-launch.md case 41).
		if err := m.CanPlace(); err != nil {
			return fmt.Errorf("runtime: cgroup: %w", err)
		}
		r.cgm = m
	}
	cg, err := r.cgm.Create(string(r.agentID), string(r.id))
	if err != nil {
		return fmt.Errorf("runtime: create cgroup: %w", err)
	}
	r.cg = cg
	limits, err := cgroup.FromResolved(r.rt.Limits)
	if err != nil {
		return fmt.Errorf("runtime: limits: %w", err)
	}
	if err := r.cgm.SetLimits(cg, limits); err != nil {
		return fmt.Errorf("runtime: set limits: %w", err)
	}
	r.checkSwapCap(cg, limits)
	if id, err := r.cgm.ID(cg); err == nil {
		r.cg.ID = id
	} else {
		r.log.Warn("runtime: cgroup id unknown", "err", err)
	}
	// The oom and pids counters' baseline is read here, while the cgroup holds no process, and not
	// when watchCgroup starts: that is after the ack, and an agent that meets pids.max in its first
	// milliseconds would already be counted in a later baseline and never read as over it, ending
	// with its own exit status instead of reason=pids (R11).
	if oom, pids, err := cgroup.ReadLimitEvents(r.cg); err == nil {
		r.limitBase.oom, r.limitBase.pids, r.limitBase.ok = oom, pids, true
	}
	return nil
}

// prepareEnforcement is §4.1 step 3: the backend opens its O_PATH fds and builds the ruleset or maps
// for this run, then binds whatever is cgroup-keyed (a no-op in tier 1).
func (r *runner) prepareEnforcement(ctx context.Context) error {
	mount, rel := splitCgroupPath(r.cg.Path)
	rows := r.rowsTable()
	r.rowsNet = rows.Net
	ref := enforce.RunRef{
		ID: string(r.id), Agent: string(r.agentID), CgroupID: r.cg.ID, RunDir: r.dir,
		Contract:    filepath.Join(r.dir, ledger.ContractFile),
		CgroupMount: mount, CgroupPath: rel,
		// The tier's own producers write to the run's queue from the moment Prepare returns: tier 2's
		// fanotify listener refuses opens and execs and reports every §7 gap there, and with no sink it
		// refused in the kernel and recorded nothing (enforce.RunRef.Events). The queue is live before
		// the pipeline runs; what it holds waits for run_start, as every producer's events do.
		Events: r.runQueue().Lane(LaneListener),
		// Tier 2 decides every connect the supervisor relays, so its port-53 rows have to name the servers
		// the supervisor's exception names: the same list, read once (enforce-cgroup-observe §5 R5).
		Resolvers: r.runResolvers(),
		// The binary the launcher execs as the child stage: tier 2 execs it again for its detached helpers
		// (linger, ring trim). The stage's own exec is never the tier's to decide: the tier arms after it
		// (arm, ADR 0021 (2)).
		StageExe: r.stageExe(),
		Log:      r.log,
	}
	// A root launch's child drops to the invoking user, so a write directory the tier creates for the run is
	// made as that user (enforce.RunRef.Drop): root's, it would refuse the agent every create in it. A target
	// that cannot be named refuses the run here, before the tier creates anything, with the error childSpec
	// would give.
	if os.Geteuid() == 0 {
		tuid, tgid, terr := dropTarget()
		if terr != nil {
			return terr
		}
		ref.Drop, ref.DropUID, ref.DropGID = true, tuid, tgid
	}
	endEnforce := startphase.Begin(nil, "enforce.prepare")
	h, err := r.deps.Enforce.Prepare(ctx, rows, ref)
	endEnforce()
	if err != nil {
		return fmt.Errorf("runtime: prepare %s: %w", r.deps.Enforce.Tier(), err)
	}
	r.handle = h
	// A tier whose handle owns a loop (tier 2's fanotify listener) starts it first, before anything else
	// this process does. Its permission marks are placed only at the arming point (arm), but they cover
	// whole mounts, so from then on an open on a marked mount by any process, this launcher included, waits
	// for this loop's answer, and the loop must already be answering. The loop stops when the run does,
	// because it runs in the run's own group like every other worker; a tier without one starts nothing.
	if l, ok := h.(api.Listener); ok {
		r.group.Go("enforce-listener", func() error { return l.RunListener(ctx) })
	}
	// run_start.bpf_hash names the pins this run's programs live in, and a tier with none has none.
	r.deps.Build.BPFHash = ""
	if kr, ok := h.(enforce.KernelRecorder); ok {
		r.deps.Build.BPFHash = kr.BPFHash()
	}
	r.startKernelRecord(h)
	r.usePlaneFilter(h)
	// attach is the tier's cgroup links (tier 2's network programs, cgroup/sock_create and cgroup/setsockopt among
	// them, each pinned), timed apart so the perf suite's warm start shows what a link more or less costs.
	endAttach := startphase.Begin(nil, "attach")
	err = h.Attach(r.cg.ID)
	endAttach()
	if err != nil {
		return fmt.Errorf("runtime: attach %s: %w", r.deps.Enforce.Tier(), err)
	}
	if err := r.requireNetworkAssurance(); err != nil {
		return err
	}
	return r.requireExecAssurance()
}

// usePlaneFilter tells a tier whose decision plane decides fs mutations in the kernel that the run's kernel recorder
// will write their lines, so its filter may stop notifying them (enforce.PlaneFilterer; enforce-plane R27, ADR 0024
// (14): the producer table live). The recorder must also name such an action by its path on its own
// (PathHookNamer): without the supervisor's naming a path hook's record in a directory its index does not hold is
// named dev:ino/name under no rule (enforce-plane §2.13's condition 1), so a recorder that does not say so keeps
// every notification, and the supervisor names and refuses as before. observe.Recorder says so from the kernel's
// directory walk (enforce-plane §2.15). Called after startKernelRecord and before the child stage takes the
// filter.
//
// An Adjustable run keeps the full filter (ADR 0125 decision 6): its live layer refuses fence entries the kernel
// layers allow, so no open, connect or exec may be decided where the supervisor cannot see it.
func (r *runner) usePlaneFilter(h api.Handle) {
	if r.rt != nil && (r.rt.Gate.Has(gate.FSRead) || r.rt.Gate.Has(gate.FSWrite) || r.rt.Adjustable()) {
		return
	}
	nm, ok := r.kernelRecord.(PathHookNamer)
	if !ok || !nm.NamesPathHooks() {
		return
	}
	if pf, ok := h.(enforce.PlaneFilterer); ok {
		r.planeFS = len(pf.UsePlaneFilter()) > 0
	}
}

// PathHookNamer is a kernel recorder that names every path-hook record (unlink, rmdir, mkdir, mknod, symlink, link,
// rename, truncate, an O_CREAT create) by its full path on its own, with no naming handed over by the supervisor.
// Only then may the filter leave those actions unnotified (usePlaneFilter). observe.Recorder does, for a run a plane
// mode decides, by the parent directory's path the trace object walks in the kernel (enforce-plane §2.15).
type PathHookNamer interface {
	NamesPathHooks() bool
}

// DeputySkipper is a kernel recorder that drops the records of the run's open deputy (ADR 0041 D2), named by its pid
// and its start time as /proc reads it (0 for unknown): the supervisor writes the line of every open the deputy makes
// (supervisor.md R7a). observe.Recorder is one.
type DeputySkipper interface {
	SetSkipProcess(pid uint32, startNS uint64)
}

// runResolvers is the run's one resolver list, read the first time anything asks for it: prepareEnforcement
// hands it to the tier and startNotifyLoop to the supervisor's resolver set. Reading /etc/resolv.conf once for
// each would let an edit between the two reads give the kernel and the supervisor different servers, and the
// kernel would then refuse (EPERM) a query the supervisor admitted and the ledger recorded allowed.
func (r *runner) runResolvers() []netip.AddrPort {
	if !r.rt.DNS.SystemResolvers() {
		return nil // agent DNS transport has no implicit system-resolver grant
	}
	if !r.resolversRead {
		r.resolvers, r.resolversRead = r.resolverEndpoints(), true
	}
	return r.resolvers
}

// stageExe is the binary the launcher execs as the child stage: the caller's Launcher.Exe, or "" for the
// default, /proc/self/exe (launch.Launcher).
func (r *runner) stageExe() string {
	if r.deps.Launcher != nil {
		return r.deps.Launcher.Exe
	}
	return ""
}

// runQueue is the run's one event queue, made the first time anything asks for it: prepareEnforcement
// hands it to the tier as RunRef.Events before startWorkers drains it into the pipeline, and both must
// name the same queue or the tier's events go to one nothing reads.
func (r *runner) runQueue() *Queue {
	if r.queue == nil {
		r.queue = NewQueue(QueueCapacity)
	}
	return r.queue
}

// splitCgroupPath separates an absolute run cgroup path into the cgroup2 mount point and the path
// relative to it, which is how tier 2 addresses the run. A path that is not under the standard mount is
// returned whole as the relative half, leaving the backend to fall back to its own default mount.
func splitCgroupPath(abs string) (mount, rel string) {
	const std = "/sys/fs/cgroup"
	if abs == "" {
		return "", ""
	}
	if strings.HasPrefix(abs, std) {
		rel = strings.TrimPrefix(abs, std)
		if rel == "" {
			rel = "/"
		}
		return std, rel
	}
	return "", abs
}

// createRuntimeDir makes the run's tmpfs directory (§4.1 step 3, before Prepare; §3): the run's own CODEX_HOME when
// the forwarder has an openai listener (writeCodexHome, capture-derive.md R19b). No socket lives here in
// this build: the forwarder listens on loopback TCP and the ask broker binds ask.SocketName in the
// ledger run directory. It is removed by the shutdown sequence, or, when the launcher died before it, by the next
// launch under the same parent (sweepRuntimeParent). It runs before Prepare, since the CODEX_HOME
// is a write grant every backend builds with (grantCodexHome, agent-contract.md R10a).
//
// A machine with no XDG_RUNTIME_DIR (or a relative one) gets no directory. That is no error for a run with no
// openai listener; for one with a listener, where Codex is to be routed through the forwarder, it is refused
// (ErrNoRuntimeDir, exit 125, naming the fix): the run used to go on with Codex unrouted and say nothing, and
// Codex then failed for want of a state directory it could write (Codex POC F2).
//
// A table that lets the agent write tego's runtime parent, or inside another run's directory there, is refused
// before anything is made (checkRuntimeParent), as compile refuses it (R10a): compile may have been given another
// environment. Every parent config.RuntimeDirBases names is checked, at every euid and whatever XDG_RUNTIME_DIR
// says: the invoking user's logind directory /run/user/<uid>/tego always, where the same user's other runs keep
// theirs, and $XDG_RUNTIME_DIR/tego when it names another. Once only $XDG_RUNTIME_DIR/tego was, and after the
// root and no-variable returns below, so under plain sudo, cron or ssh without pam_systemd a write entry over
// /run/user/<uid>/tego ran and rewrote another run's CODEX_HOME and refusal mirror.
//
// A root launcher makes none, and a root run with an openai listener runs with Codex unrouted: the gap
// codex-unrouted after run_start says so (emitCodexUnroutedGap); it fails closed, since the models[] guard refuses
// Codex's own calls to the model (E27). Refusing it was rejected: the openai listener serves every OpenAI SDK that
// reads OPENAI_BASE_URL, which a root run routes, and only Codex needs the CODEX_HOME.
//
// XDG_RUNTIME_DIR reaches root from the invoking user's environment (sudo -E, an env_keep entry), so the path
// names a directory that user controls. os.MkdirAll follows symlinks there and os.RemoveAll then removes through
// the same path, which is root writing and deleting where a user points it: the pattern the ledger root's walk (ledger/handover.go) and the doctor cache exist to
// avoid. Nothing needs the directory under root: CODEX_HOME is never written for a root run
// (writeCodexHome), and the ask socket is <ledger run dir>/ask.sock, mode 0600 and chowned to the
// invoking UID under a root launcher (ADR 0008, amended 2026-10-05; this said /run/tego).
func (r *runner) createRuntimeDir() error {
	for _, b := range runtimeDirBases() {
		if err := checkRuntimeParent(r.rt, filepath.Join(b, agent.RuntimeDirName)); err != nil {
			return err
		}
	}
	base := os.Getenv("XDG_RUNTIME_DIR")
	if os.Geteuid() == 0 {
		return nil
	}
	if !filepath.IsAbs(base) {
		if r.forwarderVars()[envOpenAIBaseURL] != "" {
			return fmt.Errorf("%w: XDG_RUNTIME_DIR is %s, and the run's Codex is routed through the forwarder by a CODEX_HOME under it (capture-derive.md R19b): "+
				"log in through a session that sets it (systemd-logind sets XDG_RUNTIME_DIR=/run/user/%d), or export XDG_RUNTIME_DIR as an absolute directory only you can write, "+
				"or remove the openai endpoint from the contract's models list", ErrNoRuntimeDir, unsetOr(base), os.Getuid())
		}
		return nil
	}
	// A path another user could change before Prepare opens the CODEX_HOME under it is refused for a routed Codex,
	// and leaves a run without one with no runtime directory, as an unset variable does.
	unsafe := func(err error) error {
		if r.forwarderVars()[envOpenAIBaseURL] != "" {
			return err
		}
		r.log.Warn("runtime: no runtime directory, so no last-refusal mirror (TEGO_REASON)", "err", err)
		return nil
	}
	if err := privateRuntimeDirs(base); err != nil {
		return unsafe(err)
	}
	parent := filepath.Join(base, agent.RuntimeDirName) // checked against the table above (runtimeDirBases)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("runtime: create run socket dir: %w", err)
	}
	if err := privateRuntimeDirs("", parent); err != nil {
		return unsafe(err)
	}
	// A launcher killed before its shutdown left its directory, CODEX_HOME and auth.json included, until logout: each
	// launch removes those whose run holds no lock any more (sweepRuntimeParent).
	sweepRuntimeParent(parent, r.log)
	dir, lock, err := makeRunRuntimeDir(parent, string(r.id))
	if err != nil {
		return err
	}
	r.runtimeDir, r.runtimeLock = dir, lock
	if err := privateRuntimeDirs("", dir); err != nil {
		return err // made just now, 0700, by this euid: another owner or mode is a race, refused whatever the run
	}
	// The run's last refusal is mirrored here, where the agent can read it, since the ledger root is
	// read-denied to it (agent-contract.md R6a); TEGO_REASON names the file (REASON-CHANNEL §2). A mirror
	// that cannot be set up costs the harness that channel, not the run.
	if r.writer != nil {
		if err := r.writer.MirrorLastRefusal(dir); err != nil {
			r.log.Warn("runtime: last-refusal mirror", "dir", dir, "err", err)
		} else {
			r.reasonFile = filepath.Join(dir, ledger.LastRefusalFile)
		}
	}
	if err := r.writeCodexHome(); err != nil {
		return err
	}
	return r.grantCodexHome()
}

// ErrNoRuntimeDir is a run whose Codex is to be routed through the forwarder (an openai listener) on a launcher
// with no absolute XDG_RUNTIME_DIR, where its CODEX_HOME would live: refused before run_start, exit 125.
var ErrNoRuntimeDir = errors.New("runtime: no runtime directory for the run's CODEX_HOME")

// ErrRuntimeDirWritable is a table whose write or ask entry covers tego's runtime parent or lies inside it
// (agent-contract.md R10a): refused before run_start, exit 125.
var ErrRuntimeDirWritable = errors.New("runtime: tego's runtime directory is inside a write entry")

// ErrCodexHomeExecutable is a run whose CODEX_HOME grant would land inside an exec directory entry, so the agent
// could run what it writes there (agent-contract.md R10a, E38): refused before run_start, exit 125.
var ErrCodexHomeExecutable = errors.New("runtime: the run's CODEX_HOME is inside an exec directory entry")

// ErrRuntimeDirUnsafe is a runtime directory another user could swap: $XDG_RUNTIME_DIR writable by group or others
// without the sticky bit, or $XDG_RUNTIME_DIR/tego or the run's directory under it not a directory of this user's
// that only it can write (agent-contract.md R10a): refused before run_start, exit 125.
var ErrRuntimeDirUnsafe = errors.New("runtime: the runtime directory is not private to this user")

// privateRuntimeDirs refuses a runtime directory whose path another user could change before Prepare opens the
// CODEX_HOME under it: base (followed, it may be a link) must not be writable by group or others
// unless it is sticky, as /tmp is, where only an entry's owner can rename it; each of dirs, not followed, must be a
// directory owned by this euid and writable by no one else. A link there, or a directory of another user, is refused
// rather than written through. An empty base is not checked.
func privateRuntimeDirs(base string, dirs ...string) error {
	if base != "" {
		fi, err := os.Stat(base)
		if err != nil {
			return fmt.Errorf("runtime: runtime directory: %w", err)
		}
		if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("%w: XDG_RUNTIME_DIR %s is writable by group or others (mode %v) without the sticky bit, so another user could replace tego's directory in it; "+
				"export XDG_RUNTIME_DIR as an absolute directory only you can write", ErrRuntimeDirUnsafe, base, fi.Mode().Perm())
		}
	}
	for _, d := range dirs {
		fi, err := os.Lstat(d)
		if err != nil {
			return fmt.Errorf("runtime: runtime directory: %w", err)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !fi.IsDir() || !ok || int(st.Uid) != os.Geteuid() || fi.Mode().Perm()&0o022 != 0 {
			uid := -1
			if ok {
				uid = int(st.Uid)
			}
			return fmt.Errorf("%w: %s is not a directory of uid %d that only it can write (mode %v, owner %d); "+
				"remove it, or export XDG_RUNTIME_DIR as an absolute directory only you can write", ErrRuntimeDirUnsafe, d, os.Geteuid(), fi.Mode(), uid)
		}
	}
	return nil
}

// logindRuntimeRoot is config.LogindRuntimeRoot, where systemd-logind makes each user's XDG_RUNTIME_DIR,
// /run/user/<uid>. A variable so this package's tests can point it into their own directory; nothing in a product
// build reassigns it.
var logindRuntimeRoot = config.LogindRuntimeRoot

// runtimeDirBases is config.RuntimeDirBases under logindRuntimeRoot: the parents R10a protects, which every compile
// of the run's contract named to agent.WithRuntimeDir (tego compile, run and rule, and the dashboard's rule service),
// so the launcher checks the very list the compile did, not a copy of it.
func runtimeDirBases() []string { return config.RuntimeDirBasesUnder(logindRuntimeRoot) }

func unsetOr(v string) string {
	if v == "" {
		return "not set"
	}
	return strconv.Quote(v) + ", not an absolute path"
}

// checkRuntimeParent refuses a table whose write or ask entry is tego's runtime parent, holds it, or lies inside
// it, where every run keeps its private directory: a grant there reached every other run's CODEX_HOME and
// last-refusal mirror (Codex POC F2). Compile refuses the same entries (agent-contract.md R10a); this is the
// launcher's own check, on the parent this run really uses, by declared and resolved spellings on both sides.
func checkRuntimeParent(rt *agent.RuleTable, parent string) error {
	if rt == nil {
		return nil
	}
	spellings := []string{filepath.Clean(parent)}
	if res, err := filepath.EvalSymlinks(parent); err == nil && res != spellings[0] {
		spellings = append(spellings, res)
	}
	for _, rules := range [][]agent.FSRule{rt.FS, rt.FSAsk} {
		for _, f := range rules {
			if (f.Kind != agent.FSWrite && f.Kind != agent.FSAsk) || f.Runtime != "" {
				continue
			}
			for _, e := range f.Spellings() {
				for _, p := range spellings {
					if agent.Covers(e, p) || agent.Covers(p, e) {
						return fmt.Errorf("%w: fs.%s %s covers or lies inside %s, where every run keeps its private directory [%s]; "+
							"the run grants its own CODEX_HOME there by itself (fs.codex_home)", ErrRuntimeDirWritable, f.Kind, rawOr(f.Raw, f.Path), p,
							identity.CodeContradiction)
					}
				}
			}
		}
	}
	return nil
}

// same reports whether p, not followed if it is a link, is the directory id names.
func (id fileID) same(p string) error {
	fi, err := os.Lstat(p)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || uint64(st.Dev) != id.dev || st.Ino != id.ino {
		return fmt.Errorf("%s is no longer the directory the run made", p)
	}
	return nil
}

// execOverCodexHome refuses a table with an exec directory entry, allowed or asked, that covers the run's CODEX_HOME,
// by declared and resolved spellings on both sides.
func execOverCodexHome(rt *agent.RuleTable, home, resolved string) error {
	return execOverGrant(rt, ErrCodexHomeExecutable, "CODEX_HOME", home, resolved)
}

// execOverGrant refuses, with sentinel, a table with an exec directory entry, allowed or asked, that covers home, a
// directory the run grants the agent for writing on its own authority (what names it), by declared and resolved
// spellings on both sides.
func execOverGrant(rt *agent.RuleTable, sentinel error, what, home, resolved string) error {
	for _, e := range rt.Exec {
		if !e.IsDir || e.Verdict == agent.VerdictRefused {
			continue
		}
		for _, s := range []string{e.Path, e.Resolved} {
			if s == "" {
				continue
			}
			for _, p := range []string{home, resolved} {
				if agent.Covers(s, p) {
					return fmt.Errorf("%w: %s %s covers %s, the run's own %s, which the agent may write, so every file it creates there would be executable [%s]; "+
						"list the individual binaries instead of the directory, or name one outside %s", sentinel, e.Source, rawOr(e.Raw, e.Path), p, what,
						identity.CodeContradiction, filepath.Dir(filepath.Dir(p)))
				}
			}
		}
	}
	return nil
}

func rawOr(raw, p string) string {
	if raw != "" {
		return raw
	}
	return p
}

// grantCodexHome adds the run's own CODEX_HOME to the table as a write grant the runtime makes on its own authority
// (agent.CodexHomeGrant, rule fs.codex_home[<path>]), the way a capture listener is admitted (admitLoopback): Codex
// keeps its state there (sqlite databases, sessions, its tmp/arg0 links), and no contract can name the directory,
// whose path holds the run id. Exactly that directory, never its parent: a contract that granted
// $XDG_RUNTIME_DIR/tego/ instead reached every other run's (Codex POC F2, agent-contract.md R10a). The compiled
// table is never mutated (agent.RuleTable I4): a new one is built, before Prepare, so every backend and the
// supervisor build with it. run_start lists it in runtime_grants. A no-op when no CODEX_HOME was written.
//
// The agent can rewrite the config.toml there, tego's openai_base_url included; that routes nothing around the
// forwarder, since under capture: forwarder the models[] guard refuses a model's own addresses whatever net.allow
// says (agent-contract.md E27, capture-derive.md R38).
//
// The path is granted only while it, and its resolved spelling, still name the directory writeCodexHome made (no
// link, the same device and inode): a process able to swap it for a link between the two would otherwise have the
// grant land where it pointed. And it is refused (ErrCodexHomeExecutable) when an exec.allow or
// exec.ask directory entry covers it, which would make every file the agent writes there executable: compile's
// exec-writable check sees only declared write entries.
func (r *runner) grantCodexHome() error {
	if r.codexHome == "" {
		return nil
	}
	resolved, err := filepath.EvalSymlinks(r.codexHome)
	if err != nil {
		return fmt.Errorf("runtime: codex home: %w", err)
	}
	for _, p := range []string{r.codexHome, resolved} {
		if err := r.codexHomeID.same(p); err != nil {
			return fmt.Errorf("runtime: codex home: %w", err)
		}
	}
	if err := execOverCodexHome(r.rt, r.codexHome, resolved); err != nil {
		return err
	}
	out := *r.rt
	out.FS = append(slices.Clone(r.rt.FS), agent.FSRule{
		Path: r.codexHome, Resolved: resolved, Kind: agent.FSWrite, Access: agent.AccessWriteSet,
		Runtime: agent.CodexHomeGrant, RuntimeDev: r.codexHomeID.dev, RuntimeIno: r.codexHomeID.ino,
	})
	r.rt = &out
	return nil
}

// runtimeOwnState is $XDG_RUNTIME_DIR/tego, the parent of every run's runtime directory (createRuntimeDir), by its
// spelling and by its resolved path where that differs: tego's own state the compiled table does not name, which
// the supervisor refuses a person's alternate from (supervisor Options.OwnState, ADR 0057 D2). Nil when the
// variable is unset or not absolute. It is read under a root launcher too, which makes no such directory: a refusal
// there costs nothing.
func runtimeOwnState() []string {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" || !filepath.IsAbs(base) {
		return nil
	}
	dir := filepath.Join(base, "tego")
	out := []string{dir}
	if real, err := filepath.EvalSymlinks(base); err == nil {
		if r := filepath.Join(real, "tego"); r != dir {
			out = append(out, r)
		}
	}
	return out
}
