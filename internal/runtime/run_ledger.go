// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ErrRunDirWritable is returned before anything is created when the run directory would sit inside a
// declared write entry: the agent could then rewrite its own record (agent.Compile refuses this as a
// contradiction, and the facade re-checks it because the ledger root is a machine setting the
// contract never saw).
var ErrRunDirWritable = errors.New("runtime: run directory is inside a write entry")

// ErrLedgerRootHome is a "~/" ledger_root this process may not expand: the passwd database names no
// home for the invoking uid (identity-config.md E9) and $HOME may not stand in for it, because the
// binary was executed with AT_SECURE set — the one environment variable spec/config/v0's Trust
// section exists to neutralise, and this resolver decides where the audit ledger is written and
// where `gc` deletes. Returned before any directory is created.
var ErrLedgerRootHome = errors.New("runtime: ledger_root needs a home the passwd database does not name")

// mintRunAttempts is how many run ids mintRun tries before it gives up: the first and up to three retries,
// each with a fresh read of the random source, when the run directory's mkdir finds the path taken
// (identity-config.md R2b). identity itself stays stateless; the retry is the caller's.
const mintRunAttempts = 4

// launcherStartBootNS is StartBootNS; a test replaces it to make the launcher's own start time unreadable.
var launcherStartBootNS = StartBootNS

// mintRun assigns the run id and creates its directory (§4.1 step 1). The directory must not exist
// (cases 1 and 16: a collision or a symlink at that path is never reused, followed or overwritten). A path
// already taken (EEXIST) is retried under a fresh id up to three times, and then the run fails with that
// EEXIST error, which exits 125 (identity-config.md R2b).
func (r *runner) mintRun() error {
	root, err := LedgerRoot(r.deps.Config)
	if err != nil {
		return err
	}
	// The lock file names this launcher by pid and start time, and a start time of 0 turns off the check that
	// keeps `tego stop` and the sweep from taking a reused pid for it (OpenStopTargetFor). A launcher that cannot
	// say when it started is refused before any run directory exists.
	start, err := launcherStartBootNS(os.Getpid())
	if err != nil {
		return fmt.Errorf("runtime: launcher start time unreadable: %w", err)
	}
	if start == 0 {
		return errors.New("runtime: launcher start time unreadable: /proc reports 0")
	}
	var id identity.RunID
	var dir string
	for attempt := 1; ; attempt++ {
		id, err = identity.NewRunID(hostID(r.deps.MachineID), r.deps.Clock.Now(), r.deps.Rand)
		if err != nil {
			return fmt.Errorf("runtime: mint run id: %w", err)
		}
		dir = identity.RunDir(root, id)
		if err := checkRunDir(r.rt, dir); err != nil {
			return err
		}
		// MakeRunDir creates the ledger root as MakeDirs does — handing what a root launcher makes in the
		// user's home (~/.tego, ~/.tego/runs) to that user, so their own unprivileged runs can still
		// create a run directory there, and refusing, as root, a link the user could have planted — and
		// then the run directory inside the ledger root it walked (ledger/handover.go, record-ledger.md §3).
		err = ledger.MakeRunDir(root, filepath.Base(dir))
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("runtime: create run dir: %w", err)
		}
		if attempt == mintRunAttempts {
			return fmt.Errorf("runtime: could not allocate a unique run id after %d attempts: %w", attempt, err)
		}
		r.log.Warn("runtime: run directory path already taken; minting another run id",
			"taken", string(id), "attempt", attempt)
	}
	r.id = id
	// Every line this run logs from here on carries run=<id> (OPERATIONS.md "Logs of tego itself"),
	// including the supervisor's, the ledger's and the budget watcher's, which are all handed this
	// logger after this point: the own log is shared by every run on the machine.
	r.log = r.log.With("run", string(id))
	r.dir = dir
	// A root launcher records that it launched this very directory, where root alone can write: a sweep looks
	// under the cgroup mount root for the scope of a run directory it does not own only on that record (sweep.go
	// orphanRoots, R20). Without it the run still runs; once its directory is handed over, only a sweep of
	// root's own finds its scope, as before any record existed.
	if os.Geteuid() == 0 {
		if err := writeRootMark(r.dir, string(id)); err != nil {
			r.log.Warn("runtime: record the root launch; a sweep of the handed-over run will not find its scope", "err", err)
		} else {
			r.rootMarked = true
		}
	}
	r.launcherStart = start
	return nil
}

// openLedger opens the run's ledger, which takes the run lock (§4.1 step 1, R1), and records who
// holds it for `tego stop` (R22).
func (r *runner) openLedger() error {
	// WithFreshRunDir: the directory opened must be the one mintRun just made, this process's own and
	// empty, and the Writer then holds it by descriptor for the whole run (record-ledger.md §3).
	w, err := ledger.Open(r.dir, record.RunRef{ID: string(r.id), Agent: string(r.agentID)},
		ledger.WithAnchor(&gatedAnchor{inner: ledger.NewFileChainAnchor(r.anchorFile()), started: &r.anchored}),
		ledger.WithClock(ledgerClock{r.deps.Clock}),
		ledger.WithContract(r.deps.ContractYAML),
		ledger.WithLogger(r.log),
		ledger.WithFreshRunDir())
	if err != nil {
		return fmt.Errorf("runtime: open ledger: %w", err)
	}
	r.writer = w
	if err := writeLockInfo(w, LockInfo{PID: os.Getpid(), StartBootNS: r.launcherStart, PIDNS: ownPIDNS()}); err != nil {
		return err
	}
	// The run is listed in the ledger root's live index while it holds its lock and before run_start, and
	// stays listed until run_end is written (clearLive): `run` and `stop` sweep only the runs the index
	// names, so a run that can be lost must be in it from before its first line (record-ledger.md §3).
	if err := markLive(filepath.Dir(r.dir), string(r.id)); err != nil {
		return fmt.Errorf("runtime: %w", err)
	}
	r.listed = true
	return nil
}

// markLive is ledger.MarkLive, a variable so a test can see what the run holds when it is listed, and make
// listing fail.
var markLive = ledger.MarkLive

// clearLive takes the run out of the live index once the ledger's Close has run: ledger.ClearLive keeps
// the entry of a run that does not read as ended, which is then the next sweep's to end. A failure is
// logged, never the run's: the next sweep clears an entry whose run has ended.
func (r *runner) clearLive() {
	if !r.listed {
		return
	}
	if err := ledger.ClearLive(filepath.Dir(r.dir), string(r.id)); err != nil {
		r.log.Warn("run: clear the live index entry", "err", err)
	}
}

// kernelCwd is this process's working directory as getcwd(2) reports it, every symlink resolved, or "" when it has no
// name (deleted, or outside this mount namespace). The paths on a run's lines come from the kernel in that same form
// (supervisor.md R6). os.Getwd answers $PWD whenever $PWD names that directory, which spells it through a symlink for
// a project reached through one (a /home that links to /var/home), and run_start then named a directory no line was
// under: tego learn proposed fs.write: [] with every write "outside the workspace", and tego receipt lost its relative
// paths.
func kernelCwd() string {
	wd, err := unix.Getwd()
	if err != nil {
		return ""
	}
	return wd
}

// writeRunStart is §4.1 step 9: the first line of the ledger, carrying everything a reader needs to
// interpret the rest without re-running the compiler (spec/record/v1 run_start).
func (r *runner) writeRunStart() error {
	cwd := r.deps.Cwd
	if cwd == "" {
		cwd = kernelCwd()
	}
	// One reading of what started feeds both capture and the capability line's capture row, so the line
	// can never say one thing and the field beside it another.
	capture := r.captureMode()
	start := record.RunStartPayload{
		LauncherPID: os.Getpid(), LauncherStartNS: r.launcherStart,
		TegoVersion: r.deps.Build.Version, Commit: r.deps.Build.Commit, BPFHash: r.deps.Build.BPFHash,
		Tier: string(r.deps.Enforce.Tier()), Capture: capture, Kernel: r.deps.Build.Kernel,
		ContractHash: hex.EncodeToString(r.rt.Hash[:]), Parsers: r.runParsers(capture),
		StopGrace: r.stopGrace.String(), Command: r.cmd, Cwd: cwd,
		Limits: runLimits(r.rt.Limits, r.ledgerCeiling()), Capabilities: r.capabilityLine(capture),
		NetAssurance: string(r.rt.NetworkAssurance()), NetGuarantees: r.networkGuaranteeLine(),
		Stdio: stdioRecord(r.deps.Stdio), RunCommandGrant: r.rt.RunCommandGrant,
		RecordMinor: launchMinor, DecisionPlane: r.decisionPlane(),
		// The run's disclosed best-effort cells (ADR 0041 D7): gate decisions on copied syscall facts that are
		// continued, never counted as enforced, and the built-in deny_write set where no plane decides this run
		// (D1 (a)), read from the tier and plane that really run.
		BestEffort: r.rt.BestEffortCellsRun(r.deps.Enforce.Tier(), r.decisionPlane(), r.deputy != nil, r.execPinned()),
		// The built-in deny_read entries the contract's fs.ask_read entries relax (ADR 0057 D4).
		AskReadRelaxes: askReadRelaxes(r.rt.AskReadRelaxes),
		// The grants the run made on its own authority (agent-contract.md R10a): the contract hash does not cover
		// them, so this is where a reader learns of them, as of run_command_grant.
		RuntimeGrants: append(runtimeGrants(r.rt), r.mcpStageRules()...),
		// The file the launching user named, by path or by registry name (agent-contract.md R26).
		ContractSource: r.deps.ContractSource,
		// The harness the run was provisioned for, and whether it was (agent-contract.md R27, ADR 0062).
		Harness: r.harness.start,
		// The profiles the contract merged, in merge order (ADR 0066 D6).
		Profiles: runProfiles(r.rt.Profiles),
		// A run with no net: section that opted out of the unix-only state with host_sockets: true (ADR 0070).
		HostSockets: r.rt.HostSocketsOpened(),
		// Whether the run held its read opens, and why (ADR 0069).
		FSReads: r.fsReads(),
		// Whether every read open reached the supervisor, so that a read Landlock refused is recorded (ADR 0077).
		ReadsNotified: r.readsNotified(),
		// The directories the ruleset listed once to build its deny_read entries, in which a name made during the
		// run is unreadable to it (GAPS A12): written on every run whose ruleset listed one.
		DenyReadFrozen: r.denyReadFrozen(),
	}
	// An Adjustable run's mode and fence (ADR 0125 decision 9); a Locked run writes neither field.
	start.LiveMode, start.LiveFence = runLiveFence(r.rt)
	// Who launched the run, on which host, and the identity its caller gave it (ADR 0073).
	r.fillRunIdentity(&start)
	// The reserved blocks the caller handed the run, checked at launchMinor by newRunner (RunStartExtras).
	r.deps.RunStartExtras.apply(&start)
	if err := r.writer.WriteRunStartIn(start, r.cg.ID); err != nil {
		return fmt.Errorf("runtime: write run_start: %w", err)
	}
	r.anchored.Store(true)
	r.noteFrozen(start.DenyReadFrozen)
	return nil
}

// denyReadFrozenLister is a handle whose Landlock ruleset lists directories to build its deny_read entries: tier 1's
// own (landlock.Handle.DenyReadFrozen) and a root tier's, which installs the tier-1 ruleset it composed.
type denyReadFrozenLister interface {
	DenyReadFrozen() []string
}

// denyReadFrozen is run_start.deny_read_frozen (record.MinorDenyReadFrozen): the directories the run's ruleset listed
// once at launch (enforce-landlock R3, E28), nil when it listed none or the run is records-only, whose handle builds
// no ruleset.
func (r *runner) denyReadFrozen() *record.DenyReadFrozen {
	h, ok := r.handle.(denyReadFrozenLister)
	if !ok || recordsOnly(r.handle) {
		return nil
	}
	return record.NewDenyReadFrozen(h.DenyReadFrozen())
}

// noteFrozen prints, once, before the agent runs, the note naming the directories run_start.deny_read_frozen names, so
// a person learns that a name made in one of them during a long run will be unreadable to it, which under record:
// summary no line records (GAPS A12). It says nothing for a run whose ruleset listed none.
func (r *runner) noteFrozen(f *record.DenyReadFrozen) {
	if f == nil || r.deps.Warn == nil {
		return
	}
	r.deps.Warn(WarnDenyReadFrozen, FrozenNote(f.Dirs, f.Omitted, "this run"))
}

// FrozenNote is the sentence tego run and tego compile print for the directories a deny_read freezes (GAPS A12): every
// one of dirs, then how many more the record left out, then what that means for a name made in one of them during run
// ("this run", "a run"). Every directory is named, since the one a person will make a name in (their home, the
// project) sorts after its ancestors.
func FrozenNote(dirs []string, omitted int, run string) string {
	list := strings.Join(dirs, ", ")
	switch {
	case omitted > 0 && len(dirs) > 0:
		list += fmt.Sprintf(" and %d more", omitted)
	case omitted > 0:
		list = fmt.Sprintf("%d directories", omitted)
	}
	return fmt.Sprintf("deny_read lists %s once, at launch: a file or directory made directly in one of them during %s "+
		"cannot be read until it ends (a new run lists them again)", list, run)
}

// fillRunIdentity sets run_start's run identity (ADR 0073, record.MinorRunIdentity), for a run and an adoption alike:
// the launcher's real uid (always), its passwd name, the account a root launcher's SUDO_UID names, the host's
// nodename, and the parent run, labels and role Deps carry (newRunner checked them) and the contract's revision.
func (r *runner) fillRunIdentity(p *record.RunStartPayload) {
	c := launcherCreds()
	// sudo_uid is the account the drop goes to, read where and as the drop reads it, so the record and the drop
	// cannot disagree: the drop (dropTarget, made when the euid is 0) takes config.InvokingUID, which trusts SUDO_UID
	// only for a real uid 0 of the initial user namespace (ADR 0042 (5)(d): under `unshare -r` uid 0 is no root, and
	// SUDO_UID is whatever the caller set) and reads it from this process's own environment (os.Getenv). A launcher
	// outside that gate is handed to LauncherOf as the no-uid euid, which reads no SUDO_UID, and the environment is
	// os.Environ(), never r.environ(): Deps.Environ is the agent's environment template, which an embedder may fill
	// from its own caller. os.Environ holds one entry per key, the one os.Getenv returns.
	euid := c.euid
	if euid == 0 && (c.ruid != 0 || !c.initialNS) {
		euid = math.MaxUint32
	}
	l := identity.LauncherOf(c.ruid, euid, passwdName, os.Environ(), os.Hostname)
	p.LauncherUID, p.LauncherUser = &l.UID, l.User
	p.SudoUID, p.SudoUser = l.SudoUID, l.SudoUser
	p.Host = l.Host
	p.ParentRun = r.deps.ParentRun
	if len(r.deps.Labels) != 0 {
		p.Labels = maps.Clone(r.deps.Labels)
	}
	p.Role = string(r.deps.Role)
	if r.rt.Contract != nil {
		p.ContractRevision = r.rt.Contract.Revision
	}
}

// launcherProcess is what fillRunIdentity reads of the launcher's own credentials: its real and effective uid, and
// whether it is in the initial user namespace.
type launcherProcess struct {
	ruid, euid uint32
	initialNS  bool
}

// launcherCreds reads the launcher's credentials; a test replaces it to stand for a root launcher.
var launcherCreds = func() launcherProcess {
	return launcherProcess{ruid: uint32(os.Getuid()), euid: uint32(os.Geteuid()), initialNS: config.InitialUserNamespace()}
}

// passwdName is uid's name in the passwd database (config.LookupPasswd, never one made up from $USER).
func passwdName(uid uint32) (string, error) {
	u, err := config.LookupPasswd(int(uid))
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

// fsReads is run_start.fs_reads (ADR 0069): held only where the run holds its reads at its tier and its open deputy
// serves the supervisor, which a run that holds them and whose deputy did not start never reaches (deputyUnavailable).
func (r *runner) fsReads() *record.FSReads {
	out := &record.FSReads{Reads: record.FSReadsDirect, Why: r.rt.ReadsWhy(r.deps.Enforce.Tier())}
	if recordsOnly(r.handle) {
		out.Why = agent.ReadsWhyRecordsOnly
	} else if r.readsHeldServed() {
		out.Reads = record.FSReadsHeld
	}
	for _, n := range r.rt.Reads.Nested {
		out.Nested = append(out.Nested, n.Rule)
	}
	return out
}

// readsNotified is run_start.reads_notified (ADR 0077): the table's answer at the run's tier (agent.RuleTable.
// ReadsNotifiedWhy), records-only for an --observe run whose record mode is not full (its filter takes nothing else),
// and not notified with no-supervisor where no started supervisor answers the run's notifications.
func (r *runner) readsNotified() *record.ReadsNotified {
	why := r.rt.ReadsNotifiedWhy(r.deps.Enforce.Tier())
	if recordsOnly(r.handle) && why != record.ReadsNotifiedWhyFull {
		why = record.ReadsNotifiedWhyRecordsOnly
	}
	out := &record.ReadsNotified{Why: why}
	switch why {
	case record.ReadsNotifiedWhyFull, record.ReadsNotifiedWhyGate, record.ReadsNotifiedWhyAskRead, record.ReadsNotifiedWhyHeld,
		record.ReadsNotifiedWhyReason:
		out.Notified = r.sup != nil && r.sup.Started()
		if !out.Notified {
			out.Why = record.ReadsNotifiedWhyNoSupervisor
		}
	}
	return out
}

// runProfiles is run_start.profiles: every profile the run's contract merged through extends, in merge order, with
// the kind of source that served it and the sha256 of its bytes (ADR 0066 D6). nil when the contract extends none,
// which at record.MinorProfiles or later is what the field's absence says.
func runProfiles(ps []agent.ProfileUse) []record.ProfileRef {
	if len(ps) == 0 {
		return nil
	}
	out := make([]record.ProfileRef, len(ps))
	for i, p := range ps {
		out[i] = record.ProfileRef{Name: p.Name, Source: string(p.Source), SHA256: hex.EncodeToString(p.SHA256[:])}
	}
	return out
}

// runLiveFence is run_start.live_mode and live_fence (ADR 0125 decision 9): "adjustable" and the fence's digest and
// entries, each with the rule a refusal under it carries and, for an exec entry that took out an exec.deny name, that
// name (part of the digest), for an Adjustable table; "" and nil for every other, so a
// Locked run's run_start is the one it always was.
func runLiveFence(rt *agent.RuleTable) (string, *record.LiveFence) {
	if !rt.Adjustable() {
		return "", nil
	}
	f := &record.LiveFence{SHA256: rt.Live.SHA256, Entries: make([]record.LiveFenceEntry, 0, len(rt.Live.Entries))}
	for _, e := range rt.Live.Entries {
		f.Entries = append(f.Entries, record.LiveFenceEntry{Kind: e.Kind, Value: e.Value, Source: e.Source,
			Rule: record.LiveFenceRule(e.Kind, e.Value), Name: e.Name})
	}
	return record.LiveModeAdjustable, f
}

// runtimeGrants is the rule name of every entry the runtime added to the run's table on its own authority, in table
// order: the capture listeners (net.capture[...]), the DNS broker's socket (net.dns-broker[...]), the run's own
// CODEX_HOME (fs.codex_home[...]) and hook-state directory (fs.harness-state[...]), then the harness hook's
// exact-argv exec grant (exec.harness-hook[<tego binary>], ADR 0064), one row for its image rule and its command rule
// alike. nil when there is none. net.resolver is not one: it is a decision the supervisor makes on a query to a
// configured resolver, not an entry of the table, and its lines name it.
func runtimeGrants(rt *agent.RuleTable) []string {
	var out []string
	for _, n := range rt.Net {
		if n.Runtime != "" {
			out = append(out, n.RuleName())
		}
	}
	for _, f := range rt.FS {
		if f.Runtime != "" {
			out = append(out, f.RuleName())
		}
	}
	if rule := rt.HarnessHookRule(); rule != "" {
		out = append(out, rule)
	}
	return out
}

// gatedAnchor forwards to the host-wide chain anchor only once the run has really started. A run
// that failed before run_start is removed whole (case 2), so anchoring its head would leave a line
// in chain.log for a run that never existed.
type gatedAnchor struct {
	inner   ledger.ChainAnchor
	started *atomic.Bool
}

// Append records the run's head, unless the run never wrote run_start.
func (a *gatedAnchor) Append(run, head string) error {
	if !a.started.Load() {
		return nil
	}
	return a.inner.Append(run, head)
}

// Head returns the anchored head of run.
func (a *gatedAnchor) Head(run string) (string, bool, error) { return a.inner.Head(run) }

// runLimits is the optional run_start.limits block: the compiled budgets, so `status` can apply
// stall_after and `measure` the ceilings without recompiling (limits-check-doctor-cli.md R12).
//
// A dimension is written exactly when ResolvedLimits.Bounded says the run has a budget there, which is
// the same question limits.Watcher asks before it enforces one: an explicit 0 is the tightest budget
// (E16), and deciding presence by the value instead wrote nothing for it, so a run the watcher would end
// at its first token showed readers no budget at all. The value written is the one the watcher compares
// against, a negative ceiling included, which it clamps at 0. ledgerBytes is the machine's record.max_run_bytes,
// written when positive (record.MinorLedgerCap).
func runLimits(l agent.ResolvedLimits, ledgerBytes int64) *record.Limits {
	var out record.Limits
	if ledgerBytes > 0 {
		out.LedgerBytes = new(ledgerBytes)
	}
	if l.Bounded(agent.BudgetTokens) {
		out.Tokens = new(max(l.Tokens, 0))
	}
	if l.Bounded(agent.BudgetCostUSD) {
		out.CostUSD = new(max(l.CostUSD, 0))
	}
	if l.Bounded(agent.BudgetRepeats) {
		out.Repeats = new(max(l.Repeats, 0))
	}
	if l.Bounded(agent.BudgetWall) {
		out.Wall = max(l.Wall, 0).String()
	}
	if l.Bounded(agent.BudgetStallAfter) {
		out.StallAfter = max(l.StallAfter, 0).String()
	}
	if out == (record.Limits{}) {
		return nil
	}
	return &out
}

// checkRunDir refuses a ledger root inside a declared write entry: the agent must never be able to
// rewrite its own record (SEMANTICS §2 "contradiction"; agent.Compile checks the contract's view,
// this checks the machine's). It compares the declared names only: an entry, or a ledger root, that is a link
// leading into the other is refused by Compile, which compares both by where they lead (agent-contract.md R10;
// agent's TestWriteEntrySymlinkToTheLedgerRootsParent), on the table this run compiled.
func checkRunDir(rt *agent.RuleTable, dir string) error {
	for _, rules := range [][]agent.FSRule{rt.FS, rt.FSAsk} {
		for _, r := range rules {
			if r.Kind != agent.FSWrite && r.Kind != agent.FSAsk {
				continue
			}
			if agent.Covers(r.Path, filepath.Clean(dir)) {
				return fmt.Errorf("%w: %s is inside fs.%s %s [%s]", ErrRunDirWritable, dir, r.Kind, r.Path,
					identity.CodeContradiction)
			}
		}
	}
	return nil
}

// LedgerRoot resolves the machine's ledger_root to an absolute path, expanding a leading ~ against
// the invoking user's home (config.Load already did that when it knew the home; this covers the
// built-in default). internal/cli uses it so `run`, `stop`, `status` and `gc` all agree on where a
// run directory lives. tego-control serve, which may not import this package, resolves the root it
// shows by the same rule in its own ledgerRootOf (internal/control/cli/serve.go), and for an
// account with no home reads the chain.log beside that root, the one AnchorPath names for the
// account's runs (serve never writes it): a change to the rule here is a change there.
func LedgerRoot(m *config.Machine) (string, error) {
	return ledgerRoot(m, config.DetectSecureExec, os.UserHomeDir)
}

// ledgerRoot is LedgerRoot over explicit AT_SECURE and $HOME readers, which is the only way a test
// can drive the secure branch: this process's own auxv is fixed at exec.
//
// The branch exists because os.UserHomeDir is $HOME and nothing else on Unix, and spec/config/v0's
// Trust section is explicit that "when the process runs with AT_SECURE set (the file-capability
// copy), $TEGO_CONFIG and $HOME are ignored; a static Go binary gets no loader secure-execution
// stripping, so the binary does it" — identity-config.md R21 says the same. pkg/spec/config honours
// it (Resolve reads getpwuid, never $HOME) and leaves Machine.Home empty when the lookup fails (E9:
// a containerized or directory-backed uid with no passwd entry, which CGO_ENABLED=0 makes any
// LDAP/SSSD host). Falling back to $HOME here would re-open exactly the door that rule closes, and
// for the worst possible target: this resolver decides where the capability-bearing launcher creates
// the run directory and writes the hash-chained ledger, and where `gc` later deletes.
//
// Unprivileged and non-secure, $HOME is still the right answer and stays the behaviour: a container
// with no passwd entry is an ordinary, honest case.
func ledgerRoot(m *config.Machine, secureExec func() (bool, error), envHome func() (string, error)) (string, error) {
	root := m.LedgerRoot.Value
	if root == "" {
		return "", fmt.Errorf("%w: empty ledger_root", ErrDeps)
	}
	if strings.HasPrefix(root, "~/") {
		home := m.Home
		if home == "" {
			secure, err := secureExec()
			// An unreadable auxv is treated as secure: it is the one input that could hide
			// AT_SECURE, and DetectSecureExec's own contract is that "a process that cannot read
			// its own auxv must not resolve $HOME or $TEGO_CONFIG either".
			if err != nil || secure {
				return "", fmt.Errorf("%w: %q, and the passwd database names no home for the "+
					"invoking uid (set ledger_root to an absolute path)", ErrLedgerRootHome, root)
			}
			h, err := envHome()
			if err != nil {
				return "", fmt.Errorf("runtime: ledger_root %q: %w", root, err)
			}
			home = h
		}
		root = filepath.Join(home, root[2:])
	}
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("%w: ledger_root %q is not absolute", ErrDeps, root)
	}
	return root, nil
}

// hostID hashes the machine id into the run id's host component. An unreadable /etc/machine-id
// degrades to the hostname and then to a constant: a run id is never refused for it (Q7).
func hostID(machineID []byte) [32]byte {
	if len(machineID) == 0 {
		if b, err := os.ReadFile("/etc/machine-id"); err == nil {
			machineID = b
		} else if h, err := os.Hostname(); err == nil {
			machineID = []byte(h)
		} else {
			machineID = []byte("tego")
		}
	}
	return identity.HostID(machineID)
}

// ledgerClock adapts the facade's Clock to the ledger's (the two name the monotonic reading
// differently; the values are the same two clocks).
type ledgerClock struct{ c Clock }

// Now is the wall clock stamped on every event.
func (l ledgerClock) Now() time.Time { return l.c.Now() }

// Mono is CLOCK_MONOTONIC in nanoseconds.
func (l ledgerClock) Mono() uint64 { return l.c.MonoNS() }

// askReadRelaxes is the run_start form of the table's relaxed built-in deny_read entries (ADR 0057 D4); nil when
// there is none, so the field is absent.
func askReadRelaxes(in []agent.AskReadRelax) []record.AskReadRelax {
	if len(in) == 0 {
		return nil
	}
	out := make([]record.AskReadRelax, len(in))
	for i, r := range in {
		out[i] = record.AskReadRelax{Rule: r.Rule, BuiltIn: r.BuiltIn, How: r.How}
	}
	return out
}
