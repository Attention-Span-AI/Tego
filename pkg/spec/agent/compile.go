// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Resolver is the DNS lookup Compile uses; *net.Resolver satisfies it and a
// test injects a fake.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Compile tunables.
const (
	// DefaultDNSTimeout is the per-host lookup budget (§9).
	DefaultDNSTimeout = 3 * time.Second
	// DefaultDNSParallel bounds concurrent lookups (§9: a channel of 8).
	DefaultDNSParallel = 8
	// DefaultDNSTTL is the re-resolution interval handed to the launcher; the
	// standard resolver does not expose record TTLs.
	DefaultDNSTTL = 60 * time.Second
	// MinDNSTTL floors a TTL so a CDN's 0s never drives the launcher's loop (E19).
	MinDNSTTL = 5 * time.Second
	// DefaultMountInfo is where mount metadata for the compile print comes from.
	DefaultMountInfo = "/proc/self/mountinfo"
)

// CompileOption tunes one Compile call; every option is additive to the
// normative Compile(c, m) signature (§11).
type CompileOption func(*compileOptions)

type compileOptions struct {
	ctx         context.Context
	offline     bool
	resolver    Resolver
	path        string
	pathSet     bool
	cwd         string
	home        string
	chainAnchor string
	// ownBinaries says WithOwnBinaries was given, and ownExe is the running tego it named, "" for none.
	ownBinaries bool
	ownExe      string
	// runtimeParents are tego's runtime parents, <XDG_RUNTIME_DIR>/tego for each base WithRuntimeDir named, cleaned
	// and without duplicates; none when none was given.
	runtimeParents []string
	mountInfo      string
	// mountInfoSet says WithMountInfo was given, so its "" disables the probe instead of meaning the default.
	mountInfoSet bool
	now          func() time.Time
	ttl          time.Duration
	dnsTimeout   time.Duration
	dnsParallel  int
	// socketRoot and socketUID are where R19's host-socket probe looks: "" and the invoking uid on a real
	// machine; a test re-roots them (withHostSocketProbe in export_test.go). socketSet says socketUID was given.
	socketRoot string
	socketUID  int
	socketSet  bool
	// tiers are the enforcement tiers this binary builds (WithTiers); tiersSet says they were given.
	tiers    []backend.Tier
	tiersSet bool
	// runCommand is the command `tego run` was given after the contract (WithRunCommand), "" for none.
	runCommand string
	// record is the record mode `tego run --record` gives in place of the contract's (WithRecord), "" for none.
	record RecordMode
	// observe says the table is compiled for a `tego run --observe` (WithObserve).
	observe bool
	// tierFlag is the tier `tego run --tier` pins (WithTierFlag), "" for none.
	tierFlag backend.Tier
	// envNames are the names of the launcher's environment (WithEnviron), never their values.
	envNames []string
}

// WithRecord gives the run's record mode in place of the contract's: `tego run --record`, the launching user's
// choice for that run. RuleTable.Record is then mode, and every finding that depends on the record mode is
// derived from it, so the run is warned about the record it makes, not the one the contract names. The contract hash
// is unaffected. mode must be full, summary or off; the CLI validates it.
func WithRecord(mode RecordMode) CompileOption {
	return func(o *compileOptions) { o.record = mode }
}

// WithObserve compiles the table for a `tego run --observe`, which installs tier landlock's seccomp filter and
// enforces nothing (SEMANTICS §7): a finding about what that filter does not see holds in TierObserve too. It
// changes no rule of the table.
func WithObserve() CompileOption { return func(o *compileOptions) { o.observe = true } }

// WithTierFlag names the tier `tego run --tier` pins for the run. Compile does not apply it: the selection does,
// after Compile (enforce.Only), and refuses a contract that pins another tier as a --tier conflict. It changes no rule
// of the table; it tells a fix that offers to pin a tier in the contract that the flag must go too.
func WithTierFlag(t backend.Tier) CompileOption { return func(o *compileOptions) { o.tierFlag = t } }

// ReadAggregationWindow is how often a root tier's recorder flushes the reads it aggregates under record: summary
// (internal/runtime/observe.DefaultFlushInterval is this value): a read reaches the record, and the stall check, up
// to this long after it happened (stallReadsUnseen).
const ReadAggregationWindow = 5 * time.Second

// WithRunCommand names the program `tego run` was given on its command line (argv[0]), which the run
// execs in place of the contract's command. That command is the launching user's choice, not the agent's,
// and is granted as the run's own command for that run: an implicit exec entry beside the contract's
// command, with its loader and a script's #! interpreter, as the contract's command gets (R8). A name
// that resolves nowhere adds nothing and is no diagnostic: the run passes it to execve unchanged and ends
// with exit 127, as it always has. The contract hash is unaffected, so the rule it adds is
// RuleTable.RunCommandGrant, an absolute path, which run_start records; the grant covers every exec of that
// file in the run, not only the first.
func WithRunCommand(name string) CompileOption {
	return func(o *compileOptions) { o.runCommand = name }
}

// Offline makes an unresolvable host a warning instead of an error; the
// launcher resolves at run start (E18, §7).
func Offline() CompileOption { return func(o *compileOptions) { o.offline = true } }

// WithResolver injects the DNS resolver (tests use a zero-latency fake).
func WithResolver(r Resolver) CompileOption { return func(o *compileOptions) { o.resolver = r } }

// WithContext cancels DNS work and stops scheduling further lookups when ctx ends.
// Compile waits for all started lookups before returning ctx.Err(); a custom Resolver
// must honor its context. The default is context.Background().
func WithContext(ctx context.Context) CompileOption {
	return func(o *compileOptions) { o.ctx = ctx }
}

// WithPATH supplies the PATH the launcher inherits. Compile derives the run's
// effective PATH from it through env.pass/deny/set (I8); it never reads
// os.Getenv itself. Without this option no basename can resolve.
func WithPATH(p string) CompileOption {
	return func(o *compileOptions) { o.path, o.pathSet = p, true }
}

// WithCwd sets the directory relative fs and exec entries resolve against
// (E28); default os.Getwd at the time of the call.
func WithCwd(dir string) CompileOption { return func(o *compileOptions) { o.cwd = dir } }

// WithHome sets the home directory "~" expands to; default is the invoking
// user's passwd entry, never $HOME.
func WithHome(dir string) CompileOption { return func(o *compileOptions) { o.home = dir } }

// WithChainAnchor names the chain.log the run will anchor its head in (the
// launcher's AnchorPath), which R10 keeps out of every write entry; default
// ~/.tego/chain.log under the compile's home (P0-DESIGN §3.3).
func WithChainAnchor(path string) CompileOption {
	return func(o *compileOptions) { o.chainAnchor = path }
}

// WithOwnBinaries keeps tego's own binaries out of every write entry (R10): exe, the running tego, the tego-control
// beside it, and the tego and tego-control the compile's PATH finds, and warns about a write entry over a PATH directory
// searched before them. exe is "" where the process cannot name it (tego-control runs from a sealed copy), which leaves
// the PATH. The caller passes exe so this package stays free of os.Executable and a test can name any file. With no such
// option a compile, as a library's, knows of no binary and refuses none.
func WithOwnBinaries(exe string) CompileOption {
	return func(o *compileOptions) { o.ownBinaries, o.ownExe = true, exe }
}

// WithRuntimeDir names the XDG_RUNTIME_DIR bases under which the invoking user's runs keep their private directories,
// <base>/tego/<run id> (a generated CODEX_HOME, a last-refusal mirror): R10a keeps every write and ask entry off
// tego's runtime parent under each, <base>/tego, and out of every run's directory there. The CLI and the dashboard
// name the user's logind directory, /run/user/<uid>, whatever their environment says, and $XDG_RUNTIME_DIR when that
// names another (config.RuntimeDirBases, the list the launcher checks): a launcher whose environment lacks the
// variable (plain sudo, cron, ssh without pam_systemd) still protects the directory where the same user's other runs
// keep theirs. "" and a relative path name none; each call adds to the bases already named.
func WithRuntimeDir(bases ...string) CompileOption {
	return func(o *compileOptions) {
		for _, b := range bases {
			if !filepath.IsAbs(b) {
				continue
			}
			if p := filepath.Join(b, RuntimeDirName); !slices.Contains(o.runtimeParents, p) {
				o.runtimeParents = append(o.runtimeParents, p)
			}
		}
	}
}

// RuntimeDirName is tego's directory under $XDG_RUNTIME_DIR, the parent of every run's private directory.
const RuntimeDirName = "tego"

// WithMountInfo sets the mountinfo file the compile print reads; "" disables
// the mount probe.
func WithMountInfo(path string) CompileOption {
	return func(o *compileOptions) { o.mountInfo, o.mountInfoSet = path, true }
}

// WithClock injects the clock NetRule.ResolvedAt is stamped from.
func WithClock(now func() time.Time) CompileOption { return func(o *compileOptions) { o.now = now } }

// WithDNSTTL sets the TTL handed to the launcher; floored at MinDNSTTL.
func WithDNSTTL(d time.Duration) CompileOption { return func(o *compileOptions) { o.ttl = d } }

// WithTiers names the enforcement tiers this binary can construct (internal/runtime/enforce.Buildable), which
// the composition root knows and this package cannot (ADR 0019). tier: auto then resolves to the highest of
// them the machine ceiling allows, never to a tier the binary does not contain, and RuleTable.Reach lists
// every one of them an auto run may land at. Without it, auto resolves to the ceiling, and Reach holds that
// tier alone.
func WithTiers(tiers ...backend.Tier) CompileOption {
	return func(o *compileOptions) { o.tiers, o.tiersSet = append([]backend.Tier(nil), tiers...), true }
}

// compiler holds one Compile call's state; nothing outlives the call.
type compiler struct {
	c    *Contract
	m    *config.Machine
	o    compileOptions
	ds   diags
	rt   *RuleTable
	top  string
	cpos Pos // a position for findings that have no field: the contract file, line 1
	// nestedWrite is the write entry that covers each deny_read target at or beneath one, by the target's path
	// (unenforced), which heldReads turns into RuleTable.Reads.Nested.
	nestedWrite map[string]writePath
	// buildCapped says tier: auto resolved below the machine's ceiling because this binary builds no
	// higher tier (WithTiers): tier landlock is then this build's limit, not what the contract or the
	// machine config asked for.
	buildCapped bool
	// askScope derives protected targets without granting write authority.
	askScope bool
	// askDenyWrite is the fs.deny_write entries only an fs.ask scope covers (compileDenyWrite): fsAsk adds them to
	// RuleTable.AskDenyWrite, so no approval opens them.
	askDenyWrite []FSRule
	// linked is what the linked-file search beneath the deny_write directory targets met (searchDenyWriteLinked), which
	// keyDenyWriteLinked decides on once every fs entry is in the table.
	linked *linkSearch
	// execHelpers are the helper images exec() granted for a row with a helper closure (ADR 0048 (2)).
	execHelpers []string
	// contractWalked is the contract file's path as Load opened it, made absolute and never cleaned (asWalked): R10
	// walks it for every name on the way to the contract (RuleTable.ContractPath is the file it names).
	contractWalked string
}

// Compile turns a loaded contract and the machine ceilings into a RuleTable:
// limits clamped (R11), tier and capture resolved (R14), env rules applied
// (R12), fs entries resolved with their implicit companions (R6, R7, R9,
// R10), exec entries resolved on the run's PATH with their loaders (R8), and
// hosts resolved through a bounded pool (§9). err is nil iff every diagnostic
// is a warning; the table is nil on error. Hash is taken before any clamp so
// it is the same on every machine (R13, I3).
func Compile(c *Contract, m *config.Machine, opts ...CompileOption) (*RuleTable, []Diagnostic, error) {
	if c == nil || !c.loaded {
		return nil, nil, fmt.Errorf("agent: Compile: %w", ErrNotLoaded)
	}
	if m == nil {
		return nil, nil, errors.New("agent: Compile: nil machine")
	}
	k := &compiler{c: c, m: m, top: c.file, cpos: Pos{File: c.file, Line: 1}}
	for _, opt := range opts {
		opt(&k.o)
	}
	if err := k.defaults(); err != nil {
		return nil, nil, err
	}
	if err := k.o.ctx.Err(); err != nil {
		return nil, nil, err
	}
	hash, err := c.Hash()
	if err != nil {
		return nil, nil, err
	}
	// The contract file is where Load's open of its path landed: the path as given, never cleaned lexically, which R10
	// walks for every name on the way (walkTarget), and the file it names, which run_start records and the .env scan starts beside.
	// k.abs cleaned it, and <dir>/lnk/../agent.yaml, which Load read beside lnk's target, became <dir>/agent.yaml, a
	// file that does not exist: an entry over the one read compiled, and the run rewrote its own contract (RS5-2).
	k.contractWalked = k.asWalked(c.file)
	place, ok := WalkedPath(k.contractWalked)
	if !ok {
		return nil, nil, fmt.Errorf("agent: Compile: the contract path %s cannot be placed as the kernel walks it (a link "+
			"before a \"..\" that does not resolve); give the contract's path without \"..\"", k.contractWalked)
	}
	k.rt = &RuleTable{Hash: hash, Contract: c, Profiles: c.Profiles(), ContractPath: place, Home: k.o.home}
	k.limits()
	k.tierAndCapture()
	k.gateConfig()
	k.askConfig()
	k.http()
	k.proxyPolicy()
	k.budgetsUnseenUnderRecordOff()
	k.budgetsUnmetered()
	k.modelBypassLowered()
	k.env()
	k.secretEnv()
	k.ownState()
	// ADR 0125: an Adjustable contract's fence becomes ordinary allow entries before any fs, net or exec table is
	// built, so every kernel layer compiles the contract plus the fence. With no live: key it changes nothing.
	live := k.compileLive()
	k.builtInDenyReadPatterns()
	k.fs()
	if c.FS != nil && c.FS.AppArmorAssumeRootNamespace {
		k.ds.warnf(k.pos("fs.apparmor_assume_root_namespace"), CodeUnenforced, "best effort (%s): %s; run_start.best_effort records this opt-in", BestEffortAppArmorNamespace, bestEffortWhy[BestEffortAppArmorNamespace]).
			fix("leave this false unless the container administrator accepts the risk and establishes root AppArmor policy-namespace visibility")
	}
	k.fsAsk()
	k.fsAskRead()
	k.builtinRefusals() // after contract entries: no contract can remove these
	k.builtinFIFOs()
	k.heldReads()   // after the fs.ask_read entries, which may replace a built-in deny_read, and before the exec grants
	k.reasonReads() // after heldReads and before stallReadsUnseen, which asks what the filter notifies
	// After every pass that adds an fs entry: the plane keys one row per file.
	k.keyDenyWriteLinked()
	k.stallReadsUnseen() // after the fs entries: what the filter notifies depends on the gate and the ask entries
	k.nameAskWarnings()
	k.exec()
	k.execResolved()
	k.execAnonymousOptOut()
	k.denyReadUnderExecDirs()
	k.execInsideDenyRead()
	k.askReadEnforced()
	k.execUnderWrite()
	k.execSharedWritable()
	k.execOverRuntimeDir()
	k.execMulticall()
	k.execMapNative()
	k.execCommands()
	k.execAssurance()
	k.net()
	k.dnsPolicy()
	k.listenerControl()
	k.ioUringListenUndecided()
	k.networkControlTier()
	if err := k.o.ctx.Err(); err != nil {
		return nil, k.ds.list, err
	}
	k.builtinContainerAliases()
	k.builtinPeerNames()
	k.containerSocketWarning()
	k.builtinRefusedAllows() // after builtinContainerAliases: ADR 0113's built-ins always win over net.allow
	k.hostSocketsReachable()
	k.harness()
	k.credentialsAndRelayTier() // ADR 0126: after tierAndCapture, which resolved the run's capture
	k.modelRoutesTier()         // ADR 0127, as credentials
	k.markLive(live)
	// ADR 0033: no_new_privs is set at every tier, and `setuid: true` is a root tier's opt-out of it. Tier 1
	// runs unprivileged, where the flag is what lets it install Landlock and seccomp at all.
	// A contract or machine config that holds the run at landlock contradicts setuid: true; an auto contract
	// that may land there (a non-root run, or a build with no root tier) keeps no_new_privs at that tier, and
	// the launcher does not honor the opt-out there either (internal/runtime childSpec).
	if c.Setuid {
		switch {
		case k.rt.Tier == backend.TierLandlock && !k.buildCapped:
			k.ds.errorf(k.pos("setuid"), CodeSchema, "setuid: true needs a root tier: at tier landlock no_new_privs is mandatory").
				fix("pin tier: cgroup, or drop setuid:")
		case k.rt.Tier != backend.TierLandlock:
			k.ds.warnf(k.pos("setuid"), CodeUnenforced, "setuid: true lets a setuid binary inside the run gain root, and a root agent keeps every root power Landlock and the filter do not mediate (setns, perf_event_open, ioperm); under a net: section it never holds CAP_NET_ADMIN, so `sudo ip route add` and the like fail").
				fix("drop setuid: unless the agent must run sudo or another setuid program")
		}
		if k.mayLand(backend.TierLandlock) && (k.rt.Tier != backend.TierLandlock || k.buildCapped) {
			k.ds.warnf(k.pos("setuid"), CodeUnenforced, "setuid: true has no effect in the landlock tier, where no_new_privs is always set").
				fix("pin a root tier, or drop setuid:").only(backend.TierLandlock)
		}
	}
	if c.IOUring && k.mayLand(backend.TierLandlock) {
		k.ds.warnf(k.pos("io_uring"), CodeIOUring, "io_uring: true has no effect in the landlock tier; io_uring stays refused (ENOSYS)").
			fix("pin a root tier or drop io_uring:").only(backend.TierLandlock)
	}
	SortDiagnostics(k.ds.list, k.top)
	if err := firstError(k.ds.list); err != nil {
		return nil, k.ds.list, err
	}
	return k.rt, k.ds.list, nil
}

// currentUser is user.Current; a test swaps it for a passwd entry with no home.
var currentUser = user.Current

func (k *compiler) defaults() error {
	o := &k.o
	if o.ctx == nil {
		o.ctx = context.Background()
	}
	if o.cwd == "" {
		wd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("agent: Compile: the current directory cannot be named (deleted? cd to one that exists): %w", err)
		}
		o.cwd = wd
	}
	if o.home == "" {
		u, err := currentUser()
		if err != nil {
			return fmt.Errorf("agent: Compile: home directory of the invoking user: %w", err)
		}
		if u.HomeDir == "" {
			return fmt.Errorf("agent: Compile: the passwd database names no home directory for uid %s; give the user one there (a library caller passes WithHome)", u.Uid)
		}
		o.home = u.HomeDir
	}
	if o.chainAnchor == "" {
		o.chainAnchor = filepath.Join(o.home, ".tego", "chain.log")
	}
	if !o.mountInfoSet {
		o.mountInfo = DefaultMountInfo
	}
	if o.now == nil {
		o.now = time.Now
	}
	if o.ttl == 0 {
		o.ttl = DefaultDNSTTL
	}
	if o.ttl < MinDNSTTL { // E19
		o.ttl = MinDNSTTL
	}
	if o.dnsTimeout == 0 {
		o.dnsTimeout = DefaultDNSTimeout
	}
	if o.dnsParallel == 0 {
		o.dnsParallel = DefaultDNSParallel
	}
	if !o.socketSet {
		o.socketUID = -1
	}
	if o.resolver == nil {
		o.resolver = net.DefaultResolver
	}
	return nil
}

// pos returns the position of a contract field, or the file's first line.
func (k *compiler) pos(key string) Pos {
	if p, ok := k.c.origins[key]; ok {
		return p
	}
	return k.cpos
}

// abs resolves "~/", relative paths against the run's cwd (E28) and cleans.
// It is purely lexical: use resolve for anything that has to agree with the
// inode the kernel will pin.
func (k *compiler) abs(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		p = filepath.Join(k.o.home, p[1:])
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(k.o.cwd, p)
	}
	return filepath.Clean(p)
}

// asWalked is p made absolute as the kernel's walk of it is (a relative path against the run's cwd, a "~" as the name
// of a directory there: a shell expands it, an open does not) and never cleaned, for a path a loader opens as given
// (the contract file, the user registry): the walk takes a ".." after a link from the link's target, where
// filepath.Clean removes the link's name. R10 walks it as that open did (walkTarget), and
// WalkedPath spells the place it names.
func (k *compiler) asWalked(p string) string {
	if !filepath.IsAbs(p) {
		return strings.TrimSuffix(k.o.cwd, "/") + "/" + p
	}
	return p
}

// resolve follows every symlink in an absolute path so a containment check
// compares the subtree the rule governs. The run opens each entry O_PATH with
// no O_NOFOLLOW, which follows the link and pins its target (E8), so a
// lexical comparison of declared names answers a different question from the
// one the kernel will: a write entry that is a symlink into the ledger root,
// or one whose target encloses a deny_read entry, escapes an unresolved R10
// or unenforced check entirely.
//
// A path that does not exist yet (the write directory run creates) resolves
// through its parent, the same shape the landlock backend's resolveTarget
// uses, and one whose parent is missing too where the walk lands once the
// missing directories are made (placePath). A path no walk
// places falls back to itself; R10, which must keep every entry off its
// targets, refuses such a target instead (writeTarget.placed). The walk is
// the kernel's (resolvePath), since many of these paths lie where the agent
// writes: filepath.EvalSymlinks
// re-walked the path from the root at every component. One kernel walk still
// follows up to 40 links of up to 4095 bytes each, so a chain the agent
// planted makes one call cost tens of milliseconds; the number of calls is
// the contract's, and the .env scan, whose results the agent can multiply,
// stops resolving them at its time limit (builtIn, I6).
func (k *compiler) resolve(p string) string {
	return resolvePath(p)
}

// limits applies R11: each contract value is kept when at or below the machine ceiling, else the ceiling
// stands with a limit-above-machine warning; an unset field inherits the ceiling. An unbounded ceiling is
// nil, never a zero value, so an operator can set a ceiling of exactly 0 and have it enforced (E12).
//
// Each field also records in ResolvedLimits.Set whether anyone asked for a budget at all, because the
// resolved number cannot say so on its own: a ceiling of exactly 0 resolves to the same 0 as "nobody set
// this", and every consumer downstream would read the tightest budget as no budget (E16).
func (k *compiler) limits() {
	l, ceil := k.c.Limits, k.m.Limits
	r := &k.rt.Limits
	// mark records that this dimension was asked for, whatever number it resolved to.
	mark := func(key BudgetSet, present bool) {
		if present {
			r.Set |= key
		}
	}

	cpu, ok := clampCPU(k, l.CPU, cpuCeiling(ceil.CPU))
	r.CPU = cpu
	mark(BudgetCPU, ok)

	weight, ok := clamp(k, "cpu_weight", l.CPUWeight, ceilPtr[int, int](ceil.CPUWeight))
	r.CPUWeight = weight
	mark(BudgetCPUWeight, ok)

	mem, ok := clamp(k, "memory", l.Memory, ceilPtr[config.ByteSize, ByteSize](ceil.Memory))
	r.MemoryB = int64(mem)
	mark(BudgetMemory, ok)

	high, ok := clamp(k, "memory_high", l.MemoryHigh, ceilPtr[config.ByteSize, ByteSize](ceil.MemoryHigh))
	r.MemoryHigh = int64(high)
	mark(BudgetMemoryHigh, ok)

	// memory_high is a throttle point and can never sit above the resolved memory cap; a memory ceiling of
	// exactly 0 is a real cap, so the comparison uses the presence of a cap, not its value.
	if r.Bounded(BudgetMemory) && r.MemoryHigh > r.MemoryB {
		// Three ways to get here. The contract wrote memory_high: Load refuses one above the contract's own
		// memory, so the cap is the machine's memory ceiling, and the message names that layer, as R11's does.
		// The contract did not: memory_high is the machine's memory_high ceiling, and the cap is either the
		// contract's own memory (kept under the memory ceiling) or, both being the machine's, its memory
		// ceiling. Neither is the contract's memory_high, so the warning says whose value is whose.
		high, capB := ByteSize(r.MemoryHigh).String(), ByteSize(r.MemoryB).String()
		switch {
		case l.MemoryHigh != nil:
			k.ds.warnf(k.pos("limits.memory_high"), CodeLimitAboveMachine, "limits.memory_high %s is above the memory ceiling %s from %s; kept at %s",
				high, capB, k.limitSource("memory"), capB).
				fix("lower limits.memory_high to %s or below, or raise the machine's memory ceiling", capB)
		case l.Memory != nil && (!ceil.Memory.Bounded || int64(*l.Memory) <= int64(ceil.Memory.Value)):
			k.ds.warnf(k.pos("limits.memory"), CodeLimitAboveMachine, "the machine's memory_high ceiling %s from %s is above this contract's limits.memory %s; throttling at %s",
				high, k.limitSource("memory_high"), capB, capB).
				fix("set limits.memory_high to %s or below, or lower the machine's memory_high ceiling", capB)
		default:
			k.ds.warnf(k.pos("limits.memory"), CodeLimitAboveMachine, "the machine's memory_high ceiling %s from %s is above its memory ceiling %s from %s; throttling at %s",
				high, k.limitSource("memory_high"), capB, k.limitSource("memory"), capB).
				fix("lower the machine's memory_high ceiling to %s or below, or raise its memory ceiling", capB)
		}
		r.MemoryHigh = r.MemoryB
	}

	k.warnBelowStart(l)

	pids, ok := clamp(k, "pids", l.Pids, ceilPtr[int, int](ceil.Pids))
	r.Pids = pids
	mark(BudgetPids, ok)
	if l.Pids != nil && *l.Pids < minStartPids {
		k.ds.errorf(k.pos("limits.pids"), CodeLimitBelowStart, "limits.pids %d cannot start a run: tego's own stage holds at least %d tasks in the run's cgroup before the agent exists, and below that it dies with a Go stack dump", *l.Pids, minStartPids).
			fix("set limits.pids to %d or more, and count the agent's own processes and threads on top", minStartPids)
	}
	k.warnCeilingBelowStart(l)

	tokens, ok := clamp(k, "tokens", l.Tokens, ceilPtr[int64, int64](ceil.Tokens))
	r.Tokens = tokens
	mark(BudgetTokens, ok)

	cost, ok := clamp(k, "cost_usd", l.CostUSD, ceilPtr[float64, float64](ceil.CostUSD))
	r.CostUSD = cost
	mark(BudgetCostUSD, ok)

	wall, ok := clamp(k, "wall", l.Wall, ceilPtr[time.Duration, Duration](ceil.Wall))
	r.Wall = time.Duration(wall)
	mark(BudgetWall, ok)
	if l.Wall != nil && l.StallAfter == nil {
		k.ds.warnf(k.pos("limits.wall"), CodeWallHardCap, "limits.wall %s is a hard cap on the run's whole time: it ends the run at that mark even while the agent is working or the person is typing", l.Wall).
			fix("for an interactive session set limits.stall_after (the person's typing counts as activity) and keep wall for a bound on the whole job").info()
	}

	stall, ok := clamp(k, "stall_after", l.StallAfter, ceilPtr[time.Duration, Duration](ceil.StallAfter))
	r.StallAfter = time.Duration(stall)
	mark(BudgetStallAfter, ok)

	repeats, ok := clamp(k, "repeats", l.Repeats, ceilPtr[int, int](ceil.Repeats))
	r.Repeats = repeats
	mark(BudgetRepeats, ok)
}

// The least a run's own start takes in the run's cgroup, before the agent exists: the child stage is a Go process and
// is under the limits from its first instruction. Measured on 2026-11-01 at tier landlock: pids 5 fails every time and
// 6 passes, memory 4 MiB fails and 6 MiB passes. A pids limit below it never starts, so it is an error. How much memory
// is charged depends on what the page cache holds, so a memory limit below it is a warning; memory_high is the same
// floor, where the stage is throttled and the start never ends. These hold what the contract writes: a machine ceiling
// of 0 is enforced as written (R11).
const (
	minStartPids   = config.MinStartPids
	minStartMemory = config.MinStartMemory
)

// warnCeilingBelowStart warns of a resolved limit below a run's start (minStartPids, minStartMemory) that the
// machine ceiling set, where the contract's own value, if any, was not: a ceiling of pids 3 compiled every contract
// clean and every run died. A warning, not an error: the ceiling is enforced as written (E12), and it is the
// operator's to raise.
func (k *compiler) warnCeilingBelowStart(l Limits) {
	r := &k.rt.Limits
	warn := func(key, value, floor string) {
		k.ds.warnf(k.pos("limits."+key), CodeLimitBelowStart, "the machine's %s ceiling %s from %s is below what a run's start takes (%s): tego's own stage is under it before the agent exists, so no run may start",
			key, value, k.limitSource(key), floor).
			fix("raise the machine's %s ceiling to %s or more", key, floor)
	}
	if r.Bounded(BudgetPids) && r.Pids < minStartPids && (l.Pids == nil || *l.Pids >= minStartPids) {
		warn("pids", strconv.Itoa(r.Pids), strconv.Itoa(minStartPids))
	}
	floor := ByteSize(minStartMemory).String()
	if r.Bounded(BudgetMemory) && r.MemoryB < minStartMemory && (l.Memory == nil || int64(*l.Memory) >= minStartMemory) {
		warn("memory", ByteSize(r.MemoryB).String(), floor)
	}
	if r.Bounded(BudgetMemoryHigh) && r.MemoryHigh < minStartMemory && (l.MemoryHigh == nil || int64(*l.MemoryHigh) >= minStartMemory) &&
		!(r.Bounded(BudgetMemory) && r.MemoryHigh == r.MemoryB && r.MemoryB < minStartMemory) {
		warn("memory_high", ByteSize(r.MemoryHigh).String(), floor)
	}
}

// belowStart says whether v, a ceiling on limits.<key>, is below what a run's own start takes.
func belowStart[R limitValue](key string, v R) bool {
	switch x := any(v).(type) {
	case int:
		return key == "pids" && x < minStartPids
	case ByteSize:
		return (key == "memory" || key == "memory_high") && int64(x) < minStartMemory
	}
	return false
}

// warnBelowStart warns of a memory limit the contract wrote that a run's start may not get through (minStartMemory).
func (k *compiler) warnBelowStart(l Limits) {
	below := func(key string, b *ByteSize) {
		if b == nil || int64(*b) >= minStartMemory {
			return
		}
		k.ds.warnf(k.pos("limits."+key), CodeLimitBelowStart, "limits.%s %s may not start a run: tego's own stage needs about %s in the run's cgroup before the agent exists",
			key, b.String(), ByteSize(minStartMemory).String()).
			fix("set limits.%s to at least %s, with the agent's own memory on top", key, ByteSize(minStartMemory).String())
	}
	below("memory", l.Memory)
	below("memory_high", l.MemoryHigh)
}

// ceilPtr converts a machine ceiling into the nil-means-unbounded form clamp consumes, preserving the
// difference between "no ceiling" and "a ceiling of exactly zero" that config.Ceiling.Bounded carries.
func ceilPtr[C comparable, R limitValue](c config.Ceiling[C]) *R {
	p := c.Ptr()
	if p == nil {
		return nil
	}
	var out R
	switch v := any(*p).(type) {
	case int:
		out = R(v)
	case int64:
		out = R(v)
	case float64:
		out = R(v)
	case config.ByteSize:
		out = R(v)
	case time.Duration:
		out = R(v)
	default:
		return nil
	}
	return &out
}

// cpuCeiling renders the cores ceiling as the CPUCores string clampCPU compares; nil when unbounded.
func cpuCeiling(c config.Ceiling[float64]) *string {
	p := c.Ptr()
	if p == nil {
		return nil
	}
	s := strconv.FormatFloat(*p, 'f', -1, 64)
	return &s
}

// limitValue is a numeric limit type.
type limitValue interface {
	~int | ~int64 | ~float64
}

// clamp resolves one limit field: a nil contract value inherits the ceiling (zero when unbounded); a value
// above a present ceiling keeps the ceiling and warns (R11). The result is expressed in R's type.
//
// The second return is the presence the resolved number loses: true when the contract named the field or
// the machine set a ceiling on it, false only when neither did. Without it a resolved 0 reads as unbounded
// downstream, which inverts a zero ceiling into no ceiling (E16).
func clamp[T limitValue, R limitValue](k *compiler, key string, v *T, ceiling *R) (R, bool) {
	if v == nil {
		if ceiling == nil {
			var zero R
			return zero, false
		}
		return *ceiling, true
	}
	got := R(*v)
	if ceiling != nil && got > *ceiling {
		k.aboveCeiling(key, limitString(*ceiling), limitString(got), belowStart(key, *ceiling))
		return *ceiling, true
	}
	return got, true
}

// limitString renders a limit in its YAML spelling.
func limitString[R limitValue](v R) string {
	switch x := any(v).(type) {
	case ByteSize:
		return x.String()
	case Duration:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}

// clampCPU is clamp for the cores string, with the same presence second return.
func clampCPU(k *compiler, v *CPUCores, ceiling *string) (string, bool) {
	if v == nil {
		if ceiling == nil {
			return "", false
		}
		return *ceiling, true
	}
	if ceiling != nil && v.Quota() > CPUCores(*ceiling).Quota() {
		k.aboveCeiling("cpu", *ceiling, string(*v), false)
		return *ceiling, true
	}
	return string(*v), true
}

// aboveCeiling is R11's warning, `ceiling <key>=<value> kept from <file>:<line>`: the layer that set the
// machine ceiling, which the message named only as "machine config", so the operator could not tell
// /etc/tego/config.yaml from their own ~/.tego/config.yaml or $TEGO_CONFIG. A ceiling below what a run's start takes
// (underStart) is not a value to lower the contract to, so the fix is the ceiling alone.
func (k *compiler) aboveCeiling(key, ceiling, got string, underStart bool) {
	d := k.ds.warnf(k.pos("limits."+key), CodeLimitAboveMachine, "ceiling %s=%s kept from %s; the contract asked for %s", key, ceiling, k.limitSource(key), got)
	if underStart {
		d.fix("raise the machine's %s ceiling: at %s no run may start", key, ceiling)
		return
	}
	d.fix("lower limits.%s to %s or raise the machine ceiling", key, ceiling)
}

// limitSource is the file:line of the machine config layer that set the ceiling on limits.<key>.
func (k *compiler) limitSource(key string) string {
	l := &k.m.Limits
	var p config.Provenance
	switch key {
	case "cpu":
		p = l.CPU.Source
	case "cpu_weight":
		p = l.CPUWeight.Source
	case "memory":
		p = l.Memory.Source
	case "memory_high":
		p = l.MemoryHigh.Source
	case "pids":
		p = l.Pids.Source
	case "tokens":
		p = l.Tokens.Source
	case "cost_usd":
		p = l.CostUSD.Source
	case "wall":
		p = l.Wall.Source
	case "stall_after":
		p = l.StallAfter.Source
	case "repeats":
		p = l.Repeats.Source
	default:
		return "the machine config"
	}
	return p.String()
}

// tierAndCapture applies R14 and SEMANTICS §8: auto resolves to the highest
// value the machine ceiling allows; a pin above the ceiling keeps the
// ceiling with a warning, never an error.
//
// Under auto with WithTiers, the ceiling is also capped at the highest tier the binary builds, so a table is
// never compiled for a tier its own run cannot get (ADR 0019): an auto contract compiled at bpflsm, a tier no
// build contains, and compile --test certified that tier's refusals while the run at landlock allowed them
// (limits-check-doctor-cli.md R28). A machine config naming a concrete tier pins it, as enforce.Select reads it.
func (k *compiler) tierAndCapture() {
	ceiling := backend.Tier(k.m.Tier.Value.String())
	machinePin := k.m.Tier.Bounded && ceiling != "" && ceiling != backend.TierAuto
	if !machinePin {
		ceiling = backend.TierBPFLSM
	}
	pin := backend.Tier(k.c.Tier)
	auto := pin == "" || pin == backend.TierAuto
	switch {
	case auto && !machinePin:
		k.rt.Tier = k.highestBuilt(ceiling)
		k.buildCapped = k.rt.Tier != ceiling
	case auto:
		k.rt.Tier = ceiling
	case pin.Rank() > ceiling.Rank():
		k.ds.warnf(k.pos("tier"), CodeLimitAboveMachine, "ceiling tier=%s kept from %s; the contract pinned %s", ceiling, k.m.Tier.Source, pin).
			fix("pin tier: %s or raise the machine ceiling", ceiling)
		k.rt.Tier = ceiling
	default:
		k.rt.Tier = pin
	}
	k.pinnedNotBuilt(auto, machinePin)
	k.rt.Reach = []backend.Tier{k.rt.Tier}
	if auto && !machinePin && k.o.tiersSet {
		k.rt.Reach = nil
		for _, t := range backend.Tiers() {
			if t.AtOrBelow(k.rt.Tier) && k.built(t) {
				k.rt.Reach = append(k.rt.Reach, t)
			}
		}
	}

	// uprobe capture needs BPF, so a landlock run tops out at the forwarder.
	tierMax := CaptureUprobe
	if k.rt.Tier == backend.TierLandlock {
		tierMax = CaptureForwarder
	}
	capCeiling := CaptureMode(k.m.Capture.Value.String())
	if !k.m.Capture.Bounded {
		capCeiling = ""
	}
	if capCeiling == "" || capCeiling == CaptureAuto || capCeiling.Rank() > tierMax.Rank() {
		capCeiling = tierMax
	}
	want := k.c.Capture
	switch {
	case want == "" || want == CaptureAuto:
		k.rt.Capture = capCeiling
	case want.Rank() > capCeiling.Rank():
		// Named by where the ceiling came from: the machine config's capture: line, or the tier, which caps a
		// landlock run at the forwarder whatever the config says.
		from := fmt.Sprintf("tier %s, which runs no uprobes", k.rt.Tier)
		if k.buildCapped {
			from = fmt.Sprintf("tier %s, the highest this tego builds, which runs no uprobes", k.rt.Tier)
		}
		if k.m.Capture.Bounded && CaptureMode(k.m.Capture.Value.String()) == capCeiling {
			from = k.m.Capture.Source.String()
		}
		k.ds.warnf(k.pos("capture"), CodeLimitAboveMachine, "ceiling capture=%s kept from %s; the contract asked for %s", capCeiling, from, want).
			fix("set capture: %s or raise the ceiling", capCeiling)
		k.rt.Capture = capCeiling
	default:
		k.rt.Capture = want
	}
	k.rt.Record = k.c.Record
	if k.o.record != "" {
		k.rt.Record = k.o.record
	}
	if k.rt.Record == "" {
		k.rt.Record = RecordSummary
	}
	k.recordOffNote()
	k.recordOffCapture()
}

// recordOffNote notes, at the record: key that set it (a profile's line when the contract extends it), a contract
// whose own record: off is the run's record mode: the ledger then keeps the run's refusals and no program it ran or
// file, connection or other action the contract allowed, so what tego receipt, tego drift and the dashboard show of
// the run is its refusals. It is what the author wrote and weakens no rule, so it is a note (Informational): `tego
// compile` prints it, and a run only under -v, since a run's start speaks only when the person must act or the run
// enforces less than the contract wrote; the run's end says "record off" (limits-check-doctor-cli.md R29, "A quiet
// start"). A record mode the run gives (WithRecord, `tego run --record`) is the launching user's choice: --record off
// has R29's own warning, and a --record that raises the record leaves the contract's off unused.
func (k *compiler) recordOffNote() {
	if k.o.record != "" || k.c.Record != RecordOff {
		return
	}
	k.ds.warnf(k.pos("record"), CodeRecordOff, "record: off keeps only a run's refusals in its ledger: no program it runs, "+
		"and no file it opens or connection it makes that the contract allows").
		fix("set record: summary (the default) or full to record what the agent does; tego run --record summary records one run so").info()
}

// recordOffCapture lowers an auto contract's uprobe capture to the forwarder under record: off. The uprobe source
// captures nothing under record: off (the capture programs keep nothing of the run's calls), so such a run captures
// with the forwarder alone, the one capture.Select starts beside the probes, and the table says so. Its mode is
// what every component reads: as forwarder, GuardedModels guards the models: endpoints, so a direct connection to
// the model host is refused at every tier, as it is at tier landlock, and the forwarder is the agent's only route
// to its model. Compiled as uprobe the table guarded nothing, since the probes read a direct connection's TLS only
// when they run, so a direct connection was neither captured nor refused and a tokens, cost_usd or repeats budget
// was spent past by any agent that ignored the forwarder's base URL. A contract that pins capture:
// uprobe keeps its mode: it asked for no forwarder, and a budget it declares is refused (budgetsUnseenUnderRecordOff).
// The record mode is the run's (WithRecord), so `tego run --record off` lowers it the same way.
//
// Rejected: guarding the endpoints under a uprobe mode whenever the record mode is off (GuardedModels, the
// supervisor's guard, decide and the run's environment would each repeat the condition, and the table would still
// name a capture the run does not have); refusing the run (it can be metered whole, as this does); and lowering only
// when a model budget is bounded (the table's capture would then turn on its limits, and measure's token totals
// would still miss a direct connection).
func (k *compiler) recordOffCapture() {
	if k.rt.Record == RecordOff && k.rt.Capture == CaptureUprobe && !k.rt.PinsUprobe() {
		k.rt.Capture = CaptureForwarder
	}
}

// modelBudgets are the run's bounded tokens, cost_usd and repeats budgets, by their contract names, split into
// the ones the contract (or a profile it extends) declares and the ones a machine ceiling alone imposes.
func (k *compiler) modelBudgets() (declared, imposed []string) {
	l := k.c.Limits
	for _, b := range []struct {
		set      BudgetSet
		name     string
		declared bool
	}{{BudgetTokens, "tokens", l.Tokens != nil}, {BudgetCostUSD, "cost_usd", l.CostUSD != nil}, {BudgetRepeats, "repeats", l.Repeats != nil}} {
		switch {
		case !k.rt.Limits.Bounded(b.set):
		case b.declared:
			declared = append(declared, b.name)
		default:
			imposed = append(imposed, b.name)
		}
	}
	return declared, imposed
}

// budgetsUnseenUnderRecordOff reports that record: off with capture: uprobe leaves the model-traffic budgets
// nothing to count. The uprobe source captures nothing under record: off (it places the probes only for a stall
// budget's activity stamp), since the capture programs keep nothing of the run's calls, so no ssl_response reaches
// the watcher (limits-check-doctor-cli.md R32). Only a contract that pins capture: uprobe gets here: an auto
// contract is compiled to the forwarder under record: off (recordOffCapture), which records the exchanges it relays
// whatever the record mode and is budgetsUnmetered's when it has no models: endpoint to listen for. A pinned
// capture: uprobe runs no forwarder, so its declared budget is reported [budget-unmetered], as the run is refused
// for it (runtime.ErrBudgetUnmetered), and one a machine ceiling alone imposes [unenforced], the run's gap
// why=budget-unmetered naming it.
//
// The record mode is the run's (WithRecord), and the finding names what made it off:
//   - `tego run --record off` over a contract that does not say off: the flag, at the first unseen budget the contract
//     declares rather than at a record: key it may not have, and the fix is to run without the flag, not to write the
//     record: summary the contract may already say;
//   - the contract's record: off, which the flag may repeat: the record: key, and the fix is record: summary, with
//     --record summary when the flag was given, since running without a flag that repeats the contract changes nothing.
//
// A budget the contract does not set, which only the machine's ceiling imposes, is named as the ceiling's, with the
// layer that set it. Under a blamed flag over a contract that declares none of the budgets, the finding sits at the
// contract's first line (k.cpos), for want of a key; the message, not the position, says where the budget came from.
func (k *compiler) budgetsUnseenUnderRecordOff() {
	if k.rt.Record != RecordOff || k.rt.Capture != CaptureUprobe {
		return
	}
	declared, imposed := k.modelBudgets()
	if len(declared)+len(imposed) == 0 {
		return
	}
	at, record, summary, under := k.pos("record"), "record: off", "set record: summary", "record: off"
	switch {
	case k.o.record != "" && k.c.Record != RecordOff:
		at, record, summary, under = k.cpos, "--record off", "run without --record off (or with --record summary)", "--record off"
		if len(declared) > 0 {
			at = k.pos("limits." + declared[0])
		}
	case k.o.record != "":
		record, summary = "record: off, which --record off repeats,", "run with --record summary and set record: summary"
	}
	fixRecord := fmt.Sprintf("%s, or capture: forwarder, which records the exchanges it relays under %s", summary, under)
	if len(k.c.Models) == 0 {
		fixRecord = summary + ", or capture: forwarder with a models: endpoint"
	}
	if len(declared) > 0 {
		k.ds.warnf(at, identity.CodeBudgetUnmetered, "%s with capture: uprobe records no model traffic, so the %s budget sees none of it and never trips, and a run that captures with uprobes is refused",
			record, strings.Join(declared, ", ")).
			fix("%s", fixRecord)
	}
	if len(imposed) > 0 {
		k.ds.warnf(at, CodeUnenforced, "%s with uprobe capture records no model traffic, so the %s budget, which the machine config's ceiling sets (%s), sees none of it and never trips",
			record, strings.Join(imposed, ", "), k.limitSource(imposed[0])).
			fix("%s", fixRecord)
	}
}

// budgetsUnmetered reports that a tokens, cost_usd or repeats budget never trips because nothing meters the
// run's model traffic: capture is off (the contract's capture: off, or a machine ceiling that lowers it
// there), or the contract declares no models: endpoint where the run captures with the forwarder, which
// binds a listener only for a declared endpoint and so never starts (capture.Select, gap why=no-models), which
// includes an auto contract under record: off at every tier (recordOffCapture). Such a
// run is refused at launch, 125 [budget-unmetered] (runtime.ErrBudgetUnmetered, limits-check-doctor-cli.md R32);
// it used to exit 0 with only a gap and this warning tagged [unenforced], a limit that silently did nothing. The
// finding is [budget-unmetered] and a warning, as compile reports a pinned tier the build lacks
// [tier-unavailable]: compile answers for the contract on this machine, while the refusal is the run's, decided
// on the capture that actually starts. The uprobe source reads the agent's own TLS by host, so a run that lands
// where it runs is metered without models:. Only a budget the contract (or a profile it extends) sets is
// reported, at its own line: one a machine ceiling alone imposes is not the contract author's to fix, is not
// refused, and the run's gap what=record why=budget-unmetered names it (internal/runtime).
func (k *compiler) budgetsUnmetered() {
	unmetered, _ := k.modelBudgets()
	if len(unmetered) == 0 {
		return
	}
	at := k.pos("limits." + unmetered[0])
	budgets := "limits." + strings.Join(unmetered, ", limits.")
	noun, trips := "budget", "never trips"
	if len(unmetered) > 1 {
		noun, trips = "budgets", "never trip"
	}
	switch {
	case k.rt.Capture == CaptureOff && (k.c.Capture == CaptureOff || !k.m.Capture.Bounded):
		k.ds.warnf(at, identity.CodeBudgetUnmetered, "%s %s %s: the contract sets capture: off, so no model traffic is metered, and every run of this contract is refused",
			budgets, noun, trips).
			fix("set capture: auto, or remove the %s", noun)
	case k.rt.Capture == CaptureOff:
		k.ds.warnf(at, identity.CodeBudgetUnmetered, "%s %s %s: the machine's capture ceiling is off (%s), so no model traffic is metered, and every run of this contract on this machine is refused",
			budgets, noun, trips, k.m.Capture.Source).
			fix("raise the machine config's capture: ceiling, or remove the %s", noun)
	case len(k.c.Models) > 0:
	case k.rt.Capture == CaptureForwarder:
		k.ds.warnf(at, identity.CodeBudgetUnmetered, "%s %s %s: no models: endpoint is declared, so the forwarder capture does not run and no model traffic is metered, and every run of this contract is refused",
			budgets, noun, trips).
			fix("declare the model endpoint under models: (provider, host, port), or remove the %s", noun)
	case k.mayLand(backend.TierLandlock):
		k.ds.warnf(at, identity.CodeBudgetUnmetered, "%s %s %s where the run lands at tier landlock: no models: endpoint is declared, and there capture is the forwarder alone, which does not run without one, so a run that lands there is refused",
			budgets, noun, trips).
			fix("declare the model endpoint under models: (provider, host, port), or remove the %s", noun)
	}
}

// stallReadsUnseen warns that a stall_after the contract sets does not count a read, or counts it late, where the run
// can land, so an agent busy only reading is ended as stalled. Only a stall_after the contract (or a profile it
// extends) sets is warned: one a machine ceiling alone imposes is not the contract author's to fix. The record mode
// is the run's (WithRecord). The stall check is not given a source that would see reads instead (SEMANTICS §8).
//
// Under record: summary and full the stall check counts the run's lines; under off it counts, at every tier, each
// notification the supervisor answers (internal/runtime's supervisor Activity hook) and, at a root tier, each sample
// the kernel recorder writes and the run's activity stamp. What is unseen is therefore what the run's seccomp filter
// does not notify and the recorder neither writes nor stamps, and a read gate changes both: it, or an fs.ask_read
// entry, has the filter notify every read-open, at every tier and in an
// --observe run (RuleTable.NotifiesReads), so under off each read is answered by the supervisor, activity; under
// summary a read the gate scores is its own line at every tier (the supervisor's at landlock, the recorder's
// gate-scored read, which skips the aggregate, at a root tier), while one an fs.ask_read entry alone notifies gets none
// (quietRead).
//
// At tier landlock, and in an --observe run, which installs the same filter (WithObserve), under record: summary or
// off a read-open never reaches the supervisor (SEMANTICS §7), so a read is neither a line nor activity (custom-agent
// POC, item 4: 14 s of reads ended at 6 s of stall_after: 5s, while record: full ran it to its own end).
//
// At a root tier under record: off nothing is warned: trace_proc writes no sample for an allowed open, path change,
// regular-file create or connect under off, and for a run a stall_after bounds it stamps the run's slot of
// tego_activity instead, which the stall check pulls once a tick (limits-check-doctor-cli.md R4), so a
// read, and a write-open or path change the decision plane decides in the kernel, is activity at once there. Before
// the stamp they were none, and that was warned at the root tiers; the landlock warning under off now offers a root
// tier as it is, where it offered one only with
// record: summary.
//
// At a root tier under record: summary a read reaches the record, and so the stall check, only in the aggregate the
// recorder flushes every ReadAggregationWindow, up to that long after it happened (record: full records each read). A
// stall_after under twice the window is warned there: one at or under the window ends a pure reader
// between two flushes, and one under twice the window leaves a pause shorter than the window enough to end a reader.
// Each warning holds in its own tiers alone (Diagnostic.Tier), so `tego run` prints the one for the tier the run
// lands at.
//
// Each fix offers only what changes the run it is printed for: a root tier is no
// way out of an --observe run, which installs tier landlock's filter whatever tier is pinned, so a warning that holds
// only there offers record: full and a longer stall_after alone, and one that holds at landlock too offers a root tier
// outside --observe and without `tego run --tier landlock` (WithTierFlag), which refuses a contract's other pin as a
// conflict, and only a root tier this binary builds and the machine's tier ceiling admits
// (rootTiersPinnable); under record: summary a root tier is a way out only with a stall_after of at least twice the
// window, and under off it is one as it is, its kernel stamping each allowed open; and a mode that came from --record
// is changed with --record.
func (k *compiler) stallReadsUnseen() {
	if k.c.Limits.StallAfter == nil || !k.rt.Limits.Bounded(BudgetStallAfter) || k.rt.Record == RecordFull {
		return
	}
	stall := k.rt.Limits.StallAfter
	off := k.rt.Record == RecordOff
	// readsSeen: every read is a line (summary, a read gate scores it) or a notification the supervisor answers (off).
	// Reason reads (ADR 0077) notify at tier landlock alone, never in an --observe run.
	readsSeen := k.rt.Gate.Has(gate.FSRead) || off && k.rt.NotifiesReads()
	observeSeen := k.rt.Gate.Has(gate.FSRead) || off && k.rt.notifiesReadsEverywhere()
	if readsSeen && (observeSeen || !k.o.observe) {
		return
	}
	record, full := "record: "+string(k.rt.Record), "set record: full"
	if k.o.record != "" {
		record, full = "--record "+string(k.rt.Record), "run with --record full"
	}
	window, floor := Duration(ReadAggregationWindow).String(), Duration(2*ReadAggregationWindow).String()
	aggregates := fmt.Sprintf("whose recorder counts reads in aggregates it flushes every %s", window)
	var unseen []backend.Tier
	where := "at tier landlock"
	if k.mayLand(backend.TierLandlock) && !readsSeen {
		unseen = append(unseen, backend.TierLandlock)
	}
	if k.o.observe && !observeSeen {
		unseen = append(unseen, backend.TierObserve)
		where = "in an --observe run (tier landlock's filter)"
		if len(unseen) > 1 {
			where = "at tier landlock and in an --observe run"
		}
	}
	if len(unseen) > 0 {
		root := ""
		if pins := k.rootTiersPinnable(); unseen[0] == backend.TierLandlock && len(pins) > 0 {
			pin := "pin tier: " + string(pins[0])
			if len(pins) > 1 {
				pin = "pin a root tier (cgroup or bpflsm)"
			}
			// A root tier pinned in the contract is no way out while a flag keeps the run at landlock's filter:
			// --observe installs it whatever tier is pinned, and --tier landlock refuses another pin as a conflict.
			var while []string
			if k.o.observe {
				while = append(while, "outside --observe")
			}
			if k.o.tierFlag == backend.TierLandlock {
				while = append(while, "without --tier landlock")
			}
			if len(while) > 0 {
				pin = strings.Join(while, " and ") + ", " + pin
			}
			root = fmt.Sprintf(", or %s with a stall_after of at least %s, %s", pin, floor, aggregates)
			if off {
				root = fmt.Sprintf(", or %s, where the kernel stamps each allowed open as activity at once", pin)
			}
		}
		k.ds.warnf(k.pos("limits.stall_after"), CodeStallReadsUnseen, "limits.stall_after counts only what the run records, and %s under %s a read is not recorded: an agent that does nothing but read for %s is ended as stalled",
			where, record, Duration(stall).String()).
			fix("%s, under which every read is a line%s; or raise stall_after past the longest stretch of reading", full, root).
			only(unseen...)
	}
	// Under off a root tier stamps each allowed open, path change and connect as the run's activity: nothing to warn.
	if off {
		return
	}
	var roots []backend.Tier
	for _, t := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
		if k.mayLand(t) {
			roots = append(roots, t)
		}
	}
	if len(roots) == 0 || stall >= 2*ReadAggregationWindow {
		return
	}
	names := make([]string, len(roots))
	for i, t := range roots {
		names[i] = string(t)
	}
	k.ds.warnf(k.pos("limits.stall_after"), CodeStallReadsUnseen, "limits.stall_after counts only what the run records, and at tier %s under %s a read is recorded in an aggregate flushed every %s, up to that long after it happened: an agent that does nothing but read can be ended as stalled under a stall_after of %s, less than twice that window",
		strings.Join(names, " or "), record, window, Duration(stall).String()).
		fix("raise stall_after to at least %s, or %s, under which every read is a line", floor, full).
		only(roots...)
}

// rootTiersPinnable is the root tiers a contract that pins one is run at on this machine by this binary: those it
// builds (WithTiers, when given), at or below the machine config's tier, which pins every run and lowers a higher pin
// (tierAndCapture). A fix offers to pin only these: on a landlock-only build a pinned root tier is
// refused [tier-unavailable] (pinnedNotBuilt), and under a landlock ceiling it is lowered to landlock.
func (k *compiler) rootTiersPinnable() []backend.Tier {
	ceiling := backend.TierBPFLSM
	if v := backend.Tier(k.m.Tier.Value.String()); k.m.Tier.Bounded && v != "" && v != backend.TierAuto {
		ceiling = v
	}
	var out []backend.Tier
	for _, t := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
		if t.AtOrBelow(ceiling) && (!k.o.tiersSet || k.built(t)) {
			out = append(out, t)
		}
	}
	return out
}

// pinnedNotBuilt warns that the tier the table was compiled for is pinned, by the contract or by the machine
// config, and this binary does not build it (WithTiers): every run of it is refused [tier-unavailable], and
// compile said nothing while its table and compile --test answered in that tier (limits-check-doctor-cli.md R32). An
// auto contract left to the machine is never compiled for a tier the binary lacks (highestBuilt).
func (k *compiler) pinnedNotBuilt(auto, machinePin bool) {
	if !k.o.tiersSet || k.built(k.rt.Tier) || (auto && !machinePin) {
		return
	}
	pos, by := k.pos("tier"), "the contract pins it"
	if auto || backend.Tier(k.c.Tier) != k.rt.Tier {
		pos, by = k.cpos, "the machine config pins it at "+k.m.Tier.Source.String()
	}
	k.ds.warnf(pos, backend.CodeTierUnavailable, "tier %s is not built into this tego, and %s: every run of this contract is refused", k.rt.Tier, by).
		fix("pin a tier this tego builds (tego doctor lists them), use a build with tier %s, or leave tier: auto", k.rt.Tier)
}

// highestBuilt is the highest tier at or below ceiling this binary builds, when WithTiers said which; the
// ceiling itself otherwise, and when the binary builds none of them (Select then refuses the run).
func (k *compiler) highestBuilt(ceiling backend.Tier) backend.Tier {
	if !k.o.tiersSet {
		return ceiling
	}
	tiers := backend.Tiers()
	for i := len(tiers) - 1; i >= 0; i-- {
		if tiers[i].AtOrBelow(ceiling) && k.built(tiers[i]) {
			return tiers[i]
		}
	}
	return ceiling
}

// built reports whether WithTiers named t.
func (k *compiler) built(t backend.Tier) bool {
	return slices.Contains(k.o.tiers, t)
}

// heldAt reports whether every run of the table is given tier t: the table's tier is t, and the contract pins it
// or the machine config holds it, rather than auto choosing it from what the machine offers.
func (k *compiler) heldAt(t backend.Tier) bool {
	if k.rt.Tier != t {
		return false
	}
	if pin := backend.Tier(k.c.Tier); pin != "" && pin != backend.TierAuto {
		return true
	}
	ceiling := backend.Tier(k.m.Tier.Value.String())
	return k.m.Tier.Bounded && ceiling != "" && ceiling != backend.TierAuto
}

// mayLand reports whether a run of the table can be given tier t (RuleTable.Reach).
func (k *compiler) mayLand(t backend.Tier) bool {
	return slices.Contains(k.rt.Reach, t)
}

// modelBypassLowered reports a net.allow entry that cannot grant direct model access when the machine
// lowers pinned uprobe capture to a forwarder. A run that stays at uprobe needs that direct allowance.
func (k *compiler) modelBypassLowered() {
	if !k.rt.PinsUprobe() || k.c.Tier == TierPin(backend.TierLandlock) {
		return
	}
	if k.rt.Capture != CaptureForwarder {
		if backend.TierCgroup.AtOrBelow(backend.Tier(k.c.Tier)) {
			return // a pinned tier that runs uprobes: no forwarder, nothing to bypass
		}
		for _, m := range modelAllows(k.c) {
			k.ds.warnf(m.at, CodeModelDirectBypass, "net.allow %q is the agent's own route to the %s model host, which capture: uprobe reads at tier cgroup or above; a run at a lower tier captures through the forwarder instead, and direct model access stays refused", m.raw, m.provider).
				fix("keep it for uprobe capture and pin tier: cgroup so the run never falls to a lower tier, or set capture: forwarder and remove it")
		}
		return
	}
	why := "capture ceiling is forwarder"
	switch {
	case k.rt.Tier == backend.TierLandlock && k.buildCapped:
		why = "tego builds tier landlock alone, which runs no uprobes"
	case k.rt.Tier == backend.TierLandlock:
		why = "tier ceiling is landlock, which runs no uprobes"
	}
	for _, m := range modelAllows(k.c) {
		k.ds.warnf(m.at, CodeModelDirectBypass, "net.allow %q cannot grant direct access to the %s model under the forwarder guard: "+
			"this machine's %s, so the contract's capture: uprobe runs the forwarder", m.raw, m.provider, why).
			fix("remove it from net.allow; the forwarder reaches the model host on the run's behalf")
	}
}

// Runtime-reserved environment names (SEMANTICS §9, R12).
const runtimeReservedPrefix = "TEGO_"

var proxyVars = map[string]bool{"HTTPS_PROXY": true, "HTTP_PROXY": true, "ALL_PROXY": true}

// env applies R12: the pass list minus deny and minus runtime-reserved names
// (warned), env.set kept whole with the same warnings, proxy variables
// flagged (SEMANTICS §5), and the run's effective PATH derived for R8 (I8).
func (k *compiler) env() {
	e := k.c.Env
	denied := make(map[string]bool, len(e.Deny))
	for _, n := range e.Deny {
		denied[n] = true
	}
	// The forwarder sets its variables wherever it runs: capture: forwarder, and uprobe reached through auto.
	// A contract that pins uprobe runs no forwarder where the tier runs uprobes, so its ANTHROPIC_BASE_URL is
	// its own there (PinsUprobe). The run's tier can still be lower than the one resolved here, and there the
	// forwarder runs after all: `tego run` warns then, when it knows (PinsUprobe's comment).
	forwarding := k.rt.Capture == CaptureForwarder || (k.rt.Capture == CaptureUprobe && !k.rt.PinsUprobe())
	if e.Pass != nil {
		k.rt.Env = make([]string, 0, len(e.Pass))
		for i, n := range e.Pass {
			if denied[n] {
				continue
			}
			if k.reserved(n, forwarding, "env.pass."+strconv.Itoa(i), "pass") {
				continue
			}
			k.rt.Env = append(k.rt.Env, n)
		}
	}
	k.rt.Deny = append([]string(nil), e.Deny...)
	if e.Set != nil {
		k.rt.Set = make(map[string]string, len(e.Set))
		keys := make([]string, 0, len(e.Set))
		for n := range e.Set {
			keys = append(keys, n)
		}
		sort.Strings(keys)
		for _, n := range keys {
			k.reserved(n, forwarding, "env.set."+n, "set")
			k.rt.Set[n] = strings.ReplaceAll(e.Set[n], ProjectDirToken, k.o.cwd)
		}
	}
	k.rt.PATH = k.effectivePATH(denied)
}

// reserved warns on a runtime-reserved or proxy variable; true means the name
// is runtime-owned and must leave the pass list.
func (k *compiler) reserved(name string, forwarding bool, key, verb string) bool {
	switch {
	case strings.HasPrefix(name, runtimeReservedPrefix):
		k.ds.warnf(k.pos(key), CodeEnvRuntimeReserved, "env.%s %s is set by the runtime and cannot be %sed by the contract", verb, name, verb).
			fix("remove %s; the run sets it", name)
		return true
	case forwarding && name == identity.EnvCodexHome:
		// The launcher reads the contract's CODEX_HOME to find the user's config.toml it copies into the run's
		// own (internal/runtime codexhome.go), so it stays in the pass list.
		k.ds.warnf(k.pos(key), CodeEnvRuntimeReserved, "env.%s %s is replaced by the run's own when the capture forwarder (capture: %s) serves an openai model; the contract's value only names the Codex config.toml the run copies", verb, name, k.rt.Capture).
			fix("keep %s only to name that config, or set capture: off", name).info()
	case forwarding && identity.ForwarderVar(name):
		// identity.ForwarderVar recognizes the fixed forwarder-owned variables (R7).
		k.ds.warnf(k.pos(key), CodeEnvRuntimeReserved, "env.%s %s is set by the capture forwarder (capture: %s) and the contract's value is overridden", verb, name, k.rt.Capture).
			fix("remove %s or set capture: off", name)
		return true
	case proxyVars[strings.ToUpper(name)]:
		k.ds.warnf(k.pos(key), CodeProxyEnv, "env.%s %s changes the effective destination of every connect; net.allow is matched on the proxy", verb, name).
			fix("allow the proxy's host:port in net.allow and expect NO_PROXY to gain 127.0.0.1,localhost")
	}
	return false
}

// effectivePATH is the PATH the run will see: env.set wins, then the
// inherited value when env.pass admits it (or there is no pass list) and
// env.deny does not remove it.
func (k *compiler) effectivePATH(denied map[string]bool) string {
	if v, ok := k.rt.Set["PATH"]; ok {
		return v
	}
	if denied["PATH"] || !k.o.pathSet {
		return ""
	}
	if k.c.Env.Pass == nil {
		return k.o.path
	}
	for _, n := range k.c.Env.Pass {
		if n == "PATH" {
			return k.o.path
		}
	}
	return ""
}
