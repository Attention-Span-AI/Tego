// SPDX-License-Identifier: Apache-2.0

// Package conformance is ADR 0017's kernel conformance suite: cells, each a contract fragment (its Fixture), one
// action and the verdict every tier must give it. The handwritten cells are tables in spec/policy/conformance
// (schema v2, its README), loaded by fixtures.go. Two runners read them. The unprivileged one (conformance_test.go)
// asks `tego compile --test` for each cell's verdict per tier (ADR 0019). The kernel one
// (kernel_integration_test.go) performs each action in a real `tego run` on every axis the machine offers (tier
// landlock, tier cgroup on the listener and in each plane mode, tier bpflsm) and checks the kernel's own result,
// the ledger line's verdict and rule, and invariants derived from the contract alone against the cell. No model is
// inside it (ADR 0003): every expectation is written in the tables, from SEMANTICS and the specs, never computed
// from Evaluate, the Landlock plan or the decision core.
//
// The mode axis (ADR 0017, TIER3-PLAN §5, §9) is the second half of a Want's Key. Tier landlock has no plane mode.
// A table's three columns are Key{landlock, ""}, Key{cgroup, fanotify} and the plane column Key{bpflsm, lsm}, which
// tier cgroup's plane modes answer as well (planeAxis).
package conformance

import (
	"sort"

	"golang.org/x/sys/unix"
)

// Tier is an enforcement tier by its name in compile --test and the ledger.
type Tier string

// The tiers a cell can name. TierBPFLSM is answered by compile --test only until tier 3 is buildable.
const (
	TierLandlock Tier = "landlock"
	TierCgroup   Tier = "cgroup"
	TierBPFLSM   Tier = "bpflsm"
)

// Mode is the decision plane a tier's decisions come from (ADR 0024).
type Mode string

// The modes. ModeNone is the tiers that have no plane mode (landlock).
const (
	ModeNone     Mode = ""
	ModeLSM      Mode = "lsm"
	ModeFmodRet  Mode = "fmod_ret"
	ModeFanotify Mode = "fanotify"
)

// Modes lists the mode axis in order; FilledModes is what v1 has expectations for.
var (
	Modes       = []Mode{ModeLSM, ModeFmodRet, ModeFanotify}
	FilledModes = []Mode{ModeFanotify}
)

// Key selects one expectation of a cell.
type Key struct {
	Tier Tier
	Mode Mode
}

// MarshalText spells a Key tier/mode, so a fixture encodes as JSON (the generated manifest's sha256).
func (k Key) MarshalText() ([]byte, error) { return []byte(string(k.Tier) + "/" + string(k.Mode)), nil }

// Verdicts as compile --test and the ledger spell them.
const (
	Allow   = "allow"
	Refused = "refused"
	// Observed is a ledger line's verdict for an outcome no Tego mechanism explains (ADR 0016: by: other).
	Observed = "observed"
)

// Want is what one (tier, mode) must give a cell.
type Want struct {
	Verdict string
	// Rule is the rule the answer names; "" leaves the rule unchecked.
	Rule string
	// NoLine says the run's ledger holds no verdict line for the action at this tier (the tier's own recorder
	// does not see it), so the ledger check asks for none.
	NoLine bool
	// Errno, when nonzero, is the errno a refusal must carry; 0 leaves it unchecked.
	Errno int
	// Ledger, when set, is the verdict the ledger line holds where it differs from the kernel's answer by design: a
	// third party's refusal (ADR 0016: the line is the mechanism's answer, Tego's allow, or observed with by: other
	// where the kernel's recorder sees the refusal unexplained). Empty: the line holds Verdict.
	Ledger string
}

// The actions of v1, as the actor (test/conformance/cmd/actor) names them. They are plain strings, not an enum:
// the runners switch over a few and treat the rest alike. Each maps onto a compile --test action name where one
// exists (compileAction).
const (
	OpRead      = "read"
	OpWriteOpen = "write-open"
	OpCreate    = "create"
	// OpCreat is creat(2): O_WRONLY|O_CREAT|O_TRUNC, no O_EXCL. On x86-64 it is the legacy syscall, which the filter
	// notifies under a number of its own (the supervisor's handleCreat); arm64 has none, and the actor opens with
	// those flags there.
	OpCreat = "creat"
	// OpOpenTrunc is an open of an existing file O_WRONLY|O_TRUNC: a write open that also truncates.
	OpOpenTrunc = "open-trunc"
	OpTruncate  = "truncate"
	OpUnlink    = "unlink"
	OpRmdir     = "rmdir"
	OpMkdir     = "mkdir"
	OpRename    = "rename"
	// OpExchange is renameat2(RENAME_EXCHANGE): Path and Dest, both existing, swap names, so each end leaves its name
	// and takes the other's.
	OpExchange = "exchange"
	OpSymlink  = "symlink"
	OpLink     = "link"
	OpChmod    = "chmod"
	OpExec     = "exec"
	// OpMapExec maps a page of Path PROT_READ|PROT_EXEC, MAP_PRIVATE (ADR 0027): only a decision plane decides it.
	OpMapExec    = "map-exec"
	OpConnectTCP = "connect-tcp"
	OpConnectUDP = "connect-udp"
	// OpSendUDP sends one datagram to Addr from an unconnected UDP socket, sendto(2): the send path (the
	// supervisor's sendto and sendmsg, cgroup/sendmsg4 and sendmsg6, the plane's socket_sendmsg), not the connect.
	OpSendUDP = "send-udp"
	// OpConnectUnix connects a stream unix socket to Addr: a pathname, or @name for an abstract name (ADR 0070). A host
	// daemon's socket is HostSocket or HostAbstract, which the runner binds outside the run.
	OpConnectUnix = "connect-unix"

	// The exec space's spellings (ADR 0017 space 2), each a way to run or map code that is not an execve of a path
	// exec.allow names. The actor performs each (cmd/actor/spell.go).

	// OpExecLoader execs the dynamic loader directly, Path ({{LOADER}}, the PT_INTERP of the machine's own
	// /usr/bin/true), with Dest as its program: `ld.so /usr/bin/true` (SEMANTICS §4, the direct loader). The exec
	// counts as allowed once the loader started, whatever the program's own exit (glibc 2.42's argv[0] guard).
	OpExecLoader = "exec-loader"
	// OpExecveatFD execs Path by an O_PATH descriptor, execveat(fd, "", AT_EMPTY_PATH): the inode, no name.
	OpExecveatFD = "execveat-fd"
	// OpExecProcFD execs Path by /proc/self/fd/N of an O_PATH descriptor.
	OpExecProcFD = "exec-proc-fd"
	// OpMemfdCreate creates a memfd the kernel would exec (no MFD_NOEXEC_SEAL; enforce-landlock R11a).
	OpMemfdCreate = "memfd-create"
	// OpMemfdExec writes the actor into a memfd and execs it by /proc/self/fd/N: an anonymous image.
	OpMemfdExec = "memfd-exec"
	// OpMemfdMapExec maps a page of a memfd PROT_READ|PROT_EXEC.
	OpMemfdMapExec = "memfd-map-exec"
	// OpMapExecRIE maps a page of Path PROT_READ under personality(READ_IMPLIES_EXEC), whose effective prot carries
	// PROT_EXEC (ADR 0027).
	OpMapExecRIE = "map-exec-rie"
	// OpMprotectExec maps a page of Path PROT_READ and mprotects it PROT_READ|PROT_EXEC.
	OpMprotectExec = "mprotect-exec"
	// OpMprotectRIE maps a page of Path PROT_NONE and mprotects it PROT_READ under READ_IMPLIES_EXEC.
	OpMprotectRIE = "mprotect-rie"
	// OpExecmod maps a page of Path MAP_PRIVATE writable, writes it, and mprotects it PROT_READ|PROT_EXEC (SELinux's
	// execmod, ADR 0027 (c)).
	OpExecmod = "execmod"
	// OpExecmem maps a page of Path MAP_PRIVATE PROT_READ|PROT_WRITE|PROT_EXEC (SELinux's execmem, ADR 0027 (c)).
	OpExecmem = "execmem"

	// Space 4's ops (ADR 0017 space 4): the attribute changes and nodes a deny_write target's ancestors must refuse,
	// and the TOCTOU harness (cmd/actor/attr.go, race.go).

	// OpChown chowns Path to the agent's own uid and gid: no change of owner, but path_chown runs all the same.
	OpChown = "chown"
	// OpSetxattr sets the user.tego xattr on Path.
	OpSetxattr = "setxattr"
	// OpSetfacl sets Path's access ACL as setfacl does, through its system.posix_acl_access xattr: the minimal ACL
	// of mode 0640, which the kernel stores as the mode (inode_set_acl from 6.2, the setxattr hooks before).
	OpSetfacl = "setfacl"
	// OpMknod makes a FIFO at Path.
	OpMknod = "mknod"
	// OpRaceSymlinkRead swaps the symlink Path between a benign file it writes (Path.benign) and the target Dest
	// with rename(2) on one thread, and opens and reads Path on another, 2,000 times or 2 s. It succeeds when a byte
	// of the target was read through the link, and is refused when none was and an open of it was refused while
	// benign opens went through. The cell's Canon is Dest: the file the race is about.
	OpRaceSymlinkRead = "race-symlink-read"
	// OpRaceSymlinkWrite is OpRaceSymlinkRead opening Path O_WRONLY|O_APPEND and writing one byte.
	OpRaceSymlinkWrite = "race-symlink-write"
	// OpRaceArgvExec is ADR 0048's disclosed argv race (R5, exec.rules/argv): Path is a copy of the actor under a
	// ruled tool's name and Argv its denied vector [tool, word]. Each attempt (500, or 2 s) is a stage that execs
	// Path with argv[1] in a buffer another of its threads flips between the word and RaceArgvBenign, and the copy
	// reports the word it ran with. It is refused when an attempt was refused and succeeds when none was; the
	// attempts that ran the word, the disclosed race's wins, are its value, measured and never judged. Its lines
	// are Path's exec lines whose copied argv read the word: none may say allow.
	OpRaceArgvExec = "race-argv-exec"

	// The process and control ops (FEATURES E54, enforce-plane §2.20): the agent's own ptrace, keyring
	// and bpf(2) calls (cmd/actor/control.go). Each reports, as its result's value, the pid its hook names.

	// OpPtraceAttach attaches to Target with PTRACE_ATTACH, waits for the stop and detaches.
	OpPtraceAttach = "ptrace-attach"
	// OpPtraceTraceme asks to be traced, PTRACE_TRACEME, by the parent Target names: TargetParent, a child of the
	// actor asking the actor, or TargetOrphan, a grandchild whose parent exited, asking the subreaper it was
	// reparented to outside the run.
	OpPtraceTraceme = "ptrace-traceme"
	// OpKeyctl is keyctl(KEYCTL_GET_KEYRING_ID) of the process keyring, created if absent.
	OpKeyctl = "keyctl"
	// OpAddKey adds a user key to the process keyring, add_key(2).
	OpAddKey = "add-key"
	// OpRequestKey looks a user key up, request_key(2), with no callout.
	OpRequestKey = "request-key"
	// OpBPF creates a one-entry array map, bpf(BPF_MAP_CREATE).
	OpBPF = "bpf"
)

// The kernel runner's await handshake for a fixture's later files (Fixture.Later): the script's first action, never a
// cell, has the actor print AwaitReady on its own line and wait until the file at its path exists; the runner, a
// process outside the run, writes the later files when it reads the line and that file after them.
const (
	// OpAwaitLater is the handshake's action (cmd/actor's await-later).
	OpAwaitLater = "await-later"
	// AwaitReady is the line the actor prints when it waits.
	AwaitReady = `{"await":"ready"}`
	// AwaitGo is the file, relative to the project, the runner writes once the later files are written.
	AwaitGo = "await-go"
)

// The targets a process op names (Cell.Target).
const (
	// TargetChild is a child of the actor that only waits, in the run.
	TargetChild = "child"
	// TargetParent is the actor itself, as the parent its child's TRACEME names.
	TargetParent = "parent"
	// TargetOrphan is the subreaper an orphaned grandchild of the actor is reparented to: outside the run.
	TargetOrphan = "orphan"
	// TargetHost is a process of the agent's uid outside every run, which the runner starts for the fixture.
	TargetHost = "{{HOSTPID}}"
)

// HostSocket and HostAbstract are a pathname and an abstract unix socket the runner binds for the fixture outside
// every run, outside the project, standing in for a host daemon's socket (ADR 0070): a connect-unix cell's addr names
// them.
const (
	HostSocket   = "{{HOSTSOCK}}"
	HostAbstract = "{{HOSTABSTRACT}}"
)

// raceOps are the TOCTOU harness's ops: one action of thousands of syscalls, whose ledger holds a line per open.
var raceOps = map[string]bool{OpRaceSymlinkRead: true, OpRaceSymlinkWrite: true, OpRaceArgvExec: true}

// RaceArgvBenign is the word OpRaceArgvExec's racing thread puts in place of the denied one: four letters, as the
// denied word must have, so the flip is a copy within one buffer.
const RaceArgvBenign = "diff"

// controlOps are the process and control ops, each with the op its refused ledger line names: the plane's process
// hooks' (ptrace, ptrace_traceme) and the supervisor's keyring arm's (keyctl, add_key, request_key); bpf(2) is
// refused by the filter, which writes no line, or by the plane's hook (op bpf).
var controlOps = map[string]string{OpPtraceAttach: "ptrace", OpPtraceTraceme: "ptrace_traceme", OpKeyctl: "keyctl",
	OpAddKey: "add_key", OpRequestKey: "request_key", OpBPF: "bpf"}

// targetOps are the control ops that name a Target, each with the targets it takes.
var targetOps = map[string][]string{OpPtraceAttach: {TargetChild, TargetHost}, OpPtraceTraceme: {TargetParent, TargetOrphan}}

// Cell is one conformance case.
type Cell struct {
	// Name is unique within its fixture; the cell's ID is fixture/name.
	Name string
	Op   string
	// Path and Dest are as the agent spells them, relative to the project directory. For a rename Path is the
	// source and Dest the destination; for an exchange the two names it swaps; for a link Path is the existing file
	// and Dest the new name; for a symlink Path is the new link and Dest what it points at. Every cell owns its Path (and Dest), so the ledger line
	// of one action is never another's.
	Path, Dest string
	// Canon is the path the kernel reports when it differs from Path (a spelling through a symlink); the ledger
	// line is looked up under it.
	Canon string
	// Addr is a connect's destination; {{PORT}} and {{PORT2}} name the fixture's two listeners, HostSocket and
	// HostAbstract its host daemon sockets.
	Addr string
	// Target is a process op's peer (targetOps): TargetChild, TargetParent, TargetOrphan or TargetHost.
	Target string `json:",omitempty"`
	// Want holds the expectations, keyed by tier and mode. A cell with no key for a tier is not asked of it.
	Want map[Key]Want
	// Source names where the cell came from (a cross-check table, verdicts.yaml, a spec rule).
	Source string
	// NoCompile says compile --test has no action for this op, with the reason; the compile runner skips it.
	NoCompile string
	// Finding, when set, says the kernel is known to allow, at tier FindingAt, what this cell's contract-derived
	// expectation refuses (a fail-open, ADR 0017): the root runner reports it and does not assert on it there,
	// and fails once the kernel stops allowing it, so the note is removed with the fix. A finding is never in the
	// baseline and is fixed, not baselined; the text says where.
	Finding   string
	FindingAt Tier
	// Exception, when set, names a stated per-tier exception (SEMANTICS §2) under which the tier ExceptionAt
	// allows what an invariant would refuse: the cell is not a finding, and Invariant accepts the allow there.
	Exception   string
	ExceptionAt Tier
	// Script is an exec cell's #! script, named to compile --test as `script:`.
	Script string
	// ScriptArg is the #! line's optional argument, compile --test's `script_arg:` (ADR 0048 (4)).
	ScriptArg string
	// Argv is an exec cell's whole vector, argv[0] included, as the actor passes it to execve and compile --test
	// reads it (`argv:`). nil is the actor's own [Path, "noop"], which no command rule reads.
	Argv []string
	// Runs is the program the kernel runs for an exec cell, relative to the project, when it is not the image the
	// cell names: a script's #! interpreter as its walk resolves it, or the applet a multicall image (a file of more
	// than one link under a name uutils links its file under) runs by its name (ADR 0048 (2) 4). The command-rule
	// invariant reads its basename.
	Runs string
	// Generated is a cell the generator made (gen.go): it has no Want, and its judge is the kernel, held to the
	// ledger, to compile --test's column for the axis, to the invariants and to the effect judge (ADR 0017 D1).
	Generated bool
	// Unasked are the columns the cell states no expectation for, each with the reason (a tier that decides nothing
	// of the action, best effort against it by design, or whose answer is the machine's filesystem, not Tego's). The
	// runners ask nothing there; the action still runs, and its effect and the invariants are judged where they bind
	// (AxisReport.JudgeFailOpens runs before the kernel runner looks for the column; TestJudgeCatchesAMutatedContract's
	// unasked fixture holds it).
	Unasked map[Key]string `json:",omitempty"`
	// WantWhere are expectations a machine fact changes, in order; the first that matches the machine and has a
	// column replaces the cell's Want for that column (WantOn). compile --test, which makes no kernel call, reads Want.
	WantWhere []CondWant `json:",omitempty"`
}

// Fixture is one contract with the files its cells act on, run once per tier (ADR 0017: all actions of one
// contract run in one tego run).
type Fixture struct {
	Name string
	// Contract is the agent.yaml. {{P}} is the project directory, {{PORT}} and {{PORT2}} the listeners.
	Contract string
	Dirs     []string
	// Files are created with mode 0644; Scripts with 0755; Actors are copies of the actor binary (0755).
	Files   map[string]string
	Scripts map[string]string
	Actors  []string
	// ExecOnlyActors are copies of the actor binary its owner may execute and nobody may read (0111).
	ExecOnlyActors []string `json:",omitempty"`
	// Links maps a symlink to its target as written; HardLinks maps a new name to the file it links.
	Links     map[string]string
	HardLinks map[string]string
	// Fifos are named pipes, mode 0755, that an exec cell names (a file the kernel never executes).
	Fifos []string
	// ThirdPartyDeny are files, relative to the project, a third-party fanotify permission listener refuses every open
	// of (test/vm/cmd/permlistener -mode deny) while the run lasts: ADR 0017 space 6. Root only.
	ThirdPartyDeny []string `json:",omitempty"`
	// Mounts are made by the root runner before the run, in a mount namespace of the run's own (ADR 0017 space 5):
	// the run's launcher, its supervisor and the agent see them, the host does not. Root only.
	Mounts []Mount `json:",omitempty"`
	// Later are files (0644, content as Files') a process outside the run writes after the run compiled and filled
	// its rules and before the actor's first cell: a file made after compile, which only a name entry decides (ADR
	// 0043; the kernel runner's await handshake, cmd/actor's await-later). Layout writes none of them, so compile,
	// compile --test and the decide core see the tree without them. Each one's parent is a Dirs entry; never with
	// Mounts.
	Later map[string]string `json:",omitempty"`
	// Model is the contract's own declared entries, relative to the project, for invariants derived from the
	// contract alone (invariants.go).
	Model Model
	// Net starts the two loopback listeners the contract's {{PORT}} and {{PORT2}} name.
	Net   bool
	Cells []Cell
}

// Mount is one mount a fixture's run sees (Fixture.Mounts), each path relative to the project.
type Mount struct {
	// Kind is MountBind, MountOverlay, MountBtrfs or MountTmpfs.
	Kind string
	// At is the mount point, an existing directory of the fixture's tree.
	At string
	// From is a bind mount's source.
	From string `json:",omitempty"`
	// Lower, Upper and Work are an overlay's directories; Upper and Work lie on one filesystem.
	Lower, Upper, Work string `json:",omitempty"`
	// Subvolumes are a btrfs mount's subvolumes, made at its root (a loop mount of an empty btrfs image).
	Subvolumes []string `json:",omitempty"`
	// Files are written on the mounted filesystem once it is mounted, relative to At, owned by the agent.
	Files map[string]string `json:",omitempty"`
}

// The mount kinds.
const (
	MountBind    = "bind"
	MountOverlay = "overlay"
	MountBtrfs   = "btrfs"
	MountTmpfs   = "tmpfs"
)

// The fs.reads values the model reads (ADR 0069 D1); "" and "auto" are the default.
const (
	ReadsHeld   = "held"
	ReadsDirect = "direct"
)

// Model is the declared entries the invariants read: what the contract says, never what a tier enforces.
type Model struct {
	Write, DenyRead, ExecAllow []string
	// NetDeclared is true when the contract has a net: section; NetAllow its declared host:port entries.
	NetDeclared bool
	NetAllow    []string
	// NetRuntime lists destinations the runtime admits on its own authority (the resolver, supervisor.md R14).
	NetRuntime []string
	// HostSockets is the contract's host_sockets: true (ADR 0070): without it and without a net: section, a unix
	// socket the run did not bind is unreachable.
	HostSockets bool `json:",omitempty"`
	// DenyWrite lists deny_write targets the contract's write entries hold: the built-in set's and the contract's own
	// fs.deny_write entries (ADR 0071).
	DenyWrite []string
	// DenyWriteDeclared lists the members of DenyWrite the contract declared in fs.deny_write (ADR 0071): a write entry
	// strictly beneath one reopens its subtree (nearest wins), which no built-in target allows, and run_start lists its
	// best-effort cell as fs.deny_write, apart from the built-in set's deny_write/default.
	DenyWriteDeclared []string `json:",omitempty"`
	// FSAssuranceKernel is a contract with fs.assurance: kernel, which a tier no decision plane decides refuses
	// before the actor starts when DenyWrite is not empty (ADR 0041 D1 (a), enforce-landlock R5a).
	FSAssuranceKernel bool
	// ExecDeny is the contract's exec.deny and exec.ask entries, as written (ADR 0048 (1)): P1 refuses both at every
	// tier, and the command-rule invariant reads them (invariants_exec.go).
	ExecDeny []string
	// ExecAllowCommands is the contract's exec.allow entries with words, each as `<command> <words...>` (the image
	// path's basename and the words, ADR 0048 (1)): a tool one names runs only as one names it (invariants_exec.go).
	ExecAllowCommands []string `json:",omitempty"`
	// Reads is the contract's fs.reads (ADR 0069), as written: "" for the default, auto, ReadsHeld or ReadsDirect.
	// Under auto and held a run at tier landlock refuses the reads of a deny_read inside a write entry (held reads);
	// under direct the entry stays readable there.
	Reads string `json:",omitempty"`
	// HeldOpens is a contract whose gate chose completion: held with fs rules that can score to allow or above (ADR 0041
	// Stage B): every open of its run is completed by the open deputy, so the run's best_effort lists neither open
	// cell, or the deputy did not start.
	HeldOpens bool
	// ExecAnonymous: the contract opts out of the memfd arm with exec: {anonymous: true} (SEMANTICS §4), so an
	// anonymous image runs, recorded fileless.
	ExecAnonymous bool `json:",omitempty"`
	// Keyring: the contract says keyring: true (SEMANTICS §1), so the keyring calls are allowed, recorded as gaps.
	Keyring bool `json:",omitempty"`
	// Names are the contract's name entries (ADR 0043), written from SEMANTICS §2 and the contract, never read from
	// compile's NameDeny: the built-in .env pair a contract whose deny_read is not [] carries, and each declared glob
	// that becomes one. The name invariant (invariants.go) holds them where the tier enforces them.
	Names []NameEntry `json:",omitempty"`
}

// NameEntry is one name entry of the model (ADR 0043 Terms): a final name, exact or a literal prefix, compared ASCII
// folded (D2), with the prefix entry's exceptions, beneath its scopes (relative to the project, D4) with no
// dependency directory between.
type NameEntry struct {
	Exact, Prefix string   `json:",omitempty"`
	Except        []string `json:",omitempty"`
	Scopes        []string
}

// ID is the cell's identity in the baseline and in reports.
func (f *Fixture) ID(c *Cell) string { return f.Name + "/" + c.Name }

// Tiers returns the tiers the cell has an expectation for, sorted: for a generated cell, every tier.
func (c *Cell) Tiers() []Tier {
	if c.Generated {
		return []Tier{TierBPFLSM, TierCgroup, TierLandlock}
	}
	seen := map[Tier]bool{}
	for k := range c.Want {
		seen[k.Tier] = true
	}
	var out []Tier
	for t := range seen {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// TruncateABI is the Landlock ABI from which truncation is Landlock's to decide (LANDLOCK_ACCESS_FS_TRUNCATE, Linux
// 6.2). Below it tier 1's filter refuses every truncate(2) with EPERM before any rule, the supervisor or a plane
// hook sees it, and writes no ledger line (docs/p0/enforce-landlock.md R2's ABI-3 row, E31; REASON-CHANNEL.md):
// deliberately coarser than the contract, a truncate inside a write entry included.
const TruncateABI = 3

// WantOn is the cell's expectation for k on a kernel whose Landlock ABI is abi: the cell's own, save a truncate
// cell's below TruncateABI, which is the filter's refusal with no line. That holds for every key: tier cgroup, in
// each mode, keeps tier 1's Landlock domain and filter, and so does tier bpflsm (AL2023's 6.1 offers it), whose
// parity check against compile --test's column is not asked where the floor answers.
// compile --test is not asked it: it has no truncate action (a truncate cell's row is fs.write, the contract's
// answer, which is every tier's from ABI 3), so the floor below it is the kernel runner's alone.
// A cell's WantWhere entries then answer before its Want, the first matching one with the column.
func (c *Cell) WantOn(k Key, m Machine) (Want, bool) {
	w, ok := c.Want[k]
	if (ok || c.Generated) && c.Op == OpTruncate && m.ABI < TruncateABI {
		return Want{Verdict: Refused, NoLine: true, Errno: int(unix.EPERM)}, true
	}
	for _, cw := range c.WantWhere {
		if v, has := cw.Want[k]; has && cw.Matches(m) {
			return v, true
		}
	}
	return w, ok
}

// CondWant is a cell's expectation on the machines a condition names.
type CondWant struct {
	// Where bounds the kernel (kernel_min, kernel_max) and the boot (bpf_lsm), as a baseline entry's does.
	Where Where
	// MemfdNoexecSeal, when set, must equal the machine's: whether its kernel honours MFD_NOEXEC_SEAL, which
	// decides tier 1's memfd arm (enforce-landlock R11a: a probe, never the version, since RHEL 9's 5.14 backports it).
	MemfdNoexecSeal *bool
	// PlaneFirst, when set, must equal the axis' Machine.PlaneFirst: whether its plane answers before Landlock's own
	// hooks.
	PlaneFirst *bool
	// SupervisorRoot, when set, must equal Machine.SupervisorRoot.
	SupervisorRoot *bool
	// UnixDiag, when set, must equal Machine.UnixDiag.
	UnixDiag *bool
	// ExecmodRefused, when set, must equal Machine.ExecmodRefused.
	ExecmodRefused *bool
	Want           map[Key]Want
}

// Matches reports whether the condition holds on m.
func (cw CondWant) Matches(m Machine) bool {
	return cw.Where.Matches(m) && (cw.MemfdNoexecSeal == nil || *cw.MemfdNoexecSeal == m.MemfdNoexecSeal) &&
		(cw.PlaneFirst == nil || *cw.PlaneFirst == m.PlaneFirst) && (cw.SupervisorRoot == nil || *cw.SupervisorRoot == m.SupervisorRoot) &&
		(cw.UnixDiag == nil || *cw.UnixDiag == m.UnixDiag) && (cw.ExecmodRefused == nil || *cw.ExecmodRefused == m.ExecmodRefused)
}
