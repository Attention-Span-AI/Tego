// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// Payload field names are frozen by docs/P0-DESIGN.md §3.2 and spec/record/v1/README.md. Each struct below
// serializes to the exact JSON keys of its kind; MarshalLine re-sorts them (R3), so declaration order here is
// documentation, not wire order.

// Limits carries the compiled budget values on run_start so views never re-run the compiler.
//
// A key is present exactly when the run had a budget on that dimension, and its value is that budget. An
// explicit 0 is the tightest budget there is, not the absence of one (docs/p0/limits-check-doctor-cli.md E16),
// so it has to survive the encoding: the three numbers are pointers because a plain number under omitempty
// drops a 0 and a reader would see no budget at all where the run enforced the strictest. The two durations
// need no pointer, since "0s" is already distinct from an absent "".
type Limits struct {
	Tokens     *int64   `json:"tokens,omitempty"`
	CostUSD    *float64 `json:"cost_usd,omitempty"`
	Wall       string   `json:"wall,omitempty"`        // duration
	StallAfter string   `json:"stall_after,omitempty"` // duration
	Repeats    *int     `json:"repeats,omitempty"`
	// LedgerBytes is the machine's record.max_run_bytes the run was started under (MinorLedgerCap): its
	// events.jsonl and blobs together (blobs from 2026-11-01, at the same minor) end the run as a limit,
	// which=ledger_bytes, once they hold that many bytes.
	LedgerBytes *int64 `json:"ledger_bytes,omitempty"`
}

// RunStartPayload is the run_start payload.
type RunStartPayload struct {
	LauncherPID     int               `json:"launcher_pid"`
	LauncherStartNS uint64            `json:"launcher_start_ns"`
	TegoVersion     string            `json:"tego_version"`
	Commit          string            `json:"commit"`
	BPFHash         string            `json:"bpf_hash"` // empty in tier 1
	Tier            string            `json:"tier"`
	Capture         string            `json:"capture"`
	NetAssurance    string            `json:"net_assurance,omitempty"`  // requested best-effort|kernel
	NetGuarantees   map[string]bool   `json:"net_guarantees,omitempty"` // actual tcp|udp|unix attachment proof
	Kernel          string            `json:"kernel"`
	ContractHash    string            `json:"contract_hash"` // hex sha256
	Parsers         map[string]string `json:"parsers"`       // {anthropic, openai, mcp}
	StopGrace       string            `json:"stop_grace"`    // duration
	Command         []string          `json:"command"`
	// CommandBlob is the sha256 of the argv's JSON when it was over R10's threshold and so is not in Command.
	CommandBlob string  `json:"command_blob,omitempty"`
	Cwd         string  `json:"cwd"`
	Limits      *Limits `json:"limits,omitempty"`
	// Capabilities is the run's capability line: one key per row of spec/backend/CAPABILITIES.md, spelled as
	// pkg/spec/backend names the row, true when this run could do it. It starts from the tier's own row as
	// the enforcement handle narrowed it, and the rows only the run can answer are then set from the run:
	// capture from the same reading as Capture, the record rows from the record mode and from what records
	// the run, and the rows no contract this binary loads can ask for as false (docs/p0/record-ledger.md
	// §2.2). A reader learns what was absent without knowing the machine. A false is a statement, never a
	// default: every row is written, and a key a reader does not know is a row a newer binary added. Absent in
	// a ledger written before the line existed, which a view shows as unknown rather than as nothing provided.
	Capabilities map[string]bool `json:"capabilities,omitempty"`
	// Stdio is what the agent's three standard descriptors were when the run started (invariant 4a).
	// They are the caller's, kept across the launch whatever they are, and
	// Landlock checks a file's access only at open: a socket, or a file opened for reading and writing
	// outside every rule, reaches the agent with the access it was opened with. Absent in a ledger written
	// before the field existed.
	Stdio *Stdio `json:"stdio,omitempty"`
	// RunCommandGrant is the absolute path of the exec rule the command given on tego run's command line
	// (after `--`) added for this run (agent.WithRunCommand): it is admitted for every exec of that file in the
	// run, as the contract's own command is, with its loader and a script's #! interpreter. The contract hash
	// does not include it, so this is where drift, events and every later reader learn of it (agent-contract.md R8). Absent
	// when the run execs the contract's command, when a declared entry already covered the one
	// given, and in a ledger written before the field existed.
	RunCommandGrant string `json:"run_command_grant,omitempty"`
	// RecordMinor is the revision of v1's optional fields the writer implements (Minor). Absent, 0, in a ledger
	// written before the field existed: such a ledger may lack run_command_grant although its run had one.
	RecordMinor int `json:"record_minor,omitempty"`
	// DecisionPlane is what decided the run's fs actions and execs in the kernel (enforce-plane R18, R19, I7):
	// DecisionPlaneLSM or DecisionPlaneFmodRet where a plane mode decided, DecisionPlaneFanotify where tier cgroup ran
	// on the listener, and absent for a tier with no plane (landlock, observe). It is written from the tier's own
	// handle, so a run a reader expected on the plane and that ran on the fallback says so even when it refused
	// nothing. Additive within v1 (2026-09-30, record_minor 2); absent in a ledger written before it.
	DecisionPlane string `json:"decision_plane,omitempty"`
	// BestEffort lists the stable ids of the run's disclosed best-effort cells (ADR 0041 D1, D7): a gate rule and
	// action whose supervisor decision is taken on copied syscall facts and continued when it does not refuse,
	// and, where no kernel decision plane decides the run, the built-in deny_write set (deny_write/default), so
	// it is never counted as enforced (agent.RuleTable.BestEffortCellsAt). Static for the compiled contract at
	// the run's tier and plane; an event that happened is a gap or a run_end anomaly instead. Absent when there
	// is none, and in a ledger written before the field (record_minor below 6).
	BestEffort []string `json:"best_effort,omitempty"`
	// AskReadRelaxes names every built-in deny_read entry an fs.ask_read entry of the top-level contract relaxes, a
	// refused read becoming one held for a person (ADR 0057 D4). Absent when there is none, and in a ledger written
	// before the field (record_minor below 9).
	AskReadRelaxes []AskReadRelax `json:"ask_read_relaxes,omitempty"`
	// RuntimeGrants lists the rule name of every entry the run added to its table on its own authority rather than
	// read from the contract (docs/p0/agent-contract.md R10a): a capture listener (net.capture[<addr>]), the DNS
	// broker's socket (net.dns-broker[unix:<path>]) and the run's own generated CODEX_HOME (fs.codex_home[<path>]).
	// The contract hash does not cover them. net.resolver, the run's own allowance of a query to a configured
	// resolver (supervisor.md R14), is a decision rather than an entry and is not listed: its lines carry the rule
	// net.resolver. Absent when there is none: at record_minor 11 or later that says the run added
	// no such entry, and absent in a ledger written before the field.
	RuntimeGrants []string `json:"runtime_grants,omitempty"`
	// ContractSource is the contract file the launching user named, by its path or by a registry name, and the file
	// whose bytes the run compiled (agent-contract.md R26): contract_hash says what the contract was, this says where
	// it came from. Absent for a contract tego generated (a watch or an adoption with no boundary): at record_minor
	// 12 or later that says no file was named, and absent in a ledger written before the field.
	ContractSource *ContractSource `json:"contract_source,omitempty"`
	// Harness is the agent harness the launcher provisioned for (agent-contract.md R27, ADR 0062): its name and
	// whether its provision was made, and if not why. Absent for a run whose contract says harness: none: at
	// record_minor 14 (MinorHarness) or later that says the run was provisioned for no harness, and absent in a
	// ledger written before the field.
	Harness *HarnessStart `json:"harness,omitempty"`
	// Profiles are the profiles the run's contract merged through extends (agent-contract.md R5, ADR 0066 D6), in
	// merge order (deepest first, a list left to right), each once: contract_hash covers what the merged contract
	// says, and these say which profiles gave it, so a reader can tell which version of a built-in profile a run
	// merged. Absent when the contract extends none: at record_minor 15 or later that says so, and absent in a
	// ledger written before the field.
	Profiles []ProfileRef `json:"profiles,omitempty"`
	// HostSockets is true for a run whose contract has no net: section and set host_sockets: true, the opt-out of
	// ADR 0070's unix-only state: such a run reached every unix socket on the host its uid could open. Absent, a run
	// with no net: section reached only the unix sockets it bound and tego's own endpoints (record minor 16).
	HostSockets bool `json:"host_sockets,omitempty"`
	// The run's identity (ADR 0073, record_minor 17, MinorRunIdentity): who launched it, on which host, the run it
	// says it is nested in, the caller's labels, its role and its contract's revision. Each is what the launcher read
	// when the run started (identity.LauncherOf), not a verified fact about a person: a root launcher's sudo_uid is
	// sudo's claim, which any root process can set, and parent_run the launcher environment's claim, not a link tego
	// checked.
	//
	// LauncherUID is the launcher's real uid, written on every run_start at MinorRunIdentity or later, 0 included;
	// absent only in a ledger written before the field.
	LauncherUID *uint32 `json:"launcher_uid,omitempty"`
	// LauncherUser is launcher_uid's passwd name; absent when the passwd database names none.
	LauncherUser string `json:"launcher_user,omitempty"`
	// SudoUID is the uid SUDO_UID names, written only when the launcher's euid was 0 in the initial user namespace and SUDO_UID was a uid; SudoUser
	// is its passwd name (never the SUDO_USER string), absent when it has none.
	SudoUID  *uint32 `json:"sudo_uid,omitempty"`
	SudoUser string  `json:"sudo_user,omitempty"`
	// Host is the launcher's kernel nodename (uname -n), at most 255 bytes; absent when it could not be read.
	Host string `json:"host,omitempty"`
	// ParentRun is the run the launcher's environment says this run is nested in, a valid run id: the enclosing run's
	// TEGO_RUN_ID for a tego run started inside a governed agent, else TEGO_PARENT_RUN; absent when it named none. A
	// claim of the environment until NESTED-RUNS verifies the link.
	ParentRun string `json:"parent_run,omitempty"`
	// Labels are the caller's labels (identity.ValidLabels); absent when there are none.
	Labels map[string]string `json:"labels,omitempty"`
	// Role is what the run is for (identity.Role): check for a run tego check started; absent for the agent's own run.
	Role string `json:"role,omitempty"`
	// ContractRevision is the contract's revision key (agent-contract.md R28); absent when the contract has none.
	ContractRevision string `json:"contract_revision,omitempty"`
	// FSReads says whether the run held its read opens (fs.reads, ADR 0069) and why: held, the open deputy completed
	// every read-capable open and refused one on the object it reached, so a deny_read inside a write entry held at
	// tier landlock; direct, reads went to the kernel as they were. Written on every run at record_minor 18 or later;
	// absent in a ledger written before the field.
	FSReads *FSReads `json:"fs_reads,omitempty"`
	// The reserved blocks (record minors 32 to 34): nothing in this tree writes them, and each is refused below its
	// revision (ValidateFields). They hold names, versions, hashes and modes, never an argv, an environment or a secret
	// value.
	Deployment *Deployment `json:"deployment,omitempty"`
	Secrets    []SecretUse `json:"secrets,omitempty"`
	Vault      *VaultUse   `json:"vault,omitempty"`
	Shares     []ShareUse  `json:"shares,omitempty"`
	// ReadsNotified says whether tier 1's seccomp filter told the supervisor of every read open of the run, and why
	// (ADR 0077): notified, a read the Landlock ruleset refuses under deny_read wrote a refused line under every record
	// mode; not notified, under record: summary or off such a refusal was Landlock's alone and wrote none. Written on
	// every run at record_minor 23 (MinorReasonReads) or later; absent in a ledger written before the field.
	ReadsNotified *ReadsNotified `json:"reads_notified,omitempty"`
	// LiveMode is "adjustable" on a run whose contract chose Adjustable (ADR 0125, MinorLiveModes): its fence is in
	// the kernel layers and Tego's live layer refuses each fence entry until a person lifts it. Absent, the run is
	// Locked. Written with LiveFence and only with it.
	LiveMode string `json:"live_mode,omitempty"`
	// LiveFence is an Adjustable run's fence: the digest of its entries and each entry, with the rule a refusal under
	// it, and an action allowed only because it is lifted, carries.
	LiveFence *LiveFence `json:"live_fence,omitempty"`
}

// LiveModeAdjustable is RunStartPayload.LiveMode's one value (ADR 0125); a Locked run writes no live_mode.
const LiveModeAdjustable = "adjustable"

// MaxLiveFence bounds a fence's entries (ADR 0125 decision 2).
const MaxLiveFence = 64

// MaxLiveFenceValue bounds a fence entry's value in bytes, the kernel's PATH_MAX (liveblock.MaxValueBytes): live_fence
// always stays on its run_start line (mvpKeys), so the record bounds it.
const MaxLiveFenceValue = 4096

// LiveFence is RunStartPayload.LiveFence.
type LiveFence struct {
	// SHA256 is the lower-case hex sha256 of the fence as the contract compiled it.
	SHA256 string `json:"sha256"`
	// Entries are the fence's entries in the contract's order; [] for an empty fence.
	Entries []LiveFenceEntry `json:"entries"`
}

// LiveFenceEntry is one entry of a run's fence.
type LiveFenceEntry struct {
	// Kind is read, net or exec (the LiveKind values a fence admits).
	Kind string `json:"kind"`
	// Value is the entry, normalized as a live block of its kind is.
	Value string `json:"value"`
	// Source is LiveFenceSourceDeny (one of the contract's own refusals, which the fence takes out) or
	// LiveFenceSourceNew (access the contract does not have).
	Source string `json:"source"`
	// Rule is LiveFenceRule(Kind, Value).
	Rule string `json:"rule"`
	// Name is, on an exec entry of source deny only, the bare program name of the exec.deny entry the fence takes
	// out, which the entry also refuses wherever a program of that name lies. It is part of the fence's digest, so a
	// reader recomputes sha256 from the entries alone (docs/user/live-modes.md).
	Name string `json:"name,omitempty"`
}

// The values of LiveFenceEntry.Source.
const (
	LiveFenceSourceDeny = "deny"
	LiveFenceSourceNew  = "new"
)

// ReadsNotified is RunStartPayload.ReadsNotified.
type ReadsNotified struct {
	// Notified is true when every read open of the run reached the supervisor.
	Notified bool `json:"notified"`
	// Why is one of the ReadsNotifiedWhy values: record-full, gate, ask-read, held and reason when notified;
	// reason-off, kernel, records-only and no-supervisor when not.
	Why string `json:"why"`
}

// The ReadsNotifiedWhy values of ReadsNotified.Why.
const (
	ReadsNotifiedWhyFull    = "record-full" // record: full notifies every open
	ReadsNotifiedWhyGate    = "gate"        // an fs.read gate scores every read
	ReadsNotifiedWhyAskRead = "ask-read"    // an fs.ask_read entry holds the reads it decides
	ReadsNotifiedWhyHeld    = "held"        // the run held its reads (fs_reads held)
	// ReadsNotifiedWhyReason: reason.reads at tier landlock, so a read Landlock refuses under deny_read is recorded.
	ReadsNotifiedWhyReason       = "reason"
	ReadsNotifiedWhyReasonOff    = "reason-off"    // reason.reads: off, or auto (ADR 0077's measured default)
	ReadsNotifiedWhyKernel       = "kernel"        // a root tier, whose kernel record carries a refused read
	ReadsNotifiedWhyRecordsOnly  = "records-only"  // a run that enforces nothing (tego watch, --observe)
	ReadsNotifiedWhyNoSupervisor = "no-supervisor" // no started supervisor answered the run's notifications
)

// FSReads is RunStartPayload.FSReads.
type FSReads struct {
	// Reads is FSReadsHeld or FSReadsDirect.
	Reads string `json:"reads"`
	// Why is one of the FSReadsWhy values: contract (fs.reads: held), nested (fs.reads: auto at tier landlock with a
	// deny_read target inside a write entry), contract-direct (fs.reads: direct), none-nested (auto, no such target),
	// kernel (auto at a root tier, whose kernel refuses such a target itself), records-only (a run that enforces
	// nothing).
	Why string `json:"why"`
	// Nested names, by rule, the deny_read targets inside write entries; absent when there is none.
	Nested []string `json:"nested,omitempty"`
}

// The values of FSReads.Reads.
const (
	FSReadsHeld   = "held"
	FSReadsDirect = "direct"
)

// The FSReadsWhy values of FSReads.Why.
const (
	FSReadsWhyContract    = "contract"        // fs.reads: held
	FSReadsWhyNested      = "nested"          // fs.reads: auto at tier landlock, a deny_read target inside a write entry
	FSReadsWhyDirect      = "contract-direct" // fs.reads: direct
	FSReadsWhyNoneNested  = "none-nested"     // fs.reads: auto at tier landlock, no target inside a write entry
	FSReadsWhyKernel      = "kernel"          // fs.reads: auto at a root tier, whose kernel refuses a nested target
	FSReadsWhyRecordsOnly = "records-only"    // a run that enforces nothing (tego watch, --observe)
)

// Deployment is run_start's reserved deployment block (MinorDeployment).
type Deployment struct {
	// ID is the deployment's id, dep_ and 26 base32-Crockford characters in lower case (DeploymentIDPattern).
	ID string `json:"id"`
	// Name is the deployment's name (DeploymentNamePattern).
	Name string `json:"name"`
	// Revision is the deployment revision the instance started from, 1 or more.
	Revision int64 `json:"revision"`
	// RevisionHash is that revision's lowercase hex sha256.
	RevisionHash string `json:"revision_hash"`
	// Instance is the instance's sequence number within the deployment, 1 or more.
	Instance int64 `json:"instance"`
	// Trigger is why the instance started (DeployTrigger*).
	Trigger string `json:"trigger"`
	// PreviousRun is the run id of the deployment's previous instance; absent for its first.
	PreviousRun string `json:"previous_run,omitempty"`
	// Change is what the revision changed from the one the previous instance ran, present only with trigger update.
	Change *DeploymentChange `json:"change,omitempty"`
}

// DeploymentChange is the rule change an update brought (Deployment.Change).
type DeploymentChange struct {
	// FromRevision is the revision the previous instance ran, 1 or more and not the new one.
	FromRevision int64 `json:"from_revision"`
	// Class is how the change moved the boundary (Change*).
	Class string `json:"class"`
}

// The values of Deployment.Trigger.
const (
	DeployTriggerStart        = "start"
	DeployTriggerRestart      = "restart"
	DeployTriggerCrashRestart = "crash-restart"
	DeployTriggerBoot         = "boot"
	DeployTriggerUpdate       = "update"
)

// The values of DeploymentChange.Class.
const (
	ChangeTighten = "tighten" // the new revision allows less
	ChangeWiden   = "widen"   // the new revision allows more
	ChangeNeutral = "neutral" // neither, or a change that moves no boundary
)

// SecretUse is one entry of the reserved run_start.secrets (MinorSecrets). A value is never in the record.
type SecretUse struct {
	// Name is the secret's name (SecretNamePattern).
	Name string `json:"name"`
	// Version is the secret's version, 1 or more.
	Version int64 `json:"version"`
	// Deliver is SecretDeliverEnv.
	Deliver string `json:"deliver"`
	// Env is the environment variable's name (EnvNamePattern).
	Env string `json:"env"`
	// Exposure is SecretExposureAgent.
	Exposure string `json:"exposure"`
}

// The values of SecretUse.Deliver and SecretUse.Exposure.
const (
	SecretDeliverEnv    = "env"
	SecretExposureAgent = "agent"
)

// VaultUse is run_start's reserved vault block (MinorSecrets).
type VaultUse struct {
	// Peer is one of VaultPeer*.
	Peer string `json:"peer"`
	// Memory is one of VaultMemory*.
	Memory string `json:"memory"`
}

// The values of VaultUse.
const (
	VaultPeerSameUID       = "same-uid"
	VaultPeerSudo          = "sudo"
	VaultMemoryMemfdSecret = "memfd-secret"
	VaultMemoryMlock       = "mlock"
)

// RedactionsKey is the payload key of a line's reserved redactions (MinorSecrets); LineRedactions decodes it.
const RedactionsKey = "redactions"

// LineRedactions is the redactions key of any line's payload: DecodePayload into it reads what was replaced.
type LineRedactions struct {
	Redactions []Redaction `json:"redactions,omitempty"`
}

// Redaction is one secret version replaced in a line, and how many times.
type Redaction struct {
	// Secret is the secret's name (SecretNamePattern).
	Secret string `json:"secret"`
	// Version is its version, 1 or more.
	Version int64 `json:"version"`
	// Count is how many replacements the line had, 1 or more.
	Count int64 `json:"count"`
}

// ShareUse is one entry of the reserved run_start.shares (MinorShares).
type ShareUse struct {
	// Name is the share's name (ShareNamePattern).
	Name string `json:"name"`
	// Path is the share's absolute, clean path.
	Path string `json:"path"`
	// Mode is one of ShareMode*.
	Mode string `json:"mode"`
}

// The values of ShareUse.Mode.
const (
	ShareModeRO  = "ro"
	ShareModeAsk = "ask"
	ShareModeRW  = "rw"
)

// ProfileRef is one profile a run's contract merged (RunStartPayload.Profiles).
type ProfileRef struct {
	// Name is the name extends gave the profile.
	Name string `json:"name"`
	// Source is where it was read: ProfileSourceBuiltin (a profile built into tego, under tego/) or ProfileSourceDir
	// (a file of the machine config's profiles directory).
	Source string `json:"source"`
	// SHA256 is the lowercase hex sha256 of the profile's bytes as read.
	SHA256 string `json:"sha256"`
}

// The values of ProfileRef.Source.
const (
	ProfileSourceBuiltin = "builtin"
	ProfileSourceDir     = "dir"
)

// HarnessStart is what run_start says of the run's harness provision (RunStartPayload.Harness).
type HarnessStart struct {
	// Name is the resolved harness: claude-code, codex or generic (auto is resolved before the run starts).
	Name string `json:"name"`
	// Provisioned says the launcher made the provision: its files, its argv and environment additions.
	Provisioned bool `json:"provisioned"`
	// Why is, when Provisioned is false, the reason (HarnessWhy*); absent when it is true.
	Why string `json:"why,omitempty"`
	// Files are the paths of the files the launcher made for the harness, in the order made.
	Files []string `json:"files,omitempty"`
	// ReasonFile is the readable last-refusal.json the agent's TEGO_REASON names, absent when there is none.
	ReasonFile string `json:"reason_file,omitempty"`
	// StateDir is the run's hook-state directory, the one place in its runtime directory the agent may write
	// (fs.harness-state[<path>] in runtime_grants), absent when the provision was not made.
	StateDir string `json:"state_dir,omitempty"`
	// Hook is the hook the provision names, absent when it names none; written from MinorHarnessHook on.
	Hook *HarnessHook `json:"hook,omitempty"`
}

// HarnessHook is the hook a harness provision names (HarnessStart.Hook, ADR 0064).
type HarnessHook struct {
	// Argv is the hook's exact argv: the tego binary and every argument.
	Argv []string `json:"argv"`
	// Granted says the launcher granted the hook's exact argv on its own authority (runtime_grants
	// exec.harness-hook[<tego binary>]): an allow-list contract's run whose own exec rules did not admit it. False
	// when the contract's exec rules admitted the hook themselves, and for a provision that was dropped.
	Granted bool `json:"granted"`
}

// The values of HarnessStart.Why.
const (
	// HarnessWhyNoProvisioner is a harness this build has no provisioner for: the run is what it would be under
	// harness: none, and TEGO_REASON is the agent's one way to its refusals.
	HarnessWhyNoProvisioner = "no-provisioner"
	// HarnessWhyReasonUnavailable is a run with no usable runtime directory (no absolute XDG_RUNTIME_DIR, or a root
	// launcher): no file can be made where the agent reads and cannot write, so nothing is provisioned.
	HarnessWhyReasonUnavailable = "reason-unavailable"
	// HarnessWhyHookRefused is a provision whose hook the run's exec rules refuse: provisioned, it would add a
	// refused exec to every tool call, so the whole provision is dropped.
	HarnessWhyHookRefused = "hook-refused"
	// HarnessWhyHookNotGranted is a provision whose hook an allow-list contract's run cannot grant exactly (ADR 0064):
	// it names another program than the tego binary the launcher runs as, its binary is no ELF file the launcher can
	// resolve and read or has a set-id bit, or a bare exec.allow entry or an implicit grant keeps the binary's name
	// unconstrained, so a grant of the file would admit every argv. The whole provision is dropped. Below
	// MinorHarnessHook every allow-list contract's provision with a hook was dropped so.
	HarnessWhyHookNotGranted = "hook-not-granted"
	// HarnessWhyHookWritable is a provision whose hook's binary, or its ELF loader, lies at or below a write or ask
	// entry of an allow-list contract's run by a name the launcher sees, or has names it cannot see (more than one
	// link, or an unreadable mount table) (ADR 0064 D2): the agent could rewrite what the grant admits, so no grant is
	// made and the whole provision is dropped. Written from MinorHarnessHook on.
	HarnessWhyHookWritable = "harness-hook-writable"
)

// ContractSource is where a run's contract came from (RunStartPayload.ContractSource).
type ContractSource struct {
	// Path is the contract file's absolute path.
	Path string `json:"path"`
	// Name is the agent name the file was resolved from, absent when the file was named by its path.
	Name string `json:"name,omitempty"`
	// Registry is the registry that resolved Name: "project" (the working directory's) or "user" (the machine
	// config's registry:). Absent when the file was named by its path.
	Registry string `json:"registry,omitempty"`
}

// AskReadRelax is one relaxed built-in deny_read entry (RunStartPayload.AskReadRelaxes): the fs.ask_read entry's rule,
// the built-in entry's path, and how: "replaces" (at its path) or "inside" (beneath it; the rest stays refused).
type AskReadRelax struct {
	Rule    string `json:"rule"`
	BuiltIn string `json:"builtin"`
	How     string `json:"how"`
}

// Stdio names the kind of each of a run's standard descriptors: one of the Stdio* kinds.
type Stdio struct {
	Stdin  string `json:"stdin"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

// The kinds a standard descriptor can be (RunStartPayload.Stdio).
const (
	StdioTTY     = "tty"     // a terminal
	StdioNull    = "null"    // /dev/null, which a stream the caller did not give becomes
	StdioChar    = "char"    // another character device
	StdioPipe    = "pipe"    // a pipe or FIFO
	StdioSocket  = "socket"  // a socket: a live channel to whatever holds the other end
	StdioFile    = "file"    // a regular file
	StdioDir     = "dir"     // a directory
	StdioOther   = "other"   // anything else (an anonymous inode, a block device)
	StdioUnknown = "unknown" // the descriptor could not be examined
)

// ExecPayload is the exec payload.
//
// Mechanism, DecisionPlane and PlaneReason are optional, additive within v1 (2026-09-29, TIER3-PLAN T9), and
// written on a line whose verdict the kernel decision plane gave (MechanismPlane).
type ExecPayload struct {
	Path          string   `json:"path"`
	Argv          []string `json:"argv"`
	Script        string   `json:"script,omitempty"` // the #! script path when a stage preceded
	Stage         string   `json:"stage,omitempty"`  // set only on a refusal
	ExecID        string   `json:"exec_id"`          // <run>/<pid>/<start-boot-ns>
	ParentExecID  string   `json:"parent_exec_id,omitempty"`
	Mechanism     string   `json:"mechanism,omitempty"`
	DecisionPlane string   `json:"decision_plane,omitempty"`
	PlaneReason   string   `json:"plane_reason,omitempty"`
	// SyscallRet is an actual negative kernel exec return, never a prediction.
	SyscallRet int64 `json:"syscall_ret,omitempty"`
	// AttemptPath preserves the attempted spelling when an opened interpreter
	// or loader supplies the outcome's Path. ArgvFrom identifies argv evidence.
	AttemptPath string `json:"attempt_path,omitempty"`
	ArgvFrom    string `json:"argv_from,omitempty"`
	Errno       int64  `json:"errno,omitempty"`
	By          string `json:"by,omitempty"`
	// The command-rule fields (ADR 0048 (8)), optional and additive at record_minor 7 (MinorExecCommands): the entry
	// that decided (command_rule, as compiled), its list (deny, ask, allow or unlisted), definite or ambiguous, the
	// interpretation that read it (name, image, argv0, identity, dashed, multicall, interpreter, shebang, closure, with
	// closure_of the allowed entry whose helper closure admitted it, or loader, the program a directly-invoked dynamic
	// loader runs in-process), where the decided argv came from
	// (copied_syscall; kernel_pinned and unproven arrive with P2's pins), and how many argv elements the decision
	// read (argv_read).
	CommandRule  string `json:"command_rule,omitempty"`
	CommandList  string `json:"command_list,omitempty"`
	CommandMatch string `json:"command_match,omitempty"`
	CommandVia   string `json:"command_via,omitempty"`
	ClosureOf    string `json:"closure_of,omitempty"`
	ArgvFacts    string `json:"argv_facts,omitempty"`
	ArgvRead     int    `json:"argv_read,omitempty"`
	// PinUnavailable marks an exec refused at a plane tier because the supervisor could not write the pin that holds
	// it to its decided facts (ADR 0048 (3) P2, (8)): rule exec.pin, reason exec-not-allowed. Additive within v1 at
	// record_minor 12 (MinorExecPins); absent elsewhere.
	PinUnavailable bool `json:"pin_unavailable,omitempty"`
	// The kill's fields (ADR 0048 (8), P2; record_minor 12): an exec the plane killed at sched_process_exec because its
	// mapped argument area was not the one its pin covers is refused rule exec.pin with its plane_reason, argv the
	// kernel's mapped vector, argv_decided the vector the decision read (the supervisor's copy), and signal SIGKILL.
	// kill_failed is bpf_send_signal's errno when the send failed; the launcher then killed the process through its
	// pidfd, late, and the line says detected_bypass: the program may have run some instructions first.
	ArgvDecided    []string `json:"argv_decided,omitempty"`
	Signal         string   `json:"signal,omitempty"`
	KillFailed     int64    `json:"kill_failed,omitempty"`
	DetectedBypass bool     `json:"detected_bypass,omitempty"`
}

// Values of ExecPayload.ArgvFacts (ADR 0048 (8)).
const (
	// ArgvFactsCopied: the decision read the supervisor's own copy of argv at the notification; the kernel copied
	// argv again after an allow.
	ArgvFactsCopied = "copied_syscall"
	// ArgvFactsKernelPinned: the decision read the supervisor's copy, and the plane held the exec to it: the kernel's
	// held sample for the exec's pin arrived (ADR 0048 (8), P2).
	ArgvFactsKernelPinned = "kernel_pinned"
	// ArgvFactsUnproven: the exec was pinned, but no held or kill sample of its pin arrived (a ring loss), or the
	// one that did names another pin than the decision wrote; the run has the gap exec-pin-unproven.
	ArgvFactsUnproven = "unproven"
)

// SignalKill is an exec line's signal when the plane killed it (ADR 0048 (8)).
const SignalKill = "SIGKILL"

// A line whose verdict the kernel decision plane gave (ADR 0024, docs/p0/enforce-plane.md R24) carries, beside its
// closed-set reason, mechanism MechanismPlane, decision_plane the mode the plane ran in (DecisionPlaneLSM or
// DecisionPlaneFmodRet) and, on a refusal whose cause the closed set has no code for, plane_reason
// (PlaneReasonRefer, PlaneReasonDenyWriteAncestor, PlaneReasonIdentityMismatch; the line's reason is then
// rename-outside-contract, write-outside-contract or path-unresolved). A new reason code would not be additive: a
// v1 reader validates reason against the closed set (spec/reason/REASON-CHANNEL.md).
//
// MechanismCgroup (additive within v1, 2026-10-05, ADR 0018 PR 2) is a refused line whose refusal a tier-2 cgroup
// program made: cgroup/sock_create's refusal of an inet socket outside ADR 0018's allowlist, on a path the seccomp
// filter did not decide. It carries no decision_plane, since no plane decided it.
//
// MechanismLandlock (record_minor 23, MinorReasonReads, ADR 0077) is a refused read-denied line of a read open the
// supervisor was told of at tier landlock and continued, which the Landlock ruleset then refused (EACCES): the line is
// the supervisor's, written before the kernel answered, from the ruleset's own model of the path (decide.AdvisoryFS),
// as a refused write's line at tier 1 is. It carries no decision_plane.
const (
	MechanismPlane               = "plane"
	MechanismCgroup              = "cgroup"
	MechanismLandlock            = "landlock"
	DecisionPlaneLSM             = "lsm"
	DecisionPlaneFmodRet         = "fmod_ret"
	PlaneReasonRefer             = "refer"
	PlaneReasonDenyWriteAncestor = "deny-write-ancestor"
	PlaneReasonIdentityMismatch  = "identity-mismatch"
	// ADR 0048 (3) P2's exec pins: bprm_check's refusals (pin-missing, pin-mismatch, pin-unverifiable, exec-traced) and
	// sched_process_exec's kills (argv-changed, argv-unreadable, and pin-missing or pin-unverifiable with no pin to check).
	PlaneReasonPinMissing      = "pin-missing"
	PlaneReasonPinMismatch     = "pin-mismatch"
	PlaneReasonPinUnverifiable = "pin-unverifiable"
	PlaneReasonArgvChanged     = "argv-changed"
	PlaneReasonArgvUnreadable  = "argv-unreadable"
	PlaneReasonExecTraced      = "exec-traced"
)

// DecisionPlaneFanotify is run_start's decision_plane for a tier-2 run on the fanotify fallback (ADR 0021): no plane
// line carries it, since no plane decided.
const DecisionPlaneFanotify = "fanotify"

// FS operation values.
const (
	FSOpen     = "open"
	FSUnlink   = "unlink"
	FSRename   = "rename"
	FSMkdir    = "mkdir"
	FSSymlink  = "symlink"
	FSLink     = "link"
	FSTruncate = "truncate"
	FSChmod    = "chmod"
	// FSChown and FSXattr are the kernel decision plane's attribute refusals (TIER3-PLAN T13, enforce-plane R12),
	// additive within v1 (2026-09-29): a chown of, and an xattr set or removal on, a file beneath a deny_write
	// target. The plane writes an ACL set or removal as FSChmod: it rewrites the file's permissions. Since
	// 2026-10-16 the supervisor writes them too, for a chown or an xattr set or removal an fs.write gate scores
	// (supervisor R17); it names the syscall's family, so its ACL set is FSXattr, the attribute's name unread.
	FSChown = "chown"
	FSXattr = "xattr"
)

// FSPayload is the fs payload.
//
// Created, Errno, By and VerdictFrom are optional, additive within v1 (2026-09-29, ADR 0016 step 2), and written
// by the tier-2 kernel record only: VerdictFrom says what the line's verdict is, FSVerdictChain for the return of
// the kernel's LSM chain read at fexit and FSVerdictModel for the tier model's prediction on a kernel whose record
// carries no return; By is FSByOther, with the Errno the chain returned, on an observed line whose refusal no
// Tego mechanism explains (another LSM's or a third-party listener's, never a reason from REASON-CHANNEL's set);
// Created marks an open that created its file. Mechanism, DecisionPlane and PlaneReason are optional, additive
// within v1 (2026-09-29, TIER3-PLAN T9): a refusal the kernel decision plane made (MechanismPlane).
type FSPayload struct {
	Op            string `json:"op"` // open|unlink|rename|mkdir|symlink|link|truncate|chmod|chown|xattr
	Path          string `json:"path"`
	Path2         string `json:"path2,omitempty"` // rename/link target, symlink target
	Flags         int    `json:"flags,omitempty"`
	Count         int    `json:"count,omitempty"` // aggregated reads
	Created       bool   `json:"created,omitempty"`
	Errno         int    `json:"errno,omitempty"`
	By            string `json:"by,omitempty"`
	VerdictFrom   string `json:"verdict_from,omitempty"`
	Mechanism     string `json:"mechanism,omitempty"`
	DecisionPlane string `json:"decision_plane,omitempty"`
	PlaneReason   string `json:"plane_reason,omitempty"`
	// AlternateFor is, on the line of an open a person's alternate completed (authority human, verdict allow), the
	// path the agent asked for, which it did not get: Path is the file delivered in its place (ADR 0057 D1;
	// record_minor 9, written by the 2026-10-06 POC before it).
	AlternateFor string `json:"alternate_for,omitempty"`
}

// The values of FSPayload.VerdictFrom and FSPayload.By.
const (
	// FSVerdictChain: the verdict is the kernel LSM chain's return, read by an fexit program (ADR 0016 (3)).
	FSVerdictChain = "chain"
	// FSVerdictModel: the record carried no return, and the verdict is the tier model's prediction.
	FSVerdictModel = "model"
	// FSByOther: a refusal no Tego mechanism explains.
	FSByOther = "other"
)

// NetPayload is the net payload.
type NetPayload struct {
	Op            string   `json:"op,omitempty"` // http_request distinguishes request policy from connect
	Method        string   `json:"method,omitempty"`
	Path          string   `json:"path,omitempty"`           // validated escaped path; ledger redacts resource paths; no query
	HTTPAuthority string   `json:"http_authority,omitempty"` // fixed declared upstream, including TLS port
	Proto         string   `json:"proto"`                    // tcp|udp|unix|raw|http
	Dst           string   `json:"dst"`                      // ip:port or unix:<path>
	Host          string   `json:"host,omitempty"`
	Boundary      bool     `json:"boundary,omitempty"`
	Propagated    []string `json:"propagated,omitempty"`
	Mechanism     string   `json:"mechanism,omitempty"`
	DecisionPlane string   `json:"decision_plane,omitempty"`
	PlaneReason   string   `json:"plane_reason,omitempty"`
	// SyscallRet is the observed kernel return. Non-permission errors can coexist
	// with an allowed policy decision, as with supervisor-relayed IP operations.
	SyscallRet   int64  `json:"syscall_ret,omitempty"`
	SyscallErrno int    `json:"syscall_errno,omitempty"`
	VerdictFrom  string `json:"verdict_from,omitempty"` // plane|lsm-chain|unknown
	// What is, on a unix destination refused rule host-sockets (ADR 0070), what the well-known daemon socket it names
	// gives an agent that reaches it ("the Docker daemon, root-equivalent"); absent for a socket R19's list does not
	// name (record minor 16).
	What string `json:"what,omitempty"`
	// Credential is a reserved field: nothing here writes it. Never a value.
	Credential *CredentialUse `json:"credential,omitempty"`
	// Route is the route the request a credential line is about took, on an endpoint that declares routes (ADR 0127,
	// MinorModelRoutes).
	Route *RouteTaken `json:"route,omitempty"`
}

// CredentialUse names a credential an http_request line injected or refused: the entry's name and, when it was
// held, its version (from 1).
type CredentialUse struct {
	Name    string `json:"name"`
	Version int    `json:"version,omitempty"`
}

// MCPPayload is the mcp payload.
type MCPPayload struct {
	Name      string   `json:"name"`
	Command   []string `json:"command,omitempty"`
	Transport string   `json:"transport"` // stdio|http
	Tool      string   `json:"tool,omitempty"`
}

// SSLRequestPayload is the ssl_request payload. Headers is optional and holds only what the redaction stage
// lets through (docs/p0/record-ledger.md R9); credentials never reach disk.
type SSLRequestPayload struct {
	Endpoint     string            `json:"endpoint"`
	Method       string            `json:"method"`
	Path         string            `json:"path"`
	Host         string            `json:"host"`
	RequestID    string            `json:"request_id,omitempty"`
	Blob         string            `json:"blob,omitempty"` // sha256 of the body, naming the blob holding it whole unless Truncated is set
	Size         int               `json:"size"`
	TraceID      string            `json:"trace_id,omitempty"`
	SpanID       string            `json:"span_id,omitempty"`
	ParentSpanID string            `json:"parent_span_id,omitempty"`
	RetryOf      string            `json:"retry_of,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	// BodySHA256, Frame and Messages are set together, and Blob is then unset, when the body was stored
	// by its conversation's elements rather than whole (docs/p0/record-ledger.md R11). No blob holds such a
	// body whole, and Blob keeps its v1 meaning, the name of the one that does, so the body's sha256 is
	// BodySHA256; Frame is the blob that rebuilds the body, and Messages is the last link of the chain of
	// its conversation array's element groups, which requests whose histories begin the same way share up
	// to the last group before they part. Optional within v1: a reader that predates them sees a body that
	// was not stored, never a Blob naming a file that does not exist.
	BodySHA256 string `json:"body_sha256,omitempty"`
	Frame      string `json:"frame,omitempty"`
	Messages   string `json:"messages,omitempty"`
	// Truncated is set when Blob holds only the prefix of a body the capture cut (R6's kernel cap,
	// MaxBody, or on the forwarder any cut of capture-derive R15), whose length on the wire is WireSize.
	// Optional within v1: a reader that predates it sees a smaller body, as before.
	Truncated bool `json:"truncated,omitempty"`
	WireSize  int  `json:"wire_size,omitempty"`
	// Route is the route the forwarder sent the request by, on every request of a models[] endpoint that declares
	// routes (ADR 0127, MinorModelRoutes); absent otherwise.
	Route *RouteTaken `json:"route,omitempty"`
	// Side marks an exchange on a declared model host that is not a model turn: telemetry, token counting, a model
	// listing, a health check (the parser's silent paths). It opens no step (capture-derive.md R40, record_minor 29).
	Side bool `json:"side,omitempty"`
	// ToolResults are the tool_use ids whose results the request's last message reports, in wire order: nil when
	// derive did not read the request (no parser reads its path, its body was cut, coded or unreadable), an empty
	// list when it read it and found none. A model request closes the tool windows it names, or leaves every window
	// of the run of unknown state when it was not read (capture-derive.md R42, record_minor 29).
	ToolResults *[]string `json:"tool_results,omitempty"`
}

// Usage is the token accounting of one model response.
type Usage struct {
	Input      int `json:"input"`
	Output     int `json:"output"`
	CacheRead  int `json:"cache_read"`
	CacheWrite int `json:"cache_write"`
	// OutputBound says Output is not what the model reported but the request's max_tokens: an event stream
	// that ended before its final message_delta, which is where the output count is carried, is charged the
	// most it could have spent (docs/adr/0036-cut-stream-charges-max-tokens.md). Optional within v1, added
	// 2026-09-24; absent means Output is the reported count.
	OutputBound bool `json:"output_bound,omitempty"`
	// CacheWrite1h is the part of CacheWrite written with the 1-hour cache lifetime, which the upstream bills
	// at its own rate (the Messages API's usage.cache_creation.ephemeral_1h_input_tokens); the rest of
	// CacheWrite is the 5-minute kind. Optional within v1, added 2026-09-24 (capture-derive.md R29); absent means
	// none, or a ledger that predates the field.
	CacheWrite1h int `json:"cache_write_1h,omitempty"`
	// ServerTool counts the server-side tool requests the upstream billed per request, keyed by the name the
	// response reported them under (the Messages API's usage.server_tool_use, e.g. "web_search_requests"). Only
	// positive counts are kept. Optional within v1, added 2026-09-24 (capture-derive.md R29).
	ServerTool map[string]int `json:"server_tool,omitempty"`
	// Modified says the response was billed under a modifier the token counters do not show: a speed,
	// service_tier or inference_geo other than the plain one, or extra iterations (compaction, a refusal
	// fallback) the top-level counts leave out. A price table cannot price it, so a cost budget charges it at
	// its upper bound. Optional within v1, added 2026-09-30 (capture-derive.md R29); absent means none.
	Modified bool `json:"modified,omitempty"`
}

// SSLResponsePayload is the ssl_response payload.
type SSLResponsePayload struct {
	// RequestSeq is the seq of this exchange's ssl_request line, which the pipeline fills in from the pair
	// token both lines carry (Event.Pair). It is omitted when that line is not known to have been written
	// (the queue dropped it), rather than naming seq 0, which is run_start.
	RequestSeq      *uint64           `json:"request_seq,omitempty"`
	Status          int               `json:"status"`
	Model           string            `json:"model,omitempty"`
	ResponseID      string            `json:"response_id,omitempty"`
	StopReason      string            `json:"stop_reason,omitempty"`
	Usage           *Usage            `json:"usage,omitempty"`
	LatencyMS       int64             `json:"latency_ms"`
	RequestID       string            `json:"request_id,omitempty"`
	ContentEncoding string            `json:"content_encoding,omitempty"`
	ParserVersion   string            `json:"parser_version"`
	Blob            string            `json:"blob,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	// Truncated and WireSize mean what they mean on SSLRequestPayload: Blob is a cut body's prefix.
	Truncated bool `json:"truncated,omitempty"`
	WireSize  int  `json:"wire_size,omitempty"`
}

// DecisionPayload is the decision payload.
type DecisionPayload struct {
	Step      int    `json:"step"`
	ToolUseID string `json:"tool_use_id,omitempty"`
	Tool      string `json:"tool,omitempty"`
	Name      string `json:"name,omitempty"`
	InputHash string `json:"input_hash,omitempty"`
	Text      bool   `json:"text"`
	Unparsed  bool   `json:"unparsed"`
	Why       string `json:"why,omitempty"` // encoding|schema|h2
}

// Gap what values.
const (
	GapCapture = "capture"
	GapRecord  = "record"
	GapEnforce = "enforce"
	// GapLimits is a limit the contract asked for that the run's cgroup cannot hold as asked (added within v1,
	// 2026-09-24): why=memory-swap-uncapped for a memory cap on a kernel that accounts no swap to cgroups while
	// swap is on (runtime-launch.md R10).
	GapLimits = "limits"
)

// GapLauncherLost is the why of the gap what=record every orphaned run carries just before its run_end
// (record-ledger.md R6): the process that held the run's record died, so its last lines may be missing. Lines are
// not fsynced before Close and the event queue is the launcher's memory, so how many, if any, is unknown and the
// line has no count.
const GapLauncherLost = "launcher-lost"

// GapOwnStateModeRestored is the why of the gap what=record a run writes for each of tego's own files and directories
// whose owner's rights it found taken and gave back (record-ledger.md §3, "Modes taken from the owner"), binary naming
// its path. No Landlock ABI has a chmod right, so an agent can change the mode of the files its user owns; their
// contents and the record are unchanged by it, so the line loses no event and has no count.
const GapOwnStateModeRestored = "own-state-mode-restored"

// The why of a gap what=enforce the kernel decision plane's counters give at run end (enforce-plane §2.8, ADR 0025
// (4)): one line per counter of the run's slot that is not zero, count the number of refusals the plane made for that
// cause, decision_plane the mode. Every one is a refusal already made (fail closed); the line says the plane met a
// state it could not decide on its rows. GapPlaneCountersUnread is the slot that could not be read at run end, with no
// count, so a missing reading is never read as none.
const (
	GapPlaneMismatch       = "plane-identity-mismatch"
	GapPlaneUnresolved     = "plane-path-unresolved"
	GapPlaneBound          = "plane-walk-bound"
	GapPlaneNoRows         = "plane-no-rows"
	GapPlaneCountersUnread = "plane-counters-unread"
)

// GapPayload is the gap payload.
type GapPayload struct {
	What   string `json:"what"` // capture|record|enforce|limits
	Why    string `json:"why"`
	Binary string `json:"binary,omitempty"`
	Count  int    `json:"count,omitempty"`
	// DecisionPlane is the plane's mode on a gap its counters gave (GapPlane*). Additive within v1 (2026-09-30).
	DecisionPlane string `json:"decision_plane,omitempty"`
	// LiveBlock is the live block a why live-block-added or live-block-removed line records (MinorLiveBlock); absent
	// from every other gap.
	LiveBlock *LiveBlockChange `json:"live_block,omitempty"`
	// LiveControl is the pause or resume a why run-paused, run-resumed, pause-failed or resume-failed line records
	// (MinorLiveControl); absent from every other gap.
	LiveControl *LiveControlChange `json:"live_control,omitempty"`
	// MCPTool is the live MCP tool switch a why mcp-tool-changed line records (MinorCredentialsAndMCPTools); absent
	// from every other gap.
	MCPTool *MCPToolChange `json:"mcp_tool,omitempty"`
	// ModelRoute is the route change a why model-route-changed line records (MinorModelRoutes); absent from every
	// other gap.
	ModelRoute *ModelRouteChange `json:"model_route,omitempty"`
}

// GapMCPToolChanged is the why of a gap what=enforce the MCP relay writes for each live tool switch it put in force
// (ADR 0126 §4).
const GapMCPToolChanged = "mcp-tool-changed"

// The decisions of a live MCP tool switch (MCPToolChange.Decision): reset drops the switch, and the contract's rule
// decides again.
const (
	MCPToolAllow = "allow"
	MCPToolAsk   = "ask"
	MCPToolDeny  = "deny"
	MCPToolReset = "reset"
)

// MCPToolChange is one live switch of an MCP tool, as the run's overlay recorded it: the server and tool, the decision
// (allow, ask, deny or reset), who made it ("uid:<uid> pid:<pid> <via>"), its serial in the overlay (from 1) and when.
type MCPToolChange struct {
	Server   string    `json:"server"`
	Tool     string    `json:"tool"`
	Decision string    `json:"decision"`
	By       string    `json:"by"`
	Serial   uint64    `json:"serial"`
	At       time.Time `json:"at"`
}

// The why of a gap what=enforce about a run's live blocks (MinorLiveBlock, internal/liveblock): one line per add and
// per remove, in the order they were made, one per overlay state the launcher could not read (the blocks it read
// last stay in force), and one counting changes whose lines were lost.
const (
	GapLiveBlockAdded      = "live-block-added"
	GapLiveBlockRemoved    = "live-block-removed"
	GapLiveBlockUnreadable = "live-block-unreadable"
	// GapLiveBlockLost counts, in count, changes the overlay no longer held when the launcher read it (it keeps the
	// newest 256): their blocks are in force or not as the overlay says, but their own lines are missing.
	GapLiveBlockLost = "live-block-lost"
)

// The ops of a live change: a live block's add and remove (LiveBlockChange.Op), and a pause's and a resume's
// (LiveControlChange.Op, MinorLiveControl).
const (
	LiveOpAdd    = "add"
	LiveOpRemove = "remove"
	LiveOpPause  = "pause"
	LiveOpResume = "resume"
	// LiveOpExpire is a time limit that ended (MinorLiveModes): a block's, an unblock's or a lift's.
	LiveOpExpire = "expire"
	// LiveOpLift is a lift or a grant of an Adjustable run's fence entry (MinorLiveModes).
	LiveOpLift = "lift"
	// LiveOpRestore is a fence entry refused again (MinorLiveModes).
	LiveOpRestore = "restore"
)

// The why of a gap what=enforce about a time limit or an Adjustable run's fence (MinorLiveModes, ADR 0125), each
// written by the launcher from what took effect, never from the writer's change list. The first two carry a
// live.block[...] rule, the rest live.fence[<kind>:<value>] with kind read, net or exec.
const (
	// GapLiveBlockExpired is a block whose until passed: it refuses nothing from then on. Op expire, with until.
	GapLiveBlockExpired = "live-block-expired"
	// GapLiveUnblockExpired is an unblock whose until passed: its block refuses again. Op expire, with until.
	GapLiveUnblockExpired = "live-unblock-expired"
	// GapLiveRuleLifted is a fence entry the launcher allowed (a lift or a grant). Op lift, with until when it ends.
	GapLiveRuleLifted = "live-rule-lifted"
	// GapLiveRuleRestored is a lifted fence entry the launcher refuses again. Op restore.
	GapLiveRuleRestored = "live-rule-restored"
	// GapLiveLiftExpired is a lift whose until passed: the fence entry is refused again. Op expire, with until.
	GapLiveLiftExpired = "live-lift-expired"
	// GapLiveLiftRefused is a lift the launcher did not apply; refused says why (LiveRefused values). Op lift.
	GapLiveLiftRefused = "live-lift-refused"
)

// The values of LiveBlockChange.Refused on a live-lift-refused line.
const (
	// LiveRefusedMAC: the lift's MAC did not check under the run's key, or the launcher had already been handed it
	// (a replay).
	LiveRefusedMAC = "mac"
	// LiveRefusedOutsideFence: the entry is not in the run's fence.
	LiveRefusedOutsideFence = "outside-fence"
	// LiveRefusedLocked: the run is Locked, or its launcher holds no fence.
	LiveRefusedLocked = "locked"
	// LiveRefusedUntil: the lift's limit had already passed when the launcher read it.
	LiveRefusedUntil = "until"
)

// The kinds of a live block (LiveBlockChange.Kind, and the <kind> of a live.block[<kind>:<value>] rule): exec (a
// program), net (a destination) and path (every operation under a path) from MinorLiveBlock; read (the read opens
// under a path) and write (every modification under it: write opens, creates, unlinks, renames at either end, mkdir,
// links and symlinks) from MinorLiveControl.
const (
	LiveKindExec  = "exec"
	LiveKindNet   = "net"
	LiveKindPath  = "path"
	LiveKindRead  = "read"
	LiveKindWrite = "write"
)

// The why of a gap what=enforce about a person's pause or resume of a running run (MinorLiveControl,
// internal/liveblock): one line per change, in serial order, each written once the launcher applied it to the run's
// cgroup or failed to. A run is paused from its run-paused or resume-failed line until a later run-resumed line or
// its run_end.
const (
	// GapRunPaused is a pause the launcher put in force: the run's cgroup was frozen (or already was).
	GapRunPaused = "run-paused"
	// GapRunResumed is a resume the launcher put in force: the run's cgroup was thawed (or was not frozen).
	GapRunResumed = "run-resumed"
	// GapPauseFailed is a pause the launcher could not put in force: the run was not frozen and kept running.
	GapPauseFailed = "pause-failed"
	// GapResumeFailed is a resume the launcher could not put in force: the run stays frozen until it is resumed again
	// or stopped.
	GapResumeFailed = "resume-failed"
)

// LiveControlChange is one pause or resume of a running run, as the overlay's writer recorded it: op pause or resume,
// who made it ("uid:<uid> pid:<pid> <via>", via cli or dashboard, as LiveBlockChange.By), the change's serial in the
// overlay (from 1, one sequence with the live blocks' changes) and when it was made. The line's own ts is when the
// launcher applied it.
type LiveControlChange struct {
	Op     string    `json:"op"`
	By     string    `json:"by"`
	Serial uint64    `json:"serial"`
	At     time.Time `json:"at"`
}

// LiveBlockChange is one add or remove of a live block, as the overlay's writer recorded it: op add or remove, the
// block's kind (exec, net or path; read or write from MinorLiveControl) and normalized value, the rule a refusal under it carries
// (live.block[<kind>:<value>]), who made the change ("uid:<uid> pid:<pid> <via>", via cli or dashboard), the change's
// serial in the overlay (from 1, one per change) and when it was made. The line's own ts is when the launcher put it
// in force.
//
// From MinorLiveModes it also records a time limit's end (op expire), and a lift and a restore of an Adjustable run's
// fence entry (op lift or restore, rule live.fence[...]).
type LiveBlockChange struct {
	Op     string    `json:"op"`
	Kind   string    `json:"kind"`
	Value  string    `json:"value"`
	Rule   string    `json:"rule"`
	By     string    `json:"by"`
	Serial uint64    `json:"serial"`
	At     time.Time `json:"at"`
	// Until is the change's time limit (MinorLiveModes): on an add, a remove or a lift, when it ends; on an expire
	// line, the instant that passed. Absent, the change had none.
	Until time.Time `json:"until,omitzero"`
	// Refused is why the launcher did not apply a lift (MinorLiveModes): one of the LiveRefused values, on a
	// live-lift-refused line only.
	Refused string `json:"refused,omitempty"`
}

// Limit which values.
const (
	LimitTokens     = "tokens"
	LimitCostUSD    = "cost_usd"
	LimitWall       = "wall"
	LimitStallAfter = "stall_after"
	LimitRepeats    = "repeats"
	// LimitLedgerBytes is the run's events.jsonl and blobs together (blobs from 2026-11-01, at the same minor)
	// reaching the machine's record.max_run_bytes (MinorLedgerCap). Its limit line carries no reason: the closed
	// reason set (spec/reason/REASON-CHANNEL.md) has no code for it.
	LimitLedgerBytes = "ledger_bytes"
)

// LimitPayload is the limit payload.
type LimitPayload struct {
	Which   string  `json:"which"` // tokens|cost_usd|wall|stall_after|repeats|ledger_bytes
	Value   float64 `json:"value"`
	Ceiling float64 `json:"ceiling"`
}

// RefusedPayload is the refused payload; it mirrors the refused action and is also the shape of last-refusal.json.
// Its reason and rule are the line's shared common fields (record.IsSharedField): MarshalLine lifts them onto
// the Event and Decode mirrors them back, so the line carries each once.
type RefusedPayload struct {
	Op     string `json:"op"`
	Target string `json:"target"`
	Reason Reason `json:"reason"`
	Rule   string `json:"rule"`
	// Mechanism and DecisionPlane are optional, additive within v1 (2026-09-29, TIER3-PLAN T13): a refusal the
	// kernel decision plane made (MechanismPlane), such as a socket its socket_create refused, or, with no
	// DecisionPlane, one cgroup/sock_create made (MechanismCgroup, 2026-10-05).
	Mechanism     string `json:"mechanism,omitempty"`
	DecisionPlane string `json:"decision_plane,omitempty"`
	// CommandRule and CommandMatch name an exec command rule's refusal (ADR 0048 (8)), optional at record_minor 7.
	CommandRule  string `json:"command_rule,omitempty"`
	CommandMatch string `json:"command_match,omitempty"`
}

// ExecRules are the exec command rules' counters of a run (ADR 0048 (8)): execs a command rule refused, those refused
// on an ambiguous match, and those refused by the reserved exec.ask list. Optional at record_minor 7; absent for a run
// without command rules.
type ExecRules struct {
	Refused   int64 `json:"refused"`
	Ambiguous int64 `json:"ambiguous"`
	Asked     int64 `json:"asked"`
	// Killed, KillFailed and PinRefused are a pinned run's (ADR 0048 (8), P2; record_minor 12, absent when zero): the
	// execs the plane killed at sched_process_exec, those of them whose kill the kernel could not send (the launcher's
	// pidfd kill followed), and those refused for their pin (bprm_check's pin refusals and pin_unavailable).
	Killed     int64 `json:"killed,omitempty"`
	KillFailed int64 `json:"kill_failed,omitempty"`
	PinRefused int64 `json:"pin_refused,omitempty"`
}

// Run end reason values.
const (
	RunEndExit       = "exit"
	RunEndSignal     = "signal"
	RunEndStopped    = "stopped"
	RunEndOOM        = "oom"
	RunEndPids       = "pids"
	RunEndLimit      = "limit"
	RunEndExecFailed = "exec-failed"
	RunEndOrphaned   = "orphaned"
	RunEndError      = "error"
)

// Supervisor is the run_end counter block: what the seccomp user-notification loop did over the run.
// Anomalies counts notifications held longer than the loop's soft ceiling, which is how a run that paid an
// unexpected supervisor cost shows up in measure instead of only in a benchmark.
type Supervisor struct {
	Notifications int64 `json:"notifications"`
	HeldMS        int64 `json:"held_ms"`
	Anomalies     int64 `json:"anomalies,omitempty"`
	// Orphaned counts syscalls the loop performed on the agent's behalf whose notification the agent
	// abandoned before the answer arrived (docs/p0/supervisor.md E35): each is a side effect the kernel is
	// about to repeat when it restarts the call. Under record: summary or full each also has its own net line
	// with result_unknown and this is their total; under record: off no allowed net line is written, so this
	// total is the only trace of them in the record.
	Orphaned int64 `json:"orphaned,omitempty"`
	// Starved counts the times a parked relay could not be backfilled because every standby worker was
	// already in use: each left the loop answering the agent's other syscalls with one worker fewer until
	// that relay returned. Nothing else in the ledger records it.
	Starved int64 `json:"starved,omitempty"`
	// OrderLost counts the notifications whose lines were written without waiting for the previous notification of
	// the same thread, because it was still writing after the supervisor's one-second bound (docs/p0/supervisor.md
	// R23a): each such line may precede, along seq, a line of an earlier syscall of its thread. Additive at
	// record_minor 11 (MinorRuntimeGrants); absent when zero, and in a ledger written before the field.
	OrderLost int64 `json:"order_lost,omitempty"`
	// ExecRules counts what the exec command rules refused (ADR 0048 (8)); nil for a run without command rules.
	ExecRules *ExecRules `json:"exec_rules,omitempty"`
	// ExecMissing counts the execs whose pathname named nothing (ENOENT or ENOTDIR on the walk the loop made as the
	// task's lookup would), which the loop answered with that errno and wrote no exec line for, at every record level:
	// nothing was named, decided or run (a PATH search's misses, mostly). Optional at record_minor 8
	// (MinorExecMissing); absent at that revision or later, there were none.
	ExecMissing int64 `json:"exec_missing,omitempty"`
}

// RunEndPayload is the run_end payload. Reason is the line's shared `reason` key (record.IsSharedField) in the
// run_end domain (RunEndReasons), not a refusal code. Head is a P1 nested child's parent-head report, absent in
// P0 (R13); the head anchored in chain.log is the run_end line's own id, written by the ledger.
type RunEndPayload struct {
	Reason     string     `json:"reason"` // exit|signal|stopped|oom|pids|limit|exec-failed|orphaned|error
	ExitCode   int        `json:"exit_code,omitempty"`
	Signal     int        `json:"signal,omitempty"`
	Escalated  bool       `json:"escalated,omitempty"`
	Detail     string     `json:"detail,omitempty"`
	Supervisor Supervisor `json:"supervisor"`
	Head       string     `json:"head,omitempty"`
	// Resources is what the run's cgroup reported it used, read once before the cgroup was removed; nil when
	// no file could be read (a run that never had a cgroup, or an older binary's line). Additive and
	// optional within v1 (docs/VERSIONING.md §2).
	Resources *Resources `json:"resources,omitempty"`
	// Network is the backend's final atomic network snapshot, before detaching
	// its maps. Absent measurements are unknown; admitted packet bytes include
	// headers and retransmissions and are not application payload bytes.
	Network *backend.NetworkCounters `json:"network,omitempty"`
	// StoppedBy is reserved (MinorStoppedBy): nothing in this tree writes it. It holds a reference matching
	// StoppedByPattern, on a run_end whose reason is stopped.
	StoppedBy string `json:"stopped_by,omitempty"`
}

// Resources is run_end's resource line, read from the run's cgroup v2 control files. A key is present
// exactly when its file and key existed on the run's kernel and controllers, so an absent key is unknown,
// never zero (docs/VERSIONING.md §2): memory_peak needs Linux 5.19 and the memory controller, pids_peak a
// kernel with pids.peak and the pids controller, the cpu_*throttled* keys the cpu controller, and
// memory_events the memory controller; cpu_usage_usec, cpu_user_usec and cpu_system_usec are on every
// cgroup v2 kernel. Every value is the kernel's own, cumulative over the run's whole cgroup subtree.
type Resources struct {
	// MemoryPeak is memory.peak: the most memory the run was ever charged at once, in bytes.
	MemoryPeak *uint64 `json:"memory_peak,omitempty"`
	// PidsPeak is pids.peak: the most tasks the run ever held at once.
	PidsPeak *uint64 `json:"pids_peak,omitempty"`
	// CPUUsageUsec, CPUUserUsec and CPUSystemUsec are cpu.stat's usage_usec, user_usec and system_usec.
	CPUUsageUsec  *uint64 `json:"cpu_usage_usec,omitempty"`
	CPUUserUsec   *uint64 `json:"cpu_user_usec,omitempty"`
	CPUSystemUsec *uint64 `json:"cpu_system_usec,omitempty"`
	// CPUNrThrottled and CPUThrottledUsec are cpu.stat's nr_throttled and throttled_usec: how often and for
	// how long cpu.max held the run back.
	CPUNrThrottled   *uint64 `json:"cpu_nr_throttled,omitempty"`
	CPUThrottledUsec *uint64 `json:"cpu_throttled_usec,omitempty"`
	// MemoryEvents is memory.events' high, max, oom and oom_kill counters; nil when the file was absent.
	MemoryEvents *MemoryEvents `json:"memory_events,omitempty"`
}

// MemoryEvents is the part of memory.events a run_end line carries. Each key is present when the file had it.
type MemoryEvents struct {
	High    *uint64 `json:"high,omitempty"`
	Max     *uint64 `json:"max,omitempty"`
	OOM     *uint64 `json:"oom,omitempty"`
	OOMKill *uint64 `json:"oom_kill,omitempty"`
}

// AskPayload is the coordination request payload. The README names the
// ask's own identifier `id`, which is the line's chain id on every event, so the wire key is `ask_id`, the same
// key AnswerPayload uses to refer back to it.
type AskPayload struct {
	AskID string `json:"ask_id"`
	Hold  string `json:"hold"`
}

// AnswerPayload is the coordination response payload.
type AnswerPayload struct {
	AskID  string  `json:"ask_id"`
	By     string  `json:"by"`
	AfterS float64 `json:"after_s"`
}

// AnswerAlternate is what an answer line carries when a person answered a held file open with an alternate (ADR
// 0057 D1, record_minor 9): the line's approved is false, since the operation as asked, the target, was not
// granted, and it has no answer_reason, since nothing was refused; Alternate is the file delivered in its place, by
// the path the supervisor read from the descriptor the person's command passed, and AlternateDev and AlternateIno its
// identity (st_dev, st_ino) when the person named it. The line's by names the person's authority (uid and pid, or
// standing:<ask_id> for a standing alternate). All three are absent from every other answer.
type AnswerAlternate struct {
	Alternate    string `json:"alternate,omitempty"`
	AlternateDev uint64 `json:"alternate_dev,omitempty"`
	AlternateIno uint64 `json:"alternate_ino,omitempty"`
}

// BoundaryPayload is the boundary payload (P2).
type BoundaryPayload struct {
	ContextBytes     int64    `json:"context_bytes"`
	DockerfileSHA256 string   `json:"dockerfile_sha256"`
	Tags             []string `json:"tags"`
	NetworkMode      string   `json:"network_mode"`
}

// SetPayload marshals v (one of the payload structs, or any JSON object) into e.Payload.
func (e *Event) SetPayload(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("record: marshal payload: %w", err)
	}
	if len(b) == 0 || b[0] != '{' {
		return fmt.Errorf("record: payload must be a JSON object: %w", ErrInvalidEvent)
	}
	e.Payload = b
	return nil
}

// DecodePayload unmarshals e.Payload into v. Unknown keys are ignored (docs/VERSIONING.md §2).
func (e *Event) DecodePayload(v any) error {
	if len(e.Payload) == 0 {
		return json.Unmarshal([]byte("{}"), v)
	}
	return json.Unmarshal(e.Payload, v)
}
