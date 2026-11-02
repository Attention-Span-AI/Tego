// SPDX-License-Identifier: Apache-2.0

package record

import (
	"encoding/json"
	"time"
)

// Version is the run record schema version written by this binary.
const Version = 1

// Minor is the revision of v1's optional fields this binary writes, recorded as run_start's record_minor. It
// tells a reader what the absence of an optional field means: absent from a ledger at or past the revision that
// added it, the field was not needed; absent from an older one, the writer did not know it. A ledger with no
// record_minor is revision 0.
//
//	1  run_command_grant is written for every run whose command line added an exec rule (2026-09-24)
//	2  decision_plane is written on the run_start of every run whose tier has a decision plane (2026-09-30)
//	3  kernel exec outcomes carry syscall_ret and argv provenance (2026-10-04)
//	4  forwarder HTTP decisions and requested/actual network assurance (2026-10-04)
//	5  explicit listener/control policies, kernel bind/listen outcomes, final network counters and copied gate decision metadata (2026-10-04)
//	6  run_start's best_effort lists the run's disclosed best-effort gate cells (ADR 0041 D7, 2026-10-05)
//	7  exec lines carry the command-rule fields, and run_end's supervisor block exec_rules (ADR 0048 (8), 2026-10-06)
//	8  an exec whose pathname names nothing writes no line, and run_end's supervisor block counts it as exec_missing (2026-10-16)
//	9  held reads and alternates: an fs.ask_read hold's ask carries op read, an answer that gave an alternate carries
//	   alternate, alternate_dev and alternate_ino, the open it completed carries alternate_for, and run_start's
//	   ask_read_relaxes names every built-in deny_read entry an fs.ask_read entry relaxes (ADR 0057 D1, D4, D5,
//	   2026-10-16; ADR 0057 chose 8, which exec_missing took first when the two were merged)
//	10 a gate decision taken on the object the open deputy pinned and the open completed through it carries gate_facts
//	   held_object (ADR 0041 D5, gate.completion: held, 2026-10-16)
//	11 run_start's runtime_grants lists the grants the run made on its own authority, and run_end's supervisor block
//	   counts order_lost (agent-contract.md R10a, supervisor.md R23a, 2026-10-16)
//	12 an exec of a pinned run may be refused rule exec.pin with pin_unavailable, or killed (argv_decided, signal,
//	   kill_failed, detected_bypass); argv_facts says kernel_pinned or unproven; run_end's exec_rules counts killed,
//	   kill_failed and pin_refused (ADR 0048 (8), P2, 2026-10-19)
//	13 run_start's contract_source names the contract file the launching user named, by path or by a registry
//	   name (agent-contract.md R26, 2026-10-20)
//	14 run_start's harness names the harness the launcher provisioned for, whether it did and why not, its files,
//	   reason file and hook-state directory; runtime_grants may list fs.harness-state[<path>] (agent-contract.md
//	   R27, ADR 0062, 2026-10-24)
//	15 run_start's profiles lists the profiles the run's contract merged, in merge order, each with its source and
//	   sha256 (ADR 0066 D6, agent-contract.md R5, 2026-10-24)
//	16 a run with no net: section refuses a unix socket it did not bind, rule host-sockets, and run_start's
//	   host_sockets says such a run opted out (host_sockets: true) (ADR 0070, 2026-10-24)
//	17 run_start's launcher_uid is written on every run, with launcher_user, sudo_uid, sudo_user, host, parent_run,
//	   labels, role and contract_revision when the run has them (ADR 0073, 2026-10-25)
//	18 run_start's fs_reads says whether the run held its read opens and why, and the nested deny_read targets; a
//	   held read's fs line names the object the open deputy reached (ADR 0069 D4, 2026-10-24)
//	19 an fs line may be refused under a contract's fs.deny_write entry, rule fs.deny_write[<entry as declared>],
//	   and run_start's best_effort may list fs.deny_write (ADR 0071, 2026-10-25)
//	20 an allow-list contract's run grants its harness hook's exact argv, exec.harness-hook[<tego binary>] in
//	   runtime_grants, and run_start's harness carries the hook {argv, granted} and may say why
//	   harness-hook-writable (ADR 0064, agent-contract.md R27, 2026-10-25)
//	21 a run's live blocks (tego block, the dashboard's Block now): every add and remove is a gap what=enforce line,
//	   why live-block-added or live-block-removed, with live_block {op, kind, value, rule, by, serial, at}; an
//	   overlay the launcher could not read is why live-block-unreadable; and an action a live block refused carries
//	   the rule live.block[<kind>:<value>] (ADR 0100 implementation notes, 2026-10-25)
//	22 a run whose events.jsonl reached the machine's record.max_run_bytes ends with a limit line which=ledger_bytes
//	   (value and ceiling in bytes, no reason: the closed reason set has no code for it) and run_end reason limit,
//	   and run_start's limits carries ledger_bytes, the ceiling the run was started under (2026-10-26); from
//	   2026-11-01 the run's blobs count with events.jsonl, at the same minor
//	23 run_start's reads_notified says whether every read open reached the supervisor and why; a read the Landlock
//	   ruleset refuses under deny_read at tier landlock is a refused line with mechanism landlock under every record
//	   mode when it did (ADR 0077, 2026-10-26)
//	24 the live controls: a person's pause and resume of a running run (tego pause, tego resume, the dashboard's
//	   Pause) are gap what=enforce lines, why run-paused, run-resumed, pause-failed or resume-failed, with
//	   live_control {op, by, serial, at}; and a live block may be of kind read or write beside exec, net and path,
//	   refused under the rule live.block[read:<path>] or live.block[write:<path>] (2026-10-27)
//	25 credentials the agent never holds and per-tool MCP rules: a net line may carry credential {name, version} under
//	   the rule credential[<name>], refused credential-not-allowed, credential-revoked or credential-unavailable; an mcp
//	   line of source proxy may be refused mcp-tool-denied under mcp[<s>].tools.*, mcp[<s>].live[...] or
//	   mcp[<s>].relay; a gap why mcp-tool-changed carries mcp_tool (ADR 0126 D1, 2026-10-27)
//	26 the live modes (ADR 0125): a live block's, an unblock's and a lift's time limit (live_block.until) and its end
//	   (why live-block-expired, live-unblock-expired, live-lift-expired, op expire); an Adjustable run's run_start
//	   live_mode and live_fence, its lifts and restores (why live-rule-lifted, live-rule-restored, op lift or
//	   restore), a lift it refused (why live-lift-refused, live_block.refused), and the rule live.fence[<kind>:<value>]
//	   (2026-10-27)
//	27 model routes (ADR 0127): an ssl_request of a models[] endpoint that declares routes, and a credential's net line
//	   for it, carries route {name, authority}, the backend the request went to; a person's route change is a gap
//	   what=enforce why model-route-changed with model_route {model, route, authority, by, serial, at}; a request held
//	   for approval and not sent because its route moved is a refused net line, reason model-route-changed, rule
//	   models[<host:port>].routes (2026-10-27)
//	28 a mutation in an fs.ask scope is held for a person: its ask line carries hold mutation and target2, its answer
//	   line target2, and the mutation the supervisor made on the pinned names writes an fs line with authority human,
//	   operation_completed, syscall_ret and result_unknown; a rename or link across entries is refused with
//	   completion_unsupported and no gate fields (ADR 0047, 2026-10-20)
//	29 an action's attribution can be method tool_id, naming the reply's tool_use_id, or method tid; an ssl_request
//	   carries side when it is a model host's side traffic and tool_results when derive read the tool results it
//	   reports (capture-derive.md R40, R42, 2026-10-20)
//
// A revision is the next free number in the build that merges it, whatever number a plan expected, so a build writes
// 1 to Minor and every one of them (TestRecordMinorsAreContiguous, spec/record/v1/README.md "Revisions").
//
// 30 to 34 are reserved record revisions (MinorStoppedBy, MinorDeployment, MinorSecrets, MinorShares; 31 is reserved),
// declared and validated ahead of their writers: Minor reaches each only when the package that writes its field merges.
const Minor = MinorAttribution

// MinorAttribution is the first revision whose attribute stage ties an action to the reply that asked for it by
// that reply's tool_use id (method tool_id, attribution.tool_use_id) or to its own thread's step (method tid), and
// whose ssl_request lines carry side and tool_results (capture-derive.md R40, R42). Below it every action is
// method time or none, and a model host's side traffic opened a step like a model turn.
const MinorAttribution = 29

// MinorFSMutationAsk is the first revision whose writer holds a mutation in an fs.ask scope for a person and makes the
// approved one itself (ADR 0047): an ask line with hold mutation, target2 on a rename's, a link's or a symlink's ask
// and answer, and the completed mutation's human fs line. Below it every mutation in an fs.ask scope was refused
// unasked.
const MinorFSMutationAsk = 28

// MinorModelRoutes is the first revision whose forwarder may send a models[] endpoint's requests to one of its declared
// routes (ADR 0127): every ssl_request of an endpoint that declares routes names the route it took, route {name,
// authority} (direct for the endpoint itself), as does the net line of a credential injected into or refused for such
// a request; each route change the forwarder put in force is a gap what=enforce why model-route-changed with
// model_route; a request held for approval and not sent because its route moved is a refused net line, reason
// model-route-changed (ReasonModelRouteChanged). Nothing at it is written for an endpoint without routes. Below it
// each is refused [below-minor].
const MinorModelRoutes = 27

// MinorLiveModes is the first revision whose launcher reads a time limit on a live block or unblock and records its
// end, and whose run_start may say the run is Adjustable (ADR 0125): live_mode and live_fence, then a gap line for
// every lift, restore, expiry and refused lift the launcher applied, and the rule live.fence[<kind>:<value>] on every
// refusal by a fence entry and every action allowed only because one is lifted. Nothing at it is written on every
// run: a ledger at 26 or later without live_mode is a Locked run. Below it no line carries live_block.until or
// .refused, one of those whys or ops, live_mode, live_fence, or a live.fence[...] rule (ValidateAt refuses each
// [below-minor]).
const MinorLiveModes = 26

// MinorCredentialsAndMCPTools is the first revision whose ledger may hold the MCP relay's decisions (ADR 0126): an mcp
// line of source proxy (Tego's relay) allowed or refused
// mcp-tool-denied under mcp[<server>].tools.allow, .tools.deny[<tool>], .tools.ask[<tool>], mcp[<server>].live[<tool>]
// or mcp[<server>].relay; and a gap what=enforce why mcp-tool-changed with mcp_tool {server, tool, decision, by, serial,
// at}. Nothing at it is written on every run. Below it each of those is refused [below-minor].
const MinorCredentialsAndMCPTools = 25

// MinorLiveControl is the first revision whose ledger may hold a person's pause and resume of a running run: the
// launcher reads them from the run's overlay (internal/liveblock), applies each in serial order by freezing or thawing
// the run's cgroup, and writes one gap line what=enforce per change, why run-paused, run-resumed, pause-failed or
// resume-failed, with live_control naming the change, who made it and when; and whose live blocks may be of kind read
// (read opens under a path) or write (every modification under it), refused under live.block[read:<path>] or
// live.block[write:<path>]. Nothing at it is written on every run, so a ledger at 24 or later without such lines had
// none. Below it no gap names live_control or has one of those whys, and no live block or rule is of kind read or
// write (ValidateAt refuses each [below-minor]).
const MinorLiveControl = 24

// MinorReasonReads is the first revision whose run_start writes reads_notified on every run (absent at this revision or
// later is not a run this binary wrote), and whose refused line of a read Landlock refused at tier landlock carries
// mechanism landlock (MechanismLandlock).
const MinorReasonReads = 23

// MinorLedgerCap is the first revision whose launcher ends a run at the machine's record.max_run_bytes: a limit line
// which=ledger_bytes (value, the bytes events.jsonl and the run's blobs held at the check, blobs counted from
// 2026-11-01 and events.jsonl alone before; ceiling, the setting), then run_end reason limit, and
// run_start.limits.ledger_bytes is the ceiling the run was started under. Absent at it or later, the run had no
// ceiling.
const MinorLedgerCap = 22

// MinorLiveBlock is the first revision whose launcher reads a run's live blocks (internal/liveblock): every add and
// remove a person made while the run ran is a gap line what=enforce, why live-block-added or live-block-removed, with
// live_block naming the block, who changed it and when; an overlay it could not read is a gap why
// live-block-unreadable, the last one it read staying in force; and an action a live block refused is refused with
// the rule live.block[<kind>:<value>] and the reason its kind always has (exec-not-allowed, net-not-allowed, or the fs
// operation's). Below it no rule is live.block[...].
const MinorLiveBlock = 21

// MinorHarnessHook is the first revision whose launcher grants an allow-list contract's harness hook its exact argv
// (exec.harness-hook[<tego binary>] in runtime_grants) and whose run_start.harness carries hook for every provision
// that names one (ADR 0064). Absent at this revision or later, the provision named no hook.
const MinorHarnessHook = 20

// MinorUserDenyWrite is the first revision whose writer refuses a modification at or beneath a contract's
// fs.deny_write entry (ADR 0071): the fs line is refused with the rule fs.deny_write[<entry as declared>], the form a
// built-in target's rule already has (its resolved path in the brackets), and run_start's best_effort lists
// fs.deny_write where no kernel decision plane decided the entries. Below it no contract declared such an entry, so a
// fs.deny_write[...] rule there names a built-in target.
const MinorUserDenyWrite = 19

// MinorHeldReads is the first revision whose run_start writes fs_reads on every run (absent at this revision or later
// is not a run this binary wrote).
const MinorHeldReads = 18

// The reserved record revisions. Each field is declared and validated here, and nothing in this tree writes one;
// Event.ValidateAt and the payloads' ValidateFields refuse a field in a ledger below its revision [below-minor], so no
// writer can put one in a ledger whose record_minor does not say it knew the field.
//
//	30 run_end.stopped_by
//	31 reserved; no field is defined, so no constant
//	32 run_start.deployment
//	33 run_start.secrets, run_start.vault and every line's redactions
//	34 run_start.shares
const (
	// MinorStoppedBy is the first revision whose run_end may carry stopped_by.
	MinorStoppedBy = 30
	// MinorDeployment is the first revision whose run_start may carry deployment.
	MinorDeployment = 32
	// MinorSecrets is the first revision whose run_start may carry secrets and vault, and whose lines may carry
	// redactions.
	MinorSecrets = 33
	// MinorShares is the first revision whose run_start may carry shares.
	MinorShares = 34
)

// MinorRunIdentity is the first revision whose run_start writes launcher_uid on every run (absent at this revision or
// later is a writer fault, absent below it the writer did not know it), and launcher_user, sudo_uid, sudo_user, host,
// parent_run, labels, role and contract_revision whenever the run has one (absent at this revision or later, it had
// none) (ADR 0073).
const MinorRunIdentity = 17

// MinorHarness is the first revision whose run_start writes harness for every run whose contract does not say
// harness: none (absent at this revision or later, the run was provisioned for no harness).
const MinorHarness = 14

// MinorProfiles is the first revision whose run_start writes profiles for every run whose contract extends a
// profile (absent at this revision or later, the contract extends none).
const MinorProfiles = 15

// MinorHostSockets is the first revision whose writer refuses, in a run with no net: section, every unix destination no
// process of the run bound (net lines refused rule host-sockets), and whose run_start writes host_sockets: true for a
// run that opted out (ADR 0070). Absent at this revision or later, a run with no net: section was in the unix-only
// state; below it, such a run reached every host socket its uid could open.
const MinorHostSockets = 16

// MinorExecPins is the first revision whose writer can pin a run's execs at a decision plane (ADR 0048 (3) P2): an exec
// whose pin could not be written is refused rule exec.pin with pin_unavailable. Below it no exec line carries P2's
// fields.
const MinorExecPins = 12

// MinorContractSource is the first revision whose run_start writes contract_source for every run whose contract file
// the launching user named (absent at this revision or later, tego generated the contract).
const MinorContractSource = 13

// MinorHeldObject is the first revision whose writer can complete a gated open in the run, through the open deputy
// (ADR 0041 Stage B, gate.completion: held): the open's fs line carries gate_facts held_object, its path is the
// pinned object's, and a held open that failed or was not delivered carries operation_completed, fd_delivered and
// syscall_ret as an approved open's does. Below it every gate decision on an open is copied_syscall.
const MinorHeldObject = 10

// MinorRuntimeGrants is the first revision whose run_start writes runtime_grants for every run with one (absent at
// this revision or later, the run made none), and whose run_end.supervisor counts order_lost (supervisor.md R23a).
const MinorRuntimeGrants = 11

// MinorAskRead is the first revision whose writer holds reads (fs.ask_read) and takes alternates, and records them
// (ADR 0057 D5): an fs.ask_read hold's ask line carries op read; an answer that gave an alternate carries alternate,
// alternate_dev and alternate_ino with approved false and no answer_reason; and the fs line of the open it completed
// carries alternate_for; and run_start carries ask_read_relaxes whenever an fs.ask_read entry relaxes a built-in
// deny_read entry. Absent from a ledger at this revision or later, an answer gave no alternate and the run relaxed
// no built-in entry; below it, the writer may have been the 2026-10-06 POC, whose alternate answer carried alternate
// alone and whose run_start never named a relaxed entry.
const MinorAskRead = 9

// MinorExecMissing is the first revision whose seccomp supervisor answers an exec whose pathname names nothing
// (ENOENT or ENOTDIR on its walk) with that errno and writes no line for it, counting it in run_end.supervisor's
// exec_missing instead. In an older ledger such an exec has a line: refused unmatched in a restricted run, observed
// path_search for a PATH candidate, observed in a run with command rules, allow unmatched in an unrestricted run.
const MinorExecMissing = 8

// MinorExecCommands is the first revision whose exec lines carry command_rule, command_list, command_match,
// command_via, closure_of, argv_facts and argv_read where an exec command rule decided (ADR 0048 (8)).
const MinorExecCommands = 7

const MinorNetworkControl = 5

// MinorBestEffort is the first revision whose run_start writes best_effort for every run with a disclosed
// best-effort cell (ADR 0041 D7): absent at this revision or later, the run had none.
const MinorBestEffort = 6

// MinorHTTPRequest is the first revision with forwarder-scoped HTTP decisions.
const MinorHTTPRequest = 4

// MinorRunCommandGrant is the first revision whose run_start writes run_command_grant whenever there is one.
const MinorRunCommandGrant = 1

// MinorDecisionPlane is the first revision whose run_start writes decision_plane for every run of tier cgroup or
// bpflsm: absent from such a run's run_start at this revision or later, the ledger is not this schema's.
const MinorDecisionPlane = 2

// MinorExecOutcome is the first revision with terminal kernel exec failures and
// explicit provenance for argv supplied by the kernel or blocked attempt.
const MinorExecOutcome = 3

// Kind is an event kind. The closed v1 set (spec/record/v1/README.md); P0 writers emit twelve of the fifteen.
// Decode accepts all fifteen because the schema is frozen for the whole product, not per phase
// (docs/VERSIONING.md §2).
type Kind string

// The fifteen v1 kinds.
const (
	KindRunStart    Kind = "run_start"
	KindRunEnd      Kind = "run_end"
	KindExec        Kind = "exec"
	KindFS          Kind = "fs"
	KindNet         Kind = "net"
	KindMCP         Kind = "mcp"
	KindSSLRequest  Kind = "ssl_request"
	KindSSLResponse Kind = "ssl_response"
	KindDecision    Kind = "decision"
	KindAsk         Kind = "ask"    // P1
	KindAnswer      Kind = "answer" // P1
	KindRefused     Kind = "refused"
	KindGap         Kind = "gap"
	KindBoundary    Kind = "boundary" // P2
	KindLimit       Kind = "limit"
)

// Verdict is the outcome of an action.
type Verdict string

// The v1 verdicts.
const (
	VerdictAllow    Verdict = "allow"
	VerdictAsk      Verdict = "ask"
	VerdictRefused  Verdict = "refused"
	VerdictObserved Verdict = "observed"
)

// Authority is who decided an action's verdict: a contract rule, a gate, or a human.
type Authority string

// The v1 authorities.
const (
	AuthorityRule  Authority = "rule"
	AuthorityGate  Authority = "gate"
	AuthorityHuman Authority = "human"
	AuthorityLLM   Authority = "llm"
)

// Source is which component produced the event.
type Source string

// The v1 sources.
const (
	SourceKernel     Source = "kernel"
	SourceLandlock   Source = "landlock"
	SourceSeccomp    Source = "seccomp"
	SourceFanotify   Source = "fanotify"
	SourceSSL        Source = "ssl"
	SourceForwarder  Source = "forwarder"
	SourceHook       Source = "hook"
	SourcePython     Source = "python"
	SourceNode       Source = "node"
	SourceSupervisor Source = "supervisor"
	SourceProxy      Source = "proxy"
)

// Reason is a refusal or limit reason code; the closed set in spec/reason/REASON-CHANNEL.md.
type Reason string

// The v1 reason codes.
const (
	ReasonWriteOutsideContract  Reason = "write-outside-contract"
	ReasonDeleteOutsideContract Reason = "delete-outside-contract"
	ReasonRenameOutsideContract Reason = "rename-outside-contract"
	ReasonMkdirOutsideContract  Reason = "mkdir-outside-contract"
	ReasonReadDenied            Reason = "read-denied"
	ReasonPathUnresolved        Reason = "path-unresolved"
	ReasonExecNotAllowed        Reason = "exec-not-allowed"
	ReasonFSGate                Reason = "fs-gate"
	ReasonExecGate              Reason = "exec-gate"
	ReasonNetNotAllowed         Reason = "net-not-allowed"
	ReasonNetGate               Reason = "net-gate"
	ReasonNetHTTP               Reason = "net-http"
	ReasonAskDenied             Reason = "ask-denied"
	ReasonAskTimeout            Reason = "ask-timeout"
	ReasonAskUnavailable        Reason = "ask-unavailable"
	ReasonAskUnreadable         Reason = "ask-unreadable"
	ReasonLandlockTopology      Reason = "landlock-topology"
	ReasonLimitTokens           Reason = "limit-tokens"
	ReasonLimitCost             Reason = "limit-cost"
	ReasonLimitWall             Reason = "limit-wall"
	ReasonLimitStall            Reason = "limit-stall"
	ReasonLimitRepeats          Reason = "limit-repeats"
	ReasonOOM                   Reason = "oom"
	ReasonPids                  Reason = "pids"
	// ReasonCredentialNotAllowed: a request carried a credential's stand-in to an endpoint the contract and the vault
	// do not both allow, or in its URL query (MinorCredentialsAndMCPTools).
	ReasonCredentialNotAllowed Reason = "credential-not-allowed"
	// ReasonCredentialRevoked: a request carried the stand-in of a credential revoked in the vault.
	ReasonCredentialRevoked Reason = "credential-revoked"
	// ReasonCredentialUnavailable: the vault does not hold the credential, or its key store or value could not be read.
	ReasonCredentialUnavailable Reason = "credential-unavailable"
	// ReasonMCPToolDenied: Tego's MCP relay refused a tools/call its rules deny.
	ReasonMCPToolDenied Reason = "mcp-tool-denied"
	// ReasonModelRouteChanged: a model request held for a person's approval was not sent because its endpoint's route
	// changed while it was held (MinorModelRoutes, ADR 0127 §4).
	ReasonModelRouteChanged Reason = "model-route-changed"
)

// Attribution confidence values.
const (
	ConfidenceExact        = "exact"
	ConfidenceLikely       = "likely"
	ConfidenceUnattributed = "unattributed"
)

// Attribution method values.
const (
	MethodToolID = "tool_id"
	MethodTID    = "tid"
	MethodTime   = "time"
	MethodNone   = "none"
)

// Attribution ties an action to a model step. Present only on exec, fs, net and mcp events (R8). A writer
// produces {unattributed, none}, {likely, time, step N}, {likely, tid, step N} or {likely, tool_id, step N,
// tool_use_id} (capture-derive.md R34, R42); exact is never written by this one.
type Attribution struct {
	Thread string `json:"thread,omitempty"`
	Step   int    `json:"step,omitempty"`
	// ToolUseID is the reply's tool_use block the action is attributed to; set exactly when Method is tool_id
	// (record_minor 29).
	ToolUseID  string `json:"tool_use_id,omitempty"`
	Confidence string `json:"confidence"` // exact | likely | unattributed
	Method     string `json:"method"`     // tool_id | tid | time | none
}

// RunRef identifies the run a ledger Writer or Reader is bound to; supplied once at Open and stamped on every
// event so per-event callers never repeat it.
type RunRef struct {
	ID    string // run id, r-<host8>-<time36>-<rand6> (spec/identity/RUN-IDENTITY.md)
	Agent string // contract name, [a-z0-9-]{1,40}
}

// Event is one line of events.jsonl. Field order is the canonical encoding order (R1):
// v seq id prev ts mono_ns run agent pid tid cgroup kind source rule verdict authority reason attribution
// followed by the payload's keys, sorted. Payload is spliced into the top level by MarshalLine, never nested (R3);
// it is a JSON object whose keys are the kind-specific fields of §2.2.
type Event struct {
	V         int             `json:"v"`
	Seq       uint64          `json:"seq"`
	ID        string          `json:"id"`
	Prev      string          `json:"prev"`
	TS        time.Time       `json:"ts"`
	MonoNS    uint64          `json:"mono_ns"`
	Run       string          `json:"run"`
	Agent     string          `json:"agent"`
	PID       int             `json:"pid"`
	TID       int             `json:"tid"`
	Cgroup    uint64          `json:"cgroup"`
	Kind      Kind            `json:"kind"`
	Source    Source          `json:"source"`
	Rule      string          `json:"rule,omitempty"`
	Verdict   Verdict         `json:"verdict,omitempty"`
	Authority Authority       `json:"authority,omitempty"`
	Reason    Reason          `json:"reason,omitempty"`
	Attr      *Attribution    `json:"attribution,omitempty"`
	Payload   json.RawMessage `json:"-"`
	// Pair is an in-process token a capture source puts on both lines of one exchange, so the pipeline can
	// give the ssl_response the seq the ledger assigned its ssl_request (request_seq). It is never written:
	// it names nothing outside the process that emitted the pair.
	Pair uint64 `json:"-"`
	// Lane is an in-process token a capture source that knows a line's process but not its thread puts on
	// it instead of a tid: the forwarder numbers the model turns one process has in flight at once, so two
	// concurrent turns are two threads to derive's step attribution (docs/p0/capture-derive.md R34) and
	// sequential turns one. It is never written; the attribution derive stamps from it is.
	Lane uint64 `json:"-"`
}
