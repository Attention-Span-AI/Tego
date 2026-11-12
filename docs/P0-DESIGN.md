# P0 — The base: complete system design

> **Frozen baseline (2026-09-22).** Code cites this document widely, so it stays, but its build order, milestones and
> dates are superseded by the current specs and ADRs.

Status: design for implementation, 2026-09-22. P0 is the platform everything else stands on: the standards, the
executor, tiers 1 and 2, the record, model-traffic capture, the ledger, budgets, the read-side views and the operating
behaviour of a production tool. It is written to be built as-is. Later phases add on top and never change P0's
contracts. Every mechanism below was verified in the review passes (`docs/ARCHITECTURE.md`,
`docs/GAPS.md`); this document is the engineering specification, not the argument.

## 0. Scope

**In P0**
- Standards v0/v1: agent contract, run record, run identity, machine config, capability matrix, policy semantics,
  reason codes, versioning.
- Executor: `tego run` with the child stage, cgroup per run, lifecycle (lock, signals, PDEATHSIG, sweep), exit codes.
- Enforcement tier 1 (`landlock`, no root): file rules by inode, `deny_read` by enumeration, exec by inode, TCP by
  supervisor-completed connect, implicit denies.
- Enforcement tier 2 (`cgroup`, root, no boot change): network by host:port and UDP per cgroup, path-aware open and
  exec deny with reasons, materialization of the run's own cgroup subtree (descendants created under the run's
  cgroup), tier-1 rules inside the run. Cross-daemon adoption (Docker, podman, pods) is P2.
- Record: seccomp supervisor record (tier 1) and eBPF record (tier 2); read aggregation; watch lists; attribution
  fields.
- Capture: OpenSSL uprobes (tier 2) and the localhost forwarder (all tiers); HTTP/1.1 reassembly; gap detection.
- Derive: Anthropic Messages API parser; steps by time; decisions.
- Ledger: append-only, hash-chained, redacted, blobs, lock, anchor.
- Budgets: tokens, cost, wall, stall, repeats; stop through the cgroup.
- Read side: `status`, `drift`, `measure`, `events`, `compile --test`; `doctor`; `version`; `gc`.
- Operations: config layers, run directory, own log, no telemetry, data handling.

**Not in P0** (P1 and later): human approval (`ask`), tier 3 BPF LSM, the gate scores, learn mode,
profiles registry, harness adapters beyond the forwarder variables, Docker proxy, undo, replay, language-level sources, desktop tier.

*Amended 2026-10-05:* this list is P0's scope, not a build status. Three of its items were built
ahead of P1 on 2026-10-04: human approval (`fs.ask`, `net.ask`, top-level `ask`; `tego ask`, `approve`,
`deny`; ADR 0008's 2026-10-04 note), the bounded gate ([gate](p0/gate.md), ADR 0007) and tier 3 through step E
([Tier 3 plan](p0/TIER3-PLAN.md)). Current status is `spec/backend/CAPABILITIES.md` and the Tier 3 plan.

## 1. System overview

```
                      ┌──────────────────────────── tego run (supervisor process) ────────────────────────────┐
                      │  cli.run ─► config.Load ─► agent.Load/Compile ─► runtime.Run                             │
                      │                                                                                          │
                      │   launch ──clone3──► tego __child ──execve──► AGENT PROCESS TREE (in run cgroup)        │
                      │     │                 (Landlock, seccomp NEW_LISTENER, env, uid)      │     │            │
                      │     │ pidfd_getfd(notify fd)                                          │     │            │
                      │     ▼                                                                 │     │            │
                      │   supervisor.NotifyLoop ◄── seccomp notifications (connect, write-open, exec, …) ◄──┘     │
                      │     │  decide connect (tier 1) · record · CONTINUE                                       │
                      │   observe.Recorder  ◄── eBPF ring buffer (tier 2: exec/open/unlink/rename/connect)       │
                      │   capture.Uprobe    ◄── SSL_write/read probes (tier 2)                                    │
                      │   capture.Forwarder ◄── HTTP/1.1 on 127.0.0.1 ──TLS──► model endpoints                    │
                      │     │                                                                                     │
                      │     ▼   pipeline: stampRule ─► attribute ─► redact ─► splitBlobs ─► ledger.Writer          │
                      │   derive.Anthropic ─► decision/step events          limits.Watcher ─► cgroup.Kill         │
                      └──────────────────────────────────────────────────────────────────────────────────────────┘
                                   │ events.jsonl + blobs/ (0700/0600, hash-chained)
                                   ▼
                      tego status | drift | measure | events   (internal/check, read-only)
```

Process model: one supervisor process per run (the `tego run` invocation), one child stage that becomes the agent,
N agent processes in one cgroup. The supervisor holds the run lock, the notify fd, the ring-buffer reader, the
forwarder listeners and the ledger writer. Nothing is shared between runs except the pinned BPF programs (tier 2),
which are attached once per host and reference-counted with a build lock.

## 2. Components and interfaces (Go)

Package layout is `docs/REPO-LAYOUT.md`. Interfaces are declared where consumed. Signatures below are normative.

### 2.1 `pkg/spec/agent` — the contract
```go
type Contract struct {
    Version  int            `yaml:"version"`   // 0
    Name     string         `yaml:"name"`      // [a-z0-9-]{1,40}
    Extends  string         `yaml:"extends,omitempty"`
    Command  []string       `yaml:"command"`
    FS       FSSection      `yaml:"fs"`        // Write, DenyRead, Watch []string; Ask (approval scopes)
    Net      NetSection     `yaml:"net"`       // Allow, HTTP policy, Assurance; Ask (approval scopes)
    Exec     ExecSection    `yaml:"exec"`      // Allow []string; Privileged (P2)
    Env      EnvSection     `yaml:"env"`       // Pass, Deny []string; Mask (P2); Set map[string]string
    MCP      []MCPServer    `yaml:"mcp"`
    Models   []ModelEndpoint`yaml:"models"`    // provider, host, port
    Limits   Limits         `yaml:"limits"`    // CPU, CPUWeight, Memory, MemoryHigh, Pids, Tokens, CostUSD, Wall, StallAfter, Repeats (default 5)
    Record   RecordMode     `yaml:"record"`    // full | summary | off
    Tier     TierPin        `yaml:"tier"`      // auto | landlock | cgroup | bpflsm
    Capture  CaptureMode    `yaml:"capture"`   // auto | uprobe | forwarder | off
    IOUring  bool           `yaml:"io_uring"`
    // schema-only, rejected as "not yet supported" when non-empty: Prompt, Skills, Visibility, Docker, Containers, Exec.Privileged, Env.Mask
}
type Diagnostic struct { File string; Line, Col int; Code string; Message, Fix string; Severity string } // error|warning
func Load(path string, profiles ProfileSource) (*Contract, []Diagnostic, error)   // KnownFields(true); line numbers
func Compile(c *Contract, m *Machine) (*RuleTable, []Diagnostic, error)          // resolves PATH, hosts, existence
type RuleTable struct {
    FS     []FSRule     // Path, Kind (write|ask|deny_read|watch|implicit), Access AccessSet; resolved at run
    Net    []NetRule    // Host, Port, Proto, Verdict (allow|ask), IPs []netip.Addr, TTL
    Exec   []ExecRule   // Path, Basename, Interp string (PT_INTERP), Verdict
    Env    []string; Set map[string]string
    Limits Limits; Record RecordMode; Tier Tier; Capture CaptureMode
    Hash   [32]byte     // contract_hash: sha256 of the contract bytes as compiled
}
```
Validation rules: unknown field = error; `Command` non-empty; `Name` regex; every `FS` path exists or is a `write`
directory that `run` creates; `Net` hosts resolve (or `host-unresolvable` warning with `compile --offline`); `Exec`
basenames resolve on `PATH`; a `Limits` value above the machine ceiling is a warning and the ceiling stands
(`limit-above-machine`, spec/config/v0); `fs.write` must not contain the run directory or the contract file
(`contradiction`, a compile error; `run` exits 125).

*Amended 2026-10-05:* the struct listed `fs.ask`, `net.ask` and top-level `ask` as schema-only,
and the schema-only line named `Gate` and `Ask`. Since 2026-10-04 `fs.ask`, `net.ask`, top-level `ask`
and `gate` load and compile; the schema-only set is `schemaOnlyFields` in `pkg/spec/agent/validate.go`.

### 2.2 `pkg/spec/record` — the run record
```go
type Kind string   // the closed v1 set in spec/record/v1/README.md (15 kinds); P0 writers emit 12 of them (never ask, answer, boundary)
type Verdict string // allow ask refused observed
type Source string  // kernel landlock seccomp fanotify ssl forwarder supervisor
type Attribution struct { Thread string; Step int; ToolUseID string; Confidence string; Method string } // exact|likely|unattributed ; tool_id|tid|time|none
type Event struct {
    V int; Seq uint64; ID string; Prev string; TS time.Time; MonoNS uint64
    Run, Agent string; PID, TID int; Cgroup uint64; Kind Kind; Source Source   // agent is a common field
    Rule string; Verdict Verdict; Authority string; Reason Reason; Attr Attribution
    Payload json.RawMessage   // kind-specific fields (§3.2)
}
type Reason string // closed set, spec/reason/REASON-CHANNEL.md
func (e *Event) MarshalLine() ([]byte, error) // canonical field order; the bytes hashed are the bytes written
func Decode(line []byte) (*Event, error)        // tolerant of unknown fields
```
*Amended 2026-10-05:* "P0 writers emit 12 of them (never ask, answer, boundary)" no longer
holds: since 2026-10-04 the runtime's ask lifecycle (`internal/runtime/ask_lifecycle.go`) writes `ask` and
`answer` too; `boundary` is still never written.

### 2.3 `pkg/spec/identity`, `pkg/spec/backend`, `pkg/spec/config`
```go
func NewRunID(hostID [32]byte, now time.Time, rnd io.Reader) string   // r-<host8>-<time36>-<rand6>
func RunSlug(id string) string                                         // dashes removed
type Env struct{ ... }; func (Env) Apply(base []string) []string       // identity + propagation set; runtime wins
const ExitLimit = 124; ExitLauncher = 125; ExitNoExec = 126; ExitNotFound = 127; ExitConfig = ExitLauncher (125, [config-untrusted])
type Tier string; type Capability string; type Set map[Capability]bool
func (s Set) Report() []Line // what ran, what was absent
type Machine struct { Tier, Capture Ceiling; Limits Limits; LedgerRoot string; Retention, StopGrace time.Duration; Resolver []netip.AddrPort; Ringbuf int; Prices, Profiles, PrivilegedBinary string; Log LogConfig }
func Load(invokingUID int, secure bool) (*Machine, []Diagnostic, error)  // layers, trust checks (0/uid owner, no g/o write), AT_SECURE
```

### 2.4 `internal/runtime` — the facade
```go
type Deps struct { Enforce enforce.Backend; Observe observe.Recorder; Capture []capture.Source; Ledger *ledger.Writer; Clock clock.Clock }
type Result struct { RunID string; ExitCode int; Reason string }
func Run(ctx context.Context, m *config.Machine, rt *agent.RuleTable, cmd []string, deps Deps) (Result, error)
```
`Run` owns the sequence in §4.1, an `errgroup` of workers, and a single `events chan record.Event` (buffered 4096)
drained by the pipeline into the ledger. Backpressure: producers never block the agent; if the channel is full the
producer increments a drop counter that becomes a `gap` event with `count` at the next opportunity: after the next
handled event, or within 100 ms while the queue is idle. The one event
that does not take that chance is the budget watcher's `limit` event, at most one per run: it has a reserved slot
beside the channel that the pipeline reads first, because the channel is full exactly when the pipeline is behind,
and a run killed for a budget must never end with `run_end reason=limit` and no line naming the ceiling.
*Amended 2026-09-24:* "producers never block the agent" let the agent choose
which of the run's lines were lost: eight processes making refused connects for 3 s left 17,748 lines and 97,538
channel-full drops, every other producer's lines among them, a model response too, whose tokens the budget then
never saw. The channel is now one lane per class of producer, 4096 each, read fairly by the pipeline: the
supervisor's lane, whose worker waits up to 250 ms for room (auditd's `backlog_wait_time`), so a flooding agent's
notified syscalls slow to the ledger's pace rather than displace other lines; the capture lane, whose producers
wait up to 5 s, and a run with a token or cost budget that loses an exchange anyway ends with `reason=error`,
since the budget can no longer be enforced; and the default lane, which never waits, for the kernel recorder's
ring drain and the tier-2 listener, where a wait would stall the kernel or the host's opens. A channel-full gap
is written at most every 100 ms, not after every event (a saturated queue wrote 54,014 gaps of count 1). The same
flood now writes every line (44,124 refused connects, no drop, `TestAFloodOfRefusalsLosesNoLines`).

### 2.5 `internal/runtime/launch` and `cgroup`
```go
type Launcher struct { ... }
func (l *Launcher) Start(ctx, spec ChildSpec) (*Child, error)   // clone3 CLONE_PIDFD|CLONE_INTO_CGROUP, control pipe
type Child struct { PID int; PidFD *sys.FD; ControlR *os.File } // owned pidfd (ADR 0023)
func (c *Child) WaitNotifyFD(ctx) (*sys.FD, error)               // reads fd number; pidfd_getfd; moved into supervisor.New
func (c *Child) Ack() error
type Manager interface { Create(path string) (Cgroup, error); Kill(Cgroup) error; SetLimits(Cgroup, Limits) error; Events(Cgroup) (<-chan bool, error) /* populated */ ; ID(Cgroup) (uint64, error) }
```
Child stage (`cmd/tego` hidden `__child`): runs on `runtime.LockOSThread`; order and facts as ARCHITECTURE §5:
env, uid drop, capability drop, `PR_SET_DUMPABLE=1`, `PR_SET_PDEATHSIG`, `no_new_privs`, `landlock_restrict_self`,
`seccomp(NEW_LISTENER)`, write fd number, wait ack, `execve` of `/proc/self/exe`'s target command.

### 2.6 `internal/runtime/enforce`
```go
type Backend interface {
    Tier() backend.Tier
    Capabilities() backend.Set
    Prepare(ctx, rt *agent.RuleTable, run RunRef) (Handle, error) // resolves inodes (O_PATH fds held), builds rulesets/maps
    Handle
}
type Handle interface { LandlockRuleset() (fd int, ok bool); SeccompFilter() ([]bpf.Instruction, bool); Attach(cgroupID uint64) error; Detach() error; Close() error }
func Select(m *config.Machine, rt *agent.RuleTable, probe *doctor.Probe) (Backend, []Diagnostic)
```
- `landlock` (tier 1): ruleset from held fds; `deny_read` by sibling enumeration to `/` (SEMANTICS §2); exec grants
  on binaries, loaders and interpreters; `CONNECT_TCP` handled, one rule per declared port; scopes on ABI ≥ 6. Seccomp filter:
  arch guard; io_uring and `openat2` → `ENOSYS`; notify on `connect`, `sendto` with address, `sendmsg`/`sendmmsg`,
  `execve`/`execveat`, `open`/`openat`/`creat` with write flags (mask `0x243`), `unlink*`, `rename*`, `mkdir*`,
  `symlink*`; everything else `ALLOW`.
- `cgroup` (tier 2): all of tier 1 inside the run, plus `cgroup/connect4,6`, `sendmsg4,6`, `bind4,6`,
  `connect_unix` programs attached to the run's cgroup with per-cgroup maps (`{cgroup, ip, port} → verdict`,
  LPM trie for CIDRs), fanotify `FAN_OPEN_PERM|FAN_OPEN_EXEC_PERM` marks on the mounts that hold rules with a
  listener that filters by the event pid's cgroup and answers `FAN_DENY` (errno on 6.13+) with a reason event, and the
  `cgroup_mkdir/rmdir` tracepoint program that materializes descendants.
- `observe`: `Prepare` returns a handle whose ruleset is empty, whose seccomp filter is tier 1's, and whose verdicts
  are `observed`: the supervisor runs record-only, continuing every action it would have refused and recording each
  one `observed` against the entry it matched (`docs/p0/supervisor.md` R30). Without the filter nothing notifies,
  so an observe run records nothing, and `Prepare` refuses to build a handle without one. R30 is about the
  supervisor's answers only. The filter's own errno arms still apply, for record completeness and parity with
  tier 1: the arch and x32 guards (so a 32-bit or x32 binary cannot run under `--observe`), `ENOSYS` for
  `io_uring_*`/`openat2`, `EPERM` for the terminal-injection ioctls, and `EPROTONOSUPPORT` for MPTCP sockets. The
  truncation arms of `docs/p0/enforce-landlock.md` R2 are the only ones left out. Because the child installs a
  listener, an `--observe` run nested inside a run that already has one fails at startup with `EBUSY`
  (`docs/p0/supervisor.md` R20).

### 2.7 `internal/runtime/supervisor` — the notify loop (P0: decisions for connect, record for the rest)
```go
type Loop struct { fd int; policy *Policy; sink Sink; workers int }
func (l *Loop) Run(ctx) error
// per notification: recv → arch/nr dispatch → read args under ID_VALID → decide → respond (CONTINUE | errno | 0 after connect-on-duplicate)
```
Rules: every target-memory read is followed by `ID_VALID` before use; connect decisions perform the connect on a
`pidfd_getfd` duplicate and return the real result; datagram sends with an address are checked then `CONTINUE`
(best-effort, recorded as such); write-opens, execs, deletes and renames are recorded and `CONTINUE`d (enforcement is
Landlock's); fast path typically under 10 µs (§9); 200 µs is the soft ceiling after which the notification is counted as an
anomaly in `run_end.supervisor`; a bounded worker pool (default 4) because a blocked worker blocks one target
thread only.

### 2.8 `internal/runtime/observe` (tier 2 record)
Programs: `trace_proc.bpf.c` on `sched_process_exec`, `sched_process_exit`, `security_file_open` (fentry, record
only), `security_path_unlink/rename/mkdir`, `security_socket_connect`; all filtered in-kernel by
`bpf_get_current_cgroup_id()` against the run-set map; events into one ring buffer; userspace `Recorder` enriches
from a process cache (`/proc` on first sight, then exec events) and aggregates reads per (exec id, rule) unless
watched. Lost-event counter → `gap` with `count`.

### 2.9 `internal/runtime/capture` and `derive`
- `Source` interface: `Start(ctx, run RunRef, sink Sink) error; Stop() error; Coverage() []Gap`. Under `capture: auto`
  both sources run: uprobes see TLS from processes in the run's cgroup, the forwarder sees plaintext on
  its loopback listeners and makes the upstream TLS connection itself outside the cgroup, so no request is ever
  captured twice; a contract that pins `uprobe` runs the uprobes alone, with no forwarder and none of its base-URL
  variables, so the agent's own TLS is what the probes read (§10 kill test 7, "a system-Python agent via uprobes");
  where the tier cannot run uprobes it tops out at the forwarder; `forwarder` runs the forwarder alone; `off` runs
  neither and records a `gap`. *Amended 2026-09-23:* `uprobe` ran both, and the forwarder's `ANTHROPIC_BASE_URL`
  routed an SDK agent's every request around the probes (docs/p0/capture-derive.md §4).
- `uprobe`: resolves the libssl (or the executable) each new process maps (`/proc/<pid>/maps`), attaches
  `SSL_write` and `SSL_write_ex2` (else `SSL_write_ex`), `SSL_read`/`SSL_read_ex` entry+return, keyed by `SSL*` per
  pid; per-cgroup filter; chunks to `httpstream`.
- `httpstream`: HTTP/1.1 request/response reassembly per connection key, chunked, `gzip`/`deflate`/`br`/`zstd`, SSE
  pass-through as one response with a body stream; emits `ssl_request`/`ssl_response` with bodies as blobs.
- `forwarder`: one `net/http` listener per `models[]` entry on `127.0.0.1:0`, upstream `host:port` over TLS, headers
  and body byte-for-byte except `Host`, `HEAD /api/hello` answered locally, no response buffering, `X-Tego-Run` and
  W3C trace headers added, retries recognised (`retry_of`), `NO_PROXY` handling by the launcher.
- `derive/anthropic`: parses request (`model`, `messages`, `tools`, `system`) and response (streaming events or JSON;
  `message.id`, `usage`, `stop_reason`, `tool_use` blocks) → `decision` events; unparseable → `decision: unparsed`.
- steps by time (E28a): a request to a declared model host opens step N+1 for that pid's thread; actions until the
  next request are attributed `method: time`, `confidence: likely` if one thread has calls in flight, else
  `unattributed`.

### 2.10 `internal/ledger`
```go
type Writer struct { ... }
func Open(dir string, run RunRef) (*Writer, error)   // creates 0700 dir, takes flock, opens events.jsonl O_APPEND
func (w *Writer) Append(e *record.Event) error         // sets seq, prev, id; one write(2); never blocks on fsync
func (w *Writer) Blob(b []byte) (sha string, err error)
func (w *Writer) Close(reason string) error            // run_end with head; appends "run head" to chain.log; fsync
type Reader struct{ ... }; func (r *Reader) Iter() iter.Seq2[*record.Event, error] // torn-line tolerant
```
Redaction stage before `Append`: header allow-list (`anthropic-version`, `request-id`, `content-type`, `user-agent`,
`traceparent`, `tracestate`); `x-api-key`, `authorization`, `cookie`, `proxy-authorization` never persisted, on the
loopback leg too. Blob split: any payload field over 4 KiB becomes a blob reference. Message dedup: `messages[]`
items stored once by hash.

### 2.11 `internal/runtime/limits`
Consumes `ssl_response` usage and the event stream: cumulative tokens, `est_cost` from the price table, wall time,
idle time (no event for `stall_after`), repeat detection (same tool name + input hash N times). On breach: `limit`
event, `cgroup.kill`, `run_end reason=limit`, exit 124.

### 2.12 `internal/check`
`status` (state machine §5), `drift` (per rule: declared vs done counts, unmatched, refused; unused MCP; contract
hash change), `measure` (steps, refused, tokens in/out, cache, est. cost, wall, idle max, repeats), `events` (raw, `--json`
verbatim lines), `compile --test` (table of action → expected verdict evaluated by the compiler's evaluator).

### 2.13 `internal/doctor`, `internal/cli`
`doctor`: kernel, BTF, cgroup v2 delegation, Landlock ABI (syscall), seccomp `ADDFD`/`SEND` self-test, LSM list
(`lsm_list_modules`, securityfs, log), every tier-2 program load test, capability matrix, the one-line fix, exit 0/211.
CLI: `init doctor compile run stop status drift measure events gc version` and hidden `__child`; flags parse, one
facade call, one-line messages in `file:line: message [code]` form.

## 3. Data model

### 3.1 Contract v0 (P0 subset consumed)
`version name extends command fs.{write,deny_read,watch} net.{allow,http,assurance} exec.allow env.{pass,deny,set} mcp models limits
record tier capture io_uring keyring ipc setuid`. Nonempty unsupported fields are rejected as `not-yet-supported`.
HTTP policy is limited to declared forwarders; kernel assurance requires measured destination hooks and the strict
client filter. See [agent-contract R2](p0/agent-contract.md) and [network semantics](../spec/policy/SEMANTICS.md).

### 3.2 Record v1 payloads (by kind)
| Kind | Payload |
|---|---|
| `run_start` | `launcher_pid launcher_start_ns tego_version commit bpf_hash tier capture kernel contract_hash parsers stop_grace command cwd`, optional `limits{tokens,cost_usd,wall,stall_after,repeats} capabilities` (the run's capability line, `docs/p0/record-ledger.md` §2.2) `stdio{stdin,stdout,stderr}` (the kind of each standard descriptor the agent kept, added 2026-09-24) `run_command_grant` (the absolute path the command given after `--` was granted as for the run, which the contract hash does not cover; added 2026-09-24) |
| `exec` | `path argv script stage exec_id parent_exec_id` |
| `fs` | `op(open\|unlink\|rename\|mkdir\|symlink\|truncate) path path2 flags count(aggregated)` |
| `net` | `proto dst(ip:port) host(if known) boundary propagated` |
| `ssl_request` | `endpoint method path host request_id blob(sha) size trace_id span_id parent_span_id retry_of` |
| `ssl_response` | `request_seq status model response_id stop_reason usage{input,output,cache_read,cache_write,output_bound?,cache_write_1h?,server_tool?,modified?} latency_ms content_encoding parser_version blob(sha)` |
| `decision` | `step tool_use_id tool name input_hash text(bool) unparsed why` |
| `gap` | `what why binary count` |
| `limit` | `which value ceiling` |
| `refused` | `op target reason rule` (mirrors the refused action) |
| `run_end` | `reason exit_code signal escalated detail supervisor{notifications,held_ms,anomalies,orphaned,starved} head` |
Common fields on every event: §2.2. `attribution` on `exec fs net mcp`.

### 3.3 Storage layout
```
<ledger_root>/<run>/           0700
  events.jsonl                 0600, append-only
  blobs/<sha256>               0600, content-addressed
  lock                         flock held by the supervisor
  contract.yaml                copy as compiled (hash = contract_hash)
  last-refusal.json            latest refusal, coalesced ≤10 ms (reason channel)
  ask.sock                     0600 approval broker socket (seqpacket; chowned to the invoking user under root)
~/.tego/chain.log             "<run> <head>" per run, 0600 (no home: <ledger_root>/../chain.log, record-ledger.md §3)
~/.tego/tego.log             own log, rotated
$XDG_RUNTIME_DIR/tego/<run>/  CODEX_HOME and the Docker proxy socket (P2); the forwarder listens on TCP 127.0.0.1; approvals use <run>/ask.sock above (amended 2026-10-05)
/sys/fs/bpf/tego/<bpf_hash>/  pinned programs, maps, links (tier 2)
/run/tego/bpf-<bpf_hash>.lock build lock
```

## 4. Flows

### 4.1 Run start
1. `cli.run`: `config.Load` (layers, trust; exit 125 [config-untrusted] on failure) → `agent.Load` (exit 125 with diagnostics) →
   `agent.Compile` against the machine (ceilings, PATH, hosts) → `enforce.Select` (highest tier at or below the
   ceiling that `doctor.Probe` allows; a pinned tier that is unavailable exits 125 `[tier-unavailable]`; `doctor --require` is the command that exits 211).
2. `runtime.Run`: `NewRunID`; create the run directory and `ledger.Open` (lock); create the cgroup
   (`CLONE_INTO_CGROUP` target) and set limits; `Backend.Prepare` (opens `O_PATH` fds, builds ruleset/maps; tier 2
   attaches programs to the cgroup and takes the build lock); start forwarder listeners and compute the identity env;
   `PR_SET_CHILD_SUBREAPER`.
3. `launch.Start` the child stage; receive the notify fd via `pidfd_getfd`; start `supervisor.Loop`,
   `observe.Recorder` (tier 2), `capture` sources, `limits.Watcher`, the pipeline; write `run_start`; `Ack`.
4. The child execs the agent. From here every event flows through the pipeline: `stampRule` (rule + verdict from
   the backend's decision or the compiler's evaluator) → `attribute` (E28a) → `redact` → `splitBlobs` → `Append`.
5. Exit: `cgroup.events populated=0` (or `stop`, limit, signal) → drain the pipeline → `limits` final →
   `ledger.Close(reason)` → `Backend.Detach/Close` (release fds, drop map entries, build lock) → remove the cgroup
   and run sockets → exit code per `spec/identity`.

### 4.2 A TCP connect
- Tier 1: filter notifies `connect` → supervisor reads `sockaddr` (ID_VALID) → resolves against `Net` rules (IP set
  refreshed on TTL) → allowed: `pidfd_getfd` the socket, `connect()` on the duplicate, respond with the real result;
  refused: respond `-EACCES`, emit `net verdict=refused reason=net-not-allowed`; either way emit `net` with `rule`.
- Tier 2: the supervisor inherited from tier 1 decides first, exactly as above, and never relays a destination it
  refuses, so the agent's refusal is `-EACCES` here too. The relay of an allowed connect is a connect on the run's
  socket, so `cgroup/connect4,6` decides it again in-kernel from the run's rows and writes its verdict and reason code
  to the run's reason breadcrumb (no ring-buffer event). The kernel's verdict is an AND with the supervisor's: a
  destination the program refuses fails the relay with the kernel's `EPERM`, which the supervisor returns as the real
  result (enforce-cgroup-observe R5; SEMANTICS §5, "The errno of a refusal"). *Amended 2026-09-23:* this said the
  notification was `CONTINUE`d after recording, which is not what the reconciled R5 or the supervisor (R9, I2) do.

### 4.3 A write open
- Tier 1: Landlock decides (`EACCES` outside `write`); the filter notifies write-opens for the record → supervisor
  reads the path (ID_VALID) → `CONTINUE`; the result is learned from the `fs` event's verdict (the supervisor cannot
  see the outcome, so verdict is `allow` when the path is inside a write rule, `refused` otherwise, with `source:
  seccomp` marking the record as advisory).
- Tier 2: fanotify `FAN_OPEN_PERM` → listener (pid → cgroup → run) → `FAN_ALLOW`/`FAN_DENY` with errno and a reason
  event; `security_file_open` fentry records with the real verdict.

### 4.4 An exec
- Filter notifies `execve` → argv read (ID_VALID) → `exec` event with `argv`; tier 1 enforcement by Landlock
  `EXECUTE` on the inode; tier 2 by `FAN_OPEN_EXEC_PERM`; the `#!` stage rule (SEMANTICS §4) applies in tier 3 only,
  so P0 documents that a directly executed unlisted script is refused in tiers 1 and 2.

### 4.5 A model call
- Uprobe path (tier 2, system OpenSSL): `SSL_write*` chunk → `httpstream` assembles the request → `ssl_request`
  (blob) → `derive` parses → step N+1 opens for the thread → `SSL_read*` chunks → response (SSE assembled) →
  `ssl_response` with usage → `decision` events per `tool_use` → `limits` updates tokens and cost.
- Forwarder path (any tier): identical events with `source: forwarder`; the listener is the only allowed route to
  the model host in the compiled rules, so a direct connect is `refused`, never silent.

### 4.6 Stop, limit, crash, orphan
- `tego stop <run>`: SIGTERM to the cgroup, `stop_grace`, `cgroup.kill`; `run_end reason=stopped`; exit 143/137.
- Limit: `limit` event, `cgroup.kill`, `run_end reason=limit`, exit 124.
- Supervisor crash: agent main process dies by `PDEATHSIG`; descendants fail closed (`ENOSYS` on notified syscalls);
  the next `run`/`stop`/`gc` sweeps: takes the free lock, kills the cgroup if populated, appends
  `run_end reason=orphaned`, cleans up.

## 5. State machines

**Run**: `starting → running → ending → ended`; `lost` is a reader state (lock free, no `run_end`).
**Status view**: `running` (events in the last T) · `waiting model` (open request, no response) · `waiting tool`
(last response ended with `tool_use`, no later request) · `stalled` (alive, no event for `stall_after`) · `done` ·
`lost`. `waiting approval` arrives in P1.
**Attribution**: `none` → `time` → `tool_id`/`tid` (2026-10-20, capture-derive R42: the reply's tool window, then the thread's own step by tid, then time).

## 6. Concurrency model
- One goroutine per source, one pipeline goroutine, one ledger writer; `events` channel buffered 4096, drop-count
  on full (never block the agent).
- Supervisor: bounded worker pool; each notification handled to completion by one worker; shared read of the rule
  table (RCU-style pointer swap on TTL refresh).
- Ring buffer: one reader goroutine, batch drain, lost counter.
- Forwarder: `net/http` server goroutines; a per-run `http.Transport` with connection reuse to each upstream.
- Shutdown: `context` cancel, `errgroup.Wait`, then ledger close; ordering guarantees `run_end` is the last line.

## 7. Security model
- **TCB**: `launch`, the child stage, `supervisor`, `enforce/cgroup` (fanotify listener), `observe`,
  `capture/uprobe`, the BPF programs. No third-party dependency inside beyond cilium/ebpf, go-landlock, x/sys, x/net.
- **Privilege**: tier 1 runs as the user. Tier 2 runs as `sudo tego run` or through a file-capability copy named
  by the root-owned machine config; the child stage drops to the invoking uid and clears capabilities before exec;
  the supervisor never opens files with root credentials (P1 asks adopt the target's identity). (*Amended
  2026-10-05, ADR 0042 (2), (3):* tier 2 runs from a root launcher only; a file-capability copy is refused at start
  with `[privileged-path-unsupported]`, and every uid-0 gate means uid 0 of the initial user namespace.)
- **Implicit denies**: run directory, contract file, `/sys/fs/cgroup`, `/sys/fs/bpf` are never writable from inside
  the run; `io_uring` and `openat2` refused unless declared in a root tier. *Amended 2026-09-24:* tego's own
  directory, the ledger root and `/run/tego` are never readable from inside the run either (agent-contract R6a).
- **Ledger**: `0700`/`0600`, header allow-list, no credentials ever written, bodies as blobs, hash chain anchored in
  `chain.log`, never rewritten.
- **Threat model** (README): holds a mistaken or injected agent to its contract for files, network and new
  processes; does not stop in-process logic, nor exfiltration through *any* allowed endpoint — the model endpoint
  and, equally, the tool hosts a coding agent needs, because a rule matches `host:port` and not the use a host is
  put to (A1, A4); it does not hide the machine.
- **Fuzz targets**: sockaddr and path readers in `supervisor`, `httpstream` parser, `derive/anthropic`, contract
  loader.

## 8. Errors and diagnostics
Exit codes and message format per `spec/identity/RUN-IDENTITY.md`. Diagnostics carry a closed code set. `doctor`
names the tier, what the next tier is missing and the one command that fixes it. Own log in `~/.tego/tego.log`,
never the agent's data. No telemetry, no update check.

## 9. Performance budgets (measured by `test/e2e/overhead`, reported per tier and record mode)
| Path | Budget |
|---|---|
| Landlock decision | negligible (kernel) |
| cgroup socket program | < 1 µs per connect |
| fanotify open/exec permission round trip | < 30 µs per open; benchmarked separately on builds |
| seccomp notification fast path (record + CONTINUE) | < 10 µs per notified syscall |
| uprobe pair per TLS read/write | 2–4 µs |
| forwarder per request | ~100 µs |
| ledger append | < 20 µs, no fsync per event |
| whole run, enforce-only / summary / full | < 1% / < 3% / < 5% on `test/workloads/build` |
Ring buffer 8 MiB default; drops counted, never blocking.

Overhead harness (`test/e2e/overhead`, `make overhead`): `docs/BENCHMARKS.md`. First
measured numbers are in: on the test machine's one reachable tier (`landlock`), the one row that isolates
marginal cost (fixed per-invocation cost subtracted out) lands at
2.7% — but most cells on this shared, memory-pressured machine came back too
noisy to publish, and `cgroup`/`bpflsm` were unreachable here at all; the full matrix still needs a
dedicated machine (`test/vm`'s kernel-matrix CI job).

## 10. Testing and CI
- **Unit**: contract loader with line numbers (golden diagnostics); compiler evaluator table tests; sibling
  enumeration cases; `httpstream` golden files per encoding and for SSE; `derive/anthropic` golden files per API
  version; ledger chain and torn-line tests; identity env; exit codes.
- **BPF map logic**: userspace tests of the LPM and verdict maps; `bpftool` load test of every object.
- **Integration** (`//go:build integration`, root, VM): child stage end-to-end (fd handoff, PDEATHSIG, dumpable),
  Landlock rules, supervisor connect decisions, cgroup programs, fanotify listener, uprobe capture on system Python,
  forwarder with the Claude Code binary, orphan sweep, stop.
- **E2E kill tests** (`test/e2e/`): 1 identity (two concurrent runs, 100% attribution), 2 capture (95% of pairs,
  gaps explained), 3 overhead, 4 ordinary work (19/20), 6 fresh VM in three halves (R16 as revised), 7 two agents
  (Claude Agent SDK via forwarder; a system-Python agent via uprobes).
- **Kernel matrix** (`test/vm`): Ubuntu 24.04 6.8, Debian 13 6.12, RHEL 9 5.14, AL2023 6.1 and 6.12, Fedora 7.0
  (WSL and macOS jobs in P2). *Amended 2026-10-05:* Ubuntu 25.10 6.17 and Fedora 7.2 are rows too. 6.17
  is the kernel the project is developed on, and Fedora 7.2 is the only row whose kernel has Landlock ABI 9 and
  10, so the pathname unix socket and UDP port rules run against a kernel that has them. Ubuntu 22.04's 5.15 is a
  doctor-only row: its Landlock is ABI 1, below the supported floor, so no tier is offered and the row asserts
  that `tego doctor` and `tego run` refuse the machine with the fix, in place of the kill tests.
- **CI**: gofmt, vet, golangci-lint with depguard layering, unit, generate-diff check, SPDX header check, schema
  validation of `spec/`, fixture ledgers replayed through every view, VM matrix on a schedule and on release tags.
- **Fixtures**: one hand-written `events.jsonl` frozen early is the contract for every view; every kill test adds a
  recorded fixture.

## 11. Operations
Config layers and trust (spec/config/v0); run directory outside every write dir; `runs/<id>/lock` liveness; sweep in
`run`/`stop`/`gc`; pins keyed by `bpf_hash` with the build lock; upgrade by rename and `/proc/self/exe`; retention by
`gc`; data handling and the operator notice (`docs/OPERATIONS.md`).

## 12. P0 done: acceptance
P0 is complete when, on the kernel matrix:
1. Kill tests 1, 2, 3, 4, 6 and 7 are green as stated in `docs/FEATURES.md` "Acceptance criteria".
2. `doctor` reports `landlock` as the user and `cgroup` with `sudo` on stock Ubuntu 24.04 with no boot change.
3. A system-Python agent, `claude -p` and a Go binary run unchanged under one contract each; one refusal each; the
   Go binary shows `gap what=capture`.
4. A looping agent is stopped by `limits.repeats`; a `$25` budget stops a run with exit 124 and a `limit` event.
5. `status`, `drift`, `measure`, `events` render from the fixture and from a real run; `compile --test` passes the
   shipped table.
6. Overhead numbers are published per tier and record mode.
7. Every P0 row in the feature map is checked off or moved to P1 with a written reason.

## 13. Detailed component specifications (models, repositories, contracts, rules, edge cases, tests)

Each component has a detailed specification under `docs/p0/`, in a fixed eleven-section shape: purpose and
boundaries, models (types), repositories and storage, functions and contracts, business rules (R-numbered), edge
cases (E-numbered), failure modes, invariants (I-numbered), conventions, tests, open questions.

| Component | Spec | Packages |
|---|---|---|
| Contract loader, compiler, evaluator, diagnostics | `docs/p0/agent-contract.md` | `pkg/spec/agent` |
| Event model, canonical encoding, chain, blobs, redaction, reader, gc | `docs/p0/record-ledger.md` | `pkg/spec/record`, `internal/ledger` |
| Ids, identity env, exit codes, machine config, capability matrix | `docs/p0/identity-config.md` | `pkg/spec/identity`, `pkg/spec/config`, `pkg/spec/backend` |
| Runtime facade, child stage, cgroup manager, lifecycle, pins | `docs/p0/runtime-launch.md` | `internal/runtime`, `launch`, `cgroup` |
| Tier 1: Landlock backend and the seccomp filter program | `docs/p0/enforce-landlock.md` | `internal/runtime/enforce`, `enforce/landlock` |
| Tier 2: cgroup programs, fanotify listener, descendants, eBPF record | `docs/p0/enforce-cgroup-observe.md` | `enforce/cgroup`, `observe`, `internal/bpf`, `bpf/` |
| Seccomp user-notification supervisor | `docs/p0/supervisor.md` | `internal/runtime/supervisor` |
| Capture (uprobes, HTTP reassembly, forwarder) and derivation | `docs/p0/capture-derive.md` | `capture/*`, `derive/*` |
| Budgets, views, doctor, CLI | `docs/p0/limits-check-doctor-cli.md` | `limits`, `internal/check/*`, `doctor`, `cli` |

Models index (where each type lives): `Contract`, `RuleTable`, `Diagnostic` in `pkg/spec/agent`; `Event`, `Kind`,
`Verdict`, `Reason`, `Attribution` in `pkg/spec/record`; `RunID`, `Env`, exit codes in `pkg/spec/identity`; `Machine`
in `pkg/spec/config`; `Tier`, `Capability`, `Set` in `pkg/spec/backend`; `Deps`, `Result` in `internal/runtime`;
`Backend`, `Handle` in `enforce`; `Child`, `Manager` in `launch`/`cgroup`; `Loop`, `Policy` in `supervisor`;
`Source`, `Gap` in `capture`; `Writer`, `Reader`, `Blob` in `ledger`.

Repositories index (every persistent or shared store): the run directory (`RunRepository`: list, open, lock,
state), the blob store (`BlobRepository`), the chain anchor (`chain.log`), the machine config layers, the pinned
BPF programs and maps (`/sys/fs/bpf/tego/<bpf_hash>/`) with the build lock, the run sockets under
`$XDG_RUNTIME_DIR/tego/<run>/`, the price table, the profiles directory, the uprobe attach cache, the own log.

Changes
- 2026-09-30: ExitConfig is ExitLauncher (125, [config-untrusted]); the former exit 213 was folded into 125 on 2026-09-22 (see OPERATIONS.md).
