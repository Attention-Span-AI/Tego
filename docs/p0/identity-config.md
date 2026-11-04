# pkg/spec/identity + pkg/spec/config + pkg/spec/backend (P0 detailed spec)

## 1. Purpose and boundaries

**`pkg/spec/identity`** owns run/agent/exec id formats, the identity+propagation env set and its precedence
against `env.pass/deny/set`, cgroup/run-directory path conventions, the closed set of `tego run` exit codes, the
signal-forwarding table, and the `file:line[:col]: message [code]` format. It computes `host8` from an
already-hashed machine id (`[32]byte` in — it never touches `/etc/machine-id` itself). It must not: read files
other than bytes the caller hands it, treat a cgroup as a live kernel object (only produce path strings), decide
*whether* to forward a signal (that's `internal/runtime/launch`; identity only says which signals are forwardable
by rule), or import any other `pkg/spec/*` package.

**`pkg/spec/config`** owns `Machine`, the four-layer discovery/merge (built-in → `/etc/tego/config.yaml` →
`~/.tego/config.yaml` → `$TEGO_CONFIG`, contract ceilings merged later by `agent.Compile`), the ceiling-vs-setting
rule, the per-layer trust check, `AT_SECURE`/`SUDO_UID` handling, and per-field provenance for effective-value
printing. It must not: validate or compile an agent contract, select an enforcement backend
(`internal/runtime/enforce.Select`'s job — `config` only supplies the ceiling it checks against), or decide
`AT_SECURE` from anything but `/proc/self/auxv` bytes it reads itself.

**`pkg/spec/backend`** owns `Tier`/`Capability` enums, their fixed ordering, `Set` and its `Report()` rendering,
and the static matrix mirrored from `spec/backend/CAPABILITIES.md`. It must not: probe the kernel
(`internal/doctor.Probe`'s job), implement `Select` (`internal/runtime/enforce.Select` consumes `Tier`'s ordering
plus a `config.Machine` ceiling and a probe — the ceiling/pin/probe *algorithm* is still specified here, in §5,
because it is this component's contract even though the imperative code lives elsewhere), or hold live state (a
`Set` is a value, produced once per run, attached to `run_start`).

`AskConfig` (config) and the `ask` `Capability` constant (backend) are consumed by the ask broker (`internal/runtime/ask`).

All three: standard library only (`config`, like `agent`, may also import `gopkg.in/yaml.v3`); the module's Go version;
`CGO_ENABLED=0`; no `internal/` import; each package has a `doc.go`; none imports another `pkg/spec/*` package
(siblings, not a hierarchy — `docs/REPO-LAYOUT.md`).

## 2. Models

### 2.1 `pkg/spec/identity` — ids and env

```go
package identity

type RunID string  // r-<host8>-<time36>-<rand6>, immutable once minted
// hostID = sha256(machine-id), computed by the caller. host8 = hex(hostID[:4]).
// time36 = now.UTC().UnixNano(), base36, zero-padded to 13 chars. rand6 = 4 random bytes from
// rnd read big-endian as a uint32, right-shifted 2 (drops the low 2 bits — a deliberate, documented
// truncation, not padding) to exactly 30 bits, then base32-Crockford lower-case to exactly 6 chars
// (5 bits/char x 6 = 30 bits exactly — R1).
func NewRunID(hostID [32]byte, now time.Time, rnd io.Reader) (RunID, error)
func (r RunID) Valid() bool // ^r-[0-9a-f]{8}-[0-9a-z]{13}-[0-9a-z]{6}$
func (r RunID) Slug() string // dashes removed
func RunSlug(id string) string

type ExecID string // <run id>/<pid>/<start-boot-ns>, stable across pid reuse within one pid namespace (E30)
func NewExecID(run RunID, pid int, startBootNS uint64) ExecID

type AgentID string // [a-z0-9-]{1,40}
func ParseAgentID(s string) (AgentID, error)

// Env: the identity+propagation set the launcher installs last, immediately before execve.
// Zero value of a field ("" / nil / false) means "do not set this variable".
type Env struct {
    RunID          RunID
    Agent          AgentID
    ParentRun      RunID             // "" is a valid value: TEGO_PARENT_RUN="" is still set
    LedgerDir      string
    Tier           string            // "landlock"|"cgroup"|"bpflsm"|"observe"
    ForwarderVars  map[string]string // ANTHROPIC_BASE_URL etc.; non-nil only when capture: forwarder
    DockerHost     string            // "" unless the contract has docker:
    ContainersConf string            // "" unless containers: rootless
    RayHook        bool
}
// Apply merges the identity set into base (already env.pass/deny/set-resolved), runtime values
// always overwriting a same-named entry in base; returns a new slice, never mutates base.
func (e Env) Apply(base []string) []string
```

### 2.2 `pkg/spec/identity` — exit codes, signals, messages, paths

```go
const (
    ExitOK = 0; ExitLimit = 124; ExitLauncher = 125; ExitNoExec = 126; ExitNotFound = 127
    ExitStoppedTerm = 143; ExitStoppedKill = 137; ExitConfig = ExitLauncher // 125 [config-untrusted]
    // ExitPinnedTier (211) removed from this set: no normative doc assigns 211 to `tego run` — 211
    // is `doctor --require`'s own exit code (docs/FEATURES.md E38b; RUN-IDENTITY.md's 125 row names
    // no carve-out for a named/pinned tier). A pinned-but-unavailable tier in `tego run` is
    // ExitLauncher (125). See R18.
)

type EndReason string // mirrors record's run_end.reason verbatim (I9)
const (
    ReasonExit = "exit"; ReasonSignal = "signal"; ReasonLimit = "limit"; ReasonStopped = "stopped"
    ReasonOOM = "oom"; ReasonPids = "pids"; ReasonExecFailed = "exec-failed"
    ReasonOrphaned = "orphaned"; ReasonError = "error"
)
type ExecFailure int // disambiguates ReasonExecFailed
const (ExecFailureNone ExecFailure = iota; ExecFailureDenied; ExecFailureNotFound)

// ExitCode is the single place `tego run` turns "why the run ended" into a process exit status.
func ExitCode(reason EndReason, ws syscall.WaitStatus, escalated bool, xf ExecFailure) int

var ForwardAlways = []syscall.Signal{SIGTERM, SIGHUP, SIGUSR1, SIGUSR2}
var ForwardWhenNotTTY = []syscall.Signal{SIGINT, SIGQUIT}
var StopGraceTriggers = []syscall.Signal{SIGINT, SIGTERM, SIGHUP}

func FormatMessage(file string, line, col int, what, code string) string // "<file>:<line>[:<col>]: <what> [<code>]"

func RunDir(ledgerRoot string, run RunID) string
func UserCgroupPath(delegatedSubtree string, agent AgentID, run RunID) string
func SystemCgroupPath(agent AgentID, run RunID) string
func DockerParentSlice(agent AgentID, slug string) string  // tego-<agent>-<slug>.slice
func DockerParentCgroupfs(agent AgentID, run RunID) string // /sys/fs/cgroup/tego/<agent>/<run>
```

### 2.3 `pkg/spec/backend`

```go
package backend

type Tier string // closed, ordered. "auto" is a config/contract sentinel, never a Tier value.
const (TierLandlock = "landlock"; TierCgroup = "cgroup"; TierBPFLSM = "bpflsm"; TierObserve = "observe")
func (t Tier) Rank() int // landlock=1 cgroup=2 bpflsm=3 observe=0; -1 unknown
func (t Tier) Valid() bool
func (a Tier) AtOrBelow(ceiling Tier) bool  // Rank comparison; TierObserve always false (R17)
func ParseTier(s string) (Tier, error)

type Capture string // off < forwarder < uprobe
const (CaptureOff = "off"; CaptureForwarder = "forwarder"; CaptureUprobe = "uprobe")
func (c Capture) Rank() int
func (c Capture) AtOrBelow(ceiling Capture) bool
func (c Capture) Valid() bool // symmetric with Tier.Valid (R25)
func ParseCapture(s string) (Capture, error) // symmetric with ParseTier (R25)

type Capability string // one row of spec/backend/CAPABILITIES.md, 26 constants:
const ( // fs.deny_write fs.deny_delete_rename_mkdir_chmod_mknod fs.deny_read exec.deny
        // net.deny_host_port net.udp_by_destination net.udp_by_port_kernel net.unix ask
        // record.exec_open_connect record.reads_mmap_chmod capture.model_traffic
        // log.allowed_with_rule containers.adopted net.http_rules containers.namespace_sandbox
        // net.unix_abstract_scope fs.deny_chmod
        // net.tcp_destination_kernel net.unix_destination_kernel exec.command_argv
        // gate.fs_open_completion gate.fs_mutation_completion gate.exec_completion gate.net_completion
        // fs.protected_write_targets
        // (appended rows go last so no index moves, R23; the second row keeps its wire name, but its
        // title is "deny delete, rename, mkdir, mknod": chmod is fs.deny_chmod, agent-contract E35)
)
func AllCapabilities() []Capability // the 26 above, CAPABILITIES.md row order; a fresh slice

type Set map[Capability]bool // absent key = not provided
func (s Set) Has(c Capability) bool

type Line struct { Capability Capability; Present bool; Detail string } // Detail mirrors CAPABILITIES.md prose
func (s Set) Report() []Line // deterministic, AllCapabilities order

func Matrix(tier Tier) Set                         // a fresh copy of the tier's column; hand-kept identical to spec/backend/CAPABILITIES.md (I9)
func MatrixDetail(tier Tier, c Capability) string // the cell's prose; "" outside the table
```

### 2.4 `pkg/spec/config`

```go
package config

type Layer int // provenance source
const (LayerBuiltin Layer = iota; LayerEtc; LayerUser; LayerEnvFile; LayerContract)
type Provenance struct { File string; Line int; Layer Layer }

type Ceiling[T comparable] struct { Value T; Source Provenance } // only ever lowered (R15)
type Setting[T any] struct { Value T; Source Provenance }        // last layer wins (R16)

type Limits struct {
    CPU Ceiling[float64]; CPUWeight Ceiling[int]; Memory, MemoryHigh Ceiling[ByteSize]
    Pids Ceiling[int]; Tokens Ceiling[int64]; CostUSD Ceiling[float64]
    Wall, StallAfter Ceiling[time.Duration]
}
type AskConfig struct { Timeout Setting[time.Duration]; Notify Setting[[]string] } // consumed by the ask broker
type RecordConfig struct{ Ringbuf Setting[ByteSize] }   // power of two, page multiple (R-ringbuf)
type ForwarderConfig struct{ Listen Setting[string] }
type LogConfig struct{ Level Setting[string] }
type LandlockConfig struct{ Audit Setting[string] } // off | new-exec: LOG_NEW_EXEC_ON (enforce-landlock §4), a floor (R16), added 2026-09-23
type UserPolicy struct { Contracts []string; MaxRuns int } // tegod only; /etc only (R16a); ADR 0042 (7)(f) reserves it

// TierSetting/CaptureSetting document meaning only; the Machine field's real Go type is string
// ("auto" | tier/capture name) because config must not import backend (siblings rule, §1) —
// internal/runtime/enforce parses it with backend.ParseTier/ParseCapture; config.Load checks the name
// against its own rank maps (R24).
type TierSetting struct{ Auto bool; Tier string }
type CaptureSetting struct{ Auto bool; Capture string }
type ResolverMode struct{ Auto bool; Servers []netip.AddrPort }
type ByteSize int64 // UnmarshalYAML parses "32GiB" etc.

type Machine struct {
    Version                          int
    Tier                             Ceiling[TierSetting]
    Capture                          Ceiling[CaptureSetting]
    LedgerRoot, Prices, Profiles     Setting[string]
    Registry                         Setting[string]   // the user registry, "" for none (agent-contract.md R26)
    Retention, StopGrace             Setting[time.Duration]
    Limits                           Limits
    Ask                              AskConfig
    Record                           RecordConfig
    Resolver                         Setting[ResolverMode]
    DeniedResolved                   Setting[[]netip.Prefix] // union across layers, never narrowed (R16)
    Forwarder                        ForwarderConfig
    Log                              LogConfig
    Landlock                         LandlockConfig
    PrivilegedBinary                 Setting[string] // honoured only when Source.Layer == LayerEtc; trust
                                                       // checked separately from R20 (E31)
    Users                            Setting[map[string]UserPolicy] // honoured only from LayerEtc (R16a)
}

type Diagnostic struct { File, Message, Code string; Line, Col int; Severity string } // error|warning

func Load(invokingUID int, secure bool) (*Machine, []Diagnostic, error)
func InvokingUID() (uid int, viaSudo bool) // the SUDO_UID rule
func CurrentUserNamespace() UserNamespace // initial, child, or unknown: uid_map unreadable (read once)
func InitialUserNamespace() bool // /proc/self/uid_map is "0 0 4294967295"; unknown is false
func InitNSRoot() bool // effective uid 0 in the initial user namespace (ADR 0042 (5)(d))
func DetectSecureExec() (bool, error) // AT_SECURE (type 23) from unix.Auxv; /proc/self/auxv only as fallback

var ErrUntrusted = errors.New("config: untrusted layer file")
type UntrustedError struct { Path string; Owner int; Mode fs.FileMode }
func (e *UntrustedError) Error() string
func (e *UntrustedError) Unwrap() error // -> ErrUntrusted
```

## 3. Repositories and storage

None of the three packages opens a socket, pin, or long-lived handle — pure/value packages. What they read or are
the schema of:

| What | Path | Owner | Permissions | Format | Notes |
|---|---|---|---|---|---|
| Machine-id source | `/etc/machine-id` | caller reads, `identity` only consumes the digest | world-readable | 32 hex chars | identity never re-reads it; fallback chain is caller's own contract (Q7) |
| `/proc/self/auxv` | fixed | `config.DetectSecureExec` | kernel-provided | `Elf64_auxv_t` pairs | the Go runtime's copy of the vector (`unix.Auxv`) first; the file only when the runtime has none. *Amended 2026-10-05:* a file-capability or setuid exec leaves the process non-dumpable and the file then refuses the process itself (`EACCES`), so the file alone failed in exactly the `AT_SECURE` case (ADR 0042 (3)(a)) |
| `/etc/tego/config.yaml` | fixed | config | root or invoking-uid owned, `g-w,o-w` | YAML v0 | read-only |
| `<pw_dir>/.tego/config.yaml` | `getpwuid(uid)`, never `$HOME` | config | same trust rule | YAML | same |
| `$TEGO_CONFIG` | env-named path | config | same trust rule; must exist (E13); skipped under `AT_SECURE` | YAML | same |
| `privileged_binary` target | `Machine.PrivilegedBinary` | not `config.Load`; nothing reads it in this release | root-owned, not group/other-writable, `security.capability` xattr carries the three caps | ELF | distinct check from R20 (E31); `config.Load` never opens this file. *Conditioned 2026-10-05 (ADR 0042 (3)(c), (d)):* the file-capability copy is not delivered and is refused at start; the setting stays parsed, `/etc` only, and warns |
| Run directory | `identity.RunDir` | identity (path only; `internal/ledger` creates `0700`) | n/a | n/a | pure formatting |
| Cgroup paths | `identity.*CgroupPath` | identity (`internal/runtime/cgroup` does the mkdir) | n/a | n/a | pure formatting |
| Capability matrix | `backend.Matrix`/`MatrixDetail` | backend | in-binary | Go source | hand-kept to match `spec/backend/CAPABILITIES.md`, checked by `TestMatrixGolden` (I9) |

`config.Load` is read-only end to end; its only "write" on failure is the returned `[]Diagnostic` and (for
`tego run`) process exit 125 [config-untrusted].

## 4. Functions and contracts

- **`identity.NewRunID(hostID, now, rnd)`**: pre — `now` non-zero and in range (before 1970 is refused with an error, E32; overflowing the
  13-char base36 `time36` field is a caller bug, not handled specially — E32), `rnd` yields ≥4 bytes without
  indefinite block. post — result `.Valid()`. errors — wraps `rnd`'s read error, never partial. Not idempotent
  by design (E24 differentiates by `rand6`); no timeout.
- **`identity.Env.Apply(base)`**: pre — `base` is `env.pass/deny/set`-resolved `KEY=VALUE` entries. post — new
  slice, every non-zero receiver field present exactly once, replacing same-named `base` entries. Pure, total
  (never errors), idempotent (`Apply(Apply(base)) == Apply(base)` for the same receiver).
- **`identity.ExitCode(reason, ws, escalated, xf)`**: pre — `ws` from a real wait on the agent's main process, or
  zero value when `reason` never waits one (`ReasonError`, `ReasonOrphaned`). post — for `reason=exit`/`signal`,
  the code follows `ws.Exited()`/`ws.Signaled()` per R10 (never a fixed formula on the reason alone); otherwise
  one of `Exit*` per R11–R13. Total; unrecognised `reason` returns `ExitLauncher` (I8's exhaustive-switch lint).
- **`config.Load(invokingUID, secure)`**: pre — `invokingUID`/`secure` from the two helpers below (or fixed in
  tests). post — success: `*Machine` fully populated (built-in fills anything unset) with correct `Provenance`;
  `[]Diagnostic` may carry warnings even on success. errors — `*UntrustedError` on a failed trust check, a wrapped
  YAML error (a layer holding more than one YAML document is one), a number not in the contract's decimal
  spelling or underflowing to 0 (`limits.cost_usd`, `limits.cpu`), or an unsupported `version`; caller maps any error to exit 125 [config-untrusted]. Read-only, idempotent given an
  unchanged filesystem, no network/lock, no timeout needed.
- **`config.DetectSecureExec()`**: pre — none when the Go runtime kept the vector (`unix.Auxv`); `/proc` mounted
  for the fallback. post — `true` iff auxv type 23 present and non-zero. errors — an I/O error reading auxv is
  treated as fatal by the caller (a process that cannot read its own auxv cannot safely resolve
  `$HOME`/`$TEGO_CONFIG` either).
- **`backend.Tier.AtOrBelow` / `Capture.AtOrBelow`**: pre — both `.Valid()` (`Capture.Valid()` exists precisely to
  satisfy this precondition — R25). post — total-order comparison; `TierObserve.AtOrBelow(x)` always `false`
  (R17). Pure, O(1).
- **`backend.Set.Report()`**: pre — none (nil `Set` valid, every `Present` false). post —
  `len(result)==len(AllCapabilities)`, stable order. Pure.

## 5. Business rules

**Run id.**
- **R1** `time36` = `now.UTC().UnixNano()` base36, zero-padded to 13 chars (valid through ~2262). `host8` = lower
  hex of `hostID[0:4]`. `rand6`: `rnd` supplies exactly **4 random bytes** (32 bits), read big-endian as a `uint32`
  and right-shifted by **2 bits** (dropping the low 2 bits — a deliberate, stated truncation) to exactly **30
  bits**, then base32-Crockford-encoded to exactly 6 lower-case chars (5 bits/char × 6 = 30 bits exactly, no
  padding). *(Corrected: 4 bytes is 32 bits, 6 Crockford chars is 30 bits — "no padding, no truncation" was
  arithmetically impossible; this rule now states which 2 bits are dropped.)*
- **R2** `RunID.Valid()` matches `^r-[0-9a-f]{8}-[0-9a-z]{13}-[0-9a-z]{6}$` exactly. `RunSlug` strips every `-`.
- **R2b** Collision handling is stateless in `identity`; the caller (`internal/runtime.Run`) detects `EEXIST` on
  `mkdir(runs/<id>)`, retries `NewRunID` with a fresh `rnd` read up to 3 times (4 ids in all, the path each taken one
  names left untouched), then fails with `ExitLauncher` (125) and `could not allocate a unique run id after 4 attempts`.

**Env precedence.**
- **R3** Order: (1) `agent.Compile` resolves `env.pass` minus `env.deny` (absent `env:` = everything; a name in
  both `set` and `deny` is a compile error), (2) applies `env.set` in name order, each name replacing every entry of that name in the inherited environment (the first keeps its place, later duplicates are dropped) or appending, producing `base` = `RuleTable.Env`+`Set` —
  this is `pkg/spec/agent`'s output, not identity's; (3) `identity.Env.Apply(base)` runs **last**, in
  `internal/runtime/launch`, immediately before `execve`, unconditionally overwriting same-named entries from
  (1)–(2). `env.set: {TEGO_RUN_ID: "x"}` compiles without error and is silently discarded at `Apply` (T-env-3).
- **R3a** A root launcher drops the agent to the invoking user, so before (1) its environment is made that account's:
  a `HOME` equal to root's passwd home becomes the target's, and a `USER` or `LOGNAME` equal to root's name becomes the
  target's. `sudo` resets all three to root's, which left the agent a home it cannot enter beside a contract whose `~`
  is the target's. Any other value is the caller's choice and stays, a name the launcher does not have stays absent, and a
  target with no passwd entry changes nothing. `env.pass`, `env.deny` and `env.set` apply afterwards, so they still decide.
- **R4** `OTEL_RESOURCE_ATTRIBUTES`: append `,tego.run=<id>,tego.agent=<name>` (or set fresh); percent-encode `,`
  and `=` in the new values (defensive no-op today — neither value contains them). See E29 for the (unspecified)
  case where `base` already carries a stale `tego.run=`/`tego.agent=` key.
- **R5** `PGAPPNAME`: set to `tego:<id>` only if the **name** is absent from `base` (an empty-string value still
  counts as present).
- **R6** `NO_PROXY`/`no_proxy`: append `,127.0.0.1,localhost` iff `base` has **any** key matching `*_PROXY`
  case-insensitively (a suffix match, not an enumerated list — `SOCKS_PROXY`, `RSYNC_PROXY`, etc. all qualify,
  per RUN-IDENTITY.md's "only when a `*_PROXY` variable is passed in" and ARCHITECTURE.md §12's "when any
  `*_PROXY` variable is passed in"); both cases of `NO_PROXY` are touched only if already present, otherwise only
  lower-case `no_proxy` is added.
- **R7** Forwarder base-URL vars (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, `OPENAI_API_BASE`, `GOOGLE_GEMINI_BASE_URL`,
  `GOOGLE_VERTEX_BASE_URL`, `CODE_ASSIST_ENDPOINT`, `CODEX_HOME`; one list, `identity.ForwarderVarNames`, which the
  listeners and `Compile`'s `env-runtime-reserved` warning both read) set only when `Env.ForwarderVars` is non-nil (decided upstream by
  `capture: forwarder`, never by `identity`), each entry overwriting unconditionally.
- **R8** `DOCKER_HOST` set iff `DockerHost != ""`; `DOCKER_CONTEXT` is **removed** from `base` when it is (a stale
  context must not silently redirect the client).
- **R9** `CONTAINERS_CONF_OVERRIDE` set iff `ContainersConf != ""`; Ray vars set iff `RayHook`.

**Exit codes.**
- **R10** `reason=exit`: `ws.Exited()` → `ws.ExitStatus()` (`run_end reason=exit exit_code=n`); `ws.Signaled()` →
  `128+ws.Signal()` (`run_end reason=exit signal=n`) — RUN-IDENTITY.md's table has **both** rows under
  `reason=exit`, not two `EndReason` values. `reason=signal` (tego forwarded a caught signal — `run_end
  reason=signal signal=<n> escalated=<bool>`) uses the **same** `Exited()`/`Signaled()` logic on `ws`, never a
  fixed `128+<forwarded signal>` formula: "the exit code stays the agent's own" (ARCHITECTURE.md §6). 
- **R11** `reason=limit` → always `124` regardless of `ws` (the agent was `SIGKILL`ed via `cgroup.kill`, which
  alone reads `137`; `ExitCode` never inspects `ws` on this branch).
- **R12** `reason=stopped` → `143` when `!escalated`, `137` when `escalated`. `reason=oom`/`pids` → always `137`.
- **R13** `reason=exec-failed` → `126` (`xf=Denied`) or `127` (`xf=NotFound`); `xf` is ignored for every other
  reason.

**Machine config layering.**
- **R14** Four layers, fixed order, each checked (R20) as opened — a present-but-untrusted layer aborts
  immediately (125 `[config-untrusted]`, formerly 213 — see the 2026-09-22 resolution at the end) before any later
  layer is read, so a low-trust layer can never be masked by a later one.
  `$TEGO_CONFIG` is skipped entirely (not merely on error) when `secure`. A layer path that is not absolute (a
  relative `$TEGO_CONFIG`; a passwd home that is not absolute) is refused unread as an invalid layer
  (`config-invalid`: `run` exits 125, `compile`/`doctor` warn and skip it), as a relative path setting is: it names
  another file in every working directory, and R10 keeps a run's writes off only the one its own Load read (*amended
  2026-10-20*). So is an absolute layer path whose walk reaches procfs (`/proc/self/cwd/machine.yaml`,
  `/proc/thread-self/cwd/...`, a link to either, `/dev/fd/../cwd/...`): the kernel resolves it against the process
  that opens it, so it names `<cwd>/machine.yaml` in every directory too; and so is a path setting (`ledger_root`,
  `prices`, `profiles`, `registry`, `privileged_binary`) written that way, at its own line (*amended 2026-10-24*). A passwd home that reaches procfs refuses the user layer under it, so every `tego run` exits 125.
- **R15** Ceilings (`tier`, `capture`, every `limits.*`): `effective = min(inherited, layer's value)` (numeric min,
  or `Rank` min for `Tier`/`Capture`). A raise is not an error: `compile` prints `ceiling <key>=<value> kept from
  <file>:<line>` and the inherited `Value`+`Source` are kept unchanged (not rewritten to the attempting layer).
- **R16** Settings: last layer present wins outright, including its `Provenance`. One exception, a deny list:
  `denied_resolved_addresses` (the ranges no `net.allow` host name admits, agent-contract R18) is the union of every
  layer's entries, `Provenance` the last layer that added one, so the invoking user's own layer cannot lift what
  `/etc/tego/config.yaml` denied (added 2026-09-23). One floor, `landlock.audit` (`off` < `new-exec`,
  enforce-landlock §4): once a layer sets `new-exec` it holds, and a later layer's `off` is refused the way R15
  refuses a raise — `compile` prints `floor landlock.audit=new-exec kept from <file>:<line>` (code `ceiling-kept`)
  and the inherited `Value`+`Source` stand; a later `new-exec` moves the `Source` as an equal ceiling does (E11). At
  tier landlock the kernel's own refusals are in no ledger, so the audit is the administrator's only view of them,
  and an `off` in the invoking user's own layer that silently undid `/etc/tego/config.yaml`'s `new-exec` would
  take that view away without a trace (`TestLandlockAuditIsAFloor`; in the KVM guest on 6.17 a `sudo tego run`
  under an `/etc` `new-exec` and a user `off` printed the warning and its refused write was one `type=1423` record
  at tier `landlock` and at tier `cgroup`).
- **R16a** `/etc`-only settings: `record.ringbuf`, `bpf.ring_budget`, `bpf.plane`, `bpf.linger`,
  `privileged_binary` and `users` are honoured from `/etc/tego/config.yaml` only; another layer that sets one gets
  `<key> is honoured from /etc/tego/config.yaml only; ignored here` (`CodeIgnored`) and the value stays as the
  earlier layers left it (`merge.go` `etcOnly`). `users:` is tegod's authorization (ADR 0042 (4), (7)(f)): from the
  invoking user's own layer it would be a user granting itself runs. `privileged_binary` set in `/etc` stays stored
  and warns once, `privileged_binary is not used in this release; ADR 0042 (3)(c)` (ADR 0042 (3)(d)).
- **R17** `tier: auto` resolves via `internal/runtime/enforce.Select`: if `Machine.Tier` names a concrete tier
  (not `"auto"`), it is both ceiling and pin (R18); otherwise `Select` probes each `Tier` in descending `Rank`
  down to `TierLandlock` and picks the first the probe allows whose `Rank() <= ceiling.Rank()`. `TierObserve` is
  never a candidate — reached only via explicit `--observe`/CI, bypassing this algorithm.
- **R18** Pinned tier unavailable → `tego run` exits `ExitLauncher` (**125**), same as any other pre-exec failure
  (contract invalid, tier/capture unavailable, cgroup, ledger or program-load error): RUN-IDENTITY.md's 125 row
  has no carve-out for a named/pinned tier. Exit **211** is defined only for `doctor --require` (FEATURES.md E38b;
  R16/kill-test-6 — both scoped to `doctor`). 

**Trust and `AT_SECURE`.**
- **R19** Invoking uid = `SUDO_UID` iff `os.Getuid()==0` in the initial user namespace and `SUDO_UID` is set and
  parses as uint; else `os.Getuid()`. `SUDO_USER` (name-based) is never trusted. The initial user namespace is the
  one whose `/proc/self/uid_map` is the identity map `0 0 4294967295` (`config.InitialUserNamespace`); under
  `unshare -r` or in a rootless container the real uid is 0 and `SUDO_UID` is the caller's to set, so it is ignored.
  *2026-10-06:* `config.CurrentUserNamespace` answers initial, child (a map that was read and is not the identity
  map) or unknown (a map that cannot be read); here unknown counts as not the initial namespace, so `SUDO_UID` is
  ignored there too.
- **R19a** Every "uid 0" gate of the root tiers asks `config.InitNSRoot()` (effective uid 0 in the initial user
  namespace), never `os.Geteuid()==0` alone: doctor's reach and the derivation's `root:` line, `gc`'s and doctor's
  bpffs reads, the system cgroup root (`cgroup.Detect`) and `helpers.scope` (ADR 0042 (5)(d)). The credential drop
  still applies to any effective uid 0, whose target under `unshare -r` is refused (runtime-launch case 36).
  *2026-10-06:* an unknown namespace is not root for these gates (`InitNSRoot` is false), but ADR 0042 (3)(a)'s
  guard does not take it for a child namespace: it reads the capability sets there as in the initial one and
  refuses a privileged set, so a launcher with no `/proc` holding `cap_sys_admin` or `cap_bpf` is refused.
- **R20** Per present layer file (the four YAML layers only — E31/R24 draw the boundary against
  `PrivilegedBinary`'s own, different check): `open(O_RDONLY)` then `fstat` the fd (TOCTOU-safe — never a
  separate `stat`/`lstat`): must be `S_ISREG`, `uid∈{0,invokingUID}`, `mode&(S_IWGRP|S_IWOTH)==0`; then the same
  three checks on the containing **directory** — which must be the directory that *holds* that fd: the file is
  reopened relative to the directory's own descriptor and must be the same device/inode, so a trusted-looking
  directory renamed into place between naming the directory and opening it cannot stand in for it (E33).
  And the file has **one name** (*added 2026-10-20*, ADR 0059, agent-contract.md R10): `st_nlink > 1` is untrusted
  (`UntrustedError.Names` set, its `Fix` naming how to give it one), unless no run of the invoking user could write it
  by any name (`uid` neither `invokingUID` nor, when `invokingUID` is 0, anyone's; no group or other write bit): R10
  keeps every write entry off each layer's names, and a hard link's other name is compared with nothing. The same
  rule holds for every file `CheckTrusted` admits (the profiles, the registry's entries) and the price table
  (`ReadTrusted`), and `CheckOneName` applies it alone to a contract given by its path. A Load records the layers it
  consulted, in order, as `Machine.Layers`, which R10 protects, each by its absolute path as written (a relative one
  is refused, R14; *amended 2026-10-20*), never cleaned: a `..` after a link names the file the open
  read only as the kernel walks it. R10 protects the layers of the Load that compiled the run, and no other:
  a `$TEGO_CONFIG` file that a run started without that variable can write (its write entry reaches it) is the
  machine config of every later run started with it (ADR 0059's residual).
  Failure → `*UntrustedError`; `run` exits 125 `[config-untrusted]` (the 2026-09-22 resolution), `compile`/`doctor`
  warn and skip that layer entirely (never
  partially applied). `gc` aborts as `run` does (*amended 2026-11-02*, GAPS C52): it removes what the `retention`
  and `ledger_root` of the config select, and a layer it skipped may set either, so a layer it cannot read, trust or
  parse ends it with 125 `[config-untrusted]` before it sweeps or removes anything, whatever its `--keep`. Both call
  sites route through one shared internal helper (I11) — abort-vs-warn is an
  explicit parameter to it, never a second, drifted implementation.
- **R21** `secure` ⇒ `$TEGO_CONFIG` skipped (R14) and the per-user layer always resolves via `getpwuid`, never
  `$HOME` — and `$HOME` is in fact never read by `Load` under any circumstance, secure or not. The lookup is
  `config.LookupPasswd`, which every passwd home and group tego takes goes through (the per-user layer, the anchor's
  and the own log's homes, `realtego.Dirs`, the child's group, `adopt`'s owner home): in a `CGO_ENABLED=0` build it
  reads `/etc/passwd` itself, because `os/user`'s `LookupId` of the process's own uid answers `user.Current`, which,
  when `/etc/passwd` lacks the uid and `$USER` is set, makes up an entry from `$USER` and `$HOME` with no error; a libc
  build keeps `getpwuid_r` and NSS, which make up nothing. One home is not such a lookup: `agent.Compile`'s library
  default (`user.Current`), which the CLI leaves in place only when `Resolve` found no passwd home, is the home a
  contract's `~` paths and default chain anchor are compiled against, the same `$HOME` an unprivileged `run` then keeps
  its ledger root under (`internal/runtime.LedgerRoot`), or an error with `$USER` unset; it reads no config layer.

**Capability matrix.**
- **R22** `backend.Matrix(tier).Has(cap)` is ground truth, hand-generated to match CAPABILITIES.md cell-for-cell
  (a row a capability, three tiers, plus prose), verified by I9, never computed from a live probe — the probe decides *which
  tier runs*; the matrix then describes what that tier can do, unconditionally.
- **R23** `Set.Report()` never reorders; two runs' reports are index-comparable.
- **R24** `Machine.Tier`/`Machine.Capture` names are checked where they are written. `config` must not
  import `backend` (§1), so it keeps its own rank maps (`tierRank`: landlock, cgroup, bpflsm; `captureRank`: off,
  forwarder, uprobe): a `tier:` or `capture:` that is neither `auto` nor one of those names (e.g. `tier: quantum`)
  is an error diagnostic (`CodeInvalid`) at its file and line, and the layer is invalid like any other malformed
  layer — `run` aborts with it, `compile` and `doctor` warn and skip the layer. `observe` is a run mode, never a
  ceiling (R17), so `tier: observe` is refused too. `enforce.Select` still parses the name with
  `backend.ParseTier`/`ParseCapture`, and a failure there exits 125 (R18). A legal concrete pin the machine cannot
  provide is no config error; `doctor` names it (`ceiling_source`, and "tier: none: the machine config pins tier
  <t> at <file:line>, which this machine cannot provide") and its fix line edits the pin.
- **R25** `Capture` carries `Valid()`/`ParseCapture` symmetric to `Tier.Valid()`/`ParseTier` (§2.3) —
  required because §4's `AtOrBelow` precondition is "both `.Valid()`" for *both* types.
- **R26** `AskConfig.Timeout`/`AskConfig.Notify` and `Capability("ask")` are parsed, stored, and
  reported like any other field/row, but neither package enforces them: pausing a run, notifying
  a human and timing out an approval are the ask broker's (FEATURES.md E13/E50/E51).
- **R27** A binary built with `-tags tegotesthooks` never reaches the invoking user's own `~/.tego` for its chain
  anchor or its own log. Its anchor is the file `TEGO_TEST_CHAIN_ANCHOR` names; with the variable unset or empty it
  has none, and every command that needs one fails closed: `run` and `watch` exit 125 `[run]` ("chain anchor: this
  binary is built with tegotesthooks and TEGO_TEST_CHAIN_ANCHOR is not set ..."), before a run directory exists;
  `events --verify` exits 125 with the same words (never "verified"); a sweep falls back to the anchor beside the
  ledger root, as it does for an account without a home. Its own log is `<TEGO_TEST_OWN_LOG_HOME>/.tego/tego.log`;
  with the variable unset it keeps none (the log is best effort: a missing one costs a diagnostic, never a run). Both
  variables are ignored under `AT_SECURE`, which keeps the product's paths (R21): a test build given file capabilities
  is outside this rule, as it is outside every `TEGO_TEST_` variable's. A product build contains none of this.
  **The ledger root is held to the same rule.** The anchor fallback above is only safe beside a ledger root of the
  harness's own, so a test build refuses (when it loads the machine config, before any command reads or sweeps the
  ledger) a `ledger_root` inside the invoking user's `~/.tego`, the built-in `~/.tego/runs` included (the root of a
  harness that wrote no `ledger_root`), and a `TEGO_TEST_CHAIN_ANCHOR` or `TEGO_TEST_OWN_LOG_HOME` that names a path
  inside it. The refusal is exit 125 `[config-untrusted]` for `run` and an error exit for every other command, and it
  names the variable or setting at fault. It covers the sweep that `run`, `stop` and `gc` start (which ends and anchors
  every orphan of the ledger it is given, and which `run` makes before it refuses for a missing anchor) and the
  retention `gc` applies. "Inside" is by the passwd home of the effective uid and of `SUDO_UID` (R21) and, when one of
  them has no passwd home, by `$HOME`, where an unprivileged tego then keeps its ledger root, anchor and own log
  (`internal/realtego.Dirs`), after symbolic
  links are resolved and a relative variable made absolute from the working directory (the path the hook would use).
  The ledger root is the one the commands resolve (`internal/runtime.LedgerRoot`: a `~/` root, the built-in one
  included, against the passwd home, or against `$HOME` when there is none), and a `~/` root that resolves to no
  directory (no passwd home and no `$HOME`) is refused too, since nothing about it can be checked.
  Every harness gives a test build the isolation before its first command, `doctor` and `compile` included, since the
  refusal covers them: test/e2e/lib.sh writes a machine config of its own into the script's scratch directory when it
  is sourced (so `kt_tier_available` and kill test 6's `doctor` calls are answered, not refused), and the matrix row and
  the doctor-only row write one before each `doctor`. A harness that runs tego as root on the machine it was started
  from, not in a guest, runs the product build only where `TEGO_DISPOSABLE_HOST` says the machine is disposable, as
  `kt_require_testhooks` does: `test/vm/root-suites.sh` with `VM_HOST=sudo` runs its `tego doctor` from the test build
  of the same tags, with a machine config, anchor and own-log home of the run's own, unless that variable is set (CI's
  runners), since a product build ignores the two test variables and under `sudo` logs to `SUDO_UID`'s `~/.tego`.
  *Why:* HOME does not decide where tego looks (R21), and the product's anchor is the one place no setting
  redirects, so a harness that forgot the variable, or read its environment before setting it, appended to the
  developer's own `chain.log` without any test failing: on 2026-10-06 `internal/runtime`'s ask-read scenes took
  `os.Environ()` in the same statement that called `writeMachineConfig` (whose `t.Setenv` therefore reached
  nothing), and every run of those tests added lines whose ledgers were temporary directories.
  *Held by:* `internal/testutil.TegoEnv` (the one way a Go test builds that environment, after its `t.Setenv`s),
  `tools/isocheck` (precommit, `make lint`, CI: an `os.Environ()` taken before `writeMachineConfig`, a
  `TEGO_CONFIG` entry with no isolation, a build of `cmd/tego` without the tag, a command that runs the tego
  binary with the inherited environment (no `Env` of its own set on that command before it starts or before it
  goes on under another name, or `nil`, `os.Environ()` or an append to it naming neither `TEGO_CONFIG` nor the
  anchor, or an isolation undone by an `Env` set to one of those inside an if or a closure, a truncation or
  `os.Environ()` appended after it: GO-5), a script that assigns
  `TEGO_CONFIG` without the anchor and own-log variables, a script that builds `cmd/tego` without the tag or runs a
  tego binary without setting the variables (or calling `kt_config`, `lib_init`), a script that starts a run
  (`run`, `watch`, `adopt`, `agents`) without an `XDG_RUNTIME_DIR` of its own or with the inherited one (SH-7,
  clause b4), a script that runs the binary its caller names without checking that it is a test build, a pseudo-terminal or `-i` shell without
  `HISTFILE=/dev/null`; `test/vm` is exempt, its scripts run in the KVM guests, but for `root-suites.sh`, whose
  `VM_HOST=sudo` runs on the host, and whose doctor SH-5 sees as the `$0` of a `sh -c` script; isocheck asks only that
  the file set the variables, and `test/vm/root-suites_test.sh` checks which doctor that mode runs), `kt_require_testhooks`
  (test/e2e/lib.sh: a binary handed to a kill test or the overhead benchmark must be a test build unless
  `TEGO_DISPOSABLE_HOST` says the machine is disposable; the POC harnesses that take `TEGO_BIN` search the binary for
  `TEGO_TEST_CHAIN_ANCHOR`, the one name only a test build contains), the ledger-root refusal above
  (`internal/cli`'s `testIsolationError`, behind `machineGuard` in `loadMachine`), and the `-tags tegotesthooks` unit
  tests of `internal/cli`, `internal/platform/sys` and `internal/runtime/enforce/landlock`, which precommit and
  CI's build-test run (they compile only with the tag, so no other step does). **Every package whose tests can start
  a run, a sweep, a gc, a reaper or the tego binary fails its test binary when the invoking user's real `~/.tego` or
  `~/.bash_history` changed while it ran** (its `TestMain` exits with the code of `testutil.GuardedMain(m)` or
  `GuardedLeakCheckMain(m)`, which run the tests between `testutil.GuardRealTego`'s snapshot and its check and
  return non-zero on the check's error, in every build that compiles such a test): `internal/runtime` and
  `internal/cli` themselves, every package with a file (a test, or its own code, which a test can call, as a
  `main_test.go` can call a `main` that calls `cli.Main`) that imports either or a package of the module whose own
  code imports one, and every package with a file that builds `cmd/tego`, runs the tego binary (a command GO-5
  knows as one, which is every command of the CLI but `version`, whatever its environment; or one given its
  arguments as a list, `exec.Command(bin, args...)`, whose program is spelled as the binary or whose list is a
  literal starting with a subcommand), gives a tego subprocess `TEGO_CONFIG` or `TEGO_TEST_CHAIN_ANCHOR`, or
  calls `testutil.TegoEnv` or `writeMachineConfig`. `tools/isocheck` GO-4 holds the list, so a new such package
  cannot leave the guard out unless it runs the binary in a shape GO-4 cannot read (an argument list given to a
  program spelled otherwise, such as `argv[0]` of a list built elsewhere or a copy of the binary under another
  name), which the test build's refusal still answers. The guard watches
  `~/.tego`, its `runs/`, the entries of each run directory there (an `events.jsonl` appended to or chmodded in
  place; a run's `blobs/` is one entry, so a write inside it that keeps that directory's modification time is out of
  its reach) and `~/.bash_history` of the homes R21 names (the effective uid's and `SUDO_UID`'s, through passwd, and
  `$HOME` as the binary started when one of them has no passwd home: without it the guard watched nothing there), by
  name, mode, size and modification time, through a symbolic link too (what the link names and its target's state),
  and only reads them. Started as `go test` starts a test binary (with `-test.paniconexit0`, which `go test` always
  passes and a test's re-exec of its own binary as a helper does not), the helpers take the snapshot, run the tests
  in a re-executed child (the same executable, arguments and environment as the binary started with, its
  descriptors, and `TEGO_TESTUTIL_GUARD_PARENT` naming the parent, which the child honours only when it names its
  own parent running the same executable and removes before the tests run), forward SIGINT, SIGTERM, SIGHUP and
  SIGQUIT (`go test`'s signal to a binary that outlived its `-timeout`) to it, and check once it ended, however it
  ended: a test that wrote the history and then panicked, ran into `-test.timeout`, called `os.Exit` or was killed
  by a signal is reported with the guard's line, and the binary exits with the child's code (128 plus the signal's
  number for a signalled child). Any other start (a helper's re-exec, a binary run by hand or by
  `test/vm/root-suites.sh`, the variable set by mistake, a child that cannot be started) runs the tests in the
  binary's own process between the snapshot and the check, where a panic, the timeout alarm, an `os.Exit` or a fatal
  signal inside `m.Run` ends the binary before its check: that write is out of the guard's reach there. A write by a
  process the tests left running, made after the check (a subprocess a test started
  and never waited for, or one reparented when its parent exited), is out of its reach: the test build's refusal
  above is what keeps such a tego out.
  **Clause b4: no test reaches the developer's runtime parent either** (*Amended 2026-10-24*; not the
  rejected option (b4) below): a run keeps its
  CODEX_HOME and last-refusal mirror in `<XDG_RUNTIME_DIR>/tego/<run id>`, and every launch first removes the
  directories there whose launcher's lock is free (agent-contract.md R10a), so a test run that inherited the
  developer's `XDG_RUNTIME_DIR` made `/run/user/<uid>/tego` and swept the directories their crashed runs left, which
  they may still want to read. *Prevent:* every `TestMain` of a package whose tests start a run in-process
  or starts tego binaries that inherit its environment (`internal/runtime`, `internal/cli`, `test/conformance`) points
  `XDG_RUNTIME_DIR` at a 0700 directory under its own temporary parent before the tests run
  (`testutil.PrivateRuntimeDir`; as root it removes the variable, since a root launcher makes no directory), and
  `testutil.TegoEnv` gives a tego subprocess `XDG_RUNTIME_DIR=<OwnStateDir>/run` (made 0700) after the inherited
  environment and before `extra`, so a test can still name its own. The shell and Python harnesses that start runs
  do the same (*Amended 2026-10-24*): `kt_config` (test/e2e/lib.sh, so every kill test and
  sourcing lib.sh itself) and `lib_init` (test/poc/custom-agent) export `XDG_RUNTIME_DIR=<dir>/run`, made 0700, and
  `m0-demo.sh`, `overhead/run.sh`, the M2 attack fixture, the POC demos and drivers (their `env.sh` included) and
  `test/perf/cmd/perfsuite`'s runs name one of their own, where until then they ran under the inherited one: a
  kill test at tier landlock as the invoking user made `/run/user/<uid>/tego`, swept it, and, killed by `kt_run`'s
  watchdog, left its own directory for the developer's next launch to sweep (`kt1-identity.sh` and `m0-demo.sh`
  made `<XDG_RUNTIME_DIR>/tego` under a stand-in variable before, and nothing after). The test guard below is a Go
  test binary's and sees none of these scripts; `tools/isocheck` SH-7 is what holds them: a script that starts a
  run (`run`, `watch`, `adopt`, `agents`) assigns `XDG_RUNTIME_DIR` (a shell assignment, or a Python keyword
  argument, dict key or item assignment) or calls `kt_config` or `lib_init`, and never assigns it the inherited
  value (`$XDG_RUNTIME_DIR`, `os.environ`) or a path under `/run/user/`, directly or copied through other names
  (*Amended 2026-10-24*: a literal `/run/user/$(id -u)`, a copy `rt=$XDG_RUNTIME_DIR;
  XDG_RUNTIME_DIR=$rt` and a Python script that only named the variable in quotes had passed it). In Python a
  quoted name counts as giving one only beside a check that refuses `/run/user/<uid>`, as the watch demo's drivers
  require the caller's variable and refuse the login session's. SH-7 reads the text and does not evaluate it: a
  value it cannot see built (an `eval`, a file sourced other than the two helpers, a command's output) passes it,
  and the prevention in the helpers and the review of a new harness are what hold that case; `test/e2e/lib_test.sh`,
  `m0_demo_test.sh` and `overhead/run_test.sh` checking the value and mode the helpers and scripts give, and
  `TestTheHelpersGiveARuntimeDirectory` the two helpers' bodies. *Detect:* `GuardRealTego` also records the
  runtime parents `internal/realtego.RuntimeDirs` names: `/run/user/<uid>/tego` for the effective uid and `SUDO_UID`,
  and `<XDG_RUNTIME_DIR>/tego` (by its resolved path) for an absolute `XDG_RUNTIME_DIR` the process started with,
  read when `realtego` is initialized, so neither a `TestMain`'s own `XDG_RUNTIME_DIR` nor the re-executed child
  moves it. The check reports a parent made, removed or replaced (the snapshot holds an `O_PATH` descriptor of it, so
  a directory made in its place cannot take its inode number), any entry made there that no live run holds at the
  check, and an entry gone at the check that the sweep would have removed at the snapshot (a sweep's removal). The
  lock test is the sweep's own: the entry's `.lock`, a regular file opened without following a link, refuses an
  exclusive `flock` without waiting; a `.new-` entry, a launch's directory made and not yet locked, is never opened (an `flock`
  of it then would fail that launch's own) and counts as held, as the sweep never opens it. What the sweep removes
  is exactly what it tests (the check had counted every entry without a held lock as one): a name of a
  run id's shape, a directory not followed through a link, of the effective uid and writable by neither group nor
  others, whose lock takes the `flock`; an entry gone that is anything else (no run id's name, no lock file, a linked
  lock, a file, a link, a directory others can write) is no sweep's work and is not reported, so the developer
  removing one by hand fails nothing. For an entry made the check is stricter than the sweep on purpose: any entry
  made that is not held is reported, odd ones included, since no run of the developer's leaves one and a test that
  left one there reached the parent whatever it left. `internal/runtime`'s
  `TestTheGuardsSweepableEntriesAreWhatASweepRemoves` plants every shape and holds the set the guard counts as
  sweepable to the set a real `sweepRuntimeParent` removes. An entry whose lock is
  held is a live run, the developer's, and is never reported, nor is
  the parent's modification time, which their runs change. Two actions of the developer's own while the tests run
  are reported all the same, and the report blames the tests (*Amended 2026-10-24*): a run they launch
  sweeps one of their crashed runs' directories (reported removed, since a test's sweep and theirs remove the same
  set), and a run of theirs that starts during the tests and is killed before it removes its directory leaves it
  unheld (reported made). A run id carries its launch time (`time36`, R1), so comparing the reported ids' times with their own
  launches during the tests tells the two apart, and a rerun with no launch of theirs meanwhile settles it; the
  guard's message says both. The detection is narrow on purpose: a test run that used
  a parent that was already there, removed its own directory and found no crashed run's directory to sweep leaves
  nothing the check can tell from the developer's own runs, and the prevention above is what keeps it out. A test that needs `/run/user/<uid>/tego` refused as a write
  entry only names the path; it makes nothing there. *Rejected:* (rt1) comparing the whole runtime parent, entries
  and times, as the `~/.tego` guard does: it fails whenever the developer has a run going while the tests run, which
  is the normal case on a workstation; (rt2) a path refusal in the product binary (a test build refusing
  `/run/user/<uid>/tego`): a Layer 1 change for a hazard only tests have, and a test build must run where a user's
  runs do; (rt3) the guard alone, without the `TestMain` and `TegoEnv` change: it would report the leak but every
  package that starts a run would fail until each test set its own variable, where one line in each `TestMain`
  covers all of them; (rt4) re-reading `XDG_RUNTIME_DIR` when the guard runs: the `TestMain` has already pointed it
  at the tests' own directory by then, so the guard would watch that and never the developer's; (rt5) narrowing the
  clause to the Go test binaries and disclosing the shell harnesses as open: the kill tests would go on sweeping the
  developer's crashed runs' directories, where one exported variable in the helpers they already call ends it;
  (rt6) a snapshot and check in the shell harnesses themselves, like the Go guard: each script would carry its own
  copy of the sweep's lock test in shell, and the helpers' value is checked directly (lib_test.sh) at less cost;
  (rt7) SH-7 on every subcommand, as SH-5: only a launch makes the parent and sweeps it, and a doctor-only script
  (`test/vm/root-suites.sh`'s, `scripts/maze-verify.sh`'s compile) would carry a variable nothing reads; (rt8) the
  guard reporting only what the sweep would remove for an entry made too: a test's lock-less directory or file left
  in the developer's parent would pass.
  *Rejected:* (a) static checks alone, which cannot see
  an environment built in a helper or taken from the caller; (b) the static rules and the test build's refusal without a
  package-level guard, which this list once chose because a guard cannot tell this package's subprocess from any
  other tego the developer or another session runs meanwhile, and so on a shared machine can fail the wrong package:
  both can be missed, as `internal/runtime`'s 2026-10-16 exec-rule and stream-stall tests showed by appending to the
  real `chain.log` with nothing failing, so the outcome is checked as well, and the guard's message names the files,
  says that a tego or a shell run meanwhile changes them too, and says to rerun; (b2) watching every shell's
  history (`~/.zsh_history` and others): the harnesses start bash only (SH-2, SH-3), and a shell that appends its
  history at every prompt, as zsh's shared history does, would fail the gate on every command typed elsewhere while it
  ran; (b3) an environment variable that points the guard elsewhere or turns it off, which a harness could set by
  mistake and so weaken it; (b4) a hand-written `TestMain` check of `GuardRealTego`'s error that GO-4 analyses for
  every way it could exit 0 (each of a check after `os.Exit(m.Run())`, a `return`
  before it, a code reset after it, an exit nested in a dead branch), where one helper whose code the `TestMain`
  exits with is a shape a static rule can hold exactly; (b5) waiting at the check for, or refusing, the processes the
  tests left running: a reparented descendant is no longer the binary's to see, and a package whose helpers outlive
  a test on purpose would fail; (b6) a check from inside the tests' own process after a panic or the timeout
  alarm: `testing` re-panics a test's panic and panics its alarm in a goroutine of its own, so the process ends with
  no hook the guard could run in (`runtime/debug.SetCrashOutput` only writes the report to a file, for a monitoring
  process to read); (b7) running every start of a guarded binary in a child: the tests start their own binary as a
  helper (a lock holder, a reaper, a process placed in a cgroup, an agent under `tego run`) and read its pid, its
  descriptors, its execs and its cgroup, which an extra process and an extra exec in between would change, and an
  agent's environment need not carry a marker through `tego run`, so the child is used only where `go test`'s own
  argument says the binary is the one it started; (c) making the product refuse a `ledger_root` outside
  `~/.tego`, which contradicts the anchor's placement in the user's own home (P0-DESIGN §3.3), wherever `ledger_root` is, and
  would break the documented server setting; (d) an in-process override, which the launcher's `AT_SECURE` rule (R21) forbids
  the product; (e) skipping the sweep in a test build whose anchor is unset: `gc` would still apply retention to the
  developer's ledger, and `stop` and `status` would still read it; (f) a test that runs `run` or `gc` against the
  built-in root and asserts the real `~/.tego` unchanged, which would write it if the guard were ever lost (the
  integration test names a contract that does not exist and runs `gc --dry-run`, so that a lost refusal costs a read).

**Changes.**
- 2026-11-02, R20 (GAPS C52): `gc` reads the machine config with the abort mode, as `run` does. It read it warn-and-skip,
  so a layer it could not read was passed over with a warning and the pass deleted by the built-in 30 days and ledger
  root: an agent's `chmod 000 ~/.tego/config.yaml` had the daily `tego gc` delete the runs the user's `retention: 365d`
  kept (`TestGCDeletesNothingByAConfigItCannotRead`, `TestGCGivesTheLayerBackBeforeItReadsIt`, failing before).
- 2026-10-24, R27 clause b4: `tools/isocheck` SH-7 reports a launch handed the login
  session's directory by a literal path under `/run/user/` (`$(id -u)`, `$UID`, digits, a Python f-string) or the
  inherited value copied through other names, shell or Python, and counts a quoted Python mention as giving a
  directory only beside a check that refuses `/run/user/<uid>`; before, an assignment of a literal path, a copy and
  `if "XDG_RUNTIME_DIR" in env` each passed (`TestSH7ALaunchGetsARuntimeDirectoryOfItsOwn`'s new cases, failing
  before). The clause now names SH-7's limit (it does not evaluate a script) and the guard's two reports a
  developer's own launch or killed run causes during the tests, which its message also names. No script in the tree
  changed: none used these shapes.
- 2026-10-24, R27 clause b4: the shell and Python harnesses that start runs give tego a
  runtime directory of their own too. `kt_config` and `lib_init` export `XDG_RUNTIME_DIR=<dir>/run` (0700);
  `m0-demo.sh`, `overhead/run.sh`, `test/fixtures/m2-env-attacks/attacks.sh`, the POC demos' `env.sh`, the
  interactive Claude Code driver (which handed tego the caller's variable), the interactive Codex driver's
  unbounded recording (which did so on purpose, so that `learn` saw the caller's sockets) and perfsuite's runs name
  one of their own. Before, `kt1-identity.sh` and `m0-demo.sh` under a stand-in `XDG_RUNTIME_DIR` with no `tego` in
  it made `<XDG_RUNTIME_DIR>/tego`; after, they make nothing there. `tools/isocheck` SH-7 holds every script that
  starts a run to it (`TestSH7ALaunchGetsARuntimeDirectoryOfItsOwn`, failing before;
  `TestTheHelpersGiveARuntimeDirectory`; lib_test.sh, m0_demo_test.sh and overhead/run_test.sh check value and mode,
  failing before). The guard's report of an entry gone is now exactly the sweep's predicate (a run id's private
  directory with a free regular lock), where it had counted every entry without a held lock, a file and a
  lock-less directory included (`TestGuardRuntimeReportsWhatATestRunLeaves`'s per-shape cases and
  `TestTheGuardsSweepableEntriesAreWhatASweepRemoves`, both failing before); its report of an entry made stays
  stricter than the sweep, on purpose.
- 2026-10-24, R27 clause b4 (ADR 0029 amended): no test reaches the developer's runtime parent. A
  reproduction with the extended guard and no prevention (`go test ./internal/runtime/... ./internal/cli/...
  ./internal/testutil/... ./tools/isocheck/... ./test/...`, unit and `-tags integration`, under a scratch
  `XDG_RUNTIME_DIR` with no `tego` in it) made `<XDG_RUNTIME_DIR>/tego`: 11 in-process launches of
  `internal/runtime`'s unit tests (the unwind tests, `TestRunIsListedWhileItHoldsItsLock`,
  `TestRunWritesTheContractsLimitsToTheCgroup`), and with `integration` 257, by `runtime.test` and by the tego
  binaries `internal/runtime`'s and `test/conformance`'s integration tests start; with a crashed run's directory
  planted there (and planted again each time it went), one run of `internal/runtime`'s unit tests swept it four
  times. `internal/runtime/capture/forwarder` failed the same
  guard only because it shares the parent with `internal/runtime` under `go test -p 2`; it starts no run. Every
  `TestMain` of a package that starts a run, and `testutil.TegoEnv`, now give the run a private `XDG_RUNTIME_DIR`,
  and `GuardRealTego` watches `/run/user/<uid>/tego` and the starting `XDG_RUNTIME_DIR`'s
  (`TestGuardRuntimeReportsWhatATestRunLeaves`, `TestGuardedRunFailsTheBinaryOnALeakedRuntimeDir`,
  `TestRuntimeDirs`, `TestTegoEnvGivesTheRunAPrivateRuntimeDir`, `TestTheTestGuardNamesTheRuntimeParentsAsARunDoes`).
- 2026-10-24, R14 (ADR 0059): a layer path or a path setting whose walk reaches procfs
  is refused, as a relative one is. `TEGO_CONFIG=/proc/self/cwd/machine.yaml` is absolute, so the relative-path refusal let
  it through, but the kernel resolves it against each opener's working directory: a run in project A with
  `fs.write` over project B wrote `B/machine.yaml`, and `tego run x` started in B ran the contract its planted
  `registry:` chose. `config.LoadSources` now refuses such a layer unread (`config-invalid`), and `parser.path`
  refuses such a setting at its line, with the walk compile already used for exec entries (R8a), moved to
  `config.ThroughProc` so the Load and the compiler share it (`TestLoadSourcesRefusesALayerThroughProcfs` and
  `TestPathSettingsValidated`, failing before; `TestThroughProc` moved with the walk). Scripts that export
  `$TEGO_CONFIG` make their work directory absolute first (`test/e2e/m0-demo.sh`, `lib.sh`, `overhead/run.sh`,
  `test/vm/doctor-refusal.sh`, `tier2-pairs.sh`, `test/e2e/m0_demo_test.sh`).
- 2026-10-20, R14, R20 (ADR 0059): a layer path that is not absolute is refused unread
  (`config-invalid`), as a relative path setting is; an earlier change made a relative `$TEGO_CONFIG` absolute against the
  loading command's working directory, so `TEGO_CONFIG=machine.yaml` named `<cwd>/machine.yaml` in every directory
  and R10 compared a run's write entries with its own directory's file only: a run in project A with a write entry
  over project B wrote `B/machine.yaml` (with a `registry:` of its own), and the next `tego run <name>` started in B
  ran the contract it planted. The join that made a relative layer absolute is gone
  (`TestLoadSourcesRefusesARelativeLayer`, which replaces the test that named a relative layer by its absolute path).
- 2026-10-20, R20 (ADR 0059): `Machine.Layers` keeps each layer's path as the Load opened
  it, made absolute by joining it to the working directory and never cleaned. That change used `filepath.Abs`,
  which cleans: `TEGO_CONFIG=<dir>/mlink/../machine.yaml` (read beside `mlink`'s target) became `<dir>/machine.yaml`,
  and a run whose write entry held the file read compiled and appended to the machine config of every later run
  (`TestLoadSourcesRefusesARelativeLayer`, `TestALayerWithDotDotAfterALinkIsTheFileTheLoadRead`).
- 2026-10-20, R20 (ADR 0059): `Machine.Layers` names each layer by its absolute path. A
  relative `$TEGO_CONFIG` was recorded as given, and R10 walks only an absolute path for the links on the way, so a
  run whose write entry held the directory of a link on a relative layer's path could repoint it
  (`TestLoadSourcesRefusesARelativeLayer`).
- 2026-10-20, R20 (ADR 0059): a trusted file has one name. A layer, the price table, a
  profile or a registry entry with a second hard link was trusted, and a run whose write entry held the other name
  (which R10 never compares) could rewrite what every later run loads; now it is `*UntrustedError` with `Names` set,
  unless no run of the invoking user could write it. `Machine.Layers` names the layer places a Load consulted, there or not, for R10
  (`TestATrustedFileHasOneName`, `TestManyNamesReasonSparesAFileNoRunCouldWrite`,
  `TestLoadSourcesNamesEveryLayerPlace`).
- 2026-10-17, R27, §10: the guard checked only when `m.Run` returned, so a test that wrote
  the real `~/.tego` or `~/.bash_history` and then panicked, or ran into `-test.timeout`, ended the binary with exit 2
  and no word of the write, and a rerun after the panic was fixed went green with the write in place (a scratch
  test reproduced both). Started as `go test` starts it, a guarded binary now runs its tests in a re-executed child
  and checks once the child ended, however it ended, forwarding the signals `go test` and a terminal send; any other
  start keeps the in-process check, and R27 and the godoc name what is out of its reach there (rejected options b6
  and b7). `TestGuardedMainsFailTheBinary` holds a panic, the timeout, a kill, a forwarded SIGQUIT and the marker
  set by mistake, `TestStartedByGoTestReadsGoTestsArguments` the argument it reads, and
  `TestGuardChildDirIsNeverARealHome` each of the re-executed test's refusals on its own (a directory outside the
  temporary directory, a real home's `.tego` or history), two of which no test held.
- 2026-10-17, R21, R27, E9, §10: on an account with no passwd home a test build accepted the
  built-in `~/.tego/runs` and a declared `~/` ledger root, because `testIsolationError` expanded `~/` only against a
  passwd home and so checked a relative path, while the commands resolved it against `$HOME`, into the
  `$HOME/.tego` a later change made real: `gc`, `gc --dry-run`, `doctor` and `run` were not refused there. It now resolves
  the root through `internal/runtime.LedgerRoot`, as the commands do, and refuses a `~/` root that resolves nowhere.
  R21's "never `$HOME`" did not hold in a `CGO_ENABLED=0` build for the process's own uid when `/etc/passwd` lacks it
  and `$USER` is set: `os/user` made up the entry from `$USER` and `$HOME`, so `Resolve` read
  `$HOME/.tego/config.yaml` as the per-user layer and E9's warning was not given. Every passwd home and group lookup
  of `pkg/spec/config`, `internal/runtime`, `internal/cli` and `internal/realtego` now goes through
  `config.LookupPasswd`, which reads `/etc/passwd` itself in such a build, so E9 holds whatever `$USER` says (no
  AT_SECURE launcher reached this: a setcap or setuid copy exits 125, ADR 0042 O4). `agent.Compile`'s default home
  (`user.Current`) is unchanged and now named in R21 as the one home that is not such a lookup.
  `internal/testutil`'s re-executed child (`TEGO_TESTUTIL_GUARD_CHILD`) truncated the history of whatever directory
  the variable named, the developer's home included, before the guard reported it; it now acts only in a directory
  inside the temporary directory that holds the parent's marker and is no real home, and only makes the history
  (`O_EXCL`), so the variable set by mistake fails the package and changes no file (R27 b3).
- 2026-10-17, R27, §10: on an account the passwd database names no home for (a
  containerized uid, or an LDAP/SSSD one that a `CGO_ENABLED=0` build cannot look up), the guard watched nothing and
  the test build refused nothing, while an unprivileged tego kept its ledger root, anchor and own log under `$HOME`:
  `internal/realtego.Dirs` now also names `$HOME/.tego` there (the guard reads `$HOME` before the tests run), which
  can only watch and refuse more: a test build run as such an account whose own-log home is the `$HOME` it is given,
  or whose ledger root or anchor is inside that `$HOME/.tego`, is refused, as it cannot tell a harness's `$HOME`
  from the developer's (the KVM
  guests give the sudo user a passwd entry, so the cross-owner tests that run as it are unaffected). GO-4 also counts a package whose own code imports `internal/cli` or
  `internal/runtime`, or a package of the module that does, directly or through others, when it has tests (a
  `main_test.go` calling a `main` that calls `cli.Main` passed it), and a run of the binary given its arguments as a
  list (`exec.Command(bin, args...)`, the tree's most common shape), whose limit R27 names. GO-4, GO-5 and SH-5 know
  every command the CLI registers but `version` (they missed `agents --adopt`, which starts ledgered runs,
  `alternate`, `dns` and `init`), and `TestTheSubcommandsAreTheCLIsCommands` fails when a new command is neither
  known nor listed with why it cannot reach a ledger, an anchor or the own log; `internal/runtime`'s DNS lifecycle
  test gives its `tego dns` the run's isolation. `GuardedLeakCheckMain` runs `GuardedMain`, so
  `internal/testutil`'s own `TestMain` exercises both helpers: `TestGuardedMainsFailTheBinary` re-executes the binary
  with a test that writes a watched history and fails if either helper stops running the guard. (The refusal half
  held only for an absolute ledger root as committed that day; the entry above extends it to the built-in and
  a `~/` root.)
- 2026-10-17, R27, §10: GO-4 no longer analyses a hand-written check of
  `testutil.GuardRealTego`'s error, which passed a `TestMain` whose check came after `os.Exit(m.Run())`, after a
  `return`, before a reset of the code, or behind a nested condition, each exiting 0 whatever the tests wrote: every
  guarded package's `TestMain` exits with the code of `testutil.GuardedMain(m)` or `GuardedLeakCheckMain(m)`, held at
  most in a name that the first exit after it takes, and GO-4 holds that shape and no other (rejected option b4). The
  guard sees a `~/.bash_history` that is a symbolic link written through (it recorded only the link's own state), and
  R27 and its godoc name the write of a process left running after the check as out of its reach (rejected option
  b5). GO-5 sees the command go on under another name (`c2 := cmd`) before its `Env` is set, an `Env` reverted to the
  inherited one inside an if or a closure, a truncated `Env` and `os.Environ()` appended after the isolation. GO-4
  also counts a package with a file that runs the tego binary (`exec.Command(bin, "run", ...)`) as one that must be
  guarded, whatever environment the command gets: one GO-5 accepts can still name no isolation (`cmd.Env =
  []string{"PATH=/bin"}`), and a product binary started so writes the real `~/.tego`.
- 2026-10-17, R27, §10: the root tests that ask a test build's `doctor --require`
  whether this machine offers a tier skip only on doctor's answer that it does not (exit 211, or 1 when no tier can
  run at all), and fail on any other end of that command (`internal/testutil` `RequireTier`, `DoctorOffers`). They
  skipped on any failure, so this refusal (exit 125, the invoking user's own `~/.tego` as ledger root) once hid some
  forty tier-2 end-to-end tests as "this machine offers no tier cgroup", caught only by root-suites' skip gate; the
  restricted-root test's `--require bpflsm` read the same refusal as "no tier bpflsm". *Rejected:* leaving it to the
  skip gate alone, which allows a listed skip on a row whose kernel lacks the tier, where the next harness fault would
  pass for that kernel. On 2026-10-17 the rule also covers the two root tests that came
  from the other side and still skipped on any failure: `TestIOUringSocketsMeetTheKernelBackstops` in
  `internal/runtime/enforce/cgroup` and
  `TestIntegrationHeldCompletionAtRootTier` (its cgroup probe and its bpflsm subtest's) in `internal/runtime`.
- 2026-10-16, R27, §10: `tools/isocheck` GO-4 counts a `TestMain` as the guard only when
  it takes the check before the tests run and, after them, in its own top-level statements, tests the check's error in
  an if that exits non-zero (a non-zero `os.Exit`, a panic, or a non-zero code a later `os.Exit` takes): a check made
  before `m.Run`, held in a deferred closure that `os.Exit` skips, or whose error was only printed passed it. GO-5
  follows each tego command's own `Env` from the statement that makes it to the one that starts it, in that block: a
  command whose name a later, isolated command reused, an `Env` set after the start or inside an if, an `Env` of `nil`
  and `os.Environ()` appended to through `cmd.Env` passed it. Every `TestMain` and tego command of the tree already
  had the shapes now required.
- 2026-10-16, R27, §10: `internal/runtime/enforce/cgroup`'s and `internal/doctor`'s
  root tests give every `doctor` call (`doctor --require cgroup` and the plane pin's `doctor --json`) a machine config
  of its own and `testutil.TegoEnv` (each package's `isolatedTego`): on the test build the sudo caller's built-in
  `~/.tego/runs` was refused, and about 18 root tests, `TestTier2ArmsAfterTheStageExec` (root-must-pass) among them,
  skipped as "no tier cgroup" on both KVM boots. `tools/isocheck` GO-5 fails a command that runs the tego binary
  with the inherited environment, and GO-4 no longer counts a `TestMain` that takes the guard's check and drops its
  error. The guard also watches the entries of each run directory (an `events.jsonl` appended to in place passed it).
- 2026-10-16, R27, §10: every package whose tests can start a run, a sweep, a gc, a reaper or the tego
  binary fails its test binary when the real `~/.tego` or `~/.bash_history` changed (`testutil.GuardRealTego`, which
  now watches `~/.bash_history` too, in the `TestMain` of `examples/agents`, `internal/doctor`, `internal/testutil`,
  `internal/runtime/capture`, `capture/forwarder`, `capture/uprobe`, `internal/runtime/observe`,
  `internal/runtime/enforce/cgroup`, `test/conformance` and `test/perf/cmd/perfsuite`, besides `internal/runtime`,
  `internal/cli` and `test/fixtures`), and `tools/isocheck` GO-4 fails a package that leaves it out. Rejected (b) is
  reversed: `internal/runtime`'s exec-rule and stream-stall integration tests ran `tego run` with `TEGO_CONFIG` only
  and appended to the developer's `chain.log` with no test failing.
- 2026-10-16, R27, §10: `tools/isocheck` saw `root-suites.sh` run tego only through an
  echo's text (`== tego-doctor (tego doctor as root on this host)`, where the `(` reads as a command start): the
  script runs its doctor as the `$0` of `/bin/sh -c "$doctor_script" "$doctor_bin"`, which SH-5 did not follow, so the
  script with those echoes reworded and no isolation passed. SH-5 now follows the binary into a shell's `-c` script:
  a word after the script that names the binary is the script's `$0`, `$1` ..., and the script (its quotes' inside, or
  the value the file assigns the variable it names) running that positional with a subcommand is a run of tego
  (`sh -c '"$0" doctor' "$tego"`, `sh -c '"$1" run x' sh "$bin"`). Like every SH rule it asks only that the file set
  the two variables somewhere; that `VM_HOST=sudo` runs the test build with them is `test/vm/root-suites_test.sh`'s
  check. *Rejected:* parsing quoting so that prose in an echo is never a run (a shell parser this heuristic does not
  attempt; the over-report errs toward a finding, and the tests of the shapes that must be reported no longer rest on
  it); naming only `root-suites_test.sh` as the guard, which would leave the next host-mode `sh -c` run unseen.
- 2026-10-16, R27, §10: `tools/isocheck` also knows a quoted subcommand
  (`"$tego" "run"`), a quoted last path segment (`"$bindir"/"tego"`, `"$W/"'tego'`), `nice`, `ionice`, `chrt`,
  `taskset`, `unshare`, `stdbuf`, `doas`, `systemd-run` and `eval` before the binary, an escaped quote around it in a
  string a shell or `eval` runs (`bash -c "\"$tego\" run"`), and a function whose body runs the binary with its own
  arguments (`ey() { "$tego" "$@"; }; ey run x`: the function is then the binary where it is called). No tracked
  script used one of them. *Rejected:* treating every function that forwards `"$@"` as the binary (`g() { git "$@"; }`
  is another program); reading a function's body past its first line that starts with `}` (a nested block would need
  a shell parser, which this heuristic does not attempt).
- 2026-10-16, R27, §10: `tools/isocheck` knows the spellings of the binary it had
  missed: a quoted segment or a command substitution in the path before `/tego` (`"$W"/tego`,
  `"$(go env GOPATH)/bin/tego"`), a quoted option word after `sudo` or `env` (`sudo -u "$SUDO_USER"`), `setpriv` and
  `runuser`, the harnesses' wrappers `kt_run` and `as_user` and any function the script itself defines (where a
  command starts), and options between the binary and its subcommand (`"$tego" --tier landlock run`). No tracked
  script used one of them. *Rejected:* any word before the binary as a wrapper (`say "$tego" run`, prose in an
  `echo`, would then count as a run).
- 2026-10-16, R27, §10: the `test/vm` exemption said its scripts run only in guests, but
  `root-suites.sh` with `VM_HOST=sudo` ran the product `tego doctor` as root on the host with no isolation (under
  `sudo` its own log is `SUDO_UID`'s `~/.tego/tego.log`). It now runs the test build with a machine config, anchor
  and own-log home in `VM_OUT/doctor-iso` unless `TEGO_DISPOSABLE_HOST` is set (CI's runners, where `GITHUB_ACTIONS`
  sets it, keep the product build), and `tools/isocheck` reads `root-suites.sh`. *Rejected:* (a) rewording the
  exemption to say `VM_HOST=sudo` is for disposable runners only, which leaves a documented developer use writing their
  `~/.tego`; (b) the product build with only `TEGO_CONFIG`, whose own log under `sudo` still goes to the developer's
  home; (c) the test build on CI too, which would stop CI's root job checking the binary a root user installs.
- 2026-10-16, R27, §10: the kill tests' `doctor --require` ran on the test build before `kt_config`
  and the ledger-root refusal skipped every one of them (exit 77), and failed kill test 6 and the matrix's doctor
  checks: sourcing `test/e2e/lib.sh` now isolates, and `test/vm/run-matrix-row.sh` and `doctor-refusal.sh` write a
  machine config before each `doctor` instead of unsetting `TEGO_CONFIG`; a relative `TEGO_TEST_CHAIN_ANCHOR` or
  `TEGO_TEST_OWN_LOG_HOME` is resolved from the working directory before the refusal compares it; `tools/isocheck`
  joins backslash-continued lines and knows more spellings of the binary (a path ending in `tego`, `$E`, `$tego_bin`,
  after `then`, `do`, `setsid`, `script`, a shell's `-c`, and a Python argv built from a call or a subscript).
  *Rejected:* any `$var` as the command word (`"${GO:-go}" run` and `"$gh" run` are in the repository's scripts).
- 2026-10-16, R27, §10: a test build also refuses a ledger root, chain anchor or own-log home inside
  the invoking user's `~/.tego` (a test build with no `TEGO_CONFIG` swept the real `~/.tego/runs` and could anchor
  in the real `chain.log`); `tools/isocheck` covers scripts that build or run tego without assigning `TEGO_CONFIG`
  (SH-4 to SH-6); the tagged unit tests run in precommit and CI.
- 2026-10-16, R27, §10: a test build fails closed on its chain anchor and its own log instead of falling back to
  the invoking user's `~/.tego`; `internal/runtime`'s ask-read scenes took `os.Environ()` before `t.Setenv` and
  appended their runs to the developer's `chain.log`.
- 2026-10-06, R19, R19a, §2.4 (ADR 0042 (3)(a)): the user namespace has three answers, initial, child and unknown
  (`config.CurrentUserNamespace`); the (3)(a) guard took an unreadable uid map for a child namespace and skipped
  the capability sets, so a non-root launcher with no `/proc` kept an inherited privileged set.
- 2026-10-06, §2.4 and §4 `DetectSecureExec`: the signature comment and the contract say the runtime's copy of the
  vector is read first, as §3's row does; they still named only `/proc/self/auxv`.
- 2026-10-05, R16a (ADR 0042 (3)(d), (4)): `users:` is honoured from `/etc/tego/config.yaml` only (it merged
  last-layer-wins from every layer, so a user's own layer could set it), and `privileged_binary` in `/etc` warns
  that it is unused; the rule names every `/etc`-only key in one place.
- 2026-10-05, §3 `/proc/self/auxv`: `DetectSecureExec` reads the runtime's copy of the vector; the file refuses a
  non-dumpable process, which every `AT_SECURE` exec makes.
- 2026-10-05, R19, R19a (ADR 0042 (5)(d)): `SUDO_UID` is read only by uid 0 of the initial user namespace, and the
  root-tier gates ask `config.InitNSRoot`; under `unshare -r` with `SUDO_UID` set a run was treated as a sudo run
  of that uid and doctor probed tier 2 and 3 as root.
- 2026-11-01, R3a: new. `sudo tego run` gave the agent, running as the invoking user, `HOME=/root` and `USER=root`.
- 2026-09-29, R3: `env.set` applies in name order and replaces every duplicate of a name, not only the first.
- 2026-09-23, R16 (fail-open fix): `landlock.audit` became a floor; it first merged last-layer-wins.
- 2026-09-24, R20 (2026-09-22 resolution): an untrusted layer under `run` exits 125, formerly 213.
- 2026-10-05, E13: a missing `$TEGO_CONFIG` file is refused (run) or warned (compile/doctor), no longer skipped silently.
- 2026-09-30, §2.2 snippet, E13, I7: still said 213; now 125 `[config-untrusted]` (`ExitConfig = ExitLauncher`), matching the code.
- 2026-09-24, R24: tier/capture names are checked in `config.Load` at their file:line;
  they surfaced only downstream (`compile` printed `tier bogus`, `doctor` named no file, a bad capture name ran
  with capture off), and `doctor` names an unprovidable pin.
- 2026-09-24, R2b: `mintRun` minted one id and failed on the first `EEXIST`; it now retries 3×.
- 2026-09-29, `config.Load`: a second YAML document, and hex, `1_0` or underflowing
  `cost_usd`/`cpu`, are refused; the second document was dropped and `1e-400` read as a 0 ceiling.
- 2026-09-30, `limits.pids` is bounded at 4194304 in the machine config and the contract schema (E20): the kernel refuses more, so every run would have failed at startup.
- 2026-09-29, `config.Load`: `ledger_root`, `prices`, `profiles` and `privileged_binary` must be absolute or `~/...` (null, `~`, relative, `~user/x` and an empty `ledger_root` are refused at parse, not by every run); with no passwd home `prices`/`profiles` are dropped (E9); `cost_usd: -0` is refused (E20).
- 2026-10-16, R22 (§2.3): 26 rows. The snippet still listed 18; the two destination-admission rows and
  `exec.command_argv` (ADR 0048) had been appended since, and ADR 0041 D7 appends five: the gate's fs open, fs
  mutation, exec and net completion rows and `fs.protected_write_targets`.
- 2026-09-28, R22 (§2.3): 18 rows, not 16 (`net.unix_abstract_scope`, then `fs.deny_chmod`); `Matrix` is a func.
- 2026-09-29, R7: the list names the OpenAI variables and is `identity.ForwarderVarNames`;
  `Compile` reserved only the Anthropic and OpenAI names, so a passed Google variable or `CODEX_HOME` was overridden unwarned.
- 2026-10-20, `config.Load`: a `registry` path setting (default `~/.config/tego`, outside the
  `~/.tego` every run read-denies; `""` for none) names the user registry
  `tego run <name>` and `tego compile <name>` resolve a name in after the working directory's project registry
  (agent-contract.md R26). It follows `profiles`: absolute or `~/...`, and dropped with a warning when the passwd
  database names no home.

## 6. Edge cases

1. **E1** `rnd` read fails (sandboxed CI entropy issue): `NewRunID` returns the wrapped error; caller aborts 125, never mints a short/zero-padded id.
2. **E2** Clock steps backward (NTP) between two `NewRunID` calls: ids stay unique, not required to sort by time.
3. **E3** Two hosts share `/etc/machine-id` (cloned image): `host8` collides; `rand6` still de-risks it — a `doctor` check candidate (Q1), not solved here.
4. **E4** Caller passes zero `[32]byte` `hostID` instead of erroring: `NewRunID` does not special-case it — a caller bug, not identity's to detect (I8).
5. **E5** Contract's `env.pass` names `TEGO_RUN_ID`: compiles fine, discarded at `Apply`, no warning (Q2).
6. **E6** `base` entry has no `=` (should be impossible from a trusted producer): left untouched, never panics.
7. **E7** `OTEL_RESOURCE_ATTRIBUTES` already ends in a trailing comma: R4's append yields a double comma; not normalized (identity must not guess intent).
8. **E8** Corrupted `SUDO_UID` (non-numeric): treated as unset, falls back to `os.Getuid()` (root, under `sudo`) — never a *different* wrong uid.
9. **E9** `getpwuid(invokingUID)` fails (containerized uid, no passwd entry): per-user layer treated as absent (warning), not untrusted. `prices` and `profiles` still written `~/...` are left empty with a `[config-ignored]` warning, never read relative to the cwd; `ledger_root` keeps its `~/` for the run to refuse.
10. **E10** `/etc/tego/config.yaml` is a symlink outside `/etc`: R20 checks the **target's** owner/mode and directory, never `/etc`'s own — a lax bind-mount silently weakens the boundary an operator thinks they set.
11. **E11** Two layers set an equal (not raised) ceiling: no warning; `Provenance` still updates to the later layer.
12. **E12** `limits.memory: 0` (explicit): valid, lowers the ceiling to zero so `agent.Compile` refuses every positive request; `Load` does not special-case zero.
13. **E13** `$TEGO_CONFIG` names a directory: `S_ISREG` fails it as untrusted (exit 125 [config-untrusted]), not silently skipped, since the operator explicitly named it. A `$TEGO_CONFIG` path that does not exist is refused the same way under `run` (125 [config-untrusted], `config: invalid layer: $TEGO_CONFIG names <path>: file does not exist`), and is a warning (layer skipped) under `compile`/`doctor`; only the `/etc` and per-user layers are optional when absent.
14. **E14** `version` absent from a layer: treated as `0`.
15. **E15** `version: 1` (or non-zero) in any layer: hard `Load` error — P0 defines only `version: 0`.
16. **E16** `ringbuf` not a power-of-two page multiple, or above 2 GiB (the launcher's ring-map limit, `config.RingbufMax`): `Diagnostic` error, never silently rounded (would make `run_start`'s recorded size lie).
17. **E17** `stop_grace: 0s`: valid "fast-kill" mode, accepted with an advisory warning, not rejected.
18. **E18** Config edited on disk mid-flight: each run keeps the `*Machine` from its own `Load()` call for its whole lifetime — no cache, no file-watch (I3); concurrent runs may legitimately see different ceilings.
19. **E19** `AT_SECURE` true with no `SUDO_UID` (direct file-capability invocation, not via `sudo`): `InvokingUID` still returns the real unprivileged `os.Getuid()` — the two checks are independent.
20. **E20** Negative `Limits` value (e.g. `pids: -1`): rejected at parse, `-0` included; P0 has no negative-value sentinel (unlike cgroupfs's `"max"`; Q3). `limits.pids` above 4194304 (PID_MAX_LIMIT, the kernel's pids.max range) is refused at parse, in the machine config and the contract alike.
21. **E21** Unicode/RTL bytes in `$TEGO_CONFIG`'s path: opaque byte string, no normalization, matching kernel path semantics.
22. **E22** Pathological 10 000-entry `env.pass` reaching `Apply`'s `base`: O(len(base)) per identity variable (a constant few), no quadratic blowup.
23. **E23** Caller passes `reason=exit` with a `ws` that is neither `Exited()` nor `Signaled()` (a contract violation `ExitCode` cannot detect): result is an implementation-defined but in-range code; I8 requires the caller to check `Exited()`/`Signaled()` before calling.
24. **E24** Two goroutines race `NewRunID` within the same clock tick: `rand6`'s 4 random bytes still differentiate with overwhelming probability; no locking inside `identity` (run creation is already single-threaded per `internal/runtime.Run`).
25. **E25** Binary upgraded mid-run (rename swap): the running process keeps its own in-memory `*Machine` and constants (baked into its own text segment) — no cross-version concern here.
26. **E26** Layer path is a FIFO: `S_ISREG` refuses it as untrusted, **but** the initial existence/type probe must use `O_NONBLOCK` (re-opened blocking only after `S_ISREG` is confirmed) or a FIFO with no writer hangs `tego run` forever — mandated by I8.
27. **E27** Multi-GB machine config file (misdirected redirect): a layer larger than `MaxLayerSize` (16 MiB, `pkg/spec/config/trust.go`) is refused, checked on the file's stat and again on the bytes read (a file that grows), with `errTooLarge` as an untrusted layer (R20). The normative docs state no cap; the number is this package's, flagged as Q4.
28. **E28** `resolver: auto` with a dangling `/etc/resolv.conf` symlink at early boot: resolved by the **caller** at run start (`Load` never reads `resolv.conf`), with a warning and an empty resolver set.
29. **E29** `base` reaching `Env.Apply` already contains a stale `tego.run=`/`tego.agent=` member inside `OTEL_RESOURCE_ATTRIBUTES` (a nested/re-invoked run, or a harness that copies parent env into a child's `env.set`): R4 as specified always **appends** a fresh pair rather than deduping — no normative doc addresses replace-vs-append, so this is a documented gap, not invented behavior; OTEL SDKs' merge semantics for duplicate keys differ, so a downstream consumer should not assume the first or last pair wins.
30. **E30** `ExecID`'s `<run id>/<pid>/<start-boot-ns>` disambiguates only within one pid namespace. Once Docker/container adoption is active (ARCHITECTURE.md §9), two processes in different pid namespaces under the same run can share `(pid, start-boot-ns)` — `<run id>` alone does not separate them. `ExecID`'s shape is not widened for a namespace discriminator in P0; a consumer correlating adopted-container processes must also key on the container's own id (already recorded per §9's `container → cgroup` ledger line).
31. **E31** `Machine.PrivilegedBinary`'s **target** is not validated by R20 at all — `config.Load` never opens or trust-checks the file the field names, only the four YAML layer files. `spec/config/v0/README.md`'s Trust section defines a separate, non-identical check performed by the launcher immediately before exec: root-owned, not group/other-writable, `security.capability` xattr carries the three caps. An implementer must not reuse R20's helper (I11) here — different owner set (`root` only, not `{0,invokingUID}`) and an xattr R20 never inspects.
32. **E32** `now` before the Unix epoch: `NewRunID` returns an error (`run id mint time before the Unix epoch`) and no id, after reading `rnd`. `now` far enough in the future that `now.UTC().UnixNano()` base36-encodes past 13 characters (~year 2262+) has no special case: per §4's precondition it is a caller error `NewRunID` does not detect (`UnixNano` itself is undefined past 2262).
33. **E33** A layer file is replaced or unlinked between R20's `open` and its directory check — an atomic `mv` over the path, or the swap half of a TOCTOU attempt: the directory the fd names no longer holds the open inode, so R20's directory half cannot be established for the bytes already pinned. The layer is refused as untrusted (`run` aborts with `[config-untrusted]`, `compile`/`doctor` warn and skip) rather than judged against a directory that does not contain it — fail-closed, since a directory that cannot be tied to the file says nothing about who could have written it. The bytes are never at risk either way: they come from the fd opened before the swap (R20's `fstat`-the-fd rule).

**Changes.**
- 2026-09-28, E27, Q4, E32: a 16 MiB layer cap exists (`MaxLayerSize`); `NewRunID` refuses a pre-epoch `now`.
- 2026-09-30, E16: `record.ringbuf` above 2 GiB is refused by the parser, from `config.RingbufMax` shared with the launcher; it used to pass and fail every tier-2 run.

## 7. Failure modes and handling

| Failure | Detection | Response | Ledger | Exit | User sees |
|---|---|---|---|---|---|
| Untrusted layer file | `fstat` owner/mode (R20) | abort before run dir exists | none | 125 `[config-untrusted]` (213 before the 2026-09-22 resolution) | `<path>: machine config untrusted: <owner> <mode>`, then the fix |
| Malformed YAML | `yaml.v3` error | abort | none | 125 `[config-untrusted]` | `<file>:<line>:<col>: yaml: <detail>` |
| `version` ≠ 0 | post-parse check | abort | none | 125 `[config-untrusted]` | `<file>: unsupported machine config version <n>` |
| `$TEGO_CONFIG` under `AT_SECURE` | `DetectSecureExec` true | skip that layer silently | n/a | n/a | nothing (visible only via `compile`'s provenance) |
| Ceiling raise attempt | per-key compare | keep inherited value | n/a | 0 + warning | `ceiling <key>=<value> kept from <file>:<line>` |
| `rnd` failure in `NewRunID` | error from `io.ReadFull` | caller retries once, else abort | none | 125 | `failed to generate run id: <cause>` |
| Run id collision | `EEXIST` on `mkdir` | retry ≤3× (4 ids) | none until success | 125 after the 4th | `could not allocate a unique run id after 4 attempts` |
| Pinned or auto-selected tier unavailable | `enforce.Select` + `doctor.Probe` | abort before child stage | none | **125** (R18; not 211, Resolved conflicts) | `<contract>: tier <name> pinned but not available: <fix>` / `no enforcement tier available on this machine` |
| `getpwuid` fails | lookup error | per-user layer absent, continue | none | 0 + warning | nothing fatal |
| `execve` ENOENT | control-pipe relay from child stage | child reports, never execs agent body | `run_end reason=exec-failed` | 127 | `<command>: not found` |
| `execve` EACCES / tier deny | same | same | `run_end reason=exec-failed` | 126 | `<command>: permission denied` / `[exec-not-allowed]` |
| Capability matrix drift | I9 golden test (CI) | CI fails the PR | n/a | n/a | diff in test output |
| Invalid `ringbuf` size | `Load` validation | abort | none | 125 `[config-untrusted]` | `record.ringbuf: <value> is not a power-of-two page multiple` |

## 8. Invariants

1. **I1** No cross-imports among `identity`/`config`/`backend`/other `pkg/spec/*`: those three import no other
   `pkg/spec` package (`agent`, the compiler, is the one that imports them); `depguard`-enforced in CI
   (`.golangci.yml` rule `spec-leaves-import-no-spec`, non-test files).
2. **I2** Every `NewRunID` result satisfies `.Valid()` — property test, 10⁶ generated ids.
3. **I3** A `*Machine` is immutable for its process's lifetime; a disk edit never affects an in-flight run.
4. **I4** Every ceiling's effective value is `<=` every layer's attempted value, transitively across the chain.
5. **I5** `Env.Apply`'s output has no duplicate `KEY=` prefix (resolved inside `Apply`, never left to `execve`'s
   first-wins `envp` semantics, which is the opposite of R3).
6. **I6** `Tier.Rank`/`Capture.Rank` are total orders with no ties among defined values; `TierObserve` is excluded
   from `AtOrBelow` by explicit rule (R17), tested directly, not just implied by its rank value.
7. **I7** `ExitCode` never returns a value in 200–254 (213 folded into 125, 211 removed from this package's range — R18),
   asserted not to collide with any systemd-assigned meaning in that band.
8. **I8** Every exported function's doc comment states pre/postconditions (§4 terms); every `switch` over
   `EndReason`/`ExecFailure`/`Tier`/`Capability`/`Layer` names every value, a `default` not counting, `exhaustive`-linted
   in CI (`.golangci.yml`, `default-signifies-exhaustive: false`). A value no branch acts on is listed in a case of
   its own (or falls through to the default), so a new value fails the lint; the default keeps its fail-safe
   handling (a refusal, `-1`, `0`) and is not required to panic.
9. **I9** `backend.Matrix`/`MatrixDetail` are hand-kept cell for cell identical to `spec/backend/CAPABILITIES.md`:
   there is no generator (`tools/gen-capmatrix` does not exist). `TestMatrixGolden` (`pkg/spec/backend`) parses
   the markdown table afresh and fails on any row title, detail or presence cell that differs. Were a generator
   built, it would replace the hand-kept source and the same test would diff its output.
10. **I10** `config.Load` opens exactly the files described in R14/R20 and nothing else — no `$HOME` stat, no
    read outside the four layer paths/directories, and no read of `PrivilegedBinary`'s target (E31, a different
    component's job); verified by a syscall-audited test, unprivileged: `test/sysaudit` runs `LoadSources` over three
    layers and `Load` for a uid the passwd database does not name in a ptrace-traced child
    (`internal/testutil.SysTrace`) and holds every path syscall to the layer files, their directories, the
    open file's `/proc/self/fd` link and, for `Load`'s passwd lookup, system paths (`/etc`, `/run`, `/usr`,
    `/lib`, `/var`, `/proc` — glibc's NSS modules reach there when the test binary links cgo), never `$HOME`,
    and to no write. R14's procfs walk (`config.ThroughProc`) may also Lstat and Readlink each ancestor of a layer
    path: the kernel's own open of the layer passes through every one of them, so the walk looks at no directory the
    open does not; an open, a link-following stat or a read of an ancestor is still outside I10 (*amended
    2026-10-24*). *Amended 2026-10-25 (ADR 0063 (7)):* the trace follows any process
    the audited code starts, whose calls count as its own (it followed threads only), and a path through a /proc
    link (`root`, `cwd`, a path below `fd/N`) or with a `.` or `..` element is outside I10 whatever its prefix (the
    `/proc` system paths admitted `/proc/self/root/<any path>`). Condition: amd64 only (the tracer decodes that ABI's
    registers).
11. **I11** R20's trust check has one implementation, shared by `tego run` (abort) and
    `compile`/`doctor` (warn-and-skip) via a parameter — never a second, drifted copy. Verified by a
    single-call-site static check, or a shared fixture-driven test table.

**Changes.**
- 2026-10-24, I10: R14's procfs refusal walks each layer path a component at a
  time, so `config.Load` now Lstats every ancestor of a layer, `$HOME` among them when a layer lies under it, and
  both `test/sysaudit` audits failed. I10 admits the walk's Lstat and Readlink of a layer path's strict ancestors
  (`walkLook`) and nothing more: an open, a link-following stat, a read or a write of an ancestor still fails the
  audit (checked by making the walk's Lstat a Stat), and `$HOME` that is not a layer's ancestor still fails it.
- 2026-09-28, I9: the rule named a `tools/gen-capmatrix` generator that does not exist; the matrix is hand-kept and `TestMatrixGolden` checks it against CAPABILITIES.md.
- 2026-09-24, I1, I8: neither lint existed; `depguard` and `exhaustive` rules added, and I8's
  `panic("unreachable")` default replaced by the listed-case form the nine `Tier` switches now use.
- 2026-09-24, I10: the named test `IT-config-syscalls` did not exist; `test/sysaudit` audits
  `Load` over ptrace, unprivileged.

## 9. Conventions and best practices

- Types are singular nouns owned by one package (`Tier`, `Machine`, `Env`); no `Manager`/`Helper`/`Util`. Constants
  use package-prefixed names (`backend.TierCgroup`, `identity.ReasonLimit`, `identity.ExitConfig`).
- Errors wrap a sentinel with `%w` (`config.ErrUntrusted`) so callers use `errors.Is`, never string-matching.
- No free-text reason codes: `EndReason`/`record.Reason`-shaped values are never interpolated into prose;
  `FormatMessage` always keeps the code as a bracketed suffix.
- No goroutines, no `context.Context` in these three packages — nothing blocks long enough to need cancellation;
  `config.Load`'s file reads are local-disk and bounded, opened and closed within the call, no fd escapes it;
  `identity` opens nothing.
- Doc comments state units explicitly (`time.Duration` = wall-clock, `ByteSize` = bytes) since the YAML surface's
  human suffixes (`GiB`, `d`, `s`) must map unambiguously to internal units.
- Fuzz: `FuzzByteSize`, `FuzzFormatMessage` (native Go fuzzing, CI corpus job); `backend` has no parsing
  surface, so no fuzz target. Benchmarks: `BenchmarkEnvApply` (sub-µs/50-entry `base`), `BenchmarkLoad` (<1ms,
  three small layer files) guard against accidental O(n²) growth as `Limits`/`Machine` gain fields.

## 10. Tests

| Test | Kind | Maps to |
|---|---|---|
| T-runid-1/2/3 | unit | R1–R2, I2, E1, E24, E32 |
| T-slug-1, T-execid-1 | unit | R2, §2.1 `NewExecID` (pid reuse table), E30 |
| T-env-1..7 | unit | R4–R9, E5, E7, E29, I5 |
| T-env-noproxy-wildcard | unit | R6 (suffix match, not enumeration) |
| T-exit-1/2/3 | unit | R10–R13, I7, E23 (documents caller contract, doesn't "fix" it) |
| T-config-load-1 | unit | R14–R16 (four temp-dir layers, provenance asserted per key) |
| T-config-trust-1/2 | unit | R20, E8–E10, E26/E26b (FIFO-hang deadline test), E33 (swap during the check), I11 (both call sites, one helper) |
| T-config-privbinary-trust-1 | unit | R20's boundary against E31 (`config.Load` never opens the target); R16a's not-used warning |
| T-config-users-etc-1 | unit | R16a (`TestUsersIsTheAdministrators`; `internal/cli` `TestRunWarnsThatUsersIsIgnored`, `TestRunWarnsThatEtcUsersIsReadByTegodOnly`) |
| T-config-secure-1 | unit | R21, E19 (`AT_SECURE`×`SUDO_UID` 2×2); R21, E9 with `$USER` and `$HOME` set and the uid missing from the passwd file (`TestResolveNeverTakesTheHomeFromTheEnvironment`, `TestFindPasswdFollowsTheFilesBackend` in `pkg/spec/config`) |
| T-testbuild-anchor-1 | unit (`-tags tegotesthooks`), integration | R27 (`TestTestBuildAnchorFailsClosed`, `TestTestBuildKeepsNoOwnLogWithoutAHome`, `TestTestBuildRefusesTheRealTegoDirectory`, `TestTestBuildRefusesTheRealTegoDirectoryWithNoPasswdHome` in `internal/cli`, run by precommit and CI's build-test with `-tags tegotesthooks`; `TestIntegrationTestBuildFailsClosedWithoutAnAnchor` in `internal/runtime`: `events --verify` and `run` refuse without the variable; `TestIntegrationTestBuildRefusesTheRealLedgerRoot`: `run` and `gc` refuse a ledger root in the real `~/.tego`) |
| T-isocheck-1 | unit | R27 (`tools/isocheck`: `TestTheRepositoryIsIsolated`, `TestGO1CatchesAnEnvironmentTakenBeforeTheSetenv`, `TestGO2AnTegoConfigEntryNeedsTheIsolation`, `TestGO3ABuildOfTheBinaryCarriesTheHooks`, `TestSH1AShellThatAssignsTegoConfigSetsTheIsolation`, `TestSH2APseudoTerminalNeedsAHistoryFile`, `TestSH4SH5SH6AScriptThatRunsTegoIsolatesIt`, `TestGO4APackageThatStartsRunsGuardsTheRealHome`, `TestGO4TheGuardsResultIsChecked`, `TestGO5AnTegoSubprocessGetsAnEnvironmentOfItsOwn`, `TestTheSubcommandsAreTheCLIsCommands`; `internal/realtego` `TestDirsFallBackToHomeWithoutAPasswdHome`; `internal/testutil` `TestTegoEnvIsolatesWhateverTheDeveloperExported`, `TestGuardTegoSeesWhatAChangedHomeHolds`, `TestGuardTegoSeesAWrittenShellHistory`, `TestRealShellHistoriesAreBesideTheRealTego`, `TestGuardTegoSeesAWriteInsideARun`, `TestGuardRealTegoWatchesWhatItsPathsName`, `TestRealGuardPathsAreTheRealHomes`, `TestGuardTegoSeesAWriteThroughASymlinkedHistory`, `TestGuardedRunFailsTheBinaryOnAChangedHome`, `TestGuardedMainsFailTheBinary`, `TestGuardChildDirIsNeverARealHome`, `TestStartedByGoTestReadsGoTestsArguments`, `TestRequireTierSkipsOnlyWhenTheMachineSaysSo`) |
| T-config-ceiling-1 | unit | R15, I4, E11 (raise across 2–3 layers, transitively) |
| T-config-ceiling-badname-1 | unit | R24 (illegal tier/capture name is a `config.Load` error at its file:line) |
| T-config-sudo-1 | unit | R19, E8 |
| T-config-initns-1 | unit | R19, R19a (`TestIdentityUIDMap`, `TestReadUserNamespace`, `TestInitNSRootIsEffectiveRootInTheInitialNamespace`, `TestInvokingUID`); guest: `TestUnshareRootIsNotRoot` |
| T-config-version-1 | unit | E14, E15 |
| T-config-ringbuf-1 | unit | E16 |
| T-tier-rank-1 | unit | I6 (full pairwise `AtOrBelow`, incl. `TierObserve`) |
| T-capture-valid-1 | unit | R25 (`Capture.Valid`/`ParseCapture` symmetry with `Tier`) |
| T-capmatrix-golden | golden | I9 (`TestMatrixGolden`: committed source vs fresh markdown parse; no generator exists) |
| T-report-1 | unit | R23 |
| TestConfigLoadSourcesOpensOnlyItsLayers, TestConfigLoadReadsNoHome (`test/sysaudit`) | unit, ptrace-audited, unprivileged | I10 |
| IT-pinned-tier-125 | integration, VM | R18 (contract pins `bpflsm` on a kernel without `bpf` in the LSM list; exit 125, not 211) |
| TestMintRunRetriesATakenPath (`internal/runtime/mintrun_test.go`) | unit | R2b (1 and 3 collisions succeed on the next id; 4 fail with EEXIST) |
| E2E kill test 6 | `test/e2e` | R17–R18, `docs/FEATURES.md` R16 three-halves acceptance (note: kill test 6's own 211 is `doctor`'s, not `tego run`'s) |

## 11. Open questions

- **Q1** (E3) Should `doctor` detect a shared/default `/etc/machine-id` and warn of `host8` collision risk? Not
  specified in any normative doc; belongs to `internal/doctor`, not this component.
- **Q2** Should `agent.Compile` warn when `env.pass`/`env.set` names a `TEGO_*`/identity-reserved variable,
  given it's silently discarded at runtime regardless (R3/E5)? Affects `pkg/spec/agent`, adjacent to this spec.
- **Q3** Should `Limits` model "unbounded" as an explicit sentinel rather than a large built-in default?
  `spec/config/v0/README.md` says only "built-in ceilings are unbounded" without a concrete representation.
- **Q4** (E27) No maximum machine-config file size is specified anywhere; the code holds a 16 MiB cap
  (`MaxLayerSize`, `errTooLarge`); recommend the normative doc state one (e.g. 1 MiB) so the number is not this
  component's alone.
- **Q5** Exact `time36` resolution/width (nanosecond `UnixNano`, base36, 13 chars) is this spec's own choice for
  the named-but-underspecified "time36" field.
- **Q6** No normative doc specifies the machine-id source/fallback chain
  the **caller** of `NewRunID` must use (`/etc/machine-id` vs. `/var/lib/dbus/machine-id` vs. generating and
  persisting one) when `/etc/machine-id` is absent or empty — common pre-`systemd-machine-id-setup`. `identity`
  puts machine-id reading out of its own scope (§1); it is left to `internal/runtime.Run`, or `host8` becomes non-reproducible across identical hosts.

## Resolved conflicts
Resolved (2026-09-22): `tego run` never exits 211 or 213; an unavailable pinned tier and an untrusted machine config both exit 125 with codes `[tier-unavailable]` and `[config-untrusted]` (RUN-IDENTITY, config README updated); `doctor --require` alone exits 211.


### env.set path token amendment, 2026-11-03 (ADR 0068)

During `agent.Compile`, the exact `${TEGO_PROJECT_DIR}` token in env.set values expands
once to the absolute working directory used for relative contract paths. All other
characters, including `$HOME`, `${NAME}` and command substitutions, stay literal. The
compiled Set and effective PATH use the expanded values; the loaded contract, canonical
copy and contract hash retain the original token. `internal/runtime.buildEnv` continues
to install the compiled Set without performing shell or environment expansion.
