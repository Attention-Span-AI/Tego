# Budgets, views, doctor, CLI (P0 detailed spec)

## 1. Purpose and boundaries

**Owns.** `internal/runtime/limits` — the only P0 subsystem that stops a run for a non-security reason; it watches
the event stream live, in-process, and trips `cgroup.Manager.Kill` when a budget is crossed. `internal/check/
{status,drift,measure,events}` — pure read-side views over a ledger (`learn`: docs/OPERATIONS.md). `internal/doctor`
— read-only machine capability probing, used before `run` picks a tier. `internal/cli` — command dispatch for the
one binary, including the hidden `__child` re-exec stage (owned here as plumbing; its *behaviour* belongs to
`docs/p0/runtime-launch.md`).

**Must not do.** `limits` never opens a file, connects a socket, or decides a Landlock/eBPF verdict; its only
effect on the world is `cgroup.Manager.Kill(cg)` plus one `limit` event through the `Sink` it is given. `check/*`
never writes the ledger and never imports `internal/runtime` (REPO-LAYOUT.md: the engine never imports the read
side and vice versa) — `tego status` "never writes: it shows `lost`" (OPERATIONS.md). `doctor` never leaves a
program loaded or a map pinned once `Run` returns, and needs no network. `cli` carries no business logic: "one
file per subcommand... parse flags and call one facade function" (REPO-LAYOUT.md).

**Imports allowed** (depguard-enforced): `limits` → `internal/runtime/cgroup`, `internal/ledger`, `pkg/spec/*`;
never `cilium/ebpf` directly. That `internal/ledger` edge is narrow: `Observe` calls only the shared
`ledger.Usage(e)` helper (§4, shared with `measure.ComputeAt`) — `limits` never opens or iterates a `ledger.Reader`
itself, which stays `check/*`'s job. `check/*` → `internal/ledger`, `pkg/spec/*`; never `internal/runtime`.
`doctor` → `internal/platform/sys`, `internal/runtime/enforce`; never `internal/check`. `cli` →
`internal/runtime`, `internal/check`, `internal/handoff`, `internal/doctor`, `pkg/spec/*`; never `cilium/ebpf`.

## 2. Models

```go
// internal/runtime/limits
type Watcher struct { // ceiling never above the machine's (SEMANTICS §8); mu guards state below
    ceiling agent.Limits; prices *PriceTable; clock clock.Clock // clock is monotonic, MonoNS-driven
    mgr cgroup.Manager; cg cgroup.Cgroup; sink record.Sink      // sink appends the `limit` event
    mu sync.Mutex; state State; tripped bool                   // tripped: Kill fires at most once/run
}
type State struct { // live per-run accumulator; zero value is a fresh run
    TokensIn, TokensOut, TokensCacheRead, TokensCacheWrite uint64
    CostUSD         float64 // sum of per-response est. cost; every surface labels it "est."
    StartMonoNS     uint64  // from run_start.MonoNS
    LastEventMonoNS uint64  // last non-gap event's MonoNS; stall = now - LastEventMonoNS
    RepeatTool, RepeatHash string // last decision's tool_use name / input_hash
    RepeatCount     int     // consecutive identical (tool, hash) decisions, >=1
}
type Breach struct{ Which, Value, Ceiling string } // Which: tokens|cost_usd|wall|stall_after|repeats;
                                                    // embeds into the `limit` event (`which value ceiling`)
type PriceTable struct { // spec/config/v0's `prices` file; P0: flat versioned map, override (E62) is P2
    Version int `yaml:"version"`; Updated time.Time `yaml:"updated"`
    Models  map[string]ModelPrice `yaml:"models"` // key: ssl_response.model, exact string
    ServerToolPerRequest map[string]float64 `yaml:"server_tool_per_request"` // USD per request, by tool name (R2)
}
type ModelPrice struct { // USD per 1e6 tokens
    InputPerMTok, OutputPerMTok, CacheReadPerMTok, CacheWritePerMTok float64
    CacheWrite1hPerMTok *float64 `yaml:"cache_write_1h_per_mtok"` // 1-hour cache writes; nil is unpriced (R2)
}

func NewWatcher(ceiling agent.Limits, prices *PriceTable, mgr cgroup.Manager, cg cgroup.Cgroup, clk clock.Clock, sink record.Sink) *Watcher
func (w *Watcher) Observe(e *record.Event)             // pipeline stage; never blocks, never errors
func (w *Watcher) Tick(now time.Time) (*Breach, error) // 1 Hz ticker; only source of wall/stall breaches
func (w *Watcher) Snapshot() State // test-only: no production caller
```

```go
// internal/check/status
type State string // running | waiting model | waiting tool | stalled | done | lost
type Snapshot struct {
    Run, Agent string; St State; Since time.Time // Since: ts of the event/check that produced this state
    Step int; LastDecision, LastEvent *record.Event // Step: max attribution.step seen, 0 if none
    ExitReason string; ExitCode int; LockHeld bool  // ExitReason/Code set only when St == Done
    Gaps []gaps.Count                               // the gap line (R34); qualifies St, never decides it
    Ended bool; Resources *record.Resources          // run_end seen, and its resources object (R-res)
    ResourcesRecorded json.RawMessage               // the same object as the ledger holds it, for --json
}
func Derive(r *ledger.Reader, lockHeld bool, now time.Time, stallAfter time.Duration) (*Snapshot, error)
func DeriveAll(ledgerRoot string, now time.Time) ([]*Snapshot, error) // every run dir; bare `tego status`
```

```go
// internal/check/drift
type RuleCount struct { Rule string; Allow, Ask, Refused, Observed int } // Rule: declared entry, or "unmatched"
type Report struct {
    Run, Agent, ContractHash, CurrentHash string // CurrentHash: recompiled from contract.yaml on disk now
    HashChanged                    bool
    FS, Net, Exec, MCP             []RuleCount
    Undone, UnusedMCP              []string // Undone: zero-event declared entries; UnusedMCP: zero-event mcp[] (R15)
    UnobservableMCP                []string // zero-event mcp[] in a run no MCP producer could have recorded (R15)
    Gaps                           []gaps.Count // the gap line (R34), summed by Aggregate
    Runs                           int      // 1 for a per-run report, N for Aggregate's result
}
func ComputeCtx(ctx context.Context, r *ledger.Reader, rt *agent.RuleTable) (*Report, error) // ctx checked every 1024 lines (R29)
func Aggregate(reports []*Report) (*Report, error) // same agent id required (R17)
func MCPTransports(parsers map[string]string) []string // transports run_start.parsers' MCP producers cover (R15)
```

```go
// internal/check/gaps — the gap line (R34), shared by status and drift
type Count struct { What, Why string; Events, Lost int; Binaries []string } // one (what, why)
type Tally struct { /* one entry per distinct (what, why, binary) */ }
func (t *Tally) Add(e *record.Event) // ignores every kind but gap
func (t *Tally) Counts() []Count // sorted by what, then why
func Merge(runs ...[]Count) []Count  // drift --aggregate
func Line(cs []Count) string         // "none", or "what/why xN (N events lost, in <binary>, ...); ..."
```

```go
// internal/check/measure
type Report struct {
    Run                                         string
    Steps, Refused                              int
    TokensIn, TokensOut, CacheRead, CacheWrite  uint64
    EstCostUSD                                  float64       // rendered "$X.XX est." (CostText, R20)
    Wall, IdleMax                               time.Duration
    Repeats                                     int // longest consecutive same-(tool,hash) run seen
    Resources                                   *record.Resources // run_end's, as recorded (R-res)
    ResourcesRecorded                           string            // the same object as the ledger holds it, for --json
}
func ComputeAt(ctx context.Context, r *ledger.Reader, p Prices, nowMonoNS uint64) (*Report, error) // nowMonoNS 0: none (R21)
```

```go
// internal/check/events
type Filter struct { Kinds []record.Kind; Sources []record.Source; Verdicts []record.Verdict; Rules []string; Steps []int; Since, Until time.Time; Limit int }
func Iterate(r *ledger.Reader, f Filter) iter.Seq2[*record.Event, error] // decoded, for the table renderer
func RawLines(r *ledger.Reader, f Filter) iter.Seq2[[]byte, error]       // design name, not built; --json: exact stored bytes, never re-marshaled
```

```go
// internal/doctor
type CheckID string // kernel | btf | cgroupv2 | landlock | seccomp | lsm | programs | fanotify
type Result struct { ID CheckID; OK bool; Detail, Fix string } // Fix == "" when OK
type Report struct {
    Results []Result; Tier backend.Tier            // Results in probe order D1..D9 (§5); Tier: highest reachable
    Missing map[backend.Tier][]string; Matrix backend.Set // Missing: per tier above Tier, what is absent
}
func Run(ctx context.Context, m *config.Machine, require backend.Tier) (*Report, error)
```

```go
// internal/cli
type Command struct { Name string; Flags func(*flag.FlagSet); Run func(ctx context.Context, fs *flag.FlagSet, stdout, stderr io.Writer) int }
func Main(argv []string, stdout, stderr io.Writer) int // dispatches argv[1], or the hidden __child stage
```

**Changes.**
- 2026-10-19 (ADR 0029 (4)): the drift and measure entry points are `drift.ComputeCtx(ctx, r, rt)` and
  `measure.ComputeAt(ctx, r, p, nowMonoNS)`, the functions `tego drift` and `tego measure` call; `drift.Compute(r, rt)`
  and `measure.Compute(r, p)`, wrappers only tests called, left the API for the tests' own files. §1, §4 (and the stop
  marker's `ledger.PlaceNewFileThen`), R16, cases 10 and 23, I4, I5, §9 and §10 name the survivors.
- 2026-09-29, `Watcher.Snapshot` is test-only; run_end carries no limits state.
- 2026-09-29: `RawLines` and `ErrEmptyLedger` are design names with no Go symbol of that spelling.
- 2026-09-24, `PriceTable`/`ModelPrice`: `cache_write_1h_per_mtok` and `server_tool_per_request`
  added (R2).

## 3. Repositories and storage

| What | Path | Perms | Format | Owner | Concurrency | Durability |
|---|---|---|---|---|---|---|
| Run ledger (read) | `<ledger_root>/<run>/events.jsonl` | `0600` in `0700` dir | JSON Lines, torn-tolerant | supervisor writes; this component reads only | `ledger.Reader` opens its own fd; N concurrent readers safe | none owed here |
| Run lock (read) | `<ledger_root>/<run>/lock` | n/a | `flock(LOCK_EX)` | supervisor | `status`/`doctor` probe `LOCK_SH\|LOCK_NB`: success ⇒ free; `EWOULDBLOCK` ⇒ held | none; never written here |
| `last-refusal.json` (read) | `<ledger_root>/<run>/last-refusal.json` | `0600` | JSON object | the ledger writer, latest refusal, coalesced at most every 10 ms (record-ledger.md §3) | advisory reason channel for harnesses (REASON-CHANNEL.md §2); `events --last` reads the ledger line instead (R29): authoritative, carries the event identity, covers `gap`/`limit`, and is what I8 makes `--json` print | none |
| Price table | `<prices>` (machine config, default `~/.tego/prices.yaml`) | trust rule of spec/config/v0 wherever `prices:` puts it (`config.ReadTrusted`; an untrusted table is refused like an unreadable one, R32); read-denied and write-protected to the agent (`agent-contract.md` R6a, R10) | YAML → `PriceTable`, strict (R32) | operator | loaded once per invocation, no lock | none |
| Profiles | `<profiles>/<name>.yaml` (machine config, default `~/.tego/profiles`) | trust rule of spec/config/v0 on the file, each directory up to `<profiles>` and `<profiles>` itself, wherever `profiles:` puts it (`config.CheckTrusted`; an untrusted profile is `extends-not-found` saying `profile "<name>" untrusted:` with the failing path, its uid and mode and the reason, never "not found", and the trust rule's fix); read-denied and write-protected to the agent (agent-contract.md R6a and R10) | YAML, read through `os.Root` (`agent-contract.md` E7) | operator | read per compile, no lock | none |
| Chain anchor (read) | `~/.tego/chain.log` of the invoking user, whatever `ledger_root` is; beside the ledger root for an account with no home (`record-ledger.md` §3) | `0600` | `<run> <head>` per line | the launcher appends at `Close`, a sweep for the orphans it ends | sequential scan by `events --verify` (R29); opened `O_NOFOLLOW`; never written here | none |
| Activity sidecar (read) | `<ledger_root>/<run>/activity` | `0600` | 16 bytes: the CLOCK_MONOTONIC `mono_ns` as a little-endian `uint64`, then its bitwise complement | the launcher (`Writer.OpenActivity`, `O_CREAT\|O_EXCL\|O_NOFOLLOW` through the run directory's descriptor), rewritten in place by one `pwrite(2)` at most once a second from the budget watcher's loop (R9) | read by `status` only while the run's lock is held; opened `O_NOFOLLOW\|O_NONBLOCK`, regular files only; anything but one whole reading (short, long, zero, halves that disagree because it was read mid-write) is no reading (`ledger.ReadActivity`) | none; not part of the record, and left in place at run end, where nothing reads it |
| Stop marker (write) | `<ledger_root>/<run>/stop.request` | `0600` | empty, or one Go duration and `\n` when `stop --grace` was given | `tego stop`, `O_EXCL` temp file + `link(2)`, never `rename` (`runtime-launch.md` R9) | read once by the launcher's first stop signal (`runtime-launch.md` R9); `O_NOFOLLOW`, at most 64 bytes | none |
| Machine config layers | spec/config/v0 | trust rule (one name included); write-protected to the agent by every name (`config.Machine.Layers`, agent-contract.md R10, ADR 0059) | YAML | operator/root | resolved once at CLI start via one `config.Load` | none |
| BTF | `/sys/kernel/btf/vmlinux` | kernel-exposed | raw BTF | kernel | single `open(2)`+`read`, never `stat`-then-`open` | n/a |
| securityfs | `/sys/kernel/security/lsm` | kernel-exposed | CSV string | kernel | single read | n/a |
| cgroup v2 delegation files | `/sys/fs/cgroup/**/cgroup.{procs,subtree_control,controllers}` | kernel-exposed | text | kernel/logind | probed with `access(2)` + a scratch `mkdir`+`rmdir` | n/a |
| Doctor's BPF probe objects | none on bpffs: D7 loads every map with `PinNone`, overriding the objects' `LIBBPF_PIN_BY_NAME` | n/a | program and map file descriptors only | doctor | a pinned map of this build is the one a live run is using, so doctor never opens or creates a pin, and production's `/sys/fs/bpf/tego/<bpf_hash>/` is untouched (§6 E28); each program is detached and closed via `defer` before `Run` returns | none; never survives the call |
| Run-probe cache (R27 "What a run probes") | `/run/tego/doctor-probe-<bpf_hash>-<privilege>-<binary>.json`, one per build, per set of process privileges and per binary | `0600`, root's, in root's `/run/tego` (`0700` when this creates it) | one JSON object: the key (the machine's and the asking process's), D7's tier-2 rows, the plane's answer and rows, D8's answer, D2's answer and the kernel's functions a run asks its BTF about | a root `tego run` at reach `cgroup` or `bpflsm` (`doctor.ForRun`); `tego doctor` never reads or writes it | written through a temporary file and `rename(2)` in the same directory, so a reader sees one whole entry or the other; read only after every directory from `/` down and the file itself pass the trust checks of R27 | none: `/run` is a tmpfs, and the key holds the boot id, so a reboot discards it either way |
| User registry | `<registry>/agents/<name>.yaml` (machine config `registry:`, default `~/.config/tego`; `""` for none), `<registry>/skills/` reserved | trust rule of spec/config/v0 on the entry, `agents/` and `<registry>` (`config.CheckTrusted`; refused `config-untrusted`, `registry entry untrusted:` or `registry directory untrusted:`); `agents/` and `skills/` write-protected to the agent (agent-contract.md R10, R26), not read-denied | YAML, read once through `os.Root` (agent-contract.md R26) | the user | read per name resolution, no lock | none |
| Run-probe flight locks (R27 "Concurrent misses") | `/run/tego/doctor-probe-flights/<sha256 of the whole key>.lock`, one per full run-probe cache key, and `.index.lock` beside them | the directory `0700`, root's, made by the first run that coordinates; each file `0600`, root's, empty, with one link | none: a file is only an `flock(2)` target | a root `tego run` at reach `cgroup` or `bpflsm` that misses the run-probe cache (`doctor.ForRun`); `tego doctor` never touches it | `flock(LOCK_EX)`, tried every 10 ms for at most 30 s; a new file is made only under `.index.lock`, and only while fewer than 128 exist, unlinking first, at 128, files nobody holds (amended 2026-10-05); every file is opened `O_NOFOLLOW` relative to the verified directory, and used only while it is a private empty single-link file that its name still leads to after the lock is taken, its name opened again when not | none: unlinked only to make room at the limit, by a caller that holds its lock, so two waiters never hold two inodes of one name; else kept until `/run`, a tmpfs, is emptied at reboot |
| `tego.log` (write) | `~/.tego/tego.log` | `0600` | structured line, `run=<id>` when applicable | this binary | rotated 10 MB × 5; one appender per process; while another process holds the rotation lock the file grows to at most twice the limit, then lines are dropped and their count logged after the next rotation (`docs/OPERATIONS.md`); an appender that cannot open or reopen the file gives the log up for the process and closes the descriptors it held | best-effort |

`limits`/`check/*` never create the run directory, lock or ledger — those belong to `internal/ledger` and
`internal/runtime/launch`. This component only opens what already exists.

**Changes.**
- 2026-10-20, §3 price table, profiles, machine config layers, user registry (ADR 0059): the trust rule now includes
  one name (a file with a second hard link is untrusted unless no run of the invoking user could write it), so each
  of these rows' files has one; a registry entry is read through `agents/` itself; and each machine config layer a
  Load consults, there or not, is an R10 target, as the price table is.
- 2026-10-20, §3 user registry (agent-contract.md R26): the row is added; `agents/` and
  `skills/` are R10 targets wherever `registry:` puts them, as the profiles are.
- 2026-10-19, §3 `tego.log` (ADR 0023 C17): an appender that gives the log up closes `~/.tego` and the file it held
  (they stayed open for the life of the process); `~/.tego`'s descriptor is a strict `sys.FD`, since it carries the
  rotation flock.
- 2026-09-24: doctor's BPF row and I7 say what the code does: every map is loaded `PinNone`, and nothing is pinned.
- 2026-09-29, §3: the stop marker is placed by `O_EXCL` temp file + `link(2)`, never `rename`.
- 2026-09-24, price table and profiles: the trust rule and the agent's denies apply wherever the
  machine config puts them.
- 2026-10-05, §3: the run-probe flight locks of `doctor.ForRun` have their row.
- 2026-10-05, §3: a flight lock file nobody holds is reclaimed when a new key meets the 128-file limit.
- 2026-10-05, §3: the activity sidecar `status` reads beside the ledger (R9).

## 4. Functions and contracts

- **`limits.NewWatcher(...)`** — Pre: `ceiling` already clamped to the machine's (SEMANTICS §8), `cg` exists.
  Post: zeroed `State`. No I/O, cannot fail; a `nil` `prices` just disables cost breaches (§6 E15).
- **`(*Watcher) Observe(e)`** — called once per event, pipeline order, before `ledger.Writer.Append`. Updates
  `state` per R1-R5; may call the unexported `trip` (below). Never blocks, no I/O, never errors (payload decode
  bugs are covered by fuzzing, §9 C8).
- **`(*Watcher) Tick(now)`** — called at 1 Hz by a dedicated goroutine on the same `clock.Clock`. Returns a
  non-nil `*Breach` exactly when wall/stall is newly crossed; idempotent past that (`tripped` guards a repeat).
  Wraps `cgroup.Manager.Kill` errors with `%w` — a failed kill is never swallowed (§7).
  A breach `Observe` trips whose kill fails is retried by `Run` on its next tick, and a second failure is returned
  to the worker group, which ends the run's cgroup.
- **`w.trip(ctx, b)`** *(unexported, contract matters)* — Pre: `tripped==false`. Post: sets `tripped=true`
  (later breaches in the same tick are dropped, never a second event); appends one `limit` event; calls
  `mgr.Kill(cg)`; never appends `run_end` itself — that is the runtime facade's job on the cgroup's `populated=0`
  transition, so `limits` never races the pipeline drain. The event is appended even if `Kill` errors.
- **`status.Derive(r, lockHeld, now, stallAfter)`** — Pre: `r` at the start of a torn-tolerant iterator;
  `lockHeld` probed *after* opening `r` (order matters, §6 E3). Post: exactly one `State` per R7-R12.
  Errors: `ErrEmptyLedger` (a design name, not built) on a zero-byte file (§6 E1); a torn *middle* line is fatal (a torn *last* line is
  tolerated). Pure, side-effect-free.
- **`drift.ComputeCtx(ctx, r, rt)`** — Pre: `rt` compiled from the same contract this run declared (caller re-runs
  `agent.Compile` against the run directory's `contract.yaml` copy). That copy is the canonical merged contract
  (`agent.Contract.Canonical`, whose sha256 is `run_start.contract_hash`, agent-contract.md R13), so the caller
  loads it with its `extends:` sealed — resolved to an empty profile, never re-read from today's profiles
  directory, whose entries are already merged into the copy — and compiles it against `run_start.cwd`, the
  directory its relative entries resolved against when the run compiled them, never the directory drift is
  invoked from. A copy whose sha256 is not the recorded hash (one a binary before this rule wrote as the file's
  raw bytes, or one edited since) is loaded as a contract file with today's profiles, and R16 then reports
  whatever that changes. Post: every declared entry lands in exactly
  one bucket (a `RuleCount`, possibly zero, or `Undone`); every observed `rule`, `"unmatched"` included, appears
  in `RuleCount`; every `exec` line flagged `fileless` or `dropped` is counted under its image in `Fileless` or
  `Dropped`, or in `FilelessMore`/`DroppedMore` past the first 32 images (R17a). Errors: a torn middle line is
  fatal like `status.Derive`.
- **`drift.Aggregate(reports)`** — Pre: all `reports[i].Agent` equal (else `ErrMixedAgent`, caught by `cli` as a
  usage error, exit 2). Post: `RuleCount`s summed by `Rule`; `Undone`/`UnusedMCP` are **intersections** across
  runs (R17); `UnobservableMCP` is what some run could not observe and no run used; `Gaps` summed by what and
  why; `Fileless`/`Dropped` summed by path under R17a's bound; `Runs = len(reports)`.
- **`measure.ComputeAt(ctx, r, p, nowMonoNS)`** — same shape as `drift.ComputeCtx`; formulas R18-R23, recomputed from the ledger, never
  sharing state with a live `Watcher` (deliberate duplication, §9 C1).
- **`ledger.Usage(e) (TokenUsage, bool)`** *(in `internal/ledger`, shared by `Observe` and `measure.ComputeAt`)* —
  `true` and populated iff `e.Kind=="ssl_response"` and its payload decodes with a `usage` object;
  `TokenUsage{Model string; In, Out, CacheRead, CacheWrite uint64}` straight from `usage{...}`, a negative count
  read as 0 (a malformed or hostile reply must neither wrap an unsigned total nor credit tokens back). The only
  code shared across the engine/read-side boundary for this formula — legal because `internal/ledger` is neutral
  shared infrastructure (REPO-LAYOUT.md) and `ledger.Usage` itself imports only `pkg/spec/record`. The type is `TokenUsage`.
- **`doctor.Run(ctx, m, require)`** — Pre: none; root unlocks tier-2/3 functional probes. Post: `Results` has
  exactly 9 entries in fixed order D1-D9 (§5); `Tier`/`Missing`/`Matrix` derived from which passed. Errors: only
  context cancellation or an unexpected syscall failure that is *not itself* a capability answer (those are
  `Result{OK:false}`, never a Go `error`, §7). Idempotent; safe next to a live run or another `doctor` (§6 E28).
  It never reads or writes the run-probe cache: `doctor` always probes afresh.
- **`doctor.Reach(m, rt, only)` and `doctor.ForRun(ctx, m, reach)`** — what `tego run` selects from (R27 "What
  a run probes"). `Reach` is pure but for `config.InitNSRoot` (effective uid 0 in the initial user namespace, ADR
  0042 (5)(d); under `unshare -r` it is false) and `enforce.Buildable`: the highest tier the selection
  can pick or has to explain. `ForRun` Post: `Results` has D1-D9's 9 entries in order, a check it did not run
  marked `Skipped` with a detail beginning `not probed by tego run`; for every tier at or below `reach`,
  `Probe()` and `WhyNot` equal those of `doctor.Run` called by the same process on the same machine, with D7's
  tier-2 rows and D8 either probed by this call or read from an entry kept under this machine's and this
  process's key (§6 E30 names the restrictions that key does not hold); every tier above it is unavailable, its
  `WhyNot` saying it was not probed. `FromCache()` says whether D7's tier-2 rows and D8 came from the run-probe
  cache, and `DiscardCache()` removes the entry they came from while it is still the file under its name (a
  no-op otherwise, including after a fresher answer was renamed over it). Errors: as `doctor.Run`.
  Leaves no kernel object behind: no bpffs entry (I7), and no thread carrying D5's filter or the `no_new_privs`
  set for it, unless D5 failed because that thread had not ended within its 5 s (R27 D5); at reach `cgroup` as root it may write or remove its cache entry, and on a miss create its key's flight lock file, which stays until reboot unless a later run of another key reclaims it while nobody holds it (§3, R27 "Concurrent misses").
- **`cli.Main(argv, stdout, stderr)`** — Pre: `argv[1]` is a subcommand, `__child`, or absent (usage, exit 2).
  Post: the process's intended exit code (R24-R26). A top-level `recover` logs `tego: internal error: <msg>
  [bug]` to stderr and returns 125 — no panic escapes the exit-code contract other tools parse.

## 5. Business rules
**Budgets (limits.Watcher)**
- **R1 Tokens.** `TokensIn += usage.input`, `TokensOut += usage.output`, cache fields likewise, on every
  `ssl_response`. Breach when `TokensIn+TokensOut > ceiling.Tokens` (cache tokens count toward cost, R2, not
  toward this ceiling — they are billed at a fraction and not rate-limited the same way). A stream cut after
  `message_start` and before the `message_delta` that carries its output count is charged the request's
  `max_tokens` as output (or the output it reported, if larger), marked `usage.output_bound` (capture-derive.md
  R29, ADR 0036): an upper bound, so an interrupted stream overcharges and never undercounts, and a user
  interrupting a stream does not end the run. Where the request declares a server-side tool the bound does not
  hold (its request counts arrive only in the lost `message_delta`), and the interrupted stream is unmetered.

  A token or cost budget is enforced only over spend the watcher can read, so a model exchange whose spend capture
  cannot read fails closed. The capture source decides and reports it through its sink (`source.ReportUnmetered`
  on the capture lane, which the runner implements, `runtime.captureUnmetered`). At the first report a run with a
  `tokens` or `cost_usd` budget ends: reason `error`, the cause in `run_end`'s detail, the cgroup killed. A report
  that arrives once the run has quiesced — its cgroup empty, or tego's own teardown (the kill after a cancel,
  shutdown) begun, so the report is a request that teardown aborted or one lost with a process that has exited —
  records `gap what=capture why=unmetered-after-exit` with its count and changes neither the end reason nor the
  exit code. The main process's exit alone is not that point: while a descendant that outlived it keeps the cgroup
  populated (`sh -c 'agent & exit 0'`), a report still ends the run. A run with
  neither budget keeps running; its record already carries the unparsed decision or capture gap. Model traffic the
  capture queue dropped ends a budgeted run the same way (`runtime.captureLost`), unless the run has quiesced: then
  the count is `gap what=capture why=unmetered-after-exit` and the end is unchanged, as for an unmetered report. "Model host" below is a host a
  `models[]` entry declares or a parser claims by default; "unlearned" is a connection whose host capture never
  read. The letters are stable: a new case takes the next free letter, a retired one keeps its letter.

  Reported as unmetered (ends a budgeted run):
  - (a) A 2xx answer on a model endpoint whose usage derive could not read (`derive.Facts.Unmetered`): an unparsed
    body (a chat completion with no usage, or a message whose usage has no `output_tokens`, among them); a path inside `/v1` the parser does not read usage from,
    including a batch's `/results`, a first segment `v1` in any case or with `;params` (`/V1/messages`,
    `/v1;x/messages`) and an ambiguous first segment (capture-derive.md R25); a declared provider with no parser.
  - (b) The creation of a message batch (2xx): it spends later upstream, where no exchange shows it. The residual
    is stated: a batch created before the run ends runs to completion upstream, outside anything the run controls.
  - (c) A 2xx Anthropic stream that ended before a `message_delta` carrying usage, when the request's `max_tokens`
    is not known and so bounds nothing: absent, not a positive integer, named more than once or only in another
    case, or unreadable. It is read from a whole body by derive and off every byte of a body capture kept only as
    a prefix by the shared scanner in derive/anthropic, with the same rule (capture-derive.md R29).
  - (d) A 2xx answer on a model host, on a path that is not silent (letter (l)), whose body capture cut by size (the forwarder's capture budget or decode
    limit, the uprobe path's byte budget) and from which no usage was read. On the forwarder the usage scanner,
    which reads an identity-coded stream off every byte relayed, can supply it; a `gzip` or `deflate` stream cut
    by size is reported. On the uprobe path a size-cut 2xx answer on a model host is always reported.
  - (e) A request to a model host or an unlearned host that got no byte of a response (ADR 0037). Forwarder: the
    upstream round trip failed, or the exchange was in flight when the run ended. Uprobe path: the request was
    waiting when its connection closed (`SSL_free`), its `SSL*` started a new connection (the count restarting
    at 1), the source stopped, a later response on the connection showed it would never be answered, or the
    per-connection table of waiting requests evicted it, or it was pipelined past R11's depth and refused, so its
    answer is passed over unread. A request with an unreadable target (h) counts here
    whatever its host; one to a path the deriver calls silent (l) does not.
  - (f) Uprobe path: a connection capture lost — gapped after a sequence hole or a framing error, or an `SSL*`
    whose I/O split across threads — while a request to a model host, an unlearned host or an unreadable target
    was waiting on it; with none waiting, when the connection's last host was a model host or unlearned.
  - (g) Uprobe path: an HTTP/2 connection (capture-derive.md R17's gap) whose peer is a model host or unlearned,
    which a preface on a fresh connection always is (ADR 0035). The cost is stated: benign h2 traffic to a host
    capture has not learned ends a budgeted run captured through uprobes; learning the peer from the handshake's
    SNI is the alternative that ADR records.
  - (h) Uprobe path: a 2xx answer to a request whose target is neither origin-form (`/...`), `*`, an
    `http`/`https` URL with a host, nor (for `CONNECT`) a host and port, whatever host its `Host` header names:
    what it reached cannot be told (capture-derive.md R10).
  - (i) Uprobe path: a 2xx answer to a `CONNECT` opening a tunnel to a model host: capture cannot tell whether it
    reads the TLS session inside it, as with (g).
  - (j) Uprobe path: an exec or libssl open the source's hook queue had no room for (`runtime.hookQueue`,
    capture-derive.md, the kernel hook): the source never attached at that process, so none of its model traffic
    can be metered. Reported once, count 1, at the run's first such drop, with the `hook-queue-full` gap written
    then.
  - (r) Under a `cost_usd` budget only: a response reporting server-tool requests when the price table names no
    `server_tool_per_request` fee at all, which bounds nothing (`limits.PriceTable.UnfeedServerTool`); `tego
    compile` warns `[unenforced]` for such a table.
  - (s) Forwarder: an event its listener's emit queue had no room for (capture-derive.md I1). The event may have
    been the line that carried an exchange's spend. The listener reports its first drop, count 1. Every drop is
    counted in the run's `gap what=capture why=emit-queue-full`.

  Not reported:
  - (k) An answer that is not 2xx, including a 2xx stream whose first event is an `error` (an
    `overloaded_error` before any `message_start`): an error answer began no message and spent nothing.
  - (l) An endpoint that spends nothing: model listing, token counting, a batch's listing, status, cancel or
    deletion, the Files API, and anything outside `/v1` (the root path, `/api/...`, a harness's telemetry),
    answered or not: both paths ask the deriver's path classification before reporting (e). "Anything outside
    `/v1`" is `api.anthropic.com`'s; on another host declared for provider `anthropic` only the root path and
    `/api/...` paths with no segment inside `/v1` are silent, and any other path there is reported (a)
    (capture-derive.md R25).
  - (m) A stream cut after `message_start` whose `max_tokens` is known: it is charged the bound (R1 above, ADR
    0036). A `message_delta` read later on the wire replaces the bound with the reported count: on the forwarder
    the usage scanner's, also when derive's whole copy stopped short of it; in derive, a stream whose assembly
    failed (a `tool_use` input that is not valid JSON, a malformed frame) is read on for it. An `error` event after
    `message_start` keeps the bound.
  - (n) A TLS peer no `models[]` entry declares and no parser claims, whose exchanges were read (uprobe path).
    The uprobe path sees plaintext only, never the connection's destination or SNI, so the peer is the name in the
    request's `Host` header (or absolute-form target), which the agent chooses: an agent that forges `Host` on a
    request to a declared endpoint that ignores it is read as this peer and its spend is not metered. Accepted: the
    check needs kernel-side destination data (not built).
  - (o) Forwarder: an upstream leg whose dial failed (`*net.OpError`, `Op == "dial"`), which sent no byte.
  - (p) Uprobe path: an exchange capture passed over because it missed the start of its request
    (capture-derive.md R4's attach race, or a connection's first chunk lost to a full ring, which
    `gap why=ring-buffer-drop` counts).
  - (q) Uprobe path: an h2 connection, an h2c upgrade among them, whose peer capture learned is not a model host;
    a `CONNECT` tunnel to a host that is not a model host; a connection that closes with nothing waiting.

  An absolute-form request (`POST https://api.anthropic.com/v1/messages`) is in neither list as such: it is
  metered as the origin-form request to the URL's host would be (capture-derive.md R10, R25). Ending rather than
  refusing is one rule for both capture paths: a batch creation could be refused before it is sent by the
  forwarder, but not by the uprobe path, which only watches, and the ledger says why the run ended.

  Changes (R1):
  - 2026-09-30: R1 (a) counts a whole message whose usage lacks `output_tokens` as unparsed and
    unmetered, as the stream path already did (`TestMessageUsageWithoutOutputIsSchemaError`).
  - 2026-09-30: R2 leaves a response with `usage.modified` unpriced and charges it at twice
    `MaxCost`; R1 (m)'s interrupted stream undercounts nothing except when the request declares a server tool, where
    it is unmetered (`TestModifiedResponseIsUnpricedAndChargedAtMaxCost`).
  - 2026-09-30: R2's all-partial price table is unmetered under a cost budget and an infinite cost
    is clamped in the `limit` event (`TestCostBudgetUnmeteredWhenTablePricesNoModel`,
    `TestLimitEventSurvivesInfiniteCost`).
  - 2026-09-30: R27 Output's tier `cgroup` matrix notes name the selected plane mode and
    `EACCES` for file writes, read-deny and exec-deny, not fanotify's `EPERM` (`TestMachineMatrixTurnsOffWhatThisKernelCannotDo`).
  - 2026-09-30: R27's run-probe cache counts a probe syscall that failed with an errno other than
    EACCES, ENOSYS or EOPNOTSUPP, or went unanswered, as a faulted probe, so it is not kept for the boot
    (`TestPlaneSyscallErrnoFaultsTheProbe`).
  - 2026-09-30: R27's run-probe cache counts a plane attach refused with a transient errno as a
    faulted probe, so it is not kept for the boot (`TestTransientAttachFaultsTheProbe`).
  - 2026-09-30: R27's run-probe cache counts an unreadable LSM list as a faulted LSM-mode probe,
    reported as unknown, never as bpf inactive with a bare `lsm=bpf` fix (`TestUnreadLSMListIsNotAnInactiveBPF`).
  - 2026-09-29: (n) states that the uprobe path's peer is the agent-controlled `Host` header and
    accepts the forged-`Host` case.
  - 2026-09-29: R9's `Idle` reads the monotonic clock only while the lock is held, so a run from
    another boot no longer shows a bogus monotonic idle (`TestIdleUsesTheWallClockWithoutTheLock`); R18's Steps
    counts decision steps in `status` too (`TestStatusStepCountsDecisionSteps`); `drift --aggregate` keeps a models[]
    entry used only through ssl_request (`TestAggregateKeepsSSLRequestUse`).
  - 2026-09-29: a pipelined request past R11's depth is reported (e) instead of being
    passed over (`TestRefusedPipelinedModelRequestsAreReportedUnmetered`).
  - 2026-09-29: a capture drop counted after the run quiesced is a gap and leaves the end
    reason alone (`TestLostModelTrafficAfterQuiesceDoesNotChangeTheEnd`).
  - 2026-09-24: unreadable spend ends a budgeted run
    instead of passing silently; (a)-(d), (f) introduced.
  - 2026-09-24 (ADR 0035): h2 to a model or unlearned host (g) and a
    request unanswered at close, restart or stop (e) are reported; h2 was on the not-reported list.
  - 2026-09-24 (ADR 0036): a cut stream is charged
    `max_tokens` (m) instead of its input alone ("the documented shortfall"), or is unmetered with no bound (c);
    a size-cut compressed stream is reported (d).
  - 2026-09-24: an unreadable target is reported (h); an absolute-form
    target is metered by its URL.
  - 2026-09-24: a hook-queue drop is reported at once (j); it was a gap
    at shutdown only.
  - 2026-09-24 (ADR 0037): (e) is one rule for both paths, the forwarder's dial
    failure alone exempt (o); `max_tokens` is read off a prefix-only body (c); `CONNECT` is a tunnel (i), not
    an unreadable target.
  - 2026-09-24: `max_tokens`, usage and model are read by exact-case key, one
    scanner for derive and capture (c); an early `error` event spends nothing (k); a failed stream is read on
    for its usage (m); `/V1` and `;params` paths are unparsed (a).
  - 2026-09-24, docs cleanup: the amendments above folded into this rule and relettered. Old letter to new:
    (a)→(a), (b)→(b), (c)→(a)/(d), (d)→(e)/(f)/(d), (e)→(g), (f)→(e), (g)→(h), (h)→(j), old (i)→(e),
    (j)→(c)/(m), (k)→(i), (l)→(c), (m)→(k), (n)→(m), (o)→(a).
  - 2026-09-24 (ADR 0037 amendment): an unanswered request to a silent path is not
    reported (e), (l); a report after the agent's main process exited is a gap, not the run's end; server-tool
    requests with no fee in the table are unmetered under a cost budget (r).
  - 2026-09-24: the after-exit gap applies only once the cgroup is empty or tego's
    teardown has begun; a report while a descendant outlives the main process still ends the run.
  - 2026-09-29, capture-derive.md I1: a drop from the forwarder's emit queue is reported (s).
  - 2026-09-29 (capture-derive.md R25): (l)'s "outside `/v1`" is Anthropic's own host only.
- **R2 Cost.** `cost = Σ tokens/1e6 × ModelPrice field`, keyed by `PriceTable.Models[usage.model]`, added per
  response. The record carries two counters the upstream bills at rates of their own: `usage.cache_write_1h`, the
  1-hour part of `cache_write`, and `usage.server_tool`, server-side tool requests by name (e.g.
  `web_search_requests`). `cost` charges `cache_write - cache_write_1h` at `cache_write_per_mtok`,
  `cache_write_1h` at the model's `cache_write_1h_per_mtok`, and each server-tool request at the table's
  `server_tool_per_request` fee for its name. Neither has a default. `Cost` and `MaxCost` take
  `ledger.TokenUsage`. Breach when `CostUSD > ceiling.CostUSD` (with `UnpricedMaxUSD` added, below). Always
  rendered with the literal suffix `"est."` (GAPS.md C17).
  A partial entry prices only what it names: an entry with no `input_per_mtok` or no `output_per_mtok` prices
  nothing, and one with no `cache_read_per_mtok`, no `cache_write_per_mtok` or no `cache_write_1h_per_mtok`
  leaves unpriced a response that reports that counter above 0 (cache reads, 5-minute writes, 1-hour writes), and
  prices one that reports none of it; a missing cache price is never charged as $0 (fail closed).
  Unpriced spend: a response whose model the table does not name, whose model's entry is partial for a counter
  it reports (above), or that reports a positive count for a tool with no fee contributes 0 to `CostUSD`
  and emits `gap what=record why=unpriced-model` once per model, naming it in `binary`, for the first 32
  distinct models; the agent chooses `usage.model`, so past 32 one more line with no model stands for the rest
  and no more names are kept. Under a cost budget that response is not free spend: it is charged toward the
  ceiling at the table's highest price per counter over every model the table names (`PriceTable.MaxCost`,
  `State.UnpricedMaxUSD`; its 1-hour rate is the highest 1-hour or 5-minute cache-write price the table names,
  its fee for a tool with none the highest fee it names, and a cache read, 5-minute write or 1-hour write price that any complete entry
  does not name is at least its highest output price, the dearest per-token rate it knows, never $0 and never
  another entry's cheaper cache price), and the breach compares `CostUSD + UnpricedMaxUSD` with
  the ceiling. `CostUSD`, the estimate every surface shows, stays the table's own prices. Charging rather than
  ending the run at the first unpriced response: a model the table has not caught up with is ordinarily a real
  model at a real price, and the dearest price the table knows bounds it from above, so the run continues and
  stops no later than it should. A response reporting `usage.modified` (fast speed, a non-standard service tier,
  or geo pinning: capture-derive.md R29) is unpriced the same way, whatever its
  model, and is charged at `MaxCost` times 2, the fast-mode premium, the dearest the Messages API documents; the
  extra or unreadable iterations of a compaction or refusal fallback may omit attempts from the counts, so
  derive reports incomplete accounting and a token or cost budget fails closed instead of using that multiplier
  as a bound. Known observed usage and `modified` remain visible. A run with no price table cannot enforce a cost ceiling (E15), and the
  run's `no-price-table` gap says so. A table that names models but prices none (every entry lacks an input or output
  price) bounds nothing either: under a cost budget each response is reported unmetered ("price table prices no
  model"), as an unfed server-tool count is, never passed at $0. A cost that overflows to +Inf is recorded in the
  `limit` event clamped to the largest finite float, so the run's death always has its event (I1).
- **R3 Wall.** `wall = now.MonoNS - StartMonoNS` (monotonic, never wall-clock `ts`, §6 E7; on the exact clock
  source, §6 E27). Breach when `wall > ceiling.Wall`, detected only by `Tick`. Wall is a hard cap by definition: it
  counts from the run's start whatever the agent or the person is doing, typing included (amended 2026-10-26).
  A contract that sets `wall` and no `stall_after` gets the informational finding `[wall-hard-cap]`, which suggests
  `stall_after` for an interactive session.
- **R4 Stall.** `stall = now.MonoNS - LastEventMonoNS`. Breach when `stall > ceiling.StallAfter`, detected only by
  `Tick`. A `gap` event never resets `LastEventMonoNS` — dropped-event bursts must not masquerade as activity.
  Under `record: off` the producers keep only refusals, so the supervisor touches the watcher (`Watcher.Touch`) on
  every notification it answers in such a run: activity without a line, so an agent busy with allowed work is not
  killed for stalling. A supervisor line's `mono_ns` is its notification's receipt (supervisor.md R23a), so a
  syscall the supervisor relayed for a long time (a blocking connect, a unix relay) writes a line stamped at its start;
  under every record level the supervisor therefore touches the watcher at the finish of each notification held past
  its soft ceiling (`supervisor.Options.Late`, the time `finish` already reads), so a 50 s relay followed by 10 s idle
  is 10 s of stall, not 60 (*amended 2026-10-16*). A held ask is the watcher's held hook's
  (`WithHeld`), not this. The kernel recorder does the same with each of its samples under `off`
  (`ActivityReporter`), but under `off` it writes a sample only for an exec, a process's exit and a refusal: an
  allowed open (read or write), path change, regular-file create or connect returns before reserving one, so
  trace_proc stamps the run's slot of `tego_activity` for it instead, which the watcher pulls (below; amended
  2026-10-19: before, at tier 2 and above under `off`, an action the decision plane decides in the kernel, which
  the supervisor is not notified of, was no activity: a read, and on a plane row a write-open or path change, so an
  agent that only read or wrote files was ended as stalled, an open gap `compile` and `run` disclosed as
  `stall-reads-unseen` at `cgroup` and `bpflsm`: a pure writer under `record: off` and
  `stall_after: 2s` was ended `limit-stall` in a KVM guest at both root tiers; neither warns at a root tier under
  `off` now). What the supervisor is notified of is activity through its
  `Touch` at every tier: a connect, a send and an exec, which no plane hook decides, every write-open and path change on
  `cgroup`'s fanotify row or under a contract with an fs gate or ask entry, and every read-open under a read gate or an
  `fs.ask_read` entry (amended 2026-10-16: a pure
  connector, and a pure reader or writer under a read gate, ran to their end under `off` in the KVM guest, and the
  warning, which called them unseen, is now derived from what the run notifies). The uprobe source's half: an `off` run
  with a stall budget has the TLS probes placed for it alone, so that its calls stamp too, and captures nothing
  (capture-derive.md R4, activity-only; amended 2026-10-19: they were placed for no `off` run, and its model stream
  was no activity). A source can also be pulled rather than pushed: `Watcher.AddActivity` registers a reading
  of the run's latest activity (a CLOCK_MONOTONIC `mono_ns`, 0 for none) that every `Tick` takes, outside the
  watcher's lock, before its stall comparison. A reading raises `LastEventMonoNS` as `Touch` does and never lowers
  it; one below the run's monotonic origin, or taken before there is one, is a previous holder's of the same slot
  and is ignored; one past the clock's own reading is clamped to it, so a bogus value holds the window open for
  one `stall_after` at most (amended 2026-10-05: the hook a per-run kernel activity stamp is read through, one
  lookup a second and no ring; `TestTickReadsActivityBeforeTheStallCheck`, `TestActivityBelowStartIsIgnored`,
  `TestActivityNeverLowersLastEvent`, `TestGapStillDoesNotCountAsActivity`, `TestActivityRace`). The run's kernel
  recorder is that source whenever `stall_after` is bounded, in every record mode (`ActivityStamper`,
  `observe.Recorder.LastActivity`): its reading is the run's slot of `tego_activity`, a CLOCK_MONOTONIC stamp the
  BPF programs write, at most once a jiffy (1 to 10 ms), only for a run whose row carries `TEGO_RUN_ACTIVITY` (set by the
  backend exactly when `stall_after` is bounded): trace_proc for each allowed action `record: off` keeps no sample
  of, and the TLS probes for each call that moved bytes in every mode (capture-derive R9). It is 0, nothing, before
  the recorder has found the run's slot, for a recorder that found no row for the run (its `kernel-record-unavailable`
  gap says so), when the map cannot be opened (the run's log says so), after `Stop`, and on a failed read; a recorder
  that found the slot and could not open its ring reads no record but still reads the stamp, which needs the slot
  alone. The slot is zeroed at `Prepare`, and a stamp below the run's origin is ignored as above (amended
  2026-10-19; `TestActivityStampPerSlot`, `TestKernelActivityStampIsPulledUnderAStallBudget`,
  `TestLastActivityReadsTheRunsOwnSlot`, `TestLastActivityReadsTheSlotWhenTheRingCannotBeOpened`,
  `TestAReadingAgentUnderRecordOffIsNotAStall`). Where no stamp is read, a stall-bounded `off` run at a root tier
  that is busy only with what the stamp counts has no activity, and `compile` no longer warns of it
  (`stall-reads-unseen`): it is ended `limit` for stalling, never freed (GAPS C35). Model traffic in
  flight is activity in every record mode: a response that streams for longer than `stall_after` has a line at its
  two ends and none between, so when the run has a stall budget the forwarder's response relay and tunnel pumps
  touch the watcher for the chunks they carry, at most one per 100 ms (`StreamActivityReporter`, capture-derive.md
  R21); a model that sends nothing still stalls (amended 2026-10-05; `TestStreamActivityUnderAStallBudgetInEveryMode`,
  `TestIntegrationAStreamingModelResponseIsNotAStall`, `TestIntegrationASilentModelStalls`, at tier `landlock` under
  `summary` and `off`). An agent that talks TLS to its model directly is seen only by the uprobe source's probes, at
  tier 2 and above, where each call that moves bytes stamps the run's activity in every record mode while the probes
  are placed (above; amended 2026-10-19); at tier 1 its stream is no activity. Nor, at tier 1 under `summary` or `off`, is a read: read-opens never reach the supervisor there, so an agent that only reads is ended as stalled, which `compile` and `run` warn of (`stall-reads-unseen`, SEMANTICS §8; added 2026-10-16); in an `--observe` run neither, and at tier 2 and above under `summary` a read counts only when its aggregate is flushed, up to 5 s late, which they warn of below a `stall_after` of 10 s; under `off` there each allowed read, write-open, path change and connect stamps the run's activity at once (above; amended 2026-10-19: it was no activity there and warned at those tiers). While a published ask awaits its human (agent-contract R22) Tego itself holds the agent,
  so each `Tick` counts as activity (`WithHeld`): the wait, bounded by `ask.timeout`, is not a stall, and the stall
  clock restarts when it ends (amended 2026-10-05: a run with `stall_after` below the time the operator took to
  answer was killed as stalled while waiting, and the late `tego approve` found no live broker).
- **R5 Repeats.** On a `decision` carrying `tool_use`: same `(tool, input_hash)` as last time ⇒ `RepeatCount++`,
  else reset to 1. Breach when `RepeatCount >= ceiling.Repeats`. `Limits.Repeats int` (YAML
  `repeats`) is a contract field, default 5.
- **R6 Precedence.** `Observe` and `Tick` may race on the same `mu`; the first to set `tripped=true` wins; never
  two `limit` events for one run (I1).
**Status state machine** — checked in this order, first match wins:
- **R7** `!lockHeld ∧ run_end present` ⇒ **Done**. `!lockHeld ∧ no line at all` ⇒ **never started** (§6 case 1),
  which is not a finding, checked before R8.
- **R8** `!lockHeld ∧ run_end absent` ⇒ **Lost**.
> **Runtime grants are not drift.** The supervisor allows a query to a configured resolver ungated by `net.allow` (`docs/p0/supervisor.md` R14), stamping `net.resolver`. `Report.Drifted()` skips any rule `agent.IsRuntimeRule` names, because counting one as an undeclared entry made every run that resolves a hostname exit 1, and a finding that fires on every run carries no information. The bucket is still printed: the traffic stays visible, only the verdict changes. The skip covers what a grant allowed, never a refusal under its name (*amended 2026-10-25*, ADR 0064): the harness hook's grant refuses every other vector of the tego binary under `exec.harness-hook[<tego>]`, and such a refusal drifts like any other (`TestRuntimeRuleRefusalIsDrift`, `TestViewsReadHarnessHookFixture`). Every other undeclared name, `unmatched` and the read-failure markers included, still drifts — an action whose argument could not be read is an action whose conformance was not established, and saying "no drift" there would overclaim.

- **R9** `lockHeld ∧ now−LastEventMonoNS ≥ stallAfter` ⇒ **Stalled**, unless a recorded ask is still pending and `now−LastEventMonoNS < stallAfter + 1h`, which is **waiting approval** (amended 2026-10-05, R4). The bound is the largest `ask.timeout` (SEMANTICS §6; `run_start` does not carry the run's own): the broker answers every ask by its timeout and the watcher kills `stallAfter` after that answer, so an ask still unanswered past both is no live wait but a wedged or stopped launcher (a foreground `tego run` suspended with Ctrl-Z), and reports **Stalled** (amended 2026-10-05: unbounded, such a run read waiting approval for as long as its lock was held). The subtraction is monotonic, as R3 and R4 are: the wall clock steps, and a step forward (NTP, a laptop resuming from suspend) would report a healthy agent as stalled while a step backward would hide a stall that is real. It would also disagree with `limits.Watcher`, which measures the same stall on `MonoNS` and is what actually kills the run. `Snapshot.IdleClock` (`monotonic` / `wall`, `idle_clock` in `--json`) names the clock used. A monotonic reading is comparable only within one boot of one host; when `lockHeld` the writer is a live process on this host, so its readings are from this boot and the comparison is always valid. `Idle` falls back to the wall clock only when the readings cannot be subtracted (another boot, a copied ledger, or `MonoNS` 0 per E20) — cases where the run is `done` or `lost` and R9 never runs, so `Idle` there is a display figure. A wall fallback never reports a negative idle. `LastEventMonoNS` is the watcher's, not the ledger's alone: the
  activity it counts without a line (R4: a supervisor answer or a kernel sample under `record: off`, a relayed model
  chunk in any mode) is published by its `Run` loop, at most once per tick and only when it rose
  (`WithActivityPublisher`), to the run directory's activity sidecar (§3), and while `lockHeld` `Derive` measures
  `Idle` from the newer of the last non-gap line and the sidecar's reading, the sidecar's taken only when the clock
  has reached it. `Snapshot.IdleFrom` (`ledger` / `activity`, `idle_from` in `--json`) names the source, and
  `Since` is the sidecar's reading on the wall clock at `now` when it is the source. A held tick (a pending ask) is
  not published: the approval rule above ranks it (amended 2026-10-05: status read the ledger alone, so a `record:
  off` run busy with allowed work, or a model response streaming for longer than `stall_after` in any mode, read
  **Stalled** while the watcher did not kill it; `TestASidecarNewerThanTheLedgerIsActivity`,
  `TestASidecarKeepsAnOpenRequestWaitingModel`, `TestASidecarIsUsedOnlyWhenItCanBeCompared`,
  `TestRunPublishesActivityWithoutALine`, `TestTheWatcherPublishesToTheRunsSidecar`, `TestStatusJSONGolden`).
- **R10** `lockHeld ∧ ∃ ssl_request with no ssl_response sharing its request_id, newer than the last response` ⇒
  **Waiting model** (P0-DESIGN §5).
- **R11** `lockHeld ∧ last decision.tool_use != "" ∧ no ssl_request since` ⇒ **Waiting tool** (P0-DESIGN §5).
- **R12 (fallback)** `lockHeld` and none of R9-R11 ⇒ **Running**. `stallAfter` here is the run's own compiled
  `Limits.StallAfter`, carried by the optional `run_start.limits{tokens,cost_usd,wall,stall_after,repeats}` block
  (legal per VERSIONING.md §2, "only optional fields may be added"; defined in `record-ledger.md` §2.2). A key is
  present exactly when the run had that budget and `0` is a budget (E16), so a `stall_after` of `"0s"` is the run's
  own ceiling of zero — the one `limits.Watcher` ends the run on at its first idle tick — and makes a live run
  **Stalled** by R9; only an absent `stall_after` falls back to the machine default (1h), marked
  `StallAfterSource:"machine-default"` in `--json`. The runtime writes a zero budget into the block.
- **R-cap Capability line.** `status <run>` prints one `capabilities: <line>` under the table, and `--json` carries
  `tier` and `capabilities` as recorded: the run's own capability line from `run_start.capabilities`
  (`record-ledger.md` §2.2), rendered as `<tier> <present>/<rows>; absent: <row>, …` with the absent rows by
  `pkg/spec/backend` name in `spec/backend/CAPABILITIES.md` order, and any row this binary does not know after
  them, sorted. A `run_start` without the line renders as `not recorded` — never as a run that could do nothing —
  and `--json` omits the key. A listing (`--all`) leaves the line out: it is one long line per run and a table of
  runs is read for their states. The line is read, never recomputed: what a tier can do on this machine is
  `doctor`'s matrix, what one run had is this. *Amended 2026-10-05 ([ADR 0041](../adr/0041-race-free-supervisor-decisions.md)
  D7):* a run whose `run_start.best_effort` names cells gets a `best effort: <id>, …` line under it (and
  `best_effort` in `--json`): the cells decided on copied syscall facts and continued, never counted as enforced
  (gate cells, and `deny_write/default` where no plane decided the run's built-in `deny_write` targets, D1 (a)); `events` shows `best_effort=<id>,…` on the run_start line, and `drift` lists them (`best_effort` in
  `--json`; the union over `--aggregate`), reported and never counted as drift. A run with none says nothing
  (`TestStatusAndEventsShowBestEffortCells`, `TestDriftReportsBestEffortCells`).
**Drift**
- **R13** Group `exec/fs/net/mcp` events by `(kind, rule)` (`"unmatched"` its own bucket, SEMANTICS §2); count
  `verdict` into `Allow/Ask/Refused/Observed`. The dedicated `refused`-kind event ("mirrors the refused action")
  is **never** counted here — only the action event's own `verdict=refused` is, to avoid double counting one
  occurrence twice (non-duplication contract not explicit in record/v1/README.md; flagged under Open questions).
  *Amended 2026-10-16 ([ADR 0057](../adr/0057-fs-ask-read-and-alternates.md) D1):* an `fs` line a person's
  alternate completed (`authority: human`, `verdict: allow`, `alternate_for` set) is counted into the rule's
  `Alternate`, never its `Allow`: the rule held the open and what it was asked for was not granted. `Total` includes
  it, so the buckets still partition the ledger; the table gains an `ALTERNATE` column and `--json` an `alternate` key
  per rule, and R17 sums it.
- **R14 Undone**: declared FS/Net/Exec entries with zero total events. Once name entries are enforced (ADR 0043), each
  is declared under every name its refusals carry, read-only as a `deny_read` entry is: a declared glob (its own
  entry even when it matched no file at compile) and the built-in `.env` list's label under each scope's spelling
  (declared, not the author's). A `models[]` entry is one Net row,
  `models[<provider>]`, under both names the record gives it: the refusal of a direct connection to it carries
  `models[<host>:<port>]` (SEMANTICS §1) and counts in that row, and an `ssl_request` whose `endpoint` is its
  provider is its use, which keeps it out of Undone though it counts in no verdict column, whichever of the
  forwarder or the uprobes recorded it. A declared `fs.deny_read` or `fs.watch` entry with zero events in
  a run whose record could not carry a read — `run_start.capabilities` has `record.reads_mmap_chmod: false`, or
  the run wrote `gap what=record why=unprivileged-tier` (tier 1 without `record: full`, SEMANTICS §7) — is
  **UnobservableFS**, not Undone: printed (`fs entries not observable`, `unobservable_fs` in `--json`) and never
  drift. Reads are the only events those entries name and a refused read leaves no line either, so reporting
  them "declared, never used" and exiting 1 invited deleting a protection the kernel had just enforced. Likewise every other declared entry with zero events in a run whose capability line has
  `record.exec_open_connect: false` (`record: off`: refusals only) is **UnobservableRecord**, not Undone:
  printed (`entries not observable`, `unobservable_record` in `--json`) and never drift. R17 aggregates both as
  it does UnobservableMCP.
  **R15 UnusedMCP**: declared `mcp[].name`
  with zero matching `mcp` events **in a run whose record could have carried one**: its `run_start.parsers` names
  an MCP producer (the `mcp` key, a version other than `""` or `"0"` — `drift.MCPTransports`), or the run recorded
  at least one `mcp` event. Otherwise the server is **UnobservableMCP**: printed (`mcp servers not observable`,
  `unobservable_mcp` in `--json`) and never drift. A producer that derives `mcp` events — P0's minimum is an exec
  matching a declared `mcp[].command` — names itself in `parsers`. The runtime writes `parsers["mcp"] = "exec"` —
  a derivation, not a protocol parser's version, since the MCP parser is P1 — exactly when the supervisor answers
  the run's `execve` notifications (every tier that installs the tier-1 seccomp filter, tier 2's inherited one
  included) and the run's record mode is not `off`, which drops an allowed exec and the `mcp` event riding on it
  before either is emitted. A run without it — tier 2 with no inherited filter, tier 3, `record: off` — reports
  declared servers it saw no event for as not observable, never unused.
  *Amended 2026-10-19 (agent-contract R16a, capture-derive R41):* observability is per transport, since
  each producer sees one kind of server. `parsers["mcp"]` is the `+`-joined list of the run's producers: `exec`
  (above) covers stdio servers (`command:`), and `mcp/1` — written when the uprobe source is the run's capture and
  the record mode is not `off` — covers HTTPS servers (an `https://` `url:`), whose `initialize` and `tools/call` it
  derives. A plain `http://` server's exchanges pass no TLS library, so no producer covers it (capture-derive R41):
  an idle one is UnobservableMCP under every producer, never UnusedMCP. Any
  other value but `""` and `"0"` is a ledger's from before this amendment and covers stdio servers
  (`drift.MCPTransports`). An `mcp` event proves its own transport's producer ran (a line with no readable
  transport counts as stdio). A server with no `mcp` event is UnusedMCP when its transport is covered and
  UnobservableMCP otherwise: an idle HTTP server in a run whose only producer is `exec` is not observable. The
  net rule an HTTP server's url derives (`NetRule.MCP`, `mcp[<name>]`) is the server's: it is reported idle under
  `mcp` alone, never in `Undone` as a net entry the author declared. *Amended 2026-10-19:* an `http://` server under `mcp/1` was UnusedMCP, which made the report drifted for a
  server the recorder could never have seen, and the derived rule was listed in `Undone` beside it.
- **R16** `HashChanged = ContractHash != CurrentHash`, `CurrentHash` = sha256 of the run directory's
  `contract.yaml` copy recompiled with *today's* compiler — not a re-fetch of a possibly-moved source file, so a
  drift report always states "what this run actually used", and a compiler upgrade also shows as drift. The copy
  is the canonical merged contract, loaded with `extends:` sealed and compiled against `run_start.cwd` (§4
  `drift.ComputeCtx`): a profile edited after the run, or drift run from another directory, is not a changed
  contract.
- **R17 Aggregate**: sum `RuleCount`s by `(kind, rule)`; `Undone`/`UnusedMCP` are read off the sum (declared in some run and used in none; a run with no
  table declares nothing and changes nothing); a server no run used that is not unused in every run — some run could not
  observe it (R15) — is `UnobservableMCP` for the agent, since that run may have started it; `HashChanged` true if
  any two runs differ or any one run's R16 comparison is changed (its `CurrentHash`, the first such run's, is the
  one shown), listing distinct hashes with counts; gap tallies (R34) summed by what and why.
- **R17a Fileless and dropped execs** (*added 2026-11-02*, GAPS C30's condition): drift reads the `exec` payload's
  `fileless` and `dropped` keys (`record-ledger.md` §2.2) and lists each image they flag by the line's `path` —
  `fileless`, an anonymous image (a memfd, another `anon_inode:`, a file unlinked since it was opened) named by the
  kernel's raw spelling; `dropped`, an image under a write entry whose inode changed during the run, drop-and-execute
  (in a run with command rules also a `#!` interpreter or a loader's program it loads) — with its lines counted by
  verdict as R13 counts a rule's, **whatever the verdict**: an allowed one ran, a refused one is an attempt the run
  stopped. Every source's `exec` line is read; a line with both flags is in both lists, and the `refused` line that
  mirrors a refused exec carries neither, so nothing is listed twice. A path the ledger stored apart (`path_blob`, R10 of `record-ledger.md`) is named
  `path_blob:<sha256>`. The table prints `execs of an image with no file (fileless): <path> (refused x1), …` and
  `execs that ran a file the run wrote (dropped; the program named, its #! interpreter or a loaded binary): …`, each name escaped for the terminal. A `dropped` entry names the exec line's own `path`: under command
  rules the file the run wrote may be that program's `#!` interpreter or the binary a loader ran, not the path named; `--json` carries
  `fileless_execs` and `dropped_execs`, `[]` when empty, each entry `{path, allow, ask, refused, observed}`. A list
  keeps the first 32 images it sees, since the names are the agent's to choose and a report holds O(rules) (§6
  case 10); the execs of any other image are counted (`fileless_more`, `dropped_more`, absent at 0; `+N execs of
  other images` in the table). R17 sums the lists by path under the same bound. **Reported, never drift on their
  own:** whether such an exec kept to the contract is its line's verdict and rule, which R13 counts and R25 reads — a
  refused one drifts as any refusal does, and an allowed fileless image is under no declared entry, since none can
  name one — so what the lists add is a dropped image a declared entry allowed: a binary the run built and then ran,
  the test binary `go test` writes, a package's installed script. That is the contract at work, and exit 1 on it
  would fire on nearly every coding run and say nothing. `TestDriftListsFlaggedExecs`,
  `TestFlaggedExecIsNoDriftOnItsOwn`, `TestFlaggedImagesAreBounded` (`internal/check/drift`),
  `TestDriftFlaggedExecsGolden` (`internal/cli`).
**Measure**
- **R18** `Steps = max(attribution.step, decision.step)`, 0 if none carry a step. A decision's own step is the model's
  turn counter and a text-only turn has no action to attribute, so `status` (`STEP`, `step`) and `measure` both read
  the higher of the two and agree on one run.
- **R19** `Refused` = count of action-kind events with `verdict=="refused"` — same non-duplication rule as R13 —
  plus every `refused` line that mirrors no action: the supervisor writes keyring and mount-family refusals as
  `refused` lines alone, and `drift` counts those in a fifth section, `other`. A `refused` line is a mirror only
  when it directly follows (seq − 1) an action refused under the same rule, which is where the pipeline writes one.

**Views**
- Every human-readable view escapes the ledger text it prints for the terminal (`record.Printable`: C0/C1 controls, DEL, every invisible format character (Unicode Cf: bidi overrides, isolates and marks, zero-width characters), line and paragraph separators, the tag block U+E0000-E007F, invalid UTF-8): `events`, `status`, `drift`, `measure`, the gap line and `compile`'s print, `compile --test`'s rows included (name, resolved paths, failure text). `--json` stays byte-exact.
- `events --json` decodes each line as the table does, and refuses what the table refuses.
- A gap that names a binary counts that binary's processes, shown as "N processes", not "events lost".
- `status` measures idle from the largest `mono_ns` of a non-gap line, as the limits watcher's stall check does (the §11 condition on this point is met).
- **R20** Tokens/cache/cost via `ledger.Usage` (§4), identical formula to R1/R2, never read from a live `Watcher`
  (works on a still-growing or crashed-mid-record ledger too). The table's cost is rendered by `measure.CostText`:
  to the cent from $0.10 up (`$0.28`, `$1234.57`), and below that with two significant digits down to a
  micro-dollar, the precision `--json`'s `est_cost_usd` keeps (`$0.0021` for $0.002127, `$0.050`, `$0.000012`);
  zero is `$0.00`, and an amount above zero that rounds to no micro-dollar is `<$0.000001`, never a zero.
  `measure --json`'s `est_cost` label is the same text (`"$0.0021 est."`, where it read `"$0.00 est."`), and
  `est_cost_usd` stays the number to parse. The
  number of decimals and the printed digits come from one rounding of the exact value (`strconv` to two
  significant digits, then to that many decimals), so `$0.0096` stays `$0.0096`, `0.00095` reads `$0.00095` and
  5e-7 reads `<$0.000001`; choosing the decimals by a separate `math.Round` once printed those as `$0.010`,
  `$0.0009` and `$0.000000`. It was
  always two decimals, so a run that ended at its `cost_usd` limit of $0.002 read `cost $0.00 est.`, as if free,
  beside a limit event that said 0.002127. More digits for every amount, or scientific notation, were rejected:
  a cost of dollars needs no fraction of a cent, and a person reads `$0.0021` faster than `$2.1e-03`
  (`TestCostTextShowsSmallCosts`).
- **R21** `Wall = last_event.MonoNS - run_start.MonoNS` if `run_end` present, else `now - run_start.MonoNS`.
- **R22** `IdleMax` = largest gap between an event's `MonoNS` and the largest `MonoNS` of the events before it
  (a producer's line keeps its capture-time reading, so `MonoNS` can go back along `seq`; a reading that goes
  back opens no window and starts none), **excluding** any gap that straddles a `gap`-kind event (a lost-events
  window is "unknown", not "idle" — already surfaced by the gap line, R34).
- **R23** `Repeats` = the longest consecutive same-`(tool,hash)` run anywhere in the ledger (historical maximum
  for reporting; distinct from `Watcher`'s live current streak used for the breach decision, R5).
  *Added 2026-10-16 ([ADR 0057](../adr/0057-fs-ask-read-and-alternates.md) D1):* `measure` also reports
  `Alternates`, the number of `answer` lines carrying `alternate` (a held file open a person answered with another
  file), as the `alternates` row after `repeats` and the `alternates` key after `repeats` in `--json`. It is read off
  the answer lines, which every record mode keeps (the delivered open's `fs` line is not written under
  `record: off`), and it is neither in `Refused` (R19: the agent's open succeeded, on the person's file) nor an
  approval.
- **R-res Resource peaks** (`record-ledger.md` §2.2 `run_end.resources`). `measure` and `status <run>` show what
  the run's cgroup said the run used, read from its `run_end` and never measured now (the cgroup is gone by
  then): `measure` as five rows after `repeats` — `memory peak` (IEC with the exact bytes), `pids peak`, `cpu`
  (`usage_usec` with its user and system halves), `cpu throttled` (`nr_throttled` times for `throttled_usec`) and
  `memory events` (`high`, `max`, `oom`, `oom_kill`) — and `status <run>` as one `resources: <line>` after the
  capability line, the same five joined (`internal/check/resources`, one rendering for both). A key the record
  lacks renders `unknown`, never `0`, and a `0` it carries renders as the kernel's zero (`docs/VERSIONING.md` §2);
  a `run_end` with no `resources` object (an older binary, a run that failed before its cgroup existed) renders
  every field `unknown`, and a run with no `run_end` yet reads `unknown until the run ends`, in `status`'s line
  and in each of `measure`'s five rows, since the peaks are read once, at shutdown, and a bare `unknown` would
  read as a kernel that told nothing. `--json` carries `resources` as recorded, the ledger's own object and so
  keys this binary does not know included (an additive key a newer binary writes, `docs/VERSIONING.md` §2), a
  key absent where the record has none and the whole object absent when `run_end` carried none or is not
  written yet, as `capabilities` is (R-cap). `status --all` leaves the line out, as it does the capability line
  (`TestResourcesFromRunEnd`, `TestResourcesJSONIsTheRecordedObject`,
  `TestRecordedKeepsKeysThisBinaryDoesNotKnow`).
- **R-ledger Ledger size** (*added 2026-10-26*). `status <run>` ends with `ledger: <size> of <ceiling>
  (record.max_run_bytes)`, or `ledger: <size>, no ceiling`: the size of the run's `events.jsonl` and blobs when
  status read them (what the ceiling is compared against) and run_start's `limits.ledger_bytes`, the machine's `record.max_run_bytes` the run started
  under (record minor 22). A run that reaches it is ended as a limit, `which=ledger_bytes`, exit 124. `--json`
  carries `ledger_bytes` and `ledger_ceiling_bytes` (absent for none); `status --all` leaves the line out
  (`TestDeriveDirReadsTheLedgerSize`, `TestStatusTableColumns`).
**CLI**
- **R24** Config precedence exactly spec/config/v0: built-in < `/etc/tego/config.yaml` < `~/.tego/config.yaml`
  < `$TEGO_CONFIG` < contract; ceilings only lowered, settings last-layer-wins; resolved once via one shared
  `config.Load` per invocation: a bare run id's ledger root, `measure`'s prices, `drift`'s tables and `events --verify`'s
  anchor all read that one load, and a `no such run` keeps its layer diagnostics.
- **R25** Exit codes (RUN-IDENTITY.md): `status/drift/compile --test/events --verify` → 0 clean, 1 a finding
  (`drift` found drift, `status` shows `stalled`/`lost`, `compile --test` has a failing row, `events --verify`
  found a ledger that does not verify); usage errors → 2 (`compile --upgrade` among them until contract version 1
  exists, R29; a `stop --grace` that is not a positive duration); Tego's own bug, or a read that failed before
  any verdict (an unreadable ledger or anchor), → 125. `doctor --require <tier>` unmet → 211 (FEATURES.md R16 /
  kill test 6; RUN-IDENTITY.md names 211 for a machine below `--require`; `doctor.Report.ExitCode`), and 1 for a
  `doctor` that finds no tier at all. A `<run>` argument that is neither a directory nor shaped like a run id, or
  a run id naming no directory under the ledger root, is a usage error (2, `[usage]`, "no such run") in every
  command that takes one — `events`, `events --verify` (when no anchor line names it either), `drift`,
  `measure`, `status`, `stop`. For `events`, `drift` and `measure` a directory the caller named that holds no
  `events.jsonl` (the project, `/tmp`, the ledger root) is that same typo, 2 `[usage]` "no such run: the
  directory holds no events.jsonl"; it is 125 for `events --verify`, where an empty directory is a ledger that
  does not verify, and a directory the caller named that holds some other unreadable record stays 125.
  A bare run id always names the run under the ledger root, never a directory of that name in the current
  directory (the agent knows its id and can write the project); `./<id>` names the local directory.
  An `events.jsonl` that holds no `run_start` (empty, a torn line alone, a first line of another kind) is no
  run: `events`, `drift`, `measure` and, when no anchor line names the run, `events --verify` exit 125 `[io]`
  "no run record", never an empty report of a complete run. Bytes after `run_end` that are not a record exit
  125 `[ledger-corrupt]` from `events`, `drift` and `measure`, naming their byte offset, as `events --verify`
  finds them (1). `status ""` (an unset variable) is 2 `[usage]`, not a listing of every run.
  A command that would exit 0 but could not write all of its output (a failed or short write to stdout or
  stderr, `ENOSPC` on `>/dev/full`) exits 125 `[io]` "tego: write output"; a nonzero exit is kept. `run` is
  exempt: its exit is the agent's (RUN-IDENTITY.md, "Warnings never change the code") and its stderr is tego's
  warnings, so a stderr it cannot write never turns the agent's 0 into 125; `run -h` still requires its usage
  text. (*Amended 2026-10-05:* the output check, added 2026-10-03, applied to `run` too.)
- **R26** Diagnostics: `<file>:<line>[:<col>]: <message> [<code>]`; `compile`/`compile --test` codes are
  `agent.Diagnostic`, refusal codes are `record.Reason` — never mixed on one line.
- **R27 Doctor probes, exact order, first-class syscalls** (`doctor.Run`'s `Results[0..7]`):
  - **D1 kernel**: `uname(2)` → parse `release` as `major.minor.patch`; compared against ARCHITECTURE §14's
    per-mechanism minimums (`cgroup.kill` 5.14, ring buffer 5.8, `pidfd_getfd` 5.6, `NEW_LISTENER` 5.0, `ADDFD`
    5.9, `ADDFD_FLAG_SEND` 5.14, Landlock ABI 1 at 5.13).
  - **D2 BTF**: `open("/sys/kernel/btf/vmlinux", O_RDONLY)`; `ENOENT` ⇒ no tier-2/3 program loads possible.
    The file is then parsed (once per process, one parse shared with D7 and the plane, since `btf.LoadKernelSpec` keeps none, so the program loads of a run that
    follows do not parse it again), and a BTF that will not parse fails D2. Every kernel type, member
    and enum value that the embedded objects read through CO-RE must be in it. The list comes from the objects'
    own relocations (enforce-cgroup-observe.md E31). A missing one fails D2 with its name, for example
    `task_struct.start_boottime`. An existence relocation (`field_exists`, `type_exists`, `type_matches`,
    `enumval_exists`) is no need: the loader resolves one to 0 on a kernel without its target and never fails the
    program for it.
  - **D3 cgroup v2 delegation**: `statfs("/sys/fs/cgroup")` magic `0x63677270`; `access(2) W_OK` on the invoking
    uid's delegated `cgroup.procs`/`cgroup.subtree_control`, confirmed by a scratch `mkdir`+`rmdir` one level below.
    Between the `mkdir` and the `rmdir`, `access(2) W_OK` on that scratch cgroup's `cgroup.kill` — the file is
    write-only and exists only below the cgroup root, so a fresh cgroup is the only place the question can be
    asked. It is asked here rather than inferred from D1's `cgroup.kill` 5.14 row because the release number is
    a guess in both directions (a backporting distribution has it in a "5.14"; the runtime's rule is that D1 is
    advice and the functional probes are the answer), and because `cgroup.kill` has no substitute: without it a
    stop or a limit breach falls back to the freeze/enumerate/`SIGKILL` loop that raced forks for runc and crun.
    Last, `cpu`, `memory` and `pids` must all be enabled in the delegated root's `cgroup.subtree_control`. Any
    one of these can be D3's sole failure. When `cgroup.Detect` itself refuses, D3's detail and fix are that
    refusal's own `Diagnosis` and `Remedy` (every Detect refusal is a `*cgroup.DetectError`), not a canned
    `Delegate=` line and not prose D3 splits apart: `ErrNotDelegated` covers more than one cause, and case 39
    (`runtime-launch.md`, a cgroup namespace looking at the host's `/sys/fs/cgroup`, asked of the uid-0 branch as
    well) is cured by that namespace's own cgroup2 mount, which no `Delegate=` drop-in changes.
    Right after `Detect`, D3 asks `FS.CanPlace` whether this process can put a process into the root at all
    (`runtime-launch.md` case 41), and its refusal is reported the same way, `Diagnosis` and `Remedy`. A login
    over ssh or a service runs outside its `user@<uid>.service` and finds everything above true of it, the
    scratch cgroup included, while the kernel refuses every agent placed there; without this question doctor
    would report tier `landlock` where `tego run` then fails in `clone3` with `EACCES`.
  - **D4 Landlock ABI**: `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` → the ABI number;
    `ENOSYS` ⇒ tier 1 unavailable.
  - **D5 seccomp ADDFD/SEND self-test**: on a throwaway locked OS thread that is never the main thread and has
    ended before D5 returns (below), install `SECCOMP_SET_MODE_FILTER |
    SECCOMP_FILTER_FLAG_NEW_LISTENER` notifying one syscall, trigger it, then `SECCOMP_IOCTL_NOTIF_ADDFD` with
    `SECCOMP_ADDFD_FLAG_SEND` from the prober. `EINVAL` on a release D1 reads as below 5.14 ⇒ the kernel lacks
    `SECCOMP_ADDFD_FLAG_SEND` and race-free `ask` is unavailable. At or above 5.14 the release has every piece
    the round trip uses, so `EINVAL` there is a kernel built without `CONFIG_SECCOMP_FILTER` (its
    `seccomp(SECCOMP_SET_MODE_FILTER)` is an `EINVAL` stub on every release) or a defect in the probe, and D5's
    fix names those rather than a kernel upgrade; on a release D1 cannot parse it names both. D5 also
    reads `/proc/sys/kernel/yama/ptrace_scope` and reports it on the same line, because a filter the kernel
    installs is worth nothing if the supervisor may not then read the agent: `process_vm_readv(2)` for every
    sockaddr/path/argv, the `/proc/<pid>/mem` fallback, and `pidfd_getfd(2)` for the listener and for every
    completed connect are all `PTRACE_MODE_ATTACH_REALCREDS` operations, which is exactly the access mode Yama
    gates. Scope 1 (the Debian/Ubuntu default) is safe only because the supervisor is the agent's own parent and
    Yama exempts a descendant; **scope 2 keeps no such exemption and admits only `CAP_SYS_PTRACE`, and scope 3
    admits nobody, so scope ≥ 2 without `CAP_SYS_PTRACE` blocks every enforcement tier** — the launch aborts at
    `pidfd_getfd` with `ErrNotifyFDUnavailable`, and a `doctor` that still reported tier `landlock` would be
    promising a sandbox no run can get. An absent sysctl (no `CONFIG_SECURITY_YAMA`) reads as scope 0; an
    unreadable or out-of-range one fails closed, because the cost of guessing wrong is a run that reports a
    working sandbox while refusing every connect. **A round trip that fails on its own blocks every enforcement
    tier too**, and is listed beside Yama's reason rather than hidden behind it: every tier installs the tier-1
    `NEW_LISTENER` filter, so a filter this process may not install is one no launch can install either —
    `EACCES` from an outer filter, or `EBUSY` when a listener already sits on this process's filter chain
    (seccomp(2): the kernel allows one), for which D5's fix names the other supervisor rather than a newer
    kernel. This is fail-closed for `EINVAL` as well: P0's supervisor never uses `ADDFD` (it answers with
    `CONTINUE`, an errno or a relayed result; `ADDFD` is the P1 ask package's), but whatever the release, an
    `EINVAL` round trip is a filter no launch can rely on, and `run` refuses it through D5 itself (below 5.14,
    through D1 as well). `ENOSYS` from `seccomp(2)`, on any release, is configuration too — the syscall is a
    `cond_syscall`, absent from a kernel built without `CONFIG_SECCOMP`, and an outer filter can answer it with
    `ENOSYS` — so D5's fix names `CONFIG_SECCOMP=y` and `CONFIG_SECCOMP_FILTER=y`, then that sandbox, not a
    newer kernel or a tego bug. `tego run`
    selects from the same derivation (R27 Output), so `doctor` and `run` agree about it. A signal is not a verdict:
    the kernel takes the notification back from a task a signal reaches and restarts that task's syscall under a new
    id (seccomp_unotify(2)), and a signal that reaches the prober inside its `ADDFD` ioctl restarts the ioctl against
    a notification its first try had already marked answered, while the notified thread returns 0 from a reply
    nobody sent. A sound round trip can therefore end in `ENOENT` at `RECV` or at `ADDFD`, or in `EINPROGRESS`,
    `ESRCH` or `EINTR` at `ADDFD`, with nothing wrong in the kernel (`SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`, 5.19,
    shuts the notified thread's window from `RECV` on, and leaves open its wait before `RECV` and the prober's own
    ioctl; a kernel without the flag leaves all three), and D5 failed once in a guest boot with `EINPROGRESS`, which
    leaves `doctor` and `run` with no tier. D5 therefore makes the whole round trip again, on a new
    throwaway thread with its own filter and listener, up to five times while its error is one of those. Any other
    errno ends it at once: it is the kernel's answer, and an `EINVAL` on a release below 5.14 must still name the
    kernel floor. An interruption on each of the five attempts fails D5 with the errno and the number of attempts,
    and its fix is to re-run `tego doctor` and report it if it fails the same way again, on every release, not a
    kernel upgrade (`TestSeccompRoundTripSurvivesASignalBetweenRecvAndAddfd`,
    `TestSeccompRoundTripSurvivesSignalsAtTheProbersAddfd`, `TestSeccompRoundTripSurvivesSignalsAtTheNotifiedThread`,
    `TestSeccompRoundTripRepeatsAnInterruptedAttempt`, `TestSeccompRoundTripAttemptsAreBounded`,
    `TestSeccompRoundTripDoesNotRepeatTheKernelsAnswer`). The throwaway thread:
    Go ends a thread whose goroutine exits locked to it, filter and all, except the main thread, which it parks
    for good instead. D5 on the main thread would leave its filter and `no_new_privs` there for the life of the
    process, `tego run`'s included. A parked thread forks nothing, so no child inherits them, but
    `/proc/self/status`, which shows the main thread, would read `Seccomp: 2` and `NoNewPrivs: 1` for the rest of
    the process (the launcher's clone diagnostic reads that `Seccomp` line). So a D5 goroutine that lands on the
    main thread hands the probe to a goroutine of its own and gives the main thread back unchanged, and D5 returns
    only once the thread that carried its filter has ended (`tgkill(2)` with signal 0 answers `ESRCH`); a thread
    that has not ended within 5 s fails D5 like any other round trip that did not complete
    (`TestSeccompProbeLeavesNoThreadFiltered`, `TestThrowawayThreadIsNeverTheMainThread`).
    D5's wait for the notification counts only `POLLIN`: `seccomp_notify_poll` answers `EPOLLERR` alone when its
    interruptible lock loses to a signal pending on the prober (the supervisor's rule, supervisor.md), and that wait
    is asked again until the 5 s run out; `POLLHUP` or `POLLNVAL` fails D5 (`TestSelfTestPollErrIsNoNotification`).
  - **D6 LSM/`bpf` activation**: `lsm_list_modules(2)` (6.8+, unprivileged) first; `ENOSYS` ⇒ read
    `/sys/kernel/security/lsm` (CSV); unavailable ⇒ parse the kernel log for `LSM: initializing lsm=`; as root,
    follow with a functional probe (a counting BPF LSM program attached to the `file_open` hook, open a
    throwaway file, assert the counter incremented, ARCHITECTURE §10). It has to be an LSM program: an `fentry`
    counter on `security_file_open` runs whether or not `bpf` is an active LSM, so it could not tell the two
    apart.
  - **D7 program load tests**: per tier-2/3 hook, resolve its attach point in D2's BTF as the type it is (the
    `security_*` function for `fentry`, `bpf_lsm_<hook>` for `lsm`, the `btf_trace_<tracepoint>` typedef for
    `tp_btf`), then `bpf(BPF_PROG_LOAD)` + `bpf(BPF_LINK_CREATE)` a fresh load of the embedded object's own
    program for that hook into doctor-owned prog/map fds and a doctor-owned link (never a handle to an existing
    production pin), then detach. An optional hook (`fexit/security_file_truncate`, `cgroup/connect_unix`,
    `cgroup/sendmsg_unix`) is `absent` when the test the backend applies says so, never by kernel version (a
    distribution backports): for the fexit hook, the function is not in the kernel's BTF; for the two unix hooks, the
    backend's own probe program with `BPF_CGROUP_UNIX_CONNECT` does not load. Its release is advice in the row's
    detail only. D7 returns one `Result`, whose detail names every failing hook after
    `missing:`, and one `HookResult` per hook in `Report.Programs` (`--json`'s `programs`). The tier-2 hooks
    are every program of `trace_proc`, `cgroup_track` and `cgroup_net`, `cgroup/sock_create` and `cgroup/setsockopt`
    among them (ADR 0018 PR 2 and (7); required for tier `cgroup`, since every run with a `net:` section attaches
    both), each attached to a
    scratch cgroup in the subtree runs live in. A cgroup row whose attach the kernel refuses with `EPERM` names the
    likely cause in the words a run's `Attach` refusal uses (`cgroup.AttachConflictHint`; enforce-cgroup-observe E36):
    a program attached above without `BPF_F_ALLOW_MULTI`, which `bpftool cgroup tree` names, or the capabilities. Each
    is loaded with only the maps it
    references and every map
    unpinned, so a program the verifier refuses fails its own hook and no other. `trace_proc` is compiled once per
    reader (enforce-cgroup-observe R10): D7 loads the build a run loads on this kernel (`bpf.KernelReader`), and
    each of its rows carries `reader` (`rdonly` or `probe`) and `reader_why`; D7's line says `trace_proc is its
    <reader> build (<why>)`. Under `lockdown=confidentiality` on a kernel whose BTF lacks `bpf_rdonly_cast` or
    `bpf_loop`, no build loads: those rows are failed before any load with `lockdown: true` and a detail naming
    lockdown and the missing function, the line says `trace_proc has no build this kernel loads under
    lockdown=confidentiality`, and the fix is to boot without that lockdown (`integrity` keeps the tier) or a kernel
    with both functions, or to pin a lower tier; tier `cgroup` is not selected there. Where there is no program to
    load — every hook of a binary built without the objects —
    D7 loads a minimal program of the hook's type instead, marks the hook `stand_in` and says so on its line:
    that answers for the kernel's attach point alone. Whether this binary can build a tier at all is the tier
    derivation's question (`enforce.Buildable`, R27 Output), not a failing hook; a stand-in never replaces a
    program the binary has, so a verifier refusal of a real program (as 6.17's of `cgroup/connect6` and
    `cgroup/sendmsg6`) fails its hook. `uprobe_ssl`, capture's object, has rows of its own, marked `capture` and
    carrying no tier: each of its six programs (`SSL_free`'s among them) is loaded the same way, maps
    unpinned, and attached as a uprobe (`SSL_read`'s return program as a uretprobe) at the first of the row's
    symbols that the first system libssl D7 finds exports
    (`/usr/lib64`, this architecture's multiarch directory, `/usr/lib`, the same under `/lib`, then
    `/usr/local`; `SSL_write_ex2` before `SSL_write_ex`, as capture's R2 picks). The attach is scoped to
    doctor's own pid, which maps no libssl, so no process on the host gets a breakpoint for the probe's length
    (`captureUprobeOptions`, pinned by `TestCaptureUprobeIsScopedToDoctor`).
    With no system libssl the rows test the load alone and say so (`load_only`); when the library is there and
    no program loaded, D7's line says the attach at that library was not tested because nothing loaded, never
    that there is no libssl (each row's `target` is the library found, loaded or not); a symbol the library does not
    export is not attached, as capture would not attach it either; a binary without the object stands in a
    minimal `KPROBE` program, as for a tier hook. **A capture row never fails D7 and never gates a tier**: no
    tier's `missing` list reads it, and D7's `OK` and fix are its tier hooks' alone. Capture is not a tier's
    requirement — at tiers `cgroup` and `bpflsm` it is "uprobes and forwarder", and under `capture: auto` the
    forwarder still runs (though a run with a `tokens`, `cost_usd` or `repeats` budget is refused
    `[capture-unavailable]` when no probe runs beside it, since its table guards no model endpoint, R32); a contract that pins `capture: uprobe` runs no forwarder there (capture-derive.md §4),
    so on a machine whose rows fail its run captures nothing, which the matrix note says,
    and records why: a `uprobe_ssl` that does not load (or a build without the object) is `gap what=capture
    why=mechanism-unavailable binary=uprobe`, while one that loads and then fails to attach at a binary's libssl
    (the uprobe `perf_event_open` there) leaves the source started and records that binary's attach failure as
    `gap what=capture why=no-openssl binary=<path>` (capture-derive.md §7's failure-modes table) —
    and a D7 failed by a capture row would put a capture remedy on the fix line, which reads D7's fix ahead of
    D6's. What the rows found is said on D7's line and, at tiers `cgroup` and `bpflsm`, in the
    `capture.model_traffic` matrix note, which is how `doctor` catches systemic uprobe failures (verifier,
    uprobe PMU, attach) before any run starts, as `capture-derive.md`'s uprobe-attach failure row says it
    does. It never touches the per-build lock
    (`/run/tego/bpf-<bpf_hash>.lock`, ARCHITECTURE §6): that lock only reference-counts *pinned* programs so
    the last launcher of a build can unpin/detach them on exit, and D7's programs and maps are never pinned or
    added to that count (§6 E28).
  - **D7's plane rows** (TIER3-PLAN T8; `docs/p0/enforce-plane.md` R18, R19, R21 own the rules): tier 3's rows
    are the decision plane's, one per `decide.bpf.c` hook per mode (`lsm/<hook>` at `bpf_lsm_<hook>`,
    `fmod_ret/security_<fn>`), carrying `plane`, `function`, `arity`, `decides`, `ran`, `inside` and `outside`
    and no tier: they gate tier `bpflsm` through the plane's answer (`--json`'s `plane`), never through D7's own
    `OK`, which stays its tier-2 rows'. D7's line ends with the plane's clause, `decision plane: <selected mode> (what tier 2 and tier 3 get from it)`,
    then the build as the first 8 characters of its object hash and each mode's answer; the `lsm` line's failure names tier 3 only; where the selected mode is the fanotify fallback, the clause says it does not scale past a few concurrent runs (an open costs 85 us with two runs and 1.3 ms with eight, enforce-plane §10.1). The six hand-listed `lsm/*` stand-in rows
    are gone. The probe pins nothing, and its child, scratch cgroup, fixtures, links, programs and maps are gone
    when it returns, on every path (`TestIntegrationPlaneProbeOnThisKernel`,
    `TestIntegrationPlaneProbeCleansUpWhenTheChildFails`, `TestIntegrationDoctorCancelledDuringThePlaneLeavesNothing`).
    A probe killed before it returns (SIGKILL, the OOM killer) leaves its fixture directory, named by its pid; the
    next plane or D8 probe removes each of its kind whose pid no longer runs once it is ten minutes old
    (`TestProbeFixtureDirsSweepAKilledProbesTree`); it likewise leaves its empty scratch cgroup, named by its pid (D3's, D7's and the plane's), and the next probe of the same kind removes each whose pid no longer runs (`TestMakeScratchDirSweepsADeadDoctorsEmptyCgroups`). The probe copies the binary into one memfd exec image, which
    the child inherits and doctor's own exec reuses (`TestPlaneChildExecsTheInheritedImage`).
  - **D8 fanotify**: `fanotify_init(FAN_CLASS_CONTENT|FAN_REPORT_FID, O_RDONLY)` (the class alone when the kernel
    refuses the pair); probe `FAN_OPEN_PERM|FAN_OPEN_EXEC_PERM` mark support, then answer one permission event on
    the probe's own file and require the open to be refused. The reply is `FAN_DENY` carrying `EACCES`, which a
    kernel refuses from a `FAN_CLASS_CONTENT` group with `EINVAL`, and then the bare `FAN_DENY` tier 2's listener
    sends (`enforce-cgroup-observe.md` §6 E2), which must reach the opener as `EPERM`; a round trip that does not
    refuse the open, or cannot be completed, fails D8. None of its failures' fixes names
    `CONFIG_FANOTIFY_ACCESS_PERMISSIONS`, which the kernel has shown it has by taking `FAN_CLASS_CONTENT` and the
    permission mark. An open refused before this listener received a permission event — the probe's own open
    already failed when no event arrived — is the host's policy: an LSM's `file_open` hook runs before fsnotify's
    permission hook, and a fanotify group of higher priority is asked first, so either refuses with no event
    reaching D8; its errno is named and the fix is to find that LSM rule or listener (an antivirus or audit
    agent) and exempt tego's files, or pin a lower tier — never a tego bug report, since a re-run fails the
    same way. A round trip that could not be completed otherwise (no event while the opener was still waiting,
    no return within the probe's timeout, an answer the kernel would not take) is re-run and, if it fails again,
    reported as a tego bug; an open this listener denied that still did not fail with `EPERM` is a kernel that
    did not apply the reply, so the fix is a current stable kernel, then a report. `FAN_DENY_ERRNO` is read off
    the same event, on the flag combination rather than a release: it arrived in 6.14, is taken only from a
    `FAN_CLASS_PRE_CONTENT` group and never with `EACCES`, so it is false on every kernel so far, and the listener
    sends no errno bits either way. The mark
    goes on the regular file the probe then opens, never on its parent directory: `fanotify_mark(2)` gives a
    plain `FAN_MARK_INODE` mark only the object named, and events for the immediate children of a marked
    directory require `FAN_EVENT_ON_CHILD` **in the mask**. Marking the file is preferred over that flag because
    a directory marked `FAN_OPEN_PERM` would raise a permission event for the probe's own creation of the file,
    before any reader exists to answer it.
  - **D9 swap** (added 2026-09-24, ADR 0038's note): whether a run's memory cap holds swap too. It asks the nearest
    cgroup of this process's own, from its cgroup up, that has the memory controller (`memory.max`), and fails
    when that cgroup has no `memory.swap.max` (the kernel accounts no swap to cgroups: `swapaccount=0`,
    `cgroup.memory=noswap`) while `/proc/swaps` lists an active area: a run's memory cap can then be exceeded into
    swap (`runtime-launch.md` §4 `SetLimits`). Its fix is to enable swap accounting (remove those two from the
    kernel command line and reboot) or turn swap off. It gates no tier, runs in every scope `tego run` probes
    (a stat and a read), and passes, saying so, when no cgroup of the process has the memory controller to ask;
    each run also checks its own cgroup and records a `what=limits` gap (`TestProbeSwap`).
> **What D8 does not establish: the running kernel's patch level.** D8 probes capability, never soundness, and
> there is no userspace mitigation for a kernel-side hole in the permission path. CVE-2026-46150 (mainline
> `7746e3bd4cc1` "fanotify: fix false positive on permission events", `Fixes:` `abc7757` from 4.12, so
> every branch through 5.10.257 / 5.15.208 / 6.1.174 / 6.6.139 / 6.12.87 / 6.18.29 / 7.0.6 is affected) is
> exactly that: `fsnotify_get_mark_safe()` could return false for a mark belonging to an *unrelated* fsnotify
> group, and `fsnotify_prepare_user_wait()` then skipped the permission check — an open tier 2's listener should
> have been asked about proceeds unasked. Any other fanotify or inotify group on the host can supply the
> unrelated mark, so it is not a contrived condition. Tier 2's refusals are only as sound as the running
> kernel's `fs/notify` code; run a stable kernel carrying this fix. `doctor` deliberately does **not** turn this
> into a version check: a distribution that backports security fixes without changing its release number would
> be failed on every run, which is the same version-inference error R27 avoids everywhere else, and a functional
> probe for a missed-notification race does not exist. It is recorded here instead.
  Output: `spec/backend/CAPABILITIES.md`'s table with this machine's values substituted ("this machine's values"
  include the one row the static table leaves to the Landlock ABI: `net.unix_abstract_scope` reads yes at ABI ≥ 6
  for tiers `landlock`, `cgroup` and `bpflsm`; tier `cgroup`'s file-write, read-deny and exec-deny rows name the plane
  mode and `EACCES` where the plane probe selected one, fanotify's `EPERM` only on the fanotify fallback;
  `--json`'s `fanotify` is `null` when D8 did not run), the highest reachable
  tier, a `missing for <tier>: <capability>` line per absent row, one `fix: <command>` line (e.g. `fix: add ,bpf
  to the kernel's lsm= line and reboot`). Between the probe lines and the table, one `summary:` line gives the answer
  first (*amended 2026-11-02*: the tier line came only after the table's rows): `summary: tier <tier>`, or `tier
  none` with the tier line's own reason; `, capped by the machine config (<file:line>)` where the machine config's
  ceiling is the tier reached and a tier above it exists; then `; <tier> needs <names>` for each tier above it, which
  names each reason of that tier's `missing for` line once, by the check, `root`, `build` or `plane` it begins with (a
  D7 hook's row by D7's `programs`), and leaves out a check that did not run for want of root wherever root is named.
  A user on a stock Ubuntu reads `summary: tier landlock; cgroup needs root; bpflsm needs root, lsm`. The summary says
  nothing the lines after the table do not, never starts with `tier: `, which scripts read from the tier line, and is
  not in `--json` (`TestSummaryComesBeforeTheMatrix`). **The tiers are one derivation, and `tego run` selects from it**
  (`internal/doctor/derive.go`; `run` selects through `doctor.ForRun`'s `Report.Select`, over `Report.Probe` under
  the same machine config, and keeps no gate of its own; `ForRun` is this derivation over the checks of the tiers
  the run can reach, "What a run probes" below). A run refused a tier it asked for — `--tier <t>`, a
  contract's `tier:` or the machine config's concrete tier — is refused as a pin of that tier, `tier <t> pinned
  but not available [tier-unavailable]`, followed by this report's own `missing for <t>:` line and the fix line
  for `<t>`, so `run` never gives another account of a tier than `doctor` does; a run that finds no tier at all
  is given tier `landlock`'s line, which every tier inherits. A `--tier <t>` that meets a contract's `tier:` or a
  machine config's concrete tier naming another tier `<p>` is neither: it is refused as the conflict it is,
  `--tier <t> conflicts with tier <p>, pinned by the contract or the machine config [tier-unavailable]`, with a fix
  line naming both ways out, never as `<p>` pinned but not available: the refusal is the conflict, whatever the
  machine has.
  When `<p>` is missing from this report as well, the message adds `, and tier <p> is not available on this machine
  either`, and the fix line offers only changing the pin to `<t>`, followed by this report's own `missing for <p>:`
  line: running without `--tier` would be refused as that pin. Tier `landlock` needs D5 (both halves), D1, D3
  and D4. D3 is there
  because every run is created in the delegated cgroup it checks and is stopped through that cgroup's
  `cgroup.kill`. D1 is there because the 5.14 floor stands for mechanisms no functional probe exercises
  (`pidfd_getfd`, seccomp `CONTINUE`, `clone3` into a cgroup), so a release below it, or one D1 cannot parse,
  fails closed rather than promise a launch that may not complete. Tier `cgroup` needs everything tier
  `landlock` needs, because it installs tier 1's Landlock ruleset and seccomp filter and gets delete, rename
  and mkdir from "Landlock inside the run" (ADR 0011), plus root, D2, D8 and its D7 hooks; and D7 itself when,
  as root, it failed before testing any hook (for example, a BTF that `cilium/ebpf` cannot parse fails D7 with no
  hook rows; D2 now fails too, but the derivation does not rely on that), because no row could then say the programs
  load. Tier `bpflsm` needs
  everything tier `cgroup` needs plus `bpf` active in D6 and the plane in LSM mode (enforce-plane R19: a
  `plane: LSM mode: ...` line, or `bpf.plane pins fmod_ret`, with LSM mode's own fix; where `bpf` is not active
  the `lsm` line and the GRUB fix say it once, `TestBPFLSMNeedsLSMMode`). Each tier also needs a binary that
  can construct it (`enforce.Buildable`, which `enforce.Select` applies to its probe as well): tier `cgroup`
  loads the embedded BPF objects, so it is buildable exactly when the build embeds them, however the binary is
  linked (ADR 0021 (4); enforce-cgroup-observe.md §5 R8). Tier `bpflsm` is implemented and uses the same
  embedded-object build requirement, with the additional actual LSM-plane readiness above. What the build
  lacks is listed as `build: <why>`, and the fix is `cgroupenforce.BuildFix`, a
  `tegobpf` build (`TestBuildable`). The fix line is the one that makes the next tier
  up available. While any tier-1 blocker stands it names the remedy of every one, joined with `; and `, whichever
  tier is next, because each blocks every tier: D5's first (Yama's, then the round trip's), then D1's, D3's and
  D4's. A line naming only the first would not make tier 1 available: at `ptrace_scope=3` with Landlock missing
  from `lsm=`, both are boot-time changes and the operator would learn of the second only after the first
  reboot. Because that line can ask for a reboot, Yama's remedy on it is one a reboot keeps: at scope 2 it is
  `kernel.yama.ptrace_scope=1` set in `/etc/sysctl.d` and applied with `sysctl --system`, not a bare `sysctl
  -w`, which the `lsm=` reboot after it would undo; at scope 3 it is a boot setting already. Above tier 1 the
  fix line is the first that applies of: the binary (a
  build that carries the tier), privilege, the boot change, the kernel build. The binary comes first because no
  machine change makes a tier this build cannot construct available, and when no build of this version carries
  the next tier there is no fix line at all rather than a machine change that would not deliver it. Only the
  checks the tier itself reads have a say in its line. Tier `cgroup`'s line comes from D2, D8 and D7 and never
  from D6, whose `lsm=` reboot gives tier `cgroup` nothing. D7's remedy for it is judged on tier `cgroup`'s own
  rows, because D7's overall remedy is worded for every row it tested, a tier-3 hook the kernel lacks included
  (`TestRunReportIsDoctorsAtAndBelowItsReach`), so `doctor` and `tego run` at reach `cgroup`, which runs
  neither D6 nor tier 3's rows, give the same line.
  After the tier lines, `doctor` reports what the ledger root holds that no sweep on this host finishes
  (`runtime.CheckLedger`; `--json`'s `ledger`, absent when there is nothing to say). It reads the root's
  directory names, the live index's names, and, for each of this host's entries, its ledger's tail and its lock
  line: it writes nothing and takes no run's lock. Two findings. Runs minted on another host (their id's
  `host8` is not this host's), counted per host: no sweep here ends, repairs or kills them, `tego gc` removes
  them past retention, and when this machine's id changed (a reinstall keeping `/home`, a cloned image, the
  hostname fallback with a renamed host) they are this machine's own runs, which nothing else would say. And
  each of this host's runs the live index still lists though it ended, its launcher gone: every sweep since
  kept the entry because its anchor repair failed on the anchor (`chain.log` unreadable or not writable) or its
  scope could not be removed, and retries it once per `run`/`stop`; `doctor` names it once when asked, with
  `events --verify <id>` to see whether it is anchored. Neither changes the exit code, and a ledger root that
  cannot be read is a warning (`TestCheckLedgerNamesTheRunsNoSweepHereFinishes`,
  `TestDoctorSaysWhatNoSweepFinishes`).
  As root, `doctor` first removes what a dead helper left (ADR 0022's 2026-09-24 amendment): a build idle past
  `bpf.linger` that no launcher holds and no live run needs, as its timer would have (`cgroup.SweepBuilds`), and a
  library's capture probes that no run holds past their grace, as their detacher would have
  (`uprobe.SweepLibraries`); a removal that fails is a warning. It then lists every tier-2 build on the bpf filesystem (`cgroup.ListBuilds`; `--json`'s `builds`,
  absent unprivileged or when there is none), one line each: its hash; whether a launcher holds it, or how long it
  has been idle, from its build lock's mtime, and when `bpf.linger` has it removed; its pinned programs and
  host-wide links; the capture probes pinned under it and on how many libraries (ADR 0026 (7), a library being
  detached included); its runs' rings and the memory they charge (ADR 0026 (2)); and its pin directory, where root
  sees and removes all of it. The section's heading says how many run rings every build holds and what they charge
  of `bpf.ring_budget`, and what every build's programs and maps charge (`tier-2 builds (bpf.linger 5m; 2 run rings
  charge 4MiB of bpf.ring_budget 256MiB; their programs and maps charge 5.6MiB):`);
  `--json` carries each build's `rings` and `ring_bytes` and a top-level `rings` object, `{budget, used, rings}`,
  absent unprivileged. Each line also gives (ADR 0022 (5), (8)): the build's memlock (`memlock_bytes`), the sum of
  the fdinfo `memlock` of every program and map pinned under it and its plane directories, of every program a pinned
  link attaches and every map those programs use, each id once (bpftool's `bytes_memlock` for the same objects); the
  objects left out of it, a pin that could not be opened or an object whose fdinfo has no `memlock:` line (one that
  says 0, an empty LPM trie's, is a 0 the kernel reported), are counted (`memlock_unreported`, `with N objects
  unreported`), and a build none of whose objects reported one says `n/a`, never 0; whether its linger timer runs
  (`timer`, `timer_pid`), read from its timer file and the process it names, never from its lock: an idle build with
  one is `removed in about <left> by its timer (pid N)`, one without `past bpf.linger in about <left>; no timer runs
  for it: the next run, tego stop or tego gc removes it after that`; and, for a build no launcher holds that is
  kept whatever gc does (`kept`, `kept_cause`), why: `a run it enforces is alive` or `its run set cannot be read (ADR
  0022 (5)): <what the read met>`, with `tego gc --builds does not remove it while that holds`, since gc's Force
  overrides neither; or `the sweep could not look at it: <error>`; a kept line then says `its timer runs (pid N)` or
  `no timer runs for it`. The sweep doctor runs first answers this for a build past its linger; for one inside its
  linger, or one the sweep did not name, the listing reads the build's run set itself, as gc's Force would, so a
  build an orphan's live run keeps is never said to be removed by gc. Any other idle build's line says `tego gc
  --builds` removes it now. The listing itself changes nothing: it tells a launcher's hold by a non-blocking
  exclusive attempt on the build lock, let go at once, moves no mtime, and opens a run set read-only, deleting none
  of its rows; a listing that fails is a warning and never the exit code
  (`TestListBuildsShowsWhatEachBuildHoldsAndWhetherARunHoldsIt`,
  `TestListBuildsSaysWhyABuildIsKeptWhetherItsTimerRunsAndWhatItCharges`, `TestDoctorBuildsGolden`; as root,
  `TestIntegrationABuildWhoseRunSetCannotBeReadIsKeptAndShown`, `TestIntegrationBuildMemlockIsBpftoolsSum`,
  `TestIntegrationPlaneBuildMemlockIsBpftoolsSum`, `TestIntegrationALingeringBuildALiveRunNeedsIsListedKept`;
  `TestFdinfoMemlockTellsAReportedZeroFromNone`).
  Exit 0 when any tier runs; 1 when none does; 211 when `--require <tier>` is unmet (R25).

  **What a run probes** (`doctor.Reach`, `doctor.ForRun`; `internal/doctor/forrun.go`, `runcache.go`). `tego
  doctor` runs every check above, afresh, every time, and never reads or writes the cache below. `tego run`
  runs only the checks of the tiers its selection can pick or has to explain. Its **reach** is the highest of:
  the tier `--tier` names, the contract's own `tier:`, and the machine config's concrete tier, each of which a
  refusal explains by name (a `--tier` that meets another pin is refused as the conflict, which also explains
  that pin, so both count); or, when none is named (tier `auto`), the highest tier at or below the machine's
  ceiling that root and this build allow — tier `landlock` for a run that is not root or a build without the
  objects, and tier `bpflsm` for a root run of a `tegobpf` build, which builds tiers `cgroup` and `bpflsm` alike
  (`enforce.Buildable`, TIER3-PLAN T7). Tier `landlock` is always within the reach, because a
  refusal that names no tier is explained by tier `landlock`'s line.
  - At reach `landlock` the run runs D1, D3, D4 and D5 — the whole of tier `landlock`'s list — and not D2, D6,
    D7 or D8: no BPF program is loaded, no LSM probe runs, no fanotify group is made.
  - At reach `cgroup` it runs those and D2, D7's tier-2 rows, the plane's mode probe (which selects tier
    `cgroup`'s plane mode) and D8. It does not run D6 or capture's rows: neither is read by tier `landlock` or
    `cgroup` (capture's rows gate no tier, above). The plane comes from the run-probe cache when it holds an
    entry, else from the build's pin directory when the pinned build records the mode `bpf.plane` would select
    (`/sys/fs/bpf/tego/<bpf_hash>-<mode>/tego_plane_probe`, written by the backend that loads it, T6), and only
    else from a probe, so an adopting run probes nothing (`TestAdoptingRunProbesNoPlane`, `TestAdoptPinnedPlane`).
  - At reach `bpflsm` it runs what reach `cgroup` runs, cache and adoption included, and D6's LSM list without
    its counting program: tier `bpflsm` is the plane in LSM mode over tier `cgroup` (enforce-plane R19), so it
    reads tier `cgroup`'s checks, `bpf` in the LSM list and LSM mode's answer, whose probe counts the plane's own
    LSM programs running (the proof D6's program gives; a cached or pinned answer is this boot's). It runs neither
    D7's tier-3 nor capture's rows, and tier `bpflsm`'s fix line reads tier `cgroup`'s rows
    (`TestRunAtReachBPFLSMProbesAsReachCgroupAndTheLSMList`). Every root auto run of a `tegobpf` build is at
    this reach, so without it every such run would have taken doctor's whole probe.

  A check the run did not run keeps its place in `Results`, `Skipped` with a detail beginning `not probed by
  tego run`, and a tier above the reach is reported unavailable with a `WhyNot` saying it was not probed; for
  every tier at or below the reach, `Probe` and `WhyNot` are exactly what `doctor` derives when the same process
  runs it on the same machine (`TestRunReportIsDoctorsAtAndBelowItsReach`, `TestProbeMachineIsDoctorsProbe`), so
  a run is selected and refused exactly as `doctor` reports it. With a cached answer they are what the process
  that kept it derived, a process the key makes the same as this one in every respect it holds (below; E30
  names what it does not hold). Skipping is safe for two reasons. A skipped check reads only into
  tiers above the reach, which the selection can neither pick nor has to explain: `auto` picks among tiers the
  reach covers, and every named tier is within it. And what a skipped or cached check would have found wrong
  still stops the run at the tier it was selected for: tier `cgroup`'s backend loads every one of its programs
  and creates its fanotify group in `Prepare`, and a failure there is exit 125 before `run_start`
  (`runtime-launch.md` R2), never a run at a lower tier.

  **The run-probe cache.** At reach `cgroup`, as root, D7's tier-2 rows, the plane's answer and its rows (entry
  format 7; the plane is kept whatever it found, since tier `cgroup` has the fanotify fallback, except an answer
  in which a mode's probe faulted (`Faulted`: a load error other than one the kernel repeats (the verifier's
  rejection, a kfunc, helper or program type it lacks, `ENOSYS` or `EOPNOTSUPP`, none of them caused by `ENOMEM`,
  `E2BIG`, `EBUSY`, `EAGAIN`, `EINTR`, `EMFILE`, `ENFILE`, `ENOSPC` or `EPERM`, is a failed mode, and is kept), an
  error from the fixtures, the scratch cgroup or the child, an attach refused with an errno that can pass on its own (`ENOMEM`, `E2BIG`, `EBUSY`, `EAGAIN`, `EINTR`,
  `EPERM`; any other attach errno is a failed row the mode fails on, and is kept), a probe syscall that answered an
  errno other than `EACCES`, `ENOSYS` or `EOPNOTSUPP` (`ENOSPC`, `EAGAIN`, `EMFILE`...) or no answer from the child, or, for LSM mode, an active LSM list no mechanism could read, which the mode reports as unknown rather
  than as bpf inactive with a GRUB fix), which is never kept, so the next run probes the plane again; the entry
  then keeps D7's tier-2 rows and D8's answer with no plane answer, and a run that reads it answers the plane alone
  (from the build's pin, else a probe) and completes the entry once the plane answers without a fault, which
  `DiscardCache` then follows; its selection is re-derived
  from `bpf.plane` on every read) and D8's answer are read from
  `/run/tego/doctor-probe-<bpf_hash>-<privilege>-<binary>.json` (§3) when it holds a valid entry, and the run then loads no program
  and makes no fanotify group before `Prepare`. The entry also keeps D2's answer when it passed (a failed D2 is
  probed again, and an entry holding one is not read) and whether the kernel's BTF has each
  function a run asks it about (`bpf.KernelFuncNames`: the reader's kfuncs, the optional tracing program's and the
  plane's optional hooks' targets); both read only the kernel's BTF and this binary's objects, which the key's boot,
  kernel and binary pin. A run that reads a valid entry takes D2 from it, whatever its plane answers, and hands the
  functions to its loaders (`bpf.SeedKernelFuncs`), so it parses no BTF: 50-100 ms of CPU a run in the KVM guests
  (enforce-plane §2.18, `TestRunAtReachCgroupReadsTheCacheAsRoot`). D1, D3, D4 and D5 are probed afresh on every
  run, and D2 on every run without a valid entry. An entry
  is used only when all of these hold, and otherwise the run probes and the entry is not read:
  - its **key** is this machine's and this process's: the entry's format version, the boot id (`/proc/sys/kernel/random/boot_id`),
    D1's kernel release, the active LSM list (D6's unprivileged half, in the kernel's order), the lockdown mode
    (`/sys/kernel/security/lockdown`, which can be raised without a reboot and changes which programs load),
    `bpf_hash`, and the running binary's device, inode, size and modification time (an upgraded or rebuilt
    tego judges with its own code even when its programs hash the same). The key also holds the **asking
    process's own privilege**, because D7 and D8 are the only proof that the process may load programs and make
    a fanotify group, and the `root` line reads its euid and user namespace alone (`config.InitNSRoot`, *amended
    2026-10-05*, ADR 0042 (5)(d): uid 0 of a child namespace is not root):
    - its effective capability set (`CapEff`): a root process started with a reduced bounding set (systemd's
      `CapabilityBoundingSet=`, `setpriv --bounding-set`) lacks `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN` or
      `CAP_SYS_ADMIN` at euid 0;
    - its LSM labels (`attr/current` and each LSM's own `attr/<lsm>/current`, `""` where an LSM keeps none): a
      confined SELinux or AppArmor domain can be refused `bpf(2)`;
    - its user namespace, and its mount namespace, through which D7 finds the invoking uid's delegated cgroup
      and D8 marks a file;
    - its own cgroup (`cgroup`, as the kernel prints it) and cgroup namespace, to whose root that path is
      relative: since 5.11 the kernel charges a BPF map's and a program's memory to the memory cgroup of the
      process that creates it, so a process whose cgroup has too little memory left (a unit's `MemoryMax=`) is
      refused a load another process is not, and a cgroup is what another tool's cgroup-attached programs
      (`BPF_LSM_CGROUP`, device programs) apply to;
    - the invoking uid, under whose delegated cgroup D7 attaches.

    These are read from `/proc/thread-self`, the calling thread's view, which every thread Go code runs on
    shares. `/proc/self` shows the main thread, which Go parks for good, with whatever a locked goroutine left
    on it, when that goroutine exits; D5's goroutine was such a one until D5 kept off the main thread
    (`TestProcessPrivilegeIsTheCallingThreads`, `TestSeccompProbeLeavesNoThreadFiltered`). A process under a
    seccomp filter does not use the cache at all: what its filter refuses cannot be read back. Each set of
    process privileges keeps its own entry, named `doctor-probe-<bpf_hash>-<privilege>-<binary>.json`, where
    `<privilege>` is 16 hex digits of the SHA-256 of that half of the key and `<binary>` 16 hex digits of the
    SHA-256 of the binary's part. A restricted process's failing probe therefore never removes an unrestricted
    process's entry, and the two never evict each other; nor do two binaries of one build (two installs, or a
    copy at another inode), which under one name each read the other's entry as a miss and replaced it, so a
    host running both probed cold on every run. The cgroup is
    part of it, so a root run from each new login session (systemd's `session-<n>.scope`) or transient unit
    probes once and keeps an entry of its own, until the next reboot empties `/run`. Nothing removes an entry
    before then but a run of its own key (`DiscardCache`, or a probe that no longer vouches for it): a rebuilt or upgraded binary of the same build leaves the old
    binary's entry in place, so `/run/tego` holds at most one entry per build, set of process privileges and
    binary that a root run used since the boot, each at most 1 MiB (a few KiB as written). Removing another
    binary's entry of the same build and privileges when this one's is written was rejected: it would bring back
    the eviction between two binaries that the per-binary name ends (*amended 2026-10-19*). Any part of the key that
    cannot be read leaves the cache unused, for reading and for writing;
  - it was **written by root and no one else could have**: every directory from `/` down to `/run/tego` is
    opened with `O_NOFOLLOW`, owned by root and writable by no group or other user (a sticky directory above
    the last is allowed, as a sticky directory lets others add entries but not replace root's), and
    `/run/tego` itself is root's and writable by no one else; the entry is a regular file of root's, opened
    `O_NOFOLLOW`, with one link, no access for group or others, at most 1 MiB, and no field this binary does
    not know. Nothing is ever read from a user-writable path. A directory that is there and refused (for
    example a group-writable `1770 root:tego` one, a form ADR 0042 (3)(b) withdrew) or an entry that cannot be written is not silent: the run
    still probes and never fails, and prints one `note:` line on stderr naming the refusal (`Report.CacheNote`,
    `TestRunCacheSaysWhyItIsUnusable`);
  - its **answer vouches for tier `cgroup`**: D7 and D8 both passed, D8's `FAN_DENY` refused the probe's open,
    and its rows are exactly this binary's tier-2 hooks, in order, each loaded and attached or an optional hook
    this kernel lacks (by the backend's own test, R27 D7). A capability-only network row (D7's "optional network
    controls") is kept as probed, failed or not: it gates no tier, so a run that reads it misses nothing a probe
    would have refused (amended 2026-10-05: a failed one used to fail the vouch, so on a kernel where one such hook
    does not load or attach no answer was ever kept and every root run probed in full, with no note;
    `TestRunCacheKeepsAnAnswerWithAFailedCapabilityOnlyRow`).

  Only an answer that vouches is ever kept: a root run at reach `cgroup` that probed writes its answer when it
  vouches (`0600`, through a temporary file and `rename(2)`) and removes its own key's entry when it does not, so
  the entry can never hide a failure from a run, and a machine that stops giving tier `cgroup` is seen by the
  next run that probes. A run started from a cached answer that then fails before `run_start` removes the entry
  (`Report.DiscardCache`), so a machine that no longer gives what the entry vouched for costs one failed run
  per set of process privileges — exit 125, never a lower tier — and the next run probes (E30 names the one
  case in which it recurs). A reboot discards it (the key's boot id, and `/run` is
  a tmpfs). The price of keeping only answers that vouch: on a root machine that does not give tier `cgroup`,
  every `auto` run probes D7's tier-2 rows and D8 before it runs at tier `landlock`; a machine config or
  contract pinned at `tier: landlock` skips them. The key holds the process's privilege (entry format 3), so a
  root process with `CAP_BPF`, `CAP_PERFMON`, `CAP_NET_ADMIN` and `CAP_SYS_ADMIN` out of its bounding set never
  reads the answer a full-root run kept, and runs at tier `landlock` as it would without the cache
  (`TestIntegrationRestrictedRootRunAfterFullRoot`, `TestRunCacheNeverLendsAnAnswerToAnotherProcess`,
  `TestRunCacheReadsOnlyTheAnswerItKeptForThisKey`, `TestProcessPrivilegeIsReadOrTheCacheIsNotUsed`). Why a run
  probes only its reach: taking the whole of `doctor.Run` first cost a root `tego run --tier landlock -- true`
  228 `bpf(2)` calls and 2.9–4.2 s against a 3–8 ms run, which failed kill test 4's pip kind at tier `landlock`
  as root on six of seven matrix kernels (2026-09-23).

  **Concurrent misses** (added 2026-10-05). Root runs that start together on a cold cache
  would each load every tier-2 program. A root run at reach `cgroup` or `bpflsm` that could read its key, and
  found no entry or one with no plane answer for its `bpf.plane`, therefore takes its key's flight lock before
  D7: `flock(LOCK_EX)` on `/run/tego/doctor-probe-flights/<sha256 of the whole key>.lock` (§3), held until its
  answer is kept or dropped (D8). A run that finds it held tries again every 10 ms for at most 30 s, and no
  longer than its context (SIGINT ends the wait and the run probes nothing). Once it has the lock, or has given up on it, it reads its
  key again: a key that changed or can no longer be read leaves the cache unused for this run, for reading and
  for writing; otherwise it reads the entry again, and an entry the holder kept is read like any other. Holding
  the lock is never evidence of anything: what is read is the published entry, through every check above, never
  the holder's answer. A run that waited and then finds no entry that answers it (the holder's answer did not
  vouch, its plane faulted again, or it died) lets the lock go and probes beside every other run that waited,
  so the runs queued behind one probe take one more probe's time together
  (`TestForRunProbeFlightWaitersOfAnUncacheableAnswerProbeTogether`; amended 2026-10-05: each such run used to
  probe holding the lock, one after another, so on a machine whose answer never vouches N runs started together
  started N probe times apart, each waiting up to 30 s). A run that cannot coordinate (the 30 s passed, a lock
  file or the directory fails the checks of §3, or its key has no lock file and all 128 are held) probes exactly as
  it would without coordination (`TestForRunConcurrentColdMissRechecksPublishedAnswer`,
  `TestForRunProbeFlightHolderDeathReprobesWithoutAnswer`, `TestForRunProbeFlightFailedOrPartialAnswerKeepsOriginalSemantics`,
  `TestForRunProbeFlightRevalidatesCallerBeforeReadingLeaderAnswer`, `TestForRunProbeFlightCancelledWaitDoesNotProbeOrPublish`,
  `TestRunProbeFlightBoundsPersistentNamesAndSeparatesFullKeys`, `TestRunProbeFlightRejectsUnsafeFilesystemAndChangedInode`).
  It still reads and keeps the run-probe cache, and prints a `note:` line of its own on stderr, `this run could
  not wait for a concurrent run's probe, so it probed on its own: <why>` (`Report.CoordinationNote`); a cache
  directory that is refused is named once, by the cache's own note (amended 2026-10-05: every such reason was
  printed as "the run-probe cache is unusable", with "probe coordination" twice at the lock limit and a refused
  directory named twice; `TestForRunProbeCoordinationIsNotAnUnusableCache`). A lock file's name hashes the whole
  key, so each new login session, unit, mount namespace or build that runs as root makes one. At 128 a new key
  first unlinks lock files nobody holds, each while holding its lock; a run waiting on one takes the lock only
  after the unlink, finds its name gone or leading elsewhere, and opens the name again, so two waiters never
  hold two inodes of one name (`TestRunProbeFlightReclaimsUnheldLockFilesAtTheLimit`,
  `TestRunProbeFlightTakesAReclaimedNameAgain`; amended 2026-10-05: lock files were never unlinked, so after 128
  keys in one boot no new key coordinated until reboot).
- **R28 `compile --test`**: a YAML table, one row `{action: fs.write|fs.read|net.connect|net.bind|net.http|exec,
  path|host_port|argv|method, expect: allow|ask|refused}` (and `fs.delete`, `fs.rename`, `fs.mkdir`; `exec.map`, a `PROT_EXEC` map of
  `path`, added 2026-09-30, which only the decision plane decides: allowed at tiers landlock and cgroup, refused
  at bpflsm, rule `exec-map`, for a file under a write entry no `exec.allow` entry covers, ADR 0027,
  `TestEvaluateExecMapSplitsByTier`, `TestCompileTestBPFLSMColumnGolden`; a filesystem row's `dir: true`, added
  2026-10-05 with ADR 0043, says its object is a directory, which `compile --test` also sets for a path that exists as
  one: a name entry never decides a directory, and a directory rename is asked whether it takes covered files out of
  coverage, `TestTestTableDirKey`; *amended 2026-10-20:* and only a move row whose object
  is a directory has paths beneath it that a gate's `fs.read matches` path pattern can match, gate.md R1). Each row is evaluated by `decide.Evaluate(rt *agent.RuleTable, a agent.Action,
  tier backend.Tier) agent.EvalResult` (`internal/policy/decide`, consumed here; amended 2026-10-05, the signature
  quoted here was stale) — the same nearest-wins/sibling-enumeration/
  basename-resolution semantics as the kernel decision (SEMANTICS §§2-5), on the compiled table alone; it runs
  nothing, and never reads this machine's `doctor`-reachable tier (R33). The contract's `gate:` is part of that
  table: after each tier's floor, `agent.EvaluateGateRow` scores the row's own facts against it (gate.md, ADR 0007)
  and can only raise the floor, `allow` to `ask` or either to `refused` (`rule: gate.rules[i]`, reason `fs-gate`,
  `exec-gate` or `net-gate`); a gate ask a run cannot complete (exec, UDP, unix, non-open fs mutation) is answered
  `refused` with `completion_unsupported`, as the run refuses it. It never supplies a human answer, and it is a no-op
  for `net.bind`, `net.http` and `exec.map` rows (amended 2026-10-05: the gate has wrapped every column
  since 2026-10-04 and this rule did not say so). A row answers in every tier a run of the
  contract can get (ADR 0019), `RuleTable.Reach`: the pinned tier alone when the contract or the machine config
  pins one (a pin is refused, never lowered), else every tier this binary builds (`enforce.Buildable`) up to the
  ceiling that this process can be given here (`doctor.AutoTiers`: tier cgroup and above as root only, tier bpflsm
  only with bpf in the LSM list). It passes only if its expectation holds in each; a row's own `tier:` narrows it to that tier, and
  `--tier <t>[,<t>]` (with `--test` alone; a usage error otherwise, and for `observe`, `auto` or a tier named
  twice) replaces the set. Output: the first line is `tiers <t>, <t> (<where the set came from>)`, then one
  `PASS`/`FAIL <row>: got <verdict> via <rule>, want <expect>` line per row, a row that fails in more than one
  column saying `at <tier> got <verdict> via <rule>` for each tier it failed in; exit 1 on any `FAIL` (R25).
  `--json` with `--test` is one object `{v: 1, table, tiers, from, rows: [{name, line, expect, rule, pass,
  columns: [{tier, verdict, rule, pass}]}], passed, failed}`; a cell the gate scored adds `score`, `gate_rule`,
  `gate_outcome` and `gate_facts: "test_row"` (the facts are the row's, not a copied syscall's, as `copied_syscall`
  marks on a ledger line), and `completion_unsupported` when set; a `bpflsm` cell answered from the plane's rows adds
  `mechanism: plane` and `decision_plane: lsm` (agent-contract R15) (amended 2026-10-05). *Amended 2026-10-16 ([ADR
  0041](../adr/0041-race-free-supervisor-decisions.md) D7, "compile --test columns show the same"):* a column whose
  answer rests on a best-effort cell, one a run decides on copied syscall facts and lists in `run_start.best_effort`,
  names it: the cell adds `best_effort: [<id>, ...]` (`agent.RuleTable.BestEffortCellsFor`, additive, still `v: 1`) and
  the line ends ` [best effort: <id>[ at <tier>, <tier>]; ...]`, each id once, its tiers named unless it holds in every
  column. A gate cell holds when the row is its action and the floor did not refuse first, refusals included (a sibling
  thread can race a benign spelling, continued, to the refused one); `exec.rules/argv` when a command rule allowed or
  asked an exec row (an exec it refuses never runs, so that refusal is exact, ADR 0048; amended 2026-10-16); `deny_write/default` when a built-in target refused a modification at a tier no plane decides, which
  compile, probing no machine, takes to be tier landlock and tier cgroup. A refusal the floor makes rests on no cell,
  and an observe column on none (`TestCompileTestShowsBestEffortCells`, `TestBestEffortCellsForARow`). The table is read as strictly as a contract: every
  row key but `argv` takes one plain value, and `argv` a list of them (a list or mapping is an error, never read
  as its empty text); a top-level key given twice is an error; `proto` is `tcp` or `udp` (`unix` is accepted only
  for `net.bind`); and a value left null —
  an unquoted `~` or nothing after the key — is an error whose fix is `"~"` in quotes, as the contract refuses a
  null list entry. The file is one YAML document whose `tests:` holds at least one row (an empty list is "no rows
  to check", never a pass); an explicit YAML tag or a NUL in any value is an error, `path`/`dest`/`script` take
  the contract's path rule, and `version` the contract's: the unquoted number `0`.
  A `net.bind` row takes exactly one literal listener endpoint in `host_port` or a Unix socket name in `path`.
  IP listeners require an explicit port; port zero requests an ephemeral port. Hostnames, CIDRs, zones and
  contradictory protocol selectors are refused. A pathname Unix socket resolves its existing parent while
  preserving its final name; an abstract name has no filesystem resolution. Rows simulate policy; they do not
  create real sockets. *Amended 2026-10-19:* under a listener policy (a `listen:` section), a pathname bind whose walk fails as the agent's
  own lookup fails (`ENOTDIR`, `ELOOP`, `EACCES`) is `refused`, rule `path-unreliable`, reason `net-not-allowed`, in
  the `landlock` and `cgroup` columns, as the supervisor's `bindUnix` refuses a bind it cannot place; it was answered on
  its spelling. With no listener policy the run never reaches `bindUnix`: it continues every bind with no line and the
  kernel answers it (supervisor.md R11a, `handleBind`), so such a row is the creation floor on its spelling, as a
  filesystem row whose walk fails is; it was once refused `path-unreliable` there too, a line the run never writes.
  *Corrected:* in the `bpflsm` column the supervisor
  hands a listener policy's bind to the decision plane (`bindHandoffReady`), which decides it at `path_mknod`, a hook a
  bind whose lookup fails never reaches: that bind binds nothing, the agent gets the kernel's own errno, and the line
  is the kernel recorder's (`observed`, or `refused` `path-unresolved` for `EACCES`), naming no rule. That column
  answers the row on its spelling, as every row whose walk fails is (agent-contract R15); it was once answered
  `path-unreliable`, a line that run never writes. A tier-2 run whose plane decides its binds is that column's (ADR
  0019's 2026-09-29 note); the `cgroup` column is tier 2 with no plane, where `bindUnix` decides.
  A `net.http` row (added 2026-10-04, written here 2026-10-05) takes `host_port`, `method` and `path`, all required,
  over TCP (`udp://` or `proto: udp` is an error): it is decided against the compiled `net.http` request rules
  (`RuleTable.HTTP`), `allow` with the matching rule or `refused` with reason `net-http`, and is `invalid-action`
  when the contract has no `net.http` section or in an `observe` column. Only a `net.http` row reads `method`; a `net.bind` row
  refuses it.
  *Amended 2026-10-16 (ADR 0017 (b); ADR 0019's "an answer for every
  runnable action"):* five more actions, each routed to the matcher the run decides it with, no new rule:
  - `fs.link` (`path` the existing file, `dest` the new name, both required): a hard link, decided as the supervisor's
    `recordLink` decides it at tiers 1 and 2 — at tier `cgroup` a link out of a `deny_read` the listener enforces by
    path is refused (supervisor.md R15d), a built-in `deny_write` target at either end is refused (supervisor.md R15c), each end is a
    modification at itself (Landlock's union at tier 1, the root walk then the union at tier 2, the root walk at tier
    3), then REFER's no-gain rule; an allowed link is named by its source's grant, as the run's line is. Reason
    `write-outside-contract`. The `bpflsm` column is the plane's `path_link` on its rows: the new name a modification,
    then REFER (enforce-plane R10). *Amended 2026-10-17:* the Landlock half is
    asked as `hook_path_link` asks it, of each end's directory (`MAKE_REG` on the new name's, `REFER` on both across
    directories), never of the file, so a file-level write entry's link into another directory is `refused`; and the
    no-gain rule compares the file rights the ruleset grants at the new name's directory with the file's own, an
    `exec.allow` directory's `EXECUTE` included, so a link into one is `refused`. The `bpflsm` column composes that
    floor after the plane (tier 3 keeps it), asks `path_link`'s walks first as the hook does, and, where the table
    holds fs notifications (an fs ask or `ask_read` entry, an fs gate), names a link at a `deny_write` end by the
    target, the supervisor's R15c refusal that runs before the plane sees it. A rename meets the same no-gain rule in
    every column. *Amended 2026-10-17:* as `hook_path_rename` asks it: an
    `fs.rename` row within one directory is not compared, one across directories compares the new name's directory
    with the moved object (never a rule on the name it replaces), and only the file rights count unless the row's
    object is a directory (`dir: true`, or a path that exists as one), so the atomic replace of an `exec.allow` file
    entry inside a write entry answers `allow` in every column, as the kernel does. *Amended 2026-10-17:* an `fs.rename`, `fs.link` or `fs.delete` row's ends are the names the syscalls act
    on, never followed: each end's directory is canonicalized and its final component kept, so an end that is a
    symlink fs entry's own name is the symlink in its own directory, where Landlock has no rule (the entry's is on its
    target). The atomic swap of a symlink write entry answers `allow` and a link or a move of the symlink into an
    `exec.allow` directory `refused`; a rename onto, or of, a symlink entry outside every write directory, and its
    unlink, `refused` (`TestCompileTestSymlinkEntryEndsGolden`). The `bpflsm` column and `Evaluate` at `bpflsm` compose
    the Landlock floor's directory rights for a rename and a delete as for a link, so a file-level write entry's own
    rename and unlink answer `refused` there as at tiers 1 and 2 (`TestCompileTestLandlockReferGolden`). The run's
    line asks the exec grants by the inodes held before the agent ran (supervisor.md R17); a row is answered against
    the contract's starting tree, where the two are one. *Amended 2026-10-19:* every row's end is landed with the kernel's lookup of the syscall
    the row stands for (`agent.ActionKind.Lookups`, the one table, to which supervisor.md R15b holds the run's own
    handlers): `fs.read` an `open(2)` and `fs.attr` a `chmod(2)` (the whole path, a final symlink followed), `fs.write`
    an `open(2)` with `O_CREAT` (a dangling final symlink followed to the name it creates), `exec` an `execve(2)` and
    its `#!` interpreter's open, `fs.delete`, `fs.mkdir`, both ends of `fs.rename`, `fs.link`'s `dest` and a pathname
    `net.bind` the name-making lookup (the final name's directory; a final `.` or `..` is refused before a lookup and
    the row answered as written), and `fs.link`'s `path` a `link(2)` of the old name, looked up whole and not followed
    (`filename_lookup`): a final symlink is the link itself, and a final `.` or `..` is where the walk lands, so
    `out/el/ob/.` with `out/el/ob -> ../../outside/sub` is answered on `outside/sub`, `refused`, `unmatched`, as the run
    records it and the kernel refuses it. compile asked a link's old name as a name-making end and answered such a row
    on the symlink or the lexical clean, `allow` (`TestCompileTestLandsAsTheKernelGolden` rows 15 to 17). *Amended
    2026-10-19:* a name-making end ending in `/` is the name in
    its directory, never followed, as `filename_parentat` and the syscall act on it (`mkdir` is `EEXIST`, `unlink`,
    `rmdir` and a rename onto it `ENOTDIR`): an `fs.mkdir` of `out/dsym/`, a dangling link inside the write entry, and
    an `fs.delete`, an `fs.rename` `dest` and an `fs.link` `dest` of such links are answered at the link, `allow`, as the
    run records them; compile followed the link out of the entry and answered `refused`, `unmatched`
    (`TestCompileTestLandsAsTheKernelGolden` rows 18 to 21).
  - `fs.attr` (`path`): a `chmod`, `chown` or extended-attribute change, a POSIX ACL included. No Landlock ABI governs
    one (CAPABILITIES `fs.deny_chmod`), so it is `allow` in every column, named as `recordAttr`'s line (the write entry
    covering the path, else the nearest entry, else `unmatched`); the `bpflsm` column, read from the plane's rows,
    refuses it at or beneath a built-in `deny_write` target (`path_chmod` and the attribute hooks, enforce-plane R12).
  - `net.socket` (`family` and `type` required, `protocol` optional, default 0, each a number or a name: `AF_INET`,
    `SOCK_STREAM`, `IPPROTO_TCP`, any case; `socketpair: true` for socketpair(2)): ADR 0018 (1)'s allowlist under a
    `net:` section (`pkg/policy/socketpolicy.Allowed`, *amended 2026-10-17:* a leaf package the decision core and
    `internal/bpf.SocketAllowed` share, which the filter's arm and the kernel's C function are held to), socketpair
    `AF_UNIX` only; nothing refused without a `net:` section; `IPPROTO_MPTCP` refused in every column,
    `observe` included (E30's filter arm). A refusal is rule `unmatched`, reason `net-not-allowed`, as the supervisor's
    `refuseSocket` and the plane's sample write it. The row takes no `path`, `host_port`, `proto` or `argv`.
  - `net.send` (`host_port`, UDP, or a `unix:` `path`): an unconnected datagram send, answered as the connect to the
    same destination (supervisor R13b decides it with the connect's own decision), the resolver exception included;
    `proto` other than `udp` is an error (a stream's send without a peer is its connect, a `net.connect` row).
    *Amended 2026-10-17:* an admitted datagram the supervisor continues is recorded
    `best_effort: true` (supervisor R13b, enforce-landlock E33: the kernel sends to its own copy of the address); the
    row's `[best effort: ...]` note and `--json` `best_effort` list only `run_start.best_effort`'s cells (ADR 0041
    D7), which that per-line mark is not, so an allowed `net.send` row shows none.
    *Amended 2026-10-19 (it restates in one model
    the amendments of that date, whose changes the Changes list keeps):* a `net.send` or `net.connect`
    row to a unix pathname is decided as the run decides the datagram or the connect (supervisor.md R11, R11a; SEMANTICS
    §5 as amended 2026-10-16), twice. First the name it passes, cleaned: a `unix:` entry by its path, else the nearest
    filesystem entry by its declared or resolved path when that is a write entry. A relative name is joined to compile's
    working directory as `getcwd(2)` reports it, every symlink resolved, the directory the run joins a relative
    `sun_path` to (`readlink /proc/<pid>/cwd`, supervisor.md R6), never `$PWD`, which spells it through a symlink when
    the shell came there through one. Then what that name reaches, landed by the run's own unix walk
    (`supervisor.LandUnix`: the supervisor's `unixWalk`, one `openat2(2)` with `RESOLVE_NO_MAGICLINKS` and, where that
    lookup fails, a walk a component at a time that refuses every magic link; a landing on procfs refused; `connect(2)`
    and `sendto(2)` follow a final symlink), asked in compile's own view of the tree the agent calls in: the tree as it
    is when compile runs, with every directory the name's walk needs made (the premise every filesystem row's missing
    part is answered under) and, at a final name that names nothing yet and that nothing needs as a directory, the
    socket the agent binds; a dangling link is followed to its target. What is already there is what it is: a socket is
    taken as one a process of the run bound (supervisor.md R11a, which no row can ask before the run), and a directory,
    or a file that is not a socket, is none. What the walk met is answered as the run answers it, connect and send alike
    unless said: a magic link, a symlink loop, procfs (`/proc/<pid>/fd/N`, `/proc/<pid>` and `task/<tid>` included, which
    appear while the agent runs) or a place another mount tree holds is `refused`, rule `path-unreliable`; a name that
    names nothing (beneath a file; a socket already there named with a trailing `/`) is, for a `net.send`, `refused`,
    rule `unix-absent`, and a lookup that fails otherwise (`EACCES`) `path-unreliable`, while a `net.connect` to either
    keeps the name's verdict, the line of a connect that fails in the agent's own lookup; a socket only the component
    walk reaches (a link `fs.protected_symlinks` refuses the lookup) refuses a connect `path-unreliable` and decides a
    send on that socket. What the walk reaches is matched as the supervisor's `decideResolved` matches it: a `unix:`
    entry by the place it resolved to before the agent ran (`NetRule.UnixResolved`, `agent.ResolveUnixPlace`; the supervisor's `resolveUnixDeclared`)
    admits it; else a `net.ask` `unix:` scope's place refuses it, rule `unix-ask-scope`, as the run refuses what
    reaches that place unasked (supervisor.md R11c), and a connect no declared entry names that lands there is refused
    under the scope's own rule, since the run asks a person about it; else the nearest filesystem entry, by its resolved path alone, admits it when that is a write entry and
    what is there is a socket, and refuses it, rule `unix-foreign`, when it is a directory or a file that is not a
    socket, since no process of the run bound one there (supervisor.md R11a); else it is `refused`, rule `unmatched`. A
    name ending in `/`, `/.` or `/..` (in its spelling or its final link's body), or one whose walk goes beneath the
    part it ends on (`x/y/..`), ends on a directory, made or already there: the write entry admits a `net.send` there in
    no state of the tree, and the run refuses it `unix-foreign` once the directory is there. An admitted socket is named
    by the entry that admitted it, as the run's line is; every refusal has reason `net-not-allowed`. The `cgroup` and `bpflsm` columns
    also refuse a `net.send` whose absolute name is not spelled canonically (`agent.UnixCanonical`, the supervisor's own
    test of it), rule `unmatched`, where the name and what it reaches admit it: the run's kernel programs
    (`sendmsg_unix` on 6.7 and above, the plane's `socket_sendmsg`) refuse it and the supervisor answers that refusal
    (supervisor.md R13b). Before this design the landing was taken as a socket whatever was there, so a datagram to
    `out/x/y/..`, `out/d/` or `out/d` (a directory) or to a regular file read `allow` where the run refuses it
    `unix-foreign`, and a missing name ending in `/` or `/.` was answered as naming nothing (`unix-absent`, a connect
    `allow`) where the run refuses it `unix-foreign` once the directory the name makes is there. Stated: where the tree
    the agent calls in is another, the run's line differs: a socket still missing when the agent calls fails a connect
    `ENOENT` with the name's verdict and refuses a send `unix-absent`; a socket already there that no process of the run
    bound is `unix-foreign`; compile walks with its own credentials, which are the agent's at tier `landlock`, while at
    tiers `cgroup` and `bpflsm` the supervisor walks a datagram's name as root, so a directory compile may not search
    answers `path-unreliable` where such a run decides the socket; and a `cgroup` run below 6.7 outside a plane mode
    loads no unix program and admits a name not spelled canonically, which the column, asked of no kernel, does not
    answer. (`TestCompileTestUnixLandsAsTheRunGolden`, `TestCompileTestUnixWalkAsTheRunGolden`,
    `TestCompileTestUnixJoinsThePhysicalCwd`, `TestCompileExecJoinsThePhysicalCwd`, `TestRunResolvedJoinsThePhysicalCwd`,
    `TestEvaluateUnixDecidedWhereTheNameLands`, `TestEvaluateUnixDecidedOnWhatTheWalkMet`,
    `TestEvaluateUnixLandedOnNoSocket`, `TestResolveActionFollowsAsTheKernel`, `TestLandUnixStepwise`;
    `TestCompileLandsWhereTheRunLands` holds every generated connect and send row's verdict to the verdict the run's own
    decision code gives once the tree is the one compile answers for.)
  - `exec.anonymous` (no target key): the exec of an anonymous image (a memfd, a file unlinked since it was opened):
    `refused`, rule `exec-anon`, reason `exec-not-allowed`, unless the run's images are unrestricted (no `exec:`
    section or a deny-list one) or the contract set `exec.anonymous: true` (SEMANTICS §4); `allow` naming `exec-anon`
    in an `observe` column. The row takes no `argv`: a run asks an admitted anonymous image's argv of the command
    rules on facts (the image's own name) a row cannot give, so compile answers the image floor alone. *Amended
    2026-10-17:* the `bpflsm` column refuses it `plane-unbuildable` with
    every exec row when the table does not compile for the plane; otherwise its `exec-anon` is the run's line at tier 3
    too, since the supervisor refuses an anonymous image the run does not admit before the plane's `bprm_check` sees
    it (supervisor.md R16b).
  The gate scores `fs.link` as `fs.rename` (both ends with the write predicates, the source with the read ones),
  `fs.attr` as a non-open mutation (its ask is `completion_unsupported`), and `net.send` as `net.connect`; the
  `best_effort` cells follow the same actions (`gate.fs.read/move` and `gate.fs.write/mutation`, `gate.fs.write/mutation`,
  `gate.net/unix-datagram` for a unix send). In `--json`, the `bpflsm` column's `fs.link` and `fs.attr` cells carry
  `mechanism: plane`; `net.socket`, `net.send` and `exec.anonymous` cells, which no plane row decides, carry neither key.
  The header's `bpflsm:` line says so (*amended 2026-10-17:* "fs, exec and exec.map answered from the plane's rows and
  the Landlock floor under them (...); exec.anonymous and network answer from the policy model"). *Amended
  2026-10-27 (ADR 0043 C9):* where the plane's rows carry the table's name entries (a build that enforces them), the
  line goes on "; deny_read's name entries answered from the plane's name rows and the climb to their scopes, a file
  created after compile at a covered name included" (`TestCompileTestBPFLSMColumnNamesTheNameEntries`); a row's
  `dir: true` asks a directory, which no name entry decides and a directory move asks D5's question of.
  ADR 0017's conformance runner asks `fs.link` and `fs.attr` of its link and chmod cells, which had no action
  (`TestEveryCellHasACompileAction`). Tests: `TestLoadTestTableConformanceActions`, `TestEvaluateLink`,
  `TestEvaluateAttr`, `TestEvaluateSocket`, `TestEvaluateSend`, `TestEvaluateExecAnonymous`,
  `TestPlaneEvaluatorMatchesEvaluate` (links and attribute changes), `TestCompileTestConformanceActionsGolden`,
  `TestCompileTestBPFLSMColumnGolden`.
- **R29 CLI commands** (one file each under `internal/cli/`, each registering its command from that file, the usage
  generated from the registry and sorted by name (*amended 2026-10-24*, ADR 0100 (2)); the nouns of R35 are handed off; REPO-LAYOUT.md's exhaustive P0 listing: `init,
  doctor, compile, run, stop, status, ask, approve, deny, dns, drift, measure, learn, events, serve, gc, version,
  __child`; since 2026-10-06 also `watch`, `agents`, `alternate` and `adopt`, below, and the hidden `__adopt-reap`; since
  2026-11-02 `licenses`).
  SIGINT and SIGTERM cancel a command's context once, and the first one also releases the handler, before the
  context is cancelled, so a second takes its default action and ends a command that did not stop on the first
  (one blocked in a read no context reaches, such as a compile of a FIFO). A command that streams a ledger
  (`events`, `events --last`, `measure`, `status`, `drift`) checks its context every 1024 lines (`status --all` also between runs) and stops on the first signal,
  "interrupted", 125. `run` is not cut short by it: from the
  moment its run directory exists it holds a signal subscription of its own (`runtime-launch.md` R9's
  forwarding, double-SIGINT escalation included) until its shutdown or unwind is done, `run_end` written and
  kernel state released. A signal before that point — after the contract compiled, during the probe, the sweep
  or the capture sources' construction — refuses the run instead: `tego run: interrupted before the agent
  started; nothing was run [run]`, exit 125, nothing launched, and a probe it cut short is reported so, never as
  `[tier-unavailable]` (`TestRunInterruptedBeforeStartLaunchesNothing`). Durations on the command line (`gc --keep`, `stop --grace`) take the machine config's
  duration grammar, `config.ParseDuration` — `30d`, `12h`, `90s`, never negative — so they take what the config
  file and gc's own output say; an explicit flag is told from an absent one by `fs.Visit`, not by its value, and
  a value the grammar refuses is a usage error, 2. The commands:
  - `init [dir]` scaffolds `agent.yaml`, 0. A `[dir]` that does not exist, or is not a directory, is a usage
    error, 2, naming it: init scaffolds an existing project and creates none. It decides about `agent.yaml`
    and reads `.gitignore` before it creates anything, so a refusal of either leaves no `.tego/` behind. It writes neither `agent.yaml` nor
    `.gitignore` through a symbolic link or into anything but a regular file, which it reads
    `O_NONBLOCK|O_NOFOLLOW`: a link is refused as foreign, and `--force` replaces the link itself by a rename,
    never the file it leads to. Without `--force` the starter is published by `link(2)`, which refuses a
    destination created after init looked; on a filesystem with no hard links (vfat, exFAT; some FUSE and
    network mounts) it is `renameat2(RENAME_NOREPLACE)`, with the same refusal (*amended 2026-10-05:* that
    filesystem failed init with 125 and no `agent.yaml`). The starter compiles with no warning: it grants `/dev/null` in `fs.write`, which
    Python's `subprocess.DEVNULL` opens for writing; its `net:` section allows nothing, so the host's unix
    sockets, the D-Bus session bus and with it `systemd-run --user` among them, are refused (`agent-contract.md`
    R19), and the model is reached through the capture forwarder the run admits on its own (allowing the model's
    endpoint would warn `model-direct-bypass`); its `cost_usd` budget is commented out with the price table it
    needs named, since without one every run of it is refused `[budget-unmetered]` and `compile` says so (R32).
  - `doctor [--require <tier>] [--json]` (R27; 0, 1 when no tier runs, 211 when `--require` is unmet, R25).
  - `compile <file> [--test <table> [--tier <t>[,<t>]]] [--offline] [--json] [--merged] [--upgrade]` (0/1/2).
    `--merged` (*added 2026-10-25*, ADR 0068 D6) prints, once the contract has compiled, its merged canonical form
    (`agent.Contract.Canonical`: every profile of its `extends` laid in, a built-in preset's included) in place of
    the rule table, and nothing else on stdout: the bytes a run keeps as `contract.yaml`, whose sha256 is
    `contract_hash` (agent-contract R13; `TestCompileMerged`). A contract with an error prints nothing and exits 1;
    `--merged` beside `--json`, `--test` or `--exec` is a usage error (exit 2). `--upgrade` rewrites a
    contract to the next contract version (VERSIONING.md §3), and version 0 is the only one there is, so today it
    is accepted and refused with exit 2 and a line naming that condition — it becomes the rewrite, printing its
    diff, when contract version 1 lands. A `<file>` of `-` reads the contract from standard input (a pipe, a
    socket — Node's `stdio: 'pipe'` is a socketpair — or a regular file, at most 1 MiB; a terminal is refused, not
    waited on); its diagnostics, and compile's own messages about it, are labelled `<stdin>`,
    and the working directory, where relative entries resolve (E28), stands in for the contract's directory.
    A `<file>` that is an agent name (`[a-z0-9-]{1,40}`, so never a path to a `.yaml` file) is the contract the
    registries resolve it to (agent-contract.md R26, *added 2026-10-20*): the print opens with `agent <name>, from
    the <project|user> registry`, `--json` carries `source` (`path`, `name`, `registry`; `path` alone for a
    contract given by its path), and a refused name (a name both registries hold among them) is
    exit 1 under `agent-not-found`, `agent-ambiguous`, `registry-entry` or `config-untrusted`, with the fix.
  - `run <agent> [-- <cmd>] [--tier] [--record] [-v]` (agent's own code / 124 / 125 / 126 / 127, detailed in
    `runtime-launch.md`). `<agent>` is the contract's path or an agent name the registries resolve (agent-contract.md
    R26, *added 2026-10-20*; a refused name is exit 125 under its code, before anything runs, as a missing file is;
    `-` is compile's standard input only, and `run -` is exit 2 `[usage]`, as are `watch` and `adopt --boundary -`),
    and `run_start.contract_source` records the file, and the name and registry for a name; `watch --boundary` and
    `adopt --boundary` take a name too. With no `<cmd>` the run execs the contract's own `command:`, and only a missing
    `<agent>` is a usage error, 2. After the contract, tego's flags are read only up to the first non-flag token;
    a `--` there ends them, and any other non-flag token starts the agent's command, which runs verbatim to the
    end, a later `--` included; tego's flags go before the contract or before that first `--`. A `<cmd>` given is
    the launching user's choice and is granted as the run's own command for that run, beside the contract's
    (agent-contract.md R8): the grant covers every exec of that file in the run, by any of its processes; a
    bare `<cmd>` a declared entry names by basename runs that entry's file and adds no grant, and one found on
    `PATH` is granted by its absolute path, never by name. The grant is recorded in `run_start.run_command_grant`,
    shown by `events` on the run_start line and by `status` under its capability line (`run command grant:
    <path>`, and `run_command_grant` in `--json`), and `drift` recompiles with it. `--tier` takes `auto`, which
    pins nothing, as `tier: auto` does in a contract, and `landlock`, `cgroup` or `bpflsm`; `--tier observe` is a
    usage error, 2, naming `--observe`; a bad `--record` or `--tier` value is a usage error, 2, before the
    contract is compiled. Every run with `--observe` or `--record off` in effect prints an `[unenforced]` warning
    saying so on stderr. A run of an auto contract below the tier `compile` resolved it to prints no
    `[tier-unavailable]` warning, and an untrusted machine config's refusal carries its fix, as `compile`'s and
    `doctor`'s warning does.

    *A quiet start (added 2026-10-26).* A run prints a notice before its agent starts only when it needs the
    person's action (an error, with its fix) or when this run enforces less than the contract wrote (a warning
    about a rule: an unenforced or best-effort rule, a refused tier, a budget nothing counts). A note that only says
    how a rule applies and weakens nothing is left out of the start: a `[held-reads]` note, a `[redundant-rule]`
    note, and a `[mount]` note that a path is a mount point (`/dev/pts/`). `tego compile` prints every one, as it
    always did (`doctor` checks the machine and compiles no contract); `run -v` (`--verbose`) prints them at the
    start too. A warning that weakens a rule is never hidden by the filter, and the AppArmor/SELinux disclosure of
    held opens (ADR 0041 D2, `[unenforced]`) stays as one short line naming its fix. The run's record is unchanged:
    the filter is on the terminal only, and the contract the run recorded (its copy and `contract_hash`) compiles
    to the same notes. `status` omits the `record/no-price-table` gap from its gap line for a run whose
    `run_start.limits` has no `cost_usd` (no price table serves a tokens or wall budget); the gap stays in the ledger
    and `tego measure` names it.
    *The answer line (ADR 0122, added 2026-10-26).* A run whose contract can ask needs the person's action
    later, so it prints one more line once the run exists and before the agent starts: the run id and the commands
    that answer (`tego ask <run>`, `tego approve <run> <ask_id>`, or deny), unless the machine config's `ask.notify`
    leaves out `cli`. A run that cannot ask prints no such line. After the agent starts, `run` writes nothing into the
    terminal; a desktop notice per held request (`ask.notify` `desktop`, tier landlock, non-root) is the one signal.
  - `stop --agent <name> [--grace <d>]` (*added 2026-10-26*): every run the ledger root's live index lists
    whose agent is `<name>` (the contract's `name:`, which a restarting unit keeps while each run gets a new id) is
    stopped as `stop <run>` stops it, one after the other, each printing its line; none prints `<name>: no live
    run`; 0 either way, the first failing stop's code otherwise; a run id beside `--agent`, or a name that is no
    agent id, is a usage error, 2.
  - `stop <run> [--grace <d>]` (SIGTERM then `cgroup.kill` after `stop_grace`, 0). `--grace`, a positive
    duration, is written into the stop marker and is the launcher's own stop_grace for this stop, longer or
    shorter than the machine's — `runtime-launch.md` R9 — as well as how long `stop` waits before its own
    backstop `cgroup.kill`; without it both use the machine's `stop_grace`. A second `stop` keeps the first one's
    grace: the launcher's timer is armed once, by the first, and the second's own backstop waits at least that
    grace before it writes `cgroup.kill` itself, a first `stop` without `--grace` (an empty marker) having left
    the machine's `stop_grace` in force. A signal to `stop` while it waits gives up the wait and writes no
    `cgroup.kill`: it prints that it stopped waiting, exits 0, and the launcher's own timer still applies. A launcher that exits between the pidfd check and the SIGTERM (ESRCH) is the run ending on its own: `stop` goes on to report stopped or not running, exit 0. A held lock whose holder has not yet written its pid/start line is waited on (2 s at most, a signal ends the wait: "interrupted", 125) before the pidfd is opened; still nameless, it is 125 `[io]`. After the backstop `cgroup.kill`, one asynchronous write, `stop` waits at most 5 s more (or the grace when shorter), not a second grace, and reports both waits when the run is still running. The backstop `cgroup.kill` goes to the run's scope as a sweep finds an
    orphan's — under the stopper's own cgroup root, the cgroup2 mount root and the run directory owner's delegated
    subtree, and only the one whose cgroup id `run_start` recorded (`runtime.RunScope`); when no scope of the
    run's is left that is logged and nothing is written. A root stopper searches the mount root only when root's
    record (`/run/tego/launched/<run id>`, `runtime-launch.md` R20) says root launched that very directory,
    whether or not the stopper owns the directory, so a root `stop` of a run id a user planted, or of a
    root-owned directory the ledger root's owner renamed, cannot kill another run. The stop marker is placed
    through the ledger's walk to the run directory (`ledger.PlaceNewFileThen`), so a root `stop` follows no link the
    owner of a user's ledger root planted. Once the run is stopped or not running (exit 0, not interrupted), a
    root `stop` starts the linger timer of every tier-2 build that no launcher holds and whose timer is not
    running (ADR 0022 (4), (8); `cgroup.RearmTimers`, liveness read from the timer's pid and, for a build that
    shows none, `/proc/locks`): the timer removes it at its deadline and applies the lingering cap, so a build
    whose timer died does not stay attached until a gc, and `stop` itself removes nothing unless a timer cannot
    be started, its latency an exec rather than a removal's 1.7 to 3.7 s. Best effort: a failure is one `[io]`
    line on stderr and the exit stays 0. A user's `stop` does not (the pins are root's)
    (`TestStopRearmsTheBuildTimersAsRoot`, `TestStopLeavesTheBuildsAloneUnprivileged`,
    `TestStopExitsZeroWhenTheBuildPassFails`, `TestRearmTimersStartsNoTestBinaryAsATimer`; as root in the KVM guest,
    `TestIntegrationStopRearmsABuildWhoseTimerDied`).
  - `alternate <run> <ask_id> --file <path> [--always] [--json]` (docs/OPERATIONS.md, SEMANTICS §6): the third
    answer to a held file open, besides `approve` and `deny`: the agent's open is completed on the named file instead (a
    stand-in for a held read, the file written into for a held `fs.ask` write). It uses the same authenticated broker
    path, the same usage/125 exits and the same `--always` key rules as `approve`/`deny`; a path the supervisor refuses as
    an alternate leaves the request pending and says why. *Amended 2026-10-16 (ADR 0057 D2):* the command opens the file
    itself, after its run checks and before it answers, with no symbolic link anywhere on the way (a path through one is
    a usage error naming where it leads, the request still pending), and passes the open file to the broker; a missing
    file is an I/O error, the request still pending.
  - `watch [--boundary <contract>] [--tier <t>] [--record <full|summary|off>] [--offline] -- <command> [args]` (ADR 0054): run any command as a black box. With no `--boundary` it is a record-only (observe) run under a
    generated contract and says on stderr, before the run, what it still refuses and does not record; with one it is
    `run` with the command given on the line. Usage errors exit 2 (no command, `--tier` without `--boundary`, a record
    level `run` does not take); the command's own exit code is the exit code, as for `run`.
  - `agents [--signature <rule>]... [--follow] [--children] [--json] [--no-default-signatures]` (root of the
    initial user namespace, else 125 `[privilege]`): list processes a signature recognises as an agent and say whether each
    runs inside a tego run; `--follow` reports starts and exits. It only observes, except as the guard: `--follow --adopt
    --uid <uid>... [--boundary <contract>] [--record <mode>]` adopts (as `adopt` below) each agent it reports outside every run
    whose real, effective and saved uid are one listed uid; `--adopt` without `--follow` or without `--uid` is a usage error (2).
  - `adopt --pid <pid> [--uid <uid>]... [--boundary <contract>] [--record <full|summary|off>]` and `adopt --release --pid <pid>`
    (ADR 0055; root of the initial user namespace, else 125 `[privilege]`): move an already-running agent's own
    process tree into `adopt-<run>.scope` and record it from the kernel until the tree ends (the agent's exit) or it is released
    (SIGINT, SIGTERM, `stop <run>`, `--release`); never kills it. A process the scope guard refuses, another user's without
    `--uid` naming its owner among them, is 125 `[adopt-refused]` with the rule named; a boundary rule a running process cannot be
    held to is 125 `[adopt-refused]` naming the rule. `stop <run>` of an adoption is a release request that adoption alone
    answers. Usage errors exit 2 (no `--pid`, arguments, `--release` with anything but `--pid`, a bad `--uid` or record level).
  - `learn <run> [--out <file>] [--workspace <dir>]` (FEATURES C9): propose a contract from a finished run;
    writes only a new file (0600) and never replaces one.
  - `status [run] [--json] [--all]` (R7-R12, 0/1; a run id and `--all` together are a usage error, 2).
  - `ask <run> [ask_id] [--json]` lists pending approvals or inspects one target. `approve <run> <ask_id> [--json]` and `deny <run> <ask_id> [--json]` answer exactly one operation. The CLI verifies the live run lock/pidfd and broker credentials; server authentication checks each packet writer and rejects governed cgroup members/descendants (amended 2026-10-25: and a writer inside any run's or adoption's scope or a look-alike of one, or in another cgroup namespace than the broker's, ADR 0008; the refusal says whom the broker serves, and the request stays pending). A listed or inspected target is in its ledger form (an `http_request`'s path and query as record-ledger R9a records them). Unknown run or malformed protocol is usage error 2; unavailable endpoint, authentication or ledger failure is 125. The operation remains refused on failure. JSON adds the run and pending/request/decision object; text escapes control characters. No body or credential is displayed by request holds.
  - Status derives `waiting approval` after done/lost checks and before the stalled check (R9) and model/tool waits, while idle stays under `stall_after` plus the 1h `ask.timeout` ceiling (amended 2026-10-05: it was checked after R9; now before it, matching the watcher's R4 hold, and bounded as R9 states), from at most 64 recorded asks lacking a matching answer. Optional `pending_approvals` in JSON is present when positive. Matching legacy v1 answers need no additive `approved` field; duplicate/malformed payload fields or an impossible pending-state overflow fail the read, while unrelated events and unmatched answers create no readiness. Ended or unlocked runs report no live pending count.
  - `dns <name> [--type A] [--run-dir <dir>] [--server-pid <pid>] [--json]` queries a running run's DNS broker
    (network-controls R8; `net.dns.mode: broker`) for one name and question type, by default from the
    `TEGO_DNS_BROKER_DIR` and `TEGO_DNS_BROKER_PID` a governed process inherits. It prints `<name> <type>
    <rcode>` and one line per answer (its name escaped), or one JSON object with `--json`; 0 on NOERROR, 1 on any other
    rcode, 2 for a missing broker, name or type, 125 when the broker cannot be reached or authenticated or its
    reply is malformed.
  - `drift <run> [--json] [--aggregate]` (R13-R17a, 0/1/2).
  - `measure <run> [--json]` (R18-R23, 0; the cost row is labelled `cost`, its value carrying the `est.` R2
    requires).
  - `events <run> [--json] [--kind K] [--source S] [--verdict V] [--rule R] [--step N] [--limit N] [--last | --follow]` (Filter, 0; values
    within one flag are alternatives and different flags are conjunctive; an unknown `--kind`, `--source` or
    `--verdict` value is a usage error, 2; a `refused` line carries no verdict field, so `--verdict refused`
    matches it as well as the action lines refused; a negative
    `--limit` is a usage error, 2; `--last` is an ordering, not a kind: it prints the single newest event the
    filter matches, defaulting the kind set to `refused|gap|limit` only when `--kind` gave none, and reads it from
    the ledger, never from the advisory `last-refusal.json` — §3. It reads the ledger from its end
    (`ledger.Reader.Backward`) and stops at that event, so it costs the distance from the end to the answer: about
    60 us on a 137,200-event run whose last failure is near its end, where reading the whole ledger twice, to find
    the event's instant and then render what was stamped then, took 2.1 to 3.0 s and 1.26 GB of allocations
    (`BenchmarkEventsLast`); a filter nothing matches reads the whole ledger once, from the end (1.3 to 1.5 s there).
    The output is byte for byte what the two passes printed (`TestEventsLastIsWhatTwoPassesPrinted`), with one
    difference by design: an older event stamped at the same nanosecond as the newest is no longer printed beside it
    (`TestEventsLastIsOneEventWhenAnOlderSharesItsInstant`). The lines after the answer are decoded and a damaged one
    is `[ledger-corrupt]`; damage before it is not read, as `status`'s state probe does not read it, and is left to
    a full view and `--verify` (§6 E3; the `--last` help says so). The newer-version count `--last` warns of is of
    the lines it read. Keeping the old exit 125 over damage before the answer was rejected: it needs every line
    decoded, which is the cost this removed (1.06 s and 631 MB at 137,200 events); a `json.Valid` pass over the
    earlier lines (0.13 s there) would still not be the old check, passing a line that is JSON and not a record;
    and the printed answer depends on no line before it. A stderr note on every `--last` was rejected as noise
    on every healthy call. Whoever needs the whole ledger checked runs `events --verify`.)
  - `events <run> --follow` (*added 2026-10-24*; 0/2/125), with `--json` and the filters
    above: prints what `events` prints for the lines the run holds, then for each line its Writer appends, read by
    one `ledger.Follower` (`record-ledger.md` §4 `Follow`) that checks the chain as each line arrives (id, seq,
    prev, the run's id, `run_start` first, nothing after `run_end`), so it reads each byte once instead of
    rescanning the run. `--json` is the stored bytes, flushed as each line arrives; the table's columns are
    measured over the lines the run held when the follow caught up (at most 1,024, as `events` measures) and then
    streamed, so over an ended run the output is `events`' byte for byte (`TestEventsFollowOfAnEndedRunIsEvents`).
    It exits 0 at `run_end` once the launcher has released the run's lock (it anchors after `run_end`, lock
    held), 0 at `--limit` matches, 125 `[ledger-corrupt]` naming the file and the line after the rows before a
    break in the chain or bytes after `run_end`, 125 `[run-lost]` when the lock is free and there is no `run_end`
    (the launcher died; the next `run`, `stop` or `gc` sweep ends the run as orphaned), and 125 "interrupted" on
    the first signal, as the other views. A run that has not written `run_start` yet is waited for, where
    `events` says "no run record". It wakes on inotify; when inotify cannot be had (`EMFILE`, `ENOSPC`) it says
    so on stderr and polls every second. `--last` (read back from the end for one answer) and `--verify` (one
    pass with the anchor) do not combine with it (2). Newer-version lines are skipped and counted, as `events`
    skips them.
  - `events <run> --verify [--json]` (`record-ledger.md` I3/I4/E29, 0/1/2/125). The run verified is the one
    `<run>` names — the run directory's own id, never the id the ledger claims while the path names one, so every
    line must carry it and the anchor is read under it; another anchored run's ledger copied into the directory
    does not verify, and a deleted anchored ledger is a finding, not "no record". A path names the run by its last
    component when that is a run id, even a link to another run's directory (the named run's record is then gone,
    and the other run's ledger is not verified in its place), and otherwise (a link such as `~/latest`) by the
    first run id its link chain names; a path that reaches no run id at all (a copy under another name, a link
    chain that names none) is the one case the run is the id on the ledger's first line. `.` is the working
    directory as `$PWD` names it when `$PWD` is that directory, and otherwise the kernel's path, which names a
    link's target (`cd -P <ledger_root>/A`, A a link to B, names B) (`record-ledger.md` §4 `Verify`). Every line
    is re-hashed against its `id`, the `seq`/`prev` links walked, each event validated, and the head checked
    against the invoking user's `chain.log` whenever it holds a line for the run — a ledger truncated after its
    `run_end` verifies internally and only the anchor tells it from a lost run; an ended run with no anchor line is
    a finding too (E29), never repaired from the ledger it would vouch for, and so is an anchored run whose ledger
    or directory is gone; a run not yet ended owes no anchor and says so. No filter, `--limit` or `--last` beside
    it.
  - `gc [--keep <d>] [--dry-run] [--builds] [--json]` (default 30 days, sweep + retention, 0; `--keep 0s` keeps no
    run that is not running, the `gc --keep 0` sweep `record-ledger.md` names). As root it also removes the tier-2
    builds no launcher holds and no live run needs, once idle for `bpf.linger`, and `--builds` removes them now,
    whatever their idle time, with their capture probes (ADR 0022 (4), ADR 0026 (7)), and every run ring no run
    holds, of any build (ADR 0026 (6) as amended; another build whose run set has a row keeps every ring, since
    only its keys are read, ADR 0022 (5)); it prints how many of each it removed, and `--json` carries
    `builds_removed` and `rings_reclaimed`. A failed build, capture-probe or ring sweep is reported on stderr and
    in `--json`'s `errors` (prefixed `builds: `, `capture probes: `, `rings: `) beside each run the pass could not
    finish; the exit stays 0. `--builds` without root, or with `--dry-run`, touches no build and says so on
    stderr.
  - `licenses` (0; *added 2026-11-02*, docs/GAPS.md B12): the licence texts and third-party notices the binary
    embeds, the licence files of the release's licenses archive, each whole under a `==> <name> <==` line: `LICENSE`,
    `NOTICE`, `THIRD_PARTY_NOTICES.txt`, then `LICENSES/*.txt` by name. No argument (2). `tego-control licenses` prints
    the same: like `version`, each binary has its own, and tego does not hand it off.
  - `version [--json]` (R30, 0).
  - The hidden `__child --run <id>` (no independent flags, exec'd by `run` only, undocumented).

  `serve` hands off to tego-control (R35); `learn` is above; local `ask`/`approve`/`deny`/`alternate` are implemented below. There is no command, by design: `completion bash|zsh|fish`.
- **R30 `version`** (VERSIONING.md §1): one `key=value` line per field — `tego commit date go contract_schema
  record_v record_readers bpf_hash parsers control_sha256` — plus `--json` for the same as one object; first line of every
  bug report and of `doctor`'s own banner. `control_sha256` (*added 2026-10-24*, ADR 0100) is the SHA-256 of the
  `tego-control` this build hands off to, `none` for an unpinned build; `tego-control version` prints the same
  version, commit and date and the SHA-256 of itself.
- **R31 Default rendering**: `status`/`drift`/`measure` print one aligned terminal table over their `Report`/
  `Snapshot` fields, in declaration order; `--json` emits one JSON object per invocation for those three, and
  for `events --json` one **raw stored line** per event (I8) — the one `--json` that is ledger bytes, not a
  re-serialized struct. The one object holds whatever the table would say: `status --json` with no runs is
  `{"runs":[]}`, never the table's `no runs`, and a run's `exit_code` is present exactly when its `exit_reason`
  is, `0` included. An orphaned run uses the logical launcher-failure code 125. For an older orphan
  ledger whose code is absent or zero, `status` reports 125 without rewriting the stored record; explicit
  nonzero orphan codes and an ordinary successful exit remain as recorded. This does not reconstruct
  the dead launcher's child wait status, and the status command's own exit remains R25's 0/1 result.
- **R32 Price-table version.** `PriceTable.Version` is read but otherwise decorative in §2; this rule fixes that.
  At `cli` startup, a `Version` the binary does not recognize (today: anything but `1`) is handled like an
  unreadable table (E15/§7) — warn once (`gap what=record why=price-table-version-mismatch got=<v>`), continue
  with `prices=nil`, never a hard error. `compile`/`doctor` do not validate it against a binary expectation (§11).
  The table is decoded strictly: a key its schema does not name (a misspelled `input_per_mtoken`, which a lax
  decoder drops, leaving that price at $0 and a `cost_usd` budget that never trips) makes it unreadable, the
  warning naming the key and its line. A model entry with no `input_per_mtok` or no `output_per_mtok` is an
  unpriced model (R2: the `unpriced-model` gap, charged at `MaxCost`, from whose highest prices it is left out);
  one with no cache price is unpriced for a response that reports that cache counter (R2). When every entry is so
  partial that the table prices no model, a cost budget the contract declares is refused at launch, 125
  `[budget-unmetered]`, and `compile` reports it with that code, as under no table (amended 2026-10-17: it ran to its first response while a table listing no model was refused); one a machine ceiling alone
  imposes is warned `[unenforced]`, and its run ends at its first response.
  A budget with nothing to count it is refused, never run (amended 2026-10-16). A
  `limits.tokens`, `cost_usd` or `repeats` budget the contract (or a profile it extends) sets never trips when the
  capture the run uses is off — the contract's `capture: off`, or a machine `capture:` ceiling of `off` that lowers
  it there — when the contract declares no `models:` endpoint and captures with the forwarder, which binds a
  listener only for a declared endpoint and so never starts (`gap why=no-models`), or under `record: off` with a
  pinned `capture: uprobe`, since the uprobe source captures nothing then and no forwarder runs beside it; and a
  `cost_usd` budget never trips when no price table loads. An `auto` contract under `record: off` is compiled to
  capture `forwarder` at every tier, the capture it really has (capture-derive.md R4, amended 2026-10-16), so it is
  metered when it declares a `models:` endpoint and is the forwarder case above when it declares none.
  A table that loads and lists no model (`version: 1` alone, or `models: {}` beside server-tool fees) prices
  nothing either, so `limits.FromMachine` reads it as no table: the same warning (`the price table <path> lists no
  models; cost is not estimated`) and `no-price-table` gap, and the same refusal and `[budget-unmetered]`
  (`TestFromMachine`, `TestCompileReportsACostBudgetUnderATableListingNoModels`); it loaded silently, and a run
  under it passed every response at $0. Ending such a run in the watcher at its first response was rejected: a
  budget a machine ceiling alone imposes would then end a run a missing table leaves running. A table whose every
  entry lacks an input or output price also prices no model, and a budget the contract declares under it is refused
  the same way (`runtime.refuseUncountedBudget`, `TestADeclaredBudgetNothingCountsIsRefused`,
  `TestCompileReportsADeclaredCostBudgetUnderATableThatPricesNoModel`). That table still loads, rather than reading as
  no table: a ceiling a machine alone imposes keeps ending its run at the first response (R2), which no table would
  let run on uncounted. Rejected: reading it as no table in `limits.FromMachine` (the same launch refusal, but the
  ceiling-only run would lose that end and run uncounted).
  The uprobe source reads the agent's own TLS by host, so a run that lands where it runs is metered without
  `models:`. Such a run is refused once its sources have started and before `run_start`, the agent never released
  and no record left, exit 125 `[budget-unmetered]`, the message naming the budgets, the cause and the fix
  (`tego run: runtime: budget unmetered: the tokens budget cannot be counted, so the run is refused rather than run
  with a limit that never trips: the contract sets capture: off, so no model traffic is metered. Fix: set capture:
  auto, or remove the budget`; `runtime.refuseUncountedBudget`, `TestADeclaredBudgetNothingCountsIsRefused`,
  `TestIntegrationADeclaredBudgetNothingCountsIsRefused`, `TestRunRefusesADeclaredBudgetNothingCounts`). The cause
  named is the one whose fix is enough: a missing `models:` endpoint where the forwarder would capture comes before
  `record: off` (the forwarder records under `record: off`), and `record: off` is named only where the run's capture
  is the uprobe source; a run at tier landlock under `record: off` with no `models:` was told to set
  `record: summary`, which only led to a second refusal. It ran
  instead with only compile's `[unenforced]` warning and a `budget-unmetered` gap and exited as the agent did: for a
  20-hour unattended run, a limit that silently did nothing.
  `compile` (and `run`, which prints the same diagnostics) reports the same contracts as a warning tagged
  `[budget-unmetered]` at the budget's line, saying the run is refused: `limits.tokens budget never trips: the
  contract sets capture: off, so no model traffic is metered, and every run of this contract is refused`, `...: the
  machine's capture ceiling is off (<file:line>), ..., and every run of this contract on this machine is refused`,
  `...: no models: endpoint is declared, so the forwarder capture does not run ..., and every run of this contract is
  refused` (which includes an `auto` contract under `record: off` with no `models:`, at any tier, since it compiles
  to the forwarder), for an `auto` contract that may land at tier landlock `... never trips where the run lands at
  tier landlock: ..., so a run that lands there is refused`, for a contract that pins `capture: uprobe` under
  `record: off` `record: off with capture: uprobe records
  no model traffic, so the tokens budget sees none of it and never trips, and a run that captures with uprobes is
  refused` (fix: `set record: summary, or capture: forwarder`, `... with a models: endpoint` when it declares none), and,
  reading the price table as `run` reads it (`limits.FromMachine`), `limits.cost_usd budget never trips: no price
  table (<why>), and every run of this contract on this machine is refused`. It is a warning, as compile reports a
  pinned tier the build lacks `[tier-unavailable]`, because the refusal is the run's, decided on the capture that
  actually starts, the record mode `--record` may change and the price table the machine has at run time; making it
  a compile error was rejected for that reason, and because `run` would then fail it as a compile error rather than
  with the cause the runtime names. Compile reports exactly the contracts the run refuses, with the run's cause
  and a fix that is enough (amended 2026-10-16): an `auto` contract with a
  `models:` endpoint under `record: off` is not reported, since it compiles to the forwarder, which records under
  `record: off`, and its models[] endpoints are guarded, so a direct connection to the model host is refused and
  the budget cannot be gone around (it was compiled to uprobe, which guards nothing, and its run started the
  forwarder beside probes that placed none: a direct connection was neither captured nor refused, and compile said
  nothing once a later change removed the `[unenforced]` warning); an `auto` contract with no `models:` under
  `record: off` is told the missing endpoint, as the run is, rather than `set record: summary, or capture:
  forwarder` (the second alternative, with no `models:`, was itself refused, and `record: summary` leaves a run at
  tier landlock unmetered) (`TestCompileWarnsUnmeteredBudgets`, `TestRecordOffWithUprobeWarnsThatBudgetsSeeNothing`,
  `TestRecordOffAutoCapturesWithTheForwarder`).
  Reporting every `record: off` uprobe table and letting the run decide was rejected: compile then announced a
  refusal that does not happen, and named a cause the run does not.
  A budget a machine `limits:` ceiling alone imposes is not refused: that ceiling bounds every contract on the
  machine, most of which talk to no model, and refusing them all where no model is declared was rejected. Its run
  records `gap what=record why=budget-unmetered binary=<tokens|cost_usd|repeats>` right after `run_start`, one per
  such budget, whenever `run_start.capture` is `off`, compile warns `[unenforced]` for it only under `record: off`
  with a pinned `capture: uprobe`, and `run`'s one no-price-table line ends `, so the cost_usd budget of <v> never trips` for a
  cost budget so imposed. The run exits as the agent did.
  A budget whose capture mechanism was given to the run and could not start fails closed instead: when the run
  has a `tokens`, `cost_usd` or `repeats` budget, `run_start.capture` would be `off`, and a mechanism the
  selection wanted is not running — a selection gap `why=mechanism-unavailable`, or a capture source that
  started inert (its own `mechanism-unavailable` gap: a capture object the kernel refused, or no capture ring
  because the host's `bpf.ring_budget` had no room for it, enforce-cgroup-observe.md R16; another run of the build
  no longer keeps a run from capturing, ADR 0026) — the run is refused once its sources have started and before `run_start`, exit 125
  `[capture-unavailable]`, the message naming the budgets, each mechanism's cause and the fix
  (`runtime.refuseUnmeteredBudget`, `TestABudgetWhoseCaptureCannotStartIsRefused`,
  `TestRunRefusesABudgetWhoseCaptureCannotStart`). The same refusal holds when the table's capture is `uprobe` at
  tier cgroup or bpflsm and only the forwarder beside the probes runs (amended 2026-10-16): such a
  table guards no models[] endpoint, since the probes read a direct connection's TLS themselves, so with no probe
  running a direct connection to the model is neither captured nor refused, and the forwarder meters only what the
  agent chooses to send it; the run started, with a budget any agent that ignored the forwarder's base URL went
  around (`... cannot be metered on a direct connection to the model, ...: the uprobe capture did not start (<cause>)`).
  An `--observe` run is not refused for it, since it refuses nothing, a direct connection included, whatever its
  capture. The uprobe source under `record: off` is not this refusal's: it captures nothing then by design, so a
  budget the contract declares is refused `[budget-unmetered]` (above). A forwarder that could not start under
  `record: off` is (amended 2026-10-16): every `record: off` run was passed over here, so a
  forwarder whose `forwarder.listen` address another process held was refused `[budget-unmetered]` and told to
  declare the `models:` endpoint the contract declared; it is refused `[capture-unavailable]` naming the forwarder,
  as under `record: summary`. The refusal's fix is each failed mechanism's own: for the forwarder, to free its
  `forwarder.listen` address or set a free one; for a probe capture, the ring-budget advice and `capture: forwarder`
  with a `models:` endpoint. When the forwarder is the only cause the probe fix is left out (amended 2026-10-17: a tier `landlock` run,
  which has no rings and already captures with the forwarder, was told to raise `bpf.ring_budget` or set `capture: forwarder`; `TestABudgetWhoseCaptureCannotStartIsRefused`).
  `compile` also warns `[tier-unavailable]` when the tier the table
  is compiled for is pinned — by the contract's `tier:` or the machine config's concrete tier — and this binary
  does not build it (`agent.WithTiers`), since every run of it is then refused; and `run`'s refusal of such a pin
  puts the build's reason first in its fix, ahead of `doctor`'s machine reasons.
- **R33 `compile --test` tier simulation.** SEMANTICS §5's net decisions differ materially by tier (Landlock's
  `CONNECT_TCP` is port-blind; root tiers decide `host:port` in the kernel). `decide.Evaluate` (R28) simulates
  every tier a run of the contract can get (ADR 0019), never the tier this machine's `doctor` can reach: a
  pinned contract in its pin alone, so a laptop correctly tests a `bpflsm`-pinned contract, and an `auto`
  contract in every tier its run can get, computed from the build alone, with no probe and no privilege, so a
  tier this machine lacks is still answered for, which errs toward reporting a difference and never toward
  certifying a refusal. This answers the former open question of warning when the local ceiling (SEMANTICS §8)
  would force a lower tier at real `run` time (§11).
- **What reads the whole ledger** (*added 2026-10-16*). `events --last` reads from the end
  (R29). `status`, `measure` and `drift` read every line, once, and their time grows with the ledger: what they print
  is a total over every line (`status`'s event count, step, gap line and pending asks; `measure`'s tokens, cost,
  steps, idle max and repeats; `drift`'s counts per entry), no line can be skipped without changing it, and the
  ledger is the only store (ADR 0004), so there is no index or running total to read instead. Measured on a
  laptop-class x86 machine (i7-10870H, `-benchmem`): `status.Derive` 1.4 to 1.9 s and 636 MB of allocations on 137,200 events, 100 to
  140 ms on 9,800 (`BenchmarkDerive`); `measure.ComputeAt` and `drift.ComputeCtx` about 265 ms on 29,400 events
  (`BenchmarkCompute`), about 9 us an event, most of it `record.Decode`'s validation of each line. A bare `status`
  reads one run, the newest; `State`, which every sweep asks of every retained run, reads only the tail (§2.3). A
  cache of totals beside the ledger was rejected (ADR 0004: a second store could disagree with the record); a
  status that printed only the tail's state was rejected because it would drop or change the columns it prints.
- **R34 Gap line** (FEATURES.md C8). `status` and `drift` say what the record could not see beside the
  verdict they give, from the run's `gap` events grouped by `(what, why)` (`internal/check/gaps`): one
  `gaps: <line>` under the table, where `<line>` is `none` for a run that recorded no gap — said out loud, so a
  run with no gaps is never mistaken for a view that does not show them — or one `what/why xN` entry per group,
  joined by `; `, each with the sum of its events' `count` fields (`N events lost`) and up to three of the
  `binary` values it named (`in <binary>, ..., +N more`). `--json` carries the same as `gaps: [{what, why,
  events, lost, binaries}]`, `[]` when there is none. `status --all` prints `gaps <run>: <line>` only for runs
  that recorded a gap; `drift --aggregate` sums the runs'. A gap qualifies the verdict and never changes it: a
  run that lost events is still `done`, and drift's exit code is R25's. A gap whose payload does not decode is
  counted as `unknown/unknown`, never dropped. A person's live changes are written as `gap what=enforce` lines too
  (a live block added, removed or ended; a fence entry lifted, restored, ended or refused; a pause or resume, failed
  ones included; an MCP tool switch; a model route change: `gaps.LiveChange`) but are not coverage the run lacked:
  the text output prints them on their own `live changes: <line>` (`live changes <run>: <line>` under `status
  --all`), only when there is one, and leaves them out of `gaps:`. `live-block-unreadable` and `live-block-lost`
  stay gaps. `--json`'s `gaps` still lists every gap line, live changes included, each with its what and why.
  `status` then says what the gaps mean: `in words: <sentence>` (`in words <run>: <sentence>` under `--all`, `gap_words`
  in `--json`, absent for a run with no gap), from `gaps.Classify`, the receipt's reading: whether actions may be
  missing, what is short if not, and what a person changed (*amended 2026-11-01*). `drift` prints the same three lines
  under its table, and `gap_words` in `--json`; a run with no run_end and no launcher, or a sum holding one, says its
  record may stop short, as a lost run's `status` does (*amended 2026-11-01*).

- **R35 `serve`.** The local page (agents, run timelines, pending approvals, drift, measure over
  the ledger, on `127.0.0.1`) is the control binary's, the second binary `tego-control` (ADR 0100,
  *amended 2026-10-24*). `tego serve`, like every command `tego help` marks `(tego-control)`,
  hands off: it opens the `tego-control` beside this `tego` (never one on `PATH` or in the working directory),
  copies it into a sealed memfd, checks the copy's SHA-256 against the hash this build pinned, and execs the copy
  with the noun and every argument verbatim (`internal/handoff`). Without it the command exits 125 with one line and
  `[control-not-installed]`; an unpinned build `[control-unpinned]`, a mismatched file `[control-mismatch]`, a
  link, a non-regular file, another owner's or a group- or world-writable file `[control-untrusted]`, euid 0
  `[control-as-root]`, a kernel that refuses an executable memfd `[memfd-noexec]`. The usage lists these nouns as
  `(tego-control)`. `tego-control serve` is the local dashboard ([DASHBOARD](../DASHBOARD.md));
  `status`, `events`, `drift` and `measure` give the same answers on the command line, each with `--json`.

**Changes.** R1's changes are listed under R1.
- 2026-11-02, R29 `licenses` (docs/GAPS.md B12): an installed tego or tego-control carried no third-party notice,
  only the release's licenses archive did. Both binaries now embed the licence files (the module root's `notices.go`)
  and print them (`TestLicensesPrintsWhatTheBinaryCarries`, `TestControlLicensesPrintsWhatTheBinaryCarries`); `licenses`
  is the second command each binary has of its own, beside `version` (`TestNoNounInBothBinaries`,
  `TestHandoffNounsMatchControlCommands`), and `scripts/check-licenses.sh` holds the embedded set to its list.
- 2026-11-02, R17a (GAPS C30): drift lists the images exec lines flag `fileless` or `dropped`, by path with their
  verdicts, in the table and in `--json` (`fileless_execs`, `dropped_execs`), and never counts them as drift on their
  own. It did not read the keys, so its report of a run's memfd exec or drop-and-execute was a count under
  `exec-anon` or an `exec[...]` entry with nothing naming the image (`TestDriftListsFlaggedExecs`,
  `TestDriftFlaggedExecsGolden`).
- 2026-10-25, R25 runtime grants (ADR 0064): `Report.Drifted()` skips a runtime
  grant's bucket only for what it allowed. A refusal under `exec.harness-hook[<tego>]`, the hook grant's rule for every
  other vector of the tego binary, made a run report no drift, where the same refused `tego run` under `unmatched`
  drifted before the grant existed (`TestRuntimeRuleRefusalIsDrift` in `internal/check/drift`,
  `TestViewsReadHarnessHookFixture` in `internal/check/viewtest`).
- 2026-10-25, R29 `init`: `--preset <list>` with `--write`, `--allow-host` and `--command`
  writes a contract extending the presets, composed by internal/setup and compiled offline before it is published
  (nothing is written when it does not compile); `--list` prints the presets and host groups; `--write`,
  `--allow-host` or `--command` without `--preset` is a usage error (`TestInitPresetCombinationsCompileClean`,
  `TestInitPresetUsageErrors`, `TestIntegrationInitPresetRunsAtTierLandlock`).
- 2026-10-26, R29 `init`: the composed contract is compiled offline (internal/setup Draft, against
  the machine `tego compile` uses) before any folder is created: one that does not compile exits 1 with compile's
  diagnostics at `agent.yaml` and leaves no `agent.yaml` and no folder (`TestInitPresetThatDoesNotCompileWritesNothing`).
  The file's text is pinned per preset combination (`TestComposeGolden` in `internal/setup`).
- 2026-10-25, R29 `compile` (ADR 0068): `--merged` prints the merged contract, whose sha256 is
  `contract_hash`, in place of the rule table; it is a usage error beside `--json`, `--test` or `--exec`.
- 2026-10-25, R29 `ask`, `approve`, `deny`, `alternate` (ADR 0008 amended, ADR 0100 (7)): the
  run's broker refuses a writer inside any run's or adoption's scope or a look-alike of one, or in another cgroup
  namespace than its own, as unauthorized with the request still pending, and the four commands then say whom it
  serves (`TestAskCLISaysWhomTheBrokerServes`; the broker's rule in `internal/runtime/askpeer_test.go` and
  `askanyrun_integration_test.go`). A listed or inspected `http_request` target is its ledger form, the path cut to
  record-ledger R9a's public route and the query to `?redacted` (`TestBrokerNeverServesRawTarget`); other targets
  are unchanged.
- 2026-10-24, R29, R30, R35 (ADR 0100 (1b), (2)): `tego serve` is no longer an unknown command; it
  hands off to the verified tego-control beside the binary, or exit 125
  with the handoff's reason code (`TestServeWithoutControlSaysNotInstalled`, `TestHandedOffNounsTakeArgumentsVerbatim`,
  `TestNoNounInBothBinaries` in `internal/cli/serve_test.go`; the handoff's own tests in `internal/handoff`). Each
  command registers from its own file, and the usage is sorted by name (`TestUsageIsSorted`); it was the table's
  order. `version` adds `control_sha256` (`TestVersionText`, `TestVersionJSON`).
- 2026-10-24, I6: the stand-in Claude Code under `test/e2e/reason-claude/fakeclaude` joins the
  programs of their own that `tools/checkexits` lets end the process (`os.Exit` in its `main`); it is test
  infrastructure that never reaches a product binary (`TestCheckExitsFindsPlantedViolations` in `tools/checkexits/checkexits_test.go`).
- 2026-10-24, R29 `events`, §7: `--follow`'s `[run-lost]` message names the run
  directory once, not behind the `events.jsonl` path a corrupt-ledger message carries, and names every command that
  ends the orphan (`run`, `stop`, `gc`), as R29 does; it named `run` and `gc` only.
- 2026-10-24, R29 `events`: `--follow` prints the run's lines as its Writer appends them,
  chain-checked line by line, and exits 0 at `run_end`, 125 `[run-lost]` for a lost run, 125 `[ledger-corrupt]`
  at a break; it takes neither `--last` nor `--verify`.
- 2026-10-20, R28 (gate.md R1): an `fs.rename` or `fs.link` row's source is a directory
  that a gate's `fs.read matches` path pattern may match a path beneath only when the row's object is a directory
  (`dir: true`, or a path that exists as one), as a run stats its move's source; a row naming a regular file is
  matched by its own name (`TestCompileTestGateScoresAMovedDirectoryOfAReadPattern`).
- 2026-10-20, R27 builds (ADR 0022 (1), (8)): a build inside its linger whose run set names a
  live cgroup (an orphan's run its reaper has not purged) or cannot be read is listed `kept`, read from its run set at
  the listing, read-only; its line said `tego gc --builds` removes it now, which gc's Force does not do. A kept
  line says whether its timer runs, as every other idle line does. `memlock_unreported` counts an object only when its
  fdinfo has no `memlock:` line: the empty LPM tries every build holds (tego_net_cidr, tego_net_ingress,
  tego_unix_names) say 0, and were counted unreported, so every healthy build read `with 3 objects unreported`.
- 2026-10-20, R27 builds (ADR 0022 (5), (8)): each build's line gives its memlock, whether
  its timer runs and with which pid, and why the sweep doctor ran kept it past its linger (a live run, an unreadable
  run set with the read's error, a sweep that failed on it); such a line no longer says `tego gc --builds` removes
  it, which was false (gc's Force overrides neither keep). The heading sums the builds' memlock. `--json` adds
  `kept`, `kept_cause`, `timer`, `timer_pid`, `memlock_bytes`, `memlock_unreported`.
- 2026-10-20, R29: `run -`, `watch --boundary -` and `adopt --boundary -` are exit 2
  `[usage]`: standard input is compile's alone (agent-contract.md R26).
- 2026-10-20, R29: a name both registries hold is refused `agent-ambiguous` (agent-contract.md
  R26), so compile's print and `--json` `source` no longer report a user entry a project entry hides.
- 2026-10-20, R29: `compile`, `run`, `watch --boundary` and `adopt --boundary` take an
  agent name as well as a contract path (agent-contract.md R26); compile prints and `--json` reports the source,
  and run_start records it (`contract_source`, record_minor 13).
- 2026-10-27, R29 `compile` (ADR 0043 D6, C10): for a table a decision plane can run whose covered
  per-file `deny_read` rows the plane's row compiler left to the name rows, the print adds `plane     <n> per-file
  deny_read rows held by the name rows (ADR 0043 D6); <m> paths keyed` after the table (the table still lists every
  file, and tier landlock keeps them all); nothing for a table compacted nothing of (`TestCompilePrintsPlaneCompaction`;
  the guest's `TestCompactedTableStaysAtBPFLSM` reads it for 4,500 `.env` files).
- 2026-11-02, R27 Output: `doctor` prints a `summary:` line between the probe lines and the capability table: the
  tier, a machine config's cap, and what each tier above it needs, by name. The tier line was the first answer a
  reader met, after the table's 31 rows. The tier line, the `missing for` lines and the fix line keep their place
  after the table, and `--json` is unchanged (`TestSummaryComesBeforeTheMatrix`, the plane `.txt.golden` files).
- 2026-10-27, R27 the matrix and the plane probe (ADR 0043 C11): every build enforces name entries, so
  the `fs.deny_read.created_later` row is no longer turned off with a "does not enforce name entries" note, and the
  plane probe's known answers always hold the seven name cells (16 in all): a mode that answers one wrongly is not
  selected. `compile --test`'s `bpflsm:` note names the name entries wherever the plane's rows carry them.
- 2026-10-27, R27 the matrix (ADR 0043 C9): the `fs.deny_read.created_later` row. Tier `cgroup`'s conditional cell is on where the plane probe selected a mode and the build enforces name entries, off on the fanotify fallback with a note saying what the listener and the supervisor refuse; both root tiers' cells are off, with the reason, in a build that does not enforce name entries (`TestMachineMatrixNameEntries`).
- 2026-10-17, R27 D5: the wait for D5's notification no longer reads a poll that came back `POLLERR` alone as one to receive, which went on to a blocking `NOTIF_RECV` past the 5 s bound; it polls again, and `POLLHUP`/`POLLNVAL` fail D5.
- 2026-10-05, R27 D5: a round trip the kernel took back because a signal reached a thread of it (`ENOENT` at `RECV` or `ADDFD`; `EINPROGRESS`, `ESRCH` or `EINTR` at `ADDFD`) is made again on a new throwaway thread, up to five times; one such interruption failed D5 in a guest boot, and a failed D5 leaves `doctor` and `run` with no tier. Any other errno still ends the round trip at once, so an `EINVAL` below 5.14 still names the kernel floor, and five interruptions in a row fail D5 with "re-run" as the fix, not a kernel upgrade.
- 2026-10-05, `Reach` and the `root` line (ADR 0042 (5)(d)): root means effective uid 0 in the initial user
  namespace; under `unshare -r` doctor and a run probed the root tiers' programs as root.
- 2026-10-05, R28 (ADR 0043): a row's `dir: true`, and `Action.Dir`; the cgroup and bpflsm columns answer name entries once the build enforces them (`agent.NameEntriesEnforced`).
- 2026-10-05, R27 "What a run probes" : a failed capability-only network row no longer keeps the run-probe cache from vouching.
- 2026-10-05, R27 "Concurrent misses" and E30: the probe flight (its lock directory, the 30 s wait, the 128-file limit, the fallback to a fresh probe) is described; it was in the `ForRun` comment alone.
- 2026-10-05, R27 "Concurrent misses" : a run that waited for an answer that was not kept probes without the lock, beside the other waiters; the lock is let go once D8's answer is kept or dropped.
- 2026-10-05, R27 "Concurrent misses" : a coordination failure is its own note (`Report.CoordinationNote`), not "the run-probe cache is unusable"; a refused cache directory is named once.
- 2026-10-05, R27 "Concurrent misses": at the 128-file limit a new key reclaims flight lock files nobody holds, and a run whose lock file was reclaimed under it opens the name again; the limit bounds runs coordinating at once, not keys per boot.
- 2026-10-05, R25: a failed write to tego's own stderr no longer turns `run`'s agent exit 0 into 125; the output check, now written down, covers every other command.
- 2026-10-05, R29 `init`: without `--force`, a link(2) refused as EPERM, EOPNOTSUPP or ENOSYS falls back to `renameat2(RENAME_NOREPLACE)`; init needed hard links since 2026-10-03.
- 2026-10-16, R29 `stop` (ADR 0022): a root `stop` that ends with the run stopped or not running starts the timer of every tier-2 build whose timer died; it removed nothing for them, which left such a build attached until a gc.
- 2026-09-30, R27: D7's plane clause says the fanotify fallback does not scale past a few concurrent runs.
- 2026-09-29, R29 `gc`: the bpf sweeps' failures are in `--json` `errors`; `--builds` that
  touches nothing (no root, `--dry-run`) says so.
- 2026-09-29, R29 `stop`: a signal while `stop` waits gives up the wait; it used to write the backstop `cgroup.kill` at once.
- 2026-09-29, R29: a SIGINT or SIGTERM between compile and the runtime's own subscription refuses the run as interrupted (exit 125 [run]); it had been swallowed and the agent started, or reported as [tier-unavailable].
- 2026-09-30, R29 `run`: the CLI subscribes to signals before its last interrupt check and hands the runtime that channel, so a signal in the window before the runtime's own subscription is queued, not swallowed.
- 2026-09-30, R29: `status` stops on the first signal (`--all` between runs and every 1024 lines); `stop` says "interrupted" for a signal during the pid-line wait, and waits at most 5 s after its backstop `cgroup.kill`, not a second full grace.
- 2026-09-30, R29 and §6 case 8: `drift` stops on the first signal too (every 1024 lines, and between `--aggregate` runs); `drift --aggregate` no longer counts a run whose ledger holds no complete line as skipped; `compile --test` escapes the row text it prints.
- 2026-09-30, R29 `stop`: ESRCH at delivery is not a failure; a held lock with no pid line is waited on, not signalled as pid 0. `status` prints no diagnostic and logs nothing for a run directory with no `events.jsonl` (E26 covers runs it could not read).
- 2026-09-30, Views: `events --verify`'s anchor path is escaped with `Printable` too; the ledger's run-mismatch errors quote the ids with `%q`.
- 2026-09-29, `Watcher.Tick`/`Run`: a kill that failed after a breach raised from `Observe` is retried by `Run` and, if it fails again, returned to the worker group.
- 2026-09-29, R17: `Undone`/`UnusedMCP` came from intersecting the runs' lists, so one run with
  no contract table emptied them for the agent; they come from the summed counts.
- 2026-09-30, R24/R29: one machine load per invocation; `events --verdict refused` matches `refused` lines; a run id that reads as `no such run` keeps the skipped-layer warnings.
- 2026-09-30, R29 `events`: the rule lists `--source` and `--verdict` and their filter semantics; the `Filter` sketch matches the code.
- 2026-09-29, R29 `compile`: an interrupt before the compile prints `tego compile: interrupted`; it exited 125 silently.
- 2026-09-29, R17: the aggregate is changed when any run's own R16 comparison is; it read only
  the first run's `CurrentHash`.
- 2026-09-29, R22: a window starts at the largest reading so far; it started at the line
  before's, which overstated idle when a capture-time reading went back.
- 2026-09-29, R29: `events` and `measure` stop on the first signal; they ignored their
  context and read the whole ledger until a second one.
- 2026-09-22, R12: a zero budget is written into `run_start.limits` and `"0s"` read as a ceiling of zero, not
  as absent.
- 2026-09-22, R15: a server no producer could have recorded is UnobservableMCP, not unused;
  `parsers["mcp"] = "exec"` names the P0 producer.
- 2026-09-22, R16: the run directory holds the canonical merged contract, recompiled with `extends:` sealed
  against `run_start.cwd`.
- 2026-09-22, R27 D8: an open refused before the listener saw it is the host's policy, not a tego bug.
- 2026-09-22, R29 `stop`: `--grace` is written into the stop marker and is the launcher's grace; a second
  `stop` keeps the first one's.
- 2026-09-22, R29 `events --verify`: the run verified is the one the path names, not the ledger's first line.
- 2026-09-23, R14: a `models[]` entry is one Net row under both names the record
  gives it; forwarder- or uprobe-recorded use keeps it out of Undone.
- 2026-09-23, R-res: resource peaks added to `measure` and `status`; a live run reads `unknown until the run
  ends`; `--json` carries the recorded object with unknown keys.
- 2026-09-23, R27 D5: the probe thread is never the main thread and has ended before D5 returns.
- 2026-09-23, R27 D7: real programs are loaded per hook (stand-ins only where none exists); BTF resolved per
  hook type; `uprobe_ssl` capture rows added; capture attach failure is `no-openssl`, not
  `mechanism-unavailable`.
- 2026-09-23, R27 Output: one tier derivation for `doctor` and `run`, `enforce.Buildable` refusing a dynamically
  linked build; tier `cgroup`'s fix line reads only its own checks; Yama's scope-2 remedy persists via
  `/etc/sysctl.d`.
- 2026-09-23, R27 "What a run probes" : a run probes only its reach; the run-probe cache key holds
  the process's privilege, cgroup and namespaces (entry format 3).
- 2026-09-29, R27 "What a run probes" (TIER3-PLAN T7): tier `bpflsm` is built with the objects, so a root auto
  run reaches it; reach `bpflsm` is reach `cgroup`'s scope and D6's list, not doctor's whole probe.
- 2026-09-30, R27: doctor's plane probe never reads or keeps the known-answers file (only a run's does); D8's fix names `/run/tego`, where its fixture lives, and not `$TMPDIR`; tier cgroup's unix note says the plane decides unix names below 6.7 where a plane mode is selected.
- 2026-09-30, R27: a killed probe's empty scratch cgroups are swept like its fixture directories, and a run whose run-probe cache is refused or unwritable says why on stderr.
- 2026-09-29, R27 D7 (TIER3-PLAN T8): tier 3's rows are the decision plane's per hook per mode; the plane's mode
  probe runs inside D7 and at reach `cgroup`, is kept in the run-probe cache (format 4) and adopted from a pinned
  build; tier `bpflsm` needs LSM mode; `bpf.plane` (`/etc` only) selects tier `cgroup`'s mode.
- 2026-09-29, R27: a faulted plane probe is not kept in the run-probe cache (format 5, whose
  key also holds `vm.memfd_noexec`), the plane's fixtures live under `/run/tego` and not `$TMPDIR`, and
  `vm.memfd_noexec=2` is a named precondition of both modes; D2 skips existence relocations and parses the kernel
  BTF once per process (one shared parse, not the library's, which keeps none); D3, D7 and the plane make their scratch cgroup by one rule (a leftover one is
  replaced when empty, an error otherwise).
- 2026-09-30, R27 "What a run probes" (tier-3 performance, enforce-plane §2.18): the run-probe cache (format 6) keeps
  D2's answer and the kernel's functions a run asks its BTF about, so a run with a valid entry parses no BTF.
- 2026-09-30, R27: D8's fixture directory is under `/run/tego` too (the temporary directory only as a fallback), `DiscardCache` removes the entry only while the file under its name is the one the report read, and `bpf_hash` is computed once per process.
- 2026-09-30, R27 D7: a killed plane or D8 probe's fixture directory is swept by the next
  probe of its kind.
- 2026-09-30, R27 D7: the plane probe makes one exec image per probe, not one per side.
- 2026-09-30, R27: a list no mechanism could read makes `fixFor` and the missing line say so (with the securityfs fix) and never build a bare `lsm=bpf` line; tier `bpflsm`'s matrix takes the ABI 6 row like `landlock` and `cgroup`; the kernel BTF is parsed once per process by doctor (D2, D7, plane), not once per call.
- 2026-09-30, R27: a plane load the kernel refuses the same way every time is a failed mode the run-probe cache keeps, not a fault (`TestPermanentLoadRefusalIsAFailedModeNotAFault`); a faulted plane answer keeps the entry's D7 and D8 half, so the next run answers the plane alone (`TestRunCacheFaultedPlaneReprobesThePlaneAlone`); the entry keeps D2 only when it passed (`TestFailedBTFIsNotCachedAndIsProbedAgain`; format 7); D7 decides an optional hook absent by the backend's own test, not by kernel version.
- 2026-09-30, R27: `ForRun`'s contract says `DiscardCache()` is a no-op once a fresher answer replaced the entry; the root integration test discards through the report read from the entry it last kept, and checks that a report read from a replaced entry leaves the fresh one.
- 2026-09-30, gc: `--builds`' ring reclaim keeps every ring of another build whose run set has a row.
- 2026-09-30, R1, R2, R32: token totals saturate at the largest `uint64` instead of wrapping (`ledger.SatAdd`, `TestTokenTotalsSaturateInsteadOfWrapping`); `compile` warns when a cost budget's table prices no model (`TestCompileWarnsCostBudgetWithoutServerToolFees`).
- 2026-09-24, R2: the unpriced-model gap is per model, capped at 32.
- 2026-09-24, R2: unpriced spend is charged at `MaxCost` under a cost budget.
- 2026-09-28, R2: `MaxCost` bounds a cache kind the table prices nowhere at its highest output rate, not $0.
- 2026-09-30, R2: a cache price any complete entry omits is charged at no less than the highest output rate, not at another entry's lower price.
- 2026-09-24, R2: 1-hour cache writes and server-tool requests are priced.
- 2026-09-24, R4: under `record: off` answered notifications and kernel samples touch the
  watcher.
- 2026-09-24, R7/R8: an unlocked run with no line is never started, not lost.
- 2026-09-24, R14: UnobservableFS for `fs.deny_read`/`fs.watch` a run could not record.
- 2026-09-30, R14: UnobservableRecord for entries a `record: off` run could not record.
- 2026-09-24, R19: lone `refused` lines (keyring, mount family) count, in drift's `other` section.
- 2026-09-24, Views: terminal escaping, strict `events --json`, process counts, `status` idle from the largest
  `mono_ns`.
- 2026-09-24, R25: `doctor --require` unmet is 211; a missing run or a
  directory with no `events.jsonl` is a usage error, 2; `status ""` is 2.
- 2026-09-24, R25: no `run_start` is 125 `[io]` "no run record" in `events`, `drift`, `measure`
  and `events --verify`; bytes after `run_end` are 125 `[ledger-corrupt]` with their offset.
- 2026-09-24, R27 D3: D3 asks `FS.CanPlace`, so a login outside `user@<uid>.service` gets no tier `landlock`.
- 2026-09-24, R27 Output: `net.unix_abstract_scope` read from the ABI; `fanotify` `null`
  when D8 did not run.
- 2026-09-24, R27: `doctor` reports ledger-root runs no sweep here finishes.
- 2026-09-24, R27 (ADR 0022 (8), ADR 0026 (7)): `doctor` lists the tier-2 builds as root, with their capture
  probes; R29 `gc --builds` removes idle ones now.
- 2026-09-24, R27 (ADR 0026 (2)): `doctor` shows the ring budget, its use, and each build's run rings.
- 2026-09-24, R32 (ADR 0026): the refusal's cause beside another run of the build is gone; a capture ring the ring
  budget left out is one.
- 2026-09-24, R32: a budget whose capture mechanism could not start is refused, 125 `[capture-unavailable]`, not
  run unmetered with a `budget-unmetered` gap.
- 2026-09-24, R28/R33 (ADR 0019): `compile --test` answers in every tier the run can get.
- 2026-09-24, R28: the test table is read as strictly as a contract.
- 2026-09-24, R28: one document, at least one row; no tag, no NUL; the contract's path and
  version rules.
- 2026-09-24, R29: second signal ends a command; `init` refuses a missing dir and links;
  `--tier auto`; `status` id with `--all`, negative `--limit` are usage errors; `measure` cost label;
  `--keep`/`--grace` take the config duration grammar.
- 2026-09-24, R29 `init`: the starter compiles with no warning.
- 2026-09-24, R29 `compile`: `compile -` reads the contract from standard input.
- 2026-09-24, R29 `compile`: `compile -` reads a socket as a pipe; every message labels it `<stdin>`.
- 2026-09-24, R29 `run`: flag parsing stops at
  the first non-flag token; no `<cmd>` runs the contract's `command:`; a given `<cmd>` is granted by absolute path
  for every exec and recorded in `run_start.run_command_grant`.
- 2026-09-24, R29 `stop`: the
  backstop kill goes to the recorded scope only; the marker is placed through the ledger walk; a root stopper
  needs root's launch record.
- 2026-09-25, R29 `gc --builds` (ADR 0026 (6) as amended): also reclaims every run ring no run
  holds, and `--json` carries `rings_reclaimed`.
- 2026-09-24, R31: `--json` holds whatever the table says, `exit_code` 0 included.
- 2026-09-24, R32: `[unenforced]` for a cost budget
  with no price table and a budget nothing meters; `budget-unmetered` gap; `[tier-unavailable]` for a pinned
  tier this build lacks.
- 2026-09-24, R35: written as a rule with its condition.
- 2026-09-25, R27, R29: `doctor -h` and its `--require` refusal name the tiers; tier bpflsm's
  missing root line names bpflsm; `run -h` names `--offline`.
- 2026-09-24, R32: the price table is decoded strictly; a model with no input or output
  price is unpriced.
- 2026-09-24, R27: D9 `swap` added, a failed check with the fix when a memory cap can be exceeded into
  swap (ADR 0038's note); `Results` has nine entries.
- 2026-09-24, R27: as root, `doctor` sweeps overdue builds and capture probes a dead helper left
  before it lists the builds.
- 2026-09-28, R28, R33 (ADR 0028 S1): rows are answered by the decision core, `internal/policy/decide.Evaluate`
  (`agent.TestTable.RunBy`); `agent.RuleTable.Evaluate` is a deprecated shim over it.
- 2026-09-29, R27 D2 (enforce-cgroup-observe.md E31): D2 parses the BTF and checks the objects' CO-RE fields by name.
- 2026-09-29, R29 `init`: `.gitignore` is read before anything is created; a refusal there
  left `.tego/` and `agent.yaml` behind.
- 2026-09-29, Views: `Printable` also escapes Cf, Zl, Zp and the tag block, so invisible text in a file name or argv shows.
- 2026-09-29, Views: `measure`'s table escapes ledger text too; its run and agent cells were raw.
- 2026-09-29, R25: a bare run id resolves under the ledger root even when the cwd holds
  a directory of that name; it used to open the cwd's.
- 2026-09-29, R27 D7 (enforce-cgroup-observe.md R10): D7 names the build of `trace_proc` it loaded (`reader`,
  `reader_why`), and fails tier `cgroup`'s rows naming lockdown where `lockdown=confidentiality` leaves no build.
- 2026-10-05, R28: the rule names `net.http` rows and their `method` key, the contract's `gate:`
  applied after each tier's floor, the gate fields of a `--json` cell, and `decide.Evaluate`'s current signature;
  the code had all of them since 2026-10-04 and the rule none.
- 2026-10-05, R29: `dns` added to the command list with its own entry; 2026-10-04's change
  registered it in `internal/cli/main.go` and the list did not name it.
- 2026-10-05, R7 and R13 views of `best_effort` (ADR 0041 D1 (a)): the list can name `deny_write/default` too, so
  `status` and `drift` say "decisions on copied syscall facts", no longer "gate decisions".
- 2026-10-05, R4 (record-off C1): the watcher pulls activity at `Tick` (`AddActivity`): raise only, a reading below
  the run's origin ignored and one past the clock clamped. Nothing pushes a kernel stamp per action, and no ring
  carries one.
- 2026-10-26, R4 and R3: when the agent's stdin is a terminal, input the agent reads from it is activity under a
  stall budget (`sharedTerminal.inputActivity`, `AddActivity`): each Tick fstats the terminal descriptor the run
  already holds and a changed access time (the kernel stamps it when a read returns bytes) counts as activity at that
  Tick. No key is read or recorded. The kernel stamps it once per 8-second window (`tty_update_time`), so input is
  seen up to 8 s late and `stall_after` under about 16 s can still end a session being typed in. Wall is unchanged, a
  hard cap; `[wall-hard-cap]` (informational: `tego compile` prints it, a run only under `-v`) tells a contract that
  sets `wall` without `stall_after` so.
- 2026-10-05, R4 (record-off C6): the forwarder's relayed chunks are activity in every record mode under a stall
  budget; a streamed response longer than `stall_after` was killed as a stall in `summary` as well as `off`.
- 2026-10-05, R9: status measures idle from the newer of the ledger and the launcher's activity
  sidecar while the lock is held, and `--json` names which (`idle_from`); it read stalled while the watcher did
  not kill.
- 2026-10-16, R27 D7 (ADR 0018 PR 2): the `cgroup/sock_create` row, required for tier
  `cgroup`; a cgroup row's `EPERM` names the attach conflict as a run's `Attach` does (`cgroup.AttachConflictHint`);
  the matrix's `net.socket_families` row is off where the row fails.
- 2026-10-16, R29 `events --last`: read from the end of the ledger, one event; and "What
  reads the whole ledger" says which views stay linear and why. §6 E3 and its table row say that `--last` reports
  damage only at or after its answer, exiting 0 over damage before it, with the options rejected.
- 2026-10-16, R32: a tokens, cost_usd or repeats budget the contract declares with nothing
  to count it (no capture runs, or no price table for cost_usd) is refused, 125 `[budget-unmetered]`, and compile
  reports it with that code; it ran with an `[unenforced]` warning and a gap.
  A price table that lists no model reads as no table.
  The refusal names a missing `models:` endpoint before `record: off`, and `record: off` only under uprobe capture.
- 2026-10-16, R20: `measure` renders a cost below $0.10 with two significant digits, down
  to a micro-dollar, instead of to the cent.
- 2026-10-16, R32: an `auto` contract under `record: off` compiles to capture `forwarder`, so its
  models[] endpoints are guarded and a budget cannot be gone around by a direct connection; a run whose table's
  capture is `uprobe` at a root tier with only the forwarder running is refused `[capture-unavailable]`.
  A forwarder that could not start under `record: off` is refused `[capture-unavailable]`, not `[budget-unmetered]`.
- 2026-10-17, R27 D7 (ADR 0018 (7)): the `cgroup/setsockopt` row, required for tier `cgroup`; the matrix's
  `net.socket_families` row is off where either socket row fails.
- 2026-10-17, R32: a `cost_usd` budget the contract declares under a price table whose every entry
  lacks an input or an output price is refused at launch, 125 `[budget-unmetered]`, and compile reports that code; it
  ran to its first response, while a table that lists no model was refused. A ceiling-only budget keeps its run's end
  at the first response.
- 2026-10-17, R32: a `[capture-unavailable]` refusal's fix names each failed mechanism's own fix;
  a forwarder that could not start alone gets only its `forwarder.listen` fix.
- 2026-10-17, R32 (text only): the §7 failure-mode row, RUN-IDENTITY's
  `budget-unmetered` row and the config reference's `prices:` comment name the table that prices no model among the
  causes; the CHANGELOG's known gap of a budget nothing counts is removed, since such a run is now refused.
- 2026-10-19, R4 (record-off C2-C4): the kernel's per-slot activity stamp (`tego_activity`) is pulled
  through the run's recorder under a stall budget: trace_proc's allowed actions under `off`, which make no sample,
  and the TLS probes' calls in every mode. "The kernel recorder does the same with each of its samples under `off`"
  over-claimed: those samples were refusals, execs and exits only.
- 2026-10-19, R4 (record-off C5): the uprobe source places the TLS probes for an `off` run with a stall budget, for
  its activity stamp alone; "the uprobe source's half ... remains owed" is done.
- 2026-10-19, R4: a recorder that found the run's slot reads the activity stamp whether or not it could
  open the run's ring (it read it only once the ring was open, so a busy `off` run whose ring failed was ended as
  stalled); a recorder with no row for the run reads none, which its `kernel-record-unavailable` gap discloses.
- 2026-10-19, R27: the run-probe cache's entry is named per binary as well
  (`doctor-probe-<bpf_hash>-<privilege>-<binary>.json`). Two binaries of one build evicted each other's entry, so
  `make vm-pairs`' two-inode variant paid the cold plane probe on every run (about 13 s a pair on 6.17 against
  under 1 s with one inode). What a key reads is unchanged.
- 2026-10-19, R27 and §3: the per-binary name's growth is stated: a rebuilt or upgraded
  binary's entry no longer replaces the old binary's, so `/run/tego` keeps one entry per build, privilege set and
  binary a root run used since the boot, until the reboot empties it; sweeping the same build's other binaries
  was rejected, as it brings the eviction back.

## 6. Edge cases

1. **Empty ledger** (0-byte `events.jsonl`): locked ⇒ **Running** for one `stallAfter` grace window measured
   from directory `mtime`, not from an absent event; unlocked ⇒ **never started**, not a finding (exit 0). A
   launcher that unwinds before `run_start` releases the ledger with `Abandon`, writes nothing, and removes the
   run directory right after, so an empty, unlocked directory is almost always a launcher killed between
   `MakeRunDir` and `run_start` (far more rarely, one killed between `Abandon` and the removal, or a removal that
   failed, which unwind logs). Its child was held before the Ack and the agent never exec'd, so nothing ran and
   there is nothing to end and no finding to report, as the sweep treats it (`ledger.StateEmpty`); a scope may
   remain until the next sweep removes it (`record-ledger.md` §4 `gc`, the empty-run hook). R8's **Lost** is a
   run with at least one line and no `run_end`.
2. **Torn last line** (writer died mid-`write(2)`): `ledger.Reader` ignores it; every view here behaves as if it
   were never written — expected on a live run, not an error.
3. **Torn middle line** (never produced by a healthy writer): fatal, reported distinctly from case 2 (`status`
   returns an error, never guesses a state). `events --last` reads from the end and stops at its answer, so it
   reports a damaged line at or after the answer and does not read one before it: over a ledger damaged only
   before its last failure it prints that failure and exits 0, where it exited 125 when it read every line (R29).
   A full view (`events <run>`, `measure`, `status`, `drift`) still exits 125 `[ledger-corrupt]` on it, and
   `events --verify` reports it as a finding, exit 1 (`tego events: <run> does not verify: ledger: unverified:
   line <n>: ... [ledger-corrupt]`, R29) (`TestEventsLastReadsOnlyTheEnd`).
4. **`run_end` written but the lock still briefly held** (slow cgroup teardown between the two): R7/R8 checks
   "unlocked" first, so this reads as Running for one extra poll, then flips to Done — no stuck state.
5. **Two `run_end` lines** (should never happen; a bug elsewhere could append twice): `status` and `measure` both
   use the **first** by `seq`/`prev` chain order, warn on stderr (`... N run_end lines; the first by chain order is
   the run's end ... [ledger-anomaly]`), name it in `--json`'s `ledger_anomalies` (absent for a healthy ledger), log
   it to `tego.log`, and never crash.
6. **PID reuse across a run's lifetime**: irrelevant here — every consumer keys by `exec_id`
   (`<run>/<pid>/<start-boot-ns>`) or run id, never bare pid.
7. **Clock changes mid-run** (NTP step, manual `date`, DST): R3/R4/R21/R22 use `MonoNS` only, immune by
   construction; `status --json` still exposes both `since_ts` and `since_mono_ns` so a reader can tell.
8. **Concurrent runs sharing one `ledger_root`**: `DeriveAll`/`doctor` collect per-entry errors; one run's
   corrupt ledger (case 3) never aborts the listing for the rest. Collecting is not swallowing: `cli` prints one
   diagnostic line per collected error (R26) and exits 125 (§7), because a listing that silently omits runs would
   read as a complete one — E26 again. `drift --aggregate` is such a listing: a run of the agent it could not read
   is named on stderr and in `--json`'s `skipped` list (always present, `[]` when none), and the exit is 125,
   the sum printed as far as it goes. The one error that is reported without changing the exit code is a run
   directory with no `events.jsonl`, or an `events.jsonl` with no complete line (case 1's never-started run): `ledger.Open` creates the directory and takes the lock before the ledger, so a
   reader can meet a run younger than its own ledger (or one a launcher died inside that window), and nothing was
   recorded there to be missing from the table. Bare `tego status`, which reads only the newest run, steps past
   those to the newest run that has a ledger, and reports any other failure instead of answering about an older
   run.
9. **Upgrade mid-run** (binary replaced by rename while a run is live): the live run keeps the old
   `record.v`, read by the v1 reader the new binary still ships (VERSIONING.md §2); `status --json` shows the
   run's own `tego_version` from `run_start`, never the invoking binary's (`Snapshot.TegoVersion`; absent for
   a run that died before `run_start`; `TestStatusJSONGolden` over `internal/cli/testdata/status-json.golden`).
10. **Huge ledger** (`npm install`-class, tens of thousands of events): every `ComputeCtx`/`ComputeAt`/`Derive` streams via
    `ledger.Reader.Iter`, O(1) memory beyond the running aggregates — never `ReadAll`. `events` streams on both
    paths, since `--limit` defaults to no limit: `--json` writes each stored line as it is read, and the table
    measures its column widths over the first 1024 matching rows and then writes every row as it comes, so the
    command costs the same memory on a ten-event run and a ten-million-event one. A row wider than its measured
    column overhangs it (keeping the two-space separator) rather than re-aligning a table already on its way to
    the terminal — the deliberate price of never holding the run in memory.
11. **Non-UTF8 bytes in a kernel path**: the writer (record-ledger.md) must already have escaped them into valid
    JSON; a decode failure here is treated as corruption (case 3), not a special path case.
12. **A contract literally names a rule `unmatched`**: cannot collide with the sentinel bucket. A declared rule's
    name is prefixed with its section and carries the author's text (`fs.write[unmatched]`), and only the sentinel
    is the bare word `unmatched`, so the author's entry is its own declared bucket beside the sentinel's and each
    counts its own events. Nothing is rejected at compile time
    (`TestAnEntryTextedUnmatchedNeverJoinsTheUnmatchedBucket`, `internal/check/drift`).
13. **Repeats with an empty `input_hash`** (a no-argument tool call): still tracked; an empty string is a valid,
    stable hash value.
14. **`decision: unparsed` events**: carry no `usage` (`ledger.Usage` returns `false`); they still update
    `LastEventMonoNS` (R4) and count toward `Steps` if attributed, never toward tokens/cost.
15. **Missing/unreadable price table, one that lists no model (R32), or a model absent from it**: `cli` warns and
    continues with `prices=nil` (or a partial table); a `cost_usd` budget the contract declares is refused (R32); cost breaches never fire for the unpriced case, `EstCostUSD` reads `0.00 est.` with one
    `gap what=record why=no-price-table` (whole table) or a per-model gap; tokens (R1) are unaffected either way.
16. **`ceiling.Tokens == 0`** (explicit, not omitted): breaches on the *first* `ssl_response` — an explicit 0 is
    a hard budget, "unlimited" is expressed by omitting the field entirely (resolves to the machine ceiling).
    `pkg/spec/agent`'s loader must distinguish "absent" from "present as 0" for this to be correct.

    **Settled 2026-09-22.** The loader always did distinguish them (`config.Ceiling.Bounded`); the
    distinction was lost one step later, in `agent.ResolvedLimits`, whose budget fields were plain numbers. So
    `clamp` propagated a ceiling of 0 as the number 0, `limits.Watcher` tested `<= 0` and read it as unbounded,
    and an operator writing `limits: {tokens: 0, cost_usd: 0}` was told by the `limit-above-machine` warning that
    the ceiling had been kept and then handed a run with no token or cost budget at all. `ResolvedLimits.Set`
    now carries a bit per dimension and `ResolvedLimits.Bounded` is the only question consumers ask; the value
    decides nothing about whether a budget exists. The rule is the same for every dimension, including the
    cgroup ones `runtime-launch.md` owns: an explicit 0 is the tightest setting, and omission is the only
    spelling of "unbounded" (that document's case 30 agrees). `R1`'s comparison is unchanged and
    still `>`, so a token budget of 0 breaches as soon as one token is spent, which is the first response of any
    real run. A `repeats` budget of 0 still needs a `tool_use` to judge: a `decision` carrying none has no streak.
17. **`stall_after` shorter than the model's own latency**: every run breaches on its first call; legitimate as
    written — `doctor`/`compile` do not cross-check against live latency in P0.
18. **`doctor` run without root**: D3/D6/D7's functional halves are skipped, `Result.OK=false, Detail:"requires
    root to test"` — distinct from an actual capability absence; a foreign/uneditable kernel command line (hosted
    CI, ARCHITECTURE §14) still gets a correct `bpf`-absent D6 result and a printed GRUB fix even where it cannot
    be applied.
19. **`compile --test` rows**: a not-yet-created `write` path is accepted (`RuleTable.FS` entries evaluate as
    declared, never filesystem-probed — SEMANTICS: "`compile` never computes an inode"); an unresolvable host is
    reported `FAIL ...: could not resolve <address> (declared host <host>)`, naming the row's literal address and the
    declared host entry (or entries) with no addresses that could have admitted it
    (`RuleTable.UnresolvedHosts`), distinct from a verdict mismatch; exit 1 either way.
20. **A view on a schema-version-bumped ledger** (out of scope for one P0 run, but defensive anyway): a line whose
    `v` is an integer greater than this binary reads (`record.ErrNewerVersion`) is skipped, never decoded as v1, by
    `events` (table and `--json`), `drift`, `measure` and `status`, which each print one warning per run naming the
    count (`warning: tego <cmd>: <path>: skipped N line(s) of a record version newer than 1 ... [newer-record]`)
    and answer from the v1 lines (`ledger.Reader.SkipNewerVersions`). `events --verify` still verifies such a line's
    link: the chain covers the raw bytes, not the schema, so its `id` must be its digest and its `seq`/`prev` must
    chain (`record.Chain.AddNewer`; condition: a newer version keeps `v`, `seq`, `id` as its first three keys and
    `prev` as a string, else it is corrupt). `v` 0, a negative, non-integer or missing `v`, and a malformed line stay
    `ErrCorruptLedger` (125). The engine's readers (sweep, `gc`, `stop`) do not skip. Tests:
    `TestNewerVersionLineSkippedByViewsVerifiedByVerify`, `TestNewerVersionLineTamperedFailsVerify`,
    `TestVersionZeroOrMalformedStaysCorrupt` (`internal/ledger`), `TestViewsSkipANewerRecordVersionWithOneWarning`,
    `TestViewsRefuseAVersionZeroLine` (`internal/cli`).
21. **`gc` racing a live run's own sweep**: `gc` performs the same `flock(LOCK_EX|LOCK_NB)` probe as `run`/`stop`
    before touching a directory; a run finishing mid-`gc` pass is simply picked up next pass, never corrupted.
22. **`--json` determinism**: one JSON object (or raw line) per stdout line, sorted map keys — golden-file and
    `jq` pipelines stay byte-stable across repeated runs of the same input.
23. **Missing `contract.yaml` copy** (crash between cgroup creation and the copy step): `drift.ComputeCtx` receives
    a nil-safe empty `RuleTable`, reports every observed rule as undeclared, `CurrentHash:""`, never panics. A
    copy that no longer compiles here (its paths gone, or a reader PATH that lacks a bare `exec.allow` entry,
    which run_start does not record) keeps its hash, so R16 still answers, and sets `DeclaredUnknown` (`--json`
    `declared_unknown`): a rule no entry covers is unknown, not undeclared, and is not drift (a refusal still is); a copy whose sha256 is not `contract_hash` is read as a legacy or edited file (§4 `drift.ComputeCtx`).
24. **Symlinked `/sys/kernel/btf/vmlinux`, or two concurrent `doctor` program-load probes**: `doctor` uses
    `open(2)` (which follows), matching what the running kernel actually exposes, never `lstat`; `doctor` pins
    nothing (every map is loaded `PinNone`, I7), so two simultaneous probes have no pin name to collide on and
    no `EEXIST` between them.
25. **A `limit` breach racing an operator `tego stop`**: independent booleans (the runner's terminal reason and
    the signal handler's outcome); `limits` guarantees its own `limit` event is appended before `trip` kills,
    and the facade's `run_end` reads the breach first: a run both stopped and over budget ends as `limit`
    (exit 124) in whichever order the two arrived, and a stop alone ends as `stopped`
    (`TestALimitTripAndAnOperatorStopAreIndependentDecisions`, `internal/runtime`, unprivileged).
26. **`status`/`measure`/`drift` against a foreign uid's `ledger_root`**: `EACCES` reported as `<path>: permission denied`
    — never conflated with `lost` or an empty (genuinely-no-data) report.
27. **The clock backing `MonoNS` is not pinned down by any normative document.** §2's comment ("clock is
    monotonic") and record/v1/README.md stop there — neither says `CLOCK_MONOTONIC` or `CLOCK_BOOTTIME`, which
    diverge across suspend/resume (the former freezes, the latter does not). On the "laptop tier" run
    ARCHITECTURE.md describes, a suspend mid-run would, under `CLOCK_MONOTONIC`, silently understate `Wall`/
    `Stall` (R3/R4) and flip `status.Derive`'s stalled check (R9) wrong after resume. **Settled as
    `CLOCK_MONOTONIC`**, which `record-ledger.md` §2 names, the writer reads (`ledger.SystemClock`) and every
    producer stamps (the kernel ring's `bpf_ktime_get_ns`, the supervisor's and the capture sources' readings), so
    the lines of one run compare on one clock. Across a suspend the clock stops: `Wall` and `Stall`
    count time the machine ran, never time it slept, so a laptop that sleeps through a run's budget is not killed
    on resume for the hours it was off, and `status` reads a run as stalled only for time it could have made
    progress.
28. **D7 attaching a fresh copy of a tier-2/3 program next to a live production run of the same build.** Two
    `fmod_ret` attachments at one hook run in sequence per ARCHITECTURE §6's coexistence model ("each returning 0
    for cgroups not in its own maps"); doctor's map holds only its own throwaway probe key, so it cannot return
    non-zero for a production cgroup. D7 never unpins anything but its own link/prog/map (§3, I7) and never
    touches the per-build `LOCK_SH`/`LOCK_EX` count (R27 D7), which only gates the last launcher's unpin of the
    shared, pinned production objects.
29. **`compile --test` against a contract pinned to a tier this machine cannot reach** (R33): expected — a
    laptop without `bpf` active still tests a `tier: bpflsm` contract with that tier's `host:port`-precise
    verdicts, not Landlock's port-blind ones, since `decide.Evaluate` works off the compiled `RuleTable` alone.
30. **The run-probe cache is planted, tampered with, stale, or kept by another machine or another process**
    (R27 "What a run probes"). A file or directory under `/run/tego` that is not root's, is writable or readable by anyone
    else, is a link or has a second link, is over 1 MiB, carries an unknown field, carries another key, or
    holds an answer that does not vouch for tier `cgroup` is not read. Another key means a reboot, another
    kernel, LSM list, lockdown mode, build or binary, or a process with other privilege: other effective
    capabilities, LSM labels, user or mount namespace, cgroup, cgroup namespace or invoking uid. A process under
    a seccomp filter reads no entry.
    The run then probes D7's tier-2 rows and D8 as if there were no entry, and writes its own answer only
    through a directory that passes the same checks. Some entries are valid but no longer true, for two
    reasons, and each can offer tier `cgroup` to a process the kernel then refuses:
    - The machine changed in a way the key does not hold, such as a new SELinux rule refusing `bpf(2)`, or a
      lower `memory.max` on the cgroup the process runs in, whose path the key holds but not its limits. That
      costs one run per set of process privileges: it stops at `Prepare` with exit 125 and removes the entry,
      and the next run probes.
    - A process runs under a restriction the key does not hold: one that leaves no trace in `/proc` (a
      Landlock domain, another tool's BPF LSM program, or an LSM that keeps no label in `/proc/<pid>/attr`), or
      a resource limit (`/proc/<pid>/limits`, such as a low open-file limit). Such a process shares its key with
      an unrestricted one. Each of its runs that reads the entry stops the same way and removes it, so this
      recurs whenever an unrestricted run keeps the answer again. Such a process should pin tier `landlock`
      (`--tier`, its contract or its machine config), since a run at reach `landlock` never reads the cache.

    Neither case runs at a lower tier than selected (`TestRunCacheRefusesAnEntryItCannotTrust`,
    `TestRunCacheReadsOnlyTheAnswerItKeptForThisKey`, `TestIntegrationForRunAsRoot`,
    `TestIntegrationRestrictedRootRunAfterFullRoot`).

**Changes.**
- 2026-09-30, case 23: a contract copy that does not recompile under the reader's PATH sets `Report.DeclaredUnknown`, and its undeclared rules no longer make `drift` exit 1.
- 2026-09-29, E1/E12 build check: tier `cgroup` is buildable whenever the BPF objects are embedded and its fix asks only for a `tegobpf` build; the static-link check, `StageLinking`, `checkStage` and `TestBuildableRefusesADynamicBinary` were removed by ADR 0021 (4) and are gone from the text.
- 2026-09-28, E12, E19, E24, E25: E12 restated to section-prefixed names, E19's FAIL line names the declared host too, E24 to `PinNone`, E25 to the runtime's first-breach-wins reading, with a test.
- 2026-09-24, E1: an empty unlocked ledger is never started,
  not lost; the unwind removes the run directory after `Abandon`.
- 2026-09-24, E27: `MonoNS` settled as `CLOCK_MONOTONIC`, replacing the
  `CLOCK_BOOTTIME` working assumption.
- 2026-09-24, E9: `status --json` gained `tego_version`; the object had no such field.
- 2026-09-24, E20 (decision): a newer-`v` line is skipped by the views with one warning and
  still chain-verified; the reader had failed every view with `ErrCorruptLedger`.
- 2026-09-25, E5: `measure` keeps the first `run_end` as `status` does; both report the anomaly.
- 2026-09-28, E29 (ADR 0028 S1): the answer is `decide.Evaluate`'s.
- 2026-09-29, case 8: `drift --aggregate` reports each run it could not read (stderr,
  `--json` `skipped`) and exits 125; it had only logged them and could exit 0 over a partial sum.

## 7. Failure modes and handling

| Failure | Detection | Response | Ledger | Exit/Event | User sees |
|---|---|---|---|---|---|
| Token/cost/repeat ceiling crossed | `Observe` totals > ceiling | `trip`: `limit` event, `cgroup.Kill` | `limit{which,value,ceiling}`, then facade's `run_end reason=limit` | 124 | ceiling name + measured value |
| Wall/stall ceiling crossed | `Tick` | same | same | 124 | same |
| `cgroup.Kill` errors (cgroup already gone) | error from `mgr.Kill` | log to `tego.log`; `limit` event still appended | present regardless | 124 (ceiling was in fact crossed) | no visible difference; only the log shows it |
| Ledger torn last line | byte-count mismatch on final line | ignore that line | n/a | n/a | none (expected) |
| Ledger torn middle line | decode error, non-final line | abort with a typed error | n/a | `check/*` commands exit 125; `events --last` only for a line at or after its answer, the lines it reads (R29) | `<path>: corrupt ledger at line N [ledger-corrupt]` |
| Missing/unreadable price table, one listing no model, or unrecognized `Version` (R32) | open/version check at `cli` startup | warn, continue with `prices=nil` | `gap what=record why=no-price-table\|price-table-version-mismatch` once | 0 | one warning line at start |
| A tokens/cost_usd/repeats budget the contract declares with nothing counting it: `run_start.capture` would be `off`, or no price table for cost_usd, or one that prices no model (R32, amended 2026-10-16; the table that prices no model added 2026-10-17) | `refuseUncountedBudget` once every source started | the run is refused before `run_start`; its sources stopped and its scope removed; compile warned `[budget-unmetered]` | none | 125 | `tego run: runtime: budget unmetered: the tokens budget cannot be counted ...: <cause>. Fix: ... [budget-unmetered]` |
| A tokens/cost_usd/repeats budget a machine ceiling alone imposes with nothing metering it: `run_start.capture` is `off` (R32) | `captureMode` after `run_start` | continue | `gap what=record why=budget-unmetered binary=<budget>` once per budget | agent's own | nothing at start (`[unenforced]` from compile under `record: off` with a pinned `capture: uprobe`) |
| A tokens/cost_usd/repeats budget whose capture mechanism could not start (R32): a `mechanism-unavailable` selection gap or inert capture source (a capture object the kernel refused, or no capture ring within `bpf.ring_budget`, or a forwarder that could not bind, under `record: off` too), and `run_start.capture` would be `off`, or the table's capture is `uprobe` at tier cgroup or bpflsm and only the forwarder runs (amended 2026-10-16) | `refuseUnmeteredBudget` once every source started | the run is refused before `run_start`; its sources stopped and its scope removed | none | 125 | `tego run: runtime: capture unavailable: the tokens budget cannot be metered ...: <cause>. Fix: ... [capture-unavailable]` |
| `doctor` probe needs root it lacks | `geteuid()!=0` before functional half | `OK:false, Detail:"requires root"` | n/a | 0, or 211 per R25 if it drops below `--require` | "requires root to test", not "unsupported"; the fix re-runs this binary by its absolute path, `sudo /home/u/.local/bin/tego doctor`, since sudo's `secure_path` cannot find a bare `tego` on the default install in `~/.local/bin` |
| A root `tego run` at reach `cgroup` meets a run-probe cache entry it cannot trust, or whose key is not this machine's and this process's, or runs under a seccomp filter (R27 "What a run probes", §6 E30) | the trust checks, the key comparison and the process's `Seccomp` status line before the entry is read | the entry is not read; D7's tier-2 rows and D8 are probed, and their answer replaces the entry when it vouches for tier `cgroup` and removes it otherwise | n/a | as the probe decides | nothing: the run costs what a probe costs, and, while another root run of the same key holds its flight lock, up to 30 s of waiting first (R27 "Concurrent misses") |
| A run selected from a cached answer fails before `run_start` | `runtime.Run` returns an error | the entry is removed (`Report.DiscardCache`), so the next run probes | none (before `run_start`) | 125 | the failure's own message, e.g. the program `Prepare` could not load |
| Yama `ptrace_scope` ≥ 2 and no `CAP_SYS_PTRACE` (R27 D5) | read of `/proc/sys/kernel/yama/ptrace_scope` | D5 fails; every enforcement tier leaves `Tiers` — the supervisor could not read the agent — and `tego run` offers no tier | n/a | no tier, so 1; 211 when `--require` is unmet (R25) | the scope, "every connect fails closed with EACCES and every exec/fs event records `rule=args-unreadable`", and `kernel.yama.ptrace_scope=1` in `/etc/sysctl.d` applied with `sysctl --system` (at scope 3, the boot-time setting; an unreadable sysctl: make it readable and re-run, with both settings named) — every remedy one the `lsm=` reboot on the same fix line keeps |
| D5's round trip fails on its own (R27 D5): `EACCES` from an outer filter, `EBUSY` under another seccomp supervisor's listener, `EINVAL`, `ENOSYS`, no notification within 5 s, the thread that carried the filter not ended 5 s after, or the notification taken back (`ENOENT`, `EINPROGRESS`, `ESRCH`, `EINTR`) on each of its five attempts | errno from `seccomp(2)` or the `ADDFD` ioctl, the listener's poll timing out, or `tgkill(2)` still finding that thread | D5 fails, without Yama's sentence; every enforcement tier leaves `Tiers`, and `tego run` offers no tier | n/a | no tier, so 1; 211 when `--require` is unmet (R25) | the errno and its own remedy (`EBUSY`: run outside the other supervisor; `EINVAL`: on a release below 5.14, a kernel ≥ 5.14; at or above it, `CONFIG_SECCOMP_FILTER=y` or a tego bug report; `ENOSYS`, any release: `CONFIG_SECCOMP=y` and `CONFIG_SECCOMP_FILTER=y`, or leave the sandbox whose filter answers `seccomp(2)` with it; a notification taken back on every attempt, on any release: re-run `tego doctor`, and report it if it fails the same way again), beside Yama's when both fail |
| A freshly created cgroup has no writable `cgroup.kill` (R27 D3) | `access(2) W_OK` in D3's scratch cgroup, before its `rmdir` | D3 fails; the scratch cgroup is still removed | n/a | feeds `Tier` | "a run could not be stopped atomically" + `boot a kernel >= 5.14` |
| Landlock ABI syscall missing (< 5.13) | `ENOSYS` from `landlock_create_ruleset` | D4 fails cleanly | n/a | feeds `Tier` | "Landlock: not available (kernel too old)" |
| `lsm_list_modules` unavailable (< 6.8) | `ENOSYS` | fall to securityfs, then dmesg (D6 order) | n/a | n/a | same answer via the fallback chain |
| BPF program-load test fails (verifier/BTF) | non-zero errno from `BPF_PROG_LOAD` of the hook's embedded program, or its attach point missing from BTF | D7 fails that hook only | n/a | feeds `Missing` for the hook's tier | named hook + the verifier's own last lines; the fix names the verifier, not "a kernel with the listed hooks", when every failed hook is in BTF and only this build's program was refused |
| D7 has no program to load at a hook (a binary built without the objects) | `bpf.Load` returns `ErrNotGenerated` | a minimal program of the hook's type stands in; the hook is marked `stand_in` | n/a | the stand-in answers for the attach point only; the tier's buildability is `enforce.Buildable`'s | "tested with a minimal program" on D7's line |
| fanotify probe fails | errno from `fanotify_init` or `fanotify_mark`; or the probe's own open, answered `FAN_DENY`, not refused with `EPERM`; or no permission event within 2 s, with the probe's own open already failed (refused before the listener) or still waiting | D8 fails | n/a | feeds `Tier` (tier cgroup) | one-line fix for the cause: `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y` only when `fanotify_init` or the mark failed; an open refused before the listener: the errno, and find the LSM rule or other fanotify listener that refused it and exempt tego's files, or pin a lower tier; a round trip that could not be completed otherwise: re-run, then report; an open a `FAN_DENY` did not refuse: a current stable kernel, then report |
| a capture row fails (R27 D7): `uprobe_ssl`'s program refused, or its uprobe not attached at the system libssl | errno from `BPF_PROG_LOAD` or from the uprobe `perf_event_open` | the row is listed on D7's line; D7 stays as its tier hooks leave it | n/a | none: no tier's `Missing`, not the fix line, not the exit code; `capture.model_traffic` stays on (under `capture: auto` the forwarder still captures; a contract that pins `capture: uprobe` runs none) with a note naming the row | "capture (uprobe_ssl, no tier): … failed: <row>" on D7's line and the matrix note |
| no system libssl for the capture rows | none of R27 D7's directories holds a regular `libssl.so*` | the rows load only, marked `load_only` | n/a | none | "attach not tested (no system libssl found)" on D7's line and the matrix note; a host with a libssl whose rows all failed to load says instead "attach at <library> not tested (no program loaded to attach)" and lists the rows as failed |
| `compile --test` row malformed | parse/validate before evaluating | whole command fails before any row runs | n/a | 2 | `<file>:<line>: <what> [schema]` |
| `compile --test` row fails (mismatch) | evaluator vs. `expect` | print FAIL row, keep going | n/a | 1 | PASS/FAIL table |
| CLI panic in a subcommand | top-level `recover` in `cli.Main` | full stack to `tego.log` only | n/a | 125 | `tego: internal error: <msg> [bug]` |
| Aggregate across a mixed agent set | precondition check in `Aggregate` | refuse before computing | n/a | 2 | `refusing to aggregate: runs are not the same agent [usage]` |
| `events --verify`: a line that does not hash to its `id`, a broken `seq`/`prev` link, a line of another run, an anchored head the ledger does not end with, an ended run `chain.log` has no line for, or an anchored run whose ledger or directory is gone | `ledger.VerifyRunDir`, wrapping `ledger.ErrUnverified` (`ErrRunMismatch`, `ErrAnchorMissing`, `ErrLedgerMissing` for those three) | report, never repair | n/a | 1 | `<run> does not verify: <why> [ledger-corrupt]`; `--json` says `verified: false` with the error |
| `events --follow`: the lock is free and the ledger holds no `run_end` (a launcher killed mid-run) | the Follower's lock probe before its last read (`record-ledger.md` §4 `Follow`) | stop following | n/a | 125 | the rows it holds, then `tego events: ledger: no writer holds the run's lock and its ledger ends without run_end: <dir>; the next tego run, tego stop or tego gc ends it as orphaned [run-lost]` |
| `events --follow`: a line that breaks the chain (id, seq, prev, another run's line, `run_start` not first) or a line after `run_end` | the Follower's per-line check | stop following; nothing after the line is printed | n/a | 125 | the rows before it, then `<path>: ledger: corrupt line N: at byte offset O: ... [ledger-corrupt]` |
| `events --verify`: the ledger or `chain.log` cannot be read, the anchor path cannot be resolved, or neither a ledger nor an anchor line exists for the run | an error without `ErrUnverified` | no verdict | n/a | 125 | the path and errno — never "does not verify", which would be a claim about the ledger |
| Machine config untrusted | `config.Load`'s trust check | `run`-path commands never start; `doctor`/`compile` warn and continue | n/a | 125 `[config-untrusted]` (the former 213, folded into 125 on 2026-09-22) / 0+warning | `machine config untrusted: <path> <owner> <mode>`, and on `run` the fix |

**Changes.**
- 2026-10-24: the two `events --follow` rows, a lost run and a break in the chain.
- 2026-09-30: the D7 stand-in row and R27 no longer name tier 3 as having no objects; the plane replaced the hand-listed `lsm/*` rows, and only a binary built without the objects gets stand-ins.
- 2026-09-24: the budget-with-nothing-metering row added.
- 2026-09-24: the requires-root fix names the binary's absolute path.
- 2026-09-24: `doctor --require` unmet is 211, not `1/211`; the untrusted-config row's 213 is 125.

## 8. Invariants

- **I1** At most one `limit` event per run — `trip` checks-and-sets `tripped` under one `mu` section, no TOCTOU
  between `Observe` and `Tick`. Tested with the race detector, both goroutines against shared near-ceiling state.
- **I2** Every `Breach.Which` maps 1:1 to a `record.Reason` limit code (`limit-tokens`, `limit-cost`, `limit-wall`,
  `limit-stall`, `limit-repeats`). Enforced by an exhaustive `switch`, no `default`.
- **I3** `status.Derive` returns exactly one `State` (R7-R12 checked in strict, mutually exclusive order; R12 is
  itself the exhaustive fallback). Tested with one case per rule boundary.
- **I4** `drift.ComputeCtx`'s buckets partition the ledger exactly: `Σ RuleCount.{Allow,Ask,Refused,Observed}` over
  all buckets equals the count of action-kind events. Tested against a fixture's raw count.
- **I5** `measure.ComputeAt` and a `Watcher.Snapshot()` over the same completed ledger agree on tokens/cost to the
  cent (both consume `ledger.Usage`). Tested by an integration diff over one fixture.
- **I6** No function but `cli.Main`'s own return calls `os.Exit`; every inner function returns `int`/`error`, so
  any command's `Run` is callable in-process from a test — enforced by `scripts/check-exits.sh` (precommit and CI
  build-test; the check is `tools/checkexits`, on the Go syntax tree), which forbids `os.Exit`/`syscall.Exit`/
  `unix.Exit` and `log.Fatal`/`Fatalf`/`Fatalln` (each ends in `os.Exit(1)`) under any import name, called or
  taken as a value, in every non-test file outside `cmd/`; a `*log.Logger`'s `Fatal*` methods (`log.New` and
  `log.Default` are refused where the logger is made, and any `Fatal*` method in a file importing `log`) and the
  `flag` exits (`flag.Parse`, `flag.ExitOnError`, each an `os.Exit(2)` on a bad flag) are refused the same way
  (`tools/`, the perf programs under `test/perf/cmd`, the test workloads under `test/workloads`, the conformance
  programs under `test/conformance/cmd`, the guest helpers under `test/vm/cmd` and the stand-in Claude Code under
  `test/e2e/reason-claude/fakeclaude` are programs of their own).
- **I7** `doctor.Run` leaves zero bpffs entries behind on every exit path, including mid-probe cancellation —
  tested by cancelling the context at each of the 8 probe boundaries and asserting the pin directory is empty. A cancel
  during D7 (as it starts, and half way through its hooks) and while D8 holds its fanotify group is tested as root
  in the tegobpf suite (`TestIntegrationCancelledDuringProgramsAndFanotifyLeavesNothing`): the bpf filesystem, the
  scratch cgroups and the process's BPF and fanotify descriptors are as they were before. Doctor pins nothing (§3:
  every map is loaded `PinNone`); a live run's production pins existing alongside it do not violate this (§6 E28).
- **I8** `events --json` bytes are byte-identical to what `ledger.Writer.Append` wrote (sha256 of exactly those
  bytes is the chain's `id`) — never re-serialized; tested by hashing the printed line against the event's `id`.
- **I9** Every exit code returned here is a documented R25/RUN-IDENTITY.md value, never a bare `return 1`/`return
  2` without a citing comment — enforced by review plus `scripts/check-exits.sh` over `internal/cli/*.go`, which
  fails on a return of one non-zero integer literal with no comment on its lines, and on a file list with no
  `internal/cli` file in it (a check that read nothing is no pass).

**Changes.**
- 2026-09-24, I6, I9: the CI greps they cited did not exist; `scripts/check-exits.sh` added.
- 2026-09-24, I6, I9: the greps listed no `internal/cli` file on git 2.51 and missed an aliased or split
  `os.Exit`; the check is now `tools/checkexits` on the syntax tree, and an empty list fails.
- 2026-09-29: I6 also forbids `log.Fatal*`; `test/conformance/cmd` is exempt.
- 2026-10-05: I6 also forbids `log.New`/`log.Default`, `Fatal*` methods in a file importing
  `log`, `flag.Parse` and `flag.ExitOnError`.
- 2026-10-05, I6: the guest helpers under `test/vm/cmd` are exempt, as
  `test/conformance/cmd` is; `test/vm/cmd/permlistener` is a fanotify listener that is not Tego's and ends with its
  own exit code.

## 9. Conventions and best practices

- **C1 Naming/dedup.** No `util`/`common`/`helpers` package (REPO-LAYOUT.md). `limits` and `measure` deliberately
  reimplement the token/cost loop (only payload decode shared via `ledger.Usage`) to keep "engine never imports
  the read side" mechanically checkable — do not "fix" with an import.
- **C2 Errors/logging.** One sentinel `var Err*` per package, wrapped with `%w` so `errors.Is` works from `cli`.
  Only `cli` and `limits` write logs; `check/*`/`doctor` are pure functions returning data, so a `Snapshot`
  renders identically from the CLI or any other reader.
- **C3 Context/goroutines.** Functions that can block on a syscall (`doctor` probes, `Tick`'s cgroup write) take
  `context.Context` first; pure ledger-scan functions do not (bounded by ledger size, caller adds any timeout).
  `limits.Watcher` owns exactly one ticker goroutine, started/stopped by its caller's `errgroup` — traceable to
  one call site.
- **C4 Resource lifetimes.** Every `ledger.Reader` opened by `check/*` is `defer r.Close()`d by the `cli` command
  that opened it; P0 has no `--watch` flag, so no reader is held across a poll loop.
- **C5 Fuzzing/benchmarks.** `doctor`'s BTF/securityfs/dmesg parsers and `events`' filter-argument parser are Go
  fuzz targets (untrusted-ish machine/user text). `measure.ComputeAt`/`drift.ComputeCtx` carry `Benchmark*` over the
  largest fixture (~30k events) guarding the streaming invariant (E10): allocation growth beyond O(1)/event fails CI.
- **C6 Doc comments.** Every exported symbol's comment starts with its name and, where it implements a business
  rule, cites it, e.g. `// Observe updates cumulative usage (R1, R2, R5).`

## 10. Tests

**Unit.** `limits`: table tests per R1-R6 including boundary cases E13/E16/E17; a race-detector test for I1; a
test for R32's warn-and-continue on an unrecognized `PriceTable.Version`. `status`: one table test per R7-R12
transition and its boundary (E1, E4, E5), golden `Snapshot` JSON per case. `drift`: fixture tests for R13-R17,
R17a's fileless and dropped lists (a table over flagged and plain execs, the bound, the aggregate, and the table and
`--json` goldens `internal/cli/testdata/drift-flagged*.golden`), including E12 (a rule named `unmatched` keeps its own section-prefixed bucket beside the sentinel) and E23 (missing `contract.yaml`); an `Aggregate` test with a
hash-drifted run; R15's three states (a producer named in `parsers`, an `mcp` event as proof of one, neither)
and their aggregate; a canonical copy with `extends:` recompiled after the profile changed, from another
directory (R16). `gaps`: grouping, the dropped-count sum, the three-binary cap, an undecodable gap, and the
fixture's own line (R34), plus status and drift carrying it, and `status --all` printing `gaps <run>:` for the
run that recorded one and nothing for the run that did not. R15's producer end to end: a tier-1 run whose agent
starts one of two declared servers records `parsers["mcp"]` and one `mcp` event, and drift reads the other as
unused (`internal/runtime` `TestIntegrationMCPUnusedIsReachable`). `events --verify`: a clean run, a changed
byte, a truncated tail, a missing anchor line, a live run, an unreadable anchor (R25), another anchored run's
ledger copied in, a deleted `events.jsonl` or run directory under an anchored id, and both findings through `.`
inside the run directory and through a link to it under another name. `stop`: a second stop's backstop waits out
the first stop's longer grace, and out the machine's `stop_grace` after a plain first stop. `measure`: table tests for R18-R23 including E14, E22, and R-res (`TestResourcesFromRunEnd`; `status`'s half, `TestDeriveReadsTheResourcePeaks` and `TestStatusShowsTheResourcePeaks`; `internal/check/resources`' `TestFieldsShowAnAbsentKeyAsUnknown`). `events`: filter-combination tests; a
`RawLines` golden test proving I8. `doctor`: D1-D8 mocked at the `platform/sys` boundary, plus tests for E18, E24,
E28, E30 (E19 is `compile --test`'s, E20 the views', E27 `status`'s clock); and R27's "What a run probes": the checks each reach runs, with a counting stand-in for every
probe (`TestRunAtReachLandlockLoadsNoProgram`), the reach's tiers offered and explained as `doctor` does
(`TestRunReportIsDoctorsAtAndBelowItsReach`), `Reach` per pin, ceiling, root and build (`TestReach`), the run-probe
cache's key, trust checks and vouching rule (`TestRunCache*`, `TestRunAtReachCgroupReadsTheCacheAsRoot`), the
process half of its key (`TestRunCacheNeverLendsAnAnswerToAnotherProcess`,
`TestProcessPrivilegeIsReadOrTheCacheIsNotUsed`, `TestProcessPrivilegeIsTheCallingThreads`), D5's round trip interrupted at each window
a signal can take (`internal/doctor/seccomp_interrupt_test.go`, R27 D5), and, as root in the
KVM guest, `TestIntegrationForRunAsRoot` and `TestIntegrationRestrictedRootRunAfterFullRoot`; at the command, `TestRunAtTierLandlockLoadsNoProgram`,
`TestRunProbesTheReachOfItsSelection` and `TestRunDropsTheCachedAnswerItCouldNotStartFrom`. `cli`: flag-parsing
and exit-code tests per command (R25, `doctor --require` unmet asserted as 211); a panic-recovery test for I6.

**Integration** (`//go:build integration`, root where noted). `doctor` against a real kernel: D3 with an actual
systemd user slice, D4 against real `landlock_create_ruleset`, D5's ADDFD/SEND self-test end-to-end, D7 loading
the real embedded BPF objects (root) while a second, real `tego run` of the same build is live, asserting
neither interferes with the other (E28; `TestDoctorDuringALiveTier2RunChangesNoVerdict` in
`internal/runtime/enforce/cgroup`, 2026-09-24: an allowed and a refused connect, a write outside the contract and a
fanotify-refused read, in rounds before, during and after `tego doctor`, all unchanged), D8 against real `fanotify_init`. `limits` end-to-end: a synthetic
looping agent tripping `limits.repeats`, and a `$25` cost budget stopping a run with exit 124 (acceptance §12.4)
against a real cgroup. `status`/`drift`/`measure`/`events` against `test/fixtures/ledger/` and every
`spec/record/v1/fixtures/` entry (P0-DESIGN §10). `compile --test` run once against a contract pinned to a tier
the CI runner cannot itself reach, asserting R33's tier comes from the contract, not a local `doctor` probe.

**E2E / golden.** The frozen M0 fixture is the contract for every view's `--json` output; any output change needs
an explicit golden update in the same PR. `compile --test` ships one real `tests.yaml` against `examples/agents/
*.yaml`, asserted green in CI (acceptance §12.5). Kill test 4 maps directly to the `limits` integration tests above.

**Changes.**
- 2026-10-05, §10 Tests: D5's round trip is tested interrupted at each window a signal can take, against the real kernel and by answering in its place.
- 2026-09-28, §10 Tests: the E12 and missing-`contract.yaml` (now E23) citations and the `doctor` case numbers (E18, E24, E28, E30) follow §6's current numbering.

## 11. Open questions

- Whether `run_start` should gain the optional `limits{...}` payload this spec proposes for R12/status accuracy,
  or whether `status`/`drift` should instead be handed the compiled `RuleTable` out-of-band by `cli` — the latter
  avoids a record-spec change but means `status` cannot work from the ledger alone (e.g. from the dashboard).
  **Settled:** `run_start` carries the block (`record-ledger.md` §2.2), with a key per bounded dimension, `0`
  included, so `status` works from the ledger alone (R12).
- Whether the `refused`-kind event and an action event's `verdict=refused` are truly always paired 1:1 (R13/R19's
  non-double-counting assumption, today only inferred). Also unsourced: the "recent activity" grace window for a
  not-yet-first-event `status` (E1); this spec picked `stallAfter` as a reasonable default.
- `measure` omits the `asked/answered/wait/replanned` columns (`docs/FEATURES.md` row C5); the receipt
  (`internal/check/receipt`) reports a run's asks.
- Price-table versioning/override semantics beyond a flat file (E62) — this spec
  implements only load-and-apply plus a coarse `Version`-mismatch warning (R32); binary-embedded validation stays undecided.
- The `doctor --require <tier>` unmet exit code (RUN-IDENTITY.md once folded it into "1, a finding"; FEATURES.md's
  R16/kill-test-6 requires 211). **Settled 2026-09-24:** 211; `spec/identity/RUN-IDENTITY.md` now names it, and
  `doctor.Report.ExitCode` returns it (R25).
- The exact clock (`CLOCK_MONOTONIC` vs `CLOCK_BOOTTIME`) backing `record.Event.MonoNS` was unstated in
  `spec/record/v1/README.md` and ARCHITECTURE.md (§6 E27). **Settled 2026-09-24:** `CLOCK_MONOTONIC`, as
  `record-ledger.md` §2 and every producer have it (§6 E27).
- **`doctor` and `tego run` disagreed about tier `landlock` when D1 or D3 failed** (R27 Output). **Settled:**
  there is one derivation and both commands read it; `run`'s own gate is gone. D3 joined the tier-1 list and its
  remedy the joined fix line, as this entry proposed. For D1 the entry argued the other way (D1 is advice, so
  `run`'s gate should drop it); the resolution keeps D1 in the one derivation, failing closed, for the reason
  R27 Output gives: the 5.14 floor stands for mechanisms no functional probe exercises. A backporting
  distribution whose release D1 reads as below 5.14, or cannot parse, therefore gets no tier from either
  command. D1 can return to advice once D5 or another functional probe also exercises `pidfd_getfd`, seccomp
  `CONTINUE` and `clone3` into a cgroup.
- **`measure`'s R22 idle max and `status`'s since-reading take `mono_ns` along `seq` as if it only grew.** It does
  not: the ledger keeps a producer's own capture-time reading (`record-ledger.md` §4 `Append`), so a kernel or
  forwarder line can carry an older reading than the supervisor line before it. R22 then measures the next gap
  from that older reading and `status` takes the last line's, both overstating idle by the capture latency,
  which is the queue's backlog under load. **Condition:** `internal/check/measure` compares each reading against
  the largest one seen so far rather than the previous line's, and `internal/check/status` takes the largest
  `mono_ns` rather than the last line's; both are changes there, with a test of a ledger whose
  readings go back by a capture latency. Both halves are met: `status`'s (§5 Views) and `measure`'s (R22,
  `TestComputeRules`).
- Minor: whether `doctor`'s D7 should defensively hold `LOCK_SH` on the build lock (§6 E28); whether `completion`
  (R29, dropped as unsourced) merits a separate future proposal. (Whether `compile --test` should warn when its
  simulated tier differs from this machine's own is answered by R28/R33: it tests every tier the run can get.)

**Changes.**
- 2026-09-24: the `--require` exit code settled at 211 (R25); the `MonoNS` clock settled as `CLOCK_MONOTONIC`
  (E27); the tier-simulation warning question answered by ADR 0019 (R28/R33); `status`'s half of the
  `mono_ns` condition met.
- 2026-09-28, R2 (decided): a missing `cache_read_per_mtok` or `cache_write_per_mtok` makes a
  response that reports that counter unpriced, as a missing 1-hour rate does; it was charged $0 and priced.
- 2026-09-28, Profiles row: an untrusted profile's diagnostic says untrusted, not "not found".
- 2026-09-29, R1 (d): a size-cut 2xx answer on a silent path (a Files API download, the model list) is not reported, on both capture paths.
- 2026-09-29: `measure`'s half of the `mono_ns` condition met (R22 measures from the largest reading so far).
- 2026-10-05, R4/R9: a pending human approval holds the watcher's stall clock, and status ranks waiting approval
  ahead of R9 only while idle is under `stall_after` plus the 1h `ask.timeout` ceiling; past it the run is stalled.
- 2026-10-16, R28 (ADR 0041 D7): an `fs.rename` row's source is scored with the gate's read
  predicates as well as its write ones, as a run scores it (ADR 0041 Step 4), so the column answers the run's `fs-gate`
  refusal of a rename of a secret out of its name rather than `allow`; and `exec.rules/argv` is named for a command
  rule's allow or ask only, never its refusal (`TestCompileTestShowsBestEffortCells`).
- 2026-10-16, R28 (ADR 0017 (b)): `compile --test` rows `fs.link`, `fs.attr`,
  `net.socket`, `net.send` and `exec.anonymous`, each answered by the matcher the run decides it with (R28's dated
  amendment); a unix or abstract connect stays `net.connect` with a `unix:` path.
- 2026-10-17, R28: `fs.link` is answered as Landlock's `hook_path_link` decides it
  (the ends' directories, the file rights gained), in every column; the `bpflsm` column composes that floor for a
  link and a rename, walks `path_link`'s ends first, names a `deny_write` link by its target under fs notifications,
  and refuses `exec.anonymous` with every exec row when the plane cannot be built; the header line names
  `exec.anonymous` with the policy model's rows; `net.send`'s per-line `best_effort` mark is stated
  (`TestCompileTestLandlockReferGolden`).
- 2026-10-17, R28: an `fs.rename` row's no-gain rule is the kernel's, nothing
  within one directory and the new name's directory across directories, file rights only for a file; a rename onto an
  `exec.allow` file entry answers `allow` (`TestCompileTestLandlockReferGolden`).
- 2026-10-17, R28: a rename's, a link's and a delete's ends are never
  followed, so a symlink entry's own name is the symlink; the `bpflsm` column composes the floor's directory rights
  for a rename and a delete (`TestCompileTestSymlinkEntryEndsGolden`, `TestCompileTestLandlockReferGolden`).
- 2026-10-19, R28: a name-making row end ending in `/` is
  landed at the name in its directory, not where a final symlink leads, by the run's own resolver (supervisor.md
  R15b), so `compile --test` and the run agree on it and on the kernel's place (golden rows 18 to 21).
- 2026-10-19, R28: each row's end is
  landed with the lookup of the syscall the row stands for (`agent.ActionKind.Lookups`), the run's own handlers held to
  the same table; an `fs.link` row's `path` is looked up whole and unfollowed, so a source ending in `.` or `..` after a
  symlink is answered where the walk lands (`refused`, `unmatched` out of every write entry), not on the symlink or the
  lexical clean (`allow`).
- 2026-10-19, R28: a `net.send` or `net.connect` row to a unix
  pathname is decided on its name and then on the socket the walk lands it on, as the supervisor decides it, and a
  relative name joins compile's working directory, as the run joins a relative `sun_path` to the agent's cwd; it was
  decided on its spelling alone, `allow` for a send or a connect through a symlink in a write entry to a socket outside
  it that the run refuses (`TestCompileTestUnixLandsAsTheRunGolden`).
- 2026-10-19, R28: a unix connect's or
  send's name is landed by the run's own unix walk and answered on what it met (`path-unreliable` through a magic link,
  a loop or procfs; `unix-absent` for a send beneath a file), a socket missing at compile is answered as the one the
  agent finds when it calls (stated), a relative name joins `getcwd(2)`'s directory, not `$PWD`, the `cgroup` and
  `bpflsm` columns refuse a send whose absolute name is not canonical, and a bind whose walk fails is refused
  `path-unreliable`; a name through `/proc/self/cwd` read `allow` that the run refuses (`TestCompileTestUnixWalkAsTheRunGolden`,
  `TestCompileTestUnixJoinsThePhysicalCwd`).
- 2026-10-19, R28: a bind whose walk
  fails is refused `path-unreliable` only under a listener policy, where the run's `bindUnix` decides it, and is the
  creation floor on its spelling with none, where the run continues it with no line; a missing part of a unix name on
  procfs is refused `path-unreliable`, not answered as naming nothing; and a missing unix name ending in `/` or `/.` is
  answered as naming nothing (`unix-absent` for a send). Each read a verdict the run never gives
  (`TestCompileTestUnixWalkAsTheRunGolden` rows 14 to 20 and L1, L2: 6 fail without the change). The landing a link
  `fs.protected_symlinks` refuses (Stepwise) and the physical cwd of `compile --exec` and of a table run with no cwd
  are now held by tests (`TestLandUnixStepwise`, `TestCompileExecJoinsThePhysicalCwd`,
  `TestRunResolvedJoinsThePhysicalCwd`).
- 2026-10-19, R28: a
  unix connect's or send's name is answered on the tree the agent calls in (the tree as it is, every directory the
  name's walk needs made, and the socket the agent binds at a final name that names nothing yet and that nothing needs
  as a directory), and what it reaches is decided as the run decides it: a directory, made or already there, or a file
  that is not a socket is refused `unix-foreign` through the write entry, as the run's R11a refuses it. A datagram to
  `out/x/y/..`, `out/d/`, `out/d` (a directory) or a regular file read `allow`, and a missing name ending in `/` or `/.`
  `unix-absent` (a connect `allow`), where the run refuses each `unix-foreign`; the amendments of R28's
  unix paragraph are restated as one model. A bind whose walk fails under a listener policy is answered on its spelling
  in the `bpflsm` column, whose plane never decides it, and `path-unreliable` only in the `landlock` and `cgroup`
  columns, where `bindUnix` does (`TestCompileTestUnixWalkAsTheRunGolden` rows 17 to 29, L1, L1c, L1p: 13 fail without
  the change; `TestEvaluateUnixLandedOnNoSocket`; `TestCompileLandsWhereTheRunLands` now holds every generated connect
  and send row's verdict, not only its landing, to the run's own decision code, and 72 of its rows disagree without the
  change).
- 2026-10-19, R28: a unix `net.connect` or `net.send` row whose name lands
  at a `net.ask` `unix:` scope's place is answered as the run answers it: `refused`, rule `unix-ask-scope`, for a
  datagram and for a connect a declared entry's spelling admits, and `refused` under the scope's rule for a connect no
  declared entry names (asked at run time). Merged, the landing was admitted by the write entry around the scope. A
  `unix:` entry's landed match is against `NetRule.UnixResolved`, the place the run gives it; the field first
  added for it, `NetRule.Resolved`, is gone (`TestEvaluateUnixLandedAtAnAskScope`).
- 2026-10-27, R14 (ADR 0043 D8): drift declares the name entries once they are enforced. Test:
  `TestDriftDeclaresNameEntries`.

## Resolved conflicts
Resolved (2026-09-22): `Limits.Repeats` (`repeats`, default 5) is a contract field and machine ceiling; `limit-repeats` is in the closed reason set; `measure`'s P0 columns exclude the ask columns until P1 (FEATURES C5); a minimal versioned price table is P0 (FEATURES E62); `run_start.limits{...}` is an optional v1 payload (record README).

Resolved (2026-09-22): E16 against `runtime-launch.md`'s `0 -> "max"` for `pids.max`/`memory.max`. E16 wins for every dimension — an explicit 0 is the tightest setting and omission is the only spelling of "unbounded" — and `runtime-launch.md` case 30 is amended to say it was describing the absent key all along. `runtime-launch.md`'s `Limits` struct comments now read `absent -> "max", an explicit 0 -> "0"`. `cpu.weight` is the single exception, on the kernel's authority rather than ours: its range starts at 1, so a 0 is an invalid value, and the machine config refuses a `limits.cpu_weight` outside 1..10000 at parse time, matching the contract schema, so no 0 reaches the cgroup writer.
