# internal/runtime + launch + cgroup + lifecycle (P0 detailed spec)

## 1. Purpose and boundaries

**Owns**: the `runtime.Run` facade and its shutdown ordering; the child stage (`cmd/tego __child`) that applies
Landlock/seccomp and execs the agent on one locked OS thread; the cgroup v2 manager (create, limits, kill, OOM/pids
detection, id lookup); the run lock (`flock`) used for liveness, `tego stop`, and the orphan sweep; signal receipt
and forwarding at the launcher; `PDEATHSIG`/subreaper wiring; the orphan sweep run by `run`/`stop`/`gc`; and the
build-lock protocol gating pin creation/detachment for tier-2/3 BPF objects (the programs belong to `enforce/cgroup`
and `enforce/bpflsm`; this document specifies the lock/pin contract those packages satisfy, because the sweep and
launcher shutdown drive `Detach`).

**Must not do**: decide any enforcement verdict (`enforce.Backend`/`Handle`); parse or attribute kernel/model traffic
(`observe`, `capture`, `derive`); decide token/cost/wall/stall/repeat breaches (`internal/runtime/limits` — a
distinct concern from the cgroup resource ceilings owned here); read the ledger for display (`internal/check` is
never imported); hold an `ask` decision (the notify loop's P0 default is unconditional `CONTINUE`; real decisions
are `internal/runtime/ask`/`supervisor`, wired by the facade but not implemented here); select or gate the
enforcement tier — `enforce.Select`/`doctor.Probe` run in `cli.run` **before** `runtime.Run` is invoked
(`P0-DESIGN.md` §4.1 step 1 vs. step 2); this package receives an already-selected, already-`Prepare`-able backend
and never re-derives or re-checks the tier ceiling (see R2).

**Imports allowed** (`docs/REPO-LAYOUT.md`, enforced by depguard):
- `internal/runtime` (facade): `internal/runtime/*`, `internal/ledger`, `internal/bpf`, `internal/platform`, `pkg/spec`.
- `internal/runtime/launch`: `internal/runtime/enforce/api` (the handle's interfaces), `internal/runtime/deputy`,
  `internal/platform/*`, `pkg/spec/identity`; no backend, not `internal/runtime/enforce` itself, not
  `internal/runtime/cgroup`, no `cilium/ebpf` and no YAML or policy type (ADR 0031 (a): depguard
  `launch-links-no-backend`, and `TestLaunchLinksNoBackend` on the whole link closure).
  `internal/platform` is a directory of sub-packages, not one package: `launch` imports `internal/platform/proc`
  (the one process start, ADR 0021 (3)) and `internal/platform/sys` (the pidfd, prctl, capability, Landlock and
  seccomp wrappers); `docs/REPO-LAYOUT.md`'s "proc, dns, sys" names them.
- `internal/runtime/cgroup`: standard library, `golang.org/x/sys/unix` only — nothing above `runtime`, no `enforce`.
- None import `internal/check`, `internal/serve`, `internal/cli`. `launch` and the child stage are TCB
  (`ARCHITECTURE.md` §16): no third-party dependency beyond `cilium/ebpf`, `go-landlock`, `x/sys`, `x/net`.

**Changes.**
- 2026-09-30, imports: `internal/platform/proc` and `internal/platform/sys` are sub-packages, as
  built; §11's open question on whether `sys` is one is dropped.
- 2026-10-19, imports (ADR 0031 (a)): `Handle`, `Armer`, `Listener` and `ListenerWaiter` moved from
  `internal/runtime/enforce` to the leaf `internal/runtime/enforce/api`, and the cgroup.kill escalation
  (`CgroupKiller`) to `internal/runtime/cgroup.Killer`, so `launch` links neither a backend nor the cgroup manager's
  policy types. Behaviour unchanged.

## 2. Models

```go
// package runtime (internal/runtime)
type Deps struct {
    Enforce enforce.Backend      // required; already Select()ed by cli.run (exit 125 [tier-unavailable] belongs there, not here — §4)
    Observe observe.Recorder     // nil when the tier has no kernel record (landlock: nil)
    Capture []capture.Source     // zero or more
    Ledger  *ledger.Writer       // already Open()'d (holds runs/<id>/lock)
    Clock   clock.Clock          // wall+mono time; fake clock in tests
}
// Result.Reason is run_end-reason-shaped (RUN-IDENTITY.md's exit-code table: exit|limit|stopped|signal|oom|pids|
// exec-failed|orphaned), NOT record.Reason-shaped — record.Reason (REASON-CHANNEL.md) is the closed refusal-code
// set on `refused` events, a distinct channel this package never writes to.
type Result struct { RunID string; ExitCode int; Reason string }

// Clock: three same-shaped interfaces, no shared package. internal/runtime/run.go and internal/runtime/limits/watcher.go
// declare Now and MonoNS; internal/ledger/clock.go declares Now and Mono. The boot-relative start time is
// runtime.StartBootNS(pid) (/proc/<pid>/stat field 22 * (1e9/Hz)), a function, not a Clock method.
type Clock interface {
    Now() time.Time                  // wall clock, record.Event.TS
    MonoNS() uint64                   // CLOCK_MONOTONIC, record.Event.MonoNS
}
```
```go
// package launch (internal/runtime/launch)
type ChildSpec struct {
    RunID, AgentID string
    Command               []string   // argv; Command[0] pre-resolved against PATH before clone
    Env                   []string   // final env, runtime vars already applied last (SEMANTICS §9)
    Dir                   string     // cwd, must exist (agent.Compile checked)
    Stdin, Stdout, Stderr *os.File
    Handle      api.Handle       // from Backend.Prepare
    Privileged  bool                 // R4 ordering swap
    Setuid      bool                 // root-tier opt-out of no_new_privs (ADR 0033)
    TargetUID, TargetGID int         // used only when Privileged
    LandlockFlags uint32             // LANDLOCK_RESTRICT_SELF_* bits; unknown ones dropped in the child
}

type Launcher struct{ subreaperSet bool } // PR_SET_CHILD_SUBREAPER set once per runtime.Run
// cgroup lends the run cgroup's O_DIRECTORY descriptor, borrowed across the clone alone (sys.CloneIntoCgroup, ADR 0023)
// as the source of CLONE_INTO_CGROUP; nil starts the child in the caller's cgroup
func (l *Launcher) Start(ctx context.Context, spec ChildSpec, cgroup sys.Lender) (*Child, error)

type Child struct {
    PID                   int
    PidFD                 *sys.FD    // clone3's CLONE_PIDFD, owned (sys.StartWithPidfd); set once, closed by Close
    ControlR              *os.File   // read end: child's fd-number write (§5 step 7)
    controlW              *os.File   // write end: parent's ack byte (§5 step 8)
    StartBootNS            uint64    // read once right after clone3 returns
}
// 4B LE read, then pidfd_getfd: the listener as a strict owner the caller moves into supervisor.New (nil: no filter)
func (c *Child) WaitNotifyFD(ctx context.Context) (*sys.FD, error)
func (c *Child) Ack() error // 1 byte, then close(controlW)
func (c *Child) Signal(sig unix.Signal) error                   // pidfd_send_signal(PidFD, sig, nil, 0), PidFD borrowed
```
```go
// package cgroup (internal/runtime/cgroup)
type Cgroup struct { Path string; ID uint64; dir *sys.FD } // dir: the directory's owner, shared by every copy, nil if none (ADR 0023); ID = the cgroup id (FS.ID, §4)
func (c Cgroup) Dir() sys.Lender // the directory for CLONE_INTO_CGROUP; nil if none, sys.ErrClosed once closed
// Limits: consumed here, owned by pkg/spec/agent (same shape on Contract and Machine).
type Limits struct {
    CPU        string   `yaml:"cpu"`         // cores; "" -> cpu.max "max"
    CPUWeight  int      `yaml:"cpu_weight"`  // 1..10000, default 100
    Memory     ByteSize `yaml:"memory"`      // memory.max; absent -> "max", an explicit 0 -> "0" (E30)
    MemoryHigh ByteSize `yaml:"memory_high"` // memory.high; absent -> unset/"max", an explicit 0 -> "0"
    Pids       int      `yaml:"pids"`        // pids.max; absent -> "max", an explicit 0 -> "0" (E30)
    Tokens, CostUSD, Wall, StallAfter interface{} // consumed by internal/runtime/limits only
}
// Manager matches P0-DESIGN.md §2.5's normative signature exactly: Events reports only the boolean "populated"
// transition.
type Manager interface {
    Create(path string) (Cgroup, error)
    Kill(Cgroup) error                    // write "1" to cgroup.kill
    SetLimits(Cgroup, Limits) error       // cpu.max, cpu.weight, memory.max, memory.high, pids.max
    Events(Cgroup) (<-chan bool, error)   // populated only, per P0-DESIGN.md §2.5 (normative)
    ID(Cgroup) (uint64, error)
    Remove(Cgroup) error                   // rmdir, descendants bottom-up
}
// ReadLimitEvents is a plain package function, not on Manager (so it does not diverge from the frozen interface):
// one pread of memory.events + pids.events, returning the raw oom_kill/max counters so the caller (runtime.Run's
// cgroup-watcher goroutine) can diff against its own last-seen baseline. See R10/R11.
func ReadLimitEvents(Cgroup) (oomKillCount, pidsMaxCount uint64, err error)
```
```go
// lock: internal/runlock (the probe, the lock line, the R22 proofs; the launcher writes the line from
// internal/runtime/runlock.go, which also delegates these names); sweep: internal/runtime/sweep.go
type LockInfo struct { PID int; StartBootNS uint64 }  // advisory content of runs/<id>/lock; liveness is the flock alone
// The flock itself is taken by the ledger writer (ledger.Repository.Lock -> *Writer, ledger.ErrRunLocked when held);
// this package only probes it and never unlinks the file.
func ProbeLock(runDir string) (held bool, info LockInfo, err error)

type SweepResult struct{ Scanned, Orphaned int; Errs []error }
func Sweep(ctx context.Context, ledgerRoot string) (SweepResult, error)

// StopTarget: pid-reuse-safe signal delivery for `tego stop` (R22). Replaces a stat-then-signal pair (TOCTOU) with
// one pidfd held across the verify-and-signal window.
func OpenStopTargetFor(runDir string, info LockInfo) (*StopTarget, error) // pidfd_open, verify BootNS(pid), else ErrStale
type StopTarget struct{ fd int }
func (t *StopTarget) Signal(sig unix.Signal) error // pidfd_send_signal(t.fd, sig, nil, 0)
func (t *StopTarget) Close() error
```
```go
// build lock: package enforce/cgroup (pins.go), unexported; taken in Handle.Prepare, asked in Detach
type buildLock struct{ path string; f *os.File }             // /run/tego/bpf-<hash>.lock only (ADR 0034)
func acquireBuildLockIn(d *hoststate.Dir, hash string) (*buildLock, error) // §5 R15, R21 (verified dir)
func (l *buildLock) lastOut() (bool, error) // §5 R16
func (l *buildLock) Close() error
```

Validation: `ChildSpec.Command` non-empty (re-checked defensively; `agent.Compile` is the real gate). `Limits.Memory`/`CPU` are pre-clamped to machine
ceilings upstream (SEMANTICS §8); this package writes what it is given and never re-checks ceilings.

**Changes.**
- 2026-10-25 (ADR 0100 (7)): the lock probe, the lock line and the stop target's proofs moved,
  unchanged, to `internal/runlock`, which the engine's clients link without the engine; `internal/runtime` keeps the
  launcher's side and delegates these names (the lock block above). No behaviour changed.
- 2026-10-19 (ADR 0029 (4)): the stop target is opened by `OpenStopTargetFor(runDir, info LockInfo)`, and the
  marker is published by `RequestStopGraceThen`; `OpenStopTarget(runDir, pid, startBootNS)` and `RequestStopGrace`,
  wrappers only tests called, left the API for the tests' own files. §3, R22, case 29 and §10 name the survivors.
- 2026-09-29: the Clock sketch and the lock block name the real types (`LockInfo`, `ProbeLock`, `ledger.ErrRunLocked`); the `internal/platform/clock` package and `RunLock`/`AcquireLock` were design names never built.
- 2026-09-29, `ChildSpec`: the `Rlimits` field and the child's setrlimit step are removed; nothing set
  them, and the `RLIMIT_NOFILE` floor this section promised was never implemented.
- 2026-09-29, §11: the `RLIMIT_NOFILE` headroom open question is dropped with the setrlimit step it tuned.
- 2026-09-30: `ChildSpec` has no `CgroupDirFD`; `Start` takes the cgroup fd as its own argument, the sketch lists `Setuid` and `LandlockFlags`, and `Cgroup`'s fd field is `FD`.

- 2026-10-19, `Child` (ADR 0023 C6 and C7): `PidFD` is a `*sys.FD` the start owns from clone3's store
  (`sys.StartWithPidfd`, the one site that adopts it) and Close closes; `Kill`, `Wait` and `Signal` borrow it, so a
  `Close` meanwhile is deferred until they return. `NotifyFD` is gone: `WaitNotifyFD` returns the listener as a strict
  `*sys.FD` (nil without a filter), which `runtime` moves into `supervisor.New`, and `Child` keeps no copy.

## 3. Repositories and storage

| What | Path | Perms | Format | Owner | Concurrency | Durability |
|---|---|---|---|---|---|---|
| Run lock | `<ledger_root>/<run>/lock` | `0600`/`0700` dir | `"<pid> <start_boot_ns> <pid_ns>\n"` (`pid_ns`: the launcher's `/proc/self/ns/pid` inode, optional when read) | launcher creates | `flock(LOCK_EX)`, one holder | not fsynced; liveness = the flock, never the content |
| Stop marker | `<ledger_root>/<run>/stop.request` | `0600` | existence is the signal; empty, or one Go duration and `\n` when `tego stop --grace` asked for its own stop_grace (R9) | `tego stop`: complete `O_EXCL` temporary write, then `link(2)` or `renameat2(RENAME_NOREPLACE)`, through the guarded retained directory (`ledger.PlaceNewFileThen`); the held-pidfd SIGTERM follows inside the publication transaction | Current cooperating publishers serialize publication, delivery and failed-delivery rollback. Earlier markers/grace survive later attempts; a rejected delivery removes only its own new matching inode through the same directory descriptor. The launcher reads `O_NOFOLLOW`, at most 64 bytes; anything but one positive duration uses the default grace. | not fsynced |
| Stop publication lock | `<ledger_root>/<run>/.stop.request.lock` | `0600`, regular, one link, run-directory owner | persistent per-marker flock | created through the guarded directory; retained until run retention removes the directory | Current `RequestStopGraceThen` and CLI publishers share `LOCK_EX`; acquisition honors caller cancellation and a 2-second limit. The lock is never unlinked/recreated by a publisher, so concurrent successful and failing requests use one serialization inode. | not fsynced |
| Cgroup | `<delegated subtree>/tego.slice/tego-<agent>.slice/run-<id>.scope` (unpriv) or `/sys/fs/cgroup/...` (priv/`tegod`) | delegated-parent perms | cgroupfs dir + control files (`cgroup.procs`, `cgroup.kill`, `cgroup.events`, `cpu.max`, `cpu.weight`, `memory.{max,high,events}`, `pids.{max,events}`) | launcher creates/removes | one writer for limits; `cgroup.kill` safe from any writer | recreated per run |
| Docker container-parent cgroup | `tego-<agent>-<runslug>.slice` or `/sys/fs/cgroup/tego/<agent>/<run>` | same | `descendants`-flagged entry in the run set | pre-created by the Docker proxy (out of scope), removed by the same `Remove` path | ancestry-based | not durable |
| Build lock | `/run/tego/bpf-<hash>.lock`, in the verified host-state directory only (ADR 0034) | `0600`, owned by the launcher's effective uid (`hoststate.OpenFile` refuses another owner, ADR 0042 (3)(b)) | empty file; existence + `flock` state | whichever launcher opens it first (`O_CREAT` relative to the directory's descriptor, `O_NOFOLLOW`, R21) | `LOCK_SH` per active launcher, taken at once, kept only once its name still leads to the opened file (`hoststate.Dir.Names`, else re-opened, at most 8 times); `LOCK_EX\|LOCK_NB` = last-out probe | stays while its build's pins do; unlinked only once they are gone, by its `LOCK_EX` holder (`removeBuildState`, ADR 0026 (6)); tmpfs clears it at boot |
| BPF pins | `/sys/fs/bpf/tego/<hash>/{progs,maps,links}/*` | bppfs default `0700` | pinned objects (`bpf_obj_pin`), not regular files | any launcher under its `LOCK_SH` hold: adopted when all present and compatible, else loaded and pinned, a concurrent pin's `EEXIST` adopted (R15) | removal only under the last-out `LOCK_EX`, held until close (R16) | lives until the last-out `Detach`; two builds coexist during upgrade |
| `$XDG_RUNTIME_DIR/tego/<run>/` | tmpfs | `0700` | the run's `CODEX_HOME` (`capture`, removed here; the approval socket is the ledger run directory's `ask.sock`, amended 2026-10-05); an unprivileged launcher's only: a root launcher makes none, since its `XDG_RUNTIME_DIR` is the invoking user's path | launcher creates (as `.new-<run>`, renamed in once its `.lock` is flocked) and removes; the next unprivileged launch under the same parent removes one whose `.lock` no launcher holds (amended 2026-10-19) | one run owns its subdir, `LOCK_EX` on `<run>/.lock` for the run's life | ephemeral (tmpfs) + explicitly removed, or by the next launch after a killed launcher |

**Changes.**
- 2026-10-05, build lock (ADR 0042 (3)(b)): no `0660` group form; a lock or slot table another uid owns is refused.
- 2026-10-19, runtime directory: a launcher killed before its shutdown left it until logout; the
  launcher now flocks `<run>/.lock` for the run's life and each launch removes its parent's unlocked run directories.
- 2026-10-05, runtime directory: holds no approval socket; the broker binds `ask.sock` in the ledger run directory.
- 2026-09-24, stop marker: placed by `link(2)`, not `rename`, so two concurrent stops cannot replace each other's
  grace.
- 2026-09-24, stop marker: placed through the ledger's walked descriptor
  (`ledger.PlaceNewFile`); a root `stop` created it wherever a user-planted link pointed.
- 2026-09-24, runtime dir: a root launcher makes none, since its `XDG_RUNTIME_DIR` is the invoking user's path.
- 2026-09-24, build lock and pins: the rows state the code — `/run/tego` only, shared from the
  start, never unlinked; they described an exclusive creator, a per-user fallback and last-out unlink.
- 2026-09-29, build lock: the lock of a build whose pins are gone is unlinked by its `LOCK_EX`
  holder, and a taker re-opens a lock whose name no longer leads to it; the row said never unlinked.

## 4. Functions and contracts

### `runtime.Run(ctx, m, rt, cmd, deps) (Result, error)`
**Pre**: `deps.Ledger` already `Open()`'d (holds the lock); `deps.Enforce` is the tier already selected by
`cli.run`'s `enforce.Select` — exit 125 [tier-unavailable] on an unavailable pinned tier happens there, before `Run` is ever called
(`P0-DESIGN.md` §4.1 steps 1–2; `RUN-IDENTITY.md`'s exit-code table never lists 211); `m` passed trust checks.
**Post**: exactly one `run_end` is the last `events.jsonl` line before returning, on every return path except an
unrecovered panic (R14). **Errors**: returns a bare `error` only for failures *before* `run_start` is written, and
that error is always exit 125 — `Run` owns no other exit code; `[tier-unavailable]` and `[config-untrusted]` are
`cli.run`'s own, before `Run`. After `run_start`, every failure folds into `Result.Reason` + `run_end` (R2).
**Idempotency**: none — one `RunID` is single-use; a second `Run` with the same id fails on the already-held
`flock`. **Timeouts**: none of `Run`'s own; `ctx` cancellation and OS signals (§6) are the only stops; `stop_grace`
belongs to the signal-handling goroutine, not to `Run` itself (R9).

Normative sequence (`P0-DESIGN.md` §4.1, ordering constraints from `ARCHITECTURE.md` §5):
1. `NewRunID`; `mkdir <ledger_root>/<run>/` `0700`; `ledger.Open` (takes the lock, writes `"<pid> <BootNS(self)>\n"` — R1).
2. `cgroup.Manager.Create`; `SetLimits`.
3. `deps.Enforce.Prepare(ctx, rt, runRef)` — opens `O_PATH` fds, builds ruleset/maps; tier 2/3 calls
   the build lock (`enforce/cgroup` `acquireBuildLockIn`) and attaches under the build-lock protocol (R15). `runRef` carries the run's resolver
   endpoints, read once here and handed to the supervisor's resolver set in step 8 as the same list, because tier 2's
   port-53 rows must name the servers the supervisor's exception names (enforce-cgroup-observe §5 R5); and the binary
   the child stage execs (`Launcher.Exe`, empty for `/proc/self/exe`), which tier 2 execs again for its detached
   helpers. Nothing `Prepare` leaves decides or records the run's actions yet: that state is armed in step 7a
   (ADR 0021 (2)).
   A tier whose kernel state outlives its launcher (tiers `cgroup` and `bpflsm`) then gets the run's reaper, `tego __reap`, started
   before any process of the run exists and never waited on (ADR 0020 (2)): in tego's helper cgroup, in a
   session of its own, holding a pidfd the launcher opened on itself and an `O_PATH` descriptor of the run
   directory taken through the ledger Writer's own, with the rest of what it needs as argv. A reaper that
   cannot be started fails the run here, exit 125, at tier `cgroup` in every plane mode and at tier `bpflsm`, whose
   backend is tier `cgroup`'s (ADR 0020 (4); its plane-mode gap path is not built); case 13.
   Before `Prepare` (*amended 2026-10-16*, agent-contract.md R10a), an unprivileged launcher creates
   `$XDG_RUNTIME_DIR/tego/<run>/` and the run's `CODEX_HOME` in it when the forwarder has an openai listener, and adds
   the write grant `fs.codex_home[<path>]` on exactly that directory to the table `Prepare` builds with, so Landlock
   pins a path that exists and every tier enforces the grant; this was step 4, after `Prepare`, where no grant could
   reach the kernel's rules. With an openai listener and no absolute `XDG_RUNTIME_DIR` the run is refused here, exit
   125, naming the fix (`ErrNoRuntimeDir`); a table whose write or ask entry covers `$XDG_RUNTIME_DIR/tego` or lies
   inside it is refused here too (`ErrRuntimeDirWritable`), before anything is made. That check runs first, at every
   euid, on every parent `config.RuntimeDirBases` names (the list every compile names, the dashboard's included):
   `/run/user/<uid>/tego` (uid `SUDO_UID` under sudo) whatever the environment says, and `$XDG_RUNTIME_DIR/tego`
   when it names another (*amended 2026-10-16*: it ran
   after the root and no-variable returns). The grant is added only while the path is still the directory just made
   (same device and inode, no link), and a run with an `exec.allow` or `exec.ask` directory over it is refused
   (`ErrCodexHomeExecutable`, exit 125). The grant carries that device and inode, and Landlock's
   `Prepare` refuses a descriptor that is not that directory; `XDG_RUNTIME_DIR` writable by group or others without the
   sticky bit, or `$XDG_RUNTIME_DIR/tego` that is a link or not this euid's alone, is `ErrRuntimeDirUnsafe`
   (exit 125) for a routed Codex and no runtime directory otherwise; a `<run>/` that is not this
   euid's alone right after its own `mkdir` (only a race makes it so) is `ErrRuntimeDirUnsafe` for every run
   (*amended 2026-10-17*: it was listed with the parent's check). Before it makes `<run>/`, the
   launcher removes each `<run id>` directory under the parent whose `.lock` no launcher holds, a killed launcher's
   (*amended 2026-10-19*; agent-contract.md R10a). A root launcher makes no
   directory; a root run with an openai listener writes `gap what=capture why=codex-unrouted` after `run_start`.
   A run that holds an owned DNS broker endpoint (`net.dns.mode: broker`, bound before `Prepare`;
   network-controls R8) gets a reaper at every tier, `landlock` and `observe` included (ADR 0020's 2026-10-05
   notes): it also holds the endpoint's directory and the verified `/tmp` parent, and takes the directory's name
   and the socket's device and inode as three more argv fields. That reaper starts before `Prepare`, as soon as the
   broker's socket is bound, and is handed the tier's target here through an inherited pipe (fd 7). Not root, the
   launcher starts it in its own cgroup (`cgroup.StartHelper`'s fallback). A reaper that cannot be started for
   that endpoint fails the run before `Prepare`, exit 125, at every tier.
4. (The runtime directory, `$XDG_RUNTIME_DIR/tego/<run>/`, is made before `Prepare` since 2026-10-16, step 3; an
   unprivileged launcher only: under root that variable is the invoking user's path, so root would create and later
   remove where that user points.) Start forwarder listeners; compute the final identity env.
5. `prctl(PR_SET_CHILD_SUBREAPER, 1)` once, before `launch.Start` (R1).
6. `launch.Start` → `clone3(CLONE_PIDFD|CLONE_INTO_CGROUP)` through `internal/platform/proc.Start`, the one process
   start of non-test code (ADR 0021 (3)), which also gives the child's start identity (`Child.StartBootNS`); returns
   `*Child`. The child stage is in the run's cgroup from its first instruction, and its `execve` of the launcher
   binary runs while `os/exec` holds the forking thread suspended. No mark of the run's fanotify group exists then
   (step 7a), so that exec never waits on the group, however tego is linked and whatever the contract names; a
   mark there held the launcher whenever a garbage collection began in the window (enforce-cgroup-observe E39).
7. `child.WaitNotifyFD(ctx)`: read the 4-byte LE fd number from `ControlR` (`write(2)` is never trapped — R6), then
   `pidfd_getfd(child.PidFD, n, 0)` into a strict owner, which the facade moves into `supervisor.New` (amended
   2026-10-19, ADR 0023 C7: New owns it on every path, closing it itself when it refuses). The stage writes that message only after its `execve` has returned.
7a. Arm (ADR 0021 (2)): a handle that implements `api.Armer` (tier 2) arms here, after the stage's `execve` and
   before the ack: the run-set row the recorder and the plane key on, and the fanotify marks. So the stage's exec
   is never decided or recorded as the run's, and the agent's first exec is. From here until step 13's `Detach`
   removes the marks the launcher starts no process (`proc.Start` refuses with `ErrArmed`): every process the run
   needs has started, and the helpers start after `Detach`. A failed arm is a pre-`run_start` failure, exit 125.
8. Construct `supervisor.Loop` over the duplicated fd; start it (and `observe.Recorder`, `capture` sources,
   `limits.Watcher`, the pipeline goroutine) in the `errgroup`, all bound to `ctx`. The loop's first
   `ioctl(NOTIF_RECV)` must be provably in flight before step 10 (R7). The DNS worker started here re-resolves host
   entries on TTL and, whenever the addresses it gives the tier differ from those the tier last received (a refresh
   that changed an entry's addresses, or a change in this host's own addresses, which agent-contract R18 keeps out
   of the rows), hands the table to a handle that implements `enforce.NetRefresher` (tier 2's `RefreshNet`,
   enforce-cgroup-observe §6 E7).
9. Write `run_start` (`launcher_pid launcher_start_ns tego_version commit bpf_hash tier capture kernel
   contract_hash parsers stop_grace command cwd`, per `spec/record/v1`), and from record minor 17 the run's identity
   (ADR 0073): `launcher_uid` always, and `launcher_user`, `sudo_uid`, `sudo_user`, `host`, `parent_run`, `labels`,
   `role` and `contract_revision` when the run has them. `Deps.ParentRun` that is not a run id, `Deps.Labels` that
   `identity.ValidLabels` refuses and a `Deps.Role` this version does not know are `ErrDeps` in `newRunner`, before
   step 1 makes the run directory. `Deps.RunStartExtras` (reserved blocks, record minors 32 to 34) is copied and checked at `record.Minor` in `newRunner` (a block
   `Minor` does not reach, or a malformed one, is `ErrDeps`, before step 1) and written into `run_start` as given;
   with every block nil the line is byte for byte what it was before the field (`TestRunStartUnchangedWithoutExtras`).
   Then the post-`run_start` gaps are queued, in `postStartGaps` order
   (`emitPostStartGaps`): own state restored (`Deps.OwnStateRestored`, case 43), capture, price, unmetered budgets,
   watched reads, codex unrouted, reason-unavailable, Landlock audit, limits.
9a. **The Started hook** (ADR 0073 D4): `Deps.Started(StartedRun{ID, Dir})`, when set, is called once, after step 9's
    `run_start` is durable and its gaps are queued, and before the group check and `child.Ack()`: the one point where
    the run id and its directory exist and the agent has not run. The agent waits for it. An error from it ends the
    run fail-closed as a failed ack does: the child is killed before it execs, `run_end reason=error` with `detail`
    `started hook: <error>` (cut to `record.MaxDetailBytes`, as every `run_end.detail` is), exit 125. The hook, the
    group check and the Ack are one function, `releaseAgent`, in that order, each only when the one before passed. A
    panic is not recovered (R14): the launcher dies before the Ack, so the child stage never execs the agent (ADR
    0020) and the sweep closes the run. An adoption calls none.
10. `child.Ack()` (one `0x01` byte) → child's blocked `read` returns → child `execve`s. `execve` is a notified
    syscall, so this is the **first** notification, already caught by step 8 (R7); recorded `kind: exec`, answered
    `CONTINUE`.
11. Start the signal-handling goroutine (§6 rules) and the cgroup limit watcher in the `errgroup`: a 200ms ticker
    (`limitPollInterval`) that reads `cgroup.ReadLimitEvents` and diffs the oom/pids counters against the baseline
    `createCgroup` read (R10/R11). It does not use `Manager.Events`; step 12's populated wait is `WaitEmpty`.
12. Block until `cgroup.events.populated` transitions `1→0`, `ctx` cancels, or a worker errors. When `ctx` ends
    with the cgroup still populated, or the wait itself fails (`cgroup.events` or its inotify watch unreadable, which
    also notes that in `run_end.detail`), the tree is killed (`cgroup.kill`) and waited for on a context of its own,
    bounded by `killTimeout` (10 s), because step 13's final ring-buffer drains read only what the rings hold when
    they begin and `cgroup.kill` delivers SIGKILL asynchronously; a tree that outlasts the bound is `gap
    what=record why=ringbuf-undrained` with no count for a run whose kernel record reads (enforce-cgroup-observe.md
    §4).
13. Shutdown, exact order (R8, R18): cancel `ctx` → stop every source, while the events channel is still written to
    the ledger (a source's `Stop` is where its final drain emits a run's last samples, which would otherwise become
    `channel-full` past the channel's free slots) → `errgroup.Wait()`, and the tier-2 listener's leftover workers,
    still with the channel read → release any producer still waiting for room (only after `errgroup.Wait()`, so a
    supervisor worker waiting in a full lane with the line of a notification it already answered writes it rather
    than dropping it as `channel-full`) → drain the events channel → read the run cgroup's resource files for `run_end.resources` (`cgroup.ReadResources`:
    `memory.peak`, `pids.peak`, `cpu.stat`, `memory.events`; the tree is normally empty by now, so nothing adds to
    them, but step 12 can end with it still populated in two ways: its wait failed while `ctx` had not ended
    (`cgroup.events` or its inotify watch could not be read), which kills the tree like a cancelled `ctx` and puts `cgroup.events unreadable, tree killed` in `run_end.detail`, or a killed tree
    was not seen empty within step 12's bound (a task in uninterruptible sleep). That tree is read as it stands and
    can still add to the files after the read, so the values are then a lower bound; the cgroup still exists; a
    file the kernel lacks is an absent key, record-ledger.md §2.2) → restore the modes of tego's own files and
    directories the run's agent took from their owner, one `gap what=record why=own-state-mode-restored` each (case
    43) →
    `ledger.Close(reason)` (`run_end` + `head`, fsync, appends to `chain.log`, then releases the run lock:
    `flock(LOCK_UN)` and the fd's close, R1) →
    `Handle.Detach()/Close()` (frees `O_PATH` fds, drops map entries, runs the build-lock last-out probe, R16) →
    `cgroup.Manager.Remove` (+ adopted descendants, bottom-up) → remove `$XDG_RUNTIME_DIR/tego/<run>/` →
    the live-index entry's removal (R8: the entry, not the lock, marks the launcher as still tearing down) → return `Result`. Every step in this
    chain runs regardless of whether an earlier step errored (R18): the alternative — aborting shutdown early —
    would leave the cgroup, pins, or lock behind, strictly worse than a logged partial failure.

### `launch.(*Launcher).Start(ctx, spec, cgroup) (*Child, error)`
**Pre**: `cgroup` lends an open `O_DIRECTORY` descriptor of the run cgroup (`cgroup.Cgroup.Dir`), borrowed across
the clone alone and passed to `clone3` as `CLONE_INTO_CGROUP` so the child is in it from its first instruction
(invariant 3; a lender whose descriptor was closed is `sys.ErrClosed` before any clone, exit 125, ADR 0023 R25), or
nil, which starts the child in the caller's cgroup
(the package's own tests only: `runtime.Run` always passes the directory of the cgroup its step 2 created, so invariant 3
holds for every run); `spec.Handle` non-nil; caller already set the subreaper flag. **Post**: on
success one child exists on one thread, blocked on its ack read (never races ahead to `execve` — R5). On error the
child (if created) is `pidfd_send_signal(SIGKILL)`ed and reaped before returning (R13, no leaked child). **Errors**:
`clone3` errno (`EAGAIN`/`ENOSPC`/`EPERM`/`EINVAL`/`ENOSYS`) → `ErrClone`, always folding into `Run`'s exit-125 path
(never 211 — the tier ceiling was already validated by `cli.run` before `Start` runs; see case
20); child-side setup errno reported as a 5th control-pipe message (negative `int32` instead of the fd number) →
decoded reason; a child that exits without writing anything → `io.EOF` on `ControlR` → `ErrChildDied`. **Side
effects**: process creation only — no fs/cgroup writes (those are `Run`'s steps 2–3). **Timeouts**: none of its own;
caller's `ctx` governs `WaitNotifyFD`/`Ack`.

### `cgroup.Manager` methods
- `Create`: `mkdir`; opens `O_DIRECTORY|O_CLOEXEC`, returns the fd. A pre-existing directory at the same path is
  `ErrCgroupExists` (run ids are unique — this is corruption, not a race).
- `SetLimits`: `cpu.max` = `"<round(CPU*100000)> 100000"` or `"max 100000"`; `cpu.weight` decimal 1–10000 (default
  `"100"`); `memory.max`/`memory.high` decimal bytes or `"max"`; `pids.max` decimal or `"max"` (never `"0"` for an
  *absent* field — E30; `"0"` for one an operator wrote as 0, which is a real cap). A `memory.max` cap writes
  `memory.swap.max` `"0"` right after it (ADR 0038): `memory.max` alone bounds the RAM a cgroup holds, and the kernel
  swapped an agent over its cap out instead of OOM-killing it, so on a host with free swap a 64 MiB agent grew to the
  size of the swap space and R10's `oom` never came. A kernel that accounts no swap to cgroups (`swapaccount=0`,
  `cgroup.memory=noswap`) has no `memory.swap.max`, and that one write is skipped; the agent can then still be
  swapped past its cap, uncapped and unaccounted, so when `/proc/swaps` lists an active area the run prints one
  warning (`[swap-uncapped]`) and records a `gap` `what=limits`, `why=memory-swap-uncapped` after `run_start`
  (`cgroup.UncappedSwap`; `doctor`'s D9 reports the same host as a failed check with the fix). Each is one `write(2)`;
  `EINVAL` is fatal to startup (exit 125), never silently dropped.
  `ENOENT` on any of these files is a distinct, diagnosed failure (case 31): the controller was never enabled on the
  delegated parent's `cgroup.subtree_control` (a common `systemd --user` / manual-delegation misconfiguration), not
  a bad value — the error names the missing controller and the one-line fix, same as `EINVAL`'s fatal-at-startup
  treatment but a different message.
- `Kill`: `write(cgroup.kill, "1")` — one syscall, returns immediately; `SIGKILL` delivery to the whole subtree
  (recursive) is asynchronous — callers poll `cgroup.events.populated` to confirm (R10, never assumed synchronous).
- `Events`: an `inotify` watch (`IN_MODIFY|IN_DELETE_SELF`) on `cgroup.events`, the kernel's documented
  notification ("a value change in this file generates a file modified event", `cgroup-v2.rst`; exercised by
  `cgroup`'s `TestEvents`). It re-reads the file on every wakeup and at least every 200ms (`pollFallback`), so a
  lost notification delays a transition by at most 200ms and never hangs it; if `inotify` cannot be armed it polls
  every 200ms. It emits the `populated` bool on each transition, matching the normative signature exactly.
  `Run` does not call it: it is kept to match the interface `P0-DESIGN.md` §2.5 freezes (§11), and `Run`'s
  populated waits use `WaitEmpty` (the same `inotify` watch and 200ms fallback). `ReadLimitEvents` reads
  `memory.events` and `pids.events` and returns the raw `oom_kill`/`max` counters for the caller to diff against
  its own baseline (R11); `Run`'s step 11 watcher calls it on its own 200ms ticker, not on an `inotify` wakeup. It
  is kept out of the `Manager` interface so the interface itself stays byte-for-byte what `P0-DESIGN.md` §2.5
  freezes (see §11).
- `ID`: the u64 inside `name_to_handle_at`'s `FILEID_KERNFS` handle for the cgroup directory (5.5+; identical to
  `bpf_get_current_cgroup_id()`'s value), read through `FD` while open, else through `Path`; on any other handle
  type or a filesystem without handles it falls back to `st_ino`, which cgroup2fs sets to the same value.
- `CanPlace` (a method of `*cgroup.FS`, not of `Manager`, which `P0-DESIGN.md` §2.5 freezes): whether this process
  can put a process into a cgroup under `Root`, which `Detect` does not ask (case 41). `runtime.Run` asks it before
  `Create`; `nil` or a `*DetectError` matching `ErrOutsideSubtree`.
- `ReadResources` (package function, not a `Manager` method, for the reason `ReadLimitEvents` is one): reads
  `memory.peak` (5.19+), `pids.peak`, `cpu.stat` (`usage_usec`, `user_usec`, `system_usec` on every cgroup v2 kernel;
  `nr_throttled`, `throttled_usec` with the cpu controller) and `memory.events` (`high`, `max`, `oom`, `oom_kill` with
  the memory controller) once, at step 13, into pointer fields: a file or key the kernel did not write stays nil and
  becomes an absent `run_end.resources` key, never a zero (`docs/VERSIONING.md` §2). A file that exists and cannot be
  read leaves all its keys absent, and a value that is not a count (`memory.peak`'s or `pids.peak`'s, or one key of
  `cpu.stat` or `memory.events`) leaves that one key absent; each is returned as an error beside what could be read,
  and the run logs it and ends as it would have. As built 2026-09-23 (`TestIntegrationRunEndCarriesResourcePeaks`: 64
  MiB and twenty processes held at once read back as `memory_peak` ≥ 64 MiB and `pids_peak` ≥ 20, equal to the files
  at that moment). `measure` and `status <run>` render the peaks from `run_end.resources`, an absent key as `unknown`
  (`limits-check-doctor-cli.md` R-res).
- `Remove`: descendants first (deepest path first), then `rmdir`. `EBUSY` (a task in uninterruptible sleep survived
  `SIGKILL`) retries 5× over 1s, then logs and defers to the next sweep pass (E9, never fatal to the current run).
  A cgroup reaching `Remove` is always fully torn down or left for the sweep in its entirety — partial limits never
  survive into reuse, because `Create` refuses to reuse an existing path (`ErrCgroupExists`) and the run id is
  single-use, so nothing downstream ever reads a half-configured cgroup as if it were fresh (case 33). Closing the
  scope's directory fd is part of `Remove` but never a precondition of it: a close that fails is reported *after* the
  `rmdir`, never instead of it (R18) — an fd that is already gone must not turn a removal into a leak. `Cgroup` is
  passed by value and the launcher's signal killer, the limits watcher and `Remove` each hold a copy of the same
  value, so the fd is owned by the value, not by a copy: the first close wins, later ones are no-ops, and a copy whose
  fd is closed resolves control files through its path — never through a descriptor number the process has reused.

**Changes.**
- 2026-10-25, `Run` step 9: `Deps.RunStartExtras` carries the reserved
  `run_start` blocks into the writer, the one way they reach it; `newRunner` refuses one `record.Minor` does not reach
  (`TestRunRefusesExtrasItsMinorDoesNotReach`), so until each block's writer raises `Minor` no run can carry it.
- 2026-10-25, `Run` steps 9 and 9a (ADR 0073): `run_start` carries the run's identity (record
  minor 17, `MinorRunIdentity`); `Deps.Labels`, `Deps.Role` and `Deps.Started` are new, and a bad parent run, label or
  role is `ErrDeps` before the run directory exists; the post-`run_start` gaps are one ordered list (`postStartGaps`),
  and the Started hook runs after the last of them and before the agent is released, an error ending the run with exit
  125; the hook, the group check and the Ack are `releaseAgent`, and `run_end.detail` is cut to
  `record.MaxDetailBytes`.
- 2026-10-19, `Start`, `Cgroup` (ADR 0023 C13): `Start` takes the run cgroup's directory as a `sys.Lender`
  (`cgroup.Cgroup.Dir`; nil: the caller's cgroup) and borrows it across the clone alone (`sys.CloneIntoCgroup`), so
  a closed one is `sys.ErrClosed` before any clone; `Cgroup` holds its directory as one `sys.FD` shared by every
  copy, closed once, and has no `FD` field.
- 2026-09-30, `Run` step 12: a failed wait for `cgroup.events` kills the tree and says so in `run_end.detail`.
- 2026-09-30, `Start`, `ID`: `Start` takes `cgroupFD` (`< 0`: the caller's cgroup); `ID` reads the `FILEID_KERNFS` handle first, `st_ino` as fallback.
- 2026-09-23, `Run` step 12: a killed tree is waited for, bounded by `killTimeout`, before the final drains.
- 2026-09-23, `Run` step 13: sources stop while the channel is still read; their final samples became
  `channel-full`. The resource read names both ways step 12 can end populated.
- 2026-09-24, `Run` step 4: a root launcher creates no `$XDG_RUNTIME_DIR` subdirectory.
- 2026-10-17, `Run` step 3: a `<run>/` directory that is not private after its own `mkdir` refuses
  every run, as the code did; the text listed it with the parent's check, which refuses only a routed one.
- 2026-10-16, `Run` steps 3, 4: the runtime directory and the run's `CODEX_HOME` are made before
  `Prepare`, whose table carries the `fs.codex_home` grant; an openai listener with no `XDG_RUNTIME_DIR` is exit 125.
  Amended the same day: the grant's identity is compared at `Prepare`, and a runtime directory another
  user could change is refused for a routed Codex and skipped otherwise.
- 2026-09-29, `Run` step 13: no final `limits` snapshot is taken; it named a step no code performs.
- 2026-09-24, `Run` step 13: waiting producers are released after `errgroup.Wait()`, not before.
- 2026-09-24, `SetLimits`: a memory cap sets `memory.swap.max` to 0 (ADR 0038).
- 2026-09-24, §4 `SetLimits` (ADR 0038's note): a skipped `memory.swap.max` with swap active is a warning
  and a `what=limits` gap, not a silence.
- 2026-09-29, `Run` step 3 (ADR 0020): a tier-2 run starts its reaper after `Prepare`, and fails without one; step
  11's watcher records `gap what=record why=cgroup-events-unavailable` when it gives up.
- 2026-10-05, `Run` step 3 (ADR 0020's 2026-10-05 note): a run with a DNS broker endpoint starts
  a reaper at every tier and fails without one; the text said tier 2 only (2026-10-04, changed the code).
- 2026-09-30, `Run` step 11 and §4 `Events`: the limit watcher polls `ReadLimitEvents` every 200ms; `Run` never
  calls `Manager.Events`, which is kept for the frozen interface.
- 2026-09-29, `Run` steps 3, 6, 7, 7a (ADR 0021): the tier arms after the stage's `execve` and before the ack; the
  stage starts through `proc.Start`, which refuses while armed and gives its start identity; tier 2's stage
  exemption and its static-build and `deny_read` refusals are gone.
- 2026-09-30, `Events`: the mechanism is `inotify` `IN_MODIFY` on `cgroup.events` with a 200ms re-read, not
  `epoll` `EPOLLPRI` (§11's open question closed).
- 2026-10-05, `Run` step 3: a DNS broker's run starts its reaper before `Prepare`, so a launcher
  killed during `Prepare` no longer leaves `/tmp/tego-dns-N` behind; the reaper learns the tier's target afterwards.

## 5. Business rules

**R1 — Lock fd identity.** The `RunLock`'s `flock` is the same open-file-description `ledger.Writer` locked;
release is "close that one fd", never a second `open`+`flock` — Linux `flock(2)` is per open-file-description, so a
second `open`+`flock(LOCK_EX)` on the same path from the *same process* still blocks against the first (verified;
also the basis of R12).

**R2 — Error surfaces exactly once, and only as 125.** Pre-`run_start`: `Run` returns a Go `error`, always mapped to
exit 125 by `cli.run` — tier-selection failures (exit 125 [tier-unavailable]) and machine-config failures (exit 125 [config-untrusted]) both happen in
`cli.run` strictly before `runtime.Run` is invoked (`P0-DESIGN.md` §4.1 step 1: `config.Load` exit 125 [config-untrusted],
`enforce.Select` exit 125 [tier-unavailable]; step 2 is `runtime.Run`), so this package's own pre-`run_start` error path owns no other
code. Post-`run_start`: every failure
becomes `Result.Reason` + `run_end`; `Run` never returns a non-nil `error` once `run_start` exists (depends on R8,
R18).

**R3 — Tier selection never self-elevates.** `enforce.Select` reports the highest tier the *current* credentials
allow; `Run` never re-execs itself through `sudo`/`privileged_binary`. A ceiling above current credentials is a
`doctor` gap, never an implicit elevation (matches `spec/config/v0`'s trust model).

*Amended 2026-10-16 ([ADR 0041](../adr/0041-race-free-supervisor-decisions.md) D2, Stage B):* given `ChildSpec.Deputy` (the run's contract chose
`gate.completion: held`), the stage starts the open deputy, `/proc/self/exe __open-deputy`, right after
`landlock_restrict_self` and before the seccomp filter, in both orders: in the run's domain and cgroup, with no
listener of its own. It is cloned with `CLONE_PARENT`, so its parent is the launcher, a subreaper, never the agent the
stage becomes; at a privileged run the exec gives it the agent's uid, gid and groups. Its standard streams are
/dev/null, opened before the domain exists; its control socket follows the inherited descriptors (`wireSpec.DeputyFD`).
The stage waits for its readiness (at most 10 s) and reports a deputy that does not start on that socket
(`deputy.ReportFailure`), failing nothing; the launcher reads the hello once the stage has reported. The run ends the
deputy once it is the run cgroup's last process, before the wait for the empty cgroup, and reaps it
(`TestStageStartsTheDeputyInTheRunsDomain`, `TestIntegrationHeldCompletionAtLandlock`). Nothing else reaps it: the
run's reaper (ADR 0006 R1) leaves the deputy's zombie alone (`Child.KeepUnreaped`), so a deputy the agent ended holds its pid, one task of
`limits.pids`, until the run's end, and no later process of the run is given the pid by which the kernel recorder
drops the deputy's records (supervisor R7a; `TestReapOrphansKeepsTheDeputy`, `TestIntegrationKilledDeputyKeepsItsPid`). The deputy's exec completes
before the stage reports, so before Arm: no plane or listener decides it, as none decides the stage's own exec. Its threads count against the run's `limits.pids`: a Go runtime's handful at start, one more for each held open in flight.
*Amended 2026-10-17 (ADR 0041 Stage B):* in the privileged order the deputy is exec'd
before the stage sets no_new_privs, so it starts without it; the deputy sets it and installs its filter on one thread,
locked for its life, which TSYNC carries to every thread (a filter installed from another thread was refused `EACCES`,
and the deputy died before its readiness, at random). A deputy that cannot start sends its reason on the readiness
socket; the stage's report carries it (`deputy.ReportFailure`'s reason), and so does the run's warning
(`TestDeputyConfinesOnOneThread`, `TestAwaitReadyNamesWhyTheDeputyDidNotStart`).

**R4 — Privileged ordering swap.** When `spec.Privileged` (root launcher, `privileged: true`, or a root tier that
needs `CAP_SYS_ADMIN` to attach programs before any per-process drop): child-stage steps 5 (Landlock) and 6
(seccomp) run **before** step 2 (uid/capability drop) while the thread still holds `CAP_SYS_ADMIN`; step 4
(`no_new_privs`) runs after the drop, dumpable and PDEATHSIG, before the ack (ADR 0033), so no process of a
root-tier run becomes root through a setuid exec — the one thing skipping it would allow, after which a root agent
could open a pinned BPF map and delete its run's row, silencing the plane, the recorder and the cgroup programs. A
contract's `setuid: true` (root tiers only; compile refuses it at tier landlock) skips step 4, compile warns, and
the opt-in is in the run's contract copy and hash. Under a `net:` section such a run takes `CAP_NET_ADMIN` out of the
bounding set before anything else in this order (`spec.DropNetAdmin`, ADR 0128), failing with `StepCaps`, so that no
exec gains it and the kernel refuses every change to the network. At tiers 2 and 3 the filter answers `bpf`, `init_module`,
`finit_module`, `delete_module`, `kexec_load` and `kexec_file_load` `EPERM` whatever the opt-in, as Docker's default
profile does: confinement in the filter itself, no ledger line. The drop itself is per-thread raw syscalls
(`sys.DropThreadCreds`): x/sys/unix's all-threads path tgkills every thread from the filtered one, which below
Landlock ABI 6 hung on the signal arm.

**R4a — The privileged drop target is a real unprivileged account, or the run is refused**.
`spec.TargetUID`/`TargetGID` are `ARCHITECTURE.md` §5 step 2's "the invoking uid/gid": `SUDO_UID` with
`SUDO_GID` (or, failing that, the target uid's own passwd primary group). They are **not**
`config.InvokingUID()`'s fallback value, which `identity-config.md` R19/E8 define for the *config trust* question
and which answers `os.Getuid()` — **0** — whenever `SUDO_UID` is absent or corrupt, and they are **not** the uid
reused as a gid (uid and primary gid are allocated independently on directory-backed hosts, so aliasing them drops
the agent into a group the caller never belonged to — DAC rights Landlock's per-path grants do not mediate). A root
launcher that can name neither exits 125 before the child is created (see case 36): with a target of 0 the drop is
three no-op syscalls and, whenever `no_new_privs` is skipped (a contract's `setuid: true`, R4), the kernel's
root-exec rule gives the agent's `execve` the whole capability bounding set as its permitted *and* effective set
(`capabilities(7)`, "Capabilities and execution of programs by root" — the `nnp`/tracer downgrade that would undo
it is exactly what that skip gives up); even with it set the agent runs as uid 0. The seccomp filter allows
`init_module`, `bpf`, `mount` and `setns`, and Landlock mediates none of them, so such an agent is outside the
confinement the run claims.
The drop replaces the supplementary group list with `TargetGID` alone (`setgroups([TargetGID])` before
`setresgid`/`setresuid`, `sys.DropThreadCreds`); it does not rebuild the invoking user's list (`initgroups`), so a
privileged run's agent has none of their other groups, where the same command run unprivileged keeps them all. This
narrowing is deliberate and fails closed: a group such as `docker`, `disk` or `kvm` grants through a socket or a
device node what Landlock's per-path grants do not bound (a `connect` to a pathname unix socket is not mediated), so
carrying it would put the agent outside the confinement the run claims, and the launcher, which already runs as
root with root's groups after `sudo`, would have to resolve the list through NSS it does not otherwise trust. A path
the invoking user reaches only through such a group answers `EACCES` in a privileged run; the contract grants it by
path under a group the target gid holds, or the run goes unprivileged (tier landlock).

**R5 — Ack ordering.** The child never `execve`s before the ack byte, so the parent's `NOTIF_RECV` loop is
*provably* running first (R7) — without the wait, the child's own `execve` notification could arrive with no
listener attached yet.

**R6 — Two anonymous pipes, not one.** Pipe A (child→parent): 4-byte LE notify-fd number, one `write(2)` (never
trapped). Pipe B (parent→child): one `0x01` ack byte after `NOTIF_RECV` is armed (R7); also never trapped. Both
ends not needed by each side are `O_CLOEXEC` and closed explicitly — the parent's copies the instant `clone3`
returns, before the spec is written, so a peer that dies mid-handshake yields `EOF`/`EPIPE` and never a hang on a
spec larger than the pipe buffer (cases 18, 27). The spec write is bounded by `ctx` besides, for the peer that is
stopped rather than dead and so keeps its read end open.

**R7 — NOTIF_RECV before Ack, always.** The supervisor's first blocking `ioctl(NOTIF_RECV)` must be confirmed
in-flight (an unbuffered "ready" signal from inside the loop, immediately before the ioctl call) before
`Child.Ack()` runs — a bare `go loop.Run(ctx)` gives no such ordering guarantee against the child's subsequent
`execve`.

**R8 — Shutdown order guarantees `run_end` last.** `ctx` cancel → `errgroup.Wait()` → drain channel → `ledger.Close`
→ (lock release, inside `ledger.Close`) → `Detach/Close` → `cgroup.Remove` → live-index entry. Every producer selects on `ctx.Done()` in its send loop (never a
bare blocking send), so nothing writes to the events channel after `Wait()` returns; `ledger.Close` is provably the
last writer. Each source's `Stop` is waited for at most 30 s (`sourceStopWait`), the kernel recorder first, then
the capture sources' hook queues are closed, then the capture sources. A `Stop` that does not return in time is left
running and recorded `gap what=record why=source-stop-timeout binary=<source>`, so it cannot hold `run_end`, and
the release of the cgroup and pins, for as long as it waits. Such a `Stop` may still be reading the ring, maps
and pins the handle owns, so when any `Stop` was left running the handle's `Detach/Close`, the `cgroup.Remove`
ordered behind it, and then the live-index entry's removal run on a goroutine of their own once every such `Stop`
has returned; the rest of the release goes ahead and the launcher does not wait
(`TestReleaseWaitsForAStopStillRunning`, run under `-race`). The live-index entry goes only after the handle's
release and the scope's removal, and only when the scope was removed; unwind's `Abandon`, run-directory removal and
clear wait the same way. A launcher that exits first, or a scope that could not be removed, leaves the run listed,
and the next sweep's ended hook (R20) — or, for a run that never started, the empty-run hook — removes what it
left, including a launcher killed between clearing the entry and removing the scope
(`TestShutdownClearsTheLiveEntryOnlyOnceTheScopeIsReleased`).
The events channel is one lane per class of producer, read fairly by the pipeline: the supervisor's (waits up to
250 ms for room), the capture sources' (waits up to 5 s), the kernel recorder's and tier 2's fanotify listener's
(each never waits: a wait would stall the kernel's ring or the host's opens), and a default lane for the run's own
lines. A flood fills its own producer's lane and no other, and every drop is a `channel-full` count.
A worker that failed is the run's end whenever it failed: `shutdown` reads the error `errgroup.Wait()` returns, and
one that is not the group's own cancellation, with no end decided yet, ends the run `reason=error` with the
worker's error as `detail` (`enforce-listener: ...`), also when the agent's own exit won the race
(`TestShutdownEndsWithErrorWhenAWorkerFailedAfterTheAgentExited`).

**R9 — `stop_grace` is launcher-owned, not kernel-owned.** On `SIGINT`/`SIGTERM`/`SIGHUP` or a detected
`stop.request`: start `time.AfterFunc(stop_grace, escalate)` — once, on the first trigger, never restarted or
extended by a later one (a process able to signal the launcher could otherwise postpone the escalation for as
long as it kept sending `SIGTERM`); when that first trigger is the `SIGTERM` of a `tego stop --grace <d>`, the
timer runs for `<d>` instead, read from the marker, longer or shorter (`launch.SignalPolicy.RequestedGrace`;
only `SIGTERM`, which is what `stop` sends, carries it — a `SIGINT` or `SIGHUP` that finds a marker runs
`stop_grace`; the requested grace postpones only this escalation, and `stop_grace` is a setting the same user
can raise in `~/.tego/config.yaml` anyway); a second
`SIGINT` within 2s cancels the timer and escalates immediately. `escalate` = `Manager.Kill`. `stop_grace` comes from
`Machine.StopGrace`, never hardcoded (default 10s). The timer's goroutine is joined by the signal worker before it
returns (§9), so no `cgroup.kill` is ever still in flight once the worker set is joined and `run_end` is decided. A
write that *failed* is not an escalation: `escalated` stays false and the error leaves the handler rather than being
stored unread (§7). No later signal retries it: the worker returns the error and handles no more signals, and the
group's error path retries the kill and writes `run_end`. A later `Escalate` call still retries, since `escalated` is
false.

**R9a — a tier-2 launcher is never stopped by its terminal (*added 2026-09-23*, enforce-cgroup-observe.md E40).**
A launcher whose enforcement handle owns a loop the host waits on — tier 2's fanotify listener
(`api.Listener`), whose permission marks cover the mount of `/` — must not stop: a stopped launcher answers
nothing its group is sent and keeps its marks, so every open and exec on the marked mounts waits until it continues,
and Ctrl-Z on `sudo tego run --tier cgroup` stopped the host. `Launcher.Start` therefore calls
`launch.HoldJobControl` for such a handle, before the clone: `SIGTSTP`, `SIGTTIN` and `SIGTTOU` are set to `SIG_IGN`
for the launcher, process-wide and once. Ignored, not caught: a caught `SIGTTIN`/`SIGTTOU` makes the tty read or write
that raised it restart (`tty_check_change` answers `-ERESTARTSYS` and signals the process group again), so a
launcher writing to its terminal from a background group would spin, where an ignored `SIGTTOU` lets the write
through and an ignored `SIGTTIN` fails the read with `EIO`. An ignored disposition survives `execve`, so the child
stage, which inherits it, sets the ones the launcher had not already inherited as ignored back to `SIG_DFL` before
it execs the agent (`wireSpec.reset_signals`, a raw `rt_sigaction`: `os/signal`'s `Reset` restores the disposition
the process started with, which is `SIG_IGN`). Ctrl-Z then stops the agent, which shares the process group and gets
its own copy, and leaves the launcher answering; the shell does not see the job stop (its child, the launcher, did
not), so the terminal stays with the run: Ctrl-C starts `stop_grace`, whose `cgroup.kill` ends a stopped agent too,
and `kill -CONT` on the agent resumes it. A tier-1 or observe launcher holds no listener and keeps the default, so
it stops with its agent and the shell's `fg` works as before. `TestJobControlStopsTheAgentNotATier2Launcher` (both
cases, against the kernel). **Not covered:** `SIGSTOP`, a debugger and the cgroup freezer, which cannot be ignored
(E40's residual until the decisions leave a stoppable process: tier 3). There is no window before the first mark:
`Prepare` places none, `Handle.Arm` places them after `Start` (ADR 0021 (2)), and `Start` calls `HoldJobControl`
for a handle that owns a listener before the clone.

**R9b — the launcher follows its agent's own stop, and keeps an ignored SIGHUP (*added 2026-10-26*).** An agent that stops itself (Claude Code's Ctrl-Z is `kill(own pid, SIGTSTP)`) stops alone, and the shell,
whose job is the launcher, never got the terminal back. When the agent shares a terminal with the run (the terminal
G1 saves) and the launcher does not ignore `SIGTSTP` (R9a's tier-2 hold, or a launcher started with it ignored, never
follows), the run's `jobstop` worker takes each stop of the agent's main process (`waitid(P_PIDFD, WSTOPPED|WNOHANG)`
on SIGCHLD and every 250 ms, `launch.Child.TakeStop`; it never reaps). If the terminal's foreground group is the
launcher's or the agent's, it puts back the modes saved before the agent ran, keeps the agent's, and raises the same
stop signal on itself (`SIGSTOP` if it ignores that one); the shell sees the job stopped. Continued and in front again
(`fg`), it gives the terminal back to the agent's group if that group was in front (`tcsetpgrp`), puts the agent's
modes back and sends `SIGCONT` to the agent's group; continued in the background (`bg`, `kill -CONT`), it only sends
the `SIGCONT`. A background run and a terminal that is not the launcher's controlling one are left as they were. It
records nothing and decides nothing: no ledger line, no `stop_grace`. Separately, a launcher started with `SIGHUP`
ignored (`nohup`) does not subscribe to it (`launch.Notify`): the hangup starts no `stop_grace`, and the agent
inherits the ignored disposition as it would without tego. `TestIntegrationAStoppedAgentStopsTegoAndResumes` (fg,
bg) and `TestIntegrationAnIgnoredSIGHUPKeepsTheRun`, against the real binary. **Not covered:** a stop while the
launcher is in the background (the agent stays stopped, as before), and `wall`/`stall_after`, which count the time
the job was stopped.

**R10 — `oom`/`pids` are this package's reasons, `limit` is not.** `reason=oom` (from a `memory.events.oom_kill`
increase, read via `cgroup.ReadLimitEvents`) and `reason=pids` (from a `pids.events.max` increase, R11) are decided
here, both exit 137. `reason=limit` (tokens/cost/wall/stall/repeats, exit 124) is decided by
`internal/runtime/limits`, a distinct channel consumer; this package never inspects token/cost fields.

**R11 — pids exhaustion triggers an immediate kill.** Any increase in `pids.events.max` (a refused `fork`/`clone`)
→ `Manager.Kill` + `Result.Reason = "pids"` immediately — a refused fork rarely surfaces as a clean top-level exit,
so it is treated as fatal rather than advisory (mirrors `limits.Watcher`'s treatment of a budget breach). The increase
is measured from the counters as they stood when the run's cgroup was created, before any process was in it, not from
a reading taken when the watcher starts: that is after the ack, and an agent that meets `pids.max` in its first
milliseconds would already be counted in such a baseline and end with its own exit status instead (seen as root in the
KVM guest, 2026-09-22; the same holds for R10's `oom_kill`).

**R12 — Self-sweep is safe with no special-casing.** `Sweep`'s per-run `flock(LOCK_EX|LOCK_NB)` probe returns
`EWOULDBLOCK` for the sweeper's *own* run too, by R1's kernel guarantee — no exclusion logic needed.

**R13 — `Start` never leaks a child.** Any error after `clone3` succeeds but before handshake completion:
`pidfd_send_signal(PidFD, SIGKILL, nil, 0)`, reap via `waitid(P_PIDFD, ...)`, then return the error. The reap
is bounded by the same 10 s as every other reap of the agent (`killTimeout`): SIGKILL takes effect only when a
task leaves uninterruptible sleep, so a child stuck in D state would otherwise hang the launcher on its own
failure path. A child still alive at the bound is reported as `ErrChildNotReaped` joined to the original error,
and its pidfd is closed anyway.

**R14 — Panics are not runtime conditions.** `Run` installs no `recover()`; a worker panic propagates and crashes
the process — matches the "supervisor crash" row in §7; the sweep, not an in-process recover, is the recovery path.

**R15 — Build-lock join, shared from the start.** `acquireBuildLockIn` opens `bpf-<hash>.lock` relative to the
verified `/run/tego` descriptor (`O_RDWR|O_CREAT|O_NOFOLLOW`, `0600`, regular files only — ADR 0034) and takes a
blocking `flock(LOCK_SH)`, held for the whole run. There is no exclusive creator and no downgrade: every launcher,
first or not, does the same thing under its shared hold — creates the pin directories one level at a time (`EEXIST`
is the concurrent case, not a failure), adopts the build's pinned maps, programs and links when every one it needs
is there and compatible, and otherwise loads and pins them itself; a pin a concurrent launcher made first
(`EEXIST`) is adopted, never replaced. The capture object a run with `capture: uprobe` loads into the build is
loaded the same way. A map a concurrent first launcher pins between this one's lookup and its own pin fails
this one's load with `EEXIST`. The load is then made again and opens that pin, at most once more per pinned map
of the object (`bpf.PinAttempts`), since a pin stays until R16's removal. `LOCK_SH` contends only with a
departing launcher's `LOCK_EX` (R16), so the blocking wait is short; a failed `flock` is `ErrBuildLock`. Correctness rests on removal happening only under the
exclusive lock (R16): no launcher holding `LOCK_SH` can see a pin being removed.

**R16 — Build-lock last-out detach.** `lastOut`: `flock(LOCK_EX|LOCK_NB)` on the held `LOCK_SH` fd. Success (no
other `LOCK_SH` outstanding) → last: the lock stays exclusive until `Close`, so a launcher arriving now waits in
R15's `LOCK_SH` instead of adopting pins being removed; the launcher closes each host-wide link's descriptor, unpins
every link, program and map and removes the hash directory's subdirectories and the hash directory
(enforce-cgroup-observe R14). Last-out never unlinks the lock file: unlinking it would let the next launcher lock
a fresh inode while a joiner still held the old one, splitting last-out in two. The one removal is of a build
whose pins are already gone (`removeBuildState` in `statefiles.go`, from `removeStaleState` at a placing `Prepare`
and in `SweepBuilds`, ADR 0026 (6)): it takes `LOCK_EX|LOCK_NB`, creating the lock file when another removal has
already unlinked it, so no file of a build is removed without its lock held
(`TestAGoneBuildWithNoLockFileKeepsAStartingLaunchersSlotTable`); it checks again that the pin directory is gone,
and unlinks the lock last. The split is closed on the taker's side: R15's taker keeps a `LOCK_SH` only once the lock's
name still leads to the file it holds (`hoststate.Dir.Names`) and otherwise opens it again
(`TestABuildLockWhoseNameWasRemovedIsTakenAgain`). `EWOULDBLOCK` → others
remain; this launcher now holds nothing (Linux converts an `flock` by dropping the shared hold first, `flock(2)`),
does not retake it, and closes the fd — so of two launchers leaving together exactly one is last
(enforce-cgroup-observe I10). The pinned `Base` directory `/sys/fs/bpf/tego` is never removed by one build.

**R17 — Two builds coexist by construction.** Each build's fmod_ret programs carry map entries only for cgroups
*its own* launchers started; a hook chain-calls all attached programs, first non-zero return wins, but every
program returns `0` for a cgroup absent from its own map — no explicit version check needed at the hook.

**R18 — Shutdown never aborts early on a step's own error**. If `ledger.Close` itself fails
(disk full, fsync `EIO`, `chain.log` append failure), the shutdown sequence (R8) still proceeds through
`Detach/Close` → `cgroup.Manager.Remove` → socket cleanup → live-index entry: every step runs unconditionally,
and each step's error is logged to `~/.tego/tego.log` (tagged `run=<id>`); aborting shutdown early to "fail
loudly" would instead leak the cgroup, the pins, and the lock, strictly worse than a logged write failure. The
failure is not only logged. A line the ledger refuses during the run (a full disk, a quota, `EIO`) ends the run at
once: reason `error` with the cause in `detail`, the tree killed, then the ordinary shutdown (record-ledger.md §7).
The ledger cuts a partial line back to the last whole one, so the `run_end` still lands where the disk takes it. A
`ledger.Close` that fails reaches the caller as `Result.RecordErr` beside the originally-determined
`Reason`/`ExitCode` (still a `Result`, never a bare `error`, preserving R2), and `tego run` prints which failure it
was and exits 125 (`[ledger]`), whatever the agent's own code, so a record nobody saw fail is never an exit 0 later
swept as `orphaned`.

**R19 — Cgroup limits need no re-application for adopted descendants**. P0 creates exactly
one cgroup per run (`run-<id>.scope`); anything the agent forks or a `PR_SET_CHILD_SUBREAPER`-adopted daemonized
descendant (case 24) stays a member of that same cgroup — cgroup v2 limits apply by hierarchy membership, not by a
per-process copy, so `SetLimits` at step 2 governs the whole subtree for the run's lifetime with no re-application
hook anywhere in this package. A descendant the launcher adopted is also *waited for* when it exits
(`Child.RunReaper`, on SIGCHLD and a timer; only zombies in the run's cgroup other than the main child), because
an unreaped zombie stays charged to `pids.current` and would fill `limits.pids` on a healthy run. Docker's container-parent cgroup (§3) is the one structural exception: pre-created
and owned by the Docker proxy, out of this package's `SetLimits` scope by construction.

**R20 — `Sweep` needs no coordination beyond R12**. `run`, `stop`, and `gc` sweep with zero
external locking or mutual exclusion among themselves — the per-run `flock(LOCK_EX|LOCK_NB)` probe (R12) is the
*entire* serialization mechanism; two sweepers, or a sweeper racing a live launcher, never need a higher-level lock
because the kernel's per-run flock already arbitrates every case (case 10); an index sweep that meets another
sweeper's lock keeps the entry for the next pass.

*Which runs.* `run` and `stop` call `SweepLive`, which sweeps only the runs the ledger root's live index names
(`record-ledger.md` §3), and `gc` alone calls `Sweep` over every run directory (a pass over every run cost each
`tego run` about 73 µs per stored run). The launcher lists its run in `mintRun`'s ledger (`openLedger`: after
`ledger.Open` took the lock, before `run_start`; a run that cannot be listed is refused, 125, before its cgroup
exists) and clears the entry only once the run reads as ended and after its scope is released (R8), so every run
that can be lost is listed whatever instant its launcher died at. A root with no index gets `Sweep`'s full pass.

*Where a lost run's tree is.* A sweep kills a lost run's tree where its launcher made the scope: a root launcher
makes it under the cgroup2 mount root, an unprivileged one under its uid's `user@<uid>.service`. `run_start`'s
`cgroup` field carries the scope's cgroup id, and a scope whose id is another is never touched (`orphanRoots`). For
a run directory a non-root sweeper owns, the sweeper's own root, the mount root and the owner's delegated subtree
are tried. For one it does not own, and for any run directory under a root sweeper, the owner's delegated subtree
is tried (none for a root-owned directory), and the mount root (with, for a root sweeper, the manager's own root)
only when a record root alone writes says root launched that very directory, whoever owns it: a root launcher,
right after `MakeRunDir`, creates `/run/tego/launched/<run id>` (`O_CREAT|O_EXCL|O_NOFOLLOW`, `0600`, in a
directory `0700` root's, under the verified host state directory) holding the run directory's device and inode, and
a sweep trusts it only when the file and its directory are root's and writable by no one else and the device and
inode are the directory's own, so a planted or renamed directory, being another inode, is never matched. A ledger
with no cgroup id never takes a candidate under the mount root without that record; with neither it takes the first
candidate that exists in the other roots. The launcher removes the record after its scope; a sweep that removed a
run's scope removes the record when it names that directory; tmpfs clears the rest at boot, with the scopes. A
record that could not be written is logged and the run still runs, and such a directory (or one that predates
records) is searched for in its owner's subtree alone. (A group member of the withdrawn `1770` host state directory
could take the name `launched` first; since ADR 0042 (3)(b) the directory is root `0700` only, so no one but root
can.) `RunScope`, what `tego stop`'s backstop kill uses, finds the scope the same way
(`TestIntegrationRootSweepLeavesAnotherUsersRootRunAlone`,
`TestOrphanRootsSearchesTheMountRootOnlyForARootLaunchedRun`,
`TestIntegrationRootSweepLeavesAnotherUsersRootRunForARenamedRootOwnedRun`,
`TestOrphanRootsOfARootSweeperNeedARecordForItsOwnRunDirectory`,
`TestIntegrationRootSweepLeavesAnotherUsersRootRunForAPlantedEndedRun`). A kill that is refused, or a tree that
does not empty within the kill timeout, fails the sweep hook, so the run stays lost and the next pass meets it
again; so does an emptied scope whose removal stays `EBUSY` (case 9) and a sweeper with no cgroup manager, which
cannot kill anything. A scope that is gone, or that cannot be read at all, still ends the run.

*An adoption (ADR 0055, amended 2026-10-16).* A lost run that is an adoption (its adopter and reaper both dead) is
never killed and never ended over a scope that still holds it. Before the launched-run search, the sweep hook reads,
as root, the adoption's record in `/run/tego/adopted` (never made by the sweep): when it names this very run
directory (device and inode) and its adopter is gone, the tree is released from the record under the adopted
process's lock as its reaper would, and the hook succeeds (so the sweep writes `run_end orphaned`) only once the scope
is removed. A record of another directory, a live adopter, a process left in the scope, a record that cannot be read,
or, with no record or no root, an `adopt-<id>.scope` with `run_start`'s cgroup id under the mount root or the
manager's root, fails the hook, and the run stays lost (`TestSweepKeepsALostAdoptionWhileItsScopeHolds`,
`TestRootSweepReleasesALostAdoptionBeforeItEndsIt`, `TestRootSweepReleasesOnlyItsOwnDirectorysAdoption`).

*A held lock.* A held lock is liveness only while the process holding it is the launcher. The ledger's sweep asks a
reclaim hook about every run whose lock is held (`ledger.WithReclaimHook`), and the runtime's hook reads the lock
line: when the launcher it names (pid and start time, R22) no longer exists, the run's tree is killed as an
orphan's is, which ends the holder, the hook waits up to the kill timeout for the lock to come free, and the run is
then swept as a lost run. A lock with no launcher line yet, a launcher that is alive, no cgroup manager, or a kill
that fails leaves the run running. A holder outside the run's cgroup would survive the kill; `clone3` is refused so
a process of the run cannot start one there, and `ledger_root` is read-denied to the agent (agent-contract R6a) so it cannot open
the lock file unless the contract makes the ledger readable (the `ledger-readable` warning).

*An ended run still listed.* That is one whose launcher died between `run_end` and clearing the entry, or is still
between them; `SweepLive` does not clear it after one tail read. Under the run's lock, a run with no anchor line
whose chain verifies is anchored at its own last id, in the anchor its launcher would have used, and that is logged
(`record-ledger.md` §3 Live index). The runtime's ended hook (`ledger.WithEndedHook`) then reads the lock line: a
launcher that is alive is left to clear its own entry; one that is gone had its scope found as an orphan's is and
removed, anything left in it killed first, and a tree that stays keeps the entry. What no sweep recovers is the rest
of that launcher's `releaseKernelState`: at tier 2 its `Detach` never ran, so its cgroup links went with its
descriptors (`enforce-cgroup-observe.md` E38), its verdict rows wait for the slot's next `Prepare` scrub (E32), its
`run_set` rows stay (E26), and, if it was the last launcher of its build, the shared pins stay until the next one
detaches.

*Another host's run.* The lock line's pid is a pid of the host that minted the run: a run whose id's host8 is not
this host's (a ledger root shared between machines, case 28) is only locked on this machine, and its launcher may
be alive on its own host. The runtime passes `ledger.WithForeignRun`: such a run is never reclaimed, has nothing
killed, is never ended as lost nor anchored, and its live-index entry stays for its own host to clear; `gc` still
ages out one that reads ended or empty (`TestASweepLeavesAnotherHostsRun`).

**R21 — The build lock lives only in the verified `/run/tego`** (ADR 0034). There is no `mkdir -p` and no per-user
fallback (`$XDG_RUNTIME_DIR/tego`, `/tmp/tego-<uid>` were removed for tiers 2–3). `hoststate.Open` opens
`/run/tego` `O_PATH|O_NOFOLLOW|O_DIRECTORY` and accepts only root `0700`, which a root launcher creates, one
`mkdir`, when it is absent; `/run` is root's, so no one else can create the name first. Anything else (a link,
another owner or mode, the root:`tego` `1770` form ADR 0042 (3)(b) withdrew) fails `Prepare` with `ErrHostState`
and `hoststate.Fix`: `chmod 0700 /run/tego && chgrp root /run/tego`, and remove any tego tmpfiles.d line. Every
file in it is opened relative to that descriptor and refused unless the launcher's effective uid owns it
(`TestRootLauncherRefusesGroupHostState`, `TestOpenFileRefusesAFileAnotherUIDOwns`). *Amended 2026-10-05 (ADR
0042 (3)(b)):* the `1770` form and `packaging/tmpfiles.d/tego.conf` are removed.

**R22 — `tego stop` targets a pid via a held pidfd, not a stat-then-signal pair.** A launcher whose own start time cannot be read never runs: `mintRun` refuses it
(125) before making the run directory, so no lock line a launcher wrote carries a start time of 0, and `OpenStopTargetFor` refuses a line that does (`ErrStale`) instead of skipping the check below. A lock that is held with no lock line yet (the instant between `ledger.Open` and `writeLockInfo`) has no process to
verify: `stop` waits up to 2 s for the line, then exits 125 "still starting" before placing any marker. `ProbeLock` yields `(pid, startBootNS)` from the lock file; `OpenStopTargetFor`
immediately `pidfd_open(pid)`s, re-reads that pid's `BootNS` via the open fd's `/proc/<pid>/stat`, and compares
against `startBootNS` — a mismatch closes the fd and returns `ErrStale` (no signal sent). On a match, `Signal` uses
`pidfd_send_signal` on the *same* fd, so the kernel targets the exact task the boot-time check just verified even
if the pid is reused between the check and the signal — and before returning the target it proves that pid holds *this* run's flock through an exact owner/device/inode kernel row or bounded descriptor proof, or returns `ErrNotLockHolder`: the line is text a user who owns the ledger root can plant, naming any pid and its world-readable start time, and a privileged `stop` or sweep must not signal a process because of it (`TestOpenStopTargetRefusesAPidThatDoesNotHoldTheLock`). `ErrNotLockHolder` is not `ErrStale`, so the sweep never reads it as a dead launcher. A line whose `pid_ns` is not the caller's pid namespace is `ErrNotLockHolder` before any lookup (`OpenStopTargetFor`; `TestOpenStopTargetForRefusesAnotherPidNamespace`): its pid is a number this process cannot interpret, so a live launcher in another namespace is never "not running" and never orphan-killed. `stop` verifies the target first and places its marker only once it holds one, so a refused or stale stop leaves no `stop.request` in a live run (`TestStopLeavesNoMarkerWhenTheLauncherIsNotVerified`). This closes the TOCTOU window a plain `kill(pid, sig)` after a
`/proc` stat would leave open. `ProbeLock` opens `<run>/lock` as the ledger's readers open theirs,
`O_NOFOLLOW|O_NONBLOCK`, and refuses anything but a regular file, so a FIFO or a link planted under the name returns
an error at once instead of hanging `tego stop` and every sweep that probes the run
(`TestProbeLockRefusesWhatIsNoLockFile`).

Ownership proof holds the guarded regular run-lock descriptor while checking kernel evidence.
A global `/proc/locks` positive must be a granted advisory full-file FLOCK for the exact owner PID and inode,
with its hexadecimal device major/minor matching that descriptor's actual `stat` device. Inode alone cannot
identify a file across filesystems (`TestLockHolderProofRejectsOtherFilesystem`). The global table payload is
limited to 16 MiB, with one extra byte read to detect overrun; an overflow or read error discards all global
bytes, including any complete-looking positive prefix, before descriptor proof. A paginated global read can
omit a still-held row, so an absent row, an unavailable table, or a differing printed superblock device proceeds
to per-descriptor proof (`TestLockHolderProofAfterRealProcPaginationOmission`). That proof requires the exact
FLOCK owner and inode, matching regular-file device/inode via `/proc/<pid>/fd/<fd>`, an unchanged repeated
fdinfo lock row, and repeated descriptor-path identity. An inherited descriptor owned by another lock PID,
an unlocked descriptor, or a replaced run-lock path is refused.

Descriptor traversal streams batches of 128 entries, refuses beyond 8,192 scanned entries, and checks a
five-second budget between entries; the budget does not interrupt an individual kernel call. Each fdinfo
payload is limited to 4,096 bytes, with one extra byte read to detect overrun. Unavailable or exhausted proof
returns `ErrNotLockHolder`. The exact-device global path preserves control of a non-dumpable launcher when
its target fdinfo is inaccessible and the global read contains its row (`TestLockHolderProofForNonDumpableLauncher`).
If pagination omits that row while target descriptor inspection is denied, the request is refused for that
observation too; this is unavailable ownership proof, not evidence that the launcher died. If a filesystem's printed
superblock device differs from the actual `stat` device and target descriptor inspection is also denied,
ownership cannot be proved and the request is refused; that refusal does not mean the launcher died.

**R23 — Overhead budgets.** The "under 5%" goal is P0-DESIGN §9's budget table: a whole run under
1% / 3% / 5% of wall time with enforce-only / `record: summary` / `record: full` on `test/workloads/build`, plus
per-path budgets (seccomp fast path under 10 µs, ledger append under 20 µs, ...). Kill test 3
(`test/e2e/kt3-overhead.sh`, the `test/e2e/overhead` harness) measures them per tier and record mode. Conditions:
kill test 3 is not in the nightly VM matrix (`vm-matrix.yml` runs each row through `test/vm/matrix.sh`, which runs kill tests 1, 2, 4, 5, 6 and 7 and runs
3 only with `VM_KT3=1`, since a shared two-vCPU guest is not the quiet machine the budgets are measured on); it is
run by hand on a quiet machine, and the numbers published so far are tier landlock's (P0-DESIGN §9).

**R24 — Ordinary work unbroken (kill test 4).** As FEATURES.md states it: `pip install` +
`pytest`, `npm install` and `go build` under `examples/profiles/base/python-dev` with `record: summary` in every
tier the machine allows, nineteen of twenty runs unbroken, broken meaning a non-zero exit, a wall time over 2×
the median of five runs outside tego, or a `refused` event naming a declared target. Status (test/vm/README.md):
the npm and go kinds pass 20 of 20 at tier landlock on every kernel-matrix row and fail 0 of
20 at tier cgroup on every row, where the tier's fixed per-run cost exceeds 2× a sub-second workload's median.
Condition: R18 is not met at tier cgroup until that fixed cost fits (ADR 0022's lingering build is the named
item; it alone does not close it); the nightly matrix runs kill test 4's npm and go kinds only with
`VM_KT4_TOOLS=1`.

**R25 — Descriptor ownership (ADR 0023, as amended 2026-10-05).** Every descriptor the engine opens has one owner,
a `sys.FD`, from the expression that creates it until its number is closed or handed on:
- **Birth.** `sys.Own` or `sys.OwnSyscall` around the producer's call (its flags carry the producer's CLOEXEC),
  `sys.Adopt` for a number the kernel wrote into memory (a fanotify event's fd, clone3's pidfd), `sys.Inherited` for
  one received at exec (its kind checked, and refused once the process has made any other owner), `sys.Stdio` for
  0–2, which every other constructor refuses. A number another owner holds, or one an API returned, is never wrapped.
- **Lend.** `Borrow(fn)` lends the number for fn under a counted lease; `Hold` lends it for a loop's lifetime and is
  returned by `defer` in the same function or in the goroutine it is handed to. A number never outlives its lease.
  An API that lends across packages returns a `sys.Lender`; a per-event seam returns the concrete `*sys.FD`.
- **Give.** `Release` hands the number to an `*os.File` (ExtraFiles, `net.FileConn`), `ReleaseNumber` to an API that
  takes ownership, and both refuse while a lease is out. `Dup` makes an independent owner.
- **Close.** Once, by whichever holder closes first; every later Close is a no-op. A Close under a lease is
  deferred to the last return, so the number is never reused under a borrower. A strict FD (a lock, a pipe's write
  end, the seccomp listener, a durability file) refuses such a Close with `ErrLeased` instead. `CloseNow` is nil
  only once close(2) has returned. An ordering that depends on the close goes through `OnClosed`, which runs after
  close(2) on whichever path closed the number and never for a released or abandoned FD (fail closed).
- **Abandon.** A number of lost or unknown identity (enforce-landlock I12) is forgotten with `Abandon`, never
  closed; a holder whose FD was abandoned under its lease re-verifies the number's identity before any grant made
  through it (I12's statx check, enforce-plane R16's fill check).
- **No finalizer** closes a descriptor, and an `*os.File` or cilium object that would close one from its own
  cleanup is kept reachable for as long as the number is meant to stay open.
- **Fail closed.** `ErrClosed` (matching EBADF) and `ErrLeased` (EBUSY) are failures on the path that met them: a
  decision path refuses where its mechanism can, a setup path fails Prepare or Start (exit 125, its text pinned by
  the migrating commit), a teardown step reports and keeps its fail-closed state.

Status: the owner type is built (ADR 0023 C1: `internal/platform/sys` fd.go, fd_lease.go, fd_errors.go,
fd_inherited.go; `TestCloseOnceUnderRace`, `TestCloseDeferredUntilLastReturn`, `TestOnClosedRunsAfterCloseOnEveryPath`,
`TestHoldBorrowDupReleaseAfterAbandon`, `TestInheritedSealed`, `TestNoFinalizer`), and so are its helpers (C2:
the pidfd, seccomp listener and ruleset owner forms, `Pipe2`, `Socketpair`, `Accept4`, `ReceiveRights`, `FileDo`,
`DupFile`, `Flock`, `FstatFile`, `CloexecFrom`, `CloseInheritedFrom`, and `CloneIntoCgroup` (C13); internal/bpf `ProgramFD` and `MapFD`;
`testutil.NoFDLeak`), and so is the lint that makes the rule binding (C3: `.golangci.yml`'s ADR 0023 forbidigo rules
and `tools/fdcheck`, run by `scripts/check-fd.sh` in `make lint`, precommit and CI). A package that is not in
`tools/fdcheck/baseline.txt` has no raw close, dup, wrap, `Fd()`, unowned producer or exported bare number, and a
package that is keeps exactly the raw sites the file counts until it migrates; the packages migrate at C5–C19,
of which C12 (hoststate), C13 (runtime/cgroup), C17 (cli) and C10 (ledger) are done. Until a package migrates, §9's "Resource lifetimes"
describes its raw numbers.

**Changes.**
- 2026-10-19, R25 (ADR 0023 C10, ledger; one entry for the steps of the day, superseding their separate entries):
  internal/ledger's descriptors are owners, the run directory and the durability paths' descriptors strict, and
  `ledger.OpenAt` takes a `sys.Lender`. A gc pass's own lookups are `*at()` calls under the root it holds (no
  `os.OpenRoot`, no proc path), and the sweep anchor's ownership reads go under the root `WithBoundWriterOptions`
  lends. A sweep's hooks are lent the run's directory, opened under the held root (the directory the pass locked
  where it holds the run's lock), and the orphan checks (the lock probe, the launcher's lock-holder proof,
  `runStartOf`, `markDir.launched`, `orphanRoots`' owner, the adoption's `sameDirectory`) look the run up under
  it, never by a path; `tego stop`, `ask` and `RunScope` keep their paths. internal/ledger has no raw site left
  and leaves the baseline.
- 2026-10-19, R25 (ADR 0023 C17): internal/cli is migrated: the own log's `~/.tego` is a strict owner (it carries
  the rotation flock), and an appender that gives the log up closes what it held; the package leaves the baseline.
- 2026-10-19, R25 (ADR 0023 C13): internal/runtime/cgroup is migrated: the scope's directory is one `sys.FD` owner
  shared by every copy of a `Cgroup`, control files are opened under its lease (through the path once it is
  closed), the cgroup.events inotify descriptor and the helper scope's directory are owners, and clone3's
  CLONE_INTO_CGROUP number is lent for the clone alone by the new `sys.CloneIntoCgroup`; `launch.Start` takes the
  directory as a `sys.Lender` (the edge rule, A6). The package leaves the baseline; launch's `api` count falls to 1.
- 2026-10-19, R25 (ADR 0023 C12): internal/runtime/hoststate is migrated: the verified host-state directory is a
  `sys.FD` owner, closed once, and a use after its Close is `sys.ErrClosed`; the package leaves the baseline.
- 2026-10-19, R25 (ADR 0023): a close, dup or io_uring trap (or a dup fcntl command) reached
  through a module constant is a site at each call as well as at the constant; a Hold's `defer l.Return()` (or
  its hand-off) and a ReleaseNumber's one taker are the statement after the call's own error check, in its
  block, and a lease is returned by its defer only; a control-message decoder (ParseSocketControlMessage,
  ParseOneSocketControlMessage) or SCM_RIGHTS outside sys is a rights site, and a recvmsg with a control buffer
  sets MSG_CMSG_CLOEXEC; a slice a lent number bounds, and len or cap of it, holds the number, and ProcPath's
  path is a lent number; a package the baseline does not list uses no other package's bare-number API (the
  edge list); no product binary links exempt code under arm64, amd64 or amd64 with cgo. 23 packages
  are listed, with 612 raw sites.
- 2026-10-19, R25 (ADR 0023): the lint type-checks every package under each build the
  project ships and refuses a file none includes; a lent number (a lender's callback parameter, a lease's `Num`) is
  held to a closed list of uses, and `ReleaseNumber`'s number to one taker; a linkname or a function without a Go
  body is a site (opaque). 23 packages are listed, with 604 raw sites: deputy.Pending's `Abandon` is no longer
  counted as sys.FD's, and internal/bpf's linkname is.
- 2026-10-17, R25 (ADR 0023 C3): the lint and the per-package ratchet are built; the rule binds every package
  `tools/fdcheck/baseline.txt` does not list (23 packages are listed, with 602 raw sites).
- 2026-10-05, R25 (ADR 0023 C2): the owner forms and helpers are built; no caller moved.
- 2026-10-05, R25 (ADR 0023 C1): the owner type is built; the rule binds no package yet.
- 2026-10-05, R25 (ADR 0023 accepted with its 2026-10-05 note): the descriptor ownership rule, not yet built.
- 2026-09-30, R4a: the privileged drop's supplementary groups are `TargetGID` alone,
  not the invoking user's list; the rule did not say the list was replaced.
- 2026-09-22, R9: the grace timer starts once and is never restarted or extended; it said "or restart, taking the
  max remaining", which the handler never did.
- 2026-11-01, R4 (ADR 0128): a `setuid: true` run under a `net:` section drops `CAP_NET_ADMIN` from the bounding set first.
- 2026-09-24, R4 (ADR 0033): `no_new_privs` runs after the privileged drop; it was skipped.
  A contract's `setuid: true` keeps the skip; tiers 2–3 refuse `bpf` and module/kexec calls whatever the opt-in.
- 2026-09-29, step 13, R8, R18: the run lock is released inside `ledger.Close`, before `Detach` and the scope's removal; the live-index entry covers the gap.
- 2026-09-24, R8: each source's `Stop` is bounded at 30 s (`source-stop-timeout` gap).
- 2026-09-24, R8: the handle's release waits for a `Stop` left running.
- 2026-09-24, R8: the live-index entry is cleared only after the scope is released.
- 2026-09-24, R8: one events-channel lane per class of producer.
- 2026-09-24, R8: a worker that failed ends the run `reason=error` even after the
  agent's exit won the race.
- 2026-09-24, R18: a ledger line refused mid-run ends the run; a failed `Close` exits 125 `[ledger]` (§7 row too).
- 2026-09-29, R19: the launcher reaps adopted orphans; they stayed zombies charged to `pids.current`.
- 2026-09-24, R20: `run`/`stop` sweep only the live index (`SweepLive`).
- 2026-09-24, R20: a lost run's scope is found where its launcher made it, by
  cgroup id; a failed kill keeps the run lost.
- 2026-09-24, R20: the mount root is searched only on root's
  `/run/tego/launched` record for that directory; planted and renamed directories killed another user's run.
- 2026-09-24, R20: a lock held by a non-launcher after its launcher died is reclaimed.
- 2026-09-24, R20: an ended run still listed is
  anchored and its scope removed by the ended hook; another host's run is left alone entirely.
- 2026-09-29, R20, R22: an emptied scope that stays busy, and a sweeper with no cgroup manager, keep the run lost;
  a launcher whose own start time is unreadable is refused (125) before its run directory, since a lock line with
  start time 0 turns off the pid-reuse check.
- 2026-09-30, R9a, R22: R9a's stale "call `HoldJobControl` before `prepareEnforcement`"
  to-do removed (the marks go down at `Arm`, after `Start`'s hold); `stop` on a held lock with no lock line waits,
  then fails before placing a stop marker. A worker that fails before `run_start` is named in `Run`'s error.
- 2026-09-30, R22, §7: `OpenStopTarget` takes the run directory, refuses start time 0 and a pid that does not hold the run's flock; the agent is not acked once the worker group has failed (`prepare`'s last step, and again before `Ack`).
- 2026-09-30, R22: the lock line carries the launcher's pid-namespace inode and a foreign one is `ErrNotLockHolder`, not `ErrStale`; `stop` opens and verifies the target before placing the stop marker.
- 2026-09-24, R22: `ProbeLock` opens `O_NOFOLLOW|O_NONBLOCK`, regular files only.
- 2026-09-24, R15, R16: the protocol as `pins.go` runs it — `LOCK_SH` at once, no downgrade, a
  not-last launcher holds nothing, the lock file never unlinked; they described take-exclusive-then-downgrade and
  unlinking the lock.
- 2026-09-24, R21 (ADR 0034): the lock lives only in the verified `/run/tego`; the rule said
  `mkdir -p` of it or of `$XDG_RUNTIME_DIR/tego`, which ADR 0034 removed.
- 2026-09-24, R23, R24: written with their budgets, status and conditions.
- 2026-09-24 (rulecheck): R6a named with the document that defines it; wording otherwise unchanged.
- 2026-09-28, R15: a map pinned by a concurrent first launcher between lookup and pin is adopted on a retried
  load; the load failed, and the run was refused (`ErrProgramLoad`, or `[capture-unavailable]` for the capture object).
- 2026-09-29, R23: vm-matrix runs kill tests 1, 2, 4, 6 and 7 on each row through matrix.sh, not only 1 and 4.
- 2026-09-29, R16: a gone build's lock is unlinked by its exclusive holder, with R15's taker
  re-opening a lock whose name was removed; the rule said the lock was never unlinked (ADR 0034 (3)'s note).
- 2026-09-30, R9: a failed `cgroup.kill` is retried by the group's error path, not by a later signal; the rule said the
  next trigger retried it, which no signal reaches once the worker has returned the error.
- 2026-09-30, R16: a removal that finds a gone build's lock already unlinked creates and holds it
  before removing the rest; it removed them holding nothing, and could unlink a starting launcher's slot table.
- 2026-10-05, R23 (KT5): vm-matrix also runs kill test 5 (`test/e2e/kt5-ask.sh`: what an
  untouched `fs.ask` and `net.ask` entry costs) on each row, through matrix.sh, as kill test 4 is: every tier the boot
  allows, and alone at tier bpflsm on the second boot.
- 2026-10-26, R9b: added. A launcher sharing a terminal with its agent stops when the agent
  stops itself and resumes it when continued; a `SIGHUP` inherited as ignored stays ignored.

## 6. Edge cases

1. **Two runs, same instant**: distinct `RunID`s (host+time+rand) → distinct cgroups/locks; a random-suffix
   collision (astronomically unlikely) hits `mkdir` `EEXIST`: a fresh id is minted, up to 3 retries
   (identity-config.md R2b), then exit 125; a taken path is never overwritten.
2. **`clone3` `ENOSPC`** (max PIDs/cgroup depth): exit 125 pre-`run_start`; the already-created cgroup is removed by
   the same error-path `defer` that fired for the ledger dir.
3. **Child dies before writing the fd number** (OOM-killed externally, `/proc/self/exe` deleted mid-run): parent's
   `read` returns `EOF` → `ErrChildDied` → exit 125. A stage that dies after writing it and before the parent's
   `pidfd_getfd` makes that call fail with `ESRCH` (or `EBADF` from a stage the pidfd reports exited), and that is
   `ErrChildDied` too. The abort that reaps it appends the child's exit status or
   killing signal to the error, since a stage killed by a signal (OOM, an outer seccomp profile's `SIGSYS`) prints
   nothing else. The stage is a Go process cloned into the run cgroup after `pids.max` is written, so its runtime's
   threads count against `limits.pids`: a cap below what it needs to start (about 6 tasks; the schema accepts 1)
   kills it with the Go runtime's `failed to create new OS thread`, whose own text points at `ulimit -u`. When the
   stage dies before its handoff and the run cgroup's `pids.events` `max` has risen above `createCgroup`'s
   baseline, the error is `runtime.ErrStagePidsCap` (still wrapping `ErrChildDied`), which names `limits.pids` as
   the cause. The run still fails closed before `run_start`; the agent never starts.
4. **Child-side `landlock_restrict_self` `EPERM`** (structurally shouldn't happen given ordering, defense in
   depth): negative error code over pipe A → `ErrChildLandlock`, not a bare `ErrChildDied` — better diagnostics.
   **Its flags** (`ChildSpec.LandlockFlags`): the child stage drops, before the call, every flag its kernel's
   Landlock ABI does not know (`launch.LandlockFlags`: the three `LOG_*` flags need ABI 7, `NO_NEW_PRIVS` ABI 11;
   `TSYNC` is never passed, enforce-landlock R13), and after the call retries an `EINVAL` once without
   `NO_NEW_PRIVS` only, since step 4's prctl already set that bit (R18's ABI<11 fallback). A flag the kernel knows
   and still refuses fails the stage here; the retry never drops an audit flag (`LOG_NEW_EXEC_ON`) the kernel
   knows along with `NO_NEW_PRIVS`. Below ABI 7 the flag costs the audit record, never the confinement
   (`TestLandlockAuditFlagReachesTheKernel`: as root on 6.17 booted with `audit=1` the agent's refused write after
   the stage's `execve` is an `AUDIT_LANDLOCK_ACCESS` record naming `blockers=fs.make_reg` with the flag and none
   without it). The launcher sets it when the machine config opts in (`landlock.audit: new-exec`, spec/config/v0;
   off by default) and the run applies a Landlock ruleset (every tier but an observe run): `internal/runtime`'s
   `childSpec` passes `LOG_NEW_EXEC_ON` in `ChildSpec.LandlockFlags`, reads the kernel's ABI as the stage will
   (`launch.LandlockFlags`' second result), and when the ABI drops the flag writes `gap what=record
   why=landlock-audit-unavailable` once after `run_start`; an ABI it cannot read asks for nothing and writes the
   same gap. When the ABI keeps the flag and the kernel's audit is known to be off at run start, it writes `gap
   what=record why=kernel-audit-off` instead, since Landlock then drops every record, and when the run could not
   read the audit state (`AUDIT_GET` refused it: an unprivileged run among others), `gap what=record
   why=kernel-audit-unknown`, since a kernel that nothing turned audit on in drops every record too and the run
   cannot tell it from one that logs; only an audit read as on writes no gap (enforce-landlock §4 says how the
   state is read and when a run cannot read it; `TestLandlockAuditOptIn`). enforce-landlock §4 `RestrictSelf` and
   R18 admit the flag. The rest of the item is not built, each part with its condition. `LANDLOCK_ADD_RULE_QUIET`
   on `landlock_add_rule` (ABI 10, Linux 7.2): enforce-landlock R20 keeps that call's flags at 0 because quieting a
   rule mutes the very records the opt-in exists to produce, so it is set only once a contract or machine key names
   the refusals an operator wants unlogged (none does); then the flag, which
   `golang.org/x/sys` defines from v0.49, and a guest kernel with ABI
   10: 7.2 is released (Fedora's koji carries 7.2.7) and `test/vm`'s `fedora-7.2` row (2026-10-05) is that
   guest, so the flag is verified in it before any launcher sets it. The
   kernel's own denial tracepoints (`landlock_deny_access_*`, 7.3): a released 7.3 kernel for the guest (koji
   carries 7.3.0-rc4 on 2026-09-22) and the owner of `trace_proc.bpf.c` and the kernel recorder attaching them.
   Their root fallback from 5.5, an `fexit/security_file_open` program that sees the LSMs' combined answer to an
   open: it needs `trace_proc.bpf.c` and the kernel recorder to add it, with an event that carries the answer and
   an additive record field for it (record-ledger.md).
5. **`pidfd_getfd` `EPERM`, non-dumpable child** (dumpable-set/capset ordering inverted): `capset` resets dumpable
   to 0 as a side effect, so `PR_SET_DUMPABLE=1` must run *after* the capability drop — `ErrNotifyFDUnavailable`,
   exit 125; guarded by an integration assertion on `/proc/<child>/status` at the exact `pidfd_getfd` call site.
6. **`seccomp(NEW_LISTENER)` `EBUSY`** (a filter chain already has a listener — only relevant if `ChildSpec` were
   misused on an already-filtered thread): programming error, fails loudly in tests, never retried in production.
7. **`NEW_LISTENER` + `TSYNC` → `EINVAL`**: this package never sets `TSYNC` (single-locked-thread design makes it
   unnecessary) — a constant flag choice, not a runtime check.
8. **`execve` of the agent fails** (`ENOENT`/`EACCES`): the notification is still answered `CONTINUE` (P0's minimal
   loop, R7/step 10); the kernel fails the real `execve`; observed only as an ordinary `wait4` exit
   (`reason=exec-failed`, exit 126/127) — never special-cased here.
9. **Orphan cgroup `EBUSY` on `rmdir`** (task in uninterruptible sleep survived `SIGKILL`): 5 retries over 1s, then
   log and defer to the next sweep pass; not re-`Kill`ed (already `SIGKILL`ed).
10. **Two concurrent sweepers** race the same orphan: only one wins `flock(LOCK_EX|LOCK_NB)` (R12); the loser's
    probe reads as "not orphaned" and moves on — no double-kill, no double `run_end`.
11. **`tego stop`** targets an already-free lock (launcher exited, or already swept): `stop` reports "not running",
    sends no signal, and does **not** fall back to a full sweep (keeps its blast radius to the named run).
12. **`stop.request` created but the launcher is `kill -9`'d first**: the marker is orphaned but harmless (no
    schema meaning); `gc` removes it with the whole run directory at retention.
13. **`SIGKILL` sent directly to the launcher**: undeliverable to a handler; the child is now orphaned mid-run with
    no `run_end`. At tiers `landlock` and `observe` it is exactly the sweep's target; the next `run`/`stop`/`gc`
    appends `reason=orphaned`, unless the run holds a DNS broker endpoint: its reaper (step 3) then ends it at
    once as below, with no kernel state to purge and no build duties, and afterwards removes the endpoint's
    socket and directory, each checked against the identity it was handed and a replaced one left alone
    (`cleanupReapDNS`; `TestDNSBrokerOrphanCleanupOnRealKernel`, `TestDNSReaperPreservesForeignSocketAndDirectory`).
    No sweep removes that endpoint (network-controls R8), so a reaper killed with its launcher leaves it.
    At tiers `cgroup` and `bpflsm` the run's reaper (step 3, ADR 0020) wakes on the launcher's pidfd,
    takes the run's lock through the run directory's descriptor (`ledger.OpenAt`, which makes nothing there, `ledger.WithExistingFiles`, so a run already being removed stays so), and ends the run at once:
    `cgroup.kill` on the run's own scope (its path and cgroup id both the launcher's), repeated while it stays
    populated, `run_end reason=orphaned`, the scope's removal, and only then the purge of the run's pinned links
    and rows (enforce-cgroup-observe E38) and the build's last-out duties (ADR 0022). A ledger that already has
    `run_end` with the scope gone means the launcher tore the run down itself, and the reaper exits. A reaper
    killed with its launcher leaves the run to the next sweep, which purges the same kernel state once it has
    removed the scope, and only for a run root's own launch record names (run_start is its owner's to write)
    (`TestPurgeOrphanNeedsRootsRecord`, `TestTier2ReaperEndsAnOrphanOnlyOnceItsTreeIsGone`,
    `TestTier2ConcurrentReapersEndAnOrphanOnce`, `TestTier2AReapersDeathLeavesTheRunToTheSweep`).
14. **`SIGSTOP` on the launcher**: cgroup-events polling stops; the agent keeps running until `SIGCONT` or natural
    completion is observed. At tier `landlock` it stays enforced by Landlock and the seccomp filter's errno arms,
    which are kernel-resident and launcher-independent (I7), while every notified syscall waits for the stopped
    supervisor. At tier `cgroup` the fanotify half of the file and exec rules is neither: the stopped launcher
    answers nothing, and every open and exec on its marked mounts — the whole host's, not only the agent's — waits
    until it continues (enforce-cgroup-observe.md E40). The job-control stops (`SIGTSTP`, `SIGTTIN`, `SIGTTOU`) do
    not stop a tier-2 launcher (R9a); `SIGSTOP`, a debugger and the freezer still do, and a tier-2 launcher is to
    be ended, never stopped.
15. **Launcher pid reuse** (crash, then the OS reissues the pid before sweep runs): `tego stop` re-verifies
    `/proc/<pid>/stat` field 22 against the lock file's `start_boot_ns` through a held `pidfd`, and signals through
    that same fd rather than by raw pid (R22) — a mismatch means "not running" and no fd is ever signaled; a bare
    stat-then-`kill(pid,...)` sequence would still leave a narrow reuse window
    between the check and the signal, which R22's pidfd-held approach removes (tested explicitly, case 29).
16. **Symlink at the run-directory path** (never legitimately pre-exists): treated as `EEXIST`-equivalent
    corruption like case 1 — refused, exit 125, never followed.
17. **Non-ASCII agent name/paths**: `Command`/`Env`/`Dir` pass through as raw bytes unmodified, UTF-8 or not:
    the spec pipe carries them as base64 byte strings, never as JSON strings, which would turn an invalid byte into
    U+FFFD before `execve`/`chdir` (`TestWireKeepsNonUTF8Bytes`, `TestNonUTF8BytesReachExecve`); the cgroup path
    segment uses `AgentID`, already regex-constrained to `[a-z0-9-]{1,40}` upstream, so no non-ASCII ever reaches a
    cgroup path.
18. **`Command`/`Env` near `ARG_MAX`** (~2MiB): `execve` returns `E2BIG`, handled identically to case 8 (an ordinary
    post-ack `execve` failure, not a preparatory-step error).
19. **Host clock stepped backward** mid-run: `record.Event.TS` may appear to move backward, but `MonoNS`
    (`CLOCK_MONOTONIC`) and `stop_grace` timers (Go's monotonic reading) are unaffected; `start_boot_ns` is
    `CLOCK_BOOTTIME`-relative throughout, immune to wall-clock steps.
20. **`clone3` refused or missing** (kernel below the 6.1 floor, *or* an outer seccomp profile filtering
    `clone3` on a perfectly modern kernel): in normal operation
    `doctor`/`enforce.Select` already refused every tier before `runtime.Run` was ever invoked (exit 125
    [tier-unavailable], in `cli.run` — see R2), so this package should never observe the kernel-age failure in
    practice; if `clone3` still returns `EINVAL`/`ENOSYS`/`EPERM` at the first call (a `doctor` false-positive, or a
    kernel downgraded between `doctor` and `run`), it is this package's own pre-`run_start` failure and is exit 125
    like any other `Start` error — never 211, which is not a code this package produces.
    `EPERM`/`ENOSYS` are **not** evidence of kernel age: a container runtime's default seccomp profile answers an
    unlisted `clone3` with `EPERM` (moby#42680 — glibc 2.34+ treats that as fatal instead of falling back to
    `clone(2)`, which broke `curl` and `docker build` on Fedora 35; runtimes since answer `ENOSYS` instead), and
    `SystemCallFilter=` on the enclosing systemd unit does the same through `SystemCallErrorNumber=` (`EPERM` by the
    documented convention). `Start` therefore reads its own `/proc/self/status` `Seccomp:` mode on exactly those two
    errnos and names only the cause it can prove: mode 2 means a filter is in force and the kernel version is not the
    problem; mode 0 with `ENOSYS` means the kernel genuinely lacks `clone3` (5.3)/`CLONE_INTO_CGROUP` (5.7); mode 0
    with `EPERM` means neither, since a cgroup-delegation refusal is `EACCES`, never `EPERM` (measured on 6.17).
    **Accepted limitation**: `doctor` infers `clone3` from `uname` and never calls it, so a container whose profile
    blocks `clone3` passes `doctor` and fails at `run` — closing that needs a live `clone3(CLONE_INTO_CGROUP)` probe
    in `doctor`'s scratch cgroup, outside this package. No fork+`cgroup.procs`-move fallback either way (would reopen
    the exact TOCTOU window `CLONE_INTO_CGROUP` closes).
21. **Upgrade between runs**: old and new binaries' launchers run concurrently, distinct `RunID`s, distinct lock
    files; `tego stop` from either binary works on either run's lock/marker unchanged (both are frozen contracts).
22. **Build-lock file deleted out-of-band** (`rm -f /run/tego/*`, root only: the directory is root `0700`, ADR
    0042 (3)(b)): the next launcher just `O_CREAT`s a fresh, unlocked file, sees the pin dir already populated, and
    joins via `LOCK_SH` (R15); currently
    running launchers keep their lock on the now-unlinked-but-open inode (Unix semantics, no disruption) but a
    *new* lock-file generation now has a disconnected `LOCK_SH` set — the pins can leak past the true last-out.
    Accepted operator-interference gap, surfaced as a `doctor` finding, not auto-healed.
23. **`memory.high` set above `memory.max`** (should be prevented upstream): the kernel accepts the write anyway
    (no cross-field validation at write time; `memory.max` triggers OOM first, making `memory.high` moot) — this
    package writes whatever `Limits` it receives.
24. **Daemonized descendant outlives the agent's main process**: `PR_SET_CHILD_SUBREAPER` re-parents it to the
    launcher (not PID 1), keeping it inside the cgroup and the Yama descendant set; `cgroup.events.populated` stays
    `1` and the wait in step 12 genuinely blocks on the whole tree — intended, not a bug (see also R19).
    *Amended 2026-10-26:* only for a contract with `keep_descendants: true` (a main that is a launcher
    daemonizing on purpose). Otherwise, once the main process is reaped, what is left in the run cgroup (the open
    deputy aside) gets `stop_grace` to exit on its own; then step 12 writes `cgroup.kill`, run_end's `detail` names
    the processes the kill ended (`the main process exited; after stop_grace 10s the kill ended 2 processes: 4711
    sleep, 4713 sleep`, the first eight by pid and name), and the run ends with the main process's own reason and
    exit code, never 137 (`runtime.endWithMain`; `TestAwaitExitEndsWhatTheMainProcessLeftRunning`,
    `TestIntegrationARunEndsWithItsMainProcess`, `TestIntegrationKeepDescendantsWaitsForTheTree`). Before, a crashed
    agent that had left a `setsid` child or a disowned background job behind kept `tego run` alive as long as that
    process lived, so a unit with `Restart=` never saw the crash and the exit code was lost to a later `tego stop`.
    The descendants get no SIGTERM first: a child that needs a clean stop is the main process's to wait for. Not
    tested at the root tiers (the same step 12 code; KVM root-suite rows to add).
25. **`privileged: true` target is itself setuid**: Landlock's domain (in the cred) and the seccomp filter (on the
    task) both survive `setresuid`/`execve`, so the setuid binary still runs Landlocked and notified; this
    package's only obligation is R4's ordering.
26. **`ctx` cancelled mid-handshake** (before `execve`): shutdown (R8) checks each resource's "was this actually
    acquired" flag independently rather than assuming a fixed prefix completed, so a cancel at any point unwinds
    only what was built, in reverse order, with no double-close and no attempted removal of a never-created cgroup.
    The tier's kernel recorder is one of those resources: built in step 3 once the handle names its build, it holds
    the pinned ring buffer, its reader and epoll, the lost counter and the run set, and unwind stops it, once, even
    before the sources started (`TestRunUnwindStopsTheKernelRecorder`). Unwind releases the ledger with
    `Writer.Abandon`, which writes nothing, never `Close`: a launcher killed before the run directory's removal, or a
    removal that failed, leaves an empty run, which retention removes and no sweep mistakes for a run, not one that
    reads as ended with no `run_start` (`TestRunUnwindWritesNoRunEnd`).
27. **Huge `env`** (large `env.pass`/`env.set`): bounded by `ARG_MAX` like case 18; this package passes whatever
    final `[]string` it receives unchanged.
28. **`ledger_root` on a filesystem with broken/advisory `flock`** (some network filesystems): out of scope for
    correctness; local disk is the assumed convention (`spec/config/v0`); no filesystem-type detection here.
    A ledger root shared between machines is not supported, but a sweep never acts on another host's run: a run
    whose id's host8 is not this host's is never reclaimed (its lock line names a pid of that host), nothing of it
    is killed, a lost one is not ended and an ended one is not anchored (R20).
29. **Pid-reuse fuzz/integration case** (canonical test for case 15/R22): fork a process, note pid+start time, kill
    and reap it, spin until the pid allocator wraps and reissues the pid to an unrelated process, then assert
    `OpenStopTargetFor` detects the start-time mismatch via the held pidfd and sends nothing.
30. **`Limits.Pids == 0`** (contract omits `pids:`): writes the literal `"max"`, never `"0"` — the Go zero value
    must be mapped explicitly, or the run's own first process would be refused.

    **The absent case only** (resolved 2026-09-22). A `ResolvedLimits` that carried the number alone
    could not tell this case from `pids: 0` written on purpose, and mapping both to `"max"` turned the tightest
    cap an operator can express into no cap at all — the inverse of what they asked for, and reported to them as
    a kept ceiling. This edge case was always about the *omitted* key, as its own parenthetical says; it never
    claimed a written 0 means unlimited. `ResolvedLimits.Set` now carries which dimensions were asked for
    (`cgroup.Limits` mirrors it in `MemoryMaxSet`/`MemoryHighSet`/`PidsMaxSet`), so both readings hold at once:
    absent still writes nothing and inherits the kernel's `"max"`, while an explicit 0 is written as `"0"`. That
    agrees with `limits-check-doctor-cli.md` E16 ("an explicit 0 is a hard budget, 'unlimited' is expressed by
    omitting the field entirely"), which is the rule for every limit dimension and not only the budget ones:
    a ceiling language in which the smallest number means "no ceiling" has a fail-open trapdoor at exactly the
    value an operator reaches for when they want the most restriction. The consequence case 30 names is real and
    intended under the new arm: `pids.max` of `"0"` refuses the run's own first process, and `memory.max` of
    `"0"` gets it OOM-killed at once. A machine that grants an agent zero processes or zero bytes cannot host a
    run, and failing to start is the correct reading of that instruction. `cpu.weight` is the one field excluded,
    because its kernel range starts at 1: a 0 there is not a tighter share but an invalid value. It never
    reaches `SetLimits`: the contract schema allows only 1..10000, and the machine config refuses a
    `limits.cpu_weight` outside the same range at parse time, where the operator wrote it (a 0 would
    otherwise resolve as a budget that `limitFiles` skips, and anything above 10000 would be `EINVAL` at
    every run's startup).
31. **Delegated subtree missing a controller** (`pids` or `cpu` never added to the parent's
    `cgroup.subtree_control` — a common `systemd --user`/manual-delegation gap): the
    corresponding `SetLimits` control file (`pids.max`, `cpu.max`, ...) does not exist, so the `write(2)` fails
    `ENOENT`, not `EINVAL`; treated as its own fatal-at-startup case (exit 125) naming the missing controller and
    the delegation fix, distinct from a bad-value `EINVAL` (see `SetLimits` in §4). `Create` writes each of
    `+cpu`, `+memory`, `+pids` to its two slices' `cgroup.subtree_control` on its own; a refused write (a slice
    holding tasks, `EBUSY`; a read-only parent, `EACCES`) does not fail `Create`, and the error, naming the
    controller and the slice, is carried into that controller's missing-controller error as its cause.
32. **Pid-reuse landing exactly between a stat check and a signal call**: the residual
    window R22 exists to close — see R22 and the revised case 15/29; a plain "read `/proc/<pid>/stat`, then
    `kill(pid, sig)`" sequence is not atomic and is never used by this package for that reason.
33. **Partial `SetLimits` failure**: `cpu.max`/`cpu.weight`/`memory.max`/`memory.high`/
    `pids.max` are five separate `write(2)` calls; if an early one succeeds and a later one fails (`EINVAL` or
    `ENOENT`, case 31), the cgroup briefly holds a mix of applied and default limits before `Run`'s error path
    tears it down via `Manager.Remove` — the run never starts with those limits live, and the cgroup path is never
    reused (`Create`'s `ErrCgroupExists` guard), so a caller never observes a half-configured cgroup as belonging
    to a subsequent run.
34. **Build-lock path replaced, not merely deleted, out-of-band**: an operator or
    packaging step writes a *new* inode at the same path while a still-running first-generation launcher holds
    `LOCK_SH`/`LOCK_EX` on the old, now-unlinked inode — a second concurrent launcher can win `LOCK_EX` on the new
    inode and race its own `mkdir -p`/pin-attach against the still-live generation's identically-named `bpf_hash`
    pin directory. Unlike case 22 (pure `rm -f`, no new inode), this can produce two unsynchronized "first"
    attachers for the same hash. Same accepted-gap treatment as case 22: operator interference, a `doctor` finding,
    not auto-healed.
35. **Host clock stepped backward at `NewRunID` generation time** (distinct from case 19's mid-run `TS` behavior): a wall-clock step could in principle produce a time-derived `RunID` component that
    collides with, or sorts before, a very recently issued (not yet `gc`'d) run id. No special handling is needed
    beyond case 1's existing `mkdir` `EEXIST` guard — `NewRunID` is never trusted for uniqueness on its own, only
    the directory-creation race is.
36. **Root launcher with no `SUDO_UID`** (`tego run` from a root systemd unit, a root cron job, `su -c`, or a
    root container entrypoint; also `sudo` with a mangled `SUDO_UID`, which E8 maps back to the real uid 0): there is no unprivileged account to drop to, so R4a refuses the run with exit 125
    before `clone3` — never "drops" the agent to uid 0. `sudo tego run` is unaffected: it sets
    `SUDO_UID`/`SUDO_GID`. *Amended 2026-10-05 (ADR 0042):* the file-capability copy is no longer a privileged path;
    it is refused at start (`[privileged-path-unsupported]`, (3)(a)). `SUDO_UID` is read only by uid 0 of the
    initial user namespace, so under `unshare -r` (uid 0 of a child namespace, any `SUDO_UID`) the run is refused
    here too (`TestUnshareRootIsNotRoot`). The fix for a root unit or cron job is `--run-as <user>` (ADR 0042
    (2)(b), not built yet).
37. **`ledger_root` is `~/`-relative and the passwd database names no home** (`identity-config.md` E9:
    containerized or directory-backed uid with no local entry, which `CGO_ENABLED=0` makes any LDAP/SSSD host): `runtime.LedgerRoot` — the resolver `run`, `stop`, `status` and `gc` share —
    expands the `~` from `$HOME` only when the process is **not** `AT_SECURE`. Under `AT_SECURE` (the
    file-capability copy), or when `/proc/self/auxv` cannot be read at all, it returns an error instead:
    `spec/config/v0`'s Trust section and `identity-config.md` R21 ignore `$HOME` in exactly that case, and this
    resolver decides where the capability-bearing launcher creates the run directory, writes the hash-chained
    ledger, and where `gc` later deletes. The fix is an absolute `ledger_root`, which never reaches this path.
    The chain anchor follows the same rule (`runtime.AnchorPath` over `ledger.AnchorPath`, the rule the dashboard
    names its anchor by too, `record-ledger.md` §3): an account with no
    home — no passwd entry, or a passwd home that does not exist — anchors in the `chain.log` beside its ledger
    root, so an absolute `ledger_root` is the fix for the anchor too, and `ErrAnchorHome` is reached only under
    exactly this case's condition: an absolute `ledger_root` needs no home, so the file-capability copy on an
    LDAP/SSSD host can always be configured to run, and a passwd home that does not exist (`/nonexistent`) is never
    created by root. An account whose home exists but cannot hold `~/.tego` (read-only, another owner's) is
    refused by the anchor probe (§7) before the run directory exists; its fix is a home it can write, as for
    `~/.tego/tego.log`. Whenever a file is named at all, nothing but the passwd entry, the home's existence and
    `ledger_root` chooses it, so the file-capability launcher, the plain binary and `events --verify` name the same
    file for one account. The one difference is this case's own condition: with no passwd home and a `~/`
    `ledger_root`, the plain binary expands the ledger root from `$HOME` and anchors beside it, while the
    `AT_SECURE` copy names no file and refuses (`ErrAnchorHome`); this is the one case where the choice depends on
    `AT_SECURE` (`runtime.AnchorPath` and its test).
38. **Privileged launcher's cgroups live directly under the cgroup v2 root, against systemd's delegation
    contract**: with `os.Geteuid()==0`, `cgroup.Detect` roots the manager at
    `/sys/fs/cgroup` itself (§2's "`/sys/fs/cgroup/...` (priv/`tegod`)"), so `Create` `mkdir`s `tego.slice/` as a
    *top-level* cgroup. On a systemd host that is forbidden: "Never create your own cgroups below arbitrary
    cgroups systemd manages, i.e cgroups you haven't set `Delegate=` in. Specifically: don't create your own
    cgroups below the root cgroup", and "each cgroup only has a single writer"
    ([systemd.io/CGROUP_DELEGATION](https://systemd.io/CGROUP_DELEGATION/)). `Delegate=` — systemd's sanctioned way
    to hand a subtree to another manager — "is available on scope and service units only. It's expressly not
    available on slice units", so no drop-in makes `tego.slice` legitimate where it sits. P0 keeps the `mkdir`
    and accepts the consequences, which are recorded here rather than left silent:
    (a) *the root's controller set becomes partly Tego's*: the kernel refuses `-<ctl>` in a cgroup's
    `cgroup.subtree_control` while a child has that controller enabled (verified on 6.17 — `echo -pids` into a
    parent whose child has `+pids` fails `EBUSY`), and `tego.slice` keeps `+cpu +memory +pids` for the life of the
    boot (case 40), so systemd can no longer disable those at the root while any Tego subtree exists;
    (b) *nothing reaps it*: the directory has no unit behind it, so `systemd-cgls` shows a slice-named cgroup no
    unit owns, and a `daemon-reload`, a systemd upgrade or a `systemctl` cleanup neither knows nor preserves it;
    (c) *a removal from outside fails network enforcement open*: `enforce-cgroup-observe.md` E26 calls an outside
    `rmdir` "a self-inflicted, undefended P0 case", which is the right verdict for an operator but not for the
    other legitimate writer of that subtree.
    The sanctioned fix is a launcher-level decision, not this package's: obtaining the subtree the way systemd
    expects — `StartTransientUnit` with `Delegate=yes` over D-Bus (runc's systemd driver's approach), or running
    `tegod` from a unit with `Delegate=yes` and treating *that* cgroup as the root exactly as the unprivileged
    path treats `user@<uid>.service` — needs a D-Bus client this repo does not have (§11). Unprivileged runs are
    unaffected: they already use the delegated `user@<uid>.service` subtree, and `Detect`'s `ErrNotDelegated`
    refusal for an undelegated subtree names the `Delegate=` fix there. Rooting at the mount does not excuse the
    mount from case 39: the privileged branch asks the same agreement question before it roots anywhere.
39. **`/proc/self/cgroup` spliced onto a mount that disagrees with it**: the path in
    `/proc/<pid>/cgroup` is relative to the *reading* process's cgroup namespace root ("the pathname shown in the
    third field of each record will be relative to the reading process's root directory", `cgroup_namespaces(7)`),
    while `Detect` joins it onto the fixed `/sys/fs/cgroup`. In a `cgroupns=private` container whose
    `/sys/fs/cgroup` is the host's tree rather than the namespace's, that splice names a real, writable, *different*
    subtree, and neither existing guard notices: the statfs magic passes for any cgroup2 mount and `W_OK` on
    `cgroup.procs` passes for any writable one. Agreement is a property of the *mount*, not of one candidate: a
    mount that does not hold this process's cgroup is someone else's tree by every path, the canonical
    `user.slice/user-<uid>.slice/user@<uid>.service` included — and the motivating shape reaches the canonical path
    without ever building a derived candidate, since a private namespace's root reads `0::/`, which names no
    `user@<uid>.service`. `Detect`'s unprivileged branch therefore asks, in order: (1) is `/sys/fs/cgroup` cgroup2
    at all — if not, `ErrNotDelegated` wrapping `ErrNotCgroup2` (or the statfs error when the mount point is
    absent), naming the hierarchy fix rather than blaming namespaces or `Delegate=`; (2) does the mount agree —
    this process must appear in the `cgroup.procs` of the cgroup its unified (`0::`) path names under the mount,
    which is systemd's "path consistency with `/proc/$PID/cgroup`" requirement expressed as a check; only then (3)
    the derived `user@<uid>.service`, then the canonical one, the first cgroup2 candidate with a writable
    `cgroup.procs` winning, else `ErrNotDelegated` naming the delegation fix. Step (2) is fail-closed: anything
    short of shown agreement is `ErrNotDelegated` citing this case, for the derived and canonical candidates alike
    — a disagreeing `cgroup.procs`, a path absent under the mount, a unified path that carries `../` (which the
    same man page documents for a cgroup outside the reader's namespace root: the process's cgroup has no name
    under that root, so no path spliced onto the mount can be shown to be it, and `path.Join` would clean the `../`
    into a path outside the cgroup2 mount), a non-absolute path, and a `/proc/self/cgroup` with no `0::` line (once
    any cgroup2 filesystem is mounted the kernel prints that line for every process, so behind a cgroup2 mount its
    absence means the file could not be read). A diagnosable refusal instead of a silent wrong subtree. A
    disagreeing derived candidate is refused, never a fall-through to the canonical `user@<uid>.service`, which
    would consult the same unverified mount. Every refusal is a `*cgroup.DetectError` whose `Remedy` is the one fix
    for its cause, which `doctor`'s D3 prints as its fix line. The privileged branch (case 38) asks (1) and (2) too
    and then roots at the mount itself, so it has no (3); its (1) refusal matches `ErrNotCgroup2` and not
    `ErrNotDelegated`, including when the mount point cannot be statted at all, where it wraps the statfs error
    beside `ErrNotCgroup2`. Being root says nothing about which tree the mount is: a uid-0 launcher in a
    `cgroupns=private` container handed the host's `/sys/fs/cgroup` reads `0::/`, and without (2) it would `mkdir`
    `tego.slice` and write limit files in the host's root cgroup before `clone3` failed (with `nsdelegate`,
    `CLONE_INTO_CGROUP` outside the namespace is `ENOENT` even for root), so the privileged branch never roots at
    the mount unverified.
40. **Empty `tego.slice`/`tego-<agent>.slice` directories are retained for the life of the boot**: `Manager.Remove` removes only `run-<id>.scope`. The parent slices are shared by concurrent runs
    of the same agent, and `rmdir`ing a momentarily-empty one would race a sibling's `Create` into `ENOENT`
    (`ensureSlice` has no retry), so they stay — a deliberate trade, bounded by the number of distinct agent ids
    ever run rather than by the number of runs. Two things follow that a clean `ls` does not show: a removed
    cgroup is not immediately free (the kernel keeps *dying* memory cgroups alive after `rmdir` while page cache
    and slab objects stay charged to them — [LWN 895431](https://lwn.net/Articles/895431/)), so `populated=0` plus
    a successful `rmdir` is not evidence that a run left no kernel residue; and a high-churn agent's residue is
    kernel-side, invisible to any check this package can make. Accepted as a known non-goal for P0. If it ever
    needs closing, the fix is an `ENOENT` retry on the scope `mkdir` in `ensureSlice` plus an opportunistic
    `rmdir` of the agent slice ignoring `EBUSY`/`ENOTEMPTY` (`rmdir` on a non-empty cgroup fails atomically, so
    with the retry the race is benign) — never an unconditional removal.
41. **An unprivileged launcher started outside its delegated subtree**:
    the kernel moves a process from one cgroup into another only for a writer of the `cgroup.procs`
    of the two cgroups' common ancestor ("Delegation Containment", `Documentation/admin-guide/cgroup-v2.rst`), and
    `clone3`'s `CLONE_INTO_CGROUP` asks the same of the parent's cgroup and the child's. A login over ssh runs in
    its `session-<n>.scope` and a service in `system.slice`, so the ancestor they share with `user@<uid>.service`
    is `user-<uid>.slice` or the cgroup2 root, both root's. `Detect` finds the canonical `user@<uid>.service` from
    there (case 39's step 3), and it is delegated and usable for every operation that moves no process: `Create`,
    `SetLimits`, `Kill`, the sweep's and `tego stop`'s kills. Only placing the agent fails, with `EACCES` from
    `clone3` once the scope exists. Measured on the GitHub runner's kernel (6.17.0-1022-azure) in a guest shaped
    like the runner: `tego doctor` reported tier `landlock` with D3 passing, and `tego run` exited 125 with
    `clone3 failed: fork/exec /proc/self/exe: permission denied`; the same binary run from inside the user's
    `user@<uid>.service` exited 0. The question is therefore asked by `FS.CanPlace`, apart from `Detect`, which
    `tego stop` and the sweep keep using from anywhere: `nil` when this process's cgroup lies inside the root, or
    when it may write the common ancestor's `cgroup.procs`, and always for a privileged root (uid 0 may write the
    mount root's, the ancestor of every cgroup); otherwise a `*DetectError` matching `ErrOutsideSubtree` and the
    errno, whose `Remedy` is to start tego inside the subtree (`systemd-run --user --scope tego ...`, which has
    the user manager ask the system manager to move the caller into a new scope there). `runtime.Run` asks it
    right after `Detect`, before anything is created, and `doctor`'s D3 asks it too, so the two agree: from such
    a shell tier `landlock` is unavailable and says why. `TestIntegrationCanPlaceIsTheKernelsAnswer` holds the
    check to a real `clone3` into the chosen root on whatever machine runs it.

42. **The launcher inherits descriptors without `FD_CLOEXEC`**: a
    parent that leaks descriptors into its children, as the GitHub Actions runner does into every step, gives them
    to `tego`, and os/exec passes each descriptor that lacks the flag on to the child stage, which passed it on to
    the agent at `execve`. An inherited descriptor is access the contract never granted and Landlock cannot take
    back, since it checks at open: a file open for writing outside the write entries, a socket, a pipe to the
    parent's tooling. CI found it as agent fds `[0 1 142 145 2]`. The stage marks every descriptor from 3 up
    close-on-exec before anything else (invariant 4a); `TestAgentInheritsNothingTheLauncherInherited` plants
    such descriptors in the launcher and holds the agent to 0, 1 and 2.

43. **The agent takes its owner's rights on tego's own state** (GAPS C52, measured at tier `landlock`): the agent runs
    as the user who owns `~/.tego`, the config layer and `tego.log` in it, `chain.log`, the ledger root, `.live`, tego's
    runtime parent (`$XDG_RUNTIME_DIR/tego`) and its own run and runtime directories, and no Landlock ABI has a chmod
    right, so `chmod 000` on them succeeds with no write entry near them. The run's `Close` then failed its directory's
    fsync and its anchor (`ErrAnchorWrite`, exit 125), and every later run exited 125, at the config's load
    (`[config-untrusted]`), at compile, which could not place the anchor, or making its runtime directory (`[run]`),
    until the modes were restored by hand. `tego run` now restores the owner's rights on `~/.tego`, the config layer and
    `tego.log` before it reads the machine config, then on `chain.log`, the directory that holds it, the ledger root,
    `.live` and the runtime parent before it compiles (`runtime.RestoreOwnState`), warning `[own-state-mode]` for each,
    and the run records them after `run_start` (step 9); every run restores the same, the config layer and `tego.log`
    included (`Deps.UserState`), and its run directory, each entry in it and each blob, and its runtime directory at its
    end (step 13), before `Close`, once no process of the run is left to take them again. `tego gc` gives back
    `~/.tego`, the config layer and `tego.log` before it reads the config too, and deletes nothing by a config it still
    cannot read whole (limits-check-doctor-cli.md R29). Only a directory or a regular file the launcher's euid owns and
    that lacks an owner right tego needs is restored, and only those owner bits are added (`chmod 000` becomes `0700` on
    a directory, `0600` on a file tego writes and `0400` on the config layer, which it only reads): a group or other bit
    is left for the config trust check (identity-config.md R20) and the runtime directory's check
    (agent-contract.md R10a) to refuse, since someone else could have replaced what such a directory holds. A link at
    one of the names is neither followed nor changed, and a root launcher, which reads and writes through any mode,
    restores none; its agent cannot take the modes of the run's own directory, root's until `Close`, and the user's next
    unprivileged run restores the rest at its start (record-ledger.md §3, "Modes taken from the owner", which lists what
    is not restored). Each restored mode is a `gap what=record why=own-state-mode-restored` naming the path, which the
    receipt, `status` and `drift` read as no lost action. Still open: while the run lives its agent can take the modes
    of its own run directory, which keeps `tego status`, `events` and `stop` (and the dashboard's Stop) out of it until
    the run ends, so such a run is stopped with Ctrl-C or a signal to its launcher; a run whose launcher died keeps the
    modes its agent gave its own run directory, since the sweep that ends it restores none; a group or other write bit
    an agent adds to `~/.tego` or the config layer still has every later run refused `[config-untrusted]`, by design,
    with the trust check's fix (`chmod g-w,o-w`), and one it adds to the runtime parent has every later run that routes
    Codex refused, with the runtime directory's fix (remove it, or export `XDG_RUNTIME_DIR` as an absolute directory
    only you can write), while every other run goes on without a runtime directory, so with no `TEGO_REASON` (tego.log
    says why); and an agent of another live run can take a mode again between a run's restore and its use.
    `TestIntegrationOwnStateModesAreRestored` holds the agent's run, the next one, and one through a link planted at
    `chain.log`; `TestIntegrationOwnStateConfigLayerIsRestoredFirst` the config layer and `~/.tego` taken by an agent and
    given back at its run's end, then taken while no run was there and given back before the next run reads the config,
    and a group-writable `~/.tego` still refused; `TestIntegrationOwnStateRuntimeParentIsRestored` the runtime parent
    and the run's runtime directory.

**Changes.**
- 2026-11-02, case 43, steps 9 and 13: tego restores the modes an agent took from its own files, before the compile and
  at the run's end, and records each (GAPS C52); `~/.tego`, its config layer and `tego.log` before the config is read
  and at the run's end, the runtime parent and the run's runtime directory too, the owner's bits only; `tego gc` gives
  back the first three before it reads the config, and deletes nothing by a config it cannot read whole.
- 2026-10-05, cases 22, 36 (ADR 0042): `/run/tego` is root `0700` only; the file-capability copy is refused at start,
  not a second privileged path; uid 0 of a child user namespace has no `SUDO_UID` drop target.
- 2026-09-22, case 37: an absolute `ledger_root` anchors with no home; the `AT_SECURE` difference is stated.
- 2026-09-23, case 4: the ABI<11 retry drops only `NO_NEW_PRIVS`, never the audit flag; the launcher sets
  `LOG_NEW_EXEC_ON` on opt-in, and an unread audit state writes `kernel-audit-unknown`.
- 2026-09-23, case 14: at tier `cgroup` a stopped launcher stalls the host's opens; job-control stops are ignored
  (R9a).
- Case 39: a disagreeing derived candidate is refused, not a fall-through; the privileged branch verifies
  the mount (2) and wraps the statfs error beside `ErrNotCgroup2`.
- 2026-09-24, case 26: unwind stops the kernel recorder and releases
  the ledger with `Abandon`.
- 2026-09-24, case 28: another host's run is left alone.
- 2026-09-24, cases 41, 42: added.
- 2026-09-25, case 31: a slice's refused controller write is kept and named as the cause.
- 2026-09-24, case 1: a collision retries a fresh id 3× (identity-config.md R2b) before 125.
- 2026-09-24, case 10: a sweep takes the orphan's lock before it kills the tree, so one of N racing sweepers kills
  and ends it and the others count nothing (`TestConcurrentSweepsKillAndEndALostRunOnce`); every racer killed and
  most reported the run swept before.
- 2026-09-28, case 17: `Command`/`Env`/`Dir` cross the spec pipe as base64 bytes; JSON strings had turned a
  non-UTF-8 argv, env or dir byte into U+FFFD before `execve`.
- 2026-09-29, case 13 (ADR 0020): at tier `cgroup` the run's reaper ends an orphan at once and purges its kernel
  state after its scope is removed; a sweep purges the same when the reaper died too.
- 2026-09-30, case 3: the `ErrChildDied` error names the dead child's exit status or signal.
- 2026-09-30, case 3: a stage that dies between its fd message and `pidfd_getfd` is `ErrChildDied` with its status.
- 2026-09-30, case 3: a stage killed by a small `limits.pids` before its handoff is `ErrStagePidsCap`.
- 2026-09-30, case 13: a sweep purges an orphan's kernel state only for a run root's launch record names; a planted directory with a forged run_start unpinned another run's links.
- 2026-10-05, case 13 and §7's launcher-death row: a DNS broker run's reaper ends its orphan at
  once at tiers `landlock` and `observe` too, then removes the owned endpoint; the text said the sweep's target.
  §7 gains the reaper-start row, which no tier had.
- 2026-10-05, step 3, case 13 and §7's launcher-death and reaper-start rows: they
  name tier `bpflsm` beside tier `cgroup`. Tier `bpflsm` runs tier `cgroup`'s backend, whose handle carries the
  `ReapTarget` `startReaper` asks for, so it gets the same reaper and fails the same way when one cannot start; the
  text said tier 2, or tier `cgroup`, alone.
- 2026-10-05, case 4: the guest kernel with Landlock ABI 10 that the `LANDLOCK_ADD_RULE_QUIET` condition
  waited for is test/vm's `fedora-7.2` row. No launcher sets the flag yet.
- 2026-10-16, R3's deputy note (ADR 0041 Stage B): the run's reaper (ADR 0006 R1) leaves the open deputy's
  zombie unreaped (`Child.KeepUnreaped`); it reaped a deputy the agent had ended, which freed the pid by which the
  kernel recorder drops the deputy's records for a later process of the run.
- 2026-10-17, R3's deputy note (ADR 0041 Stage B): the deputy sets no_new_privs and
  installs its filter on one locked thread (a privileged stage execs it without no_new_privs, and a filter installed
  from another thread was refused), and a deputy that cannot start names its reason in the stage's report.
- 2026-10-17, R10's swap warning (ADR 0041 Stage B): the run's warnings carry their own
  diagnostic codes (`Deps.Warn` takes one): `[swap-uncapped]` stays the swap warning's, and the held completion's
  degrade is `[held-unavailable]` and its label residual `[unenforced]`; both were printed `[swap-uncapped]`.

## 7. Failure modes and handling

| Failure | Detection | Response | Ledger | Exit / event | User sees |
|---|---|---|---|---|---|
| A worker (enforce listener, dns) fails pre-`run_start` | the group cancels; the next prepare step returns the cancellation | cleanup as above | none | exit 125 | stderr names the worker: `... (worker failed: enforce-listener: <err>)` |
| `clone3` fails pre-`run_start` | errno from `Start` | cleanup cgroup/lock/dir, return error | none | exit 125 | one-line stderr `file:line: msg [code]` |
| Child dies before fd handoff | `EOF` on `ControlR` | same cleanup | none | exit 125 | stderr: failed before exec; names `limits.pids` when `pids.events max` rose (case 3) |
| Landlock/seccomp setup errno in child | negative code over pipe (case 4) | same cleanup, decoded reason | none | exit 125 | specific stderr line naming the step |
| `execve` of agent fails | ordinary `wait4` status | record only | `run_end reason=exec-failed` | exit 126/127 | agent's own shell-convention error |
| `SetLimits` writes `EINVAL` | errno from `write(2)` | cleanup, return error | none | exit 125 | stderr names the bad value |
| `SetLimits` writes `ENOENT` (missing controller, case 31) | errno from `write(2)` | cleanup, return error | none | exit 125 | stderr names the missing controller + delegation fix |
| Memory cgroup OOM-kills a task | `memory.events.oom_kill` increase (`ReadLimitEvents`) | wait for `populated=0` (kernel already killed) | `run_end reason=oom` | exit 137 | "run ended: out of memory" |
| pids cap exhausted | `pids.events.max` increase (`ReadLimitEvents`) | `Manager.Kill` | `run_end reason=pids` | exit 137 | "run ended: process limit reached" |
| Signal, terminal absent | signal handler | start/escalate `stop_grace` (R9) | `run_end reason=signal signal=<n> escalated=<bool>` | passthrough | agent's shutdown, then tego's summary |
| `tego stop` marker + signal | `stop.request` present at handler time | same timer, different reason | `run_end reason=stopped` | 143 / 137 | "run stopped" |
| `cgroup.kill` fails at escalation (R9) | errno from the `Killer`'s write | the signal worker returns the error, so the group cancels and the run's own cancel path retries the kill | `run_end` keeps `escalated=false` — the write never happened | terminal reason unchanged (`stopped`/`signal`) | `run: worker` log naming the failed `cgroup.kill`; the summary never claims an escalation that did not happen |
| Supervisor crash/`SIGKILL` | none in-process; at tiers `cgroup` and `bpflsm`, or with a DNS broker endpoint at any tier, the run's reaper, on the launcher's pidfd (case 13) | tiers `cgroup` and `bpflsm`: the reaper kills, ends and removes the run at once, then purges its links and rows; a DNS broker run's reaper does the same at any tier, purging no kernel state at tiers `landlock` and `observe`, then removes the endpoint; otherwise none until next sweep | `run_end reason=orphaned` from the reaper, or when swept | orphan until reaped or swept | `status` shows `lost` until then, never `done` |
| The run's reaper cannot be started (step 3) | error from `pidfd_open(self)`, the run directory's descriptor or the helper's fork/exec (a helper cgroup that cannot be made falls back to the launcher's own) | unwind before the child stage | none (pre-`run_start`) | exit 125 | at tiers `cgroup` (every plane mode) and `bpflsm` (tier `cgroup`'s backend in LSM mode; ADR 0020 (4)'s plane-mode gap is not built), or with a DNS broker endpoint at any tier: stderr names the reaper and why it was needed |
| Sweep finds a dead run | `flock(LOCK_EX\|LOCK_NB)` succeeds on `run_start`-only ledger | `Kill` if populated, wait, `Remove` | `run_end reason=orphaned exit_code=125` (logical launcher failure, written by the sweeper; the reaper records the same code) | n/a (retroactive; no child wait status recovered) | `status` shows `reason=orphaned` and interprets an older orphan's missing or zero code as 125 without changing its ledger |
| `rmdir` `EBUSY` repeatedly | retries exhausted (case 9) | log, leave for next sweep | none new | not fatal to current run | nothing immediate; a later `doctor` finding |
| Build-lock pin check never succeeds | 5 retries/500ms fail | `Prepare` returns error | none (pre-`run_start`) | exit 125 | "tier unavailable: build lock contention" |
| `clone3` refused or missing at `Start` (case 20) | `EINVAL`/`ENOSYS`/`EPERM` at first call | refuse before any resource created | none | exit 125 | one line naming whichever cause this process's own `Seccomp:` mode proves — an outer seccomp profile filtering `clone3`, or a kernel without the flags (the normal-path refusal is `doctor`'s exit 125 [tier-unavailable], before `Run`) |
| `ledger.Close` fails mid-shutdown (R18) | errno/`EIO` from `Close` | continue shutdown regardless, log the failure, return it as `Result.RecordErr` | best-effort (may be short) | original terminal reason kept; `tego run` exits 125 `[ledger]` | `tego run` prints which ledger failure it was |
| Panic in a worker goroutine | `errgroup` propagates; process terminates | none — this is the crash case | whatever flushed before the crash | process exits non-zero | discovered later via `status` = `lost` |
| Root launcher, no unprivileged drop target (R4a, case 36) | `os.Geteuid()==0` and no usable `SUDO_UID`/`SUDO_GID` | refuse before `clone3`; nothing created | none (pre-`run_start`) | exit 125 | stderr names the missing uid and points at `sudo tego run` |
| `~/` `ledger_root` with no passwd home under `AT_SECURE` (case 37) | `Machine.Home == ""` and `DetectSecureExec` | refuse before `mkdir`; `$HOME` never read | none (pre-`run_start`) | exit 125 | stderr asks for an absolute `ledger_root` |
| The chain anchor cannot be opened for append (case 37): a home that cannot hold `~/.tego`, a symlink or hard link planted at `~/.tego` or `chain.log` (refused as root), a directory where `chain.log` goes | `ledger.ProbeAnchor`, which `tego run` calls after resolving the anchor and before `runtime.Run`: `~/.tego` and an empty `chain.log` made if missing, nothing written | refuse before the run directory exists; the agent never starts | none (no run directory) | exit 125 `[run]` | `tego run: chain anchor: <path and errno>` — the fix is a home the account can write (an account with no home anchors beside an absolute `ledger_root`); a later failure at `Close` (a full disk) is still `ErrAnchorWrite`, E29 |
| A pipeline stage or `Append` refuses an event | non-nil error from `RedactStage`/`SplitBlobsStage`/`Append` | drop that event, count it | `gap what=record why=stage-refused count=n`, written at drain (R8) alongside `why=channel-full` | not fatal to the run | the ledger says how many events were lost and why, never a silence |

## 8. Invariants

1. At most one process holds `runs/<id>/lock`'s `flock(LOCK_EX)` at a time; "live" is defined only as "the lock is
   held" — never a pid or state file (R1, ADR 0013).
2. `run_end` is always the last line for a run that has one (R8, R18); a ledger with `run_start` and no `run_end`
   is either live (lock held) or orphaned (lock free) — no third state.
3. Every child this package creates is inside the run's cgroup from its first instruction (`CLONE_INTO_CGROUP` at
   `clone3` time, never a later `cgroup.procs` write) — no TOCTOU window outside any cgroup's limits.
4. The supervisor's notify fd is never inherited by the agent's process tree (obtained via `pidfd_getfd` into a
   fresh parent-table fd, never passed across the control pipe) — the agent can never hold its own notify channel.
4a. The agent's `execve` keeps descriptors 0, 1 and 2 and nothing else: the child stage's first act is
   `close_range(3, ~0, CLOSE_RANGE_CLOEXEC)` (a `/proc/self/fd` walk setting `FD_CLOEXEC` where a seccomp profile
   refuses that call), which covers the handshake's pipes, the ruleset and every descriptor the launcher itself
   inherited without the flag (case 42). 0, 1 and 2 are the caller's whatever they are, and Landlock checks a
   file's access only at open, so `run_start.stdio` records each one's kind (`tty`, `null`, `char`, `pipe`,
   `socket`, `file`, `dir`, `other`, `unknown`), and `tego run` warns `[stdio]` before the run when one gives the
   agent access no rule does: a socket on any of them, or a regular file outside every write entry that the stream
   opens beyond its own direction (stdin for writing, stdout or stderr for reading). Output redirected into a file
   goes only its own way, is what the caller asked for, and is recorded without a warning.
5. `PR_SET_PDEATHSIG` is armed only after the child's *last* credential change — `commit_creds` clears a pending
   `pdeath_signal` on any credential change, so earlier arming would silently disable it (kernel-source-verified,
   integration-tested).
6. The build lock's `LOCK_SH` count is always exactly the number of live launchers of that `bpf_hash` — no
   separate integer refcount exists anywhere to drift out of sync (R15/R16 rely on this; there is no downgrade, and
   the only conversion, R16's non-blocking `LOCK_EX`, leaves a launcher told it is not last holding nothing).
7. Landlock, seccomp's errno arms, the cgroup limits and, at tier `cgroup`, the run's network programs stay
   enforced on the agent's tree even if the launcher is stopped, killed, or crashed — enforcement lives in the
   kernel (cred/filter/cgroup files, and the run's cgroup links, pinned, with its map rows: ADR 0020 (1),
   enforce-cgroup-observe E38), never in a userspace loop that must stay alive. What does live in the launcher, the
   seccomp notifications and tier 2's fanotify decisions, fails closed (`ENOSYS`) and open (enforce-cgroup-observe
   E15) respectively when it dies, and the run's reaper ends the run at once (case 13).
8. `Manager.Remove` never removes a cgroup with a non-empty `cgroup.procs` except by retrying past a transient
   `EBUSY` (case 9) — there is no mechanism to force-empty a cgroup other than `cgroup.kill` + wait.
9. Exactly one of `{agent's own exit, signal, stopped, oom, pids, limit, exec-failed, orphaned, error}` is the
   terminal reason for any run reaching `run_end` — mutually exclusive by construction (R10).
10. `runtime.Run` never produces `[tier-unavailable]` or `[config-untrusted]` itself; those belong to `cli.run`'s
    pre-`Run` steps (`config.Load`, `enforce.Select`) — this package's own pre-`run_start` failures are a plain 125 (R2).

**Changes.**
- 2026-09-24, invariant 4a: added; `run_start.stdio` records 0–2 and `tego run` warns
  `[stdio]`.
- 2026-09-29, invariant 7 (ADR 0020): tier 2's pinned network programs are kernel-resident too; what lives in the
  launcher is named, with how it fails.

## 9. Conventions and best practices

- **Naming**: short lowercase package nouns (`launch`, `cgroup`); no `util`/`helpers`. One sentinel error per
  failure *class* (`ErrRunLocked`, `ErrClone`, `ErrChildDied`, `ErrChildLandlock`, `ErrCgroupExists`,
  `ErrNotifyFDUnavailable`, `ErrStale`), wrapped with `%w` around the underlying `syscall.Errno` so `errors.Is`
  still reaches it.
- **Error wrapping**: every syscall error names the syscall and the argument that mattered
  (`fmt.Errorf("clone3(CLONE_PIDFD|CLONE_INTO_CGROUP): %w", err)`) — this is the TCB; messages are read by whoever
  debugs a failed install.
- **Logging**: nothing here writes the ledger except via `ledger.Writer`; diagnostics go to `~/.tego/tego.log`
  (`run=<id>` tagged), never mixed with agent data (`docs/OPERATIONS.md`).
- **Context discipline**: every goroutine takes `ctx` first and selects on `ctx.Done()`. The two operations with no
  cancellable variant — the child's blocked `read`, and `ioctl(NOTIF_RECV)` — are bounded by closing the underlying
  fd instead (`ControlR` close → `EOF`; the notify fd's close is `ask`/`supervisor`'s shutdown concern).
- **Goroutine ownership**: every goroutine `Run` starts is started inside the `errgroup` it later `Wait()`s on;
  none fire-and-forget — the `stop_grace` timer included, whose escalation the signal worker joins before
  returning (R9), since `Wait()` is also the point where `run_end` is decided and the cgroup fd is closed.
  `Start`'s handshake is synchronous on the calling goroutine, keeping §5's ordering guarantees provable by
  reading top to bottom.
- **Resource lifetimes**: every `O_PATH`/`O_DIRECTORY` fd is closed exactly once, on exactly one code path (the
  shutdown sequence) — never a `defer` racing a hand-written close elsewhere. The same rule governs the seccomp
  notify fd across its handover: `supervisor.New` takes ownership and `Loop.Run` closes it on every return path it
  has, so the facade drops its own copy of the number at that call and closes the listener itself only on the paths
  where no `Loop` was ever constructed. A second `close(2)` on a freed number is not benign — by shutdown time the
  drain and `ledger.Close` have opened and closed files, and the kernel's lowest-free-fd rule can have reissued it.
  In a package migrated to `sys.FD` (one `tools/fdcheck/baseline.txt` no longer lists), "exactly once" is the
  owner's: every holder may call Close, the number is closed exactly once, by whichever holder closes first, and a
  later Close is a no-op (R25); the one-code-path rule above holds for the packages still listed.
- **Fuzzing**: `FuzzControlPipeDecode` (4-byte fd number + negative-error-code branch) and `FuzzParseLockInfo` and
  `FuzzParseStartBootNS` (`"<pid> <start_boot_ns>"`) — both parse locally-written-but-untrusted-shaped bytes and must never panic on a
  torn or truncated read.
- **Benchmarks**: `BenchmarkCgroupCreateRemove`, scheduled CI (needs root), not on every PR.
  `BenchmarkSweepLiveNRuns` (N = 10/100/1000 sealed runs, no privilege) is the sweep `run` and `stop` make, and its
  time must not grow with N; CI's bench gate compares it against the base commit on every push.
  `BenchmarkSweepNRuns` measures in-process `gc`'s full pass (N = 10/100 ended run dirs).
- **Doc comments**: every exported symbol states its purpose plus, for anything syscall-facing, the exact
  syscall(s) and minimum kernel version — cross-checkable against `ARCHITECTURE.md` §14's support matrix.

**Changes.**
- 2026-10-17, Resource lifetimes (ADR 0023 C3): in a package migrated to `sys.FD`, a number is closed exactly once
  by whichever holder closes first (R25); the lint and ratchet that bind it are built, and no package has migrated.
- 2026-09-24, benchmarks: `BenchmarkSweepLiveNRuns` added and gated in CI; `BenchmarkSweepNRuns` is `gc`'s pass.

## 10. Tests

**Unit** (no root): lock file round-trip incl. pid-reuse mismatch (case 15/29, mocked `pidfd_open`); sweep against a
fixture tree covering running/orphan/ended states, asserting exactly the orphan set gets `reason=orphaned` (R12,
cases 10–11); `Limits`→control-file-string table test incl. both arms of case 30 (absent `Pids`→`"max"`,
`Pids` asked for as 0→`"0"`), `memory.high`>`memory.max`
passthrough (case 23), and the `EINVAL`-vs-`ENOENT` failure split (case 31); control-pipe encode/decode incl. the
negative-error branch (case 4) and truncated-read fuzz corpus; the build-lock protocol over real `flock`s on a
temporary directory, `TestBuildLockProtocolAsSpecified` (`enforce/cgroup/buildlock_protocol_test.go`): every holder
shared from the start (R15), not-last then last and the last out exclusive until close (R16), last-out never
unlinking the lock file, the next launcher locking the same inode (R16, R21), and a lock whose name was removed
taken again (`TestABuildLockWhoseNameWasRemovedIsTakenAgain`, R16), with `TestBuildLockLastOut` and
`TestTwoDeparturesExactlyOneIsLast` beside it; shutdown continues past a simulated `ledger.Close` failure and still runs
`Detach`/`Remove`/`Release` (R18).

**Integration** (`//go:build integration`, root, VM): child stage end-to-end — real `pidfd_getfd`, `PDEATHSIG`
delivery on launcher kill (I5, I7), dumpable-state assertion at the `pidfd_getfd` call site (case 5); real
`clone3(CLONE_PIDFD|CLONE_INTO_CGROUP)` with zero intermediate `cgroup.procs` writes (I3); `cgroup.kill` semantics
incl. a grandchild that forked after the write started (R10); OOM detection (`oom_kill` increments, `reason=oom`,
exit 137); pids-cap detection (fork-bomb workload, low `pids.max`, `reason=pids`, R11); a delegated subtree with
`pids` missing from `cgroup.subtree_control`, asserting `ENOENT` is diagnosed distinctly from `EINVAL` (case 31);
orphan sweep against a real `kill -9`'d launcher, one-pass cleanup (case 13); signal-forwarding matrix for
`SIGTERM/HUP/USR1/USR2` (always) and `SIGINT/QUIT` (tty vs. not), incl. double-`SIGINT`-within-2s escalation (R9);
`tego stop` marker → `reason=stopped` vs. `reason=signal`, stop-against-ended-run (case 11), stop-against-stale-lock
via `OpenStopTargetFor` (case 15/29/32, falling back to a mocked `/proc` when kernel pid wrap isn't reproducible in
CI); build-lock protocol under real concurrency — N simultaneous launchers of one `bpf_hash`, one set of pins shared by all,
detach only on the true last exit (R15/R16); two-build coexistence against a mocked hook dispatch, asserting
neither shadows the other's map entries (R17).

**Fixtures**: a hand-written `events.jsonl` with `run_start` and no `run_end` (sweep test's core input, shared with
the M0 fixture ledger, `docs/P0-DESIGN.md` §10); golden lock-file bytes for the parser round-trip test.

## 11. Open questions

- **Stop-marker vs. control socket.** This spec resolves "how does `tego stop` reach a running launcher, and how
  does it distinguish a requested stop from an arbitrary `SIGTERM`, with no pid file" via a `stop.request` marker
  plus pid+start-boot-ns in the lock file, now targeted through a held `pidfd` (§3, R9, R22). The normative docs
  state the *outcome* (`ARCHITECTURE.md` §6, `RUN-IDENTITY.md`: "SIGTERM to the cgroup... `run_end reason=stopped`")
  but not this mechanism.
- **`Manager.Events`'s normative shape vs. oom/pids detection.** `docs/P0-DESIGN.md` §2.5 freezes
  `Events(Cgroup) (<-chan bool, error) /* populated */` — bool-only, populated-only (§2/§4). R10/R11's oom/pids detection now reads `memory.events`/`pids.events`
  through a separate package function, `cgroup.ReadLimitEvents`, kept off the `Manager` interface so the frozen
  signature is not silently diverged from. This split is a pragmatic reconciliation, not a normative decision —
  `P0-DESIGN.md` §2.5 itself should be revisited to decide whether oom/pids detection belongs on `Manager` at all,
  or is confirmed as this document now assumes.
- **`Manager.Events`'s change notification** is `inotify` `IN_MODIFY` on `cgroup.events` (§4), the mechanism the
  kernel's cgroup v2 documentation names, with a 200ms re-read bounding any lost notification; no `EPOLLPRI` path
  exists.
- **Non-local `ledger_root` detection** (case 28): neither `spec/config/v0` nor `docs/OPERATIONS.md` requires a
  filesystem-type check; unresolved whether `doctor` or this package should add one.
- **Where a privileged launcher's subtree comes from** (case 38): P0 `mkdir`s `tego.slice` directly under
  `/sys/fs/cgroup`, which systemd's delegation contract forbids and which this document now records as an accepted
  cost rather than an oversight. The sanctioned alternatives — a transient scope with `Delegate=yes` via
  `StartTransientUnit`, or shipping `tegod` as a unit with `Delegate=yes` and rooting the manager at its own
  cgroup — both need a D-Bus client (no new dependency exists for one) and a decision about whether `tego run`
  as root must work on a host with no systemd at all. The cgroup layout
  is in `RUN-IDENTITY.md` and in the BPF `run_set` keying, so moving it later is not a local change.

## Resolved conflicts
Resolved (2026-09-22): pre-`Run` failures in `cli.run` exit 125 with a diagnostic code (`[config-untrusted]`, `[tier-unavailable]`), never 211 or 213.
